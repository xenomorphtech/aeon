use serde_json::{json, Value};

/// Why a tool call failed. The string form is stable: clients may branch
/// on it, while messages are for people and may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// No tool has that name.
    UnknownTool,
    /// The tool needs a binary and none is loaded.
    NoBinaryLoaded,
    /// An argument is missing, of the wrong type, or not parseable.
    InvalidArgument,
    /// The arguments were understood and the analysis itself failed: no
    /// function at that address, a file that would not load, and so on.
    Analysis,
}

impl ErrorCode {
    pub const ALL: [ErrorCode; 4] = [
        ErrorCode::UnknownTool,
        ErrorCode::NoBinaryLoaded,
        ErrorCode::InvalidArgument,
        ErrorCode::Analysis,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnknownTool => "unknown_tool",
            ErrorCode::NoBinaryLoaded => "no_binary_loaded",
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::Analysis => "analysis_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError {
    pub code: ErrorCode,
    pub message: String,
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The error as a JSON object: `{"code": ..., "message": ...}`.
    pub fn to_value(&self) -> Value {
        json!({ "code": self.code.as_str(), "message": self.message })
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ToolError {}

/// The core reports failures as strings; they are all analysis failures.
/// Argument problems are raised here in the frontend, as [`ArgError`].
impl From<String> for ToolError {
    fn from(message: String) -> Self {
        Self::new(ErrorCode::Analysis, message)
    }
}

/// A problem with a tool call's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgError(String);

impl From<&str> for ArgError {
    fn from(message: &str) -> Self {
        Self(message.to_string())
    }
}

impl From<String> for ArgError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl From<ArgError> for ToolError {
    fn from(error: ArgError) -> Self {
        Self::new(ErrorCode::InvalidArgument, error.0)
    }
}

pub type ToolResult = Result<Value, ToolError>;

pub struct AeonFrontend {
    session: Option<aeon::AeonSession>,
}

impl AeonFrontend {
    pub fn new() -> Self {
        Self { session: None }
    }

    pub fn status(&self) -> Value {
        match &self.session {
            Some(session) => json!({
                "loaded": true,
                "session": session.summary(),
            }),
            None => json!({
                "loaded": false,
            }),
        }
    }

    /// Runs the tool called `name`. See [`TOOLS`] for what exists.
    pub fn call_tool(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        self.call_tool_typed(name, args)
            .map_err(|error| error.message)
    }

    /// As [`Self::call_tool`], with an error that carries a stable code.
    pub fn call_tool_typed(&mut self, name: &str, args: &Value) -> ToolResult {
        let tool = TOOLS
            .iter()
            .find(|tool| tool.name == name)
            .ok_or_else(|| ToolError::new(ErrorCode::UnknownTool, format!("Unknown tool: {}", name)))?;
        (tool.handler)(self, args)
    }

    fn require_session(&self) -> Result<&aeon::AeonSession, ToolError> {
        self.session.as_ref().ok_or_else(|| {
            ToolError::new(
                ErrorCode::NoBinaryLoaded,
                "No binary loaded. Call load_binary first.",
            )
        })
    }

    fn tool_load_binary(&mut self, args: &Value) -> ToolResult {
        let path = args
            .get("path")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: path"))?;
        let format = args
            .get("format")
            .and_then(|value| value.as_str())
            .unwrap_or("elf");

        let session = match format {
            "elf" => aeon::AeonSession::load(path)
                .map_err(|e| format!("Failed to load ELF binary: {}", e))?,
            "raw" => {
                let base_addr = args
                    .get("base_addr")
                    .and_then(|value| value.as_str())
                    .ok_or(ArgError::from("Missing required parameter for raw binaries: base_addr"))?;
                let base_addr = parse_hex(base_addr)
                    .ok_or_else(|| ArgError::from(format!("Invalid hex address for base_addr: {}", base_addr)))?;
                aeon::AeonSession::load_raw(path, base_addr)
                    .map_err(|e| format!("Failed to load raw binary: {}", e))?
            }
            other => {
                return Err(ArgError::from(format!(
                    "Unsupported binary format: {} (expected 'elf' or 'raw')",
                    other
                ))
                .into())
            }
        };
        let result = session.summary();
        self.session = Some(session);
        Ok(result)
    }

    fn tool_list_functions(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let offset = args
            .get("offset")
            .and_then(|value| value.as_u64())
            .unwrap_or(0) as usize;
        let limit = args
            .get("limit")
            .and_then(|value| value.as_u64())
            .unwrap_or(100) as usize;
        let name_filter = args
            .get("name_filter")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        Ok(session.list_functions(offset, limit, Some(name_filter)))
    }

    fn tool_set_analysis_name(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let name = args
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: name"))?;
        Ok(session.set_analysis_name(addr, name))
    }

    fn tool_rename_symbol(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let name = args
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: name"))?;
        Ok(session.rename_symbol(addr, name))
    }

    fn tool_define_struct(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let definition = args
            .get("definition")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: definition"))?;
        Ok(session.define_struct(addr, definition))
    }

    fn tool_add_hypothesis(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let note = args
            .get("note")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: note"))?;
        Ok(session.add_hypothesis(addr, note))
    }

    fn tool_search_analysis_names(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let pattern = args
            .get("pattern")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: pattern"))?;
        Ok(session.search_analysis_names(pattern)?)
    }

    fn tool_get_blackboard_entry(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_blackboard_entry(addr))
    }

    fn tool_get_function_il(&self, args: &Value) -> ToolResult {
        self.tool_get_il(args)
    }

    fn tool_get_reduced_il(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_reduced_il(addr)?)
    }

    fn tool_get_ssa(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let optimize = parse_bool_arg(args, "optimize", true)?;
        Ok(session.get_ssa(addr, optimize)?)
    }

    fn tool_get_stack_frame(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_stack_frame(addr)?)
    }

    fn tool_get_il(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_il(addr)?)
    }

    fn tool_get_function_cfg(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_function_cfg(addr)?)
    }

    fn tool_get_function_skeleton(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_function_skeleton(addr)?)
    }


    fn tool_get_data_flow_slice(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let register = args
            .get("register")
            .and_then(|v| v.as_str())
            .ok_or(ArgError::from("register parameter required"))?;
        let direction = args
            .get("direction")
            .and_then(|v| v.as_str())
            .ok_or(ArgError::from("direction parameter required ('backward' or 'forward')"))?;
        Ok(session.get_data_flow_slice(addr, register, direction)?)
    }

    fn tool_get_xrefs(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_xrefs(addr))
    }

    fn tool_execute_datalog(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let query = args
            .get("query")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: query"))?;
        let addr = parse_addr_arg(args)?;
        let register = args.get("register").and_then(|value| value.as_str());
        let limit = args.get("limit").and_then(|value| value.as_u64()).map(|v| v as usize);

        Ok(session.execute_datalog(query, addr, register, limit)?)
    }

    fn tool_scan_pointers(&self) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.scan_pointers())
    }

    fn tool_scan_vtables(&self) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.scan_vtables())
    }

    fn tool_get_function_pointers(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = match args.get("addr").and_then(|value| value.as_str()) {
            Some(value) => {
                Some(parse_hex(value).ok_or_else(|| ArgError::from(format!("Invalid hex address: {}", value)))?)
            }
            None => None,
        };
        let offset = args
            .get("offset")
            .and_then(|value| value.as_u64())
            .unwrap_or(0) as usize;
        let limit = args
            .get("limit")
            .and_then(|value| value.as_u64())
            .unwrap_or(50) as usize;
        Ok(session.scan_function_pointers(addr, offset, limit)?)
    }

    fn tool_find_call_paths(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let start_str = args
            .get("start_addr")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: start_addr"))?;
        let goal_str = args
            .get("goal_addr")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: goal_addr"))?;
        let start_addr =
            parse_hex(start_str).ok_or_else(|| ArgError::from(format!("Invalid hex address: {}", start_str)))?;
        let goal_addr =
            parse_hex(goal_str).ok_or_else(|| ArgError::from(format!("Invalid hex address: {}", goal_str)))?;
        let max_depth = args
            .get("max_depth")
            .and_then(|value| value.as_u64())
            .unwrap_or(6) as usize;
        let include_all_paths = parse_bool_arg(args, "include_all_paths", false)?;
        let max_paths = args
            .get("max_paths")
            .and_then(|value| value.as_u64())
            .unwrap_or(32) as usize;
        Ok(session.find_call_paths(
            start_addr,
            goal_addr,
            max_depth,
            include_all_paths,
            max_paths,
        )?)
    }

    fn tool_get_bytes(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let size = args
            .get("size")
            .and_then(|value| value.as_u64())
            .unwrap_or(64) as usize;
        Ok(session.get_bytes(addr, size)?)
    }

    fn tool_search_rc4(&self) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.search_rc4())
    }

    fn tool_get_coverage(&self) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_coverage())
    }

    fn tool_get_asm(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let start_str = args
            .get("start_addr")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: start_addr"))?;
        let stop_str = args
            .get("stop_addr")
            .and_then(|value| value.as_str())
            .ok_or(ArgError::from("Missing required parameter: stop_addr"))?;

        let start_addr =
            parse_hex(start_str).ok_or_else(|| ArgError::from(format!("Invalid hex address: {}", start_str)))?;
        let stop_addr =
            parse_hex(stop_str).ok_or_else(|| ArgError::from(format!("Invalid hex address: {}", stop_str)))?;
        Ok(session.get_asm(start_addr, stop_addr)?)
    }

    fn tool_get_function_at(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let include_asm = parse_bool_arg(args, "include_asm", false)?;
        let include_il = parse_bool_arg(args, "include_il", false)?;
        Ok(session.get_function_at(addr, include_asm, include_il)?)
    }

    fn tool_get_string(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let max_len = args
            .get("max_len")
            .and_then(|value| value.as_u64())
            .unwrap_or(256) as usize;
        Ok(session.get_string(addr, max_len)?)
    }

    fn tool_get_data(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let size = args
            .get("size")
            .and_then(|value| value.as_u64())
            .unwrap_or(64) as usize;
        Ok(session.get_data(addr, size)?)
    }

    fn tool_emulate_snippet_il(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let start_addr = parse_hex_arg(args, "start_addr")?;
        let end_addr = parse_hex_arg(args, "end_addr")?;
        let step_limit = args
            .get("step_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        let initial_registers = parse_register_map(args)?;

        Ok(session.emulate_snippet_il(start_addr, end_addr, initial_registers, step_limit)?)
    }

    fn tool_emulate_snippet_native(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let start_addr = parse_hex_arg(args, "start_addr")?;
        let end_addr = parse_hex_arg(args, "end_addr")?;
        let step_limit = args
            .get("step_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        let initial_registers = parse_register_map(args)?;
        let initial_memory = parse_memory_map(args)?;

        Ok(session.emulate_snippet(start_addr, end_addr, initial_registers, initial_memory, step_limit)?)
    }

    fn tool_emulate_snippet_native_advanced(&self, args: &Value) -> ToolResult {
        let session = self.require_session()?;
        let start_addr = parse_hex_arg(args, "start_addr")?;
        let end_addr = parse_hex_arg(args, "end_addr")?;
        let step_limit = args
            .get("step_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        let initial_registers = parse_register_map(args)?;
        let initial_memory = parse_memory_map(args)?;
        let watchpoints = parse_watchpoints(args)?;
        let address_hooks = parse_address_hooks(args)?;
        let record_pc_trace = args
            .get("record_pc_trace")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let req = aeon::api::AdvancedEmulationRequest {
            start_addr,
            end_addr,
            initial_registers,
            initial_memory,
            step_limit,
            watchpoints,
            address_hooks,
            record_pc_trace,
        };

        Ok(session.emulate_snippet_native_advanced(req)?)
    }
}

/// One tool: its name, what it is for, the JSON schema of its arguments and
/// the function that runs it.
///
/// `TOOLS` is the only list of tools. Dispatch (`AeonFrontend::call_tool`),
/// the schema listing (`tools_list`) and the documentation table
/// (`tools_markdown_table`) are all derived from it, so a tool cannot be
/// callable but unlisted, or listed but not callable.
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    input_schema: fn() -> Value,
    handler: fn(&mut AeonFrontend, &Value) -> ToolResult,
}

impl ToolSpec {
    pub fn input_schema(&self) -> Value {
        (self.input_schema)()
    }
}

pub static TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "load_binary",
        description: "Load an ELF or raw AArch64 binary for analysis. Must be called before other tools.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "path": {"type": "string", "description": "Path to binary"},
                "format": {"type": "string", "description": "Binary format: 'elf' or 'raw'", "default": "elf"},
                "base_addr": {"type": "string", "description": "Required for raw binaries: virtual base address in hex"}
            }, "required": ["path"]})
        },
        handler: |frontend, args| frontend.tool_load_binary(args),
    },
    ToolSpec {
        name: "list_functions",
        description: "List functions discovered from .eh_frame unwind tables. Supports pagination and name filtering.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "offset": {"type": "integer", "description": "Start index", "default": 0},
                "limit": {"type": "integer", "description": "Max results", "default": 100},
                "name_filter": {"type": "string", "description": "Substring filter on symbol name"}
            }})
        },
        handler: |frontend, args| frontend.tool_list_functions(args),
    },
    ToolSpec {
        name: "set_analysis_name",
        description: "Backwards-compatible alias for rename_symbol. Attaches or overwrites a semantic symbol on an address.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "name": {"type": "string", "description": "Analysis name to assign to the address"}
            }, "required": ["addr", "name"]})
        },
        handler: |frontend, args| frontend.tool_set_analysis_name(args),
    },
    ToolSpec {
        name: "rename_symbol",
        description: "Attach or overwrite a semantic symbol name on an address.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "name": {"type": "string", "description": "Semantic symbol name to assign to the address"}
            }, "required": ["addr", "name"]})
        },
        handler: |frontend, args| frontend.tool_rename_symbol(args),
    },
    ToolSpec {
        name: "define_struct",
        description: "Attach or overwrite a structure definition on an address.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "definition": {"type": "string", "description": "Structure definition text"}
            }, "required": ["addr", "definition"]})
        },
        handler: |frontend, args| frontend.tool_define_struct(args),
    },
    ToolSpec {
        name: "add_hypothesis",
        description: "Record a semantic hypothesis on an address. Duplicate notes are ignored.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "note": {"type": "string", "description": "Hypothesis or analyst note"}
            }, "required": ["addr", "note"]})
        },
        handler: |frontend, args| frontend.tool_add_hypothesis(args),
    },
    ToolSpec {
        name: "search_analysis_names",
        description: "Search analysis names attached to addresses using a regex pattern.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "pattern": {"type": "string", "description": "Regex pattern matched against analysis names"}
            }, "required": ["pattern"]})
        },
        handler: |frontend, args| frontend.tool_search_analysis_names(args),
    },
    ToolSpec {
        name: "get_blackboard_entry",
        description: "Look up all semantic context recorded for an address: symbol name, struct definition, hypotheses, and containing function. Use to inspect what the blackboard knows about a specific address.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Address to look up in hex"}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_blackboard_entry(args),
    },
    ToolSpec {
        name: "get_il",
        description: "Get the lifted AeonIL intermediate language listing for the function containing a given address.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_il(args),
    },
    ToolSpec {
        name: "get_function_il",
        description: "Backwards-compatible alias for get_il.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_function_il(args),
    },
    ToolSpec {
        name: "get_reduced_il",
        description: "Return block-structured reduced AeonIL for the function containing a given address.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_reduced_il(args),
    },
    ToolSpec {
        name: "get_ssa",
        description: "Return reduced SSA form for the function containing a given address, optionally optimized.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"},
                "optimize": {"type": "boolean", "description": "Run SSA optimization passes before returning JSON", "default": true}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_ssa(args),
    },
    ToolSpec {
        name: "get_stack_frame",
        description: "Summarize the detected stack frame and visible stack-slot accesses for the function containing a given address.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_stack_frame(args),
    },
    ToolSpec {
        name: "get_function_cfg",
        description: "Get the Control Flow Graph for a function. Returns adjacency list, terminal blocks, and reachability from Datalog analysis.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Function address in hex"}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_function_cfg(args),
    },
    ToolSpec {
        name: "get_function_skeleton",
        description: "Get a dense summary of function properties for efficient triage: argument count, calls, strings, loops, crypto constants, stack frame size, and suspicious patterns.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Function address in hex"}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_function_skeleton(args),
    },
    ToolSpec {
        name: "get_data_flow_slice",
        description: "Trace value flow for a register backward or forward through a function: backward shows where a value comes from, forward shows where it goes. Detects data dependencies through assignments and control flow.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Instruction address in hex, e.g. '0x5e611fc'"},
                "register": {"type": "string", "description": "Register name (e.g., 'x0', 'w1', 'sp')"},
                "direction": {"type": "string", "enum": ["backward", "forward"], "description": "Direction of data flow to trace"}
            }, "required": ["addr", "register", "direction"]})
        },
        handler: |frontend, args| frontend.tool_get_data_flow_slice(args),
    },
    ToolSpec {
        name: "get_xrefs",
        description: "Get cross-references for an address: outgoing calls from the function, and incoming calls from other functions.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Function address in hex"}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_xrefs(args),
    },
    ToolSpec {
        name: "execute_datalog",
        description: "Run a named Datalog query over a function or the whole binary. Returns structured facts derived by the ascent Datalog engine from lifted AeonIL.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "query": {"type": "string", "enum": ["reachability", "defines", "reads_mem", "writes_mem", "flows_to", "call_graph", "call_graph_transitive"], "description": "Named Datalog query to execute"},
                "addr": {"type": "string", "description": "Virtual address in hex. For per-function queries, identifies the function. For cross-function queries, identifies the root function."},
                "register": {"type": "string", "description": "Register name (e.g. 'x0', 'w1', 'sp'). Required for 'defines' and 'flows_to' queries."},
                "limit": {"type": "integer", "description": "Maximum number of result tuples to return", "default": 500}
            }, "required": ["query", "addr"]})
        },
        handler: |frontend, args| frontend.tool_execute_datalog(args),
    },
    ToolSpec {
        name: "scan_pointers",
        description: "Scan non-executable mapped sections for pointer-sized values that reference other locations in the binary, classifying data-to-data and data-to-code edges.",
        input_schema: || {
            json!({"type": "object", "properties": {}})
        },
        handler: |frontend, _args| frontend.tool_scan_pointers(),
    },
    ToolSpec {
        name: "scan_vtables",
        description: "Detect candidate C++ vtables in .rodata/.data-style sections by finding arrays of function pointers and grouping related tables.",
        input_schema: || {
            json!({"type": "object", "properties": {}})
        },
        handler: |frontend, _args| frontend.tool_scan_vtables(),
    },
    ToolSpec {
        name: "get_function_pointers",
        description: "Enumerate pointer-valued operands and resolved code/data references for one function or a paginated slice of functions.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Optional function address in hex; when present, analyzes the containing function"},
                "offset": {"type": "integer", "description": "Start index when scanning multiple functions", "default": 0},
                "limit": {"type": "integer", "description": "Max functions to analyze when addr is omitted", "default": 50}
            }})
        },
        handler: |frontend, args| frontend.tool_get_function_pointers(args),
    },
    ToolSpec {
        name: "find_call_paths",
        description: "Find shortest and optionally all bounded call-graph paths between two functions using direct calls and vtable-resolved indirect calls.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Start function address in hex"},
                "goal_addr": {"type": "string", "description": "Goal function address in hex"},
                "max_depth": {"type": "integer", "description": "Maximum call depth to explore", "default": 6},
                "include_all_paths": {"type": "boolean", "description": "Include all simple paths up to max_depth", "default": false},
                "max_paths": {"type": "integer", "description": "Maximum number of paths to return when include_all_paths is true", "default": 32}
            }, "required": ["start_addr", "goal_addr"]})
        },
        handler: |frontend, args| frontend.tool_find_call_paths(args),
    },
    ToolSpec {
        name: "get_bytes",
        description: "Read raw bytes from the binary at a virtual address. Returns hex-encoded string.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "size": {"type": "integer", "description": "Number of bytes", "default": 64}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_bytes(args),
    },
    ToolSpec {
        name: "search_rc4",
        description: "Search for RC4 cipher implementations using Datalog behavioral subgraph isomorphism. Detects KSA (swap+256+mod256) and PRGA (swap+keystream XOR) patterns.",
        input_schema: || {
            json!({"type": "object", "properties": {}})
        },
        handler: |frontend, _args| frontend.tool_search_rc4(),
    },
    ToolSpec {
        name: "get_coverage",
        description: "Get IL lift coverage statistics: proper IL vs intrinsic vs nop vs decode errors.",
        input_schema: || {
            json!({"type": "object", "properties": {}})
        },
        handler: |frontend, _args| frontend.tool_get_coverage(),
    },
    ToolSpec {
        name: "get_asm",
        description: "Disassemble ARM64 instructions between two virtual addresses. Returns asm only, without AeonIL.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Start virtual address in hex, e.g. '0x512025c'"},
                "stop_addr": {"type": "string", "description": "Stop virtual address in hex (exclusive), e.g. '0x51202cc'"}
            }, "required": ["start_addr", "stop_addr"]})
        },
        handler: |frontend, args| frontend.tool_get_asm(args),
    },
    ToolSpec {
        name: "get_function_at",
        description: "Find the function containing a given address. Returns function metadata by default, and can optionally attach asm and/or AeonIL listings.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"},
                "include_asm": {"type": "boolean", "description": "Include asm in the returned listing", "default": false},
                "include_il": {"type": "boolean", "description": "Include AeonIL in the returned listing", "default": false}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_function_at(args),
    },
    ToolSpec {
        name: "get_string",
        description: "Read a null-terminated string at any virtual address (works across all ELF segments, not just .text).",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "max_len": {"type": "integer", "description": "Max bytes to scan for null terminator", "default": 256}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_string(args),
    },
    ToolSpec {
        name: "get_data",
        description: "Read raw bytes at any virtual address (works across all ELF segments). Returns hex + ASCII.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "size": {"type": "integer", "description": "Number of bytes to read", "default": 64}
            }, "required": ["addr"]})
        },
        handler: |frontend, args| frontend.tool_get_data(args),
    },
    ToolSpec {
        name: "emulate_snippet_il",
        description: "Execute an ARM64 code region using AeonIL interpretation. Executes lifted IL statements without full binary emulation. Useful for symbolic execution or analyzing stripped code.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Hex address to begin execution, e.g. '0x1234'"},
                "end_addr": {"type": "string", "description": "Hex address to stop execution (exclusive)"},
                "initial_registers": {"type": "object", "description": "Register values at entry. Keys: x0-x30, sp. Values: hex strings or integers.", "additionalProperties": {}},
                "step_limit": {"type": "integer", "description": "Max IL statements to execute (default 1000)", "default": 1000}
            }, "required": ["start_addr", "end_addr"]})
        },
        handler: |frontend, args| frontend.tool_emulate_snippet_il(args),
    },
    ToolSpec {
        name: "emulate_snippet_native",
        description: "Execute an ARM64 code region in unicorn ARM64 sandbox. Full native emulation with memory support. Returns final register state, memory writes, and decoded strings.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Hex address to begin execution, e.g. '0x1234'"},
                "end_addr": {"type": "string", "description": "Hex address to stop execution (exclusive)"},
                "initial_registers": {"type": "object", "description": "Register values at entry. Keys: x0-x30, sp, pc, nzcv. Values: hex strings or integers.", "additionalProperties": {}},
                "initial_memory": {"type": "object", "description": "Memory overlays. Keys: hex addresses. Values: hex string or array of bytes.", "additionalProperties": {}},
                "step_limit": {"type": "integer", "description": "Max instructions to execute (default 1000)", "default": 1000}
            }, "required": ["start_addr", "end_addr"]})
        },
        handler: |frontend, args| frontend.tool_emulate_snippet_native(args),
    },
    ToolSpec {
        name: "emulate_snippet",
        description: "Execute an ARM64 code region in a bounded sandbox. Alias for emulate_snippet_native. Returns final register state, memory writes, and any decoded strings. Use for reversing obfuscated loops, string decryption, or format decoders.",
        input_schema: || {
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Hex address to begin execution, e.g. '0x1234'"},
                "end_addr": {"type": "string", "description": "Hex address to stop execution (exclusive)"},
                "initial_registers": {"type": "object", "description": "Register values at entry. Keys: x0-x30, sp, pc, nzcv. Values: hex strings or integers.", "additionalProperties": {}},
                "initial_memory": {"type": "object", "description": "Memory overlays. Keys: hex addresses. Values: hex string or array of bytes.", "additionalProperties": {}},
                "step_limit": {"type": "integer", "description": "Max instructions to execute (default 1000)", "default": 1000}
            }, "required": ["start_addr", "end_addr"]})
        },
        handler: |frontend, args| frontend.tool_emulate_snippet_native(args),
    },
    ToolSpec {
        name: "emulate_snippet_native_advanced",
        description: "Execute an ARM64 code region with advanced features: memory watchpoints, instruction hooks with register patching, PC tracing, and extended register state (SIMD).",
        input_schema: || {
            build_advanced_emulation_schema()
        },
        handler: |frontend, args| frontend.tool_emulate_snippet_native_advanced(args),
    },
];

/// The tools as the MCP `tools/list` result.
pub fn tools_list() -> Value {
    let tools: Vec<Value> = TOOLS
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema(),
            })
        })
        .collect();
    json!({ "tools": tools })
}

fn build_advanced_emulation_schema() -> Value {
    let mut props = serde_json::Map::new();
    props.insert("start_addr".to_string(), json!({"type": "string", "description": "Hex address to begin execution, e.g. '0x1234'"}));
    props.insert("end_addr".to_string(), json!({"type": "string", "description": "Hex address to stop execution (exclusive)"}));
    props.insert("initial_registers".to_string(), json!({"type": "object", "description": "Register values at entry. Keys: x0-x30, sp, pc, nzcv. Values: hex strings or integers.", "additionalProperties": {}}));
    props.insert("initial_memory".to_string(), json!({"type": "object", "description": "Memory overlays. Keys: hex addresses. Values: hex string or array of bytes.", "additionalProperties": {}}));
    props.insert("step_limit".to_string(), json!({"type": "integer", "description": "Max instructions to execute (default 1000)", "default": 1000}));

    let wpt_patch = json!({"type": "object", "properties": {
        "name": {"type": "string", "description": "Register name (x0-x30, sp, pc, nzcv)"},
        "value": {"type": "string", "description": "Value in hex"}
    }, "required": ["name", "value"]});

    let wpt_item = json!({"type": "object", "properties": {
        "addr": {"type": "string", "description": "Watchpoint address in hex"},
        "size": {"type": "integer", "description": "Range size (default 8)"},
        "on_read": {"type": "boolean", "description": "Trigger on reads (default false)"},
        "on_write": {"type": "boolean", "description": "Trigger on writes (default true)"},
        "stop_on_hit": {"type": "boolean", "description": "Stop execution on hit (default false)"}
    }, "required": ["addr"]});

    let hook_item = json!({"type": "object", "properties": {
        "addr": {"type": "string", "description": "Hook address in hex"},
        "stop_on_hit": {"type": "boolean", "description": "Stop execution on hit (default false)"},
        "patches": {"type": "array", "description": "Register patches to apply", "items": wpt_patch}
    }, "required": ["addr"]});

    props.insert("watchpoints".to_string(), json!({"type": "array", "description": "Memory watchpoints to track", "items": wpt_item}));
    props.insert("address_hooks".to_string(), json!({"type": "array", "description": "Instruction hooks with optional register patches", "items": hook_item}));
    props.insert("record_pc_trace".to_string(), json!({"type": "boolean", "description": "Record visited PC values (default false)"}));

    json!({"type": "object", "properties": props, "required": ["start_addr", "end_addr"]})
}

pub fn tools_markdown_table() -> String {
    let mut lines = vec![
        "| Tool | Description |".to_string(),
        "|------|-------------|".to_string(),
    ];

    for tool in TOOLS {
        lines.push(format!(
            "| `{}` | {} |",
            escape_markdown_cell(tool.name),
            escape_markdown_cell(tool.description)
        ));
    }

    lines.join("\n")
}

fn parse_addr_arg(args: &Value) -> Result<u64, ArgError> {
    let s = args
        .get("addr")
        .and_then(|value| value.as_str())
        .ok_or("Missing required parameter: addr")?;
    Ok(parse_hex(s).ok_or_else(|| format!("Invalid hex address: {}", s))?)
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}

fn parse_bool_arg(args: &Value, key: &str, default: bool) -> Result<bool, ArgError> {
    match args.get(key) {
        Some(value) => Ok(value
            .as_bool()
            .ok_or_else(|| format!("Invalid boolean parameter: {}", key))?),
        None => Ok(default),
    }
}

fn parse_hex_arg(args: &Value, key: &str) -> Result<u64, ArgError> {
    let s = args
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("Missing required parameter: {}", key))?;
    Ok(parse_hex(s).ok_or_else(|| format!("Invalid hex address for {}: {}", key, s))?)
}

fn parse_register_map(args: &Value) -> Result<std::collections::HashMap<String, u64>, ArgError> {
    use std::collections::HashMap;
    let mut result = HashMap::new();

    if let Some(regs) = args.get("initial_registers").and_then(|v| v.as_object()) {
        for (name, value) in regs {
            let val = if let Some(s) = value.as_str() {
                parse_hex(s).ok_or_else(|| format!("Invalid hex value for register {}: {}", name, s))?
            } else if let Some(n) = value.as_u64() {
                n
            } else {
                return Err(format!("Invalid register value for {}: expected hex string or integer", name).into());
            };
            result.insert(name.clone(), val);
        }
    }

    Ok(result)
}

fn parse_memory_map(args: &Value) -> Result<std::collections::HashMap<u64, Vec<u8>>, ArgError> {
    use std::collections::HashMap;
    let mut result = HashMap::new();

    if let Some(mem) = args.get("initial_memory").and_then(|v| v.as_object()) {
        for (addr_str, value) in mem {
            let addr = parse_hex(addr_str)
                .ok_or_else(|| format!("Invalid hex address for memory: {}", addr_str))?;

            let bytes = if let Some(s) = value.as_str() {
                // Parse hex string
                let hex_str = s.trim_start_matches("0x").trim_start_matches("0X");
                let num = u64::from_str_radix(hex_str, 16)
                    .map_err(|_| format!("Invalid hex value: {}", s))?;
                // Convert u64 to little-endian bytes
                num.to_le_bytes().to_vec()
            } else if let Some(arr) = value.as_array() {
                // Parse array of bytes
                let mut bytes = Vec::new();
                for item in arr {
                    let byte = item.as_u64()
                        .ok_or_else(|| format!("Invalid byte value in memory array"))?
                        as u8;
                    bytes.push(byte);
                }
                bytes
            } else {
                return Err(format!("Invalid memory value at {}: expected hex string or array of bytes", addr_str).into());
            };

            result.insert(addr, bytes);
        }
    }

    Ok(result)
}

fn parse_watchpoints(args: &Value) -> Result<Vec<aeon::sandbox::WatchpointSpec>, ArgError> {
    let mut result = Vec::new();

    if let Some(watchpoints) = args.get("watchpoints").and_then(|v| v.as_array()) {
        for (idx, wpt) in watchpoints.iter().enumerate() {
            let obj = wpt.as_object()
                .ok_or_else(|| format!("Watchpoint {} must be an object", idx))?;

            let addr = obj.get("addr")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Watchpoint {} missing addr", idx))
                .and_then(|s| parse_hex(s).ok_or_else(|| format!("Invalid addr for watchpoint {}", idx)))?;

            let size = obj.get("size")
                .and_then(|v| v.as_u64())
                .unwrap_or(8);

            let on_read = obj.get("on_read")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let on_write = obj.get("on_write")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let stop_on_hit = obj.get("stop_on_hit")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            result.push(aeon::sandbox::WatchpointSpec {
                addr,
                size,
                on_read,
                on_write,
                stop_on_hit,
            });
        }
    }

    Ok(result)
}

fn parse_address_hooks(args: &Value) -> Result<Vec<aeon::sandbox::AddressHookSpec>, ArgError> {
    let mut result = Vec::new();

    if let Some(hooks) = args.get("address_hooks").and_then(|v| v.as_array()) {
        for (idx, hook) in hooks.iter().enumerate() {
            let obj = hook.as_object()
                .ok_or_else(|| format!("Address hook {} must be an object", idx))?;

            let addr = obj.get("addr")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Address hook {} missing addr", idx))
                .and_then(|s| parse_hex(s).ok_or_else(|| format!("Invalid addr for hook {}", idx)))?;

            let stop_on_hit = obj.get("stop_on_hit")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let mut patches = Vec::new();
            if let Some(patch_array) = obj.get("patches").and_then(|v| v.as_array()) {
                for (pidx, patch) in patch_array.iter().enumerate() {
                    let patch_obj = patch.as_object()
                        .ok_or_else(|| format!("Patch {} in hook {} must be an object", pidx, idx))?;

                    let name = patch_obj.get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("Patch {} in hook {} missing name", pidx, idx))?
                        .to_string();

                    let value = patch_obj.get("value")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("Patch {} in hook {} missing value", pidx, idx))
                        .and_then(|s| parse_hex(s).ok_or_else(|| format!("Invalid value for patch {} in hook {}", pidx, idx)))?;

                    patches.push(aeon::sandbox::RegisterPatch { name, value });
                }
            }

            result.push(aeon::sandbox::AddressHookSpec {
                addr,
                stop_on_hit,
                patches,
            });
        }
    }

    Ok(result)
}

fn escape_markdown_cell(value: &str) -> String {
    value.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::{json, Value};

    use super::{tools_list, tools_markdown_table, AeonFrontend, ErrorCode, TOOLS};

    const README_BEGIN: &str = "<!-- BEGIN GENERATED TOOL SURFACE -->";
    const README_END: &str = "<!-- END GENERATED TOOL SURFACE -->";

    fn sample_binary_path() -> String {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .join("../../samples/hello_aarch64.elf")
            .display()
            .to_string()
    }

    fn has_stack_slot(value: &Value) -> bool {
        match value {
            Value::Object(map) => {
                map.get("op")
                    .and_then(Value::as_str)
                    .is_some_and(|op| op == "stack_slot")
                    || map.values().any(has_stack_slot)
            }
            Value::Array(items) => items.iter().any(has_stack_slot),
            _ => false,
        }
    }

    #[test]
    fn readme_tool_surface_matches_generated_table() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let readme_path = manifest_dir.join("../../README.md");
        let readme = std::fs::read_to_string(&readme_path).expect("failed to read README.md");

        let start = readme
            .find(README_BEGIN)
            .expect("missing tool surface start marker");
        let after_start = start + README_BEGIN.len();
        let rest = &readme[after_start..];
        let end_rel = rest
            .find(README_END)
            .expect("missing tool surface end marker");
        let actual = rest[..end_rel].trim();
        let expected = tools_markdown_table();

        assert_eq!(
            actual, expected,
            "README tool surface is out of date; regenerate it from tools_markdown_table()"
        );
    }

    #[test]
    fn tools_list_registers_reduction_tools() {
        let tool_list = tools_list();
        let tools = tool_list["tools"]
            .as_array()
            .expect("tools list should be an array");

        assert!(tools.iter().any(|tool| tool["name"] == "get_reduced_il"));
        assert!(tools.iter().any(|tool| tool["name"] == "get_ssa"));
        assert!(tools.iter().any(|tool| tool["name"] == "get_stack_frame"));
    }

    #[test]
    fn frontend_call_tool_smoke_for_reduction_artifacts() {
        let mut frontend = AeonFrontend::new();
        frontend
            .call_tool("load_binary", &json!({ "path": sample_binary_path() }))
            .expect("sample binary should load");

        let reduced = frontend
            .call_tool("get_reduced_il", &json!({ "addr": "0x718" }))
            .expect("reduced IL should succeed");
        assert_eq!(reduced["artifact"], "reduced_il");
        assert!(has_stack_slot(&reduced));

        let ssa = frontend
            .call_tool("get_ssa", &json!({ "addr": "0x718", "optimize": true }))
            .expect("SSA should succeed");
        assert_eq!(ssa["artifact"], "ssa");
        assert_eq!(ssa["optimized"], true);

        let frame = frontend
            .call_tool("get_stack_frame", &json!({ "addr": "0x718" }))
            .expect("stack frame should succeed");
        assert_eq!(frame["artifact"], "stack_frame");
        assert_eq!(frame["detected"], true);
        assert!(
            frame["slots"]
                .as_array()
                .is_some_and(|slots| !slots.is_empty()),
            "stack frame output should expose stack-slot summaries"
        );
    }

    #[test]
    fn every_listed_tool_is_callable_and_named_once() {
        let listed = tools_list();
        let listed = listed["tools"].as_array().expect("tools array");
        assert_eq!(listed.len(), TOOLS.len());

        let mut names = std::collections::HashSet::new();
        let mut frontend = AeonFrontend::new();
        for tool in TOOLS {
            assert!(names.insert(tool.name), "duplicate tool {}", tool.name);
            assert!(!tool.description.is_empty(), "{} has no description", tool.name);
            assert_eq!(
                tool.input_schema()["type"],
                "object",
                "{} schema is not an object",
                tool.name
            );
            // With no binary loaded and no arguments a tool must fail, but
            // never because it is unknown.
            let error = frontend
                .call_tool_typed(tool.name, &json!({}))
                .expect_err("no binary is loaded");
            assert_ne!(error.code, ErrorCode::UnknownTool, "{}", tool.name);
        }
    }

    #[test]
    fn errors_carry_stable_codes() {
        let mut frontend = AeonFrontend::new();
        let code = |frontend: &mut AeonFrontend, name: &str, args: Value| {
            frontend
                .call_tool_typed(name, &args)
                .expect_err("call should fail")
                .code
        };

        assert_eq!(code(&mut frontend, "no_such_tool", json!({})), ErrorCode::UnknownTool);
        assert_eq!(
            code(&mut frontend, "get_il", json!({ "addr": "0x718" })),
            ErrorCode::NoBinaryLoaded
        );
        assert_eq!(code(&mut frontend, "load_binary", json!({})), ErrorCode::InvalidArgument);
        assert_eq!(
            code(&mut frontend, "load_binary", json!({ "path": "x", "format": "pe" })),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            code(&mut frontend, "load_binary", json!({ "path": "/nonexistent/binary" })),
            ErrorCode::Analysis
        );

        frontend
            .call_tool("load_binary", &json!({ "path": sample_binary_path() }))
            .expect("sample binary should load");
        assert_eq!(code(&mut frontend, "get_il", json!({})), ErrorCode::InvalidArgument);
        assert_eq!(
            code(&mut frontend, "get_il", json!({ "addr": "zzz" })),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            code(&mut frontend, "get_ssa", json!({ "addr": "0x718", "optimize": "yes" })),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            code(&mut frontend, "get_reduced_il", json!({ "addr": "0xffffffff" })),
            ErrorCode::Analysis
        );

        // The string forms are what clients see; they must stay distinct.
        let strings: std::collections::HashSet<_> =
            ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
        assert_eq!(strings.len(), ErrorCode::ALL.len());
    }

    #[test]
    fn emulate_snippet_in_tools_list() {
        let tool_list = tools_list();
        let tools = tool_list["tools"]
            .as_array()
            .expect("tools list should be an array");

        let emulate_tool = tools
            .iter()
            .find(|tool| tool.get("name").and_then(|n| n.as_str()) == Some("emulate_snippet"))
            .expect("emulate_snippet tool should be registered");

        assert!(emulate_tool["description"]
            .as_str()
            .unwrap()
            .contains("Execute an ARM64 code region"));

        let schema = &emulate_tool["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"].get("start_addr").is_some());
        assert!(schema["properties"].get("end_addr").is_some());
        assert!(schema["properties"].get("step_limit").is_some());
    }
}
