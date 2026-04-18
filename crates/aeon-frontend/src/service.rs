use serde_json::{json, Value};

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

    pub fn call_tool(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
            "load_binary" => self.tool_load_binary(args),
            "list_functions" => self.tool_list_functions(args),
            "set_analysis_name" => self.tool_set_analysis_name(args),
            "rename_symbol" => self.tool_rename_symbol(args),
            "define_struct" => self.tool_define_struct(args),
            "add_hypothesis" => self.tool_add_hypothesis(args),
            "search_analysis_names" => self.tool_search_analysis_names(args),
            "get_blackboard_entry" => self.tool_get_blackboard_entry(args),
            "get_il" => self.tool_get_il(args),
            "get_function_il" => self.tool_get_function_il(args),
            "get_reduced_il" => self.tool_get_reduced_il(args),
            "get_ssa" => self.tool_get_ssa(args),
            "get_stack_frame" => self.tool_get_stack_frame(args),
            "get_function_cfg" => self.tool_get_function_cfg(args),
            "get_function_skeleton" => self.tool_get_function_skeleton(args),
            "get_xrefs" => self.tool_get_xrefs(args),
            "scan_pointers" => self.tool_scan_pointers(),
            "scan_vtables" => self.tool_scan_vtables(),
            "get_function_pointers" => self.tool_get_function_pointers(args),
            "find_call_paths" => self.tool_find_call_paths(args),
            "get_bytes" => self.tool_get_bytes(args),
            "search_rc4" => self.tool_search_rc4(),
            "get_coverage" => self.tool_get_coverage(),
            "get_asm" => self.tool_get_asm(args),
            "get_function_at" => self.tool_get_function_at(args),
            "get_string" => self.tool_get_string(args),
            "get_data" => self.tool_get_data(args),
            "emulate_snippet" => self.tool_emulate_snippet(args),
            _ => Err(format!("Unknown tool: {}", name)),
        }
    }

    fn require_session(&self) -> Result<&aeon::AeonSession, String> {
        self.session
            .as_ref()
            .ok_or("No binary loaded. Call load_binary first.".into())
    }

    fn tool_load_binary(&mut self, args: &Value) -> Result<Value, String> {
        let path = args
            .get("path")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: path")?;
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
                    .ok_or("Missing required parameter for raw binaries: base_addr")?;
                let base_addr = parse_hex(base_addr)
                    .ok_or_else(|| format!("Invalid hex address for base_addr: {}", base_addr))?;
                aeon::AeonSession::load_raw(path, base_addr)
                    .map_err(|e| format!("Failed to load raw binary: {}", e))?
            }
            other => {
                return Err(format!(
                    "Unsupported binary format: {} (expected 'elf' or 'raw')",
                    other
                ))
            }
        };
        let result = session.summary();
        self.session = Some(session);
        Ok(result)
    }

    fn tool_list_functions(&self, args: &Value) -> Result<Value, String> {
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

    fn tool_set_analysis_name(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let name = args
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: name")?;
        Ok(session.set_analysis_name(addr, name))
    }

    fn tool_rename_symbol(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let name = args
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: name")?;
        Ok(session.rename_symbol(addr, name))
    }

    fn tool_define_struct(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let definition = args
            .get("definition")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: definition")?;
        Ok(session.define_struct(addr, definition))
    }

    fn tool_add_hypothesis(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let note = args
            .get("note")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: note")?;
        Ok(session.add_hypothesis(addr, note))
    }

    fn tool_search_analysis_names(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let pattern = args
            .get("pattern")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: pattern")?;
        session.search_analysis_names(pattern)
    }

    fn tool_get_blackboard_entry(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_blackboard_entry(addr))
    }

    fn tool_get_function_il(&self, args: &Value) -> Result<Value, String> {
        self.tool_get_il(args)
    }

    fn tool_get_reduced_il(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        session.get_reduced_il(addr)
    }

    fn tool_get_ssa(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let optimize = parse_bool_arg(args, "optimize", true)?;
        session.get_ssa(addr, optimize)
    }

    fn tool_get_stack_frame(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        session.get_stack_frame(addr)
    }

    fn tool_get_il(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        session.get_il(addr)
    }

    fn tool_get_function_cfg(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        session.get_function_cfg(addr)
    }

    fn tool_get_function_skeleton(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        session.get_function_skeleton(addr)
    }

    fn tool_get_xrefs(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_xrefs(addr))
    }

    fn tool_scan_pointers(&self) -> Result<Value, String> {
        let session = self.require_session()?;
        Ok(session.scan_pointers())
    }

    fn tool_scan_vtables(&self) -> Result<Value, String> {
        let session = self.require_session()?;
        Ok(session.scan_vtables())
    }

    fn tool_get_function_pointers(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = match args.get("addr").and_then(|value| value.as_str()) {
            Some(value) => {
                Some(parse_hex(value).ok_or_else(|| format!("Invalid hex address: {}", value))?)
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
        session.scan_function_pointers(addr, offset, limit)
    }

    fn tool_find_call_paths(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let start_str = args
            .get("start_addr")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: start_addr")?;
        let goal_str = args
            .get("goal_addr")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: goal_addr")?;
        let start_addr =
            parse_hex(start_str).ok_or_else(|| format!("Invalid hex address: {}", start_str))?;
        let goal_addr =
            parse_hex(goal_str).ok_or_else(|| format!("Invalid hex address: {}", goal_str))?;
        let max_depth = args
            .get("max_depth")
            .and_then(|value| value.as_u64())
            .unwrap_or(6) as usize;
        let include_all_paths = parse_bool_arg(args, "include_all_paths", false)?;
        let max_paths = args
            .get("max_paths")
            .and_then(|value| value.as_u64())
            .unwrap_or(32) as usize;
        session.find_call_paths(
            start_addr,
            goal_addr,
            max_depth,
            include_all_paths,
            max_paths,
        )
    }

    fn tool_get_bytes(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let size = args
            .get("size")
            .and_then(|value| value.as_u64())
            .unwrap_or(64) as usize;
        session.get_bytes(addr, size)
    }

    fn tool_search_rc4(&self) -> Result<Value, String> {
        let session = self.require_session()?;
        Ok(session.search_rc4())
    }

    fn tool_get_coverage(&self) -> Result<Value, String> {
        let session = self.require_session()?;
        Ok(session.get_coverage())
    }

    fn tool_get_asm(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let start_str = args
            .get("start_addr")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: start_addr")?;
        let stop_str = args
            .get("stop_addr")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: stop_addr")?;

        let start_addr =
            parse_hex(start_str).ok_or_else(|| format!("Invalid hex address: {}", start_str))?;
        let stop_addr =
            parse_hex(stop_str).ok_or_else(|| format!("Invalid hex address: {}", stop_str))?;
        session.get_asm(start_addr, stop_addr)
    }

    fn tool_get_function_at(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let include_asm = parse_bool_arg(args, "include_asm", false)?;
        let include_il = parse_bool_arg(args, "include_il", false)?;
        session.get_function_at(addr, include_asm, include_il)
    }

    fn tool_get_string(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let max_len = args
            .get("max_len")
            .and_then(|value| value.as_u64())
            .unwrap_or(256) as usize;
        session.get_string(addr, max_len)
    }

    fn tool_get_data(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let size = args
            .get("size")
            .and_then(|value| value.as_u64())
            .unwrap_or(64) as usize;
        session.get_data(addr, size)
    }

    fn tool_emulate_snippet(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let start_addr = parse_addr_arg(args)?;
        let end_addr = parse_hex_arg(args, "end_addr")?;
        let step_limit = args
            .get("step_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        let initial_registers = parse_register_map(args)?;
        let initial_memory = parse_memory_map(args)?;

        session.emulate_snippet(start_addr, end_addr, initial_registers, initial_memory, step_limit)
    }
}

pub fn tools_list() -> Value {
    json!({
        "tools": [
            tool_schema("load_binary",
                "Load an ELF or raw AArch64 binary for analysis. Must be called before other tools.",
                json!({"type": "object", "properties": {
                    "path": {"type": "string", "description": "Path to binary"},
                    "format": {"type": "string", "description": "Binary format: 'elf' or 'raw'", "default": "elf"},
                    "base_addr": {"type": "string", "description": "Required for raw binaries: virtual base address in hex"}
                }, "required": ["path"]})),

            tool_schema("list_functions",
                "List functions discovered from .eh_frame unwind tables. Supports pagination and name filtering.",
                json!({"type": "object", "properties": {
                    "offset": {"type": "integer", "description": "Start index", "default": 0},
                    "limit": {"type": "integer", "description": "Max results", "default": 100},
                    "name_filter": {"type": "string", "description": "Substring filter on symbol name"}
                }})),

            tool_schema("set_analysis_name",
                "Backwards-compatible alias for rename_symbol. Attaches or overwrites a semantic symbol on an address.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Virtual address in hex"},
                    "name": {"type": "string", "description": "Analysis name to assign to the address"}
                }, "required": ["addr", "name"]})),

            tool_schema("rename_symbol",
                "Attach or overwrite a semantic symbol name on an address.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Virtual address in hex"},
                    "name": {"type": "string", "description": "Semantic symbol name to assign to the address"}
                }, "required": ["addr", "name"]})),

            tool_schema("define_struct",
                "Attach or overwrite a structure definition on an address.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Virtual address in hex"},
                    "definition": {"type": "string", "description": "Structure definition text"}
                }, "required": ["addr", "definition"]})),

            tool_schema("add_hypothesis",
                "Record a semantic hypothesis on an address. Duplicate notes are ignored.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Virtual address in hex"},
                    "note": {"type": "string", "description": "Hypothesis or analyst note"}
                }, "required": ["addr", "note"]})),

            tool_schema("search_analysis_names",
                "Search analysis names attached to addresses using a regex pattern.",
                json!({"type": "object", "properties": {
                    "pattern": {"type": "string", "description": "Regex pattern matched against analysis names"}
                }, "required": ["pattern"]})),

            tool_schema("get_blackboard_entry",
                "Look up all semantic context recorded for an address: symbol name, struct definition, hypotheses, and containing function. Use to inspect what the blackboard knows about a specific address.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Address to look up in hex"}
                }, "required": ["addr"]})),

            tool_schema("get_il",
                "Get the lifted AeonIL intermediate language listing for the function containing a given address.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
                }, "required": ["addr"]})),

            tool_schema("get_function_il",
                "Backwards-compatible alias for get_il.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
                }, "required": ["addr"]})),

            tool_schema("get_reduced_il",
                "Return block-structured reduced AeonIL for the function containing a given address.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
                }, "required": ["addr"]})),

            tool_schema("get_ssa",
                "Return reduced SSA form for the function containing a given address, optionally optimized.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"},
                    "optimize": {"type": "boolean", "description": "Run SSA optimization passes before returning JSON", "default": true}
                }, "required": ["addr"]})),

            tool_schema("get_stack_frame",
                "Summarize the detected stack frame and visible stack-slot accesses for the function containing a given address.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
                }, "required": ["addr"]})),

            tool_schema("get_function_cfg",
                "Get the Control Flow Graph for a function. Returns adjacency list, terminal blocks, and reachability from Datalog analysis.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Function address in hex"}
                }, "required": ["addr"]})),

            tool_schema("get_function_skeleton",
                "Get a dense summary of function properties for efficient triage: argument count, calls, strings, loops, crypto constants, stack frame size, and suspicious patterns.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Function address in hex"}
                }, "required": ["addr"]})),

            tool_schema("get_xrefs",
                "Get cross-references for an address: outgoing calls from the function, and incoming calls from other functions.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Function address in hex"}
                }, "required": ["addr"]})),

            tool_schema("scan_pointers",
                "Scan non-executable mapped sections for pointer-sized values that reference other locations in the binary, classifying data-to-data and data-to-code edges.",
                json!({"type": "object", "properties": {}})),

            tool_schema("scan_vtables",
                "Detect candidate C++ vtables in .rodata/.data-style sections by finding arrays of function pointers and grouping related tables.",
                json!({"type": "object", "properties": {}})),

            tool_schema("get_function_pointers",
                "Enumerate pointer-valued operands and resolved code/data references for one function or a paginated slice of functions.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Optional function address in hex; when present, analyzes the containing function"},
                    "offset": {"type": "integer", "description": "Start index when scanning multiple functions", "default": 0},
                    "limit": {"type": "integer", "description": "Max functions to analyze when addr is omitted", "default": 50}
                }})),

            tool_schema("find_call_paths",
                "Find shortest and optionally all bounded call-graph paths between two functions using direct calls and vtable-resolved indirect calls.",
                json!({"type": "object", "properties": {
                    "start_addr": {"type": "string", "description": "Start function address in hex"},
                    "goal_addr": {"type": "string", "description": "Goal function address in hex"},
                    "max_depth": {"type": "integer", "description": "Maximum call depth to explore", "default": 6},
                    "include_all_paths": {"type": "boolean", "description": "Include all simple paths up to max_depth", "default": false},
                    "max_paths": {"type": "integer", "description": "Maximum number of paths to return when include_all_paths is true", "default": 32}
                }, "required": ["start_addr", "goal_addr"]})),

            tool_schema("get_bytes",
                "Read raw bytes from the binary at a virtual address. Returns hex-encoded string.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Virtual address in hex"},
                    "size": {"type": "integer", "description": "Number of bytes", "default": 64}
                }, "required": ["addr"]})),

            tool_schema("search_rc4",
                "Search for RC4 cipher implementations using Datalog behavioral subgraph isomorphism. Detects KSA (swap+256+mod256) and PRGA (swap+keystream XOR) patterns.",
                json!({"type": "object", "properties": {}})),

            tool_schema("get_coverage",
                "Get IL lift coverage statistics: proper IL vs intrinsic vs nop vs decode errors.",
                json!({"type": "object", "properties": {}})),

            tool_schema("get_asm",
                "Disassemble ARM64 instructions between two virtual addresses. Returns asm only, without AeonIL.",
                json!({"type": "object", "properties": {
                    "start_addr": {"type": "string", "description": "Start virtual address in hex, e.g. '0x512025c'"},
                    "stop_addr": {"type": "string", "description": "Stop virtual address in hex (exclusive), e.g. '0x51202cc'"}
                }, "required": ["start_addr", "stop_addr"]})),

            tool_schema("get_function_at",
                "Find the function containing a given address. Returns function metadata by default, and can optionally attach asm and/or AeonIL listings.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"},
                    "include_asm": {"type": "boolean", "description": "Include asm in the returned listing", "default": false},
                    "include_il": {"type": "boolean", "description": "Include AeonIL in the returned listing", "default": false}
                }, "required": ["addr"]})),

            tool_schema("get_string",
                "Read a null-terminated string at any virtual address (works across all ELF segments, not just .text).",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Virtual address in hex"},
                    "max_len": {"type": "integer", "description": "Max bytes to scan for null terminator", "default": 256}
                }, "required": ["addr"]})),

            tool_schema("get_data",
                "Read raw bytes at any virtual address (works across all ELF segments). Returns hex + ASCII.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Virtual address in hex"},
                    "size": {"type": "integer", "description": "Number of bytes to read", "default": 64}
                }, "required": ["addr"]})),

            tool_schema("emulate_snippet",
                "Execute an ARM64 code region in a bounded sandbox. Returns final register state, memory writes, and any decoded strings. Use for reversing obfuscated loops, string decryption, or format decoders.",
                json!({"type": "object", "properties": {
                    "start_addr": {"type": "string", "description": "Hex address to begin execution, e.g. '0x1234'"},
                    "end_addr": {"type": "string", "description": "Hex address to stop execution (exclusive)"},
                    "initial_registers": {"type": "object", "description": "Register values at entry. Keys: x0-x30, sp, pc, nzcv. Values: hex strings or integers.", "additionalProperties": {}},
                    "initial_memory": {"type": "object", "description": "Memory overlays. Keys: hex addresses. Values: hex string or array of bytes.", "additionalProperties": {}},
                    "step_limit": {"type": "integer", "description": "Max instructions to execute (default 1000)", "default": 1000}
                }, "required": ["start_addr", "end_addr"]})),
        ]
    })
}

pub fn tools_markdown_table() -> String {
    let mut lines = vec![
        "| Tool | Description |".to_string(),
        "|------|-------------|".to_string(),
    ];

    if let Some(tools) = tools_list().get("tools").and_then(Value::as_array) {
        for tool in tools {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(description) = tool.get("description").and_then(Value::as_str) else {
                continue;
            };
            lines.push(format!(
                "| `{}` | {} |",
                escape_markdown_cell(name),
                escape_markdown_cell(description)
            ));
        }
    }

    lines.join("\n")
}

fn tool_schema(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema
    })
}

fn parse_addr_arg(args: &Value) -> Result<u64, String> {
    let s = args
        .get("addr")
        .and_then(|value| value.as_str())
        .ok_or("Missing required parameter: addr")?;
    parse_hex(s).ok_or_else(|| format!("Invalid hex address: {}", s))
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}

fn parse_bool_arg(args: &Value, key: &str, default: bool) -> Result<bool, String> {
    match args.get(key) {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("Invalid boolean parameter: {}", key)),
        None => Ok(default),
    }
}

fn parse_hex_arg(args: &Value, key: &str) -> Result<u64, String> {
    let s = args
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("Missing required parameter: {}", key))?;
    parse_hex(s).ok_or_else(|| format!("Invalid hex address for {}: {}", key, s))
}

fn parse_register_map(args: &Value) -> Result<std::collections::HashMap<String, u64>, String> {
    use std::collections::HashMap;
    let mut result = HashMap::new();

    if let Some(regs) = args.get("initial_registers").and_then(|v| v.as_object()) {
        for (name, value) in regs {
            let val = if let Some(s) = value.as_str() {
                parse_hex(s).ok_or_else(|| format!("Invalid hex value for register {}: {}", name, s))?
            } else if let Some(n) = value.as_u64() {
                n
            } else {
                return Err(format!("Invalid register value for {}: expected hex string or integer", name));
            };
            result.insert(name.clone(), val);
        }
    }

    Ok(result)
}

fn parse_memory_map(args: &Value) -> Result<std::collections::HashMap<u64, Vec<u8>>, String> {
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
                return Err(format!("Invalid memory value at {}: expected hex string or array of bytes", addr_str));
            };

            result.insert(addr, bytes);
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

    use super::{tools_list, tools_markdown_table, AeonFrontend};

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
