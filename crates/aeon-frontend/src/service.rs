use serde_json::{json, Value};

/// Why a tool call failed. The string form is stable: clients may branch
/// on it, while messages are for people and may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// No tool has that name.
    UnknownTool,
    /// The tool needs a binary and none is loaded.
    NoBinaryLoaded,
    /// An argument is missing, of the wrong type, not parseable, or asks
    /// for something malformed (a bad pattern, an empty range).
    InvalidArgument,
    /// Nothing is known at that address: no function, no instruction.
    NotFound,
    /// The address or range is not part of the loaded image.
    OutOfRange,
    /// The binary could not be read or parsed.
    LoadFailed,
    /// Emulation could not be set up or failed to run.
    EmulationFailed,
    /// A failure that is not the caller's doing.
    Internal,
}

impl ErrorCode {
    pub const ALL: [ErrorCode; 8] = [
        ErrorCode::UnknownTool,
        ErrorCode::NoBinaryLoaded,
        ErrorCode::InvalidArgument,
        ErrorCode::NotFound,
        ErrorCode::OutOfRange,
        ErrorCode::LoadFailed,
        ErrorCode::EmulationFailed,
        ErrorCode::Internal,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnknownTool => "unknown_tool",
            ErrorCode::NoBinaryLoaded => "no_binary_loaded",
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::NotFound => "not_found",
            ErrorCode::OutOfRange => "out_of_range",
            ErrorCode::LoadFailed => "load_failed",
            ErrorCode::EmulationFailed => "emulation_failed",
            ErrorCode::Internal => "internal",
        }
    }
}

impl From<aeon::ErrorKind> for ErrorCode {
    fn from(kind: aeon::ErrorKind) -> Self {
        match kind {
            aeon::ErrorKind::NotFound => ErrorCode::NotFound,
            aeon::ErrorKind::OutOfRange => ErrorCode::OutOfRange,
            aeon::ErrorKind::InvalidInput => ErrorCode::InvalidArgument,
            aeon::ErrorKind::Load => ErrorCode::LoadFailed,
            aeon::ErrorKind::Emulation => ErrorCode::EmulationFailed,
            aeon::ErrorKind::Internal => ErrorCode::Internal,
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

impl From<aeon::Error> for ToolError {
    fn from(error: aeon::Error) -> Self {
        Self::new(error.kind.into(), error.message)
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

use crate::requests::{
    memory_map, parse, register_map, schema_of, AddHypothesis, AtAddress, DefineStruct,
    EmulateIl, EmulateNative, EmulateNativeAdvanced, ExecuteDatalog, FindCallPaths, GetAsm,
    GetDataFlowSlice, GetFunctionAt, GetFunctionPointers, GetSsa, GetString, ListFunctions,
    LoadBinary, NameAddress, NoArgs, ReadBytes, SearchAnalysisNames,
};

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
        let tool = TOOLS.iter().find(|tool| tool.name == name).ok_or_else(|| {
            ToolError::new(ErrorCode::UnknownTool, format!("Unknown tool: {}", name))
        })?;
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

    // One method per tool. Each takes its arguments already parsed, so what
    // is left here is the call into the session.

    fn load_binary(&mut self, request: LoadBinary) -> ToolResult {
        let session = match request.format.as_str() {
            "elf" => aeon::AeonSession::load(&request.path).map_err(|e| {
                ToolError::new(e.kind.into(), format!("Failed to load ELF binary: {}", e))
            })?,
            "raw" => {
                let base_addr = request.base_addr.ok_or(ArgError::from(
                    "Missing required parameter for raw binaries: base_addr",
                ))?;
                aeon::AeonSession::load_raw(&request.path, base_addr.0).map_err(|e| {
                    ToolError::new(e.kind.into(), format!("Failed to load raw binary: {}", e))
                })?
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

    fn list_functions(&self, request: ListFunctions) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.list_functions(request.offset, request.limit, Some(&request.name_filter)))
    }

    fn rename_symbol(&self, request: NameAddress) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.rename_symbol(request.addr.0, &request.name))
    }

    fn define_struct(&self, request: DefineStruct) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.define_struct(request.addr.0, &request.definition))
    }

    fn add_hypothesis(&self, request: AddHypothesis) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.add_hypothesis(request.addr.0, &request.note))
    }

    fn search_analysis_names(&self, request: SearchAnalysisNames) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.search_analysis_names(&request.pattern)?)
    }

    fn get_blackboard_entry(&self, request: AtAddress) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_blackboard_entry(request.addr.0))
    }

    fn get_il(&self, request: AtAddress) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_il(request.addr.0)?)
    }

    fn get_reduced_il(&self, request: AtAddress) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_reduced_il(request.addr.0)?)
    }

    fn get_ssa(&self, request: GetSsa) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_ssa(request.addr.0, request.optimize)?)
    }

    fn get_stack_frame(&self, request: AtAddress) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_stack_frame(request.addr.0)?)
    }

    fn get_function_cfg(&self, request: AtAddress) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_function_cfg(request.addr.0)?)
    }

    fn get_function_skeleton(&self, request: AtAddress) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_function_skeleton(request.addr.0)?)
    }

    fn get_data_flow_slice(&self, request: GetDataFlowSlice) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_data_flow_slice(request.addr.0, &request.register, &request.direction)?)
    }

    fn get_xrefs(&self, request: AtAddress) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_xrefs(request.addr.0))
    }

    fn execute_datalog(&self, request: ExecuteDatalog) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.execute_datalog(
            &request.query,
            request.addr.0,
            request.register.as_deref(),
            request.limit,
        )?)
    }

    fn scan_pointers(&self, _: NoArgs) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.scan_pointers())
    }

    fn scan_vtables(&self, _: NoArgs) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.scan_vtables())
    }

    fn get_function_pointers(&self, request: GetFunctionPointers) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.scan_function_pointers(
            request.addr.map(|addr| addr.0),
            request.offset,
            request.limit,
        )?)
    }

    fn find_call_paths(&self, request: FindCallPaths) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.find_call_paths(
            request.start_addr.0,
            request.goal_addr.0,
            request.max_depth,
            request.include_all_paths,
            request.max_paths,
        )?)
    }

    fn get_bytes(&self, request: ReadBytes) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_bytes(request.addr.0, request.size)?)
    }

    fn search_rc4(&self, _: NoArgs) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.search_rc4())
    }

    fn get_coverage(&self, _: NoArgs) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_coverage())
    }

    fn get_asm(&self, request: GetAsm) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_asm(request.start_addr.0, request.stop_addr.0)?)
    }

    fn get_function_at(&self, request: GetFunctionAt) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_function_at(request.addr.0, request.include_asm, request.include_il)?)
    }

    fn get_string(&self, request: GetString) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_string(request.addr.0, request.max_len)?)
    }

    fn get_data(&self, request: ReadBytes) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.get_data(request.addr.0, request.size)?)
    }

    fn emulate_snippet_il(&self, request: EmulateIl) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.emulate_snippet_il(
            request.start_addr.0,
            request.end_addr.0,
            register_map(request.initial_registers)?,
            request.step_limit,
        )?)
    }

    fn emulate_snippet_native(&self, request: EmulateNative) -> ToolResult {
        let session = self.require_session()?;
        Ok(session.emulate_snippet(
            request.start_addr.0,
            request.end_addr.0,
            register_map(request.initial_registers)?,
            memory_map(request.initial_memory)?,
            request.step_limit,
        )?)
    }

    fn emulate_snippet_native_advanced(&self, request: EmulateNativeAdvanced) -> ToolResult {
        let session = self.require_session()?;
        let watchpoints = request
            .watchpoints
            .into_iter()
            .map(|watchpoint| {
                let size = match &watchpoint.size {
                    Some(size) => size.value("watchpoint size")?,
                    None => 8,
                };
                Ok(aeon::sandbox::WatchpointSpec {
                    addr: watchpoint.addr.0,
                    size,
                    on_read: watchpoint.on_read,
                    on_write: watchpoint.on_write,
                    stop_on_hit: watchpoint.stop_on_hit,
                })
            })
            .collect::<Result<Vec<_>, ArgError>>()?;
        let address_hooks = request
            .address_hooks
            .into_iter()
            .map(|hook| aeon::sandbox::AddressHookSpec {
                addr: hook.addr.0,
                stop_on_hit: hook.stop_on_hit,
                patches: hook
                    .patches
                    .into_iter()
                    .map(|patch| aeon::sandbox::RegisterPatch {
                        name: patch.name,
                        value: patch.value.0,
                    })
                    .collect(),
            })
            .collect();

        Ok(session.emulate_snippet_native_advanced(aeon::api::AdvancedEmulationRequest {
            start_addr: request.start_addr.0,
            end_addr: request.end_addr.0,
            initial_registers: register_map(request.initial_registers)?,
            initial_memory: memory_map(request.initial_memory)?,
            step_limit: request.step_limit,
            watchpoints,
            address_hooks,
            record_pc_trace: request.record_pc_trace,
        })?)
    }
}

/// One tool: its name, what it is for, the type of its arguments and the
/// function that runs it.
///
/// `TOOLS` is the only list of tools. Dispatch (`AeonFrontend::call_tool`),
/// the schema listing (`tools_list`) and the documentation table
/// (`tools_markdown_table`) are all derived from it, so a tool cannot be
/// callable but unlisted, or listed but not callable. The schema and the
/// argument parser both come from the entry's request type.
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

macro_rules! tool {
    ($name:literal, $request:ty, $method:ident, $description:literal $(,)?) => {
        ToolSpec {
            name: $name,
            description: $description,
            input_schema: schema_of::<$request>,
            handler: |frontend, args| {
                let request: $request = parse(args)?;
                frontend.$method(request)
            },
        }
    };
}

pub static TOOLS: &[ToolSpec] = &[
    tool!(
        "load_binary",
        LoadBinary,
        load_binary,
        "Load an ELF or raw AArch64 binary for analysis. Must be called before other tools.",
    ),
    tool!(
        "list_functions",
        ListFunctions,
        list_functions,
        "List functions discovered from .eh_frame unwind tables. Supports pagination and name filtering.",
    ),
    tool!(
        "set_analysis_name",
        NameAddress,
        rename_symbol,
        "Backwards-compatible alias for rename_symbol. Attaches or overwrites a semantic symbol on an address.",
    ),
    tool!(
        "rename_symbol",
        NameAddress,
        rename_symbol,
        "Attach or overwrite a semantic symbol name on an address.",
    ),
    tool!(
        "define_struct",
        DefineStruct,
        define_struct,
        "Attach or overwrite a structure definition on an address.",
    ),
    tool!(
        "add_hypothesis",
        AddHypothesis,
        add_hypothesis,
        "Record a semantic hypothesis on an address. Duplicate notes are ignored.",
    ),
    tool!(
        "search_analysis_names",
        SearchAnalysisNames,
        search_analysis_names,
        "Search analysis names attached to addresses using a regex pattern.",
    ),
    tool!(
        "get_blackboard_entry",
        AtAddress,
        get_blackboard_entry,
        "Look up all semantic context recorded for an address: symbol name, struct definition, hypotheses, and containing function. Use to inspect what the blackboard knows about a specific address.",
    ),
    tool!(
        "get_il",
        AtAddress,
        get_il,
        "Get the lifted AeonIL intermediate language listing for the function containing a given address.",
    ),
    tool!(
        "get_function_il",
        AtAddress,
        get_il,
        "Backwards-compatible alias for get_il.",
    ),
    tool!(
        "get_reduced_il",
        AtAddress,
        get_reduced_il,
        "Return block-structured reduced AeonIL for the function containing a given address.",
    ),
    tool!(
        "get_ssa",
        GetSsa,
        get_ssa,
        "Return reduced SSA form for the function containing a given address, optionally optimized.",
    ),
    tool!(
        "get_stack_frame",
        AtAddress,
        get_stack_frame,
        "Summarize the detected stack frame and visible stack-slot accesses for the function containing a given address.",
    ),
    tool!(
        "get_function_cfg",
        AtAddress,
        get_function_cfg,
        "Get the Control Flow Graph for a function. Returns adjacency list, terminal blocks, and reachability from Datalog analysis.",
    ),
    tool!(
        "get_function_skeleton",
        AtAddress,
        get_function_skeleton,
        "Get a dense summary of function properties for efficient triage: argument count, calls, strings, loops, crypto constants, stack frame size, and suspicious patterns.",
    ),
    tool!(
        "get_data_flow_slice",
        GetDataFlowSlice,
        get_data_flow_slice,
        "Trace value flow for a register backward or forward through a function: backward shows where a value comes from, forward shows where it goes. Detects data dependencies through assignments and control flow.",
    ),
    tool!(
        "get_xrefs",
        AtAddress,
        get_xrefs,
        "Get cross-references for an address: outgoing calls from the function, and incoming calls from other functions.",
    ),
    tool!(
        "execute_datalog",
        ExecuteDatalog,
        execute_datalog,
        "Run a named Datalog query over a function or the whole binary. Returns structured facts derived by the ascent Datalog engine from lifted AeonIL.",
    ),
    tool!(
        "scan_pointers",
        NoArgs,
        scan_pointers,
        "Scan non-executable mapped sections for pointer-sized values that reference other locations in the binary, classifying data-to-data and data-to-code edges.",
    ),
    tool!(
        "scan_vtables",
        NoArgs,
        scan_vtables,
        "Detect candidate C++ vtables in .rodata/.data-style sections by finding arrays of function pointers and grouping related tables.",
    ),
    tool!(
        "get_function_pointers",
        GetFunctionPointers,
        get_function_pointers,
        "Enumerate pointer-valued operands and resolved code/data references for one function or a paginated slice of functions.",
    ),
    tool!(
        "find_call_paths",
        FindCallPaths,
        find_call_paths,
        "Find shortest and optionally all bounded call-graph paths between two functions using direct calls and vtable-resolved indirect calls.",
    ),
    tool!(
        "get_bytes",
        ReadBytes,
        get_bytes,
        "Read raw bytes from the binary at a virtual address. Returns hex-encoded string.",
    ),
    tool!(
        "search_rc4",
        NoArgs,
        search_rc4,
        "Search for RC4 cipher implementations using Datalog behavioral subgraph isomorphism. Detects KSA (swap+256+mod256) and PRGA (swap+keystream XOR) patterns.",
    ),
    tool!(
        "get_coverage",
        NoArgs,
        get_coverage,
        "Get IL lift coverage statistics: proper IL vs intrinsic vs nop vs decode errors.",
    ),
    tool!(
        "get_asm",
        GetAsm,
        get_asm,
        "Disassemble ARM64 instructions between two virtual addresses. Returns asm only, without AeonIL.",
    ),
    tool!(
        "get_function_at",
        GetFunctionAt,
        get_function_at,
        "Find the function containing a given address. Returns function metadata by default, and can optionally attach asm and/or AeonIL listings.",
    ),
    tool!(
        "get_string",
        GetString,
        get_string,
        "Read a null-terminated string at any virtual address (works across all ELF segments, not just .text).",
    ),
    tool!(
        "get_data",
        ReadBytes,
        get_data,
        "Read raw bytes at any virtual address (works across all ELF segments). Returns hex + ASCII.",
    ),
    tool!(
        "emulate_snippet_il",
        EmulateIl,
        emulate_snippet_il,
        "Execute an ARM64 code region using AeonIL interpretation. Executes lifted IL statements without full binary emulation. Useful for symbolic execution or analyzing stripped code.",
    ),
    tool!(
        "emulate_snippet_native",
        EmulateNative,
        emulate_snippet_native,
        "Execute an ARM64 code region in unicorn ARM64 sandbox. Full native emulation with memory support. Returns final register state, memory writes, and decoded strings.",
    ),
    tool!(
        "emulate_snippet",
        EmulateNative,
        emulate_snippet_native,
        "Execute an ARM64 code region in a bounded sandbox. Alias for emulate_snippet_native. Returns final register state, memory writes, and any decoded strings. Use for reversing obfuscated loops, string decryption, or format decoders.",
    ),
    tool!(
        "emulate_snippet_native_advanced",
        EmulateNativeAdvanced,
        emulate_snippet_native_advanced,
        "Execute an ARM64 code region with advanced features: memory watchpoints, instruction hooks with register patching, PC tracing, and extended register state (SIMD).",
    ),
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
            ErrorCode::LoadFailed
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
            ErrorCode::NotFound
        );
        assert_eq!(
            code(&mut frontend, "get_bytes", json!({ "addr": "0xffffffff" })),
            ErrorCode::OutOfRange
        );
        assert_eq!(
            code(&mut frontend, "search_analysis_names", json!({ "pattern": "(" })),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            code(
                &mut frontend,
                "execute_datalog",
                json!({ "addr": "0x718", "query": "no_such_query" })
            ),
            ErrorCode::InvalidArgument
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
