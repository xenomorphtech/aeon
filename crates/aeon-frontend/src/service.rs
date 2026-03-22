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
            "get_function_il" => self.tool_get_function_il(args),
            "get_function_cfg" => self.tool_get_function_cfg(args),
            "get_xrefs" => self.tool_get_xrefs(args),
            "get_bytes" => self.tool_get_bytes(args),
            "search_rc4" => self.tool_search_rc4(),
            "get_coverage" => self.tool_get_coverage(),
            "get_asm" => self.tool_get_asm(args),
            "get_function_at" => self.tool_get_function_at(args),
            "get_string" => self.tool_get_string(args),
            "get_data" => self.tool_get_data(args),
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

        let session =
            aeon::AeonSession::load(path).map_err(|e| format!("Failed to load binary: {}", e))?;
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

    fn tool_get_function_il(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        session.get_function_il(addr)
    }

    fn tool_get_function_cfg(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        session.get_function_cfg(addr)
    }

    fn tool_get_xrefs(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_xrefs(addr))
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
        session.get_function_at(addr)
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
}

pub fn tools_list() -> Value {
    json!({
        "tools": [
            tool_schema("load_binary",
                "Load an ELF binary for analysis. Must be called before other tools.",
                json!({"type": "object", "properties": {
                    "path": {"type": "string", "description": "Path to ELF binary"}
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

            tool_schema("get_function_il",
                "Get the lifted AeonIL intermediate language listing for a function.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Function address in hex, e.g. '0x1000'"}
                }, "required": ["addr"]})),

            tool_schema("get_function_cfg",
                "Get the Control Flow Graph for a function. Returns adjacency list, terminal blocks, and reachability from Datalog analysis.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Function address in hex"}
                }, "required": ["addr"]})),

            tool_schema("get_xrefs",
                "Get cross-references for an address: outgoing calls from the function, and incoming calls from other functions.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Function address in hex"}
                }, "required": ["addr"]})),

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
                "Disassemble ARM64 instructions between two virtual addresses. Like objdump --start-address/--stop-address.",
                json!({"type": "object", "properties": {
                    "start_addr": {"type": "string", "description": "Start virtual address in hex, e.g. '0x512025c'"},
                    "stop_addr": {"type": "string", "description": "Stop virtual address in hex (exclusive), e.g. '0x51202cc'"}
                }, "required": ["start_addr", "stop_addr"]})),

            tool_schema("get_function_at",
                "Find the function containing a given address. Returns the function's start address, size, name, and IL listing.",
                json!({"type": "object", "properties": {
                    "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
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

fn escape_markdown_cell(value: &str) -> String {
    value.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::tools_markdown_table;

    const README_BEGIN: &str = "<!-- BEGIN GENERATED TOOL SURFACE -->";
    const README_END: &str = "<!-- END GENERATED TOOL SURFACE -->";

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
        let end_rel = rest.find(README_END).expect("missing tool surface end marker");
        let actual = rest[..end_rel].trim();
        let expected = tools_markdown_table();

        assert_eq!(
            actual,
            expected,
            "README tool surface is out of date; regenerate it from tools_markdown_table()"
        );
    }
}
