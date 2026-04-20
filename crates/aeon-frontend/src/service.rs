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
            "get_function_il" => self.tool_get_il(args), // Backward compatibility alias
            "get_reduced_il" => self.tool_get_reduced_il(args),
            "get_ssa" => self.tool_get_ssa(args),
            "get_stack_frame" => self.tool_get_stack_frame(args),
            "get_function_cfg" => self.tool_get_function_cfg(args),
            "get_function_skeleton" => self.tool_get_function_skeleton(args),
            "get_data_flow_slice" => self.tool_get_data_flow_slice(args),
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
            "emulate_snippet_il" => self.tool_emulate_snippet_il(args),
            "emulate_snippet_native" => self.tool_emulate_snippet_native(args),
            "emulate_snippet" => self.tool_emulate_snippet_native(args), // Backward compatibility alias
            "emulate_snippet_native_advanced" => self.tool_emulate_snippet_native_advanced(args),
            "execute_datalog" => self.tool_execute_datalog(args),
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


    fn tool_get_data_flow_slice(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        let register = args
            .get("register")
            .and_then(|v| v.as_str())
            .ok_or("register parameter required")?;
        let direction = args
            .get("direction")
            .and_then(|v| v.as_str())
            .ok_or("direction parameter required ('backward' or 'forward')")?;
        session.get_data_flow_slice(addr, register, direction)
    }

    fn tool_get_xrefs(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let addr = parse_addr_arg(args)?;
        Ok(session.get_xrefs(addr))
    }

    fn tool_execute_datalog(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let query = args
            .get("query")
            .and_then(|value| value.as_str())
            .ok_or("Missing required parameter: query")?;
        let addr = parse_addr_arg(args)?;
        let register = args.get("register").and_then(|value| value.as_str());
        let limit = args.get("limit").and_then(|value| value.as_u64()).map(|v| v as usize);

        session.execute_datalog(query, addr, register, limit)
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

    fn tool_emulate_snippet_il(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let start_addr = parse_hex_arg(args, "start_addr")?;
        let end_addr = parse_hex_arg(args, "end_addr")?;
        let step_limit = args
            .get("step_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        let initial_registers = parse_register_map(args)?;

        session.emulate_snippet_il(start_addr, end_addr, initial_registers, step_limit)
    }

    fn tool_emulate_snippet_native(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        let start_addr = parse_hex_arg(args, "start_addr")?;
        let end_addr = parse_hex_arg(args, "end_addr")?;
        let step_limit = args
            .get("step_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;

        let initial_registers = parse_register_map(args)?;
        let initial_memory = parse_memory_map(args)?;

        session.emulate_snippet(start_addr, end_addr, initial_registers, initial_memory, step_limit)
    }

    fn tool_emulate_snippet_native_advanced(&self, args: &Value) -> Result<Value, String> {
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

        session.emulate_snippet_native_advanced(req)
    }
}

pub fn tools_list() -> Value {
    let mut tools_vec = tools_list_base();
    tools_vec.push(tool_schema("emulate_snippet_native_advanced",
        "Execute an ARM64 code region with advanced features: memory watchpoints, instruction hooks with register patching, PC tracing, and extended register state (SIMD).",
        build_advanced_emulation_schema()));

    json!({
        "tools": tools_vec
    })
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

fn tools_list_base() -> Vec<Value> {
    vec![
        tool_schema("load_binary",
            "Load an ELF or raw AArch64 binary for analysis. Must be called before other tools. Typical workflow: load_binary → list_functions → get_function_skeleton (triage) → get_il/get_ssa (deep analysis). Returns binary metadata (entry point, section info). For raw binaries, base_addr sets virtual address offset.",
            json!({"type": "object", "properties": {
                "path": {"type": "string", "description": "Path to binary"},
                "format": {"type": "string", "description": "Binary format: 'elf' or 'raw'", "default": "elf"},
                "base_addr": {"type": "string", "description": "Required for raw binaries: virtual base address in hex"}
            }, "required": ["path"]})),

        tool_schema("list_functions",
            "List functions discovered from .eh_frame unwind tables. Typical workflow: load_binary → list_functions → get_function_skeleton (triage) → get_il/get_ssa (analysis). Supports pagination (offset/limit) and name filtering. Returns function addresses, names, and sizes. Use to enumerate all discoverable functions; pagination needed for large binaries (e.g., offset=100, limit=50 for functions 100-149).",
            json!({"type": "object", "properties": {
                "offset": {"type": "integer", "description": "Start index", "default": 0},
                "limit": {"type": "integer", "description": "Max results", "default": 100},
                "name_filter": {"type": "string", "description": "Substring filter on symbol name"}
            }})),

        tool_schema("set_analysis_name",
            "Attach or overwrite a semantic symbol name on an address (identical to rename_symbol). Assigns a custom analysis label for documentation and reference. Naming conventions: `crypto_init`, `buffer_overflow_site`, `obfuscated_loop`, `vtable_<class>`. Retrieved via get_blackboard_entry. Use in workflows: find suspicious patterns → annotate with descriptive name → search_analysis_names to find all similar patterns.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "name": {"type": "string", "description": "Analysis name to assign to the address"}
            }, "required": ["addr", "name"]})),

        tool_schema("rename_symbol",
            "Attach or overwrite a semantic symbol name on an address (identical to set_analysis_name). Assigns a custom analysis label for documentation and reference. Naming conventions: `crypto_init`, `buffer_overflow_site`, `obfuscated_loop`, `vtable_<class>`. Retrieved via get_blackboard_entry. Use in workflows: find suspicious patterns → annotate with descriptive name → search_analysis_names to find all similar patterns.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "name": {"type": "string", "description": "Semantic symbol name to assign to the address"}
            }, "required": ["addr", "name"]})),

        tool_schema("define_struct",
            "Attach or overwrite a structure definition on an address. Use to document inferred struct layouts at data locations or function parameters. Definition is free-form text (e.g. `{field1: u64, field2: u32}` or C-like `struct { uint64_t a; uint32_t b; }`). Returns success/failure. Limitation: definition is stored as text; no validation or type checking applied.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "definition": {"type": "string", "description": "Structure definition text"}
            }, "required": ["addr", "definition"]})),

        tool_schema("add_hypothesis",
            "Record a semantic hypothesis or analyst note on an address. Accumulates observations; duplicates ignored. Use to document reasoning, suspected vulnerabilities, or ambiguous behavior. Example notes: `possible_integer_overflow`, `looks_like_CRC32_loop`, `malloc_call_without_check`. All notes retrieved via get_blackboard_entry.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "note": {"type": "string", "description": "Hypothesis or analyst note"}
            }, "required": ["addr", "note"]})),

        tool_schema("search_analysis_names",
            "Search analysis names attached to addresses using a regex pattern. Finds all addresses where set_analysis_name was used matching the pattern. Workflow: annotate locations with set_analysis_name → use search_analysis_names to find all similar patterns → use get_blackboard_entry to review context. Returns all matching addresses. Example: pattern `^crypto_` finds all crypto-related annotations; `.*_vulnerability$` finds all marked vulnerabilities. Limitation: searches only annotated addresses; empty result means no matches.",
            json!({"type": "object", "properties": {
                "pattern": {"type": "string", "description": "Regex pattern matched against analysis names"}
            }, "required": ["pattern"]})),

        tool_schema("get_blackboard_entry",
            "Look up all semantic context at an address: symbol name, struct definition, hypotheses, containing function. Use to inspect accumulated annotations (e.g., what prior analysis named this location). Returns annotations added via set_analysis_name, define_struct, add_hypothesis. Limitation: empty if no annotations were added to this address. Use after analysis pass to review findings.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Address to look up in hex"}
            }, "required": ["addr"]})),

        tool_schema("get_il",
            "Get the lifted AeonIL intermediate language listing for the function containing a given address. Use when analyzing full IL details. For block-structure overview, use get_reduced_il instead.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
            }, "required": ["addr"]})),

        tool_schema("get_function_il",
            "Backwards-compatible alias for get_il.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
            }, "required": ["addr"]})),

        tool_schema("get_reduced_il",
            "Return block-structured reduced AeonIL for the function containing a given address. Use when you need control flow structure without full IL details. Faster than get_il for overview analysis.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
            }, "required": ["addr"]})),

        tool_schema("get_ssa",
            "Return reduced SSA form for the function containing a given address, optionally optimized. Use for data flow analysis and value tracking. Better than IL for understanding variable definitions and uses.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"},
                "optimize": {"type": "boolean", "description": "Run SSA optimization passes before returning JSON", "default": true}
            }, "required": ["addr"]})),

        tool_schema("get_stack_frame",
            "Summarize the detected stack frame and visible stack-slot accesses for the function containing a given address. Use to identify local variables, stack-based arguments, and saved register locations.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"}
            }, "required": ["addr"]})),

        tool_schema("get_function_cfg",
            "Get the Control Flow Graph for a function. Returns block adjacency (edges), terminal blocks, and reachability analysis. Use to identify loops, dominators, dead code, or understand control dependencies. Returns block addresses and successors (branch targets). Limitation: represents lifted IL structure, not obfuscated control flow flattening patterns.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Function address in hex"}
            }, "required": ["addr"]})),

        tool_schema("get_function_skeleton",
            "Get a dense summary of function properties for quick analysis: argument count, calls, string literals, loops, crypto constants, stack frame, suspicious patterns. Use for initial function triage before detailed analysis with get_il or get_cfg.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Function address in hex"}
            }, "required": ["addr"]})),

        tool_schema("get_data_flow_slice",
            "Trace value flow for a register backward or forward from an instruction. Backward: find where value originates. Forward: find where value is consumed. Returns instruction addresses and registers in the data dependency chain. Use to understand parameter flow or value dependencies.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Instruction address in hex, e.g. '0x5e611fc'"},
                "register": {"type": "string", "description": "Register name (e.g., 'x0', 'w1', 'sp')"},
                "direction": {"type": "string", "enum": ["backward", "forward"], "description": "Backward: find value origin. Forward: find value uses."}
            }, "required": ["addr", "register", "direction"]})),

        tool_schema("get_xrefs",
            "Get cross-references for an address: outgoing calls (direct BL/BLR) and incoming callers. Returns call sites with target functions. Use to map call graph edges, find data flow entry points, or identify vulnerability sinks. Limitation: does not resolve indirect VTable calls. Returns both function addresses and call site locations for tracing execution paths.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Function address in hex"}
            }, "required": ["addr"]})),

        tool_schema("execute_datalog",
            "Run a named Datalog query over a function or the whole binary. Query types: 'reachability' (which blocks reachable from entry), 'defines' (where register is assigned), 'reads_mem'/'writes_mem' (memory access locations), 'flows_to' (where register value flows), 'call_graph' (direct callees), 'call_graph_transitive' (all reachable functions). Returns tuples of addresses and facts. REQUIRED register parameter: 'defines' and 'flows_to' only.",
            json!({"type": "object", "properties": {
                "query": {"type": "string", "enum": ["reachability", "defines", "reads_mem", "writes_mem", "flows_to", "call_graph", "call_graph_transitive"], "description": "Named Datalog query to execute"},
                "addr": {"type": "string", "description": "Virtual address in hex. For per-function queries, identifies the function. For cross-function queries, identifies the root function."},
                "register": {"type": "string", "description": "Register name (e.g. 'x0', 'w1', 'sp'). REQUIRED for 'defines' and 'flows_to' queries only."},
                "limit": {"type": "integer", "description": "Maximum number of result tuples to return. Default 500 usually sufficient, increase for large result sets.", "default": 500}
            }, "required": ["query", "addr"]})),

        tool_schema("scan_pointers",
            "Scan data sections (.rodata, .data) for embedded pointers. Classifies references as data-to-data or data-to-code. Returns map of pointer addresses and targets. Use to find hidden function pointers or global data references.",
            json!({"type": "object", "properties": {}})),

        tool_schema("scan_vtables",
            "Detect C++ virtual method tables (vtables) in data sections. Finds arrays of function pointers and groups related tables. Returns vtable addresses and methods. Use to understand class hierarchies and virtual dispatch.",
            json!({"type": "object", "properties": {}})),

        tool_schema("get_function_pointers",
            "Enumerate pointer-valued operands and resolved code/data references for one function or scan all. Use to find embedded function pointers (vtables, callbacks), global data references, or jump table indices. Returns operand addresses and their targets (code or data). With addr: analyze one function; omit addr: scan all functions (paginated). Typical usage: find hidden function pointers before analyzing control flow.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Optional function address in hex; when present, analyzes the containing function"},
                "offset": {"type": "integer", "description": "Start index when scanning multiple functions", "default": 0},
                "limit": {"type": "integer", "description": "Max functions to analyze when addr is omitted", "default": 50}
            }})),

        tool_schema("find_call_paths",
            "Find call-graph paths between two functions. Returns shortest path by default. Use to understand how execution reaches target functions. Enable include_all_paths for all reachable paths (useful for exploit chains or data flow tracking).",
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Start function address in hex"},
                "goal_addr": {"type": "string", "description": "Goal function address in hex"},
                "max_depth": {"type": "integer", "description": "Maximum call depth to explore (default 6 sufficient for most analysis)", "default": 6},
                "include_all_paths": {"type": "boolean", "description": "Find all paths (slower, useful for exploit chains)", "default": false},
                "max_paths": {"type": "integer", "description": "Limit result count when include_all_paths=true", "default": 32}
            }, "required": ["start_addr", "goal_addr"]})),

        tool_schema("get_bytes",
            "Read raw bytes from the binary at a virtual address. Returns hex-encoded string. Use for quick binary inspection at text section addresses. Prefer get_data for reading ELF data sections (.rodata, .data) which handles segment mapping automatically.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "size": {"type": "integer", "description": "Number of bytes", "default": 64}
            }, "required": ["addr"]})),

        tool_schema("search_rc4",
            "Search for RC4 cipher implementations using behavioral pattern matching (KSA: swap+mod256; PRGA: XOR+keystream). Use to identify crypto operations in obfuscated code. Returns candidate functions with confidence scores. Limitation: may match similar bit-manipulation patterns (not guaranteed RC4). No examples available (algorithm signatures); returns matching function addresses and matching IL subgraph patterns.",
            json!({"type": "object", "properties": {}})),

        tool_schema("get_coverage",
            "Get IL lift coverage: % successfully lifted vs intrinsics vs NOPs vs decode errors. Use to assess IL quality and identify unlifted patterns (e.g., SIMD/crypto). Returns counts and percentages for each category. Interpretation: >95% lifted = high confidence, <85% = significant gaps. Limitation: does not indicate semantic correctness, only syntactic liftability.",
            json!({"type": "object", "properties": {}})),

        tool_schema("get_asm",
            "Disassemble ARM64 instructions between two virtual addresses. Returns asm only, without IL lifting. Use for quick assembly inspection or when IL lifting is unavailable. Trade-offs: faster than get_il but no semantic understanding; prefer get_il for detailed analysis, get_bytes for raw binary inspection. Returns instruction mnemonics and operands with addresses.",
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Start virtual address in hex, e.g. '0x512025c'"},
                "stop_addr": {"type": "string", "description": "Stop virtual address in hex (exclusive), e.g. '0x51202cc'"}
            }, "required": ["start_addr", "stop_addr"]})),

        tool_schema("get_function_at",
            "Find the function containing a given address. Returns function metadata (bounds, name, etc.). Use include_asm=true for assembly listing or include_il=true for full IL analysis. Quick way to identify function context before deeper analysis.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Any virtual address in hex, e.g. '0x5e611fc'"},
                "include_asm": {"type": "boolean", "description": "Include asm in the returned listing", "default": false},
                "include_il": {"type": "boolean", "description": "Include AeonIL in the returned listing", "default": false}
            }, "required": ["addr"]})),

        tool_schema("get_string",
            "Read a null-terminated string at any virtual address (works across all ELF segments, not just .text). Use to extract embedded strings, error messages, or constants for context in analysis.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "max_len": {"type": "integer", "description": "Max bytes to scan for null terminator", "default": 256}
            }, "required": ["addr"]})),

        tool_schema("get_data",
            "Read raw bytes at any virtual address (works across all ELF segments). Returns hex + ASCII. Use for inspecting data sections, tables, or constants outside of code regions.",
            json!({"type": "object", "properties": {
                "addr": {"type": "string", "description": "Virtual address in hex"},
                "size": {"type": "integer", "description": "Number of bytes to read", "default": 64}
            }, "required": ["addr"]})),

        tool_schema("emulate_snippet_il",
            "Execute an ARM64 code region using AeonIL interpretation without full binary emulation. Faster than native emulation. Use for symbolic execution, quick logic analysis, or stripped code. For accurate memory simulation, use emulate_snippet_native instead.",
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Hex address to begin execution, e.g. '0x1234'"},
                "end_addr": {"type": "string", "description": "Hex address to stop execution (exclusive)"},
                "initial_registers": {"type": "object", "description": "Register values at entry. Keys: x0-x30, sp. Values: hex strings or integers.", "additionalProperties": {}},
                "step_limit": {"type": "integer", "description": "Max IL statements to execute. Use 100-1000 for snippets, 10000+ for loops (default 1000)", "default": 1000}
            }, "required": ["start_addr", "end_addr"]})),

        tool_schema("emulate_snippet_native",
            "Execute an ARM64 code region in unicorn ARM64 sandbox. Full native emulation with memory support. Use for reversing obfuscated loops, string decryption, or format decoders. Returns final register state, memory writes, and decoded strings. For faster interpretation-only analysis, use emulate_snippet_il instead.",
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Hex address to begin execution, e.g. '0x1234'"},
                "end_addr": {"type": "string", "description": "Hex address to stop execution (exclusive)"},
                "initial_registers": {"type": "object", "description": "Register values at entry. Keys: x0-x30, sp, pc, nzcv. Values: hex strings or integers.", "additionalProperties": {}},
                "initial_memory": {"type": "object", "description": "Memory overlays. Keys: hex addresses. Values: hex string or array of bytes.", "additionalProperties": {}},
                "step_limit": {"type": "integer", "description": "Max instructions to execute (default 1000)", "default": 1000}
            }, "required": ["start_addr", "end_addr"]})),

        tool_schema("emulate_snippet",
            "Execute an ARM64 code region in a bounded sandbox. Alias for emulate_snippet_native. Returns final register state, memory writes, and decoded strings. Use for reversing obfuscated loops, string decryption, or format decoders.",
            json!({"type": "object", "properties": {
                "start_addr": {"type": "string", "description": "Hex address to begin execution, e.g. '0x1234'"},
                "end_addr": {"type": "string", "description": "Hex address to stop execution (exclusive)"},
                "initial_registers": {"type": "object", "description": "Register values at entry. Keys: x0-x30, sp, pc, nzcv. Values: hex strings or integers.", "additionalProperties": {}},
                "initial_memory": {"type": "object", "description": "Memory overlays. Keys: hex addresses. Values: hex string or array of bytes.", "additionalProperties": {}},
                "step_limit": {"type": "integer", "description": "Max instructions to execute (default 1000)", "default": 1000}
            }, "required": ["start_addr", "end_addr"]})),
    ]
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

fn parse_watchpoints(args: &Value) -> Result<Vec<aeon::sandbox::WatchpointSpec>, String> {
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

fn parse_address_hooks(args: &Value) -> Result<Vec<aeon::sandbox::AddressHookSpec>, String> {
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
