//! MCP (Model Context Protocol) server — JSON-RPC 2.0 over stdio.
//!
//! Exposes Aeon's reverse engineering capabilities as discrete, single-action
//! tools with strict JSON input/output for agent consumption.

use std::io::{BufRead, Write};
use serde_json::{json, Value};

use crate::elf::LoadedBinary;
use crate::engine::AeonEngine;
use crate::il::Stmt;
use crate::lifter;

// ═══════════════════════════════════════════════════════════════════════
// Server state
// ═══════════════════════════════════════════════════════════════════════

struct AeonMcp {
    binary: Option<LoadedBinary>,
}

impl AeonMcp {
    fn new() -> Self {
        AeonMcp { binary: None }
    }

    fn require_binary(&self) -> Result<&LoadedBinary, (i64, String)> {
        self.binary.as_ref().ok_or((-32000, "No binary loaded. Call load_binary first.".into()))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════

pub fn run() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut server = AeonMcp::new();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                write_error(&mut stdout, Value::Null, -32700, &format!("Parse error: {}", e));
                continue;
            }
        };

        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));

        // Notifications (no id) don't get a response
        if id.is_null() {
            continue;
        }

        let result = dispatch(method, &params, &mut server);

        match result {
            Ok(val) => write_result(&mut stdout, &id, val),
            Err((code, msg)) => write_error(&mut stdout, id, code, &msg),
        }
    }
}

fn dispatch(method: &str, params: &Value, server: &mut AeonMcp) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => Ok(handle_initialize()),
        "tools/list" => Ok(handle_tools_list()),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let result = handle_tool_call(name, &args, server);
            // tools/call always returns 200-level; errors go in isError
            Ok(result)
        }
        _ => Err((-32601, format!("Method not found: {}", method))),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Protocol handlers
// ═══════════════════════════════════════════════════════════════════════

fn handle_initialize() -> Value {
    json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "aeon",
            "version": "0.1.0"
        }
    })
}

fn handle_tools_list() -> Value {
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
        ]
    })
}

fn tool_schema(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Tool dispatch
// ═══════════════════════════════════════════════════════════════════════

fn handle_tool_call(name: &str, args: &Value, server: &mut AeonMcp) -> Value {
    let result = match name {
        "load_binary" => tool_load_binary(args, server),
        "list_functions" => tool_list_functions(args, server),
        "get_function_il" => tool_get_function_il(args, server),
        "get_function_cfg" => tool_get_function_cfg(args, server),
        "get_xrefs" => tool_get_xrefs(args, server),
        "get_bytes" => tool_get_bytes(args, server),
        "search_rc4" => tool_search_rc4(server),
        "get_coverage" => tool_get_coverage(server),
        "get_asm" => tool_get_asm(args, server),
        _ => Err(format!("Unknown tool: {}", name)),
    };

    match result {
        Ok(val) => json!({
            "content": [{"type": "text", "text": serde_json::to_string(&val).unwrap()}],
            "isError": false
        }),
        Err(msg) => json!({
            "content": [{"type": "text", "text": msg}],
            "isError": true
        }),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tool implementations
// ═══════════════════════════════════════════════════════════════════════

fn tool_load_binary(args: &Value, server: &mut AeonMcp) -> Result<Value, String> {
    let path = args.get("path").and_then(|p| p.as_str())
        .ok_or("Missing required parameter: path")?;

    let binary = crate::elf::load_elf(path)
        .map_err(|e| format!("Failed to load binary: {}", e))?;

    let result = json!({
        "status": "loaded",
        "path": path,
        "text_section_addr": format!("0x{:x}", binary.text_section_addr),
        "text_section_size": format!("0x{:x}", binary.text_section_size),
        "total_functions": binary.functions.len(),
        "named_functions": binary.functions.iter().filter(|f| f.name.is_some()).count(),
    });

    server.binary = Some(binary);
    Ok(result)
}

fn tool_list_functions(args: &Value, server: &AeonMcp) -> Result<Value, String> {
    let binary = server.require_binary().map_err(|(_,m)| m)?;

    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let name_filter = args.get("name_filter").and_then(|v| v.as_str()).unwrap_or("");

    let filtered: Vec<&crate::elf::FunctionInfo> = if name_filter.is_empty() {
        binary.functions.iter().collect()
    } else {
        binary.functions.iter()
            .filter(|f| f.name.as_deref().map_or(false, |n| n.contains(name_filter)))
            .collect()
    };

    let total = filtered.len();
    let page: Vec<Value> = filtered.iter()
        .skip(offset)
        .take(limit)
        .map(|f| json!({
            "addr": format!("0x{:x}", f.addr),
            "size": f.size,
            "name": f.name.as_deref().unwrap_or_null(),
        }))
        .collect();

    Ok(json!({
        "total": total,
        "offset": offset,
        "count": page.len(),
        "functions": page,
    }))
}

fn tool_get_function_il(args: &Value, server: &AeonMcp) -> Result<Value, String> {
    let binary = server.require_binary().map_err(|(_,m)| m)?;
    let addr = parse_addr_arg(args)?;

    let func = binary.functions.iter().find(|f| f.addr == addr)
        .ok_or_else(|| format!("No function at 0x{:x}", addr))?;

    let bytes = binary.function_bytes(func)
        .ok_or("Function bytes out of range")?;

    let listing = lift_function(bytes, addr);

    Ok(json!({
        "function": format!("0x{:x}", addr),
        "size": func.size,
        "name": func.name.as_deref().unwrap_or_null(),
        "instruction_count": listing.len(),
        "listing": listing,
    }))
}

fn tool_get_function_cfg(args: &Value, server: &AeonMcp) -> Result<Value, String> {
    let binary = server.require_binary().map_err(|(_,m)| m)?;
    let addr = parse_addr_arg(args)?;

    let func = binary.functions.iter().find(|f| f.addr == addr)
        .ok_or_else(|| format!("No function at 0x{:x}", addr))?;

    let bytes = binary.function_bytes(func)
        .ok_or("Function bytes out of range")?;

    // Fresh engine for this analysis
    let mut engine = AeonEngine::new();
    engine.ingest_function(addr, bytes);
    let details = engine.get_function_details(addr);

    // Reshape into clean CFG output
    Ok(json!({
        "function": format!("0x{:x}", addr),
        "name": func.name.as_deref().unwrap_or_null(),
        "instruction_count": details["instruction_count"],
        "edges": details["internal_edges"],
        "terminal_blocks": details["terminal_blocks"],
        "reachable_paths": details["reachable_paths_count"],
    }))
}

fn tool_get_xrefs(args: &Value, server: &AeonMcp) -> Result<Value, String> {
    let binary = server.require_binary().map_err(|(_,m)| m)?;
    let target_addr = parse_addr_arg(args)?;

    // Find the target function for outgoing refs
    let target_func = binary.functions.iter().find(|f| f.addr == target_addr);

    // Outgoing: calls/branches FROM this function
    let mut calls_out: Vec<Value> = Vec::new();
    if let Some(func) = target_func {
        if let Some(bytes) = binary.function_bytes(func) {
            let mut offset = 0usize;
            let mut pc = func.addr;
            while offset + 4 <= bytes.len() {
                let word = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());
                if let Ok(insn) = bad64::decode(word, pc) {
                    let next_pc = if offset + 8 <= bytes.len() { Some(pc + 4) } else { None };
                    let result = lifter::lift(&insn, pc, next_pc);
                    match &result.stmt {
                        Stmt::Call { target: crate::il::Expr::Imm(t) } => {
                            let callee_name = binary.functions.iter()
                                .find(|f| f.addr == *t)
                                .and_then(|f| f.name.as_deref());
                            calls_out.push(json!({
                                "from": format!("0x{:x}", pc),
                                "to": format!("0x{:x}", t),
                                "name": callee_name.unwrap_or_null(),
                            }));
                        }
                        _ => {}
                    }
                }
                offset += 4;
                pc += 4;
            }
        }
    }

    // Incoming: calls TO target_addr from other functions (scan all functions)
    let mut calls_in: Vec<Value> = Vec::new();
    for func in &binary.functions {
        if func.addr == target_addr { continue; }
        if let Some(bytes) = binary.function_bytes(func) {
            let mut offset = 0usize;
            let mut pc = func.addr;
            while offset + 4 <= bytes.len() {
                let word = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());
                if let Ok(insn) = bad64::decode(word, pc) {
                    let next_pc = if offset + 8 <= bytes.len() { Some(pc + 4) } else { None };
                    let result = lifter::lift(&insn, pc, next_pc);
                    if let Stmt::Call { target: crate::il::Expr::Imm(t) } = &result.stmt {
                        if *t == target_addr {
                            calls_in.push(json!({
                                "from_func": format!("0x{:x}", func.addr),
                                "from_inst": format!("0x{:x}", pc),
                                "caller_name": func.name.as_deref().unwrap_or_null(),
                            }));
                        }
                    }
                }
                offset += 4;
                pc += 4;
            }
        }
    }

    Ok(json!({
        "target": format!("0x{:x}", target_addr),
        "calls_out": calls_out,
        "calls_in": calls_in,
        "calls_out_count": calls_out.len(),
        "calls_in_count": calls_in.len(),
    }))
}

fn tool_get_bytes(args: &Value, server: &AeonMcp) -> Result<Value, String> {
    let binary = server.require_binary().map_err(|(_,m)| m)?;
    let addr = parse_addr_arg(args)?;
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(64) as usize;
    let size = size.min(4096); // cap at 4KB

    // Convert virtual address to file offset
    let offset_in_text = addr.checked_sub(binary.text_section_addr)
        .ok_or("Address before .text section")?;
    let file_offset = binary.text_section_file_offset + offset_in_text;
    let end = (file_offset + size as u64).min(binary.data.len() as u64);
    let start = file_offset as usize;
    let end = end as usize;

    if start >= binary.data.len() {
        return Err(format!("Address 0x{:x} out of range", addr));
    }

    let bytes = &binary.data[start..end];
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();

    // Also try to extract ASCII strings
    let ascii: String = bytes.iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect();

    Ok(json!({
        "addr": format!("0x{:x}", addr),
        "size": bytes.len(),
        "hex": hex,
        "ascii": ascii,
    }))
}

fn tool_search_rc4(server: &AeonMcp) -> Result<Value, String> {
    let binary = server.require_binary().map_err(|(_,m)| m)?;
    Ok(crate::rc4_search::search(binary))
}

fn tool_get_coverage(server: &AeonMcp) -> Result<Value, String> {
    let binary = server.require_binary().map_err(|(_,m)| m)?;
    let mut engine = AeonEngine::new();
    engine.binary = Some(crate::elf::LoadedBinary {
        data: binary.data.clone(),
        text_section_file_offset: binary.text_section_file_offset,
        text_section_addr: binary.text_section_addr,
        text_section_size: binary.text_section_size,
        functions: Vec::new(), // not needed for coverage
    });
    Ok(engine.coverage_report())
}

fn tool_get_asm(args: &Value, server: &AeonMcp) -> Result<Value, String> {
    let binary = server.require_binary().map_err(|(_,m)| m)?;

    let start_str = args.get("start_addr").and_then(|a| a.as_str())
        .ok_or("Missing required parameter: start_addr")?;
    let stop_str = args.get("stop_addr").and_then(|a| a.as_str())
        .ok_or("Missing required parameter: stop_addr")?;

    let start_addr = parse_hex(start_str)
        .ok_or_else(|| format!("Invalid hex address: {}", start_str))?;
    let stop_addr = parse_hex(stop_str)
        .ok_or_else(|| format!("Invalid hex address: {}", stop_str))?;

    if stop_addr <= start_addr {
        return Err("stop_addr must be greater than start_addr".into());
    }

    let size = stop_addr - start_addr;
    if size > 1_048_576 {
        return Err("Range too large (max 1MB)".into());
    }

    // Convert virtual address to file offset
    let offset_in_text = start_addr.checked_sub(binary.text_section_addr)
        .ok_or("start_addr before .text section")?;
    let file_start = (binary.text_section_file_offset + offset_in_text) as usize;
    let file_end = file_start + size as usize;

    if file_end > binary.data.len() {
        return Err(format!("Address range 0x{:x}..0x{:x} extends past binary data", start_addr, stop_addr));
    }

    let bytes = &binary.data[file_start..file_end];
    let listing = lift_function(bytes, start_addr);

    Ok(json!({
        "start_addr": format!("0x{:x}", start_addr),
        "stop_addr": format!("0x{:x}", stop_addr),
        "size": size,
        "instruction_count": listing.len(),
        "listing": listing,
    }))
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

fn parse_addr_arg(args: &Value) -> Result<u64, String> {
    let s = args.get("addr").and_then(|a| a.as_str())
        .ok_or("Missing required parameter: addr")?;
    parse_hex(s).ok_or_else(|| format!("Invalid hex address: {}", s))
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}

fn lift_function(raw_bytes: &[u8], func_addr: u64) -> Vec<Value> {
    let mut listing = Vec::new();
    let mut offset = 0usize;
    let mut pc = func_addr;

    while offset + 4 <= raw_bytes.len() {
        let word = u32::from_le_bytes(raw_bytes[offset..offset + 4].try_into().unwrap());
        let next_pc = if offset + 8 <= raw_bytes.len() { Some(pc + 4) } else { None };

        let entry = if let Ok(insn) = bad64::decode(word, pc) {
            let result = lifter::lift(&insn, pc, next_pc);
            json!({
                "addr": format!("0x{:x}", pc),
                "asm": result.disasm,
                "il": format!("{:?}", result.stmt),
                "edges": result.edges.iter().map(|e| format!("0x{:x}", e)).collect::<Vec<_>>(),
            })
        } else {
            json!({"addr": format!("0x{:x}", pc), "asm": "(invalid)", "il": "Nop"})
        };

        listing.push(entry);
        offset += 4;
        pc += 4;
    }

    listing
}

// ── JSON-RPC output ────────────────────────────────────────────────

fn write_result(out: &mut impl Write, id: &Value, result: Value) {
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    });
    let _ = writeln!(out, "{}", serde_json::to_string(&response).unwrap());
    let _ = out.flush();
}

fn write_error(out: &mut impl Write, id: Value, code: i64, message: &str) {
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    });
    let _ = writeln!(out, "{}", serde_json::to_string(&response).unwrap());
    let _ = out.flush();
}

// serde helper: convert None to JSON null
trait UnwrapOrNull {
    fn unwrap_or_null(&self) -> Value;
}

impl UnwrapOrNull for Option<&str> {
    fn unwrap_or_null(&self) -> Value {
        match self {
            Some(s) => Value::String(s.to_string()),
            None => Value::Null,
        }
    }
}
