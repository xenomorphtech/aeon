use std::cell::RefCell;

use serde_json::{json, Value};

use crate::elf::{self, FunctionInfo, LoadedBinary};
use crate::engine::{AeonEngine, SemanticContext};
use crate::il::{Expr, Stmt};
use crate::lifter;

pub struct AeonSession {
    path: String,
    binary: LoadedBinary,
    analysis_state: RefCell<AeonEngine>,
}

impl AeonSession {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let binary = elf::load_elf(path)?;
        Ok(Self {
            path: path.to_string(),
            binary,
            analysis_state: RefCell::new(AeonEngine::new()),
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn binary(&self) -> &LoadedBinary {
        &self.binary
    }

    pub fn set_analysis_name(&self, addr: u64, name: &str) -> Value {
        let semantic = self
            .analysis_state
            .borrow_mut()
            .set_analysis_name(addr, name.to_string());

        json!({
            "status": "assigned",
            "addr": format!("0x{:x}", addr),
            "analysis_name": name,
            "semantic": semantic_to_value(Some(semantic)),
        })
    }

    pub fn rename_symbol(&self, addr: u64, name: &str) -> Value {
        let semantic = self
            .analysis_state
            .borrow_mut()
            .rename_symbol(addr, name.to_string());

        json!({
            "status": "renamed",
            "addr": format!("0x{:x}", addr),
            "symbol": name,
            "semantic": semantic_to_value(Some(semantic)),
        })
    }

    pub fn define_struct(&self, addr: u64, definition: &str) -> Value {
        let semantic = self
            .analysis_state
            .borrow_mut()
            .define_struct(addr, definition.to_string());

        json!({
            "status": "defined",
            "addr": format!("0x{:x}", addr),
            "struct_definition": definition,
            "semantic": semantic_to_value(Some(semantic)),
        })
    }

    pub fn add_hypothesis(&self, addr: u64, note: &str) -> Value {
        let semantic = self
            .analysis_state
            .borrow_mut()
            .add_hypothesis(addr, note.to_string());

        json!({
            "status": "recorded",
            "addr": format!("0x{:x}", addr),
            "hypothesis": note,
            "semantic": semantic_to_value(Some(semantic)),
        })
    }

    pub fn search_analysis_names(&self, pattern: &str) -> Result<Value, String> {
        let engine = self.analysis_state.borrow();
        let matches = engine
            .search_analysis_names(pattern)
            .map_err(|e| format!("Invalid regex: {}", e))?;

        let matches: Vec<Value> = matches
            .into_iter()
            .map(|entry| {
                let function = self
                    .binary
                    .function_containing(entry.address)
                    .map(|f| f.addr);
                json!({
                    "addr": format!("0x{:x}", entry.address),
                    "analysis_name": entry.analysis_name,
                    "function": option_hex(function),
                    "semantic": semantic_value(&engine, entry.address),
                })
            })
            .collect();

        Ok(json!({
            "pattern": pattern,
            "count": matches.len(),
            "matches": matches,
        }))
    }

    pub fn summary(&self) -> Value {
        let engine = self.analysis_state.borrow();
        json!({
            "status": "loaded",
            "path": self.path,
            "text_section_addr": format!("0x{:x}", self.binary.text_section_addr),
            "text_section_size": format!("0x{:x}", self.binary.text_section_size),
            "total_functions": self.binary.functions.len(),
            "named_functions": self.binary.functions.iter().filter(|f| f.name.is_some()).count(),
            "blackboard": serde_json::to_value(engine.blackboard_summary()).unwrap(),
        })
    }

    pub fn list_functions(&self, offset: usize, limit: usize, name_filter: Option<&str>) -> Value {
        let name_filter = name_filter.unwrap_or("");
        let engine = self.analysis_state.borrow();

        let filtered: Vec<&FunctionInfo> = self
            .binary
            .functions
            .iter()
            .filter(|func| function_matches_filter(func, name_filter, &engine))
            .collect();

        let total = filtered.len();
        let functions: Vec<Value> = filtered
            .iter()
            .skip(offset)
            .take(limit)
            .map(|func| {
                json!({
                    "addr": format!("0x{:x}", func.addr),
                    "size": func.size,
                    "name": option_str(func.name.as_deref()),
                    "resolved_name": resolved_name_value(func.addr, func.name.as_deref(), &self.binary, &engine),
                    "semantic": semantic_value(&engine, func.addr),
                })
            })
            .collect();

        json!({
            "total": total,
            "offset": offset,
            "count": functions.len(),
            "functions": functions,
        })
    }

    pub fn get_il(&self, addr: u64) -> Result<Value, String> {
        let func = self
            .binary
            .function_containing(addr)
            .ok_or_else(|| format!("No function containing 0x{:x}", addr))?;
        let bytes = self
            .binary
            .function_bytes(func)
            .ok_or("Function bytes out of range")?;
        let engine = self.analysis_state.borrow();
        let listing = render_instruction_listing(bytes, func.addr, &self.binary, &engine, ListingMode::Il);

        Ok(json!({
            "query_addr": format!("0x{:x}", addr),
            "query_semantic": semantic_value(&engine, addr),
            "function": format!("0x{:x}", func.addr),
            "size": func.size,
            "name": option_str(func.name.as_deref()),
            "resolved_name": resolved_name_value(func.addr, func.name.as_deref(), &self.binary, &engine),
            "semantic": semantic_value(&engine, func.addr),
            "listing_kind": ListingMode::Il.label(),
            "instruction_count": listing.len(),
            "listing": listing,
        }))
    }

    pub fn get_function_il(&self, addr: u64) -> Result<Value, String> {
        self.get_il(addr)
    }

    pub fn get_function_details(&self, addr: u64) -> Result<Value, String> {
        let func = self.find_function(addr)?;
        let bytes = self
            .binary
            .function_bytes(func)
            .ok_or("Function bytes out of range")?;

        let mut analysis = AeonEngine::new();
        analysis.ingest_function(addr, bytes);
        let mut details = analysis.get_function_details(addr);

        let engine = self.analysis_state.borrow();
        annotate_function_details(&mut details, func, &self.binary, &engine);
        Ok(details)
    }

    pub fn get_function_cfg(&self, addr: u64) -> Result<Value, String> {
        let func = self.find_function(addr)?;
        let details = self.get_function_details(addr)?;

        Ok(json!({
            "function": format!("0x{:x}", addr),
            "name": option_str(func.name.as_deref()),
            "resolved_name": details["resolved_name"].clone(),
            "semantic": details["semantic"].clone(),
            "instruction_count": details["instruction_count"].clone(),
            "edges": details["internal_edges"].clone(),
            "terminal_blocks": details["terminal_blocks"].clone(),
            "reachable_paths": details["reachable_paths_count"].clone(),
        }))
    }

    pub fn get_xrefs(&self, target_addr: u64) -> Value {
        let target_func = self.binary.functions.iter().find(|f| f.addr == target_addr);
        let engine = self.analysis_state.borrow();

        let mut calls_out = Vec::new();
        if let Some(func) = target_func {
            if let Some(bytes) = self.binary.function_bytes(func) {
                let mut offset = 0usize;
                let mut pc = func.addr;
                while offset + 4 <= bytes.len() {
                    let word = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                    if let Ok(insn) = bad64::decode(word, pc) {
                        let next_pc = if offset + 8 <= bytes.len() {
                            Some(pc + 4)
                        } else {
                            None
                        };
                        let result = lifter::lift(&insn, pc, next_pc);
                        if let Stmt::Call {
                            target: Expr::Imm(target),
                        } = &result.stmt
                        {
                            let callee_name = exact_function_name(&self.binary, *target);
                            calls_out.push(json!({
                                "from": format!("0x{:x}", pc),
                                "from_semantic": semantic_value(&engine, pc),
                                "to": format!("0x{:x}", target),
                                "name": option_str(callee_name),
                                "to_resolved_name": resolved_name_value(*target, callee_name, &self.binary, &engine),
                                "to_semantic": semantic_value(&engine, *target),
                            }));
                        }
                    }
                    offset += 4;
                    pc += 4;
                }
            }
        }

        let mut calls_in = Vec::new();
        for func in &self.binary.functions {
            if func.addr == target_addr {
                continue;
            }
            if let Some(bytes) = self.binary.function_bytes(func) {
                let mut offset = 0usize;
                let mut pc = func.addr;
                while offset + 4 <= bytes.len() {
                    let word = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                    if let Ok(insn) = bad64::decode(word, pc) {
                        let next_pc = if offset + 8 <= bytes.len() {
                            Some(pc + 4)
                        } else {
                            None
                        };
                        let result = lifter::lift(&insn, pc, next_pc);
                        if let Stmt::Call {
                            target: Expr::Imm(target),
                        } = &result.stmt
                        {
                            if *target == target_addr {
                                calls_in.push(json!({
                                    "from_func": format!("0x{:x}", func.addr),
                                    "from_inst": format!("0x{:x}", pc),
                                    "caller_name": option_str(func.name.as_deref()),
                                    "caller_resolved_name": resolved_name_value(func.addr, func.name.as_deref(), &self.binary, &engine),
                                    "caller_semantic": semantic_value(&engine, func.addr),
                                }));
                            }
                        }
                    }
                    offset += 4;
                    pc += 4;
                }
            }
        }

        json!({
            "target": format!("0x{:x}", target_addr),
            "name": option_str(target_func.and_then(|func| func.name.as_deref())),
            "resolved_name": resolved_name_value(target_addr, target_func.and_then(|func| func.name.as_deref()), &self.binary, &engine),
            "semantic": semantic_value(&engine, target_addr),
            "calls_out": calls_out,
            "calls_in": calls_in,
            "calls_out_count": calls_out.len(),
            "calls_in_count": calls_in.len(),
        })
    }

    pub fn get_bytes(&self, addr: u64, size: usize) -> Result<Value, String> {
        let size = size.min(4096);
        let offset_in_text = addr
            .checked_sub(self.binary.text_section_addr)
            .ok_or("Address before .text section")?;
        let file_offset = self.binary.text_section_file_offset + offset_in_text;
        let end = (file_offset + size as u64).min(self.binary.data.len() as u64);
        let start = file_offset as usize;
        let end = end as usize;

        if start >= self.binary.data.len() {
            return Err(format!("Address 0x{:x} out of range", addr));
        }

        let bytes = &self.binary.data[start..end];
        let engine = self.analysis_state.borrow();
        Ok(data_view(addr, bytes, &self.binary, &engine))
    }

    pub fn get_data(&self, addr: u64, size: usize) -> Result<Value, String> {
        let size = size.min(4096);
        let bytes = self
            .binary
            .read_vaddr(addr, size)
            .ok_or_else(|| format!("Cannot read address 0x{:x} — not in any LOAD segment", addr))?;
        let engine = self.analysis_state.borrow();
        Ok(data_view(addr, bytes, &self.binary, &engine))
    }

    pub fn get_string(&self, addr: u64, max_len: usize) -> Result<Value, String> {
        let max_len = max_len.min(4096);
        let string = self
            .binary
            .read_string(addr, max_len)
            .ok_or_else(|| format!("Cannot read address 0x{:x} — not in any LOAD segment", addr))?;
        let engine = self.analysis_state.borrow();

        Ok(json!({
            "addr": format!("0x{:x}", addr),
            "length": string.len(),
            "string": string,
            "resolved_name": resolved_name_value(addr, None, &self.binary, &engine),
            "semantic": semantic_value(&engine, addr),
        }))
    }

    pub fn get_coverage(&self) -> Value {
        let text = self.binary.text_bytes();
        let base_addr = self.binary.text_section_addr;

        let mut total: u64 = 0;
        let mut decode_errors: u64 = 0;
        let mut proper_il: u64 = 0;
        let mut intrinsic_count: u64 = 0;
        let mut nop_count: u64 = 0;

        let mut offset = 0usize;
        let mut pc = base_addr;
        while offset + 4 <= text.len() {
            let word = u32::from_le_bytes(text[offset..offset + 4].try_into().unwrap());
            total += 1;

            match bad64::decode(word, pc) {
                Ok(insn) => {
                    let result = lifter::lift(&insn, pc, Some(pc + 4));
                    match &result.stmt {
                        Stmt::Nop => nop_count += 1,
                        Stmt::Intrinsic { .. } => intrinsic_count += 1,
                        Stmt::Assign {
                            src: Expr::Intrinsic { .. },
                            ..
                        } => intrinsic_count += 1,
                        Stmt::Pair(_, _) => proper_il += 1,
                        _ => proper_il += 1,
                    }
                }
                Err(_) => decode_errors += 1,
            }

            offset += 4;
            pc += 4;
        }

        let named_functions = self
            .binary
            .functions
            .iter()
            .filter(|f| f.name.is_some())
            .count();

        json!({
            "total_instructions": total,
            "decode_errors": decode_errors,
            "decode_error_pct": percent(decode_errors, total, 4),
            "proper_il": proper_il,
            "proper_il_pct": percent(proper_il, total, 2),
            "intrinsic": intrinsic_count,
            "intrinsic_pct": percent(intrinsic_count, total, 2),
            "nop": nop_count,
            "nop_pct": percent(nop_count, total, 2),
            "total_functions": self.binary.functions.len(),
            "named_functions": named_functions,
            "text_section_addr": format!("0x{:x}", self.binary.text_section_addr),
            "text_section_size": format!("0x{:x}", self.binary.text_section_size),
        })
    }

    pub fn get_asm(&self, start_addr: u64, stop_addr: u64) -> Result<Value, String> {
        if stop_addr <= start_addr {
            return Err("stop_addr must be greater than start_addr".into());
        }

        let size = stop_addr - start_addr;
        if size > 1_048_576 {
            return Err("Range too large (max 1MB)".into());
        }

        let offset_in_text = start_addr
            .checked_sub(self.binary.text_section_addr)
            .ok_or("start_addr before .text section")?;
        let file_start = (self.binary.text_section_file_offset + offset_in_text) as usize;
        let file_end = file_start + size as usize;
        if file_end > self.binary.data.len() {
            return Err(format!(
                "Address range 0x{:x}..0x{:x} extends past binary data",
                start_addr, stop_addr
            ));
        }

        let bytes = &self.binary.data[file_start..file_end];
        let engine = self.analysis_state.borrow();
        let listing =
            render_instruction_listing(bytes, start_addr, &self.binary, &engine, ListingMode::Asm);

        Ok(json!({
            "start_addr": format!("0x{:x}", start_addr),
            "stop_addr": format!("0x{:x}", stop_addr),
            "size": size,
            "listing_kind": ListingMode::Asm.label(),
            "instruction_count": listing.len(),
            "listing": listing,
        }))
    }

    pub fn get_function_at(
        &self,
        addr: u64,
        include_asm: bool,
        include_il: bool,
    ) -> Result<Value, String> {
        let func = self
            .binary
            .function_containing(addr)
            .ok_or_else(|| format!("No function containing 0x{:x}", addr))?;
        let engine = self.analysis_state.borrow();
        let mut response = json!({
            "query_addr": format!("0x{:x}", addr),
            "query_semantic": semantic_value(&engine, addr),
            "function": format!("0x{:x}", func.addr),
            "size": func.size,
            "name": option_str(func.name.as_deref()),
            "resolved_name": resolved_name_value(func.addr, func.name.as_deref(), &self.binary, &engine),
            "semantic": semantic_value(&engine, func.addr),
        });

        if let Some(mode) = ListingMode::from_flags(include_asm, include_il) {
            let bytes = self
                .binary
                .function_bytes(func)
                .ok_or("Function bytes out of range")?;
            let listing =
                render_instruction_listing(bytes, func.addr, &self.binary, &engine, mode);
            if let Some(object) = response.as_object_mut() {
                object.insert(
                    "listing_kind".to_string(),
                    Value::String(mode.label().to_string()),
                );
                object.insert(
                    "instruction_count".to_string(),
                    Value::Number((listing.len() as u64).into()),
                );
                object.insert("listing".to_string(), Value::Array(listing));
            }
        }

        Ok(response)
    }

    pub fn search_rc4(&self) -> Value {
        let mut report = crate::rc4_search::search(&self.binary);
        let engine = self.analysis_state.borrow();
        annotate_rc4_report(&mut report, &self.binary, &engine);
        report
    }

    fn find_function(&self, addr: u64) -> Result<&FunctionInfo, String> {
        self.binary
            .functions
            .iter()
            .find(|f| f.addr == addr)
            .ok_or_else(|| format!("No function at 0x{:x}", addr))
    }
}

fn function_matches_filter(func: &FunctionInfo, filter: &str, engine: &AeonEngine) -> bool {
    if filter.is_empty() {
        return true;
    }

    func.name
        .as_deref()
        .map_or(false, |name| name.contains(filter))
        || engine
            .symbol_name(func.addr)
            .map_or(false, |symbol| symbol.contains(filter))
}

fn option_str(value: Option<&str>) -> Value {
    match value {
        Some(value) => Value::String(value.to_string()),
        None => Value::Null,
    }
}

fn option_hex(value: Option<u64>) -> Value {
    match value {
        Some(value) => Value::String(format!("0x{:x}", value)),
        None => Value::Null,
    }
}

fn semantic_to_value(value: Option<SemanticContext>) -> Value {
    match value {
        Some(value) => serde_json::to_value(value).unwrap(),
        None => Value::Null,
    }
}

fn semantic_value(engine: &AeonEngine, addr: u64) -> Value {
    semantic_to_value(engine.semantic_context(addr))
}

fn exact_function_name<'a>(binary: &'a LoadedBinary, addr: u64) -> Option<&'a str> {
    binary
        .functions
        .iter()
        .find(|func| func.addr == addr)
        .and_then(|func| func.name.as_deref())
}

fn resolved_name_value(
    addr: u64,
    fallback_name: Option<&str>,
    binary: &LoadedBinary,
    engine: &AeonEngine,
) -> Value {
    match engine
        .symbol_name(addr)
        .or(fallback_name)
        .or_else(|| exact_function_name(binary, addr))
    {
        Some(value) => Value::String(value.to_string()),
        None => Value::Null,
    }
}

fn percent(count: u64, total: u64, decimals: usize) -> String {
    if total == 0 {
        return format!("{:.*}%", decimals, 0.0);
    }
    format!("{:.*}%", decimals, count as f64 / total as f64 * 100.0)
}

fn data_view(addr: u64, bytes: &[u8], binary: &LoadedBinary, engine: &AeonEngine) -> Value {
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let ascii: String = bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    json!({
        "addr": format!("0x{:x}", addr),
        "size": bytes.len(),
        "hex": hex,
        "ascii": ascii,
        "resolved_name": resolved_name_value(addr, None, binary, engine),
        "semantic": semantic_value(engine, addr),
    })
}

#[derive(Clone, Copy)]
enum ListingMode {
    Asm,
    Il,
    AsmAndIl,
}

impl ListingMode {
    fn from_flags(include_asm: bool, include_il: bool) -> Option<Self> {
        match (include_asm, include_il) {
            (true, true) => Some(Self::AsmAndIl),
            (true, false) => Some(Self::Asm),
            (false, true) => Some(Self::Il),
            (false, false) => None,
        }
    }

    fn include_asm(self) -> bool {
        matches!(self, Self::Asm | Self::AsmAndIl)
    }

    fn include_il(self) -> bool {
        matches!(self, Self::Il | Self::AsmAndIl)
    }

    fn label(self) -> &'static str {
        match self {
            Self::Asm => "asm",
            Self::Il => "il",
            Self::AsmAndIl => "asm+il",
        }
    }
}

fn render_instruction_listing(
    raw_bytes: &[u8],
    start_addr: u64,
    binary: &LoadedBinary,
    engine: &AeonEngine,
    mode: ListingMode,
) -> Vec<Value> {
    let mut listing = Vec::new();
    let mut offset = 0usize;
    let mut pc = start_addr;

    while offset + 4 <= raw_bytes.len() {
        let word = u32::from_le_bytes(raw_bytes[offset..offset + 4].try_into().unwrap());
        let next_pc = if offset + 8 <= raw_bytes.len() {
            Some(pc + 4)
        } else {
            None
        };

        let mut entry = if let Ok(insn) = bad64::decode(word, pc) {
            let result = lifter::lift(&insn, pc, next_pc);
            let mut entry = json!({
                "addr": format!("0x{:x}", pc),
            });
            if let Some(object) = entry.as_object_mut() {
                if mode.include_asm() {
                    object.insert("asm".to_string(), Value::String(result.disasm.clone()));
                }
                if mode.include_il() {
                    object.insert("il".to_string(), Value::String(format!("{:?}", result.stmt)));
                    object.insert(
                        "edges".to_string(),
                        Value::Array(
                            result
                                .edges
                                .iter()
                                .map(|edge| Value::String(format!("0x{:x}", edge)))
                                .collect(),
                        ),
                    );
                }
            }
            annotate_instruction_entry(&mut entry, pc, &result.stmt, binary, engine);
            entry
        } else {
            let mut entry = json!({
                "addr": format!("0x{:x}", pc),
            });
            if let Some(object) = entry.as_object_mut() {
                if mode.include_asm() {
                    object.insert("asm".to_string(), Value::String("(invalid)".to_string()));
                }
                if mode.include_il() {
                    object.insert("il".to_string(), Value::String("Nop".to_string()));
                }
            }
            annotate_instruction_address(&mut entry, "addr", pc, None, binary, engine);
            entry
        };

        if entry.get("semantic").is_none() {
            annotate_instruction_address(&mut entry, "addr", pc, None, binary, engine);
        }

        listing.push(entry);
        offset += 4;
        pc += 4;
    }

    listing
}

fn annotate_instruction_entry(
    entry: &mut Value,
    addr: u64,
    stmt: &Stmt,
    binary: &LoadedBinary,
    engine: &AeonEngine,
) {
    annotate_instruction_address(entry, "addr", addr, None, binary, engine);

    if let Some(call_target) = call_target(stmt) {
        let call_target_name = exact_function_name(binary, call_target);
        if let Some(object) = entry.as_object_mut() {
            object.insert(
                "call_target".to_string(),
                Value::String(format!("0x{:x}", call_target)),
            );
            object.insert("call_target_name".to_string(), option_str(call_target_name));
            object.insert(
                "call_target_resolved_name".to_string(),
                resolved_name_value(call_target, call_target_name, binary, engine),
            );
            object.insert(
                "call_target_semantic".to_string(),
                semantic_value(engine, call_target),
            );
        }
    }
}

fn call_target(stmt: &Stmt) -> Option<u64> {
    match stmt {
        Stmt::Call {
            target: Expr::Imm(target),
        } => Some(*target),
        _ => None,
    }
}

fn annotate_function_details(
    details: &mut Value,
    func: &FunctionInfo,
    binary: &LoadedBinary,
    engine: &AeonEngine,
) {
    if let Some(object) = details.as_object_mut() {
        object.insert("name".to_string(), option_str(func.name.as_deref()));
        object.insert(
            "resolved_name".to_string(),
            resolved_name_value(func.addr, func.name.as_deref(), binary, engine),
        );
        object.insert("semantic".to_string(), semantic_value(engine, func.addr));
    }

    if let Some(entries) = details.get_mut("il_listing").and_then(Value::as_array_mut) {
        annotate_listing(entries, "address", binary, engine);
    }
}

fn annotate_rc4_report(report: &mut Value, binary: &LoadedBinary, engine: &AeonEngine) {
    let Some(candidates) = report.get_mut("candidates").and_then(Value::as_array_mut) else {
        return;
    };

    for candidate in candidates {
        let Some(addr) = candidate
            .get("address")
            .and_then(Value::as_str)
            .and_then(parse_hex_value)
        else {
            continue;
        };

        if let Some(object) = candidate.as_object_mut() {
            object.insert(
                "resolved_name".to_string(),
                resolved_name_value(addr, exact_function_name(binary, addr), binary, engine),
            );
            object.insert("semantic".to_string(), semantic_value(engine, addr));
        }

        if let Some(entries) = candidate
            .get_mut("il_listing")
            .and_then(Value::as_array_mut)
        {
            annotate_listing(entries, "addr", binary, engine);
        }
    }
}

fn annotate_listing(
    entries: &mut [Value],
    addr_key: &str,
    binary: &LoadedBinary,
    engine: &AeonEngine,
) {
    for entry in entries {
        let Some(addr) = entry
            .get(addr_key)
            .and_then(Value::as_str)
            .and_then(parse_hex_value)
        else {
            continue;
        };

        annotate_instruction_address(entry, addr_key, addr, None, binary, engine);
    }
}

fn annotate_instruction_address(
    entry: &mut Value,
    _addr_key: &str,
    addr: u64,
    fallback_name: Option<&str>,
    binary: &LoadedBinary,
    engine: &AeonEngine,
) {
    if let Some(object) = entry.as_object_mut() {
        object.insert(
            "resolved_name".to_string(),
            resolved_name_value(addr, fallback_name, binary, engine),
        );
        object.insert("semantic".to_string(), semantic_value(engine, addr));
    }
}

fn parse_hex_value(value: &str) -> Option<u64> {
    let trimmed = value.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(trimmed, 16).ok()
}
