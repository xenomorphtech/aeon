use std::cell::RefCell;

use serde_json::{json, Value};

use crate::elf::{self, FunctionInfo, LoadedBinary};
use crate::engine::AeonEngine;
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
        self.analysis_state
            .borrow_mut()
            .set_analysis_name(addr, name.to_string());

        json!({
            "status": "assigned",
            "addr": format!("0x{:x}", addr),
            "analysis_name": name,
        })
    }

    pub fn search_analysis_names(&self, pattern: &str) -> Result<Value, String> {
        let matches = self
            .analysis_state
            .borrow_mut()
            .search_analysis_names(pattern)
            .map_err(|e| format!("Invalid regex: {}", e))?;

        let matches: Vec<Value> = matches
            .into_iter()
            .map(|entry| {
                json!({
                    "addr": format!("0x{:x}", entry.address),
                    "analysis_name": entry.analysis_name,
                    "function": option_hex(entry.function),
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
        json!({
            "status": "loaded",
            "path": self.path,
            "text_section_addr": format!("0x{:x}", self.binary.text_section_addr),
            "text_section_size": format!("0x{:x}", self.binary.text_section_size),
            "total_functions": self.binary.functions.len(),
            "named_functions": self.binary.functions.iter().filter(|f| f.name.is_some()).count(),
        })
    }

    pub fn list_functions(&self, offset: usize, limit: usize, name_filter: Option<&str>) -> Value {
        let name_filter = name_filter.unwrap_or("");
        let filtered: Vec<&FunctionInfo> = if name_filter.is_empty() {
            self.binary.functions.iter().collect()
        } else {
            self.binary
                .functions
                .iter()
                .filter(|f| f.name.as_deref().map_or(false, |n| n.contains(name_filter)))
                .collect()
        };

        let total = filtered.len();
        let functions: Vec<Value> = filtered
            .iter()
            .skip(offset)
            .take(limit)
            .map(|f| {
                json!({
                    "addr": format!("0x{:x}", f.addr),
                    "size": f.size,
                    "name": option_str(f.name.as_deref()),
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

    pub fn get_function_il(&self, addr: u64) -> Result<Value, String> {
        let func = self.find_function(addr)?;
        let bytes = self
            .binary
            .function_bytes(func)
            .ok_or("Function bytes out of range")?;
        let listing = lift_function(bytes, addr);

        Ok(json!({
            "function": format!("0x{:x}", addr),
            "size": func.size,
            "name": option_str(func.name.as_deref()),
            "instruction_count": listing.len(),
            "listing": listing,
        }))
    }

    pub fn get_function_details(&self, addr: u64) -> Result<Value, String> {
        let func = self.find_function(addr)?;
        let bytes = self
            .binary
            .function_bytes(func)
            .ok_or("Function bytes out of range")?;

        let mut engine = AeonEngine::new();
        engine.ingest_function(addr, bytes);
        Ok(engine.get_function_details(addr))
    }

    pub fn get_function_cfg(&self, addr: u64) -> Result<Value, String> {
        let func = self.find_function(addr)?;
        let details = self.get_function_details(addr)?;

        Ok(json!({
            "function": format!("0x{:x}", addr),
            "name": option_str(func.name.as_deref()),
            "instruction_count": details["instruction_count"],
            "edges": details["internal_edges"],
            "terminal_blocks": details["terminal_blocks"],
            "reachable_paths": details["reachable_paths_count"],
        }))
    }

    pub fn get_xrefs(&self, target_addr: u64) -> Value {
        let target_func = self.binary.functions.iter().find(|f| f.addr == target_addr);

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
                            let callee_name = self
                                .binary
                                .functions
                                .iter()
                                .find(|f| f.addr == *target)
                                .and_then(|f| f.name.as_deref());
                            calls_out.push(json!({
                                "from": format!("0x{:x}", pc),
                                "to": format!("0x{:x}", target),
                                "name": option_str(callee_name),
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
        Ok(data_view(addr, bytes))
    }

    pub fn get_data(&self, addr: u64, size: usize) -> Result<Value, String> {
        let size = size.min(4096);
        let bytes = self
            .binary
            .read_vaddr(addr, size)
            .ok_or_else(|| format!("Cannot read address 0x{:x} — not in any LOAD segment", addr))?;
        Ok(data_view(addr, bytes))
    }

    pub fn get_string(&self, addr: u64, max_len: usize) -> Result<Value, String> {
        let max_len = max_len.min(4096);
        let string = self
            .binary
            .read_string(addr, max_len)
            .ok_or_else(|| format!("Cannot read address 0x{:x} — not in any LOAD segment", addr))?;

        Ok(json!({
            "addr": format!("0x{:x}", addr),
            "length": string.len(),
            "string": string,
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

        let named_functions = self.binary.functions.iter().filter(|f| f.name.is_some()).count();

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
        let listing = lift_function(bytes, start_addr);

        Ok(json!({
            "start_addr": format!("0x{:x}", start_addr),
            "stop_addr": format!("0x{:x}", stop_addr),
            "size": size,
            "instruction_count": listing.len(),
            "listing": listing,
        }))
    }

    pub fn get_function_at(&self, addr: u64) -> Result<Value, String> {
        let func = self
            .binary
            .function_containing(addr)
            .ok_or_else(|| format!("No function containing 0x{:x}", addr))?;

        let bytes = self
            .binary
            .function_bytes(func)
            .ok_or("Function bytes out of range")?;
        let listing = lift_function(bytes, func.addr);

        Ok(json!({
            "query_addr": format!("0x{:x}", addr),
            "function": format!("0x{:x}", func.addr),
            "size": func.size,
            "name": option_str(func.name.as_deref()),
            "instruction_count": listing.len(),
            "listing": listing,
        }))
    }

    pub fn search_rc4(&self) -> Value {
        crate::rc4_search::search(&self.binary)
    }

    fn find_function(&self, addr: u64) -> Result<&FunctionInfo, String> {
        self.binary
            .functions
            .iter()
            .find(|f| f.addr == addr)
            .ok_or_else(|| format!("No function at 0x{:x}", addr))
    }
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

fn percent(count: u64, total: u64, decimals: usize) -> String {
    if total == 0 {
        return format!("{:.*}%", decimals, 0.0);
    }
    format!("{:.*}%", decimals, count as f64 / total as f64 * 100.0)
}

fn data_view(addr: u64, bytes: &[u8]) -> Value {
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let ascii: String = bytes
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect();

    json!({
        "addr": format!("0x{:x}", addr),
        "size": bytes.len(),
        "hex": hex,
        "ascii": ascii,
    })
}

fn lift_function(raw_bytes: &[u8], start_addr: u64) -> Vec<Value> {
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

        let entry = if let Ok(insn) = bad64::decode(word, pc) {
            let result = lifter::lift(&insn, pc, next_pc);
            json!({
                "addr": format!("0x{:x}", pc),
                "asm": result.disasm,
                "il": format!("{:?}", result.stmt),
                "edges": result.edges.iter().map(|edge| format!("0x{:x}", edge)).collect::<Vec<_>>(),
            })
        } else {
            json!({
                "addr": format!("0x{:x}", pc),
                "asm": "(invalid)",
                "il": "Nop",
            })
        };

        listing.push(entry);
        offset += 4;
        pc += 4;
    }

    listing
}
