use std::cell::RefCell;
use std::collections::{hash_map::Entry, HashMap};

use serde_json::{json, Value};
use bad64;

use crate::coverage::analyze_lift_coverage;
use crate::elf::{self, FunctionInfo, LoadedBinary};
use crate::engine::{AeonEngine, SemanticContext};
use crate::function_ir::{
    decode_function, DecodedFunction, FunctionArtifacts, ReducedFunctionView, SsaFunctionView,
    StackFrameArtifactView,
};
use crate::il::{Expr, Stmt};
use crate::lifter;
use crate::object_layout::ConstructorObjectLayout;
use crate::pointer_analysis;

pub struct AeonSession {
    path: String,
    binary: LoadedBinary,
    analysis_state: RefCell<AeonEngine>,
    function_cache: RefCell<HashMap<u64, FunctionArtifacts>>,
}

impl AeonSession {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let binary = elf::load_elf(path)?;
        Ok(Self {
            path: path.to_string(),
            analysis_state: RefCell::new(AeonEngine::with_binary(binary.clone())),
            binary,
            function_cache: RefCell::new(HashMap::new()),
        })
    }

    pub fn load_raw(path: &str, base_addr: u64) -> Result<Self, Box<dyn std::error::Error>> {
        let binary = elf::load_raw(path, base_addr)?;
        Ok(Self {
            path: path.to_string(),
            analysis_state: RefCell::new(AeonEngine::with_binary(binary.clone())),
            binary,
            function_cache: RefCell::new(HashMap::new()),
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

    pub fn get_blackboard_entry(&self, addr: u64) -> Value {
        let engine = self.analysis_state.borrow();
        let func = self.binary.function_containing(addr);
        json!({
            "addr": format!("0x{:x}", addr),
            "resolved_name": resolved_name_value(addr, None, &self.binary, &engine),
            "semantic": semantic_value(&engine, addr),
            "function": func.map(|f| format!("0x{:x}", f.addr)),
            "function_name": func.and_then(|f| f.name.as_deref()).map(str::to_string),
            "function_resolved_name": func.map(|f|
                resolved_name_value(f.addr, f.name.as_deref(), &self.binary, &engine)),
        })
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
        let engine = self.analysis_state.borrow();
        self.with_function_artifacts(addr, |func, artifacts| {
            let listing =
                render_decoded_listing(artifacts.decoded(), &self.binary, &engine, ListingMode::Il);

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
        })
    }

    pub fn get_function_il(&self, addr: u64) -> Result<Value, String> {
        self.get_il(addr)
    }

    pub fn get_reduced_il(&self, addr: u64) -> Result<Value, String> {
        let engine = self.analysis_state.borrow();
        self.with_function_artifacts(addr, |func, artifacts| {
            let mut value =
                serde_json::to_value(ReducedFunctionView::from_artifacts(addr, artifacts)).unwrap();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("name".to_string(), option_str(func.name.as_deref()));
                obj.insert(
                    "resolved_name".to_string(),
                    resolved_name_value(func.addr, func.name.as_deref(), &self.binary, &engine),
                );
                obj.insert("semantic".to_string(), semantic_value(&engine, func.addr));
            }
            Ok(value)
        })
    }

    pub fn get_ssa(&self, addr: u64, optimize: bool) -> Result<Value, String> {
        let engine = self.analysis_state.borrow();
        self.with_function_artifacts(addr, |func, artifacts| {
            let mut value = serde_json::to_value(SsaFunctionView::from_artifacts(addr, artifacts, optimize))
                .unwrap();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("name".to_string(), option_str(func.name.as_deref()));
                obj.insert(
                    "resolved_name".to_string(),
                    resolved_name_value(func.addr, func.name.as_deref(), &self.binary, &engine),
                );
                obj.insert("semantic".to_string(), semantic_value(&engine, func.addr));
            }
            Ok(value)
        })
    }

    pub fn get_stack_frame(&self, addr: u64) -> Result<Value, String> {
        self.with_function_artifacts(addr, |_, artifacts| {
            Ok(
                serde_json::to_value(StackFrameArtifactView::from_artifacts(addr, artifacts))
                    .unwrap(),
            )
        })
    }

    pub fn lift_function_instructions(
        &self,
        addr: u64,
    ) -> Result<Vec<(u64, Stmt, Vec<u64>)>, String> {
        self.with_function_artifacts(addr, |_, artifacts| {
            Ok(artifacts.decoded().instruction_tuples())
        })
    }

    pub fn analyze_constructor_object_layout(
        &self,
        addr: u64,
    ) -> Result<ConstructorObjectLayout, String> {
        let func = self
            .binary
            .function_containing(addr)
            .ok_or_else(|| format!("No function containing 0x{:x}", addr))?;
        Ok(crate::object_layout::analyze_constructor_object_layout(
            &self.binary,
            func,
            addr,
        ))
    }

    pub fn get_function_details(&self, addr: u64) -> Result<Value, String> {
        let func = self.find_function(addr)?;
        let mut details = self.with_function_artifacts(addr, |_, artifacts| {
            let mut analysis = AeonEngine::new();
            analysis.ingest_decoded_function(artifacts.decoded());
            Ok(analysis.get_function_details(func.addr))
        })?;

        let engine = self.analysis_state.borrow();
        annotate_function_details(&mut details, func, &self.binary, &engine);
        Ok(details)
    }

    pub fn get_function_skeleton(&self, addr: u64) -> Result<Value, String> {
        let func = self.find_function(addr)?;

        // Get stack frame size outside the closure to avoid borrow conflicts
        let mut stack_frame_size = 0u64;
        if let Ok(sf) = self.get_stack_frame(addr) {
            if let Some(size) = sf.get("frame_size").and_then(|s| s.as_u64()) {
                stack_frame_size = size;
            }
        }

        self.with_function_artifacts(addr, |_, artifacts| {
            let decoded = artifacts.decoded();
            let instructions = &decoded.instructions;

            let mut calls = Vec::new();
            let strings: Vec<String> = Vec::new();
            let mut loop_count = 0;
            let mut has_crypto_constants = false;
            let mut suspicious_patterns = Vec::new();

            let mut seen_branches = std::collections::HashSet::new();

            for instr in instructions {
                match &instr.stmt {
                    Stmt::Branch { target } => {
                        if let Expr::Imm(addr) = target {
                            calls.push(format!("0x{:x}", addr));
                        }
                    }
                    Stmt::Call { target } => {
                        if let Expr::Imm(addr) = target {
                            calls.push(format!("0x{:x}", addr));
                        } else if let Expr::Reg(_) = target {
                            calls.push("indirect".to_string());
                        }
                    }
                    Stmt::CondBranch { target, fallthrough: _, cond: _ } => {
                        if let Expr::Imm(addr) = target {
                            if !seen_branches.insert(*addr) {
                                loop_count += 1;
                            }
                        }
                    }
                    Stmt::Assign { src, .. } => {
                        if let Expr::Imm(_) = src {
                            has_crypto_constants = true;
                        }
                    }
                    _ => {}
                }
            }

            if instructions.len() > 100 {
                suspicious_patterns.push("large_function".to_string());
            }

            let has_indirect_call = calls.iter().any(|c| c == "indirect");
            if has_indirect_call {
                suspicious_patterns.push("indirect_calls".to_string());
            }

            if has_crypto_constants {
                suspicious_patterns.push("crypto_constants".to_string());
            }

            Ok(json!({
                "addr": format!("0x{:x}", addr),
                "name": option_str(func.name.as_deref()),
                "size": decoded.size,
                "instruction_count": instructions.len(),
                "arg_count": 0, // Would need DWARF or ABI analysis
                "calls": calls,
                "strings": strings,
                "loops": loop_count,
                "crypto_constants": has_crypto_constants,
                "stack_frame_size": stack_frame_size,
                "suspicious_patterns": suspicious_patterns,
            }))
        })
    }

    pub fn get_data_flow_slice(&self, addr: u64, register: &str, direction: &str) -> Result<Value, String> {
        let _func = self.find_function(addr)?;

        let direction_lower = direction.to_lowercase();
        if direction_lower != "backward" && direction_lower != "forward" {
            return Err("Direction must be 'backward' or 'forward'".to_string());
        }

        self.with_function_artifacts(addr, |_, artifacts| {
            let decoded = artifacts.decoded();
            let instructions = &decoded.instructions;

            let target_idx = instructions.iter().position(|instr| instr.addr == addr)
                .ok_or_else(|| format!("No instruction at address 0x{:x}", addr))?;

            let mut slice_instructions = Vec::new();
            let mut complexity_flags = std::collections::HashSet::new();

            if direction_lower == "backward" {
                for i in (0..=target_idx).rev() {
                    let instr = &instructions[i];
                    let mut defines_reg = false;
                    let mut uses_reg = false;

                    match &instr.stmt {
                        Stmt::Assign { dst, src } => {
                            if register_matches(&dst, register) {
                                defines_reg = true;
                            }
                            if expr_uses_register(src, register) {
                                uses_reg = true;
                            }
                        }
                        Stmt::Call { target } => {
                            if expr_uses_register(target, register) {
                                uses_reg = true;
                            }
                            complexity_flags.insert("calls".to_string());
                        }
                        Stmt::Branch { target } => {
                            if expr_uses_register(target, register) {
                                uses_reg = true;
                            }
                        }
                        Stmt::CondBranch { target, cond, .. } => {
                            if expr_uses_register(target, register) {
                                uses_reg = true;
                            }
                            if branch_cond_uses_register(cond, register) {
                                uses_reg = true;
                            }
                            complexity_flags.insert("branches".to_string());
                        }
                        Stmt::Store { addr: addr_expr, value, .. } => {
                            if expr_uses_register(addr_expr, register) || expr_uses_register(value, register) {
                                uses_reg = true;
                            }
                        }
                        _ => {}
                    }

                    if defines_reg || uses_reg {
                        slice_instructions.push(json!({
                            "addr": format!("0x{:x}", instr.addr),
                            "role": if defines_reg { "defines" } else { "uses" },
                        }));
                    }

                    if defines_reg && i < target_idx {
                        break;
                    }
                }
                slice_instructions.reverse();
            } else {
                for i in target_idx..instructions.len() {
                    let instr = &instructions[i];
                    let mut uses_reg = false;
                    let mut defines_reg = false;

                    match &instr.stmt {
                        Stmt::Assign { dst, src } => {
                            if expr_uses_register(src, register) {
                                uses_reg = true;
                            }
                            if register_matches(&dst, register) {
                                defines_reg = true;
                            }
                        }
                        Stmt::Call { target } => {
                            if expr_uses_register(target, register) {
                                uses_reg = true;
                            }
                            complexity_flags.insert("calls".to_string());
                        }
                        Stmt::Branch { target } => {
                            if expr_uses_register(target, register) {
                                uses_reg = true;
                            }
                        }
                        Stmt::CondBranch { target, cond, .. } => {
                            if expr_uses_register(target, register) {
                                uses_reg = true;
                            }
                            if branch_cond_uses_register(cond, register) {
                                uses_reg = true;
                            }
                            complexity_flags.insert("branches".to_string());
                        }
                        Stmt::Store { addr: addr_expr, value, .. } => {
                            if expr_uses_register(addr_expr, register) || expr_uses_register(value, register) {
                                uses_reg = true;
                            }
                        }
                        _ => {}
                    }

                    if uses_reg || defines_reg {
                        slice_instructions.push(json!({
                            "addr": format!("0x{:x}", instr.addr),
                            "role": if uses_reg { "uses" } else { "defines" },
                        }));
                    }

                    if defines_reg && i > target_idx {
                        break;
                    }
                }
            }

            let complexity = if complexity_flags.is_empty() {
                "simple".to_string()
            } else if complexity_flags.len() <= 1 {
                "moderate".to_string()
            } else {
                "complex".to_string()
            };

            Ok(json!({
                "slice_type": direction_lower,
                "register": register,
                "address": format!("0x{:x}", addr),
                "instructions": slice_instructions,
                "length": slice_instructions.len(),
                "complexity": complexity,
            }))
        })
    }


    pub fn get_function_cfg(&self, addr: u64) -> Result<Value, String> {
        let func = self.find_function(addr)?;
        let details = self.get_function_details(addr)?;
        let engine = self.analysis_state.borrow();

        let mut edges = details["internal_edges"].clone();
        annotate_cfg_edges(&mut edges, &self.binary, &engine);

        Ok(json!({
            "function": format!("0x{:x}", addr),
            "name": option_str(func.name.as_deref()),
            "resolved_name": details["resolved_name"].clone(),
            "semantic": details["semantic"].clone(),
            "instruction_count": details["instruction_count"].clone(),
            "edges": edges,
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

    pub fn scan_pointers(&self) -> Value {
        serde_json::to_value(pointer_analysis::scan_pointers(&self.binary)).unwrap()
    }

    pub fn scan_vtables(&self) -> Value {
        serde_json::to_value(pointer_analysis::scan_vtables(&self.binary)).unwrap()
    }

    pub fn scan_function_pointers(
        &self,
        addr: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> Result<Value, String> {
        let report = pointer_analysis::scan_function_pointers(&self.binary, addr, offset, limit)?;
        Ok(serde_json::to_value(report).unwrap())
    }

    pub fn find_call_paths(
        &self,
        start_addr: u64,
        goal_addr: u64,
        max_depth: usize,
        include_all_paths: bool,
        max_paths: usize,
    ) -> Result<Value, String> {
        let report = pointer_analysis::find_call_paths(
            &self.binary,
            start_addr,
            goal_addr,
            max_depth,
            include_all_paths,
            max_paths,
        )?;
        let mut value = serde_json::to_value(report).unwrap();
        let engine = self.analysis_state.borrow();
        annotate_call_paths(&mut value, &self.binary, &engine);
        Ok(value)
    }

    pub fn execute_datalog(
        &self,
        query: &str,
        addr: u64,
        register: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Value, String> {
        let limit = limit.unwrap_or(500).min(5000);
        match query {
            "reachability" | "defines" | "reads_mem" | "writes_mem" | "flows_to" => {
                self.execute_function_datalog(query, addr, register, limit)
            }
            "call_graph" | "call_graph_transitive" => {
                self.execute_cross_function_datalog(query, addr, limit)
            }
            _ => Err(format!(
                "Unknown query: '{}'. Supported: reachability, defines, reads_mem, writes_mem, flows_to, call_graph, call_graph_transitive",
                query
            )),
        }
    }

    fn execute_function_datalog(
        &self,
        query: &str,
        addr: u64,
        register: Option<&str>,
        limit: usize,
    ) -> Result<Value, String> {
        use crate::datalog::{extract_function_facts, FunctionDatalog};

        self.with_function_artifacts(addr, |func, artifacts| {
            let decoded = artifacts.decoded();
            let func_addr = func.addr;

            let mut prog = FunctionDatalog::default();
            extract_function_facts(&mut prog, func_addr, decoded);
            prog.run();

            // Query results based on query type
            let mut results = Vec::new();
            match query {
                "reachability" => {
                    for (fn_addr, src, dst) in &prog.reachable {
                        if *fn_addr == func_addr && results.len() < limit {
                            results.push(json!({
                                "src": format!("0x{:x}", src),
                                "dst": format!("0x{:x}", dst),
                            }));
                        }
                    }
                }
                "defines" => {
                    for (inst_addr, reg_name) in &prog.defines {
                        if let Some(filter_reg) = register {
                            let filter_lower = filter_reg.to_lowercase();
                            let reg_base = if reg_name.starts_with('w') {
                                &reg_name[1..]
                            } else {
                                &reg_name[..]
                            };
                            let filter_base = if filter_lower.starts_with('w') {
                                &filter_lower[1..]
                            } else {
                                &filter_lower[..]
                            };
                            if reg_base != filter_base {
                                continue;
                            }
                        }
                        if results.len() < limit {
                            results.push(json!({
                                "addr": format!("0x{:x}", inst_addr),
                                "reg": reg_name,
                            }));
                        }
                    }
                }
                "reads_mem" => {
                    for (inst_addr, size) in &prog.reads_mem {
                        if results.len() < limit {
                            results.push(json!({
                                "addr": format!("0x{:x}", inst_addr),
                                "size": size,
                            }));
                        }
                    }
                }
                "writes_mem" => {
                    for (inst_addr, size) in &prog.writes_mem {
                        if results.len() < limit {
                            results.push(json!({
                                "addr": format!("0x{:x}", inst_addr),
                                "size": size,
                            }));
                        }
                    }
                }
                "flows_to" => {
                    let filter_reg = register.ok_or("flows_to query requires 'register' parameter")?;
                    for (def_addr, reg_name, use_addr) in &prog.flows_to {
                        if reg_name == filter_reg && results.len() < limit {
                            results.push(json!({
                                "from": format!("0x{:x}", def_addr),
                                "register": reg_name,
                                "to": format!("0x{:x}", use_addr),
                            }));
                        }
                    }
                }
                _ => unreachable!(),
            }

            Ok(json!({
                "query": query,
                "addr": format!("0x{:x}", addr),
                "function": format!("0x{:x}", func_addr),
                "result_count": results.len(),
                "results": results,
            }))
        })
    }

    fn execute_cross_function_datalog(
        &self,
        query: &str,
        addr: u64,
        limit: usize,
    ) -> Result<Value, String> {
        use crate::datalog::{extract_cross_function_facts, CrossFunctionDatalog};

        let mut prog = CrossFunctionDatalog::default();

        // Load facts from all functions
        for func in &self.binary.functions {
            if let Ok(decoded) = decode_function(&self.binary, func) {
                extract_cross_function_facts(&mut prog, func.addr, &decoded);
            }
        }

        // Run the Datalog program
        prog.run();

        // Query results based on query type
        let mut results = Vec::new();
        match query {
            "call_graph" => {
                for (caller, callee, call_site) in &prog.call_edge {
                    if *caller == addr && results.len() < limit {
                        results.push(json!({
                            "from": format!("0x{:x}", caller),
                            "to": format!("0x{:x}", callee),
                            "call_site": format!("0x{:x}", call_site),
                        }));
                    }
                }
            }
            "call_graph_transitive" => {
                for (caller, callee) in &prog.can_reach {
                    if *caller == addr && results.len() < limit {
                        results.push(json!({
                            "caller": format!("0x{:x}", caller),
                            "callee": format!("0x{:x}", callee),
                        }));
                    }
                }
            }
            _ => unreachable!(),
        }

        Ok(json!({
            "query": query,
            "addr": format!("0x{:x}", addr),
            "result_count": results.len(),
            "results": results,
        }))
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
        let stats = analyze_lift_coverage(self.binary.text_bytes(), self.binary.text_section_addr);
        let named_functions = self
            .binary
            .functions
            .iter()
            .filter(|f| f.name.is_some())
            .count();

        stats.to_json(
            self.binary.functions.len(),
            named_functions,
            self.binary.text_section_addr,
            self.binary.text_section_size,
        )
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
            let listing = self.with_function_artifacts(addr, |_, artifacts| {
                Ok(render_decoded_listing(
                    artifacts.decoded(),
                    &self.binary,
                    &engine,
                    mode,
                ))
            })?;
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
}

pub struct AdvancedEmulationRequest {
    pub start_addr: u64,
    pub end_addr: u64,
    pub initial_registers: HashMap<String, u64>,
    pub initial_memory: HashMap<u64, Vec<u8>>,
    pub step_limit: usize,
    pub watchpoints: Vec<crate::sandbox::WatchpointSpec>,
    pub address_hooks: Vec<crate::sandbox::AddressHookSpec>,
    pub record_pc_trace: bool,
}

impl AeonSession {
    pub fn emulate_snippet_il(
        &self,
        start_addr: u64,
        end_addr: u64,
        initial_registers: HashMap<String, u64>,
        step_limit: usize,
    ) -> Result<Value, String> {
        use crate::emulation::{self, Value as EmulValue};
        use std::collections::BTreeMap;

        if start_addr >= end_addr {
            return Err("start_addr must be less than end_addr".to_string());
        }

        let binary_len = (end_addr - start_addr) as usize;
        if binary_len > 0x10000 {
            return Err("snippet too large (max 64KB)".to_string());
        }

        let file_offset = self.binary
            .vaddr_to_file_offset(start_addr)
            .ok_or_else(|| format!("Cannot read bytes at 0x{:x}", start_addr))?;

        if file_offset + binary_len > self.binary.data.len() {
            return Err(format!("Cannot read 0x{:x} bytes at 0x{:x}", binary_len, start_addr));
        }

        let raw_bytes = &self.binary.data[file_offset..file_offset + binary_len];

        // Lift instructions in range
        let mut stmts = Vec::new();
        let mut offset = 0usize;
        let mut pc = start_addr;

        while offset + 4 <= raw_bytes.len() && pc < end_addr {
            let word = u32::from_le_bytes(raw_bytes[offset..offset + 4].try_into().unwrap());
            match bad64::decode(word, pc) {
                Ok(insn) => {
                    let next_pc = Some(pc + 4);
                    let lift_result = lifter::lift(&insn, pc, next_pc);
                    stmts.push(lift_result.stmt);
                }
                Err(_) => {
                    // Skip invalid instructions
                }
            }
            offset += 4;
            pc += 4;
        }

        // Convert initial registers from string keys to Reg enum
        let mut regs_map = BTreeMap::new();
        for (name, value) in initial_registers {
            if let Some(reg) = parse_register_name(&name) {
                regs_map.insert(reg, EmulValue::U64(value));
            }
        }

        // Create binary backing store
        struct BinaryBacking<'a>(&'a LoadedBinary);
        impl<'a> emulation::BackingStore for BinaryBacking<'a> {
            fn load(&self, addr: u64, size: u8) -> Option<Vec<u8>> {
                let off = self.0.vaddr_to_file_offset(addr)?;
                let end = off + size as usize;
                if end <= self.0.data.len() {
                    Some(self.0.data[off..end].to_vec())
                } else {
                    None
                }
            }
        }

        // Execute IL snippet with BlockExecutor (tracks reads + writes)
        let result = emulation::execute_block(
            &stmts,
            regs_map,
            BTreeMap::new(),
            &BinaryBacking(&self.binary),
            emulation::MissingMemoryPolicy::ContinueAsUnknown,
            step_limit,
        );

        // Convert result to JSON
        let mut final_regs = std::collections::HashMap::new();
        for (reg, value) in &result.final_registers {
            final_regs.insert(reg_name(reg), value_to_hex_string(value));
        }

        let memory_writes: Vec<Value> = result.writes
            .iter()
            .map(|write| {
                json!({
                    "addr": format!("{:?}", write.id.location),
                    "size": write.id.size,
                    "value": value_to_hex_string(&write.value),
                })
            })
            .collect();

        let memory_reads: Vec<Value> = result.reads
            .iter()
            .map(|read| {
                json!({
                    "addr": format!("{:?}", read.id.location),
                    "size": read.id.size,
                    "value": value_to_hex_string(&read.value),
                })
            })
            .collect();

        let budget_exhausted = matches!(result.stop, emulation::BlockStop::StepBudget);

        Ok(json!({
            "mode": "il",
            "start_addr": format!("0x{:x}", start_addr),
            "end_addr": format!("0x{:x}", end_addr),
            "steps_executed": result.steps_executed,
            "budget_exhausted": budget_exhausted,
            "final_registers": final_regs,
            "memory_writes": memory_writes,
            "memory_reads": memory_reads,
        }))
    }

    pub fn emulate_snippet(
        &self,
        start_addr: u64,
        end_addr: u64,
        initial_registers: HashMap<String, u64>,
        initial_memory: HashMap<u64, Vec<u8>>,
        step_limit: usize,
    ) -> Result<Value, String> {
        use crate::sandbox::{run_sandbox, SandboxConfig};
        let config = SandboxConfig { step_limit, ..Default::default() };
        let result = run_sandbox(&self.binary, start_addr, end_addr, &initial_registers, &initial_memory, &config)?;
        serde_json::to_value(&result).map_err(|e| format!("serialize result: {}", e))
    }

    pub fn emulate_snippet_native_advanced(&self, req: AdvancedEmulationRequest) -> Result<Value, String> {
        use crate::sandbox::{run_sandbox, SandboxConfig};
        let config = SandboxConfig {
            step_limit: req.step_limit,
            watchpoints: req.watchpoints,
            address_hooks: req.address_hooks,
            record_pc_trace: req.record_pc_trace,
            ..Default::default()
        };
        let result = run_sandbox(&self.binary, req.start_addr, req.end_addr, &req.initial_registers, &req.initial_memory, &config)?;
        serde_json::to_value(&result).map_err(|e| format!("serialize result: {}", e))
    }

    /// Create instrumentation for a code region
    pub fn create_instrumentation(
        &self,
        start_addr: u64,
        end_addr: u64,
    ) -> Result<crate::instrumentation::InstrumentationBuilder, String> {
        if start_addr >= end_addr {
            return Err("start_addr must be less than end_addr".to_string());
        }

        // Get bytes for the region
        let size = (end_addr - start_addr) as usize;
        if size > 0x100000 {
            return Err("region too large (max 1MB)".to_string());
        }

        let bytes = vec![0u8; size];
        let region = crate::rewriter::CodeRegion::new(start_addr, end_addr, bytes);

        Ok(crate::instrumentation::InstrumentationBuilder::new()
            .register_region(region)?)
    }

    /// Get rewriter info for all registered regions
    pub fn instrumentation_info(&self) -> Value {
        json!({
            "status": "instrumentation framework ready",
            "phases": {
                "phase_1": "Core Rewriter (shadow memory, PC redirection)",
                "phase_2": "IL Storage (LLIL/MLIL/HLIL queries)",
                "phase_3": "Hook Engine (sandboxed execution context)",
                "phase_4": "Rust Scripting API (high-level hooks)",
                "phase_5": "AeonSession Integration (this endpoint)"
            },
            "hooks_available": [
                "InstructionTracer - log all instructions",
                "MemoryTracer - log memory accesses",
                "RegisterTracer - track register changes",
                "BranchTracer - log branches/calls",
                "Custom hooks via InstrumentationHook trait"
            ]
        })
    }

    fn with_function_artifacts<T>(
        &self,
        addr: u64,
        f: impl FnOnce(&FunctionInfo, &mut FunctionArtifacts) -> Result<T, String>,
    ) -> Result<T, String> {
        let func = self
            .binary
            .function_containing(addr)
            .ok_or_else(|| format!("No function containing 0x{:x}", addr))?;
        let mut cache = self.function_cache.borrow_mut();

        let artifacts = match cache.entry(func.addr) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let decoded = decode_function(&self.binary, func)?;
                entry.insert(FunctionArtifacts::new(decoded))
            }
        };

        f(func, artifacts)
    }

    fn find_function(&self, addr: u64) -> Result<&FunctionInfo, String> {
        self.binary
            .functions
            .iter()
            .find(|f| f.addr == addr)
            .ok_or_else(|| format!("No function at 0x{:x}", addr))
    }
}

use aeonil::Reg;

pub(crate) fn reg_name(r: &Reg) -> String {
    match r {
        Reg::X(n) => format!("x{}", n),
        Reg::W(n) => format!("w{}", n),
        Reg::SP => "sp".to_string(),
        Reg::PC => "pc".to_string(),
        Reg::XZR => "xzr".to_string(),
        Reg::Flags => "flags".to_string(),
        Reg::V(n) => format!("v{}", n),
        Reg::Q(n) => format!("q{}", n),
        Reg::D(n) => format!("d{}", n),
        Reg::S(n) => format!("s{}", n),
        Reg::H(n) => format!("h{}", n),
        Reg::VByte(n) => format!("b{}", n),
    }
}

fn parse_register_name(name: &str) -> Option<Reg> {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "x0" => Some(Reg::X(0)),
        "x1" => Some(Reg::X(1)),
        "x2" => Some(Reg::X(2)),
        "x3" => Some(Reg::X(3)),
        "x4" => Some(Reg::X(4)),
        "x5" => Some(Reg::X(5)),
        "x6" => Some(Reg::X(6)),
        "x7" => Some(Reg::X(7)),
        "x8" => Some(Reg::X(8)),
        "x9" => Some(Reg::X(9)),
        "x10" => Some(Reg::X(10)),
        "x11" => Some(Reg::X(11)),
        "x12" => Some(Reg::X(12)),
        "x13" => Some(Reg::X(13)),
        "x14" => Some(Reg::X(14)),
        "x15" => Some(Reg::X(15)),
        "x16" => Some(Reg::X(16)),
        "x17" => Some(Reg::X(17)),
        "x18" => Some(Reg::X(18)),
        "x19" => Some(Reg::X(19)),
        "x20" => Some(Reg::X(20)),
        "x21" => Some(Reg::X(21)),
        "x22" => Some(Reg::X(22)),
        "x23" => Some(Reg::X(23)),
        "x24" => Some(Reg::X(24)),
        "x25" => Some(Reg::X(25)),
        "x26" => Some(Reg::X(26)),
        "x27" => Some(Reg::X(27)),
        "x28" => Some(Reg::X(28)),
        "x29" => Some(Reg::X(29)),
        "x30" => Some(Reg::X(30)),
        "sp" => Some(Reg::SP),
        "pc" => Some(Reg::PC),
        _ => None,
    }
}

fn value_to_hex_string(value: &crate::emulation::Value) -> String {
    match value {
        crate::emulation::Value::U64(v) => format!("0x{:x}", v),
        crate::emulation::Value::U128(v) => format!("0x{:x}", v),
        crate::emulation::Value::F64(v) => format!("0x{:x}", v.to_bits()),
        crate::emulation::Value::Unknown => "unknown".to_string(),
    }
}

pub(crate) fn register_matches(reg: &Reg, target: &str) -> bool {
    let reg_name = reg_name(reg);
    let target_lower = target.to_lowercase();

    let reg_base = if reg_name.starts_with('w') {
        &reg_name[1..]
    } else {
        &reg_name[..]
    };

    let target_base = if target_lower.starts_with('w') {
        &target_lower[1..]
    } else {
        &target_lower[..]
    };

    reg_base == target_base
}



pub(crate) fn expr_uses_register(expr: &Expr, register: &str) -> bool {
    match expr {
        Expr::Reg(r) => register_matches(r, register),
        // Binary operations that might use registers
        Expr::Add(left, right)
        | Expr::Sub(left, right)
        | Expr::Mul(left, right)
        | Expr::Div(left, right)
        | Expr::UDiv(left, right)
        | Expr::Xor(left, right)
        | Expr::And(left, right)
        | Expr::Or(left, right)
        | Expr::Shl(left, right)
        | Expr::Lsr(left, right)
        | Expr::Asr(left, right)
        | Expr::Ror(left, right)
        | Expr::FAdd(left, right)
        | Expr::FSub(left, right)
        | Expr::FMul(left, right)
        | Expr::FDiv(left, right)
        | Expr::FMax(left, right)
        | Expr::FMin(left, right) => {
            expr_uses_register(left, register) || expr_uses_register(right, register)
        }
        // Unary operations that might use registers
        Expr::Neg(e)
        | Expr::Abs(e)
        | Expr::Not(e)
        | Expr::FNeg(e)
        | Expr::FAbs(e)
        | Expr::FSqrt(e)
        | Expr::FCvt(e)
        | Expr::IntToFloat(e)
        | Expr::FloatToInt(e)
        | Expr::Clz(e)
        | Expr::Cls(e)
        | Expr::Rev(e)
        | Expr::Rbit(e) => {
            expr_uses_register(e, register)
        }
        // Extension operations
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } => {
            expr_uses_register(src, register)
        }
        // Bitfield operations
        Expr::Extract { src, .. } => expr_uses_register(src, register),
        Expr::Insert { dst, src, .. } => {
            expr_uses_register(dst, register) || expr_uses_register(src, register)
        }
        // Memory operations
        Expr::Load { addr, .. } => expr_uses_register(addr, register),
        // Conditional operations
        Expr::CondSelect { if_true, if_false, .. } => {
            expr_uses_register(if_true, register) || expr_uses_register(if_false, register)
        }
        Expr::Compare { lhs, rhs, .. } => {
            expr_uses_register(lhs, register) || expr_uses_register(rhs, register)
        }
        // Constants and literals
        Expr::Imm(_) | Expr::FImm(_) | Expr::AdrpImm(_) | Expr::AdrImm(_) => false,
        // Stack slots don't directly use registers (the SP is implicit)
        Expr::StackSlot { .. } => false,
        // System register reads don't use GPRs
        Expr::MrsRead(_) => false,
        // Intrinsic operations might use registers
        Expr::Intrinsic { operands, .. } => {
            operands.iter().any(|op| expr_uses_register(op, register))
        }
    }
}

pub(crate) fn branch_cond_uses_register(cond: &aeonil::BranchCond, register: &str) -> bool {
    use aeonil::BranchCond;
    match cond {
        BranchCond::Flag(_) => false,
        BranchCond::Zero(e) | BranchCond::NotZero(e) | BranchCond::BitZero(e, _) | BranchCond::BitNotZero(e, _) => {
            expr_uses_register(e, register)
        }
        BranchCond::Compare { lhs, rhs, .. } => {
            expr_uses_register(lhs, register) || expr_uses_register(rhs, register)
        }
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

fn annotate_cfg_edges(edges: &mut Value, binary: &LoadedBinary, engine: &AeonEngine) {
    let Some(arr) = edges.as_array_mut() else { return };
    for edge in arr {
        let Some(obj) = edge.as_object_mut() else { continue };
        for key in &["src", "dst"] {
            let addr_str = obj
                .get(*key)
                .and_then(Value::as_str)
                .and_then(parse_hex_value);
            if let Some(addr) = addr_str {
                let name_key = format!("{}_name", key);
                obj.insert(
                    name_key,
                    resolved_name_value(addr, None, binary, engine),
                );
            }
        }
    }
}

fn annotate_call_paths(root: &mut Value, binary: &LoadedBinary, engine: &AeonEngine) {
    if let Some(path) = root.get_mut("shortest_path") {
        if let Some(functions) = path.get_mut("functions").and_then(Value::as_array_mut) {
            let mut annotated = Vec::new();
            for func_val in functions.iter() {
                if let Some(addr_str) = func_val.as_str().and_then(parse_hex_value) {
                    let resolved = resolved_name_value(addr_str, None, binary, engine);
                    annotated.push(json!({
                        "addr": func_val,
                        "resolved_name": resolved
                    }));
                } else {
                    annotated.push(func_val.clone());
                }
            }
            *functions = annotated;
        }
    }

    if let Some(all_paths) = root.get_mut("all_paths").and_then(Value::as_array_mut) {
        for path in all_paths {
            if let Some(functions) = path.get_mut("functions").and_then(Value::as_array_mut) {
                let mut annotated = Vec::new();
                for func_val in functions.iter() {
                    if let Some(addr_str) = func_val.as_str().and_then(parse_hex_value) {
                        let resolved = resolved_name_value(addr_str, None, binary, engine);
                        annotated.push(json!({
                            "addr": func_val,
                            "resolved_name": resolved
                        }));
                    } else {
                        annotated.push(func_val.clone());
                    }
                }
                *functions = annotated;
            }
        }
    }
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
                    object.insert(
                        "il".to_string(),
                        Value::String(format!("{:?}", result.stmt)),
                    );
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

fn render_decoded_listing(
    decoded: &DecodedFunction,
    binary: &LoadedBinary,
    engine: &AeonEngine,
    mode: ListingMode,
) -> Vec<Value> {
    let mut listing = Vec::new();

    for instruction in &decoded.instructions {
        let mut entry = json!({
            "addr": format!("0x{:x}", instruction.addr),
        });

        if let Some(object) = entry.as_object_mut() {
            if mode.include_asm() {
                object.insert("asm".to_string(), Value::String(instruction.asm.clone()));
            }
            if mode.include_il() {
                object.insert(
                    "il".to_string(),
                    Value::String(format!("{:?}", instruction.stmt)),
                );
                object.insert(
                    "edges".to_string(),
                    Value::Array(
                        instruction
                            .edges
                            .iter()
                            .map(|edge| Value::String(format!("0x{:x}", edge)))
                            .collect(),
                    ),
                );
            }
        }

        if instruction.valid {
            annotate_instruction_entry(
                &mut entry,
                instruction.addr,
                &instruction.stmt,
                binary,
                engine,
            );
        } else {
            annotate_instruction_address(
                &mut entry,
                "addr",
                instruction.addr,
                None,
                binary,
                engine,
            );
        }

        listing.push(entry);
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value;

    use super::AeonSession;

    fn sample_binary_path() -> String {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .join("../../samples/hello_aarch64.elf")
            .display()
            .to_string()
    }

    fn session() -> AeonSession {
        AeonSession::load(&sample_binary_path()).expect("sample binary should load")
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
    fn reduced_il_json_exposes_block_shape_and_stack_slots() {
        let session = session();
        let reduced = session
            .get_reduced_il(0x718)
            .expect("reduced IL should succeed");

        assert_eq!(reduced["artifact"], "reduced_il");
        assert_eq!(reduced["function"], "0x718");
        assert!(
            reduced["block_count"]
                .as_u64()
                .is_some_and(|count| count >= 1),
            "reduced IL should report block count"
        );
        assert!(
            reduced["blocks"]
                .as_array()
                .is_some_and(|blocks| !blocks.is_empty()),
            "reduced IL should include blocks"
        );
        assert!(
            has_stack_slot(&reduced),
            "reduced IL should expose stack_slot operands"
        );
    }

    #[test]
    fn ssa_json_exposes_metrics_and_stack_slots() {
        let session = session();
        let ssa = session
            .get_ssa(0x718, false)
            .expect("SSA view should succeed");

        assert_eq!(ssa["artifact"], "ssa");
        assert_eq!(ssa["optimized"], false);
        assert!(
            ssa["metrics"]["stack_slot_count"]
                .as_u64()
                .is_some_and(|count| count > 0),
            "SSA metrics should count visible stack slots"
        );
        assert!(
            has_stack_slot(&ssa),
            "SSA JSON should expose stack_slot expressions"
        );
    }

    #[test]
    fn stack_frame_json_reports_saved_registers_and_slots() {
        let session = session();
        let frame = session
            .get_stack_frame(0x7d8)
            .expect("stack frame should succeed");

        assert_eq!(frame["artifact"], "stack_frame");
        assert_eq!(frame["detected"], true);
        assert_eq!(frame["frame_size"], 32);
        assert!(
            frame["saved_regs"]
                .as_array()
                .is_some_and(|saved| saved.iter().any(|reg| reg["reg"] == "x29")),
            "stack frame summary should expose saved registers"
        );
        assert!(
            frame["slots"]
                .as_array()
                .is_some_and(|slots| !slots.is_empty()),
            "stack frame summary should include visible stack slots"
        );
    }
}
