use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use serde_json::{json, Value};

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
use crate::xref_graph;
use crate::xref_scan;

const DEFAULT_FUNCTION_CACHE_MAX_BYTES: usize = 4 * 1024 * 1024 * 1024;
const DEFAULT_FUNCTION_CACHE_MAX_ENTRIES: usize = 256;

pub struct AeonSession {
    path: String,
    binary: LoadedBinary,
    analysis_state: RefCell<AeonEngine>,
    function_cache: RefCell<FunctionArtifactCache>,
    xref_graph_cache: RefCell<Option<xref_graph::XrefGraph>>,
}

impl AeonSession {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let binary = elf::load_elf(path)?;
        Ok(Self {
            path: path.to_string(),
            analysis_state: RefCell::new(AeonEngine::new()),
            binary,
            function_cache: RefCell::new(FunctionArtifactCache::new_from_env()),
            xref_graph_cache: RefCell::new(None),
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
        let function_cache = self.function_cache.borrow();
        json!({
            "status": "loaded",
            "path": self.path,
            "text_section_addr": format!("0x{:x}", self.binary.text_section_addr),
            "text_section_size": format!("0x{:x}", self.binary.text_section_size),
            "total_functions": self.binary.functions.len(),
            "named_functions": self.binary.functions.iter().filter(|f| f.name.is_some()).count(),
            "function_cache_max_bytes": function_cache.max_bytes,
            "function_cache_max_entries": function_cache.max_entries,
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
        self.with_function_artifacts(addr, |_, artifacts| {
            Ok(serde_json::to_value(ReducedFunctionView::from_artifacts(addr, artifacts)).unwrap())
        })
    }

    pub fn get_ssa(&self, addr: u64, optimize: bool) -> Result<Value, String> {
        self.with_function_artifacts(addr, |_, artifacts| {
            Ok(
                serde_json::to_value(SsaFunctionView::from_artifacts(addr, artifacts, optimize))
                    .unwrap(),
            )
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

    pub fn scan_pointers(&self) -> Value {
        serde_json::to_value(pointer_analysis::scan_pointers(&self.binary)).unwrap()
    }

    pub fn scan_vtables(&self, include_functions: bool) -> Value {
        serde_json::to_value(pointer_analysis::scan_vtables_for_output(
            &self.binary,
            include_functions,
        ))
        .unwrap()
    }

    pub fn scan_xrefs_pass(&self, threads: Option<usize>) -> Result<Value, String> {
        let report = xref_scan::scan_all_xrefs(&self.binary, threads)?;
        Ok(serde_json::to_value(report).unwrap())
    }

    pub fn xref_graph_summary(
        &self,
        threads: Option<usize>,
    ) -> Result<xref_graph::XrefGraphSummaryReport, String> {
        self.with_xref_graph(threads, |graph| Ok(graph.summary()))
    }

    pub fn xref_graph_build_stats(
        &self,
        threads: Option<usize>,
    ) -> Result<xref_graph::XrefGraphBuildStats, String> {
        xref_graph::XrefGraph::estimate(&self.binary, threads)
    }

    pub fn get_xref_graph_summary(&self, threads: Option<usize>) -> Result<Value, String> {
        let report = self.xref_graph_summary(threads)?;
        Ok(serde_json::to_value(report).unwrap())
    }

    pub fn find_xref_path_report(
        &self,
        start_addr: u64,
        goal_addr: u64,
        max_depth: usize,
        include_all_paths: bool,
        max_paths: usize,
        threads: Option<usize>,
    ) -> Result<xref_graph::XrefPathSearchReport, String> {
        self.with_xref_graph(threads, |graph| {
            graph.find_paths(
                &self.binary,
                start_addr,
                goal_addr,
                max_depth,
                include_all_paths,
                max_paths,
            )
        })
    }

    pub fn find_xref_paths(
        &self,
        start_addr: u64,
        goal_addr: u64,
        max_depth: usize,
        include_all_paths: bool,
        max_paths: usize,
        threads: Option<usize>,
    ) -> Result<Value, String> {
        let report = self.find_xref_path_report(
            start_addr,
            goal_addr,
            max_depth,
            include_all_paths,
            max_paths,
            threads,
        )?;
        Ok(serde_json::to_value(report).unwrap())
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
        Ok(serde_json::to_value(report).unwrap())
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
        cache.with_function(&self.binary, func, |artifacts| f(func, artifacts))
    }

    fn with_xref_graph<T>(
        &self,
        threads: Option<usize>,
        f: impl FnOnce(&xref_graph::XrefGraph) -> Result<T, String>,
    ) -> Result<T, String> {
        if self.xref_graph_cache.borrow().is_none() {
            let graph = xref_graph::XrefGraph::build(&self.binary, threads)?;
            *self.xref_graph_cache.borrow_mut() = Some(graph);
        }

        let cache = self.xref_graph_cache.borrow();
        let graph = cache
            .as_ref()
            .expect("xref graph cache should be populated");
        f(graph)
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

struct CachedFunctionArtifacts {
    artifacts: FunctionArtifacts,
    estimated_bytes: usize,
}

struct FunctionArtifactCache {
    entries: HashMap<u64, CachedFunctionArtifacts>,
    lru: VecDeque<u64>,
    current_bytes: usize,
    max_bytes: usize,
    max_entries: usize,
}

impl FunctionArtifactCache {
    fn new_from_env() -> Self {
        Self {
            entries: HashMap::new(),
            lru: VecDeque::new(),
            current_bytes: 0,
            max_bytes: parse_cache_limit_bytes_from_env()
                .unwrap_or(DEFAULT_FUNCTION_CACHE_MAX_BYTES),
            max_entries: DEFAULT_FUNCTION_CACHE_MAX_ENTRIES,
        }
    }

    fn with_function<T>(
        &mut self,
        binary: &LoadedBinary,
        func: &FunctionInfo,
        f: impl FnOnce(&mut FunctionArtifacts) -> Result<T, String>,
    ) -> Result<T, String> {
        if !self.entries.contains_key(&func.addr) {
            let decoded = decode_function(binary, func)?;
            self.insert(func.addr, FunctionArtifacts::new(decoded));
        }

        self.touch(func.addr);

        let (result, old_size, new_size) = {
            let entry = self.entries.get_mut(&func.addr).unwrap();
            let old_size = entry.estimated_bytes;
            let result = f(&mut entry.artifacts);
            let new_size = entry.artifacts.estimated_bytes();
            entry.estimated_bytes = new_size;
            (result, old_size, new_size)
        };

        self.current_bytes = self.current_bytes.saturating_sub(old_size);
        self.current_bytes = self.current_bytes.saturating_add(new_size);
        self.evict_if_needed(Some(func.addr));
        result
    }

    fn insert(&mut self, addr: u64, artifacts: FunctionArtifacts) {
        let estimated_bytes = artifacts.estimated_bytes();
        self.current_bytes = self.current_bytes.saturating_add(estimated_bytes);
        self.entries.insert(
            addr,
            CachedFunctionArtifacts {
                artifacts,
                estimated_bytes,
            },
        );
        self.touch(addr);
        self.evict_if_needed(Some(addr));
    }

    fn touch(&mut self, addr: u64) {
        if let Some(position) = self.lru.iter().position(|existing| *existing == addr) {
            self.lru.remove(position);
        }
        self.lru.push_back(addr);
    }

    fn evict_if_needed(&mut self, protected: Option<u64>) {
        while self.entries.len() > self.max_entries || self.current_bytes > self.max_bytes {
            let Some(candidate) = self.lru.pop_front() else {
                break;
            };

            if Some(candidate) == protected {
                self.lru.push_back(candidate);
                if self.entries.len() == 1 {
                    break;
                }
                continue;
            }

            if let Some(entry) = self.entries.remove(&candidate) {
                self.current_bytes = self.current_bytes.saturating_sub(entry.estimated_bytes);
            }
        }
    }
}

fn parse_cache_limit_bytes_from_env() -> Option<usize> {
    if let Some(value) = std::env::var_os("AEON_FUNCTION_CACHE_BYTES") {
        return value.to_str().and_then(parse_nonzero_usize);
    }

    if let Some(value) = std::env::var_os("AEON_FUNCTION_CACHE_GB") {
        return value
            .to_str()
            .and_then(parse_nonzero_usize)
            .map(|gigabytes| gigabytes.saturating_mul(1024 * 1024 * 1024));
    }

    None
}

fn parse_nonzero_usize(value: &str) -> Option<usize> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("off") || trimmed == "0" {
        return None;
    }
    trimmed.parse::<usize>().ok()
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
