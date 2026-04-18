use std::collections::HashMap;

use bevy_ecs::world::World;
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};

use crate::analysis::AeonAnalysis;
use crate::components::{Address, BelongsToFunction, CfgEdges, LiftedIL, RawInstruction};
use crate::coverage::analyze_lift_coverage;
use crate::elf::LoadedBinary;
use crate::facts::{analyze_function, FunctionAnalysis};
use crate::function_ir::DecodedFunction;
use crate::il::Stmt;
use crate::lifter;

pub struct AeonEngine {
    pub world: World,
    pub binary: Option<LoadedBinary>,
    semantic: HashMap<u64, SemanticContext>,
    function_analyses: HashMap<u64, FunctionAnalysis>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SemanticContext {
    pub symbol: Option<String>,
    pub struct_definition: Option<String>,
    pub hypotheses: Vec<String>,
}

impl SemanticContext {
    fn is_empty(&self) -> bool {
        self.symbol.is_none() && self.struct_definition.is_none() && self.hypotheses.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct BlackboardSummary {
    pub entries: usize,
    pub renamed_symbols: usize,
    pub defined_structs: usize,
    pub hypotheses: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AnalysisNameMatch {
    pub address: u64,
    pub analysis_name: String,
}

impl AeonEngine {
    pub fn new() -> Self {
        AeonEngine {
            world: World::new(),
            binary: None,
            semantic: HashMap::new(),
            function_analyses: HashMap::new(),
        }
    }

    pub fn with_binary(binary: LoadedBinary) -> Self {
        let mut engine = Self::new();
        engine.binary = Some(binary);
        engine
    }

    pub fn load_binary(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let binary = crate::elf::load_elf(path)?;
        eprintln!(
            "Loaded: .text at 0x{:x}, size 0x{:x}, {} functions from eh_frame",
            binary.text_section_addr,
            binary.text_section_size,
            binary.functions.len()
        );
        self.binary = Some(binary);
        self.function_analyses.clear();
        Ok(())
    }

    /// Ingest a single function into ECS by address lookup from loaded binary
    pub fn ingest_function_by_addr(&mut self, func_addr: u64) -> bool {
        let binary = match &self.binary {
            Some(b) => b,
            None => return false,
        };

        let func = match binary.functions.iter().find(|f| f.addr == func_addr) {
            Some(f) => f,
            None => return false,
        };

        let raw_bytes = match binary.function_bytes(func) {
            Some(b) => b.to_vec(),
            None => return false,
        };

        self.ingest_function(func_addr, &raw_bytes);
        true
    }

    pub fn function_analysis(&mut self, func_addr: u64) -> Option<&FunctionAnalysis> {
        if !self.function_analyses.contains_key(&func_addr) {
            let raw_bytes = {
                let binary = self.binary.as_ref()?;
                let func = binary.functions.iter().find(|f| f.addr == func_addr)?;
                binary.function_bytes(func)?.to_vec()
            };
            let analysis = analyze_function(&raw_bytes, func_addr);
            self.function_analyses.insert(func_addr, analysis);
        }

        self.function_analyses.get(&func_addr)
    }

    /// Ingest raw function bytes into ECS
    pub fn ingest_function(&mut self, func_addr: u64, raw_bytes: &[u8]) {
        let mut decoded = Vec::new();
        let mut offset = 0usize;
        let mut pc = func_addr;

        while offset + 4 <= raw_bytes.len() {
            let word = u32::from_le_bytes(raw_bytes[offset..offset + 4].try_into().unwrap());
            let decode_result = bad64::decode(word, pc);
            decoded.push((pc, decode_result));
            offset += 4;
            pc += 4;
        }

        for (i, (inst_pc, ref decode_result)) in decoded.iter().enumerate() {
            let inst_pc = *inst_pc;
            let next_pc = decoded.get(i + 1).map(|(addr, _)| *addr);

            let result = match decode_result {
                Ok(insn) => lifter::lift(insn, inst_pc, next_pc),
                Err(_) => lifter::LiftResult {
                    disasm: "(invalid)".to_string(),
                    stmt: Stmt::Nop,
                    edges: next_pc.into_iter().collect(),
                },
            };

            let mut entity = self.world.spawn((
                Address(inst_pc),
                RawInstruction(result.disasm),
                LiftedIL(result.stmt),
                BelongsToFunction(func_addr),
            ));

            if !result.edges.is_empty() {
                entity.insert(CfgEdges(result.edges));
            }
        }
    }

    /// Ingest an already-decoded function into ECS without re-running decode/lift.
    pub fn ingest_decoded_function(&mut self, decoded: &DecodedFunction) {
        for instruction in &decoded.instructions {
            let mut entity = self.world.spawn((
                Address(instruction.addr),
                RawInstruction(instruction.asm.clone()),
                LiftedIL(instruction.stmt.clone()),
                BelongsToFunction(decoded.func_addr),
            ));

            if !instruction.edges.is_empty() {
                entity.insert(CfgEdges(instruction.edges.clone()));
            }
        }
    }

    pub fn set_analysis_name(&mut self, addr: u64, name: impl Into<String>) -> SemanticContext {
        self.rename_symbol(addr, name)
    }

    pub fn rename_symbol(&mut self, addr: u64, name: impl Into<String>) -> SemanticContext {
        let entry = self.semantic.entry(addr).or_default();
        entry.symbol = Some(name.into());
        entry.clone()
    }

    pub fn define_struct(&mut self, addr: u64, definition: impl Into<String>) -> SemanticContext {
        let entry = self.semantic.entry(addr).or_default();
        entry.struct_definition = Some(definition.into());
        entry.clone()
    }

    pub fn add_hypothesis(&mut self, addr: u64, note: impl Into<String>) -> SemanticContext {
        let note = note.into();
        let entry = self.semantic.entry(addr).or_default();
        if !entry.hypotheses.iter().any(|existing| existing == &note) {
            entry.hypotheses.push(note);
        }
        entry.clone()
    }

    pub fn semantic_context(&self, addr: u64) -> Option<SemanticContext> {
        self.semantic
            .get(&addr)
            .filter(|context| !context.is_empty())
            .cloned()
    }

    pub fn symbol_name(&self, addr: u64) -> Option<&str> {
        self.semantic
            .get(&addr)
            .and_then(|context| context.symbol.as_deref())
    }

    pub fn blackboard_summary(&self) -> BlackboardSummary {
        let mut summary = BlackboardSummary::default();

        for context in self.semantic.values().filter(|context| !context.is_empty()) {
            summary.entries += 1;
            if context.symbol.is_some() {
                summary.renamed_symbols += 1;
            }
            if context.struct_definition.is_some() {
                summary.defined_structs += 1;
            }
            summary.hypotheses += context.hypotheses.len();
        }

        summary
    }

    /// Search renamed symbols attached to addresses using a regex.
    pub fn search_analysis_names(
        &self,
        pattern: &str,
    ) -> Result<Vec<AnalysisNameMatch>, regex::Error> {
        let regex = Regex::new(pattern)?;
        let mut matches = Vec::new();
        let mut seen_addrs = std::collections::HashSet::new();

        for (&addr, context) in &self.semantic {
            if context.is_empty() {
                continue;
            }

            let symbol = context.symbol.as_deref();
            let matched = symbol.is_some_and(|s| regex.is_match(s))
                || context
                    .struct_definition
                    .as_deref()
                    .is_some_and(|s| regex.is_match(s))
                || context.hypotheses.iter().any(|h| regex.is_match(h));

            if matched && seen_addrs.insert(addr) {
                let analysis_name = symbol
                    .unwrap_or_else(|| {
                        context
                            .struct_definition
                            .as_deref()
                            .or_else(|| context.hypotheses.first().map(|h| h.as_str()))
                            .unwrap_or("")
                    })
                    .to_string();
                matches.push(AnalysisNameMatch {
                    address: addr,
                    analysis_name,
                });
            }
        }

        matches.sort_by(|lhs, rhs| {
            lhs.address
                .cmp(&rhs.address)
                .then(lhs.analysis_name.cmp(&rhs.analysis_name))
        });
        Ok(matches)
    }

    /// Run Datalog analysis and return JSON report
    pub fn get_function_details(&mut self, target_func: u64) -> Value {
        let mut analysis = AeonAnalysis::default();
        let mut instructions: Vec<(u64, String, Stmt)> = Vec::new();

        let mut query_state = self.world.query::<(
            &Address,
            &RawInstruction,
            &LiftedIL,
            &BelongsToFunction,
            Option<&CfgEdges>,
        )>();

        for (addr, raw, lifted, belongs, cfg_edges) in query_state.iter(&self.world) {
            if belongs.0 == target_func {
                instructions.push((addr.0, raw.0.clone(), lifted.0.clone()));
                analysis.inst_in_func.push((target_func, addr.0));
                if let Some(edges) = cfg_edges {
                    for &target in &edges.0 {
                        analysis.edge.push((addr.0, target));
                    }
                }
            }
        }

        analysis.run();
        instructions.sort_by_key(|(addr, _, _)| *addr);

        let il_listing: Vec<Value> = instructions
            .iter()
            .map(|(addr, disasm, stmt)| {
                json!({
                    "address": format!("0x{:x}", addr),
                    "disassembly": disasm,
                    "il": format!("{:?}", stmt),
                })
            })
            .collect();

        let internal_edges: Vec<Value> = analysis
            .internal_edge
            .iter()
            .map(|(_, src, dst)| {
                json!({ "src": format!("0x{:x}", src), "dst": format!("0x{:x}", dst) })
            })
            .collect();

        let terminals: Vec<String> = analysis
            .terminal
            .iter()
            .map(|(_, addr)| format!("0x{:x}", addr))
            .collect();

        json!({
            "function": format!("0x{:x}", target_func),
            "instruction_count": instructions.len(),
            "il_listing": il_listing,
            "internal_edges": internal_edges,
            "terminal_blocks": terminals,
            "reachable_paths_count": analysis.reachable.len(),
        })
    }

    /// Scan entire .text section and report IL coverage stats
    pub fn coverage_report(&self) -> Value {
        let binary = match &self.binary {
            Some(b) => b,
            None => return json!({"error": "no binary loaded"}),
        };

        let stats = analyze_lift_coverage(binary.text_bytes(), binary.text_section_addr);
        let named_functions = binary.functions.iter().filter(|f| f.name.is_some()).count();

        stats.to_json(
            binary.functions.len(),
            named_functions,
            binary.text_section_addr,
            binary.text_section_size,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{AeonEngine, AnalysisNameMatch, SemanticContext};

    #[test]
    fn analysis_name_search_matches_regex() {
        let mut engine = AeonEngine::new();
        engine.set_analysis_name(0x1010, "rc4_candidate");
        engine.set_analysis_name(0x2020, "aes_round");

        let matches = engine.search_analysis_names("^rc4_.*$").unwrap();

        assert_eq!(
            matches,
            vec![AnalysisNameMatch {
                address: 0x1010,
                analysis_name: "rc4_candidate".to_string(),
            }]
        );
    }

    #[test]
    fn semantic_context_accumulates_mutations_without_duplicate_hypotheses() {
        let mut engine = AeonEngine::new();
        engine.rename_symbol(0x1000, "load_plugin_manifest");
        engine.define_struct(0x1000, "NetworkPacket { size: u32, data: char* }");
        engine.add_hypothesis(
            0x1000,
            "This looks like a custom stream cipher initialization block",
        );
        engine.add_hypothesis(
            0x1000,
            "This looks like a custom stream cipher initialization block",
        );

        assert_eq!(
            engine.semantic_context(0x1000),
            Some(SemanticContext {
                symbol: Some("load_plugin_manifest".to_string()),
                struct_definition: Some("NetworkPacket { size: u32, data: char* }".to_string()),
                hypotheses: vec![
                    "This looks like a custom stream cipher initialization block".to_string(),
                ],
            })
        );

        let summary = engine.blackboard_summary();
        assert_eq!(summary.entries, 1);
        assert_eq!(summary.renamed_symbols, 1);
        assert_eq!(summary.defined_structs, 1);
        assert_eq!(summary.hypotheses, 1);
    }
}
