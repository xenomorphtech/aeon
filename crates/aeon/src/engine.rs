use bevy_ecs::{entity::Entity, world::World};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};

use crate::il::Stmt;
use crate::components::{
    Address, AnalysisName, BelongsToFunction, CfgEdges, LiftedIL, RawInstruction,
};
use crate::analysis::AeonAnalysis;
use crate::elf::LoadedBinary;
use crate::lifter;

pub struct AeonEngine {
    pub world: World,
    pub binary: Option<LoadedBinary>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AnalysisNameMatch {
    pub address: u64,
    pub analysis_name: String,
    pub function: Option<u64>,
}

impl AeonEngine {
    pub fn new() -> Self {
        AeonEngine {
            world: World::new(),
            binary: None,
        }
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
        Ok(())
    }

    /// Ingest a single function into ECS by address lookup from loaded binary
    pub fn ingest_function_by_addr(&mut self, func_addr: u64) -> bool {
        let binary = match &self.binary {
            Some(b) => b,
            None => return false,
        };

        // Find the function
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

    /// Ingest raw function bytes into ECS
    pub fn ingest_function(&mut self, func_addr: u64, raw_bytes: &[u8]) {
        // Decode all instructions first
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

    /// Attach or overwrite an analysis name on an address entity.
    pub fn set_analysis_name(&mut self, addr: u64, name: impl Into<String>) {
        let entity = self.find_address_entity(addr).unwrap_or_else(|| {
            self.world.spawn((Address(addr),)).id()
        });
        self.world
            .entity_mut(entity)
            .insert(AnalysisName(name.into()));
    }

    /// Search analysis names attached to addresses using a regex.
    pub fn search_analysis_names(
        &mut self,
        pattern: &str,
    ) -> Result<Vec<AnalysisNameMatch>, regex::Error> {
        let regex = Regex::new(pattern)?;
        let mut matches = Vec::new();

        let mut query = self
            .world
            .query::<(&Address, &AnalysisName, Option<&BelongsToFunction>)>();
        for (addr, analysis_name, belongs) in query.iter(&self.world) {
            if regex.is_match(&analysis_name.0) {
                matches.push(AnalysisNameMatch {
                    address: addr.0,
                    analysis_name: analysis_name.0.clone(),
                    function: belongs.map(|belongs| belongs.0),
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
            &Address, &RawInstruction, &LiftedIL, &BelongsToFunction, Option<&CfgEdges>,
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

        let il_listing: Vec<Value> = instructions.iter().map(|(addr, disasm, stmt)| {
            json!({
                "address": format!("0x{:x}", addr),
                "disassembly": disasm,
                "il": format!("{:?}", stmt),
            })
        }).collect();

        let internal_edges: Vec<Value> = analysis.internal_edge.iter().map(|(_, src, dst)| {
            json!({ "src": format!("0x{:x}", src), "dst": format!("0x{:x}", dst) })
        }).collect();

        let terminals: Vec<String> = analysis.terminal.iter()
            .map(|(_, addr)| format!("0x{:x}", addr)).collect();

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

        let text = binary.text_bytes();
        let base_addr = binary.text_section_addr;

        let mut total: u64 = 0;
        let mut decode_errors: u64 = 0;
        let mut proper_il: u64 = 0;
        let mut intrinsic_count: u64 = 0;
        let mut nop_count: u64 = 0;
        let _other: u64 = 0;

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
                        Stmt::Assign { src: crate::il::Expr::Intrinsic { .. }, .. } => intrinsic_count += 1,
                        Stmt::Pair(_, _) => {
                            proper_il += 1;
                        }
                        _ => proper_il += 1,
                    }
                }
                Err(_) => decode_errors += 1,
            }

            offset += 4;
            pc += 4;
        }

        let named_functions = binary.functions.iter().filter(|f| f.name.is_some()).count();

        json!({
            "total_instructions": total,
            "decode_errors": decode_errors,
            "decode_error_pct": format!("{:.4}%", decode_errors as f64 / total as f64 * 100.0),
            "proper_il": proper_il,
            "proper_il_pct": format!("{:.2}%", proper_il as f64 / total as f64 * 100.0),
            "intrinsic": intrinsic_count,
            "intrinsic_pct": format!("{:.2}%", intrinsic_count as f64 / total as f64 * 100.0),
            "nop": nop_count,
            "nop_pct": format!("{:.2}%", nop_count as f64 / total as f64 * 100.0),
            "total_functions": binary.functions.len(),
            "named_functions": named_functions,
            "text_section_addr": format!("0x{:x}", binary.text_section_addr),
            "text_section_size": format!("0x{:x}", binary.text_section_size),
        })
    }

    fn find_address_entity(&mut self, addr: u64) -> Option<Entity> {
        let mut query = self.world.query::<(Entity, &Address)>();
        query
            .iter(&self.world)
            .find_map(|(entity, address)| (address.0 == addr).then_some(entity))
    }
}

#[cfg(test)]
mod tests {
    use super::{AeonEngine, AnalysisNameMatch};
    use crate::components::{Address, BelongsToFunction};

    #[test]
    fn analysis_name_search_matches_regex_and_reports_function() {
        let mut engine = AeonEngine::new();
        engine
            .world
            .spawn((Address(0x1010), BelongsToFunction(0x1000)));
        engine.set_analysis_name(0x1010, "rc4_candidate");
        engine.set_analysis_name(0x2020, "aes_round");

        let matches = engine.search_analysis_names("^rc4_.*$").unwrap();

        assert_eq!(
            matches,
            vec![AnalysisNameMatch {
                address: 0x1010,
                analysis_name: "rc4_candidate".to_string(),
                function: Some(0x1000),
            }]
        );
    }
}
