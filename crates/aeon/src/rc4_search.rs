use serde_json::{json, Value};

use aeon_reduce::ssa::types::{SsaExpr, SsaStmt};

use crate::elf::LoadedBinary;
use crate::engine::AeonEngine;
use crate::facts::{FunctionFacts, PatternMatch, PatternSpec, StmtSite};
use crate::lifter;

const RC4_PRGA: &str = "RC4_PRGA (swap + keystream XOR)";
const RC4_KSA: &str = "RC4_KSA (swap + 256 loop + mod256)";
const RC4_SWAP_ONLY: &str = "swap_pattern (unconfirmed)";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rc4CandidateEvidence {
    swap_instances: Vec<(StmtSite, StmtSite, StmtSite, StmtSite)>,
    keystream_xor_sites: Vec<StmtSite>,
    has_256_bound: bool,
    has_mod256: bool,
    byte_loads: usize,
    byte_stores: usize,
    flows_to_edges: usize,
    loop_instructions: usize,
}

pub fn search(binary: &LoadedBinary) -> Value {
    let mut engine = AeonEngine::with_binary(binary.clone());
    search_with_engine(binary, &mut engine)
}

pub fn search_with_engine(binary: &LoadedBinary, engine: &mut AeonEngine) -> Value {
    let mut phase1_count = 0u64;
    let mut phase2_count = 0u64;
    let mut verified = Vec::new();

    for func in &binary.functions {
        if func.size < 48 || func.size > 4000 {
            continue;
        }

        let raw_bytes = match binary.function_bytes(func) {
            Some(bytes) => bytes,
            None => continue,
        };

        let Some(analysis) = engine.function_analysis(func.addr) else {
            continue;
        };
        let evidence = extract_candidate_evidence(&analysis.facts);

        if !passes_phase1(&evidence) {
            continue;
        }
        phase1_count += 1;

        if evidence.swap_instances.is_empty() {
            continue;
        }
        phase2_count += 1;

        let classification = classify_evidence(&evidence);
        let swaps: Vec<Value> = evidence
            .swap_instances
            .iter()
            .take(3)
            .map(|(load1, load2, store1, store2)| {
                json!({
                    "load1": format_stmt_site(&analysis.facts, *load1),
                    "load2": format_stmt_site(&analysis.facts, *load2),
                    "store1": format_stmt_site(&analysis.facts, *store1),
                    "store2": format_stmt_site(&analysis.facts, *store2),
                })
            })
            .collect();
        let xor_sites: Vec<String> = evidence
            .keystream_xor_sites
            .iter()
            .map(|site| format_stmt_site(&analysis.facts, *site))
            .collect();
        let listing = disassemble_function(raw_bytes, func.addr);

        verified.push(json!({
            "address": format!("0x{:x}", func.addr),
            "size": func.size,
            "name": func.name.as_deref().unwrap_or("(unnamed)"),
            "classification": classification,
            "evidence": {
                "swap_instances": swaps,
                "keystream_xor_sites": xor_sites,
                "has_256_bound": evidence.has_256_bound,
                "has_mod256": evidence.has_mod256,
                "byte_loads": evidence.byte_loads,
                "byte_stores": evidence.byte_stores,
                "flows_to_edges": evidence.flows_to_edges,
                "loop_instructions": evidence.loop_instructions,
            },
            "il_listing": listing,
        }));
    }

    json!({
        "search": "rc4_behavioral",
        "method": "shared_facts_ssa_patterns",
        "phase1_prefiltered": phase1_count,
        "phase2_verified": phase2_count,
        "candidates": verified,
    })
}

fn extract_candidate_evidence(facts: &FunctionFacts) -> Rc4CandidateEvidence {
    let swap_instances = facts
        .find_pattern(PatternSpec::LoopByteSwap)
        .into_iter()
        .filter_map(|entry| match entry {
            PatternMatch::ByteSwap {
                load1,
                load2,
                store1,
                store2,
            } => Some((load1, load2, store1, store2)),
            PatternMatch::KeystreamXor { .. } => None,
        })
        .collect();
    let keystream_xor_sites = facts
        .find_pattern(PatternSpec::LoopKeystreamXor)
        .into_iter()
        .filter_map(|entry| match entry {
            PatternMatch::KeystreamXor { stmt } => Some(stmt),
            PatternMatch::ByteSwap { .. } => None,
        })
        .collect();

    Rc4CandidateEvidence {
        swap_instances,
        keystream_xor_sites,
        has_256_bound: facts.has_immediate_value(256)
            || facts.get_constants().iter().any(|fact| fact.value == 256),
        has_mod256: facts.has_and_mask(0xff),
        byte_loads: facts
            .definitions()
            .iter()
            .filter(|fact| matches!(fact.expr, SsaExpr::Load { size: 1, .. }))
            .count(),
        byte_stores: facts
            .stmt_sites()
            .iter()
            .filter(|site| matches!(facts.stmt(**site), Some(SsaStmt::Store { size: 1, .. })))
            .count(),
        flows_to_edges: facts.uses().len(),
        loop_instructions: facts
            .stmt_sites()
            .iter()
            .filter(|site| facts.is_in_loop(**site))
            .count(),
    }
}

fn passes_phase1(evidence: &Rc4CandidateEvidence) -> bool {
    evidence.byte_loads >= 2 && evidence.byte_stores >= 2 && evidence.loop_instructions > 0
}

fn classify_evidence(evidence: &Rc4CandidateEvidence) -> &'static str {
    if !evidence.keystream_xor_sites.is_empty() {
        RC4_PRGA
    } else if evidence.has_256_bound && evidence.has_mod256 {
        RC4_KSA
    } else {
        RC4_SWAP_ONLY
    }
}

fn format_stmt_site(facts: &FunctionFacts, site: StmtSite) -> String {
    format!("0x{:x}", facts.stmt_address(site))
}

fn disassemble_function(raw_bytes: &[u8], func_addr: u64) -> Vec<Value> {
    let mut listing = Vec::new();
    let mut offset = 0usize;
    let mut pc = func_addr;

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
            })
        } else {
            json!({ "addr": format!("0x{:x}", pc), "asm": "(invalid)", "il": "Nop" })
        };

        listing.push(entry);
        offset += 4;
        pc += 4;
    }

    listing
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::extract_function_facts;
    use aeon_reduce::ssa::construct::{SsaBlock, SsaFunction};
    use aeon_reduce::ssa::types::{RegLocation, RegWidth, SsaBranchCond, SsaExpr, SsaStmt, SsaVar};
    use aeonil::Condition;

    fn var(index: u8, version: u32) -> SsaVar {
        SsaVar {
            loc: RegLocation::Gpr(index),
            version,
            width: RegWidth::W64,
        }
    }

    fn block(
        id: u32,
        addr: u64,
        stmts: Vec<SsaStmt>,
        successors: Vec<u32>,
        predecessors: Vec<u32>,
    ) -> SsaBlock {
        SsaBlock {
            id,
            addr,
            stmts,
            successors,
            predecessors,
        }
    }

    fn build_candidate(include_xor: bool, include_ksa_hints: bool) -> FunctionFacts {
        let load_a = var(0, 1);
        let load_b = var(1, 1);
        let mixed = var(2, 1);
        let loop_counter = var(3, 0);
        let addr_a = var(4, 0);
        let addr_b = var(5, 0);
        let addr_c = var(6, 0);
        let input = var(7, 0);
        let bound = var(8, 1);
        let masked = var(9, 1);

        let mut header_stmts = Vec::new();
        if include_ksa_hints {
            header_stmts.push(SsaStmt::Assign {
                dst: bound,
                src: SsaExpr::Imm(256),
            });
            header_stmts.push(SsaStmt::Assign {
                dst: masked,
                src: SsaExpr::And(
                    Box::new(SsaExpr::Var(loop_counter)),
                    Box::new(SsaExpr::Imm(0xff)),
                ),
            });
        }
        header_stmts.push(SsaStmt::Branch {
            target: SsaExpr::Imm(0x1100),
        });

        let mut loop_stmts = vec![
            SsaStmt::Assign {
                dst: load_a,
                src: SsaExpr::Load {
                    addr: Box::new(SsaExpr::Var(addr_a)),
                    size: 1,
                },
            },
            SsaStmt::Assign {
                dst: load_b,
                src: SsaExpr::Load {
                    addr: Box::new(SsaExpr::Var(addr_b)),
                    size: 1,
                },
            },
            SsaStmt::Store {
                addr: SsaExpr::Var(addr_a),
                value: SsaExpr::Var(load_b),
                size: 1,
            },
            SsaStmt::Store {
                addr: SsaExpr::Var(addr_c),
                value: SsaExpr::Var(load_a),
                size: 1,
            },
        ];
        if include_xor {
            loop_stmts.push(SsaStmt::Assign {
                dst: mixed,
                src: SsaExpr::Xor(
                    Box::new(SsaExpr::Var(load_a)),
                    Box::new(SsaExpr::Var(input)),
                ),
            });
        }
        loop_stmts.push(SsaStmt::CondBranch {
            cond: SsaBranchCond::Compare {
                cond: Condition::NE,
                lhs: Box::new(SsaExpr::Var(loop_counter)),
                rhs: Box::new(SsaExpr::Imm(0)),
            },
            target: SsaExpr::Imm(0x1000),
            fallthrough: 2,
        });

        let func = SsaFunction {
            entry: 0,
            blocks: vec![
                block(0, 0x1000, header_stmts, vec![1], vec![]),
                block(1, 0x1100, loop_stmts, vec![0, 2], vec![0, 1]),
                block(2, 0x1200, vec![SsaStmt::Ret], vec![], vec![1]),
            ],
        };

        extract_function_facts(&func)
    }

    #[test]
    fn rc4_regression_prga_classification_uses_shared_facts() {
        let facts = build_candidate(true, true);
        let evidence = extract_candidate_evidence(&facts);

        assert!(passes_phase1(&evidence));
        assert_eq!(classify_evidence(&evidence), RC4_PRGA);
        assert_eq!(evidence.swap_instances.len(), 1);
        assert_eq!(evidence.keystream_xor_sites.len(), 1);
    }

    #[test]
    fn rc4_regression_ksa_classification_uses_shared_facts() {
        let facts = build_candidate(false, true);
        let evidence = extract_candidate_evidence(&facts);

        assert!(passes_phase1(&evidence));
        assert_eq!(classify_evidence(&evidence), RC4_KSA);
        assert_eq!(evidence.swap_instances.len(), 1);
        assert!(evidence.keystream_xor_sites.is_empty());
    }

    #[test]
    fn rc4_regression_swap_only_classification_uses_shared_facts() {
        let facts = build_candidate(false, false);
        let evidence = extract_candidate_evidence(&facts);

        assert!(passes_phase1(&evidence));
        assert_eq!(classify_evidence(&evidence), RC4_SWAP_ONLY);
        assert_eq!(evidence.swap_instances.len(), 1);
        assert!(!evidence.has_256_bound);
        assert!(!evidence.has_mod256);
    }
}
