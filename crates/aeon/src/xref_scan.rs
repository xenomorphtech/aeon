use std::collections::HashSet;
use std::time::Instant;

use rayon::prelude::*;
use serde::Serialize;

use crate::elf::{FunctionInfo, LoadedBinary};
use crate::il::{Expr, Stmt};
use crate::lifter;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum XrefKind {
    DirectCall,
    TailCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct XrefRelation {
    from_func: u64,
    to_func: u64,
    kind: XrefKind,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct XrefScanReport {
    pub total_functions: usize,
    pub total_instructions: usize,
    pub lifted_instructions: usize,
    pub invalid_instructions: usize,
    pub direct_call_sites: usize,
    pub tail_call_sites: usize,
    pub unique_direct_edges: usize,
    pub unique_tail_edges: usize,
    pub caller_functions: usize,
    pub callee_functions: usize,
    pub functions_with_xrefs: usize,
    pub max_outgoing_edges_per_function: usize,
    pub max_incoming_edges_per_function: usize,
    pub threads_used: usize,
    pub elapsed_ms: u128,
}

#[derive(Debug, Default)]
struct LocalXrefStats {
    total_instructions: usize,
    lifted_instructions: usize,
    invalid_instructions: usize,
    direct_call_sites: usize,
    tail_call_sites: usize,
    relations: Vec<XrefRelation>,
}

impl LocalXrefStats {
    fn merge(mut self, other: Self) -> Self {
        self.total_instructions += other.total_instructions;
        self.lifted_instructions += other.lifted_instructions;
        self.invalid_instructions += other.invalid_instructions;
        self.direct_call_sites += other.direct_call_sites;
        self.tail_call_sites += other.tail_call_sites;
        self.relations.extend(other.relations);
        self
    }
}

pub fn scan_all_xrefs(
    binary: &LoadedBinary,
    threads: Option<usize>,
) -> Result<XrefScanReport, String> {
    let mut builder = rayon::ThreadPoolBuilder::new();
    if let Some(thread_count) = threads {
        builder = builder.num_threads(thread_count.max(1));
    }
    let pool = builder
        .build()
        .map_err(|error| format!("failed to build xref thread pool: {}", error))?;

    let started = Instant::now();
    let stats = pool.install(|| {
        binary
            .functions
            .par_iter()
            .map(|func| scan_function_xrefs(binary, func))
            .reduce(LocalXrefStats::default, LocalXrefStats::merge)
    });

    let mut relations = stats.relations;
    relations.sort_unstable();
    relations.dedup();

    let unique_direct_edges = relations
        .iter()
        .filter(|relation| matches!(relation.kind, XrefKind::DirectCall))
        .count();
    let unique_tail_edges = relations
        .iter()
        .filter(|relation| matches!(relation.kind, XrefKind::TailCall))
        .count();

    let mut callers = HashSet::new();
    let mut callees = HashSet::new();
    let mut current_caller = None;
    let mut current_outgoing = 0usize;
    let mut max_outgoing = 0usize;

    for relation in &relations {
        callers.insert(relation.from_func);
        callees.insert(relation.to_func);

        if current_caller == Some(relation.from_func) {
            current_outgoing += 1;
        } else {
            max_outgoing = max_outgoing.max(current_outgoing);
            current_caller = Some(relation.from_func);
            current_outgoing = 1;
        }
    }
    max_outgoing = max_outgoing.max(current_outgoing);

    let mut incoming_relations = relations
        .iter()
        .map(|relation| relation.to_func)
        .collect::<Vec<_>>();
    incoming_relations.sort_unstable();

    let mut current_callee = None;
    let mut current_incoming = 0usize;
    let mut max_incoming = 0usize;
    for callee in incoming_relations {
        if current_callee == Some(callee) {
            current_incoming += 1;
        } else {
            max_incoming = max_incoming.max(current_incoming);
            current_callee = Some(callee);
            current_incoming = 1;
        }
    }
    max_incoming = max_incoming.max(current_incoming);

    Ok(XrefScanReport {
        total_functions: binary.functions.len(),
        total_instructions: stats.total_instructions,
        lifted_instructions: stats.lifted_instructions,
        invalid_instructions: stats.invalid_instructions,
        direct_call_sites: stats.direct_call_sites,
        tail_call_sites: stats.tail_call_sites,
        unique_direct_edges,
        unique_tail_edges,
        caller_functions: callers.len(),
        callee_functions: callees.len(),
        functions_with_xrefs: callers.len(),
        max_outgoing_edges_per_function: max_outgoing,
        max_incoming_edges_per_function: max_incoming,
        threads_used: pool.current_num_threads(),
        elapsed_ms: started.elapsed().as_millis(),
    })
}

fn scan_function_xrefs(binary: &LoadedBinary, func: &FunctionInfo) -> LocalXrefStats {
    let Some(bytes) = binary.function_bytes(func) else {
        return LocalXrefStats::default();
    };

    let mut stats = LocalXrefStats::default();
    let mut seen_relations = HashSet::new();
    let mut offset = 0usize;
    let mut pc = func.addr;

    while offset + 4 <= bytes.len() {
        stats.total_instructions += 1;
        let word = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let next_pc = (offset + 8 <= bytes.len()).then_some(pc + 4);

        match bad64::decode(word, pc) {
            Ok(insn) => {
                stats.lifted_instructions += 1;
                let lifted = lifter::lift(&insn, pc, next_pc);
                fold_stmt_into_xrefs(
                    binary,
                    func.addr,
                    &lifted.stmt,
                    &mut stats,
                    &mut seen_relations,
                );
            }
            Err(_) => {
                stats.invalid_instructions += 1;
            }
        }

        offset += 4;
        pc += 4;
    }

    stats
}

fn fold_stmt_into_xrefs(
    binary: &LoadedBinary,
    func_addr: u64,
    stmt: &Stmt,
    stats: &mut LocalXrefStats,
    seen_relations: &mut HashSet<XrefRelation>,
) {
    match stmt {
        Stmt::Call {
            target: Expr::Imm(target),
        } => {
            if let Some(callee) = binary.function_containing(*target).map(|func| func.addr) {
                stats.direct_call_sites += 1;
                seen_relations.insert(XrefRelation {
                    from_func: func_addr,
                    to_func: callee,
                    kind: XrefKind::DirectCall,
                });
            }
        }
        Stmt::Branch {
            target: Expr::Imm(target),
        } => {
            if let Some(callee) = binary.function_containing(*target).map(|func| func.addr) {
                if callee != func_addr {
                    stats.tail_call_sites += 1;
                    seen_relations.insert(XrefRelation {
                        from_func: func_addr,
                        to_func: callee,
                        kind: XrefKind::TailCall,
                    });
                }
            }
        }
        _ => {}
    }

    if matches!(stmt, Stmt::Call { .. } | Stmt::Branch { .. }) {
        stats.relations.extend(seen_relations.drain());
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::scan_all_xrefs;
    use crate::elf::load_elf;

    fn sample_binary_path() -> String {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .join("../../samples/hello_aarch64.elf")
            .display()
            .to_string()
    }

    #[test]
    fn xref_scan_summarizes_sample_binary() {
        let binary = load_elf(&sample_binary_path()).expect("sample binary should load");
        let report = scan_all_xrefs(&binary, Some(2)).expect("xref scan should succeed");

        assert!(report.total_functions > 0);
        assert_eq!(
            report.total_instructions,
            report.lifted_instructions + report.invalid_instructions
        );
        assert!(report.threads_used >= 1);
    }
}
