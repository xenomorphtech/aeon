// Symbolic analysis on concrete traces
//
// Given a TraceLog, the SymbolicFolder identifies:
//   - Register invariants: registers that hold the same value across
//     all visits to a block (constants, loop-invariant pointers)
//   - Memory invariants: addresses always read producing the same value
//     (vtable pointers, global constants, string literals)
//   - Branch invariants: conditional branches that always go the same way
//     (dead code, always-taken paths)
//   - Dataflow patterns: which registers/memory feed into which outputs
//     (taint-like analysis from concrete observations)
//
// These invariants let us simplify the lifted IL:
//   - Replace invariant registers with constants
//   - Eliminate dead branches
//   - Resolve indirect calls (vtable dispatch → concrete target)
//   - Identify loop trip counts and induction variables

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::trace::TraceLog;

/// An observed invariant from trace analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Invariant {
    /// Register `reg` always has value `value` at entry to block `block_addr`.
    RegisterConstant {
        block_addr: u64,
        reg: usize,
        value: u64,
    },
    /// Memory at `addr` always reads as `value` (size bytes).
    MemoryConstant { addr: u64, size: u8, value: u64 },
    /// Branch at `block_addr` always goes to `target`.
    BranchAlwaysTaken { block_addr: u64, target: u64 },
    /// Register `reg` at block entry is always `base + stride * visit_index`
    /// (linear induction variable).
    InductionVariable {
        block_addr: u64,
        reg: usize,
        base: u64,
        stride: i64,
    },
    /// Memory at `addr` is read by block `reader` and written by block `writer`.
    DataflowEdge {
        addr: u64,
        writer_block: u64,
        reader_block: u64,
    },
}

/// Results of symbolic folding.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FoldResult {
    pub invariants: Vec<Invariant>,
    pub constant_registers: usize,
    pub constant_memory: usize,
    pub resolved_branches: usize,
    pub induction_variables: usize,
    pub dataflow_edges: usize,
}

/// Analyze a trace log to discover invariants.
pub struct SymbolicFolder;

impl SymbolicFolder {
    /// Run all analyses on the trace and return discovered invariants.
    pub fn fold(trace: &TraceLog) -> FoldResult {
        let mut result = FoldResult::default();

        Self::find_register_constants(trace, &mut result);
        Self::find_memory_constants(trace, &mut result);
        Self::find_branch_invariants(trace, &mut result);
        Self::find_induction_variables(trace, &mut result);
        Self::find_dataflow_edges(trace, &mut result);

        result
    }

    fn find_register_constants(trace: &TraceLog, result: &mut FoldResult) {
        // For each block visited more than once, check if any register
        // has the same value across all visits at entry.
        let visit_counts = trace.visit_counts();
        for (&addr, &count) in &visit_counts {
            if count < 2 {
                continue;
            }
            let traces = trace.traces_for_block(addr);
            for reg_idx in 0..31 {
                let first_val = traces[0].entry_regs.x[reg_idx];
                if traces.iter().all(|t| t.entry_regs.x[reg_idx] == first_val) {
                    result.invariants.push(Invariant::RegisterConstant {
                        block_addr: addr,
                        reg: reg_idx,
                        value: first_val,
                    });
                    result.constant_registers += 1;
                }
            }
        }
    }

    fn find_memory_constants(trace: &TraceLog, result: &mut FoldResult) {
        // Group all reads by address — if same address always yields same value.
        let mut reads: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for block in &trace.blocks {
            for access in &block.memory_accesses {
                if !access.is_write {
                    reads.entry(access.addr).or_default().push(access.value);
                }
            }
        }
        for (addr, values) in &reads {
            if values.len() >= 2 && values.iter().all(|v| *v == values[0]) {
                result.invariants.push(Invariant::MemoryConstant {
                    addr: *addr,
                    size: 8, // TODO: track actual size
                    value: values[0],
                });
                result.constant_memory += 1;
            }
        }
    }

    fn find_branch_invariants(trace: &TraceLog, result: &mut FoldResult) {
        // Blocks visited multiple times that always exit to the same next_pc.
        let visit_counts = trace.visit_counts();
        for (&addr, &count) in &visit_counts {
            if count < 2 {
                continue;
            }
            let traces = trace.traces_for_block(addr);
            let first_target = traces[0].next_pc;
            if traces.iter().all(|t| t.next_pc == first_target) {
                result.invariants.push(Invariant::BranchAlwaysTaken {
                    block_addr: addr,
                    target: first_target,
                });
                result.resolved_branches += 1;
            }
        }
    }

    fn find_induction_variables(trace: &TraceLog, result: &mut FoldResult) {
        // For blocks visited 3+ times, check if any register follows
        // a linear pattern: val[i] = base + stride * i
        let visit_counts = trace.visit_counts();
        for (&addr, &count) in &visit_counts {
            if count < 3 {
                continue;
            }
            let traces = trace.traces_for_block(addr);
            for reg_idx in 0..31 {
                let values: Vec<u64> = traces.iter().map(|t| t.entry_regs.x[reg_idx]).collect();
                if values.windows(2).all(|w| w[0] == w[1]) {
                    continue; // constant, not induction
                }
                // Check linear: stride = v[1] - v[0], then all diffs match
                let stride = values[1].wrapping_sub(values[0]) as i64;
                let is_linear = values
                    .windows(2)
                    .all(|w| w[1].wrapping_sub(w[0]) as i64 == stride);
                if is_linear {
                    result.invariants.push(Invariant::InductionVariable {
                        block_addr: addr,
                        reg: reg_idx,
                        base: values[0],
                        stride,
                    });
                    result.induction_variables += 1;
                }
            }
        }
    }

    fn find_dataflow_edges(trace: &TraceLog, result: &mut FoldResult) {
        // Match memory writes to subsequent reads at the same address.
        let mut last_writer: BTreeMap<u64, u64> = BTreeMap::new(); // addr → writer block
        for block in &trace.blocks {
            for access in &block.memory_accesses {
                if access.is_write {
                    last_writer.insert(access.addr, block.addr);
                } else if let Some(&writer) = last_writer.get(&access.addr) {
                    if writer != block.addr {
                        result.invariants.push(Invariant::DataflowEdge {
                            addr: access.addr,
                            writer_block: writer,
                            reader_block: block.addr,
                        });
                        result.dataflow_edges += 1;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{BlockTrace, MemoryAccess, RegSnapshot, TraceLog};

    /// Build a RegSnapshot with all x regs set to a default, then apply overrides.
    fn regs_with(overrides: &[(usize, u64)]) -> RegSnapshot {
        let mut snap = RegSnapshot {
            x: [0; 31],
            sp: 0,
            pc: 0,
            flags: 0,
        };
        for &(idx, val) in overrides {
            snap.x[idx] = val;
        }
        snap
    }

    /// Build a minimal BlockTrace for a given block address.
    fn block(
        addr: u64,
        entry_overrides: &[(usize, u64)],
        next_pc: u64,
        mem: Vec<MemoryAccess>,
    ) -> BlockTrace {
        BlockTrace {
            addr,
            entry_regs: regs_with(entry_overrides),
            exit_regs: regs_with(&[]),
            memory_accesses: mem,
            next_pc,
            visit_count: 0, // TraceLog tracks this externally
            seq: 0,
        }
    }

    fn mem_read(addr: u64, value: u64, block_addr: u64) -> MemoryAccess {
        MemoryAccess {
            addr,
            size: 8,
            value,
            is_write: false,
            block_addr,
            seq: 0,
        }
    }

    fn mem_write(addr: u64, value: u64, block_addr: u64) -> MemoryAccess {
        MemoryAccess {
            addr,
            size: 8,
            value,
            is_write: true,
            block_addr,
            seq: 0,
        }
    }

    // ── RegisterConstant ──────────────────────────────────────────

    #[test]
    fn register_constant_found_when_same_across_visits() {
        let mut trace = TraceLog::new();
        // Block 0x1000 visited 3 times, x5 is always 42
        for _ in 0..3 {
            trace.record_block(block(0x1000, &[(5, 42)], 0x1010, vec![]));
        }
        let result = SymbolicFolder::fold(&trace);
        let reg_consts: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| {
                matches!(
                    inv,
                    Invariant::RegisterConstant {
                        reg: 5,
                        value: 42,
                        ..
                    }
                )
            })
            .collect();
        assert!(!reg_consts.is_empty(), "should find x5=42 as constant");
        assert!(result.constant_registers > 0);
    }

    #[test]
    fn register_constant_not_found_when_varying() {
        let mut trace = TraceLog::new();
        // Block 0x1000, x5 changes each visit
        trace.record_block(block(0x1000, &[(5, 10)], 0x1010, vec![]));
        trace.record_block(block(0x1000, &[(5, 20)], 0x1010, vec![]));
        trace.record_block(block(0x1000, &[(5, 30)], 0x1010, vec![]));
        let result = SymbolicFolder::fold(&trace);
        let bad: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| matches!(inv, Invariant::RegisterConstant { reg: 5, .. }))
            .collect();
        assert!(bad.is_empty(), "varying x5 should not be flagged constant");
    }

    #[test]
    fn register_constant_skipped_for_single_visit() {
        let mut trace = TraceLog::new();
        // Only visited once — not enough evidence
        trace.record_block(block(0x1000, &[(5, 42)], 0x1010, vec![]));
        let result = SymbolicFolder::fold(&trace);
        let reg_consts: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| {
                matches!(
                    inv,
                    Invariant::RegisterConstant {
                        block_addr: 0x1000,
                        ..
                    }
                )
            })
            .collect();
        assert!(
            reg_consts.is_empty(),
            "single visit should not produce register constants"
        );
    }

    // ── MemoryConstant ────────────────────────────────────────────

    #[test]
    fn memory_constant_found_when_reads_identical() {
        let mut trace = TraceLog::new();
        // Two blocks read 0x1000 and always get 0xFF
        trace.record_block(block(
            0x2000,
            &[],
            0x2010,
            vec![mem_read(0x1000, 0xFF, 0x2000)],
        ));
        trace.record_block(block(
            0x3000,
            &[],
            0x3010,
            vec![mem_read(0x1000, 0xFF, 0x3000)],
        ));
        let result = SymbolicFolder::fold(&trace);
        let mem_consts: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| {
                matches!(
                    inv,
                    Invariant::MemoryConstant {
                        addr: 0x1000,
                        value: 0xFF,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(mem_consts.len(), 1, "should find memory constant at 0x1000");
        assert_eq!(result.constant_memory, 1);
    }

    #[test]
    fn memory_constant_not_found_when_reads_differ() {
        let mut trace = TraceLog::new();
        trace.record_block(block(
            0x2000,
            &[],
            0x2010,
            vec![mem_read(0x1000, 0xFF, 0x2000)],
        ));
        trace.record_block(block(
            0x3000,
            &[],
            0x3010,
            vec![mem_read(0x1000, 0xAA, 0x3000)],
        ));
        let result = SymbolicFolder::fold(&trace);
        let mem_consts: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| matches!(inv, Invariant::MemoryConstant { addr: 0x1000, .. }))
            .collect();
        assert!(
            mem_consts.is_empty(),
            "different values should not be constant"
        );
    }

    #[test]
    fn memory_constant_needs_at_least_two_reads() {
        let mut trace = TraceLog::new();
        // Single read — not enough evidence
        trace.record_block(block(
            0x2000,
            &[],
            0x2010,
            vec![mem_read(0x1000, 0xFF, 0x2000)],
        ));
        let result = SymbolicFolder::fold(&trace);
        assert_eq!(result.constant_memory, 0);
    }

    // ── BranchAlwaysTaken ─────────────────────────────────────────

    #[test]
    fn branch_always_taken_when_exit_constant() {
        let mut trace = TraceLog::new();
        // Block 0x4000 always exits to 0x5000
        for _ in 0..4 {
            trace.record_block(block(0x4000, &[], 0x5000, vec![]));
        }
        let result = SymbolicFolder::fold(&trace);
        let branches: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| {
                matches!(
                    inv,
                    Invariant::BranchAlwaysTaken {
                        block_addr: 0x4000,
                        target: 0x5000,
                    }
                )
            })
            .collect();
        assert_eq!(branches.len(), 1);
        assert_eq!(result.resolved_branches, 1);
    }

    #[test]
    fn branch_not_always_taken_when_exit_varies() {
        let mut trace = TraceLog::new();
        trace.record_block(block(0x4000, &[], 0x5000, vec![]));
        trace.record_block(block(0x4000, &[], 0x6000, vec![]));
        let result = SymbolicFolder::fold(&trace);
        let branches: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| {
                matches!(
                    inv,
                    Invariant::BranchAlwaysTaken {
                        block_addr: 0x4000,
                        ..
                    }
                )
            })
            .collect();
        assert!(
            branches.is_empty(),
            "varying exit should not be always-taken"
        );
    }

    // ── InductionVariable ─────────────────────────────────────────

    #[test]
    fn induction_variable_stride_4() {
        let mut trace = TraceLog::new();
        // Block 0x8000 visited 5 times, x3 = 100, 104, 108, 112, 116
        for i in 0u64..5 {
            trace.record_block(block(0x8000, &[(3, 100 + i * 4)], 0x8010, vec![]));
        }
        let result = SymbolicFolder::fold(&trace);
        let indvars: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| {
                matches!(
                    inv,
                    Invariant::InductionVariable {
                        block_addr: 0x8000,
                        reg: 3,
                        base: 100,
                        stride: 4,
                    }
                )
            })
            .collect();
        assert_eq!(
            indvars.len(),
            1,
            "should detect x3 as induction variable with stride 4"
        );
        assert_eq!(result.induction_variables, 1);
    }

    #[test]
    fn induction_variable_negative_stride() {
        let mut trace = TraceLog::new();
        // x7 = 200, 192, 184 (stride -8 via wrapping)
        let vals = [200u64, 192, 184];
        for &v in &vals {
            trace.record_block(block(0x8000, &[(7, v)], 0x8010, vec![]));
        }
        let result = SymbolicFolder::fold(&trace);
        let indvars: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| {
                matches!(
                    inv,
                    Invariant::InductionVariable {
                        reg: 7,
                        stride: -8,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(indvars.len(), 1, "should detect negative stride induction");
    }

    #[test]
    fn induction_variable_not_detected_for_constant() {
        let mut trace = TraceLog::new();
        // x3 is always 42 — constant, not induction
        for _ in 0..4 {
            trace.record_block(block(0x8000, &[(3, 42)], 0x8010, vec![]));
        }
        let result = SymbolicFolder::fold(&trace);
        let indvars: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| matches!(inv, Invariant::InductionVariable { reg: 3, .. }))
            .collect();
        assert!(
            indvars.is_empty(),
            "constant should not be induction variable"
        );
    }

    #[test]
    fn induction_variable_needs_three_visits() {
        let mut trace = TraceLog::new();
        // Only 2 visits — not enough to confirm linear pattern
        trace.record_block(block(0x8000, &[(3, 100)], 0x8010, vec![]));
        trace.record_block(block(0x8000, &[(3, 104)], 0x8010, vec![]));
        let result = SymbolicFolder::fold(&trace);
        let indvars: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| matches!(inv, Invariant::InductionVariable { reg: 3, .. }))
            .collect();
        assert!(indvars.is_empty(), "need 3+ visits for induction detection");
    }

    // ── DataflowEdge ──────────────────────────────────────────────

    #[test]
    fn dataflow_edge_write_then_read() {
        let mut trace = TraceLog::new();
        // Block A writes 0x9000, Block B reads 0x9000
        trace.record_block(block(
            0xA000,
            &[],
            0xB000,
            vec![mem_write(0x9000, 0xDEAD, 0xA000)],
        ));
        trace.record_block(block(
            0xB000,
            &[],
            0xC000,
            vec![mem_read(0x9000, 0xDEAD, 0xB000)],
        ));
        let result = SymbolicFolder::fold(&trace);
        let edges: Vec<_> = result
            .invariants
            .iter()
            .filter(|inv| {
                matches!(
                    inv,
                    Invariant::DataflowEdge {
                        addr: 0x9000,
                        writer_block: 0xA000,
                        reader_block: 0xB000,
                    }
                )
            })
            .collect();
        assert_eq!(edges.len(), 1, "should find dataflow edge A→B via 0x9000");
        assert_eq!(result.dataflow_edges, 1);
    }

    #[test]
    fn dataflow_edge_not_for_same_block() {
        let mut trace = TraceLog::new();
        // Block writes and reads same address — no cross-block edge
        trace.record_block(block(
            0xA000,
            &[],
            0xB000,
            vec![
                mem_write(0x9000, 0xDEAD, 0xA000),
                mem_read(0x9000, 0xDEAD, 0xA000),
            ],
        ));
        let result = SymbolicFolder::fold(&trace);
        assert_eq!(
            result.dataflow_edges, 0,
            "same-block write-read should not be an edge"
        );
    }

    #[test]
    fn dataflow_edge_no_prior_write() {
        let mut trace = TraceLog::new();
        // Read without any prior write — no edge
        trace.record_block(block(
            0xB000,
            &[],
            0xC000,
            vec![mem_read(0x9000, 0xDEAD, 0xB000)],
        ));
        let result = SymbolicFolder::fold(&trace);
        assert_eq!(result.dataflow_edges, 0);
    }

    // ── Combined / integration ────────────────────────────────────

    #[test]
    fn fold_finds_multiple_invariant_types() {
        let mut trace = TraceLog::new();

        // Block 0x1000: x0 always 99, always exits to 0x2000, reads 0x5000 = 0xBEEF
        for i in 0u64..4 {
            trace.record_block(BlockTrace {
                addr: 0x1000,
                entry_regs: regs_with(&[(0, 99), (1, 10 + i * 2)]),
                exit_regs: regs_with(&[]),
                memory_accesses: vec![
                    mem_read(0x5000, 0xBEEF, 0x1000),
                    mem_write(0x6000, i, 0x1000),
                ],
                next_pc: 0x2000,
                visit_count: 0,
                seq: 0,
            });
        }

        // Block 0x2000: reads what 0x1000 wrote at 0x6000
        trace.record_block(block(
            0x2000,
            &[],
            0x3000,
            vec![mem_read(0x6000, 3, 0x2000)],
        ));

        let result = SymbolicFolder::fold(&trace);

        // x0=99 is a register constant
        assert!(result.constant_registers > 0, "should find x0=99 constant");

        // x1 is an induction variable (base=10, stride=2)
        assert!(result.induction_variables > 0, "should find x1 induction");

        // Branch always to 0x2000
        assert!(
            result.resolved_branches > 0,
            "should find always-taken branch"
        );

        // Memory 0x5000 always 0xBEEF
        assert!(result.constant_memory > 0, "should find memory constant");

        // Dataflow: 0x1000 writes 0x6000, 0x2000 reads it
        assert!(result.dataflow_edges > 0, "should find dataflow edge");
    }
}
