//! Sparse conditional constant propagation (SCCP) -- a lattice-based
//! forward dataflow analysis that simultaneously discovers constant values
//! and unreachable branches, yielding stronger results than simple constant
//! propagation or dead-branch elimination alone.
//!
//! Implements the Wegman-Zadeck algorithm with a dual worklist: SSA edges
//! for value propagation and CFG edges for reachability.

use std::collections::{HashMap, HashSet, VecDeque};

use super::construct::SsaFunction;
use super::types::*;
use super::use_def::UseDefMap;

// ---------------------------------------------------------------------------
// Lattice
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatticeValue {
    /// Not yet analyzed (optimistic: assume unreachable).
    Top,
    /// Known constant.
    Constant(u64),
    /// Proven non-constant.
    Bottom,
}

fn meet(a: LatticeValue, b: LatticeValue) -> LatticeValue {
    match (a, b) {
        (LatticeValue::Top, x) | (x, LatticeValue::Top) => x,
        (LatticeValue::Constant(a), LatticeValue::Constant(b)) => {
            if a == b {
                LatticeValue::Constant(a)
            } else {
                LatticeValue::Bottom
            }
        }
        (LatticeValue::Bottom, _) | (_, LatticeValue::Bottom) => LatticeValue::Bottom,
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct SccpState {
    values: HashMap<SsaVar, LatticeValue>,
    executable_edges: HashSet<(BlockId, BlockId)>,
    executable_blocks: HashSet<BlockId>,
    ssa_worklist: VecDeque<SsaVar>,
    cfg_worklist: VecDeque<(BlockId, BlockId)>,
}

impl SccpState {
    fn new() -> Self {
        SccpState {
            values: HashMap::new(),
            executable_edges: HashSet::new(),
            executable_blocks: HashSet::new(),
            ssa_worklist: VecDeque::new(),
            cfg_worklist: VecDeque::new(),
        }
    }

    /// Get the lattice value for a variable (Top if not yet visited).
    fn get(&self, var: &SsaVar) -> LatticeValue {
        self.values.get(var).cloned().unwrap_or(LatticeValue::Top)
    }

    /// Update a variable's lattice value.  Returns true if the value changed
    /// (i.e. moved down in the lattice).
    fn update(&mut self, var: SsaVar, new_val: LatticeValue) -> bool {
        let old = self.get(&var);
        if old == new_val {
            return false;
        }
        // Lattice values only move downward: Top -> Constant -> Bottom.
        // If old is already Bottom, we should not change it.
        if old == LatticeValue::Bottom {
            return false;
        }
        self.values.insert(var, new_val);
        true
    }
}

// ---------------------------------------------------------------------------
// Expression evaluation
// ---------------------------------------------------------------------------

fn eval_expr(
    expr: &SsaExpr,
    values: &HashMap<SsaVar, LatticeValue>,
    executable_edges: &HashSet<(BlockId, BlockId)>,
    block: BlockId,
) -> LatticeValue {
    match expr {
        SsaExpr::Var(v) => values.get(v).cloned().unwrap_or(LatticeValue::Top),
        SsaExpr::Imm(c) => LatticeValue::Constant(*c),
        SsaExpr::Add(a, b) => {
            eval_binary(a, b, values, executable_edges, block, |x, y| {
                x.wrapping_add(y)
            })
        }
        SsaExpr::Sub(a, b) => {
            eval_binary(a, b, values, executable_edges, block, |x, y| {
                x.wrapping_sub(y)
            })
        }
        SsaExpr::Mul(a, b) => {
            eval_binary(a, b, values, executable_edges, block, |x, y| {
                x.wrapping_mul(y)
            })
        }
        SsaExpr::And(a, b) => {
            eval_binary(a, b, values, executable_edges, block, |x, y| x & y)
        }
        SsaExpr::Or(a, b) => {
            eval_binary(a, b, values, executable_edges, block, |x, y| x | y)
        }
        SsaExpr::Xor(a, b) => {
            eval_binary(a, b, values, executable_edges, block, |x, y| x ^ y)
        }
        SsaExpr::Shl(a, b) => {
            eval_binary(a, b, values, executable_edges, block, |x, y| {
                if y < 64 {
                    x.wrapping_shl(y as u32)
                } else {
                    0
                }
            })
        }
        SsaExpr::Lsr(a, b) => {
            eval_binary(a, b, values, executable_edges, block, |x, y| {
                if y < 64 {
                    x.wrapping_shr(y as u32)
                } else {
                    0
                }
            })
        }
        SsaExpr::Neg(a) => {
            eval_unary(a, values, executable_edges, block, |x| x.wrapping_neg())
        }
        SsaExpr::Not(a) => eval_unary(a, values, executable_edges, block, |x| !x),
        SsaExpr::Phi(operands) => {
            // Meet over operands whose incoming edge is executable.
            let mut result = LatticeValue::Top;
            for &(pred, var) in operands {
                if executable_edges.contains(&(pred, block)) {
                    let val = values.get(&var).cloned().unwrap_or(LatticeValue::Top);
                    result = meet(result, val);
                }
            }
            result
        }
        SsaExpr::Load { .. } => LatticeValue::Bottom,
        SsaExpr::FImm(_) => LatticeValue::Bottom,
        // Conservative for everything else.
        _ => LatticeValue::Bottom,
    }
}

fn eval_binary(
    a: &SsaExpr,
    b: &SsaExpr,
    values: &HashMap<SsaVar, LatticeValue>,
    exec_edges: &HashSet<(BlockId, BlockId)>,
    block: BlockId,
    op: impl Fn(u64, u64) -> u64,
) -> LatticeValue {
    let va = eval_expr(a, values, exec_edges, block);
    let vb = eval_expr(b, values, exec_edges, block);
    match (va, vb) {
        (LatticeValue::Constant(a), LatticeValue::Constant(b)) => {
            LatticeValue::Constant(op(a, b))
        }
        (LatticeValue::Bottom, _) | (_, LatticeValue::Bottom) => LatticeValue::Bottom,
        _ => LatticeValue::Top,
    }
}

fn eval_unary(
    a: &SsaExpr,
    values: &HashMap<SsaVar, LatticeValue>,
    exec_edges: &HashSet<(BlockId, BlockId)>,
    block: BlockId,
    op: impl Fn(u64) -> u64,
) -> LatticeValue {
    let va = eval_expr(a, values, exec_edges, block);
    match va {
        LatticeValue::Constant(v) => LatticeValue::Constant(op(v)),
        LatticeValue::Bottom => LatticeValue::Bottom,
        LatticeValue::Top => LatticeValue::Top,
    }
}

// ---------------------------------------------------------------------------
// Branch condition evaluation
// ---------------------------------------------------------------------------

/// Evaluate a branch condition to a tri-state: Some(true) = taken,
/// Some(false) = not taken, None = unknown.
fn eval_branch_cond(
    cond: &SsaBranchCond,
    values: &HashMap<SsaVar, LatticeValue>,
    exec_edges: &HashSet<(BlockId, BlockId)>,
    block: BlockId,
) -> Option<bool> {
    match cond {
        SsaBranchCond::Zero(expr) => {
            match eval_expr(expr, values, exec_edges, block) {
                LatticeValue::Constant(v) => Some(v == 0),
                _ => None,
            }
        }
        SsaBranchCond::NotZero(expr) => {
            match eval_expr(expr, values, exec_edges, block) {
                LatticeValue::Constant(v) => Some(v != 0),
                _ => None,
            }
        }
        SsaBranchCond::BitZero(expr, bit) => {
            match eval_expr(expr, values, exec_edges, block) {
                LatticeValue::Constant(v) => Some((v >> *bit as u64) & 1 == 0),
                _ => None,
            }
        }
        SsaBranchCond::BitNotZero(expr, bit) => {
            match eval_expr(expr, values, exec_edges, block) {
                LatticeValue::Constant(v) => Some((v >> *bit as u64) & 1 != 0),
                _ => None,
            }
        }
        SsaBranchCond::Compare {
            cond: cc,
            lhs,
            rhs,
        } => {
            let lv = eval_expr(lhs, values, exec_edges, block);
            let rv = eval_expr(rhs, values, exec_edges, block);
            match (lv, rv) {
                (LatticeValue::Constant(a), LatticeValue::Constant(b)) => {
                    eval_condition(cc, a, b)
                }
                _ => None,
            }
        }
        SsaBranchCond::Flag(_, _) => None, // flags are complex; conservative
    }
}

/// Evaluate an ARM64 condition code on two u64 operands.
fn eval_condition(cond: &aeonil::Condition, a: u64, b: u64) -> Option<bool> {
    use aeonil::Condition;
    match cond {
        Condition::EQ => Some(a == b),
        Condition::NE => Some(a != b),
        Condition::CS => Some(a >= b),
        Condition::CC => Some(a < b),
        Condition::HI => Some(a > b),
        Condition::LS => Some(a <= b),
        Condition::GE => Some((a as i64) >= (b as i64)),
        Condition::LT => Some((a as i64) < (b as i64)),
        Condition::GT => Some((a as i64) > (b as i64)),
        Condition::LE => Some((a as i64) <= (b as i64)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Block/statement evaluation
// ---------------------------------------------------------------------------

/// Evaluate all statements in a block.
fn evaluate_block(func: &SsaFunction, block_id: BlockId, state: &mut SccpState) {
    let block = &func.blocks[block_id as usize];
    for stmt_idx in 0..block.stmts.len() {
        evaluate_stmt(func, block_id, stmt_idx, state);
    }
}

/// Evaluate only phi nodes in a block (when a new edge becomes executable).
fn evaluate_phis(func: &SsaFunction, block_id: BlockId, state: &mut SccpState) {
    let block = &func.blocks[block_id as usize];
    for stmt_idx in 0..block.stmts.len() {
        if let SsaStmt::Assign {
            src: SsaExpr::Phi(_),
            ..
        } = &block.stmts[stmt_idx]
        {
            evaluate_stmt(func, block_id, stmt_idx, state);
        }
    }
}

/// Evaluate a single statement at (block_id, stmt_idx).
fn evaluate_stmt(
    func: &SsaFunction,
    block_id: BlockId,
    stmt_idx: usize,
    state: &mut SccpState,
) {
    let block = &func.blocks[block_id as usize];
    let stmt = &block.stmts[stmt_idx];

    match stmt {
        SsaStmt::Assign { dst, src } => {
            let new_val = eval_expr(src, &state.values, &state.executable_edges, block_id);
            if state.update(*dst, new_val) {
                state.ssa_worklist.push_back(*dst);
            }
        }
        SsaStmt::CondBranch {
            cond,
            fallthrough,
            ..
        } => {
            let result =
                eval_branch_cond(cond, &state.values, &state.executable_edges, block_id);

            // Determine the branch-taken target block from the successors list.
            // Convention: successors[0] = branch target, successors[1] = fallthrough
            // (if present).  We also have the `fallthrough` field.
            let succs = &block.successors;
            let taken_block = succs
                .iter()
                .find(|&&s| s != *fallthrough)
                .copied()
                .unwrap_or(*fallthrough);

            match result {
                Some(true) => {
                    // Branch is taken.
                    state.cfg_worklist.push_back((block_id, taken_block));
                }
                Some(false) => {
                    // Branch is not taken: fall through.
                    state.cfg_worklist.push_back((block_id, *fallthrough));
                }
                None => {
                    // Unknown: mark both edges.
                    state.cfg_worklist.push_back((block_id, taken_block));
                    state.cfg_worklist.push_back((block_id, *fallthrough));
                }
            }
        }
        SsaStmt::Branch { .. } => {
            // Unconditional branch: mark all successor edges.
            for &succ in &block.successors {
                state.cfg_worklist.push_back((block_id, succ));
            }
        }
        SsaStmt::Ret | SsaStmt::Trap => {
            // No successors.
        }
        _ => {
            // For any other statement (Store, Call, SetFlags, etc.), mark all
            // successor edges executable if this is the last statement.
            // Non-terminal statements don't affect CFG edges.
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run sparse conditional constant propagation.  Returns `true` if any
/// assignments were rewritten to constants.
pub fn run(func: &mut SsaFunction, use_def: &mut UseDefMap) -> bool {
    let mut state = SccpState::new();

    // Initialize: mark entry block executable via a self-edge seed.
    state.executable_blocks.insert(func.entry);
    state.cfg_worklist.push_back((func.entry, func.entry));

    // Main loop: drain both worklists until fixed point.
    while !state.cfg_worklist.is_empty() || !state.ssa_worklist.is_empty() {
        // Process CFG worklist.
        while let Some((src, dst)) = state.cfg_worklist.pop_front() {
            if src == dst && src == func.entry {
                // Self-edge seed: evaluate the entry block.
                evaluate_block(func, dst, &mut state);
                // Mark successor edges of the entry block.
                let succs: Vec<BlockId> = func.blocks[dst as usize].successors.clone();
                for succ in succs {
                    state.cfg_worklist.push_back((dst, succ));
                }
                continue;
            }

            if !state.executable_edges.insert((src, dst)) {
                continue; // already processed
            }

            let first_visit = state.executable_blocks.insert(dst);
            if first_visit {
                // Evaluate all statements in dst.
                evaluate_block(func, dst, &mut state);
                // For blocks that don't end with a branch/ret, propagate to
                // successors (e.g., blocks ending with Store, Nop, etc.).
                let block = &func.blocks[dst as usize];
                let has_terminator = block.stmts.last().map_or(false, |s| {
                    matches!(
                        s,
                        SsaStmt::Branch { .. }
                            | SsaStmt::CondBranch { .. }
                            | SsaStmt::Ret
                            | SsaStmt::Trap
                    )
                });
                if !has_terminator {
                    let succs: Vec<BlockId> = block.successors.clone();
                    for succ in succs {
                        state.cfg_worklist.push_back((dst, succ));
                    }
                }
            } else {
                // Re-evaluate only phi nodes in dst (new edge may contribute).
                evaluate_phis(func, dst, &mut state);
            }
        }

        // Process SSA worklist.
        while let Some(var) = state.ssa_worklist.pop_front() {
            let use_locs: Vec<_> = use_def.uses_of(&var).cloned().collect();
            for use_loc in use_locs {
                if state.executable_blocks.contains(&use_loc.block) {
                    evaluate_stmt(func, use_loc.block, use_loc.stmt_idx, &mut state);
                }
            }
        }
    }

    // Rewriting phase.
    rewrite(func, &state)
}

// ---------------------------------------------------------------------------
// Rewriting
// ---------------------------------------------------------------------------

/// Replace all assignments whose destination has a known constant lattice
/// value with `Imm(c)`.  Returns true if any changes were made.
fn rewrite(func: &mut SsaFunction, state: &SccpState) -> bool {
    let mut changed = false;

    for block in &mut func.blocks {
        if !state.executable_blocks.contains(&block.id) {
            continue;
        }
        for stmt in &mut block.stmts {
            if let SsaStmt::Assign { dst, src } = stmt {
                if let Some(LatticeValue::Constant(c)) = state.values.get(dst) {
                    // Don't rewrite if it is already Imm with the same value.
                    if *src != SsaExpr::Imm(*c) {
                        *src = SsaExpr::Imm(*c);
                        changed = true;
                    }
                }
            }
        }
    }

    changed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::construct::{SsaBlock, SsaFunction};
    use crate::ssa::use_def::UseDefMap;

    /// Helper to create a simple SsaVar for testing.
    fn var(n: u8, version: u32) -> SsaVar {
        SsaVar {
            loc: RegLocation::Gpr(n),
            version,
            width: RegWidth::W64,
        }
    }

    fn make_func(entry: BlockId, blocks: Vec<SsaBlock>) -> SsaFunction {
        SsaFunction { entry, blocks }
    }

    fn make_block(
        id: BlockId,
        stmts: Vec<SsaStmt>,
        successors: Vec<BlockId>,
        predecessors: Vec<BlockId>,
    ) -> SsaBlock {
        SsaBlock {
            id,
            addr: id as u64 * 4,
            stmts,
            successors,
            predecessors,
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: sccp_const_assign
    // -----------------------------------------------------------------------

    #[test]
    fn sccp_const_assign() {
        // v1 = Imm(42)
        // v2 = Add(Var(v1), Imm(8))
        // Expected: v2 becomes Imm(50)
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let mut func = make_func(
            0,
            vec![make_block(
                0,
                vec![
                    SsaStmt::Assign {
                        dst: v1,
                        src: SsaExpr::Imm(42),
                    },
                    SsaStmt::Assign {
                        dst: v2,
                        src: SsaExpr::Add(
                            Box::new(SsaExpr::Var(v1)),
                            Box::new(SsaExpr::Imm(8)),
                        ),
                    },
                ],
                vec![],
                vec![],
            )],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        // v2's src should now be Imm(50).
        assert_eq!(
            func.blocks[0].stmts[1],
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Imm(50),
            }
        );
    }

    // -----------------------------------------------------------------------
    // Test 2: sccp_transitive
    // -----------------------------------------------------------------------

    #[test]
    fn sccp_transitive() {
        // v1 = Imm(2)
        // v2 = Mul(Var(v1), Imm(3))   => 6
        // v3 = Add(Var(v2), Imm(1))    => 7
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let v3 = var(2, 1);
        let mut func = make_func(
            0,
            vec![make_block(
                0,
                vec![
                    SsaStmt::Assign {
                        dst: v1,
                        src: SsaExpr::Imm(2),
                    },
                    SsaStmt::Assign {
                        dst: v2,
                        src: SsaExpr::Mul(
                            Box::new(SsaExpr::Var(v1)),
                            Box::new(SsaExpr::Imm(3)),
                        ),
                    },
                    SsaStmt::Assign {
                        dst: v3,
                        src: SsaExpr::Add(
                            Box::new(SsaExpr::Var(v2)),
                            Box::new(SsaExpr::Imm(1)),
                        ),
                    },
                ],
                vec![],
                vec![],
            )],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        assert_eq!(
            func.blocks[0].stmts[2],
            SsaStmt::Assign {
                dst: v3,
                src: SsaExpr::Imm(7),
            }
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: sccp_phi_same_const
    // -----------------------------------------------------------------------

    #[test]
    fn sccp_phi_same_const() {
        // Block 0 (entry): v1 = Imm(5), branch to block 2
        // Block 1: v2 = Imm(5), branch to block 2
        // Block 2: v3 = Phi((0, v1), (1, v2))
        // Both operands are constant 5, so v3 = 5
        let v1 = var(0, 1);
        let v2 = var(0, 2);
        let v3 = var(0, 3);
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![
                        SsaStmt::Assign {
                            dst: v1,
                            src: SsaExpr::Imm(5),
                        },
                        SsaStmt::Branch {
                            target: SsaExpr::Imm(2),
                        },
                    ],
                    vec![2],
                    vec![],
                ),
                make_block(
                    1,
                    vec![
                        SsaStmt::Assign {
                            dst: v2,
                            src: SsaExpr::Imm(5),
                        },
                        SsaStmt::Branch {
                            target: SsaExpr::Imm(2),
                        },
                    ],
                    vec![2],
                    vec![],
                ),
                make_block(
                    2,
                    vec![SsaStmt::Assign {
                        dst: v3,
                        src: SsaExpr::Phi(vec![(0, v1), (1, v2)]),
                    }],
                    vec![],
                    vec![0, 1],
                ),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        // v3 should be folded to Imm(5).
        // Note: block 1 is unreachable from entry (entry=0, 0->2 only),
        // so only the (0,v1) edge is executable. v1=5, so v3=5.
        assert_eq!(
            func.blocks[2].stmts[0],
            SsaStmt::Assign {
                dst: v3,
                src: SsaExpr::Imm(5),
            }
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: sccp_phi_different
    // -----------------------------------------------------------------------

    #[test]
    fn sccp_phi_different() {
        // Block 0 (entry): v1 = Imm(5), condbranch to block 1 or block 2
        // Block 1: v2 = Imm(5), branch to block 3
        // Block 2: v3 = Imm(7), branch to block 3
        // Block 3: v4 = Phi((1, v2), (2, v3))
        // Both edges are executable and values differ => v4 = Bottom (no fold)
        let v1 = var(0, 1);
        let v2 = var(0, 2);
        let v3 = var(0, 3);
        let v4 = var(0, 4);
        // We need a flags var for the CondBranch.
        let flags_var = SsaVar {
            loc: RegLocation::Flags,
            version: 1,
            width: RegWidth::Full,
        };
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![
                        SsaStmt::Assign {
                            dst: v1,
                            src: SsaExpr::Imm(5),
                        },
                        SsaStmt::CondBranch {
                            cond: SsaBranchCond::Flag(aeonil::Condition::EQ, flags_var),
                            target: SsaExpr::Imm(1),
                            fallthrough: 2,
                        },
                    ],
                    vec![1, 2],
                    vec![],
                ),
                make_block(
                    1,
                    vec![
                        SsaStmt::Assign {
                            dst: v2,
                            src: SsaExpr::Imm(5),
                        },
                        SsaStmt::Branch {
                            target: SsaExpr::Imm(3),
                        },
                    ],
                    vec![3],
                    vec![0],
                ),
                make_block(
                    2,
                    vec![
                        SsaStmt::Assign {
                            dst: v3,
                            src: SsaExpr::Imm(7),
                        },
                        SsaStmt::Branch {
                            target: SsaExpr::Imm(3),
                        },
                    ],
                    vec![3],
                    vec![0],
                ),
                make_block(
                    3,
                    vec![SsaStmt::Assign {
                        dst: v4,
                        src: SsaExpr::Phi(vec![(1, v2), (2, v3)]),
                    }],
                    vec![],
                    vec![1, 2],
                ),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);

        // v4 should NOT be folded (different constants => Bottom).
        // The phi should remain unchanged.
        assert_eq!(
            func.blocks[3].stmts[0],
            SsaStmt::Assign {
                dst: v4,
                src: SsaExpr::Phi(vec![(1, v2), (2, v3)]),
            }
        );
        // v1, v2, v3 might have been folded but v4 stays as phi.
        // `changed` might be true if v1/v2/v3 were already Imm (they are,
        // so no rewrite for those). The key assertion is that v4's phi is not folded.
        let _ = changed;
    }

    // -----------------------------------------------------------------------
    // Test 5: sccp_non_const_load
    // -----------------------------------------------------------------------

    #[test]
    fn sccp_non_const_load() {
        // v1 = Load(Imm(0x1000), 8)
        // Loads are always Bottom (unknown memory), so no folding.
        let v1 = var(0, 1);
        let mut func = make_func(
            0,
            vec![make_block(
                0,
                vec![SsaStmt::Assign {
                    dst: v1,
                    src: SsaExpr::Load {
                        addr: Box::new(SsaExpr::Imm(0x1000)),
                        size: 8,
                    },
                }],
                vec![],
                vec![],
            )],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(!changed);

        // Load should remain unchanged.
        assert!(matches!(
            &func.blocks[0].stmts[0],
            SsaStmt::Assign {
                src: SsaExpr::Load { .. },
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Test 6: sccp_overflow_wraps
    // -----------------------------------------------------------------------

    #[test]
    fn sccp_overflow_wraps() {
        // v1 = Imm(u64::MAX)
        // v2 = Add(Var(v1), Imm(1))
        // Expected: v2 = Imm(0) (wrapping add)
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let mut func = make_func(
            0,
            vec![make_block(
                0,
                vec![
                    SsaStmt::Assign {
                        dst: v1,
                        src: SsaExpr::Imm(u64::MAX),
                    },
                    SsaStmt::Assign {
                        dst: v2,
                        src: SsaExpr::Add(
                            Box::new(SsaExpr::Var(v1)),
                            Box::new(SsaExpr::Imm(1)),
                        ),
                    },
                ],
                vec![],
                vec![],
            )],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        assert_eq!(
            func.blocks[0].stmts[1],
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Imm(0),
            }
        );
    }

    // -----------------------------------------------------------------------
    // Test 7: sccp_no_change
    // -----------------------------------------------------------------------

    #[test]
    fn sccp_no_change() {
        // v1 = Load(Imm(0x2000), 8)  -- unknown
        // v2 = Add(Var(v1), Imm(1))  -- depends on unknown => Bottom
        // Already-optimal code => returns false (no change)
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let mut func = make_func(
            0,
            vec![make_block(
                0,
                vec![
                    SsaStmt::Assign {
                        dst: v1,
                        src: SsaExpr::Load {
                            addr: Box::new(SsaExpr::Imm(0x2000)),
                            size: 8,
                        },
                    },
                    SsaStmt::Assign {
                        dst: v2,
                        src: SsaExpr::Add(
                            Box::new(SsaExpr::Var(v1)),
                            Box::new(SsaExpr::Imm(1)),
                        ),
                    },
                ],
                vec![],
                vec![],
            )],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(!changed);

        // Both statements should remain unchanged.
        assert!(matches!(
            &func.blocks[0].stmts[0],
            SsaStmt::Assign {
                src: SsaExpr::Load { .. },
                ..
            }
        ));
        assert!(matches!(
            &func.blocks[0].stmts[1],
            SsaStmt::Assign {
                src: SsaExpr::Add(..),
                ..
            }
        ));
    }
}
