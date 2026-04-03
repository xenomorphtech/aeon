//! Dead branch elimination -- removes conditional branches whose condition
//! is statically known (after SCCP or constant folding), rewrites them as
//! unconditional branches, and deletes newly-unreachable basic blocks.
//! Also cleans up phi nodes that reference removed predecessors.

use super::construct::SsaFunction;
use super::types::*;
use super::use_def::UseDefMap;
use aeonil::Condition;
use std::collections::{HashSet, VecDeque};

/// Run dead branch and unreachable block elimination. Returns true if changes were made.
pub fn run(func: &mut SsaFunction, use_def: &mut UseDefMap) -> bool {
    let mut changed = false;
    changed |= resolve_constant_branches(func);
    changed |= remove_unreachable_blocks(func, use_def);
    changed |= cleanup_phis(func, use_def);
    changed
}

// ---------------------------------------------------------------------------
// Phase 1: Resolve constant branches
// ---------------------------------------------------------------------------

/// Evaluate an ARM64 condition on two immediate operands.
fn eval_compare(cond: &Condition, a: u64, b: u64) -> Option<bool> {
    match cond {
        Condition::EQ => Some(a == b),
        Condition::NE => Some(a != b),
        Condition::CS => Some(a >= b), // unsigned >=
        Condition::CC => Some(a < b),  // unsigned <
        Condition::HI => Some(a > b),  // unsigned >
        Condition::LS => Some(a <= b), // unsigned <=
        Condition::GE => Some((a as i64) >= (b as i64)),
        Condition::LT => Some((a as i64) < (b as i64)),
        Condition::GT => Some((a as i64) > (b as i64)),
        Condition::LE => Some((a as i64) <= (b as i64)),
        // MI, PL, VS, VC, AL, NV depend on flag state we don't have
        _ => None,
    }
}

/// Walk all blocks and resolve CondBranch whose condition is statically known.
fn resolve_constant_branches(func: &mut SsaFunction) -> bool {
    let mut changed = false;

    for block_idx in 0..func.blocks.len() {
        let resolved = {
            // Find the last CondBranch in this block
            let block = &func.blocks[block_idx];
            let mut result = None;

            for (stmt_idx, stmt) in block.stmts.iter().enumerate() {
                if let SsaStmt::CondBranch {
                    cond,
                    target,
                    fallthrough,
                } = stmt
                {
                    let takes_branch = match cond {
                        SsaBranchCond::Compare { cond: cc, lhs, rhs } => {
                            if let (SsaExpr::Imm(a), SsaExpr::Imm(b)) = (lhs.as_ref(), rhs.as_ref())
                            {
                                eval_compare(cc, *a, *b)
                            } else {
                                None
                            }
                        }
                        SsaBranchCond::Zero(expr) => {
                            if let SsaExpr::Imm(v) = expr {
                                Some(*v == 0)
                            } else {
                                None
                            }
                        }
                        SsaBranchCond::NotZero(expr) => {
                            if let SsaExpr::Imm(v) = expr {
                                Some(*v != 0)
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };

                    if let Some(taken) = takes_branch {
                        result = Some((stmt_idx, taken, target.clone(), *fallthrough));
                    }
                }
            }
            result
        };

        if let Some((stmt_idx, taken, target_expr, fallthrough)) = resolved {
            let block = &mut func.blocks[block_idx];

            if taken {
                // Branch is taken: replace with unconditional branch to target,
                // remove fallthrough from successors.
                block.stmts[stmt_idx] = SsaStmt::Branch {
                    target: target_expr,
                };
                block.successors.retain(|&s| s != fallthrough);
            } else {
                // Branch is not taken: replace with unconditional branch to fallthrough,
                // remove the branch target from successors.
                // The branch target block is the successor that isn't the fallthrough.
                let branch_target_block: Vec<BlockId> = block
                    .successors
                    .iter()
                    .copied()
                    .filter(|&s| s != fallthrough)
                    .collect();
                block.stmts[stmt_idx] = SsaStmt::Branch {
                    target: SsaExpr::Imm(fallthrough as u64),
                };
                for btb in &branch_target_block {
                    block.successors.retain(|s| s != btb);
                }
            }
            changed = true;
        }
    }

    changed
}

// ---------------------------------------------------------------------------
// Phase 2: Remove unreachable blocks
// ---------------------------------------------------------------------------

fn remove_unreachable_blocks(func: &mut SsaFunction, _use_def: &mut UseDefMap) -> bool {
    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(func.entry);
    reachable.insert(func.entry);

    while let Some(b) = queue.pop_front() {
        if let Some(block) = func.blocks.iter().find(|bl| bl.id == b) {
            for &succ in &block.successors {
                if reachable.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }

    let before = func.blocks.len();
    func.blocks.retain(|b| reachable.contains(&b.id));

    // Rebuild predecessor lists to reflect removed blocks
    rebuild_predecessors(func);

    func.blocks.len() < before
}

/// Recompute predecessor lists from successor edges.
fn rebuild_predecessors(func: &mut SsaFunction) {
    // Clear all predecessor lists
    for block in &mut func.blocks {
        block.predecessors.clear();
    }

    // Collect edges: (pred_id, succ_id)
    let edges: Vec<(BlockId, BlockId)> = func
        .blocks
        .iter()
        .flat_map(|b| b.successors.iter().map(move |&s| (b.id, s)))
        .collect();

    for (pred, succ) in edges {
        if let Some(block) = func.blocks.iter_mut().find(|b| b.id == succ) {
            if !block.predecessors.contains(&pred) {
                block.predecessors.push(pred);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 3: Phi cleanup
// ---------------------------------------------------------------------------

fn cleanup_phis(func: &mut SsaFunction, _use_def: &mut UseDefMap) -> bool {
    let mut changed = false;

    for block_idx in 0..func.blocks.len() {
        let preds: HashSet<BlockId> = func.blocks[block_idx]
            .predecessors
            .iter()
            .copied()
            .collect();

        for stmt_idx in 0..func.blocks[block_idx].stmts.len() {
            if let SsaStmt::Assign {
                dst,
                src: SsaExpr::Phi(operands),
            } = &func.blocks[block_idx].stmts[stmt_idx]
            {
                let dst = *dst;
                let new_operands: Vec<_> = operands
                    .iter()
                    .filter(|(pred, _)| preds.contains(pred))
                    .cloned()
                    .collect();

                if new_operands.len() < operands.len() {
                    if new_operands.len() == 1 {
                        // Single operand: replace phi with copy
                        func.blocks[block_idx].stmts[stmt_idx] = SsaStmt::Assign {
                            dst,
                            src: SsaExpr::Var(new_operands[0].1),
                        };
                    } else {
                        func.blocks[block_idx].stmts[stmt_idx] = SsaStmt::Assign {
                            dst,
                            src: SsaExpr::Phi(new_operands),
                        };
                    }
                    changed = true;
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

    /// Build a multi-block function from a list of blocks.
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
    // Test 1: dead_branch_const_true
    // -----------------------------------------------------------------------

    #[test]
    fn dead_branch_const_true() {
        // Block 0: CondBranch(Compare(EQ, Imm(5), Imm(5)), target=block 1, fallthrough=block 2)
        // Block 1: Ret
        // Block 2: Ret
        // EQ(5, 5) is true => replaced with Branch(target), block 2 removed from successors
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![SsaStmt::CondBranch {
                        cond: SsaBranchCond::Compare {
                            cond: Condition::EQ,
                            lhs: Box::new(SsaExpr::Imm(5)),
                            rhs: Box::new(SsaExpr::Imm(5)),
                        },
                        target: SsaExpr::Imm(0x100),
                        fallthrough: 2,
                    }],
                    vec![1, 2],
                    vec![],
                ),
                make_block(1, vec![SsaStmt::Ret], vec![], vec![0]),
                make_block(2, vec![SsaStmt::Ret], vec![], vec![0]),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        // Block 0 should now have an unconditional Branch
        assert!(matches!(
            &func.blocks[0].stmts[0],
            SsaStmt::Branch {
                target: SsaExpr::Imm(0x100)
            }
        ));
        // Successors should only contain block 1 (not block 2)
        assert_eq!(func.blocks[0].successors, vec![1]);
    }

    // -----------------------------------------------------------------------
    // Test 2: dead_branch_const_false
    // -----------------------------------------------------------------------

    #[test]
    fn dead_branch_const_false() {
        // Block 0: CondBranch(Compare(EQ, Imm(5), Imm(3)), target=block 1, fallthrough=block 2)
        // Block 1: Ret
        // Block 2: Ret
        // EQ(5, 3) is false => replaced with Branch to fallthrough (block 2)
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![SsaStmt::CondBranch {
                        cond: SsaBranchCond::Compare {
                            cond: Condition::EQ,
                            lhs: Box::new(SsaExpr::Imm(5)),
                            rhs: Box::new(SsaExpr::Imm(3)),
                        },
                        target: SsaExpr::Imm(0x100),
                        fallthrough: 2,
                    }],
                    vec![1, 2],
                    vec![],
                ),
                make_block(1, vec![SsaStmt::Ret], vec![], vec![0]),
                make_block(2, vec![SsaStmt::Ret], vec![], vec![0]),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        // Block 0 should now have an unconditional Branch to fallthrough
        assert!(matches!(
            &func.blocks[0].stmts[0],
            SsaStmt::Branch {
                target: SsaExpr::Imm(2)
            }
        ));
        // Successors should only contain block 2 (not block 1)
        assert_eq!(func.blocks[0].successors, vec![2]);
    }

    // -----------------------------------------------------------------------
    // Test 3: unreachable_block_removed
    // -----------------------------------------------------------------------

    #[test]
    fn unreachable_block_removed() {
        // Block 0: CondBranch(Compare(EQ, Imm(5), Imm(5)), target=block 1, fallthrough=block 2)
        // Block 1: Ret
        // Block 2: Ret
        // After resolving, block 0 only goes to block 1, so block 2 is unreachable.
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![SsaStmt::CondBranch {
                        cond: SsaBranchCond::Compare {
                            cond: Condition::EQ,
                            lhs: Box::new(SsaExpr::Imm(5)),
                            rhs: Box::new(SsaExpr::Imm(5)),
                        },
                        target: SsaExpr::Imm(0x100),
                        fallthrough: 2,
                    }],
                    vec![1, 2],
                    vec![],
                ),
                make_block(1, vec![SsaStmt::Ret], vec![], vec![0]),
                make_block(2, vec![SsaStmt::Ret], vec![], vec![0]),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        // Only blocks 0 and 1 should remain
        let block_ids: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
        assert_eq!(block_ids, vec![0, 1]);
    }

    // -----------------------------------------------------------------------
    // Test 4: phi_cleanup
    // -----------------------------------------------------------------------

    #[test]
    fn phi_cleanup() {
        // Block 0: Branch to block 2
        // Block 1: Branch to block 2 (but block 1 is unreachable)
        // Block 2: v3 = Phi((0, v1), (1, v2))
        //
        // After removing unreachable block 1, the phi should be simplified
        // to a copy: v3 = Var(v1)
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
                            src: SsaExpr::Imm(10),
                        },
                        SsaStmt::Branch {
                            target: SsaExpr::Imm(8),
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
                            src: SsaExpr::Imm(20),
                        },
                        SsaStmt::Branch {
                            target: SsaExpr::Imm(8),
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

        // Block 1 should be removed (unreachable from entry)
        let block_ids: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
        assert_eq!(block_ids, vec![0, 2]);

        // The phi in block 2 should be simplified to a copy
        let block2 = func.blocks.iter().find(|b| b.id == 2).unwrap();
        assert!(matches!(
            &block2.stmts[0],
            SsaStmt::Assign { dst, src: SsaExpr::Var(v) }
            if *dst == v3 && *v == v1
        ));
    }

    // -----------------------------------------------------------------------
    // Test 5: entry_never_removed
    // -----------------------------------------------------------------------

    #[test]
    fn entry_never_removed() {
        // Single entry block with Ret. No predecessors, no successors.
        // It should always survive.
        let mut func = make_func(0, vec![make_block(0, vec![SsaStmt::Ret], vec![], vec![])]);
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(!changed);
        assert_eq!(func.blocks.len(), 1);
        assert_eq!(func.blocks[0].id, 0);
    }

    // -----------------------------------------------------------------------
    // Test 6: cascade_unreachable
    // -----------------------------------------------------------------------

    #[test]
    fn cascade_unreachable() {
        // Block 0: CondBranch(Compare(NE, Imm(0), Imm(0)), target=block 1, fallthrough=block 3)
        //   NE(0, 0) is false => resolve to Branch(fallthrough=block 3)
        //   => block 1 becomes unreachable
        // Block 1: Branch to block 2
        //   => block 2's only predecessor is block 1 => also unreachable
        // Block 2: Ret
        // Block 3: Ret
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![SsaStmt::CondBranch {
                        cond: SsaBranchCond::Compare {
                            cond: Condition::NE,
                            lhs: Box::new(SsaExpr::Imm(0)),
                            rhs: Box::new(SsaExpr::Imm(0)),
                        },
                        target: SsaExpr::Imm(0x100),
                        fallthrough: 3,
                    }],
                    vec![1, 3],
                    vec![],
                ),
                make_block(
                    1,
                    vec![SsaStmt::Branch {
                        target: SsaExpr::Imm(0x200),
                    }],
                    vec![2],
                    vec![0],
                ),
                make_block(2, vec![SsaStmt::Ret], vec![], vec![1]),
                make_block(3, vec![SsaStmt::Ret], vec![], vec![0]),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        // Only blocks 0 and 3 should remain; blocks 1 and 2 are both unreachable
        let block_ids: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
        assert_eq!(block_ids, vec![0, 3]);
    }

    // -----------------------------------------------------------------------
    // Additional edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn zero_branch_const_true() {
        // CondBranch with Zero(Imm(0)) => condition true (value is zero), take branch
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![SsaStmt::CondBranch {
                        cond: SsaBranchCond::Zero(SsaExpr::Imm(0)),
                        target: SsaExpr::Imm(0x100),
                        fallthrough: 1,
                    }],
                    vec![2, 1],
                    vec![],
                ),
                make_block(1, vec![SsaStmt::Ret], vec![], vec![0]),
                make_block(2, vec![SsaStmt::Ret], vec![], vec![0]),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        // Should have become an unconditional branch, fallthrough removed
        assert!(matches!(
            &func.blocks[0].stmts[0],
            SsaStmt::Branch {
                target: SsaExpr::Imm(0x100)
            }
        ));
        // Fallthrough (block 1) should be removed from successors
        assert!(!func.blocks[0].successors.contains(&1));
    }

    #[test]
    fn notzero_branch_const_false() {
        // CondBranch with NotZero(Imm(0)) => condition false (value is zero, but cond is not-zero)
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![SsaStmt::CondBranch {
                        cond: SsaBranchCond::NotZero(SsaExpr::Imm(0)),
                        target: SsaExpr::Imm(0x100),
                        fallthrough: 1,
                    }],
                    vec![2, 1],
                    vec![],
                ),
                make_block(1, vec![SsaStmt::Ret], vec![], vec![0]),
                make_block(2, vec![SsaStmt::Ret], vec![], vec![0]),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        // Should branch to fallthrough (block 1)
        assert!(matches!(
            &func.blocks[0].stmts[0],
            SsaStmt::Branch {
                target: SsaExpr::Imm(1)
            }
        ));
        // The branch target block should be removed from successors
        assert!(!func.blocks[0].successors.contains(&2));
        assert!(func.blocks[0].successors.contains(&1));
    }

    #[test]
    fn unsigned_compare_hi() {
        // HI: unsigned greater-than. Compare(HI, Imm(10), Imm(5)) => true
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![SsaStmt::CondBranch {
                        cond: SsaBranchCond::Compare {
                            cond: Condition::HI,
                            lhs: Box::new(SsaExpr::Imm(10)),
                            rhs: Box::new(SsaExpr::Imm(5)),
                        },
                        target: SsaExpr::Imm(0x100),
                        fallthrough: 2,
                    }],
                    vec![1, 2],
                    vec![],
                ),
                make_block(1, vec![SsaStmt::Ret], vec![], vec![0]),
                make_block(2, vec![SsaStmt::Ret], vec![], vec![0]),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);
        assert!(matches!(
            &func.blocks[0].stmts[0],
            SsaStmt::Branch {
                target: SsaExpr::Imm(0x100)
            }
        ));
    }

    #[test]
    fn signed_compare_lt() {
        // LT: signed less-than. Compare(LT, Imm(u64::MAX), Imm(0))
        // u64::MAX as i64 is -1, which is < 0 => true
        let mut func = make_func(
            0,
            vec![
                make_block(
                    0,
                    vec![SsaStmt::CondBranch {
                        cond: SsaBranchCond::Compare {
                            cond: Condition::LT,
                            lhs: Box::new(SsaExpr::Imm(u64::MAX)),
                            rhs: Box::new(SsaExpr::Imm(0)),
                        },
                        target: SsaExpr::Imm(0x100),
                        fallthrough: 2,
                    }],
                    vec![1, 2],
                    vec![],
                ),
                make_block(1, vec![SsaStmt::Ret], vec![], vec![0]),
                make_block(2, vec![SsaStmt::Ret], vec![], vec![0]),
            ],
        );
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);
        assert!(matches!(
            &func.blocks[0].stmts[0],
            SsaStmt::Branch {
                target: SsaExpr::Imm(0x100)
            }
        ));
    }
}
