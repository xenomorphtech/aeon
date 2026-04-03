//! SSA optimization pipeline -- orchestrates the SSA passes in the
//! recommended order and provides a convenience entry point for the
//! full reduce + SSA + optimize sequence.

use super::construct::SsaFunction;
use super::copy_prop;
use super::cse;
use super::dce;
use super::dead_branch;
use super::domtree::DomTree;
use super::sccp;
use super::use_def::UseDefMap;

const MAX_ITERATIONS: usize = 10;

/// Run all cross-block SSA optimizations on the given function to a fixed point.
pub fn optimize_ssa(func: &mut SsaFunction) {
    let mut use_def = UseDefMap::build(func);

    let mut iteration = 0;
    let mut changed = true;
    while changed && iteration < MAX_ITERATIONS {
        changed = false;
        iteration += 1;

        // 1. SCCP: propagate constants, identify dead branches
        changed |= sccp::run(func, &mut use_def);

        // 2. Dead branch/block elimination
        changed |= dead_branch::run(func, &mut use_def);

        // 3. Copy propagation + phi simplification
        changed |= copy_prop::run(func, &mut use_def);

        // 4. CSE (rebuild domtree since block structure may have changed)
        let dom_tree = DomTree::build(func);
        changed |= cse::run(func, &dom_tree, &mut use_def);

        // 5. DCE: clean up dead definitions
        changed |= dce::run(func, &mut use_def);

        // Rebuild use_def for next iteration since passes may have
        // made incremental updates that drifted from reality
        if changed {
            use_def = UseDefMap::build(func);
        }
    }
}

/// Full pipeline: intra-block reduce -> CFG -> SSA -> optimize.
/// Input: flat instruction list `(address, statement, edge_targets)`.
pub fn reduce_and_build_ssa(instructions: &[(u64, aeonil::Stmt, Vec<u64>)]) -> SsaFunction {
    use super::construct::build_ssa;
    use crate::pipeline::reduce_function_cfg;

    // 1. Build the function-level reduced CFG from the instruction list
    let cfg = reduce_function_cfg(instructions);

    // 2. Build SSA on top of the reduced CFG
    let mut ssa_func = build_ssa(&cfg);

    // 3. Optimize
    optimize_ssa(&mut ssa_func);

    ssa_func
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::construct::{SsaBlock, SsaFunction};
    use crate::ssa::types::*;

    /// Helper to create a simple SsaVar for testing.
    fn var(n: u8, version: u32) -> SsaVar {
        SsaVar {
            loc: RegLocation::Gpr(n),
            version,
            width: RegWidth::W64,
        }
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
    // Test 1: pipeline_identity
    // -----------------------------------------------------------------------
    // Simple straight-line code with no optimization opportunities.
    // A load followed by a store -- nothing to fold, propagate, or eliminate.

    #[test]
    fn pipeline_identity() {
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let mut func = SsaFunction {
            entry: 0,
            blocks: vec![make_block(
                0,
                vec![
                    // v1 = Load(Imm(0x1000), 8) -- unknown value
                    SsaStmt::Assign {
                        dst: v1,
                        src: SsaExpr::Load {
                            addr: Box::new(SsaExpr::Imm(0x1000)),
                            size: 8,
                        },
                    },
                    // v2 = Load(Imm(0x2000), 8) -- unknown value
                    SsaStmt::Assign {
                        dst: v2,
                        src: SsaExpr::Load {
                            addr: Box::new(SsaExpr::Imm(0x2000)),
                            size: 8,
                        },
                    },
                    // Store(Imm(0x3000), v1, 8)
                    SsaStmt::Store {
                        addr: SsaExpr::Imm(0x3000),
                        value: SsaExpr::Var(v1),
                        size: 8,
                    },
                    // Store(Imm(0x4000), v2, 8)
                    SsaStmt::Store {
                        addr: SsaExpr::Imm(0x4000),
                        value: SsaExpr::Var(v2),
                        size: 8,
                    },
                ],
                vec![],
                vec![],
            )],
        };

        let before_stmts = func.blocks[0].stmts.clone();
        optimize_ssa(&mut func);

        // Nothing should have changed: loads and stores are not optimizable
        assert_eq!(func.blocks.len(), 1);
        assert_eq!(func.blocks[0].stmts, before_stmts);
    }

    // -----------------------------------------------------------------------
    // Test 2: pipeline_dce_after_sccp
    // -----------------------------------------------------------------------
    // v1 = Imm(3); v2 = Add(v1, Imm(5)); v3 = Imm(99); Store(addr, v2, 8)
    // SCCP folds v2 to Imm(8).  DCE removes dead v3 and dead v1 (whose only
    // use was in v2's pre-fold expression, now replaced by Imm).

    #[test]
    fn pipeline_dce_after_sccp() {
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let v3 = var(2, 1);

        let mut func = SsaFunction {
            entry: 0,
            blocks: vec![make_block(
                0,
                vec![
                    SsaStmt::Assign {
                        dst: v1,
                        src: SsaExpr::Imm(3),
                    },
                    SsaStmt::Assign {
                        dst: v2,
                        src: SsaExpr::Add(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Imm(5))),
                    },
                    SsaStmt::Assign {
                        dst: v3,
                        src: SsaExpr::Imm(99),
                    },
                    SsaStmt::Store {
                        addr: SsaExpr::Imm(0x5000),
                        value: SsaExpr::Var(v2),
                        size: 8,
                    },
                ],
                vec![],
                vec![],
            )],
        };

        optimize_ssa(&mut func);

        // After SCCP, v2 = Imm(8).  After DCE, v1 and v3 are dead.
        // Expected remaining: v2 = Imm(8), Store(addr, v2, 8)
        let stmts = &func.blocks[0].stmts;

        // v3 (Imm(99)) should be removed -- it is dead
        assert!(
            !stmts
                .iter()
                .any(|s| matches!(s, SsaStmt::Assign { dst, src: SsaExpr::Imm(99) } if *dst == v3)),
            "v3 = Imm(99) should have been eliminated by DCE"
        );

        // v2 should be folded to Imm(8)
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s, SsaStmt::Assign { dst, src: SsaExpr::Imm(8) } if *dst == v2)),
            "v2 should be folded to Imm(8) by SCCP"
        );

        // Store should still exist
        assert!(
            stmts.iter().any(|s| matches!(s, SsaStmt::Store { .. })),
            "Store should survive"
        );

        // v1 should be removed (its only use was in v2 which is now Imm(8))
        assert!(
            !stmts
                .iter()
                .any(|s| matches!(s, SsaStmt::Assign { dst, src: SsaExpr::Imm(3) } if *dst == v1)),
            "v1 = Imm(3) should have been eliminated by DCE"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: pipeline_copy_then_dce
    // -----------------------------------------------------------------------
    // v1 = Load(..., 8)  -- non-constant so SCCP won't fold it
    // v2 = Var(v1)       -- copy
    // Store(addr, v2, 8)
    // Copy prop replaces v2 uses with v1.  DCE removes dead v2.

    #[test]
    fn pipeline_copy_then_dce() {
        let v1 = var(0, 1);
        let v2 = var(1, 1);

        let mut func = SsaFunction {
            entry: 0,
            blocks: vec![make_block(
                0,
                vec![
                    SsaStmt::Assign {
                        dst: v1,
                        src: SsaExpr::Load {
                            addr: Box::new(SsaExpr::Imm(0x8000)),
                            size: 8,
                        },
                    },
                    SsaStmt::Assign {
                        dst: v2,
                        src: SsaExpr::Var(v1),
                    },
                    SsaStmt::Store {
                        addr: SsaExpr::Imm(0x6000),
                        value: SsaExpr::Var(v2),
                        size: 8,
                    },
                ],
                vec![],
                vec![],
            )],
        };

        optimize_ssa(&mut func);

        let stmts = &func.blocks[0].stmts;

        // After copy prop: Store should reference v1 directly
        // After DCE: v2 = Var(v1) should be removed (no more uses)
        // v1 survives because Store now uses it

        // The copy v2 = Var(v1) should be eliminated by DCE
        assert!(
            !stmts
                .iter()
                .any(|s| matches!(s, SsaStmt::Assign { dst, src: SsaExpr::Var(_) } if *dst == v2)),
            "v2 = Var(v1) copy should be eliminated"
        );

        // Store should exist and reference v1
        let store = stmts
            .iter()
            .find(|s| matches!(s, SsaStmt::Store { .. }))
            .expect("Store should survive");
        assert!(
            matches!(store, SsaStmt::Store { value: SsaExpr::Var(v), .. } if *v == v1),
            "Store should reference v1 after copy propagation"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: pipeline_converges
    // -----------------------------------------------------------------------
    // Diamond CFG with phis. Verify optimize_ssa terminates and does not
    // infinite loop.

    #[test]
    fn pipeline_converges() {
        let v1 = var(0, 1);
        let v2 = var(0, 2);
        let v3 = var(0, 3);
        let flags_var = SsaVar {
            loc: RegLocation::Flags,
            version: 1,
            width: RegWidth::Full,
        };

        //   Block 0 (entry): v1 = Imm(10), condbranch to 1 or 2
        //   Block 1: v2 = Load(Imm(0x1000), 8), branch to 3
        //   Block 2: -- empty, branch to 3
        //   Block 3: v3 = Phi((1, v2), (2, v1)), Store(Imm(0x2000), v3, 8)
        let mut func = SsaFunction {
            entry: 0,
            blocks: vec![
                make_block(
                    0,
                    vec![
                        SsaStmt::Assign {
                            dst: v1,
                            src: SsaExpr::Imm(10),
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
                            src: SsaExpr::Load {
                                addr: Box::new(SsaExpr::Imm(0x1000)),
                                size: 8,
                            },
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
                    vec![SsaStmt::Branch {
                        target: SsaExpr::Imm(3),
                    }],
                    vec![3],
                    vec![0],
                ),
                make_block(
                    3,
                    vec![
                        SsaStmt::Assign {
                            dst: v3,
                            src: SsaExpr::Phi(vec![(1, v2), (2, v1)]),
                        },
                        SsaStmt::Store {
                            addr: SsaExpr::Imm(0x2000),
                            value: SsaExpr::Var(v3),
                            size: 8,
                        },
                    ],
                    vec![],
                    vec![1, 2],
                ),
            ],
        };

        // The main check: this must terminate (no infinite loop)
        optimize_ssa(&mut func);

        // The function should still be well-formed
        assert!(!func.blocks.is_empty(), "function should still have blocks");
        // The Store should survive (it is side-effecting)
        let has_store = func
            .blocks
            .iter()
            .any(|b| b.stmts.iter().any(|s| matches!(s, SsaStmt::Store { .. })));
        assert!(has_store, "Store should survive optimization");
    }

    // -----------------------------------------------------------------------
    // Test 5: pipeline_full_end_to_end
    // -----------------------------------------------------------------------
    // Use reduce_and_build_ssa with a small instruction sequence.

    #[test]
    fn pipeline_full_end_to_end() {
        use aeonil::{Expr, Reg, Stmt};

        // Simple straight-line code:
        //   0x1000: X0 = Imm(100)          edges: [0x1004]
        //   0x1004: X1 = Add(Var(X0), Imm(200))  edges: [0x1008]
        //   0x1008: Store(Imm(0x5000), Var(X1), 8)  edges: [0x100c]
        //   0x100c: Ret                    edges: []
        let instructions: Vec<(u64, Stmt, Vec<u64>)> = vec![
            (
                0x1000,
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Imm(100),
                },
                vec![0x1004],
            ),
            (
                0x1004,
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: Expr::Add(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(200))),
                },
                vec![0x1008],
            ),
            (
                0x1008,
                Stmt::Store {
                    addr: Expr::Imm(0x5000),
                    value: Expr::Reg(Reg::X(1)),
                    size: 8,
                },
                vec![0x100c],
            ),
            (0x100c, Stmt::Ret, vec![]),
        ];

        let ssa_func = reduce_and_build_ssa(&instructions);

        // The function should be well-formed
        assert!(!ssa_func.blocks.is_empty());

        // There should be at least a Store and a Ret surviving
        let has_store = ssa_func
            .blocks
            .iter()
            .any(|b| b.stmts.iter().any(|s| matches!(s, SsaStmt::Store { .. })));
        assert!(has_store, "Store should survive the full pipeline");

        let has_ret = ssa_func
            .blocks
            .iter()
            .any(|b| b.stmts.iter().any(|s| matches!(s, SsaStmt::Ret)));
        assert!(has_ret, "Ret should survive the full pipeline");

        // SCCP should have folded the constant arithmetic:
        // X0 = 100, X1 = 100 + 200 = 300
        // After SCCP/copy-prop the value should appear either as an Assign
        // or directly in the surviving Store.
        let has_folded_const = ssa_func.blocks.iter().any(|b| {
            b.stmts.iter().any(|s| {
                matches!(
                    s,
                    SsaStmt::Assign {
                        src: SsaExpr::Imm(300),
                        ..
                    }
                ) || matches!(
                    s,
                    SsaStmt::Store {
                        value: SsaExpr::Imm(300),
                        ..
                    }
                )
            })
        });
        assert!(has_folded_const, "SCCP should fold 100 + 200 to 300");
    }

    #[test]
    fn pipeline_full_end_to_end_preserves_stack_slots() {
        use aeonil::{e_add, Expr, Reg, Stmt};

        let instructions: Vec<(u64, Stmt, Vec<u64>)> = vec![
            (
                0x1000,
                Stmt::Pair(
                    Box::new(Stmt::Store {
                        addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-16i64) as u64)),
                        value: Expr::Reg(Reg::X(29)),
                        size: 8,
                    }),
                    Box::new(Stmt::Store {
                        addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-8i64) as u64)),
                        value: Expr::Reg(Reg::X(30)),
                        size: 8,
                    }),
                ),
                vec![0x1004],
            ),
            (
                0x1004,
                Stmt::Assign {
                    dst: Reg::X(29),
                    src: Expr::Reg(Reg::SP),
                },
                vec![0x1008],
            ),
            (
                0x1008,
                Stmt::Store {
                    addr: Expr::Imm(0x5000),
                    value: Expr::Load {
                        addr: Box::new(e_add(Expr::Reg(Reg::SP), Expr::Imm(8))),
                        size: 8,
                    },
                    size: 8,
                },
                vec![0x100c],
            ),
            (0x100c, Stmt::Ret, vec![]),
        ];

        let ssa_func = reduce_and_build_ssa(&instructions);
        let has_stack_slot = ssa_func.blocks.iter().any(|block| {
            block.stmts.iter().any(|stmt| {
                matches!(
                    stmt,
                    SsaStmt::Store {
                        value: SsaExpr::Load { addr, size: 8 },
                        size: 8,
                        ..
                    } if matches!(addr.as_ref(), SsaExpr::StackSlot { offset: 8, size: 8 })
                )
            })
        });

        assert!(
            has_stack_slot,
            "reduce_and_build_ssa should preserve stack-slot rewrites into SSA"
        );
    }

    // -----------------------------------------------------------------------
    // Test 6: pipeline_sccp_dead_branch_integration
    // -----------------------------------------------------------------------
    // SCCP resolves a branch condition to a constant, dead_branch eliminates
    // the unreachable path, and DCE removes the dead code.

    #[test]
    fn pipeline_sccp_dead_branch_integration() {
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let v3 = var(2, 1);

        // Block 0: v1 = Imm(5)
        //          CondBranch(Compare(EQ, Imm(5), Imm(5)), target=1, fallthrough=2)
        // Block 1: v2 = Imm(42), Store(0x1000, v2, 8), Ret
        // Block 2: v3 = Imm(99), Store(0x2000, v3, 8), Ret
        //
        // SCCP sees EQ(5,5) = true => branch to block 1
        // dead_branch removes block 2
        let mut func = SsaFunction {
            entry: 0,
            blocks: vec![
                make_block(
                    0,
                    vec![
                        SsaStmt::Assign {
                            dst: v1,
                            src: SsaExpr::Imm(5),
                        },
                        SsaStmt::CondBranch {
                            cond: SsaBranchCond::Compare {
                                cond: aeonil::Condition::EQ,
                                lhs: Box::new(SsaExpr::Imm(5)),
                                rhs: Box::new(SsaExpr::Imm(5)),
                            },
                            target: SsaExpr::Imm(0x100),
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
                            src: SsaExpr::Imm(42),
                        },
                        SsaStmt::Store {
                            addr: SsaExpr::Imm(0x1000),
                            value: SsaExpr::Var(v2),
                            size: 8,
                        },
                        SsaStmt::Ret,
                    ],
                    vec![],
                    vec![0],
                ),
                make_block(
                    2,
                    vec![
                        SsaStmt::Assign {
                            dst: v3,
                            src: SsaExpr::Imm(99),
                        },
                        SsaStmt::Store {
                            addr: SsaExpr::Imm(0x2000),
                            value: SsaExpr::Var(v3),
                            size: 8,
                        },
                        SsaStmt::Ret,
                    ],
                    vec![],
                    vec![0],
                ),
            ],
        };

        optimize_ssa(&mut func);

        // Block 2 should have been removed (unreachable)
        let block_ids: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();
        assert!(
            !block_ids.contains(&2),
            "Block 2 should be eliminated as unreachable after constant branch resolution"
        );

        // v1 should be dead (not used by anything after SCCP folded the branch)
        assert!(
            !func
                .blocks
                .iter()
                .any(|b| b.stmts.iter().any(
                    |s| matches!(s, SsaStmt::Assign { dst, src: SsaExpr::Imm(5) } if *dst == v1)
                )),
            "v1 = Imm(5) should be eliminated by DCE"
        );
    }

    // -----------------------------------------------------------------------
    // Test 7: pipeline_max_iterations_guard
    // -----------------------------------------------------------------------
    // Verify optimize_ssa terminates on a loop CFG.

    #[test]
    fn pipeline_max_iterations_guard() {
        // Block 0 (entry): v1 = Load(Imm(0x1000), 8), Branch to block 1
        // Block 1: v2 = Load(Imm(0x2000), 8), Store(Imm(0x3000), v2, 8)
        //          CondBranch(flag, target=block 1, fallthrough=block 2)
        // Block 2: Ret
        //
        // The loop body has non-constant loads so SCCP won't fold,
        // but the pipeline must still converge and terminate.
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let flags_var = SsaVar {
            loc: RegLocation::Flags,
            version: 1,
            width: RegWidth::Full,
        };

        let mut func = SsaFunction {
            entry: 0,
            blocks: vec![
                make_block(
                    0,
                    vec![
                        SsaStmt::Assign {
                            dst: v1,
                            src: SsaExpr::Load {
                                addr: Box::new(SsaExpr::Imm(0x1000)),
                                size: 8,
                            },
                        },
                        SsaStmt::Branch {
                            target: SsaExpr::Imm(1),
                        },
                    ],
                    vec![1],
                    vec![],
                ),
                make_block(
                    1,
                    vec![
                        SsaStmt::Assign {
                            dst: v2,
                            src: SsaExpr::Load {
                                addr: Box::new(SsaExpr::Imm(0x2000)),
                                size: 8,
                            },
                        },
                        SsaStmt::Store {
                            addr: SsaExpr::Imm(0x3000),
                            value: SsaExpr::Var(v2),
                            size: 8,
                        },
                        SsaStmt::CondBranch {
                            cond: SsaBranchCond::Flag(aeonil::Condition::NE, flags_var),
                            target: SsaExpr::Imm(1),
                            fallthrough: 2,
                        },
                    ],
                    vec![1, 2],
                    vec![0, 1],
                ),
                make_block(2, vec![SsaStmt::Ret], vec![], vec![1]),
            ],
        };

        // Must terminate within MAX_ITERATIONS
        optimize_ssa(&mut func);

        // Just verify it didn't panic or hang
        assert!(!func.blocks.is_empty());
    }
}
