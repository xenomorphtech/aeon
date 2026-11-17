// Integration tests for aeon-reduce.
//
// Tests here exercise the full reduction pipeline on small AeonIL function
// snippets that model realistic ARM64 instruction sequences.

use aeon_reduce::pipeline::{reduce_block, reduce_function_cfg};
use aeonil::*;

// ---- Test 1: ADRP + ADD + LDR ----

#[test]
fn real_adrp_add_ldr() {
    // Simulates: ADRP X8, page; ADD X8, X8, #off; LDR X0, [X8]
    let input = vec![
        Stmt::Assign {
            dst: Reg::X(8),
            src: Expr::AdrpImm(0x412000),
        },
        Stmt::Assign {
            dst: Reg::X(8),
            src: e_add(Expr::Reg(Reg::X(8)), Expr::Imm(0x340)),
        },
        Stmt::Assign {
            dst: Reg::X(0),
            src: e_load(Expr::Reg(Reg::X(8)), 8),
        },
    ];
    let result = reduce_block(input);
    assert_eq!(result.len(), 3);
    // X8 should be resolved to Imm(0x412340)
    assert_eq!(
        result[1],
        Stmt::Assign {
            dst: Reg::X(8),
            src: Expr::Imm(0x412340),
        }
    );
    // X0 load should use the resolved address: Load(Imm(0x412340), 8)
    assert_eq!(
        result[2],
        Stmt::Assign {
            dst: Reg::X(0),
            src: e_load(Expr::Imm(0x412340), 8),
        }
    );
}

// ---- Test 2: CMP + B.NE ----

#[test]
fn real_cmp_bne() {
    // Simulates: CMP W8, #1; B.NE target
    let input = vec![
        Stmt::SetFlags {
            expr: e_sub(Expr::Reg(Reg::W(8)), Expr::Imm(1)),
        },
        Stmt::CondBranch {
            cond: BranchCond::Flag(Condition::NE),
            target: Expr::Imm(0x1000),
            fallthrough: 0x104,
        },
    ];
    let result = reduce_block(input.clone());
    // The branch becomes a comparison. The compare itself stays: a block
    // cannot tell whether a later block reads its flags.
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], input[0]);
    assert_eq!(
        result[1],
        Stmt::CondBranch {
            cond: BranchCond::Compare {
                cond: Condition::NE,
                lhs: Box::new(Expr::Reg(Reg::W(8))),
                rhs: Box::new(Expr::Imm(1)),
            },
            target: Expr::Imm(0x1000),
            fallthrough: 0x104,
        }
    );
}

// ---- Test 2b: the same compare, where the whole function is known ----

#[test]
fn function_level_reduction_drops_a_compare_nothing_reads() {
    // 0x100: CMP W8, #1
    // 0x104: B.NE 0x10c
    // 0x108: MOV X0, #1
    // 0x10c: RET
    let instructions = vec![
        (
            0x100,
            Stmt::SetFlags {
                expr: e_sub(Expr::Reg(Reg::W(8)), Expr::Imm(1)),
            },
            vec![0x104],
        ),
        (
            0x104,
            Stmt::CondBranch {
                cond: BranchCond::Flag(Condition::NE),
                target: Expr::Imm(0x10c),
                fallthrough: 0x108,
            },
            vec![0x10c, 0x108],
        ),
        (
            0x108,
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(1),
            },
            vec![0x10c],
        ),
        (0x10c, Stmt::Ret, vec![]),
    ];
    let cfg = reduce_function_cfg(&instructions);
    let entry = &cfg.blocks[cfg.entry as usize];
    assert_eq!(
        entry.stmts,
        vec![Stmt::CondBranch {
            cond: BranchCond::Compare {
                cond: Condition::NE,
                lhs: Box::new(Expr::Reg(Reg::W(8))),
                rhs: Box::new(Expr::Imm(1)),
            },
            target: Expr::Imm(0x10c),
            fallthrough: 0x108,
        }]
    );
}

#[test]
fn function_level_reduction_keeps_a_compare_a_later_block_reads() {
    // 0x100: CMP W8, #1
    // 0x104: CBZ X1, 0x10c
    // 0x108: MOV X0, #1
    // 0x10c: CSET X2, EQ
    // 0x110: RET
    let cmp = Stmt::SetFlags {
        expr: e_sub(Expr::Reg(Reg::W(8)), Expr::Imm(1)),
    };
    let instructions = vec![
        (0x100, cmp.clone(), vec![0x104]),
        (
            0x104,
            Stmt::CondBranch {
                cond: BranchCond::Zero(Expr::Reg(Reg::X(1))),
                target: Expr::Imm(0x10c),
                fallthrough: 0x108,
            },
            vec![0x10c, 0x108],
        ),
        (
            0x108,
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(1),
            },
            vec![0x10c],
        ),
        (
            0x10c,
            Stmt::Assign {
                dst: Reg::X(2),
                src: e_cond_select(Condition::EQ, Expr::Imm(1), Expr::Imm(0)),
            },
            vec![0x110],
        ),
        (0x110, Stmt::Ret, vec![]),
    ];
    let cfg = reduce_function_cfg(&instructions);
    let entry = &cfg.blocks[cfg.entry as usize];
    assert_eq!(entry.stmts.first(), Some(&cmp));
}

// ---- Test 3: MOVZ + 3x MOVK (64-bit constant) ----

#[test]
fn real_movz_movk_4step() {
    // Simulates building 0xDEADBEEFCAFEBABE across 4 instructions.
    let input = vec![
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(0xBABE),
        }, // MOVZ
        Stmt::Assign {
            dst: Reg::X(0),
            src: e_insert(Expr::Reg(Reg::X(0)), Expr::Imm(0xCAFE), 16, 16),
        },
        Stmt::Assign {
            dst: Reg::X(0),
            src: e_insert(Expr::Reg(Reg::X(0)), Expr::Imm(0xBEEF), 32, 16),
        },
        Stmt::Assign {
            dst: Reg::X(0),
            src: e_insert(Expr::Reg(Reg::X(0)), Expr::Imm(0xDEAD), 48, 16),
        },
    ];
    let result = reduce_block(input);
    // Should resolve to a single final Assign(X(0), Imm(0xDEADBEEFCAFEBABE))
    assert_eq!(result.len(), 4);
    assert_eq!(
        result[3],
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(0xDEADBEEFCAFEBABE),
        }
    );
}

// ---- Test 4: LDP + CMP + B.LT ----

#[test]
fn real_ldp_cmp_bcc() {
    // Simulates: LDP X0,X1,[SP]; CMP X0,X1; B.LT target
    let input = vec![
        Stmt::Pair(
            Box::new(Stmt::Assign {
                dst: Reg::X(0),
                src: e_load(Expr::Reg(Reg::SP), 8),
            }),
            Box::new(Stmt::Assign {
                dst: Reg::X(1),
                src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
            }),
        ),
        Stmt::SetFlags {
            expr: e_sub(Expr::Reg(Reg::X(0)), Expr::Reg(Reg::X(1))),
        },
        Stmt::CondBranch {
            cond: BranchCond::Flag(Condition::LT),
            target: Expr::Imm(0x2000),
            fallthrough: 0x204,
        },
    ];
    let result = reduce_block(input.clone());
    // Pair flattened to 2 assigns, then the compare and the fused branch.
    assert_eq!(result.len(), 4);
    assert_eq!(result[2], input[1]);
    // First two are the flattened loads
    assert_eq!(
        result[0],
        Stmt::Assign {
            dst: Reg::X(0),
            src: e_load(Expr::Reg(Reg::SP), 8),
        }
    );
    assert_eq!(
        result[1],
        Stmt::Assign {
            dst: Reg::X(1),
            src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
        }
    );
    // Last is the fused compare-and-branch. It compares the registers: the
    // loads are not repeated, since memory may have changed in between.
    assert_eq!(
        result[3],
        Stmt::CondBranch {
            cond: BranchCond::Compare {
                cond: Condition::LT,
                lhs: Box::new(Expr::Reg(Reg::X(0))),
                rhs: Box::new(Expr::Reg(Reg::X(1))),
            },
            target: Expr::Imm(0x2000),
            fallthrough: 0x204,
        }
    );
}

// ---- Test 5: STP (function prologue) ----

#[test]
fn real_function_prologue() {
    // Simulates: STP X29,X30,[SP,#-16]!; MOV X29,SP
    let input = vec![
        Stmt::Pair(
            Box::new(Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm(0xFFFFFFFFFFFFFFF0)), // SP-16
                value: Expr::Reg(Reg::X(29)),
                size: 8,
            }),
            Box::new(Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm(0xFFFFFFFFFFFFFFF8)), // SP-8
                value: Expr::Reg(Reg::X(30)),
                size: 8,
            }),
        ),
        Stmt::Assign {
            dst: Reg::X(29),
            src: Expr::Reg(Reg::SP),
        },
    ];
    let result = reduce_block(input);
    // Pair flattened to 2 stores + 1 assign = 3 statements
    assert_eq!(result.len(), 3);
    assert_eq!(
        result[0],
        Stmt::Store {
            addr: Expr::StackSlot {
                offset: -16,
                size: 8,
            },
            value: Expr::Reg(Reg::X(29)),
            size: 8,
        }
    );
    assert_eq!(
        result[1],
        Stmt::Store {
            addr: Expr::StackSlot {
                offset: -8,
                size: 8
            },
            value: Expr::Reg(Reg::X(30)),
            size: 8,
        }
    );
    assert_eq!(
        result[2],
        Stmt::Assign {
            dst: Reg::X(29),
            src: Expr::Reg(Reg::SP),
        }
    );
}

// ---- Test 6: dead flags before CBZ ----

#[test]
fn dead_flags_before_cbz() {
    // Simulates: CMP W0, #5; CMP W0, #6; CBZ W1, target. The first compare
    // is overwritten before anything reads it. The second stays: CBZ does not
    // read flags, but the code after this block might.
    let input = vec![
        Stmt::SetFlags {
            expr: e_sub(Expr::Reg(Reg::W(0)), Expr::Imm(5)),
        },
        Stmt::SetFlags {
            expr: e_sub(Expr::Reg(Reg::W(0)), Expr::Imm(6)),
        },
        Stmt::CondBranch {
            cond: BranchCond::Zero(Expr::Reg(Reg::W(1))),
            target: Expr::Imm(0x3000),
            fallthrough: 0x304,
        },
    ];
    let result = reduce_block(input.clone());
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], input[1]);
    assert_eq!(
        result[1],
        Stmt::CondBranch {
            cond: BranchCond::Zero(Expr::Reg(Reg::W(1))),
            target: Expr::Imm(0x3000),
            fallthrough: 0x304,
        }
    );
}

// ---- Test 7: a branch decided by constants ----

#[test]
fn ssa_optimisation_survives_removing_a_block_in_the_middle() {
    // 0x100: MOV X0, #5
    // 0x104: CMP X0, #5
    // 0x108: B.EQ 0x114
    // 0x10c: MOV X1, #1        (never reached)
    // 0x110: B 0x114
    // 0x114: MOV X2, #2
    // 0x118: RET
    //
    // The compare is decidable, so the SSA passes delete the middle block
    // and then run again over the blocks that are left.
    let assign = |dst, value| Stmt::Assign {
        dst,
        src: Expr::Imm(value),
    };
    let instructions = vec![
        (0x100, assign(Reg::X(0), 5), vec![0x104]),
        (
            0x104,
            Stmt::SetFlags {
                expr: e_sub(Expr::Reg(Reg::X(0)), Expr::Imm(5)),
            },
            vec![0x108],
        ),
        (
            0x108,
            Stmt::CondBranch {
                cond: BranchCond::Flag(Condition::EQ),
                target: Expr::Imm(0x114),
                fallthrough: 0x10c,
            },
            vec![0x114, 0x10c],
        ),
        (0x10c, assign(Reg::X(1), 1), vec![0x110]),
        (
            0x110,
            Stmt::Branch {
                target: Expr::Imm(0x114),
            },
            vec![0x114],
        ),
        (0x114, assign(Reg::X(2), 2), vec![0x118]),
        (0x118, Stmt::Ret, vec![]),
    ];

    // The compare keeps its operator: `5 - 5` must not become a literal
    // NZCV of 0, which would read as "not equal".
    let cfg = reduce_function_cfg(&instructions);
    let entry = &cfg.blocks[cfg.entry as usize];
    assert_eq!(
        entry.stmts.last(),
        Some(&Stmt::CondBranch {
            cond: BranchCond::Compare {
                cond: Condition::EQ,
                lhs: Box::new(Expr::Imm(5)),
                rhs: Box::new(Expr::Imm(5)),
            },
            target: Expr::Imm(0x114),
            fallthrough: 0x10c,
        })
    );

    let ssa = aeon_reduce::ssa::pipeline::reduce_and_build_ssa(&instructions);
    let addrs: Vec<u64> = ssa.blocks.iter().map(|block| block.addr).collect();
    assert_eq!(addrs, vec![0x100, 0x114]);
    for (index, block) in ssa.blocks.iter().enumerate() {
        assert_eq!(block.id as usize, index);
    }
}
