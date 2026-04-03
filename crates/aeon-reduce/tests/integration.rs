// Integration tests for aeon-reduce.
//
// Tests here exercise the full reduction pipeline on small AeonIL function
// snippets that model realistic ARM64 instruction sequences.

use aeon_reduce::pipeline::reduce_block;
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
    let result = reduce_block(input);
    assert_eq!(result.len(), 1);
    // Should be a single CondBranch with BranchCond::Compare
    assert_eq!(
        result[0],
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
            src: e_intrinsic("movk", vec![Expr::Reg(Reg::X(0)), Expr::Imm(0xCAFE0000)]),
        },
        Stmt::Assign {
            dst: Reg::X(0),
            src: e_intrinsic(
                "movk",
                vec![Expr::Reg(Reg::X(0)), Expr::Imm(0xBEEF00000000)],
            ),
        },
        Stmt::Assign {
            dst: Reg::X(0),
            src: e_intrinsic(
                "movk",
                vec![Expr::Reg(Reg::X(0)), Expr::Imm(0xDEAD000000000000)],
            ),
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
    let result = reduce_block(input);
    // Pair flattened to 2 assigns, SetFlags+CondBranch fused into 1
    assert_eq!(result.len(), 3); // 2 assigns + 1 fused CondBranch
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
    // Third is the fused compare-and-branch.
    // The ADRP/register-resolution pass substitutes known register values into
    // the SetFlags expression before fusion, so the Compare operands carry the
    // resolved Load expressions rather than bare Reg references.
    assert_eq!(
        result[2],
        Stmt::CondBranch {
            cond: BranchCond::Compare {
                cond: Condition::LT,
                lhs: Box::new(e_load(Expr::Reg(Reg::SP), 8)),
                rhs: Box::new(e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8)),
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
    // Simulates: CMP W0, #5; CBZ W1, target (CBZ doesn't use flags -> SetFlags is dead)
    let input = vec![
        Stmt::SetFlags {
            expr: e_sub(Expr::Reg(Reg::W(0)), Expr::Imm(5)),
        },
        Stmt::CondBranch {
            cond: BranchCond::Zero(Expr::Reg(Reg::W(1))),
            target: Expr::Imm(0x3000),
            fallthrough: 0x304,
        },
    ];
    let result = reduce_block(input);
    assert_eq!(result.len(), 1); // SetFlags eliminated, only CBZ remains
    assert_eq!(
        result[0],
        Stmt::CondBranch {
            cond: BranchCond::Zero(Expr::Reg(Reg::W(1))),
            target: Expr::Imm(0x3000),
            fallthrough: 0x304,
        }
    );
}
