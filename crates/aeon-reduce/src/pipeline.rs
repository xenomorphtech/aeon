//! Reduction pipeline -- sequences the individual peephole passes (const,
//! adrp, movk, pair, flags, ext) in the correct order for intra-block
//! reduction.

use aeonil::Stmt;

use crate::reduce_adrp::resolve_adrp_add;
use crate::reduce_const::fold_constants;
use crate::reduce_ext::fold_extensions;
use crate::reduce_flags::{eliminate_dead_flags, fuse_flags};
use crate::reduce_movk::resolve_movk_chains;
use crate::reduce_pair::flatten_pairs;
use crate::reduce_stack::{detect_prologue, recognize_stack_frame, rewrite_stack_accesses};
use crate::ssa::cfg::{build_cfg, Cfg};

/// Apply only the block-local reductions.
pub fn reduce_block_local(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let stmts = flatten_pairs(stmts); // 1. structural
    let stmts = fold_constants(stmts); // 2. expression-level
    let stmts = resolve_adrp_add(stmts); // 3. multi-stmt, RegisterEnv
    let stmts = resolve_movk_chains(stmts); // 4. multi-stmt, RegisterEnv
    let stmts = fold_constants(stmts); // 5. again (ADRP/MOVK may produce foldable exprs)
    let stmts = fuse_flags(stmts); // 6. multi-stmt, flag tracking
    let stmts = eliminate_dead_flags(stmts); // 7. liveness
    let stmts = fold_extensions(stmts); // 8. expression-level
    stmts
}

/// Apply the historical single-block pipeline, including immediate stack-frame
/// recognition when the block contains the full prologue context.
pub fn reduce_block(stmts: Vec<Stmt>) -> Vec<Stmt> {
    recognize_stack_frame(reduce_block_local(stmts))
}

/// Apply the canonical function-level reduction pipeline to a lifted function.
///
/// This is the shared path that should feed SSA, API serialization, evaluation,
/// and future fact extraction. Block-local passes still run per block, but
/// stack-slot rewriting uses one shared prologue from the function entry.
pub fn reduce_function_cfg(instructions: &[(u64, Stmt, Vec<u64>)]) -> Cfg {
    let mut cfg = build_cfg(instructions);

    for block in &mut cfg.blocks {
        block.stmts = reduce_block_local(std::mem::take(&mut block.stmts));
    }

    let prologue = cfg
        .blocks
        .get(cfg.entry as usize)
        .and_then(|entry| detect_prologue(&entry.stmts));

    if let Some(prologue) = prologue.as_ref() {
        for block in &mut cfg.blocks {
            block.stmts = rewrite_stack_accesses(std::mem::take(&mut block.stmts), prologue);
        }
    }

    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, e_load, Expr, Reg};

    #[test]
    fn pipeline_identity() {
        let input = vec![
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(42),
            },
            Stmt::Ret,
        ];
        let result = reduce_block(input.clone());
        assert_eq!(result, input);
    }

    #[test]
    fn pipeline_composes() {
        // Pair(Assign(X(0), Add(Imm(1), Imm(2))), Assign(X(1), Imm(3)))
        // => flatten pair, then constant fold Add(1,2) -> 3
        // => [Assign(X(0), Imm(3)), Assign(X(1), Imm(3))]
        let input = vec![Stmt::Pair(
            Box::new(Stmt::Assign {
                dst: Reg::X(0),
                src: e_add(Expr::Imm(1), Expr::Imm(2)),
            }),
            Box::new(Stmt::Assign {
                dst: Reg::X(1),
                src: Expr::Imm(3),
            }),
        )];
        let result = reduce_block(input);
        assert_eq!(
            result,
            vec![
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Imm(3),
                },
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: Expr::Imm(3),
                },
            ]
        );
    }

    #[test]
    fn pipeline_recognizes_stack_frame_in_single_block() {
        let input = vec![
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
            Stmt::Assign {
                dst: Reg::X(29),
                src: Expr::Reg(Reg::SP),
            },
            Stmt::Assign {
                dst: Reg::X(0),
                src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
            },
        ];

        let result = reduce_block(input);
        assert_eq!(result.len(), 4);
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
            result[3],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Load {
                    addr: Box::new(Expr::StackSlot { offset: 8, size: 8 }),
                    size: 8,
                },
            }
        );
    }

    #[test]
    fn reduce_function_cfg_rewrites_stack_accesses_across_blocks() {
        let instructions = vec![
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
                Stmt::CondBranch {
                    cond: aeonil::BranchCond::Zero(Expr::Imm(0)),
                    target: Expr::Imm(0x1010),
                    fallthrough: 0x1014,
                },
                vec![0x1010, 0x1014],
            ),
            (
                0x1010,
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
                },
                vec![0x1014],
            ),
            (0x1014, Stmt::Ret, vec![]),
        ];

        let cfg = reduce_function_cfg(&instructions);
        let load_block = cfg
            .blocks
            .iter()
            .find(|block| block.addr == 0x1010)
            .expect("missing load block");
        assert_eq!(
            load_block.stmts[0],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Load {
                    addr: Box::new(Expr::StackSlot { offset: 8, size: 8 }),
                    size: 8,
                },
            }
        );
    }
}
