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

/// Apply all intra-block reductions in the correct order.
pub fn reduce_block(stmts: Vec<Stmt>) -> Vec<Stmt> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, Expr, Reg};

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
}
