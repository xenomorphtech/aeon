//! Constant folding -- evaluates pure arithmetic/logic `Expr` nodes whose
//! operands are all `Expr::Imm` at compile time, replacing the tree with a
//! single `Expr::Imm`.  Also applies identity and annihilation rules.

use aeonil::{BranchCond, Expr, Stmt};

/// Recursively fold constant expressions within an expression tree.
pub fn fold_expr(expr: &Expr) -> Expr {
    // First, recursively fold all sub-expressions
    let folded = expr.map_subexprs(|e| fold_expr(e));

    // Then try to simplify the folded result
    match &folded {
        // --- Binary constant folding ---
        Expr::Add(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => Expr::Imm(a.wrapping_add(*b)),
            // Identity: x + 0 = x, 0 + x = x
            (_, Expr::Imm(0)) => *a.clone(),
            (Expr::Imm(0), _) => *b.clone(),
            _ => folded,
        },
        Expr::Sub(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => Expr::Imm(a.wrapping_sub(*b)),
            // Identity: x - 0 = x
            (_, Expr::Imm(0)) => *a.clone(),
            _ => folded,
        },
        Expr::Mul(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => Expr::Imm(a.wrapping_mul(*b)),
            // Annihilation: x * 0 = 0
            (_, Expr::Imm(0)) | (Expr::Imm(0), _) => Expr::Imm(0),
            // Identity: x * 1 = x, 1 * x = x
            (_, Expr::Imm(1)) => *a.clone(),
            (Expr::Imm(1), _) => *b.clone(),
            _ => folded,
        },
        Expr::Div(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) if *b != 0 => Expr::Imm(a.wrapping_div(*b)),
            _ => folded,
        },
        Expr::UDiv(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) if *b != 0 => Expr::Imm(a.wrapping_div(*b)),
            _ => folded,
        },
        Expr::And(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => Expr::Imm(a & b),
            // Identity: x & MAX = x
            (_, Expr::Imm(v)) if *v == u64::MAX => *a.clone(),
            (Expr::Imm(v), _) if *v == u64::MAX => *b.clone(),
            _ => folded,
        },
        Expr::Or(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => Expr::Imm(a | b),
            // Identity: x | 0 = x
            (_, Expr::Imm(0)) => *a.clone(),
            (Expr::Imm(0), _) => *b.clone(),
            _ => folded,
        },
        Expr::Xor(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => Expr::Imm(a ^ b),
            // Identity: x ^ 0 = x
            (_, Expr::Imm(0)) => *a.clone(),
            (Expr::Imm(0), _) => *b.clone(),
            _ => folded,
        },

        // --- Unary constant folding ---
        Expr::Not(a) => match a.as_ref() {
            Expr::Imm(a) => Expr::Imm(!a),
            _ => folded,
        },
        Expr::Neg(a) => match a.as_ref() {
            Expr::Imm(a) => Expr::Imm(a.wrapping_neg()),
            _ => folded,
        },

        // --- Shifts ---
        Expr::Shl(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => {
                if *b < 64 {
                    Expr::Imm(a.wrapping_shl(*b as u32))
                } else {
                    Expr::Imm(0)
                }
            }
            _ => folded,
        },
        Expr::Lsr(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => {
                if *b < 64 {
                    Expr::Imm(a.wrapping_shr(*b as u32))
                } else {
                    Expr::Imm(0)
                }
            }
            _ => folded,
        },
        Expr::Asr(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => {
                if *b < 64 {
                    Expr::Imm((*a as i64).wrapping_shr(*b as u32) as u64)
                } else {
                    // Arithmetic shift: all sign bits
                    Expr::Imm((*a as i64).wrapping_shr(63) as u64)
                }
            }
            _ => folded,
        },
        Expr::Ror(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => {
                let shift = (*b % 64) as u32;
                Expr::Imm(a.rotate_right(shift))
            }
            _ => folded,
        },

        // Everything else: already recursively folded by map_subexprs
        _ => folded,
    }
}

/// Fold expressions inside a `BranchCond`.
fn fold_branch_cond(cond: BranchCond) -> BranchCond {
    match cond {
        BranchCond::Flag(c) => BranchCond::Flag(c),
        BranchCond::Zero(e) => BranchCond::Zero(fold_expr(&e)),
        BranchCond::NotZero(e) => BranchCond::NotZero(fold_expr(&e)),
        BranchCond::BitZero(e, bit) => BranchCond::BitZero(fold_expr(&e), bit),
        BranchCond::BitNotZero(e, bit) => BranchCond::BitNotZero(fold_expr(&e), bit),
        BranchCond::Compare { cond, lhs, rhs } => BranchCond::Compare {
            cond,
            lhs: Box::new(fold_expr(&lhs)),
            rhs: Box::new(fold_expr(&rhs)),
        },
    }
}

/// Apply constant folding to a single statement.
fn fold_stmt(stmt: Stmt) -> Stmt {
    match stmt {
        Stmt::Assign { dst, src } => Stmt::Assign {
            dst,
            src: fold_expr(&src),
        },
        Stmt::Store { addr, value, size } => Stmt::Store {
            addr: fold_expr(&addr),
            value: fold_expr(&value),
            size,
        },
        Stmt::SetFlags { expr } => Stmt::SetFlags {
            expr: fold_expr(&expr),
        },
        Stmt::CondBranch {
            cond,
            target,
            fallthrough,
        } => Stmt::CondBranch {
            cond: fold_branch_cond(cond),
            target: fold_expr(&target),
            fallthrough,
        },
        Stmt::Branch { target } => Stmt::Branch {
            target: fold_expr(&target),
        },
        Stmt::Call { target } => Stmt::Call {
            target: fold_expr(&target),
        },
        Stmt::Pair(a, b) => Stmt::Pair(Box::new(fold_stmt(*a)), Box::new(fold_stmt(*b))),
        Stmt::Intrinsic { name, operands } => Stmt::Intrinsic {
            name,
            operands: operands.iter().map(|e| fold_expr(e)).collect(),
        },
        // Ret, Nop, Barrier, Trap: pass through unchanged
        other => other,
    }
}

/// Apply constant folding to all expressions within each statement.
pub fn fold_constants(stmts: Vec<Stmt>) -> Vec<Stmt> {
    stmts.into_iter().map(fold_stmt).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, e_and, e_lsr, e_mul, e_or, e_shl, e_sub, e_xor, Expr, Reg, Stmt};

    #[test]
    fn fold_add_imm() {
        let expr = e_add(Expr::Imm(3), Expr::Imm(5));
        assert_eq!(fold_expr(&expr), Expr::Imm(8));
    }

    #[test]
    fn fold_sub_imm() {
        let expr = e_sub(Expr::Imm(10), Expr::Imm(3));
        assert_eq!(fold_expr(&expr), Expr::Imm(7));
    }

    #[test]
    fn fold_shl_imm() {
        let expr = e_shl(Expr::Imm(1), Expr::Imm(16));
        assert_eq!(fold_expr(&expr), Expr::Imm(0x10000));
    }

    #[test]
    fn fold_lsr_imm() {
        let expr = e_lsr(Expr::Imm(0x10000), Expr::Imm(16));
        assert_eq!(fold_expr(&expr), Expr::Imm(1));
    }

    #[test]
    fn fold_and_imm() {
        let expr = e_and(Expr::Imm(0xFF), Expr::Imm(0x0F));
        assert_eq!(fold_expr(&expr), Expr::Imm(0x0F));
    }

    #[test]
    fn fold_or_imm() {
        let expr = e_or(Expr::Imm(0xF0), Expr::Imm(0x0F));
        assert_eq!(fold_expr(&expr), Expr::Imm(0xFF));
    }

    #[test]
    fn fold_xor_self() {
        let expr = e_xor(Expr::Imm(0xFF), Expr::Imm(0xFF));
        assert_eq!(fold_expr(&expr), Expr::Imm(0));
    }

    #[test]
    fn fold_nested() {
        // Add(Imm(1), Sub(Imm(5), Imm(2))) => Imm(4)
        let expr = e_add(Expr::Imm(1), e_sub(Expr::Imm(5), Expr::Imm(2)));
        assert_eq!(fold_expr(&expr), Expr::Imm(4));
    }

    #[test]
    fn fold_in_assign() {
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(0),
            src: e_add(Expr::Imm(1), Expr::Imm(2)),
        }];
        let result = fold_constants(stmts);
        assert_eq!(
            result,
            vec![Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(3),
            }]
        );
    }

    #[test]
    fn fold_in_store_addr() {
        let stmts = vec![Stmt::Store {
            addr: e_add(Expr::Imm(0x1000), Expr::Imm(0x20)),
            value: Expr::Reg(Reg::X(1)),
            size: 8,
        }];
        let result = fold_constants(stmts);
        assert_eq!(
            result,
            vec![Stmt::Store {
                addr: Expr::Imm(0x1020),
                value: Expr::Reg(Reg::X(1)),
                size: 8,
            }]
        );
    }

    #[test]
    fn identity_add_zero() {
        let expr = e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0));
        assert_eq!(fold_expr(&expr), Expr::Reg(Reg::X(0)));
    }

    #[test]
    fn identity_mul_one() {
        let expr = e_mul(Expr::Reg(Reg::X(0)), Expr::Imm(1));
        assert_eq!(fold_expr(&expr), Expr::Reg(Reg::X(0)));
    }

    #[test]
    fn annihilate_mul_zero() {
        let expr = e_mul(Expr::Reg(Reg::X(0)), Expr::Imm(0));
        assert_eq!(fold_expr(&expr), Expr::Imm(0));
    }

    #[test]
    fn no_fold_reg() {
        let expr = e_add(Expr::Reg(Reg::X(0)), Expr::Imm(5));
        assert_eq!(fold_expr(&expr), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(5)));
    }

    #[test]
    fn wrap_u64_overflow() {
        let expr = e_add(Expr::Imm(u64::MAX), Expr::Imm(1));
        assert_eq!(fold_expr(&expr), Expr::Imm(0));
    }
}
