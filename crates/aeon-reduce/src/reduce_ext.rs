//! Extension elimination -- removes redundant sign/zero extensions when the
//! source value is already narrower than the target width, or when the result
//! is immediately truncated.  Handles W-register to X-register promotions.

use aeonil::{BranchCond, Expr, Stmt};

/// Recursively fold redundant or constant sign/zero extensions within an
/// expression tree (bottom-up).
pub fn fold_extension(expr: &Expr) -> Expr {
    // First, recursively fold all sub-expressions
    let folded = expr.map_subexprs(|e| fold_extension(e));

    match &folded {
        // Rule 5: Extension with from_bits >= 64 is a no-op
        Expr::ZeroExtend { src, from_bits } if *from_bits >= 64 => *src.clone(),
        Expr::SignExtend { src, from_bits } if *from_bits >= 64 => *src.clone(),

        // Rule 1: ZeroExtend(ZeroExtend(x, inner), outer)
        //   If inner <= outer, the inner extension is the bottleneck.
        Expr::ZeroExtend {
            src,
            from_bits: outer_bits,
        } => match src.as_ref() {
            Expr::ZeroExtend {
                src: inner_src,
                from_bits: inner_bits,
            } if *inner_bits <= *outer_bits => Expr::ZeroExtend {
                src: inner_src.clone(),
                from_bits: *inner_bits,
            },
            // Rule 3: ZeroExtend(Imm(val), from_bits)
            Expr::Imm(val) => {
                let bits = *outer_bits;
                if bits >= 64 {
                    Expr::Imm(*val)
                } else {
                    let mask = (1u64 << bits) - 1;
                    Expr::Imm(val & mask)
                }
            }
            _ => folded,
        },

        // Rule 2: SignExtend(SignExtend(x, inner), outer)
        Expr::SignExtend {
            src,
            from_bits: outer_bits,
        } => match src.as_ref() {
            Expr::SignExtend {
                src: inner_src,
                from_bits: inner_bits,
            } if *inner_bits <= *outer_bits => Expr::SignExtend {
                src: inner_src.clone(),
                from_bits: *inner_bits,
            },
            // Rule 4: SignExtend(Imm(val), from_bits)
            Expr::Imm(val) => {
                let bits = *outer_bits;
                if bits >= 64 {
                    Expr::Imm(*val)
                } else {
                    let mask = (1u64 << bits) - 1;
                    let sign_bit = 1u64 << (bits - 1);
                    let truncated = val & mask;
                    if truncated & sign_bit != 0 {
                        Expr::Imm(truncated | !mask) // sign-extend with 1s
                    } else {
                        Expr::Imm(truncated) // sign-extend with 0s
                    }
                }
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
        BranchCond::Zero(e) => BranchCond::Zero(fold_extension(&e)),
        BranchCond::NotZero(e) => BranchCond::NotZero(fold_extension(&e)),
        BranchCond::BitZero(e, bit) => BranchCond::BitZero(fold_extension(&e), bit),
        BranchCond::BitNotZero(e, bit) => BranchCond::BitNotZero(fold_extension(&e), bit),
        BranchCond::Compare { cond, lhs, rhs } => BranchCond::Compare {
            cond,
            lhs: Box::new(fold_extension(&lhs)),
            rhs: Box::new(fold_extension(&rhs)),
        },
    }
}

/// Apply extension folding to a single statement.
fn fold_stmt(stmt: Stmt) -> Stmt {
    match stmt {
        Stmt::Assign { dst, src } => Stmt::Assign {
            dst,
            src: fold_extension(&src),
        },
        Stmt::Store { addr, value, size } => Stmt::Store {
            addr: fold_extension(&addr),
            value: fold_extension(&value),
            size,
        },
        Stmt::SetFlags { expr } => Stmt::SetFlags {
            expr: fold_extension(&expr),
        },
        Stmt::CondBranch {
            cond,
            target,
            fallthrough,
        } => Stmt::CondBranch {
            cond: fold_branch_cond(cond),
            target: fold_extension(&target),
            fallthrough,
        },
        Stmt::Branch { target } => Stmt::Branch {
            target: fold_extension(&target),
        },
        Stmt::Call { target } => Stmt::Call {
            target: fold_extension(&target),
        },
        Stmt::Pair(a, b) => Stmt::Pair(Box::new(fold_stmt(*a)), Box::new(fold_stmt(*b))),
        Stmt::Intrinsic { name, operands } => Stmt::Intrinsic {
            name,
            operands: operands.iter().map(|e| fold_extension(e)).collect(),
        },
        // Ret, Nop, Barrier, Trap: pass through unchanged
        other => other,
    }
}

/// Apply extension folding to all expressions within each statement.
pub fn fold_extensions(stmts: Vec<Stmt>) -> Vec<Stmt> {
    stmts.into_iter().map(fold_stmt).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_sign_extend, e_zero_extend, Expr, Reg, Stmt};

    #[test]
    fn zext_of_zext() {
        // ZeroExtend(ZeroExtend(Reg(X(0)), 8), 16) => ZeroExtend(Reg(X(0)), 8)
        let expr = e_zero_extend(e_zero_extend(Expr::Reg(Reg::X(0)), 8), 16);
        assert_eq!(
            fold_extension(&expr),
            e_zero_extend(Expr::Reg(Reg::X(0)), 8)
        );
    }

    #[test]
    fn sext_of_sext() {
        // SignExtend(SignExtend(Reg(X(0)), 8), 16) => SignExtend(Reg(X(0)), 8)
        let expr = e_sign_extend(e_sign_extend(Expr::Reg(Reg::X(0)), 8), 16);
        assert_eq!(
            fold_extension(&expr),
            e_sign_extend(Expr::Reg(Reg::X(0)), 8)
        );
    }

    #[test]
    fn zext_of_imm_truncates() {
        // ZeroExtend(Imm(0x1FF), 8) => Imm(0xFF)
        let expr = e_zero_extend(Expr::Imm(0x1FF), 8);
        assert_eq!(fold_extension(&expr), Expr::Imm(0xFF));
    }

    #[test]
    fn zext_of_imm_fits() {
        // ZeroExtend(Imm(0xFF), 8) => Imm(0xFF)
        let expr = e_zero_extend(Expr::Imm(0xFF), 8);
        assert_eq!(fold_extension(&expr), Expr::Imm(0xFF));
    }

    #[test]
    fn sext_of_imm_negative() {
        // SignExtend(Imm(0x80), 8) => Imm(0xFFFFFFFFFFFFFF80)
        let expr = e_sign_extend(Expr::Imm(0x80), 8);
        assert_eq!(fold_extension(&expr), Expr::Imm(0xFFFFFFFFFFFFFF80));
    }

    #[test]
    fn sext_of_imm_positive() {
        // SignExtend(Imm(0x7F), 8) => Imm(0x7F)
        let expr = e_sign_extend(Expr::Imm(0x7F), 8);
        assert_eq!(fold_extension(&expr), Expr::Imm(0x7F));
    }

    #[test]
    fn zext_64bit_noop() {
        // ZeroExtend(Reg(X(0)), 64) => Reg(X(0))
        let expr = e_zero_extend(Expr::Reg(Reg::X(0)), 64);
        assert_eq!(fold_extension(&expr), Expr::Reg(Reg::X(0)));
    }

    #[test]
    fn sext_64bit_noop() {
        // SignExtend(Reg(X(0)), 64) => Reg(X(0))
        let expr = e_sign_extend(Expr::Reg(Reg::X(0)), 64);
        assert_eq!(fold_extension(&expr), Expr::Reg(Reg::X(0)));
    }

    #[test]
    fn no_fold_plain_ext() {
        // ZeroExtend(Reg(X(0)), 16) => unchanged
        let expr = e_zero_extend(Expr::Reg(Reg::X(0)), 16);
        assert_eq!(
            fold_extension(&expr),
            e_zero_extend(Expr::Reg(Reg::X(0)), 16)
        );
    }

    #[test]
    fn fold_in_assign() {
        // Assign { dst: X(0), src: ZeroExtend(Imm(0x1FF), 8) } => Assign { dst: X(0), src: Imm(0xFF) }
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(0),
            src: e_zero_extend(Expr::Imm(0x1FF), 8),
        }];
        let result = fold_extensions(stmts);
        assert_eq!(
            result,
            vec![Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0xFF),
            }]
        );
    }
}
