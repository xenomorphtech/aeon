//! Expr-to-SsaExpr conversion -- translates aeonil `Expr` and `BranchCond`
//! to their SSA counterparts with unversioned variables (version=0).
//! This is the mechanical first step before SSA renaming.

use aeonil::{Expr, Reg, BranchCond, Stmt};
use super::types::*;

/// Convert an aeonil `Expr` to `SsaExpr`, mapping `Reg` references to
/// unversioned `SsaVar` (version=0).
pub fn convert_expr(expr: &Expr) -> SsaExpr {
    match expr {
        Expr::Reg(Reg::XZR) => SsaExpr::Imm(0),
        Expr::Reg(Reg::PC) => panic!("PC should not appear in reduced IL"),
        Expr::Reg(r) => {
            let (loc, _width) = reg_to_location(r);
            SsaExpr::Var(SsaVar {
                loc,
                version: 0,
                width: loc.full_width(),
            })
        }
        Expr::Imm(v) => SsaExpr::Imm(*v),
        Expr::FImm(v) => SsaExpr::FImm(*v),
        Expr::Load { addr, size } => SsaExpr::Load {
            addr: Box::new(convert_expr(addr)),
            size: *size,
        },
        Expr::Add(a, b) => SsaExpr::Add(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Sub(a, b) => SsaExpr::Sub(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Mul(a, b) => SsaExpr::Mul(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Div(a, b) => SsaExpr::Div(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::UDiv(a, b) => SsaExpr::UDiv(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Neg(a) => SsaExpr::Neg(Box::new(convert_expr(a))),
        Expr::Abs(a) => SsaExpr::Abs(Box::new(convert_expr(a))),
        Expr::And(a, b) => SsaExpr::And(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Or(a, b) => SsaExpr::Or(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Xor(a, b) => SsaExpr::Xor(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Not(a) => SsaExpr::Not(Box::new(convert_expr(a))),
        Expr::Shl(a, b) => SsaExpr::Shl(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Lsr(a, b) => SsaExpr::Lsr(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Asr(a, b) => SsaExpr::Asr(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::Ror(a, b) => SsaExpr::Ror(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::SignExtend { src, from_bits } => SsaExpr::SignExtend {
            src: Box::new(convert_expr(src)),
            from_bits: *from_bits,
        },
        Expr::ZeroExtend { src, from_bits } => SsaExpr::ZeroExtend {
            src: Box::new(convert_expr(src)),
            from_bits: *from_bits,
        },
        Expr::Extract { src, lsb, width } => SsaExpr::Extract {
            src: Box::new(convert_expr(src)),
            lsb: *lsb,
            width: *width,
        },
        Expr::Insert { dst, src, lsb, width } => SsaExpr::Insert {
            dst: Box::new(convert_expr(dst)),
            src: Box::new(convert_expr(src)),
            lsb: *lsb,
            width: *width,
        },
        Expr::FAdd(a, b) => SsaExpr::FAdd(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::FSub(a, b) => SsaExpr::FSub(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::FMul(a, b) => SsaExpr::FMul(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::FDiv(a, b) => SsaExpr::FDiv(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::FNeg(a) => SsaExpr::FNeg(Box::new(convert_expr(a))),
        Expr::FAbs(a) => SsaExpr::FAbs(Box::new(convert_expr(a))),
        Expr::FSqrt(a) => SsaExpr::FSqrt(Box::new(convert_expr(a))),
        Expr::FMax(a, b) => SsaExpr::FMax(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::FMin(a, b) => SsaExpr::FMin(Box::new(convert_expr(a)), Box::new(convert_expr(b))),
        Expr::FCvt(a) => SsaExpr::FCvt(Box::new(convert_expr(a))),
        Expr::IntToFloat(a) => SsaExpr::IntToFloat(Box::new(convert_expr(a))),
        Expr::FloatToInt(a) => SsaExpr::FloatToInt(Box::new(convert_expr(a))),
        Expr::Clz(a) => SsaExpr::Clz(Box::new(convert_expr(a))),
        Expr::Cls(a) => SsaExpr::Cls(Box::new(convert_expr(a))),
        Expr::Rev(a) => SsaExpr::Rev(Box::new(convert_expr(a))),
        Expr::Rbit(a) => SsaExpr::Rbit(Box::new(convert_expr(a))),
        Expr::CondSelect { cond, if_true, if_false } => SsaExpr::CondSelect {
            cond: *cond,
            if_true: Box::new(convert_expr(if_true)),
            if_false: Box::new(convert_expr(if_false)),
        },
        Expr::Compare { cond, lhs, rhs } => SsaExpr::Compare {
            cond: *cond,
            lhs: Box::new(convert_expr(lhs)),
            rhs: Box::new(convert_expr(rhs)),
        },
        Expr::StackSlot { offset, size } => SsaExpr::StackSlot {
            offset: *offset,
            size: *size,
        },
        Expr::MrsRead(s) => SsaExpr::MrsRead(s.clone()),
        Expr::Intrinsic { name, operands } => SsaExpr::Intrinsic {
            name: name.clone(),
            operands: operands.iter().map(convert_expr).collect(),
        },
        Expr::AdrpImm(v) => SsaExpr::AdrpImm(*v),
        Expr::AdrImm(v) => SsaExpr::AdrImm(*v),
    }
}

/// Convert an aeonil `BranchCond` to `SsaBranchCond`.
pub fn convert_branch_cond(cond: &BranchCond) -> SsaBranchCond {
    match cond {
        BranchCond::Flag(c) => {
            // Flags condition reads the current flags version (unversioned = 0)
            let flags_var = SsaVar {
                loc: RegLocation::Flags,
                version: 0,
                width: RegWidth::Full,
            };
            SsaBranchCond::Flag(*c, flags_var)
        }
        BranchCond::Zero(expr) => SsaBranchCond::Zero(convert_expr(expr)),
        BranchCond::NotZero(expr) => SsaBranchCond::NotZero(convert_expr(expr)),
        BranchCond::BitZero(expr, bit) => SsaBranchCond::BitZero(convert_expr(expr), *bit),
        BranchCond::BitNotZero(expr, bit) => SsaBranchCond::BitNotZero(convert_expr(expr), *bit),
        BranchCond::Compare { cond: c, lhs, rhs } => SsaBranchCond::Compare {
            cond: *c,
            lhs: Box::new(convert_expr(lhs)),
            rhs: Box::new(convert_expr(rhs)),
        },
    }
}

/// Convert an aeonil `Stmt` to `SsaStmt`.
pub fn convert_stmt(stmt: &Stmt) -> SsaStmt {
    match stmt {
        Stmt::Assign { dst, src } => {
            if matches!(dst, Reg::XZR | Reg::PC) {
                // Writes to XZR are discarded; PC writes shouldn't appear
                SsaStmt::Nop
            } else {
                let (loc, _width) = reg_to_location(dst);
                let ssa_dst = SsaVar {
                    loc,
                    version: 0,
                    width: loc.full_width(),
                };
                SsaStmt::Assign {
                    dst: ssa_dst,
                    src: convert_expr(src),
                }
            }
        }
        Stmt::Store { addr, value, size } => SsaStmt::Store {
            addr: convert_expr(addr),
            value: convert_expr(value),
            size: *size,
        },
        Stmt::Branch { target } => SsaStmt::Branch {
            target: convert_expr(target),
        },
        Stmt::CondBranch { cond, target, fallthrough: _ } => SsaStmt::CondBranch {
            cond: convert_branch_cond(cond),
            target: convert_expr(target),
            fallthrough: 0, // block id resolved later during CFG integration
        },
        Stmt::Call { target } => SsaStmt::Call {
            target: convert_expr(target),
        },
        Stmt::Ret => SsaStmt::Ret,
        Stmt::Nop => SsaStmt::Nop,
        Stmt::Pair(a, b) => SsaStmt::Pair(
            Box::new(convert_stmt(a)),
            Box::new(convert_stmt(b)),
        ),
        Stmt::SetFlags { expr } => {
            let flags_var = SsaVar {
                loc: RegLocation::Flags,
                version: 0,
                width: RegWidth::Full,
            };
            SsaStmt::SetFlags {
                src: flags_var,
                expr: convert_expr(expr),
            }
        }
        Stmt::Barrier(s) => SsaStmt::Barrier(s.clone()),
        Stmt::Trap => SsaStmt::Trap,
        Stmt::Intrinsic { name, operands } => SsaStmt::Intrinsic {
            name: name.clone(),
            operands: operands.iter().map(convert_expr).collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{Condition, Reg, Expr};

    #[test]
    fn convert_reg_x() {
        let expr = Expr::Reg(Reg::X(5));
        let result = convert_expr(&expr);
        match result {
            SsaExpr::Var(v) => {
                assert_eq!(v.loc, RegLocation::Gpr(5));
                assert_eq!(v.version, 0);
                assert_eq!(v.width, RegWidth::W64);
            }
            other => panic!("expected Var, got {:?}", other),
        }
    }

    #[test]
    fn convert_xzr() {
        let expr = Expr::Reg(Reg::XZR);
        assert_eq!(convert_expr(&expr), SsaExpr::Imm(0));
    }

    #[test]
    fn convert_imm() {
        let expr = Expr::Imm(42);
        assert_eq!(convert_expr(&expr), SsaExpr::Imm(42));
    }

    #[test]
    fn convert_add() {
        let expr = Expr::Add(
            Box::new(Expr::Reg(Reg::X(0))),
            Box::new(Expr::Imm(1)),
        );
        let result = convert_expr(&expr);
        match result {
            SsaExpr::Add(lhs, rhs) => {
                match *lhs {
                    SsaExpr::Var(v) => {
                        assert_eq!(v.loc, RegLocation::Gpr(0));
                        assert_eq!(v.version, 0);
                    }
                    other => panic!("expected Var, got {:?}", other),
                }
                assert_eq!(*rhs, SsaExpr::Imm(1));
            }
            other => panic!("expected Add, got {:?}", other),
        }
    }

    #[test]
    fn convert_nested() {
        // Sub(Add(X(1), Imm(2)), Mul(X(3), X(4)))
        let expr = Expr::Sub(
            Box::new(Expr::Add(
                Box::new(Expr::Reg(Reg::X(1))),
                Box::new(Expr::Imm(2)),
            )),
            Box::new(Expr::Mul(
                Box::new(Expr::Reg(Reg::X(3))),
                Box::new(Expr::Reg(Reg::X(4))),
            )),
        );
        let result = convert_expr(&expr);
        match result {
            SsaExpr::Sub(lhs, rhs) => {
                match *lhs {
                    SsaExpr::Add(a, b) => {
                        assert!(matches!(*a, SsaExpr::Var(SsaVar { loc: RegLocation::Gpr(1), .. })));
                        assert_eq!(*b, SsaExpr::Imm(2));
                    }
                    other => panic!("expected Add, got {:?}", other),
                }
                match *rhs {
                    SsaExpr::Mul(a, b) => {
                        assert!(matches!(*a, SsaExpr::Var(SsaVar { loc: RegLocation::Gpr(3), .. })));
                        assert!(matches!(*b, SsaExpr::Var(SsaVar { loc: RegLocation::Gpr(4), .. })));
                    }
                    other => panic!("expected Mul, got {:?}", other),
                }
            }
            other => panic!("expected Sub, got {:?}", other),
        }
    }

    #[test]
    fn convert_fimm() {
        let expr = Expr::FImm(3.14);
        assert_eq!(convert_expr(&expr), SsaExpr::FImm(3.14));
    }

    #[test]
    fn convert_load() {
        let expr = Expr::Load {
            addr: Box::new(Expr::Reg(Reg::X(0))),
            size: 8,
        };
        match convert_expr(&expr) {
            SsaExpr::Load { addr, size } => {
                assert!(matches!(*addr, SsaExpr::Var(_)));
                assert_eq!(size, 8);
            }
            other => panic!("expected Load, got {:?}", other),
        }
    }

    #[test]
    fn convert_branch_cond_flag() {
        let cond = BranchCond::Flag(Condition::EQ);
        let result = convert_branch_cond(&cond);
        match result {
            SsaBranchCond::Flag(c, var) => {
                assert_eq!(c, Condition::EQ);
                assert_eq!(var.loc, RegLocation::Flags);
                assert_eq!(var.version, 0);
            }
            other => panic!("expected Flag, got {:?}", other),
        }
    }

    #[test]
    fn convert_branch_cond_zero() {
        let cond = BranchCond::Zero(Expr::Reg(Reg::X(5)));
        let result = convert_branch_cond(&cond);
        match result {
            SsaBranchCond::Zero(expr) => {
                assert!(matches!(expr, SsaExpr::Var(SsaVar { loc: RegLocation::Gpr(5), .. })));
            }
            other => panic!("expected Zero, got {:?}", other),
        }
    }

    #[test]
    fn convert_stmt_assign() {
        let stmt = Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(99),
        };
        let result = convert_stmt(&stmt);
        match result {
            SsaStmt::Assign { dst, src } => {
                assert_eq!(dst.loc, RegLocation::Gpr(0));
                assert_eq!(src, SsaExpr::Imm(99));
            }
            other => panic!("expected Assign, got {:?}", other),
        }
    }

    #[test]
    fn convert_stmt_assign_xzr_is_nop() {
        let stmt = Stmt::Assign {
            dst: Reg::XZR,
            src: Expr::Imm(0),
        };
        assert_eq!(convert_stmt(&stmt), SsaStmt::Nop);
    }

    #[test]
    fn convert_reg_w() {
        // W register maps to same GPR location but with full_width for SSA var
        let expr = Expr::Reg(Reg::W(7));
        match convert_expr(&expr) {
            SsaExpr::Var(v) => {
                assert_eq!(v.loc, RegLocation::Gpr(7));
                assert_eq!(v.version, 0);
                // full_width of Gpr is W64
                assert_eq!(v.width, RegWidth::W64);
            }
            other => panic!("expected Var, got {:?}", other),
        }
    }

    #[test]
    fn convert_sign_extend() {
        let expr = Expr::SignExtend {
            src: Box::new(Expr::Reg(Reg::W(2))),
            from_bits: 32,
        };
        match convert_expr(&expr) {
            SsaExpr::SignExtend { src, from_bits } => {
                assert!(matches!(*src, SsaExpr::Var(_)));
                assert_eq!(from_bits, 32);
            }
            other => panic!("expected SignExtend, got {:?}", other),
        }
    }

    #[test]
    fn convert_intrinsic() {
        let expr = Expr::Intrinsic {
            name: "dmb".to_string(),
            operands: vec![Expr::Imm(0xf)],
        };
        match convert_expr(&expr) {
            SsaExpr::Intrinsic { name, operands } => {
                assert_eq!(name, "dmb");
                assert_eq!(operands.len(), 1);
                assert_eq!(operands[0], SsaExpr::Imm(0xf));
            }
            other => panic!("expected Intrinsic, got {:?}", other),
        }
    }

    #[test]
    fn convert_adrp_imm() {
        let expr = Expr::AdrpImm(0x1000);
        assert_eq!(convert_expr(&expr), SsaExpr::AdrpImm(0x1000));
    }

    #[test]
    fn convert_cond_select() {
        let expr = Expr::CondSelect {
            cond: Condition::GE,
            if_true: Box::new(Expr::Reg(Reg::X(1))),
            if_false: Box::new(Expr::Reg(Reg::X(2))),
        };
        match convert_expr(&expr) {
            SsaExpr::CondSelect { cond, if_true, if_false } => {
                assert_eq!(cond, Condition::GE);
                assert!(matches!(*if_true, SsaExpr::Var(SsaVar { loc: RegLocation::Gpr(1), .. })));
                assert!(matches!(*if_false, SsaExpr::Var(SsaVar { loc: RegLocation::Gpr(2), .. })));
            }
            other => panic!("expected CondSelect, got {:?}", other),
        }
    }
}
