//! Constant folding -- evaluates pure arithmetic/logic `Expr` nodes whose
//! operands are all `Expr::Imm` at compile time, replacing the tree with a
//! single `Expr::Imm`.  Also applies identity and annihilation rules.

use aeonil::{BranchCond, Expr, Stmt};

/// Recursively fold constant expressions within an expression tree.
pub fn fold_expr(expr: &Expr) -> Expr {
    // First, recursively fold all sub-expressions
    let folded = expr.map_subexprs(|e| fold_expr(e));

    if let Some(constant) = fold_32_bit(&folded) {
        return constant;
    }

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
            // Signed: `MIN / -1` wraps to `MIN`, as on the CPU.
            (Expr::Imm(a), Expr::Imm(b)) if *b != 0 => {
                Expr::Imm((*a as i64).wrapping_div(*b as i64) as u64)
            }
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
        // A shift by a register takes the amount modulo the width, and that
        // is what `Shl`/`Lsr`/`Asr` mean in every engine. A 32-bit value
        // was folded above, so the width here is 64.
        Expr::Shl(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => Expr::Imm(a.wrapping_shl((*b % 64) as u32)),
            _ => folded,
        },
        Expr::Lsr(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => Expr::Imm(a.wrapping_shr((*b % 64) as u32)),
            _ => folded,
        },
        Expr::Asr(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Imm(a), Expr::Imm(b)) => {
                Expr::Imm((*a as i64).wrapping_shr((*b % 64) as u32) as u64)
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
        // --- Bitfield insert into a constant (`movk` onto a known value) ---
        Expr::Insert {
            dst,
            src,
            lsb,
            width,
        } => match (dst.as_ref(), src.as_int_const()) {
            (Expr::Imm(old), Some(field)) if u32::from(*lsb) + u32::from(*width) <= 64 => {
                Expr::Imm(insert_bits(*old, field, *lsb, *width))
            }
            (Expr::Imm32(old), Some(field)) if u32::from(*lsb) + u32::from(*width) <= 32 => {
                Expr::Imm32(insert_bits(u64::from(*old), field, *lsb, *width) as u32)
            }
            _ => folded,
        },

        // Everything else: already recursively folded by map_subexprs
        _ => folded,
    }
}

/// Folds an operation on constants that a typed operand makes 32-bit.
///
/// Arithmetic and logic are 32-bit if either operand is an `Imm32`; a shift
/// is 32-bit if the value shifted is, whatever its amount. The result is an
/// `Imm32`, so it keeps the width in whatever it is an operand of.
fn fold_32_bit(expr: &Expr) -> Option<Expr> {
    let typed = |e: &Expr| matches!(e, Expr::Imm32(_));
    let low = |e: &Expr| e.as_int_const().map(|value| value as u32);
    let amount = |e: &Expr| e.as_int_const().map(|value| (value % 32) as u32);

    let value = match expr {
        Expr::Add(a, b) if typed(a) || typed(b) => low(a)?.wrapping_add(low(b)?),
        Expr::Sub(a, b) if typed(a) || typed(b) => low(a)?.wrapping_sub(low(b)?),
        Expr::Mul(a, b) if typed(a) || typed(b) => low(a)?.wrapping_mul(low(b)?),
        Expr::And(a, b) if typed(a) || typed(b) => low(a)? & low(b)?,
        Expr::Or(a, b) if typed(a) || typed(b) => low(a)? | low(b)?,
        Expr::Xor(a, b) if typed(a) || typed(b) => low(a)? ^ low(b)?,
        Expr::Div(a, b) if typed(a) || typed(b) => {
            let (a, b) = (low(a)? as i32, low(b)? as i32);
            if b == 0 {
                return None;
            }
            a.wrapping_div(b) as u32
        }
        Expr::UDiv(a, b) if typed(a) || typed(b) => {
            let (a, b) = (low(a)?, low(b)?);
            if b == 0 {
                return None;
            }
            a / b
        }
        Expr::Shl(a, b) if typed(a) => low(a)?.wrapping_shl(amount(b)?),
        Expr::Lsr(a, b) if typed(a) => low(a)?.wrapping_shr(amount(b)?),
        Expr::Asr(a, b) if typed(a) => (low(a)? as i32).wrapping_shr(amount(b)?) as u32,
        Expr::Ror(a, b) if typed(a) => low(a)?.rotate_right(amount(b)?),
        Expr::Not(a) if typed(a) => !low(a)?,
        Expr::Neg(a) if typed(a) => low(a)?.wrapping_neg(),
        _ => return None,
    };
    Some(Expr::Imm32(value))
}

/// `dst` with `width` bits at `lsb` replaced by the low bits of `field`.
fn insert_bits(dst: u64, field: u64, lsb: u8, width: u8) -> u64 {
    if width == 0 {
        return dst;
    }
    let mask = (u64::MAX >> (64 - u32::from(width))) << lsb;
    (dst & !mask) | ((field << lsb) & mask)
}

/// Applies `f` to the operands of a flag-setting expression, leaving the
/// expression's own shape alone.
///
/// The top-level operator of a `SetFlags` says how the flags are computed:
/// `Sub(x, 0)` sets carry, `Add(x, 0)` clears it, an `Imm` is a literal
/// NZCV, and a `CondSelect` picks between two such expressions (`ccmp`).
/// Simplifying `Sub(x, 0)` to `x`, or `Sub(5, 5)` to `0`, would change them.
pub(crate) fn map_flag_operands(expr: &Expr, f: &dyn Fn(&Expr) -> Expr) -> Expr {
    match expr {
        Expr::CondSelect {
            cond,
            if_true,
            if_false,
        } => Expr::CondSelect {
            cond: *cond,
            if_true: Box::new(map_flag_operands(if_true, f)),
            if_false: Box::new(map_flag_operands(if_false, f)),
        },
        Expr::Imm(_) => expr.clone(),
        other => other.map_subexprs(|operand| f(operand)),
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
            expr: map_flag_operands(&expr, &fold_expr),
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
    fn fold_insert_into_constant() {
        // movk x, #0xace0, lsl #16 onto 0x7140.
        let expr = aeonil::e_insert(Expr::Imm(0x7140), Expr::Imm(0xace0), 16, 16);
        assert_eq!(fold_expr(&expr), Expr::Imm(0xace0_7140));
        // A zero field clears the bits it names.
        let expr = aeonil::e_insert(Expr::Imm(u64::MAX), Expr::Imm(0), 32, 16);
        assert_eq!(fold_expr(&expr), Expr::Imm(0xffff_0000_ffff_ffff));
        // Into a 32-bit constant the result stays 32-bit.
        let expr = aeonil::e_insert(Expr::Imm32(0xffff), Expr::Imm(0x12), 16, 16);
        assert_eq!(fold_expr(&expr), Expr::Imm32(0x0012_ffff));
    }

    #[test]
    fn fold_nested_insert_chain() {
        let expr = aeonil::e_insert(
            aeonil::e_insert(Expr::Imm(0x7140), Expr::Imm(0xace0), 16, 16),
            Expr::Imm(0x76),
            32,
            16,
        );
        assert_eq!(fold_expr(&expr), Expr::Imm(0x76_ace0_7140));
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

    #[test]
    fn a_32_bit_constant_keeps_the_operation_32_bit() {
        // lsr w, #4 of 0x8000_0000 stays within 32 bits; asr sign-extends
        // from bit 31, not bit 63.
        assert_eq!(
            fold_expr(&e_lsr(Expr::Imm32(0x8000_0010), Expr::Imm(4))),
            Expr::Imm32(0x0800_0001)
        );
        assert_eq!(
            fold_expr(&aeonil::e_asr(Expr::Imm32(0x8000_0000), Expr::Imm(4))),
            Expr::Imm32(0xf800_0000)
        );
        // The amount is taken modulo 32.
        assert_eq!(
            fold_expr(&e_shl(Expr::Imm32(1), Expr::Imm32(33))),
            Expr::Imm32(2)
        );
        // Wraps at 32 bits, whichever side the typed operand is on.
        assert_eq!(
            fold_expr(&e_add(Expr::Imm(1), Expr::Imm32(u32::MAX))),
            Expr::Imm32(0)
        );
        assert_eq!(
            fold_expr(&aeonil::e_div(Expr::Imm32(0x8000_0000), Expr::Imm32(u32::MAX))),
            Expr::Imm32(0x8000_0000)
        );
        assert_eq!(
            fold_expr(&aeonil::e_not(Expr::Imm32(0))),
            Expr::Imm32(u32::MAX)
        );
    }

    #[test]
    fn untyped_constants_still_fold_at_64_bits() {
        assert_eq!(
            fold_expr(&e_lsr(Expr::Imm(0x1_0000_0000), Expr::Imm(4))),
            Expr::Imm(0x1000_0000)
        );
    }
}
