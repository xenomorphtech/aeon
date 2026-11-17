//! ADRP+ADD folding -- resolves `AdrpImm` followed by an `Add` with a
//! 12-bit page offset into a fully-resolved 64-bit address constant, which
//! downstream passes can use for direct memory references or symbol lookup.

use aeonil::{BranchCond, Expr, Reg, Stmt};
use std::cell::Cell;

use crate::env::{regs_in, RegisterEnv};
use crate::reduce_const::{fold_expr, map_flag_operands};

fn fold_adr_add_with_count(expr: &Expr) -> (Expr, usize) {
    let count = Cell::new(0usize);
    let folded = expr.map_subexprs(|e| {
        let (subexpr, subcount) = fold_adr_add_with_count(e);
        count.set(count.get() + subcount);
        subexpr
    });

    let folded = match &folded {
        Expr::Add(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::AdrpImm(page), Expr::Imm(off)) | (Expr::Imm(off), Expr::AdrpImm(page)) => {
                count.set(count.get() + 1);
                Expr::Imm(page.wrapping_add(*off))
            }
            (Expr::AdrImm(addr), Expr::Imm(off)) | (Expr::Imm(off), Expr::AdrImm(addr)) => {
                count.set(count.get() + 1);
                Expr::Imm(addr.wrapping_add(*off))
            }
            _ => folded,
        },
        _ => folded,
    };

    (folded, count.get())
}

fn resolve_and_fold_with_count(expr: &Expr, env: &RegisterEnv) -> (Expr, usize) {
    let resolved = env.resolve(expr);
    let folded = fold_expr(&resolved);
    fold_adr_add_with_count(&folded)
}

fn resolve_branch_cond_with_count(cond: &BranchCond, env: &RegisterEnv) -> (BranchCond, usize) {
    match cond {
        BranchCond::Flag(c) => (BranchCond::Flag(*c), 0),
        BranchCond::Zero(e) => {
            let (expr, count) = resolve_and_fold_with_count(e, env);
            (BranchCond::Zero(expr), count)
        }
        BranchCond::NotZero(e) => {
            let (expr, count) = resolve_and_fold_with_count(e, env);
            (BranchCond::NotZero(expr), count)
        }
        BranchCond::BitZero(e, bit) => {
            let (expr, count) = resolve_and_fold_with_count(e, env);
            (BranchCond::BitZero(expr, *bit), count)
        }
        BranchCond::BitNotZero(e, bit) => {
            let (expr, count) = resolve_and_fold_with_count(e, env);
            (BranchCond::BitNotZero(expr, *bit), count)
        }
        BranchCond::Compare { cond, lhs, rhs } => {
            let (lhs, lhs_count) = resolve_and_fold_with_count(lhs, env);
            let (rhs, rhs_count) = resolve_and_fold_with_count(rhs, env);
            (
                BranchCond::Compare {
                    cond: *cond,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                lhs_count + rhs_count,
            )
        }
    }
}

fn resolve_stmt_exprs_with_count(stmt: Stmt, env: &RegisterEnv) -> (Stmt, usize) {
    match stmt {
        Stmt::Branch { target } => {
            let (target, count) = resolve_and_fold_with_count(&target, env);
            (Stmt::Branch { target }, count)
        }
        Stmt::CondBranch {
            cond,
            target,
            fallthrough,
        } => {
            let (cond, cond_count) = resolve_branch_cond_with_count(&cond, env);
            let (target, target_count) = resolve_and_fold_with_count(&target, env);
            (
                Stmt::CondBranch {
                    cond,
                    target,
                    fallthrough,
                },
                cond_count + target_count,
            )
        }
        Stmt::SetFlags { expr } => {
            // Only the operands: the operator decides how flags are set.
            let count = Cell::new(0usize);
            let expr = map_flag_operands(&expr, &|operand| {
                let (operand, operand_count) = resolve_and_fold_with_count(operand, env);
                count.set(count.get() + operand_count);
                operand
            });
            (Stmt::SetFlags { expr }, count.get())
        }
        Stmt::Pair(a, b) => {
            let (a, a_count) = resolve_stmt_exprs_with_count(*a, env);
            let (b, b_count) = resolve_stmt_exprs_with_count(*b, env);
            (Stmt::Pair(Box::new(a), Box::new(b)), a_count + b_count)
        }
        // Statement intrinsics are left alone: an operand may be a register
        // the intrinsic writes, and a constant cannot stand in for that.
        // Ret, Nop, Barrier, Trap: no expressions to resolve
        other => (other, 0),
    }
}

/// The value that may replace later reads of `dst` after `dst = value`, if
/// there is one.
///
/// Only integer constants qualify. Anything else changes meaning when
/// moved:
/// - an expression over registers is wrong once one of them is redefined
///   (`x29 = sp` after `sp` moved);
/// - a float constant read through a general-purpose register is a bit
///   pattern, not that float.
///
/// A constant assigned to a W register is forwarded as an `Imm32`, so the
/// operations that read it stay 32-bit.
fn forwardable(dst: &Reg, value: &Expr) -> Option<Expr> {
    match (dst, value) {
        (Reg::X(_), Expr::Imm(_) | Expr::AdrpImm(_) | Expr::AdrImm(_)) => Some(value.clone()),
        (Reg::W(_), Expr::Imm(_) | Expr::Imm32(_)) => Expr::const_for_reg(dst, value.as_int_const()?),
        _ => None,
    }
}

/// Forward-propagate ADRP/ADR values and other integer constants through
/// register assignments and fold `Add(AdrpImm(page), Imm(offset))` into
/// `Imm(page + offset)`.
///
/// This is the main entry point.  It walks the statement list in order,
/// maintaining a `RegisterEnv` that maps registers to their known constant
/// values.  For each `Assign`, it resolves the source expression (substituting
/// known register values), constant-folds, and then applies the ADRP+ADD
/// pattern match.
pub fn resolve_adrp_add(stmts: Vec<Stmt>) -> Vec<Stmt> {
    resolve_adrp_add_with_stats(stmts).0
}

pub(crate) fn resolve_adrp_add_with_stats(stmts: Vec<Stmt>) -> (Vec<Stmt>, usize) {
    let mut env = RegisterEnv::new();
    let mut result = Vec::with_capacity(stmts.len());
    let mut resolutions = 0usize;

    for stmt in stmts {
        match stmt {
            Stmt::Assign { dst, src } => {
                let (folded, count) = resolve_and_fold_with_count(&src, &env);
                match forwardable(&dst, &folded) {
                    Some(constant) => env.assign(dst.clone(), constant),
                    None => env.remove(&dst),
                }
                result.push(Stmt::Assign { dst, src: folded });
                resolutions += count;
            }
            Stmt::Store { addr, value, size } => {
                let (resolved_addr, addr_count) = resolve_and_fold_with_count(&addr, &env);
                let (resolved_value, value_count) = resolve_and_fold_with_count(&value, &env);
                result.push(Stmt::Store {
                    addr: resolved_addr,
                    value: resolved_value,
                    size,
                });
                resolutions += addr_count + value_count;
            }
            Stmt::Call { target } => {
                let (resolved_target, count) = resolve_and_fold_with_count(&target, &env);
                result.push(Stmt::Call {
                    target: resolved_target,
                });
                env.invalidate_caller_saved();
                env.remove(&Reg::X(30));
                resolutions += count;
            }
            Stmt::Intrinsic { name, operands } => {
                // It may write any register it names (a destination, or the
                // base of a post-indexed load).
                for reg in operands.iter().flat_map(regs_in) {
                    env.remove(&reg);
                }
                result.push(Stmt::Intrinsic { name, operands });
            }
            other => {
                let (stmt, count) = resolve_stmt_exprs_with_count(other, &env);
                result.push(stmt);
                resolutions += count;
            }
        }
    }
    (result, resolutions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, e_load, Expr, Reg, Stmt};

    /// Helper: build `Assign { dst, src }`.
    fn assign(dst: Reg, src: Expr) -> Stmt {
        Stmt::Assign { dst, src }
    }

    // 1. Basic ADRP + ADD resolves to a single immediate.
    #[test]
    fn adrp_add_resolves() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrpImm(0x12345000)),
            assign(Reg::X(0), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x678))),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result.len(), 2);
        assert_eq!(result[1], assign(Reg::X(0), Expr::Imm(0x12345678)));
    }

    // 2. ADRP on X(0), ADD uses X(0) but writes to X(1).
    #[test]
    fn adrp_add_different_regs() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrpImm(0x12345000)),
            assign(Reg::X(1), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10))),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result[1], assign(Reg::X(1), Expr::Imm(0x12345010)));
    }

    // 3. Unrelated assignment between ADRP and ADD does not clobber the ADRP reg.
    #[test]
    fn adrp_add_interleaved() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrpImm(0x12345000)),
            assign(Reg::X(1), Expr::Imm(99)),
            assign(Reg::X(0), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x678))),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result.len(), 3);
        assert_eq!(result[1], assign(Reg::X(1), Expr::Imm(99)));
        assert_eq!(result[2], assign(Reg::X(0), Expr::Imm(0x12345678)));
    }

    // 4. ADRP clobbered before use -- ADD should NOT resolve to a folded address.
    #[test]
    fn adrp_add_clobbered() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrpImm(0x12345000)),
            assign(Reg::X(0), Expr::Imm(0)),
            assign(Reg::X(0), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x678))),
        ];
        let result = resolve_adrp_add(stmts);
        // X(0) was overwritten with Imm(0), so Add(0, 0x678) = 0x678
        assert_eq!(result[2], assign(Reg::X(0), Expr::Imm(0x678)));
    }

    // 5. ADRP value propagated into a Load address.
    #[test]
    fn adrp_add_into_load() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrpImm(0x1000)),
            assign(
                Reg::X(0),
                e_load(e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10)), 8),
            ),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result[1], assign(Reg::X(0), e_load(Expr::Imm(0x1010), 8)));
    }

    // 6. Two independent ADRP+ADD sequences on different registers.
    #[test]
    fn adrp_two_independent() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrpImm(0xA000)),
            assign(Reg::X(1), Expr::AdrpImm(0xB000)),
            assign(Reg::X(0), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x100))),
            assign(Reg::X(1), e_add(Expr::Reg(Reg::X(1)), Expr::Imm(0x200))),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result[2], assign(Reg::X(0), Expr::Imm(0xA100)));
        assert_eq!(result[3], assign(Reg::X(1), Expr::Imm(0xB200)));
    }

    // 7. Page boundary wrapping.
    #[test]
    fn adrp_page_boundary() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrpImm(0xFFFFF000)),
            assign(Reg::X(0), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0xFFF))),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result[1], assign(Reg::X(0), Expr::Imm(0xFFFFFFFF)));
    }

    // --- Additional coverage ---

    // AdrImm behaves the same as AdrpImm.
    #[test]
    fn adr_imm_resolves() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrImm(0x42000)),
            assign(Reg::X(0), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x42))),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result[1], assign(Reg::X(0), Expr::Imm(0x42042)));
    }

    // ADRP value propagated through a Store address.
    #[test]
    fn adrp_into_store() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrpImm(0x1000)),
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10)),
                value: Expr::Reg(Reg::X(1)),
                size: 8,
            },
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(
            result[1],
            Stmt::Store {
                addr: Expr::Imm(0x1010),
                value: Expr::Reg(Reg::X(1)),
                size: 8,
            }
        );
    }

    // Call invalidates caller-saved registers.
    #[test]
    fn call_invalidates_adrp() {
        let stmts = vec![
            assign(Reg::X(0), Expr::AdrpImm(0x5000)),
            Stmt::Call {
                target: Expr::Imm(0xDEAD),
            },
            assign(Reg::X(0), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10))),
        ];
        let result = resolve_adrp_add(stmts);
        // X(0) was invalidated by the call, so Add(Reg(X(0)), Imm(0x10))
        // cannot be resolved -- the register reference stays.
        assert_eq!(
            result[2],
            assign(Reg::X(0), e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10)))
        );
    }

    // Callee-saved register survives a call.
    #[test]
    fn callee_saved_survives_call() {
        let stmts = vec![
            assign(Reg::X(19), Expr::AdrpImm(0x5000)),
            Stmt::Call {
                target: Expr::Imm(0xDEAD),
            },
            assign(Reg::X(19), e_add(Expr::Reg(Reg::X(19)), Expr::Imm(0x10))),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result[2], assign(Reg::X(19), Expr::Imm(0x5010)));
    }

    // A constant in a W register is forwarded as a 32-bit constant, so the
    // shift that reads it stays within 32 bits.
    #[test]
    fn w_constant_is_forwarded_at_32_bits() {
        let stmts = vec![
            assign(Reg::W(1), Expr::Imm(0xffff_ffff)),
            assign(
                Reg::W(8),
                aeonil::e_lsr(Expr::Reg(Reg::W(1)), Expr::Imm(4)),
            ),
            assign(
                Reg::W(9),
                aeonil::e_asr(Expr::Reg(Reg::W(1)), Expr::Reg(Reg::W(2))),
            ),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result[1], assign(Reg::W(8), Expr::Imm32(0x0fff_ffff)));
        // Not foldable, but still a 32-bit shift.
        assert_eq!(
            result[2],
            assign(
                Reg::W(9),
                aeonil::e_asr(Expr::Imm32(0xffff_ffff), Expr::Reg(Reg::W(2)))
            )
        );
    }

    // Writing the W view ends what was known about the X view, and the
    // other way round.
    #[test]
    fn w_and_x_views_invalidate_each_other() {
        let stmts = vec![
            assign(Reg::X(1), Expr::Imm(u64::MAX)),
            assign(Reg::W(1), Expr::Imm(5)),
            assign(Reg::X(8), e_add(Expr::Reg(Reg::X(1)), Expr::Imm(1))),
            assign(Reg::X(1), Expr::Reg(Reg::X(0))),
            assign(Reg::W(9), e_add(Expr::Reg(Reg::W(1)), Expr::Imm(1))),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(
            result[2],
            assign(Reg::X(8), e_add(Expr::Reg(Reg::X(1)), Expr::Imm(1)))
        );
        assert_eq!(
            result[4],
            assign(Reg::W(9), e_add(Expr::Reg(Reg::W(1)), Expr::Imm(1)))
        );
    }
}
