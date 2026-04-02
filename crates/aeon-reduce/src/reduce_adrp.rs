//! ADRP+ADD folding -- resolves `AdrpImm` followed by an `Add` with a
//! 12-bit page offset into a fully-resolved 64-bit address constant, which
//! downstream passes can use for direct memory references or symbol lookup.

use aeonil::{BranchCond, Expr, Stmt};

use crate::env::RegisterEnv;
use crate::reduce_const::fold_expr;

/// Fold `Add(AdrpImm(a), Imm(b))` and `Add(AdrImm(a), Imm(b))` into `Imm(a + b)`.
/// Also handles the reversed operand order.
/// Applied recursively to sub-expressions.
fn fold_adr_add(expr: &Expr) -> Expr {
    let folded = expr.map_subexprs(|e| fold_adr_add(e));

    match &folded {
        Expr::Add(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::AdrpImm(page), Expr::Imm(off))
            | (Expr::Imm(off), Expr::AdrpImm(page)) => Expr::Imm(page.wrapping_add(*off)),
            (Expr::AdrImm(addr), Expr::Imm(off))
            | (Expr::Imm(off), Expr::AdrImm(addr)) => Expr::Imm(addr.wrapping_add(*off)),
            _ => folded,
        },
        _ => folded,
    }
}

/// Resolve an expression: substitute registers from `env`, constant-fold,
/// then fold ADRP/ADR + immediate additions.
fn resolve_and_fold(expr: &Expr, env: &RegisterEnv) -> Expr {
    let resolved = env.resolve(expr);
    let folded = fold_expr(&resolved);
    fold_adr_add(&folded)
}

/// Resolve expressions inside a `BranchCond`.
fn resolve_branch_cond(cond: &BranchCond, env: &RegisterEnv) -> BranchCond {
    match cond {
        BranchCond::Flag(c) => BranchCond::Flag(*c),
        BranchCond::Zero(e) => BranchCond::Zero(resolve_and_fold(e, env)),
        BranchCond::NotZero(e) => BranchCond::NotZero(resolve_and_fold(e, env)),
        BranchCond::BitZero(e, bit) => BranchCond::BitZero(resolve_and_fold(e, env), *bit),
        BranchCond::BitNotZero(e, bit) => BranchCond::BitNotZero(resolve_and_fold(e, env), *bit),
        BranchCond::Compare { cond, lhs, rhs } => BranchCond::Compare {
            cond: *cond,
            lhs: Box::new(resolve_and_fold(lhs, env)),
            rhs: Box::new(resolve_and_fold(rhs, env)),
        },
    }
}

/// Resolve register references and fold constants in all expressions within a
/// statement.  Used for statement types not handled specially in the main loop.
fn resolve_stmt_exprs(stmt: Stmt, env: &RegisterEnv) -> Stmt {
    match stmt {
        Stmt::Branch { target } => Stmt::Branch {
            target: resolve_and_fold(&target, env),
        },
        Stmt::CondBranch {
            cond,
            target,
            fallthrough,
        } => Stmt::CondBranch {
            cond: resolve_branch_cond(&cond, env),
            target: resolve_and_fold(&target, env),
            fallthrough,
        },
        Stmt::SetFlags { expr } => Stmt::SetFlags {
            expr: resolve_and_fold(&expr, env),
        },
        Stmt::Pair(a, b) => Stmt::Pair(
            Box::new(resolve_stmt_exprs(*a, env)),
            Box::new(resolve_stmt_exprs(*b, env)),
        ),
        Stmt::Intrinsic { name, operands } => Stmt::Intrinsic {
            name,
            operands: operands.iter().map(|e| resolve_and_fold(e, env)).collect(),
        },
        // Ret, Nop, Barrier, Trap: no expressions to resolve
        other => other,
    }
}

/// Forward-propagate ADRP/ADR values through register assignments and fold
/// `Add(AdrpImm(page), Imm(offset))` into `Imm(page + offset)`.
///
/// This is the main entry point.  It walks the statement list in order,
/// maintaining a `RegisterEnv` that maps registers to their known symbolic
/// values.  For each `Assign`, it resolves the source expression (substituting
/// known register values), constant-folds, and then applies the ADRP+ADD
/// pattern match.
pub fn resolve_adrp_add(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut env = RegisterEnv::new();
    let mut result = Vec::with_capacity(stmts.len());

    for stmt in stmts {
        match stmt {
            Stmt::Assign { dst, src } => {
                let folded = resolve_and_fold(&src, &env);
                env.assign(dst.clone(), folded.clone());
                result.push(Stmt::Assign { dst, src: folded });
            }
            Stmt::Store { addr, value, size } => {
                let resolved_addr = resolve_and_fold(&addr, &env);
                let resolved_value = resolve_and_fold(&value, &env);
                result.push(Stmt::Store {
                    addr: resolved_addr,
                    value: resolved_value,
                    size,
                });
            }
            Stmt::Call { target } => {
                let resolved_target = resolve_and_fold(&target, &env);
                result.push(Stmt::Call {
                    target: resolved_target,
                });
                env.invalidate_caller_saved();
            }
            other => {
                result.push(resolve_stmt_exprs(other, &env));
            }
        }
    }
    result
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
            assign(
                Reg::X(0),
                e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x678)),
            ),
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
            assign(
                Reg::X(1),
                e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10)),
            ),
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
            assign(
                Reg::X(0),
                e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x678)),
            ),
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
            assign(
                Reg::X(0),
                e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x678)),
            ),
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
            assign(
                Reg::X(0),
                e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x100)),
            ),
            assign(
                Reg::X(1),
                e_add(Expr::Reg(Reg::X(1)), Expr::Imm(0x200)),
            ),
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
            assign(
                Reg::X(0),
                e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0xFFF)),
            ),
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
            assign(
                Reg::X(0),
                e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x42)),
            ),
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
            assign(
                Reg::X(0),
                e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10)),
            ),
        ];
        let result = resolve_adrp_add(stmts);
        // X(0) was invalidated by the call, so Add(Reg(X(0)), Imm(0x10))
        // cannot be resolved -- the register reference stays.
        assert_eq!(
            result[2],
            assign(
                Reg::X(0),
                e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10))
            )
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
            assign(
                Reg::X(19),
                e_add(Expr::Reg(Reg::X(19)), Expr::Imm(0x10)),
            ),
        ];
        let result = resolve_adrp_add(stmts);
        assert_eq!(result[2], assign(Reg::X(19), Expr::Imm(0x5010)));
    }
}
