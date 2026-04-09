//! Copy propagation and phi simplification.
//!
//! Two passes that feed into each other:
//!
//! 1. **Phi simplification** -- if every non-self operand of a phi is the same
//!    variable, the phi is replaced with a simple copy (`dst = Var(v)`).
//!
//! 2. **Copy propagation** -- when `v2 = Var(v1)` (bare copy), all uses of
//!    `v2` are rewritten to `v1`.
//!
//! Returns `true` if any IR was changed.

use super::construct::SsaFunction;
use super::types::*;
use super::use_def::{StmtLocation, UseDefMap};

/// Run copy propagation and phi simplification.  Returns `true` if any
/// changes were made.
pub fn run(func: &mut SsaFunction, use_def: &mut UseDefMap) -> bool {
    let mut changed = false;
    changed |= simplify_phis(func, use_def);
    changed |= propagate_copies(func, use_def);
    changed
}

// ---------------------------------------------------------------------------
// Phi simplification
// ---------------------------------------------------------------------------

/// If all operands of a phi (ignoring self-references to the dst) are the
/// same variable, replace the phi with a simple copy.
fn simplify_phis(func: &mut SsaFunction, use_def: &mut UseDefMap) -> bool {
    let mut changed = false;

    for block_idx in 0..func.blocks.len() {
        for stmt_idx in 0..func.blocks[block_idx].stmts.len() {
            // Extract the info we need without holding a borrow on func.
            let (dst, operands) = {
                let stmt = &func.blocks[block_idx].stmts[stmt_idx];
                match stmt {
                    SsaStmt::Assign {
                        dst,
                        src: SsaExpr::Phi(operands),
                    } => (*dst, operands.clone()),
                    _ => continue,
                }
            };

            // Determine the single non-self operand (if the phi is trivial).
            let mut same: Option<SsaVar> = None;
            let mut trivial = true;
            for &(_, op) in &operands {
                if op == dst {
                    continue; // skip self-references
                }
                match same {
                    None => same = Some(op),
                    Some(s) if s == op => {} // still the same
                    Some(_) => {
                        trivial = false;
                        break;
                    }
                }
            }

            if !trivial {
                continue;
            }

            if let Some(replacement) = same {
                let loc = StmtLocation {
                    block: func.blocks[block_idx].id,
                    stmt_idx,
                };

                // Remove use-def entries for old phi operands.
                for &(_, op) in &operands {
                    use_def.remove_use(&op, loc);
                }

                // Replace the phi with a copy.
                func.blocks[block_idx].stmts[stmt_idx] = SsaStmt::Assign {
                    dst,
                    src: SsaExpr::Var(replacement),
                };

                // Add the new use.
                use_def.add_use(&replacement, loc);

                changed = true;
            }
        }
    }

    changed
}

// ---------------------------------------------------------------------------
// Copy propagation
// ---------------------------------------------------------------------------

/// For every `v2 = Var(v1)` (bare copy, v2 != v1), replace all uses of `v2`
/// with `v1`.
fn propagate_copies(func: &mut SsaFunction, use_def: &mut UseDefMap) -> bool {
    let mut changed = false;

    // Collect all copy definitions.
    let mut copies: Vec<(SsaVar, SsaVar)> = Vec::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            if let SsaStmt::Assign {
                dst,
                src: SsaExpr::Var(src_var),
            } = stmt
            {
                if dst != src_var {
                    copies.push((*dst, *src_var));
                }
            }
        }
    }

    // For each copy v2 = v1, replace all uses of v2 with v1.
    for (v2, v1) in copies {
        let use_locs: Vec<StmtLocation> = use_def.uses_of(&v2).copied().collect();
        if use_locs.is_empty() {
            continue;
        }

        for loc in &use_locs {
            let stmt = &mut func.blocks[loc.block as usize].stmts[loc.stmt_idx];
            replace_var_in_stmt(stmt, &v2, &v1);
            use_def.remove_use(&v2, *loc);
            use_def.add_use(&v1, *loc);
        }
        changed = true;
    }

    changed
}

// ---------------------------------------------------------------------------
// Helpers -- recursive variable replacement in expressions / statements
// ---------------------------------------------------------------------------

fn replace_var_in_expr(expr: &mut SsaExpr, from: &SsaVar, to: &SsaVar) {
    match expr {
        SsaExpr::Var(v) => {
            if v == from {
                *v = *to;
            }
        }
        SsaExpr::Phi(operands) => {
            for (_, v) in operands.iter_mut() {
                if v == from {
                    *v = *to;
                }
            }
        }

        // Binary ops
        SsaExpr::Add(a, b)
        | SsaExpr::Sub(a, b)
        | SsaExpr::Mul(a, b)
        | SsaExpr::Div(a, b)
        | SsaExpr::UDiv(a, b)
        | SsaExpr::And(a, b)
        | SsaExpr::Or(a, b)
        | SsaExpr::Xor(a, b)
        | SsaExpr::Shl(a, b)
        | SsaExpr::Lsr(a, b)
        | SsaExpr::Asr(a, b)
        | SsaExpr::Ror(a, b)
        | SsaExpr::FAdd(a, b)
        | SsaExpr::FSub(a, b)
        | SsaExpr::FMul(a, b)
        | SsaExpr::FDiv(a, b)
        | SsaExpr::FMax(a, b)
        | SsaExpr::FMin(a, b) => {
            replace_var_in_expr(a, from, to);
            replace_var_in_expr(b, from, to);
        }

        // Insert has two sub-expressions
        SsaExpr::Insert { dst, src, .. } => {
            replace_var_in_expr(dst, from, to);
            replace_var_in_expr(src, from, to);
        }

        // Compare and CondSelect
        SsaExpr::Compare { lhs, rhs, .. } => {
            replace_var_in_expr(lhs, from, to);
            replace_var_in_expr(rhs, from, to);
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => {
            replace_var_in_expr(if_true, from, to);
            replace_var_in_expr(if_false, from, to);
        }

        // Unary ops
        SsaExpr::Neg(a)
        | SsaExpr::Abs(a)
        | SsaExpr::Not(a)
        | SsaExpr::FNeg(a)
        | SsaExpr::FAbs(a)
        | SsaExpr::FSqrt(a)
        | SsaExpr::FCvt(a)
        | SsaExpr::IntToFloat(a)
        | SsaExpr::FloatToInt(a)
        | SsaExpr::Clz(a)
        | SsaExpr::Cls(a)
        | SsaExpr::Rev(a)
        | SsaExpr::Rbit(a) => {
            replace_var_in_expr(a, from, to);
        }

        // Unary with extra fields
        SsaExpr::SignExtend { src, .. }
        | SsaExpr::ZeroExtend { src, .. }
        | SsaExpr::Extract { src, .. } => {
            replace_var_in_expr(src, from, to);
        }

        // Load
        SsaExpr::Load { addr, .. } => {
            replace_var_in_expr(addr, from, to);
        }

        // Intrinsic
        SsaExpr::Intrinsic { operands, .. } => {
            for op in operands.iter_mut() {
                replace_var_in_expr(op, from, to);
            }
        }

        // Leaves with no variable references
        SsaExpr::Imm(_)
        | SsaExpr::FImm(_)
        | SsaExpr::StackSlot { .. }
        | SsaExpr::MrsRead(_)
        | SsaExpr::AdrpImm(_)
        | SsaExpr::AdrImm(_) => {}
    }
}

fn replace_var_in_branch_cond(cond: &mut SsaBranchCond, from: &SsaVar, to: &SsaVar) {
    match cond {
        SsaBranchCond::Flag(_, var) => {
            if var == from {
                *var = *to;
            }
        }
        SsaBranchCond::Zero(expr) | SsaBranchCond::NotZero(expr) => {
            replace_var_in_expr(expr, from, to);
        }
        SsaBranchCond::BitZero(expr, _) | SsaBranchCond::BitNotZero(expr, _) => {
            replace_var_in_expr(expr, from, to);
        }
        SsaBranchCond::Compare { lhs, rhs, .. } => {
            replace_var_in_expr(lhs, from, to);
            replace_var_in_expr(rhs, from, to);
        }
    }
}

fn replace_var_in_stmt(stmt: &mut SsaStmt, from: &SsaVar, to: &SsaVar) {
    match stmt {
        SsaStmt::Assign { src, .. } => {
            replace_var_in_expr(src, from, to);
        }
        SsaStmt::Store { addr, value, .. } => {
            replace_var_in_expr(addr, from, to);
            replace_var_in_expr(value, from, to);
        }
        SsaStmt::Branch { target } => {
            replace_var_in_expr(target, from, to);
        }
        SsaStmt::CondBranch { cond, target, .. } => {
            replace_var_in_branch_cond(cond, from, to);
            replace_var_in_expr(target, from, to);
        }
        SsaStmt::Call { target } => {
            replace_var_in_expr(target, from, to);
        }
        SsaStmt::SetFlags { src, expr } => {
            if src == from {
                *src = *to;
            }
            replace_var_in_expr(expr, from, to);
        }
        SsaStmt::Intrinsic { operands, .. } => {
            for op in operands.iter_mut() {
                replace_var_in_expr(op, from, to);
            }
        }
        SsaStmt::Pair(a, b) => {
            replace_var_in_stmt(a, from, to);
            replace_var_in_stmt(b, from, to);
        }
        SsaStmt::Ret | SsaStmt::Nop | SsaStmt::Barrier(_) | SsaStmt::Trap { .. } => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::construct::{SsaBlock, SsaFunction};
    use crate::ssa::use_def::UseDefMap;

    /// Helper to create an SsaVar on GPR `n` with the given version.
    fn var(n: u8, version: u32) -> SsaVar {
        SsaVar {
            loc: RegLocation::Gpr(n),
            version,
            width: RegWidth::W64,
        }
    }

    /// Build a single-block function from a list of statements.
    fn one_block(stmts: Vec<SsaStmt>) -> SsaFunction {
        SsaFunction {
            entry: 0,
            blocks: vec![SsaBlock {
                id: 0,
                addr: 0,
                stmts,
                successors: vec![],
                predecessors: vec![],
            }],
        }
    }

    // -----------------------------------------------------------------------
    // Copy propagation tests
    // -----------------------------------------------------------------------

    #[test]
    fn copy_simple() {
        // v1 = Imm(100)
        // v2 = Var(v1)        <-- copy
        // Store(Imm(0x1000), v2, 4)
        //
        // After copy-prop: Store uses v1 directly.
        let v1 = var(0, 1);
        let v2 = var(0, 2);

        let mut func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(100),
            },
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Var(v1),
            },
            SsaStmt::Store {
                addr: SsaExpr::Imm(0x1000),
                value: SsaExpr::Var(v2),
                size: 4,
            },
        ]);

        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &mut ud);

        assert!(changed);
        // Store should now reference v1
        assert_eq!(
            func.blocks[0].stmts[2],
            SsaStmt::Store {
                addr: SsaExpr::Imm(0x1000),
                value: SsaExpr::Var(v1),
                size: 4,
            }
        );
    }

    #[test]
    fn copy_transitive() {
        // v1 = Imm(42)
        // v2 = Var(v1)        <-- copy
        // v3 = Var(v2)        <-- copy
        // Store(Imm(0x2000), v3, 4)
        //
        // One round propagates v3->v2 and v2->v1 for existing uses.
        // But v3->v2 introduces a new use of v2 that wasn't in the original
        // copy collection.  A second call finishes the transitive chain.
        let v1 = var(0, 1);
        let v2 = var(0, 2);
        let v3 = var(0, 3);

        let mut func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(42),
            },
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Var(v1),
            },
            SsaStmt::Assign {
                dst: v3,
                src: SsaExpr::Var(v2),
            },
            SsaStmt::Store {
                addr: SsaExpr::Imm(0x2000),
                value: SsaExpr::Var(v3),
                size: 4,
            },
        ]);

        let mut ud = UseDefMap::build(&func);

        // First round
        run(&mut func, &mut ud);
        // Second round to complete transitive chain
        run(&mut func, &mut ud);

        assert_eq!(
            func.blocks[0].stmts[3],
            SsaStmt::Store {
                addr: SsaExpr::Imm(0x2000),
                value: SsaExpr::Var(v1),
                size: 4,
            }
        );
    }

    #[test]
    fn copy_multiple_uses() {
        // v1 = Imm(10)
        // v2 = Var(v1)        <-- copy
        // v3 = Add(v2, v2)
        //
        // After copy-prop: v3 = Add(v1, v1)
        let v1 = var(0, 1);
        let v2 = var(0, 2);
        let v3 = var(1, 1);

        let mut func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(10),
            },
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Var(v1),
            },
            SsaStmt::Assign {
                dst: v3,
                src: SsaExpr::Add(Box::new(SsaExpr::Var(v2)), Box::new(SsaExpr::Var(v2))),
            },
        ]);

        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &mut ud);

        assert!(changed);
        assert_eq!(
            func.blocks[0].stmts[2],
            SsaStmt::Assign {
                dst: v3,
                src: SsaExpr::Add(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Var(v1)),),
            }
        );
    }

    // -----------------------------------------------------------------------
    // Phi simplification tests
    // -----------------------------------------------------------------------

    #[test]
    fn phi_trivial() {
        // v3 = Phi((0, v1), (1, v1))   -- both operands are v1
        //
        // After simplification: v3 = Var(v1)
        let v1 = var(0, 1);
        let v3 = var(0, 3);

        let mut func = one_block(vec![SsaStmt::Assign {
            dst: v3,
            src: SsaExpr::Phi(vec![(0, v1), (1, v1)]),
        }]);

        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &mut ud);

        assert!(changed);
        assert_eq!(
            func.blocks[0].stmts[0],
            SsaStmt::Assign {
                dst: v3,
                src: SsaExpr::Var(v1),
            }
        );
    }

    #[test]
    fn phi_self_ref() {
        // v3 = Phi((0, v1), (1, v3))   -- self-reference filtered out
        //
        // After simplification: v3 = Var(v1)
        let v1 = var(0, 1);
        let v3 = var(0, 3);

        let mut func = one_block(vec![SsaStmt::Assign {
            dst: v3,
            src: SsaExpr::Phi(vec![(0, v1), (1, v3)]),
        }]);

        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &mut ud);

        assert!(changed);
        assert_eq!(
            func.blocks[0].stmts[0],
            SsaStmt::Assign {
                dst: v3,
                src: SsaExpr::Var(v1),
            }
        );
    }

    #[test]
    fn phi_distinct() {
        // v3 = Phi((0, v1), (1, v2))   -- v1 != v2 -> not trivial
        //
        // Should remain unchanged.
        let v1 = var(0, 1);
        let v2 = var(0, 2);
        let v3 = var(0, 3);

        let original = SsaStmt::Assign {
            dst: v3,
            src: SsaExpr::Phi(vec![(0, v1), (1, v2)]),
        };

        let mut func = one_block(vec![original.clone()]);

        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &mut ud);

        assert!(!changed);
        assert_eq!(func.blocks[0].stmts[0], original);
    }

    // -----------------------------------------------------------------------
    // Non-copy guard
    // -----------------------------------------------------------------------

    #[test]
    fn no_copy_for_non_var() {
        // v1 = Imm(10)
        // v2 = Add(v1, Imm(1))   <-- NOT a copy
        // Store(Imm(0x3000), v2, 4)
        //
        // Nothing should change.
        let v1 = var(0, 1);
        let v2 = var(1, 1);

        let original_store = SsaStmt::Store {
            addr: SsaExpr::Imm(0x3000),
            value: SsaExpr::Var(v2),
            size: 4,
        };

        let mut func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(10),
            },
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Add(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Imm(1))),
            },
            original_store.clone(),
        ]);

        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &mut ud);

        assert!(!changed);
        assert_eq!(func.blocks[0].stmts[2], original_store);
    }
}
