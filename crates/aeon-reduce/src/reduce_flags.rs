//! Flag-expression simplification -- replaces `SetFlags` + `CondBranch`
//! patterns with direct comparisons when the flag-setting expression and
//! the condition code are simple enough (e.g., CMP+BEQ -> branch-if-equal).
//!
//! Two sub-passes:
//! 1. `fuse_flags` — forward scan to fuse `SetFlags` with the next flag-reading
//!    statement (`CondBranch { cond: Flag(..) }` or `CondSelect`).
//! 2. `eliminate_dead_flags` — backward scan to remove `SetFlags` with no consumer.

use aeonil::{BranchCond, Expr, Stmt};

/// Extract the comparison operands (lhs, rhs) from a flag-setting expression.
/// Returns `None` for expressions we cannot decompose into a simple comparison.
fn extract_comparison(expr: &Expr) -> Option<(Expr, Expr)> {
    match expr {
        Expr::Sub(lhs, rhs) => Some((*lhs.clone(), *rhs.clone())), // CMP
        Expr::Add(lhs, rhs) => Some((*lhs.clone(), *rhs.clone())), // CMN
        Expr::And(lhs, rhs) => Some((*lhs.clone(), *rhs.clone())), // TST
        _ => None, // complex SetFlags we can't fuse
    }
}

/// Returns true if the statement reads the implicit flags register.
fn reads_flags(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::CondBranch {
            cond: BranchCond::Flag(_),
            ..
        } => true,
        Stmt::Assign {
            src: Expr::CondSelect { .. },
            ..
        } => true,
        _ => false,
    }
}

/// Returns true if the statement writes the implicit flags register.
fn writes_flags(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::SetFlags { .. })
}

/// Forward fusion pass: walk the statement list and fuse `SetFlags` with the
/// next downstream flag-reading statement, skipping over intervening statements
/// that do not write flags.
///
/// For `SetFlags { expr: Sub/Add/And(lhs, rhs) }` + `CondBranch { cond: Flag(c) }`:
///   -> `CondBranch { cond: Compare { cond: c, lhs, rhs } }`
///   The `SetFlags` is removed.
///
/// For `SetFlags` + `Assign { dst, src: CondSelect { cond, .. } }`:
///   The `SetFlags` is removed (the `CondSelect` already carries the condition code).
pub fn fuse_flags(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let len = stmts.len();
    // Track which indices have been consumed (removed) by fusion.
    let mut consumed = vec![false; len];
    // Collect output: we'll rebuild from the original list, applying replacements.
    let mut replacements: Vec<Option<Stmt>> = vec![None; len];

    for i in 0..len {
        if consumed[i] {
            continue;
        }
        if let Stmt::SetFlags { ref expr } = stmts[i] {
            if let Some((lhs, rhs)) = extract_comparison(expr) {
                // Look ahead for the next flag reader, skipping non-flag-writing stmts.
                let mut found = false;
                for j in (i + 1)..len {
                    if writes_flags(&stmts[j]) {
                        // Another SetFlags before any reader — stop looking.
                        break;
                    }
                    if reads_flags(&stmts[j]) {
                        match &stmts[j] {
                            Stmt::CondBranch {
                                cond: BranchCond::Flag(c),
                                target,
                                fallthrough,
                            } => {
                                // Fuse: replace the CondBranch and remove SetFlags.
                                replacements[j] = Some(Stmt::CondBranch {
                                    cond: BranchCond::Compare {
                                        cond: *c,
                                        lhs: Box::new(lhs.clone()),
                                        rhs: Box::new(rhs.clone()),
                                    },
                                    target: target.clone(),
                                    fallthrough: *fallthrough,
                                });
                                consumed[i] = true;
                                found = true;
                            }
                            Stmt::Assign {
                                src: Expr::CondSelect { .. },
                                ..
                            } => {
                                // The CondSelect already carries the condition code.
                                // Just remove the SetFlags; the CondSelect is unchanged.
                                consumed[i] = true;
                                found = true;
                            }
                            _ => {}
                        }
                        break;
                    }
                }
                let _ = found;
            }
        }
    }

    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        if consumed[i] {
            continue;
        }
        if let Some(replacement) = replacements[i].take() {
            out.push(replacement);
        } else {
            out.push(stmts[i].clone());
        }
    }
    out
}

/// Backward liveness pass: remove `SetFlags` statements whose flags are never
/// read before being overwritten or the block ends.
///
/// Walk backward from the end. Track whether flags are "live" (needed by a
/// downstream reader). When we hit a flag reader, mark live. When we hit
/// `SetFlags`: if live, keep it and mark dead (consumed); if not live, remove it.
pub fn eliminate_dead_flags(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let len = stmts.len();
    let mut keep = vec![true; len];
    let mut flags_live = false;

    for i in (0..len).rev() {
        let stmt = &stmts[i];
        if reads_flags(stmt) {
            flags_live = true;
        } else if writes_flags(stmt) {
            if flags_live {
                // This SetFlags is consumed — keep it, mark flags as no longer live
                // (this SetFlags satisfies the demand).
                flags_live = false;
            } else {
                // Dead SetFlags — remove it.
                keep[i] = false;
            }
        }
        // Other statements don't affect flag liveness.
    }

    stmts
        .into_iter()
        .enumerate()
        .filter(|(i, _)| keep[*i])
        .map(|(_, s)| s)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{Condition, Expr, Reg};

    // ---- Helpers ----

    fn set_flags_sub(lhs: Expr, rhs: Expr) -> Stmt {
        Stmt::SetFlags {
            expr: Expr::Sub(Box::new(lhs), Box::new(rhs)),
        }
    }

    fn set_flags_add(lhs: Expr, rhs: Expr) -> Stmt {
        Stmt::SetFlags {
            expr: Expr::Add(Box::new(lhs), Box::new(rhs)),
        }
    }

    fn set_flags_and(lhs: Expr, rhs: Expr) -> Stmt {
        Stmt::SetFlags {
            expr: Expr::And(Box::new(lhs), Box::new(rhs)),
        }
    }

    fn cond_branch_flag(c: Condition, target: Expr, fallthrough: u64) -> Stmt {
        Stmt::CondBranch {
            cond: BranchCond::Flag(c),
            target,
            fallthrough,
        }
    }

    fn cond_branch_compare(
        c: Condition,
        lhs: Expr,
        rhs: Expr,
        target: Expr,
        fallthrough: u64,
    ) -> Stmt {
        Stmt::CondBranch {
            cond: BranchCond::Compare {
                cond: c,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            },
            target,
            fallthrough,
        }
    }

    fn cond_branch_zero(expr: Expr, target: Expr, fallthrough: u64) -> Stmt {
        Stmt::CondBranch {
            cond: BranchCond::Zero(expr),
            target,
            fallthrough,
        }
    }

    fn assign(dst: Reg, src: Expr) -> Stmt {
        Stmt::Assign { dst, src }
    }

    // ---- Fusion tests ----

    #[test]
    fn cmp_bne_fuses() {
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
            cond_branch_flag(Condition::NE, Expr::Imm(0x1000), 0x104),
        ];
        let result = fuse_flags(input);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            cond_branch_compare(
                Condition::NE,
                Expr::Reg(Reg::X(8)),
                Expr::Imm(1),
                Expr::Imm(0x1000),
                0x104,
            )
        );
    }

    #[test]
    fn cmp_beq_fuses() {
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(42)),
            cond_branch_flag(Condition::EQ, Expr::Imm(0x2000), 0x200),
        ];
        let result = fuse_flags(input);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            cond_branch_compare(
                Condition::EQ,
                Expr::Reg(Reg::X(0)),
                Expr::Imm(42),
                Expr::Imm(0x2000),
                0x200,
            )
        );
    }

    #[test]
    fn cmn_bmi_fuses() {
        let input = vec![
            set_flags_add(Expr::Reg(Reg::X(0)), Expr::Reg(Reg::X(1))),
            cond_branch_flag(Condition::MI, Expr::Imm(0x3000), 0x300),
        ];
        let result = fuse_flags(input);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            cond_branch_compare(
                Condition::MI,
                Expr::Reg(Reg::X(0)),
                Expr::Reg(Reg::X(1)),
                Expr::Imm(0x3000),
                0x300,
            )
        );
    }

    #[test]
    fn tst_beq_fuses() {
        let input = vec![
            set_flags_and(Expr::Reg(Reg::X(0)), Expr::Imm(0xFF)),
            cond_branch_flag(Condition::EQ, Expr::Imm(0x4000), 0x400),
        ];
        let result = fuse_flags(input);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            cond_branch_compare(
                Condition::EQ,
                Expr::Reg(Reg::X(0)),
                Expr::Imm(0xFF),
                Expr::Imm(0x4000),
                0x400,
            )
        );
    }

    #[test]
    fn cmp_with_nop_between() {
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
            Stmt::Nop,
            cond_branch_flag(Condition::NE, Expr::Imm(0x1000), 0x104),
        ];
        let result = fuse_flags(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], Stmt::Nop);
        assert_eq!(
            result[1],
            cond_branch_compare(
                Condition::NE,
                Expr::Reg(Reg::X(8)),
                Expr::Imm(1),
                Expr::Imm(0x1000),
                0x104,
            )
        );
    }

    #[test]
    fn cmp_with_assign_between() {
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
            assign(Reg::X(1), Expr::Imm(5)),
            cond_branch_flag(Condition::NE, Expr::Imm(0x1000), 0x104),
        ];
        let result = fuse_flags(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], assign(Reg::X(1), Expr::Imm(5)));
        assert_eq!(
            result[1],
            cond_branch_compare(
                Condition::NE,
                Expr::Reg(Reg::X(8)),
                Expr::Imm(1),
                Expr::Imm(0x1000),
                0x104,
            )
        );
    }

    #[test]
    fn double_setflags() {
        // Two SetFlags followed by a CondBranch: only the second fuses.
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(10)),
            set_flags_sub(Expr::Reg(Reg::X(1)), Expr::Imm(20)),
            cond_branch_flag(Condition::EQ, Expr::Imm(0x5000), 0x500),
        ];
        let result = fuse_flags(input);
        // First SetFlags stays (dead — eliminated separately), second fuses with branch.
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(10))
        );
        assert_eq!(
            result[1],
            cond_branch_compare(
                Condition::EQ,
                Expr::Reg(Reg::X(1)),
                Expr::Imm(20),
                Expr::Imm(0x5000),
                0x500,
            )
        );
    }

    #[test]
    fn cbz_ignores_flags() {
        // CBZ uses Zero condition, not Flag — SetFlags should NOT fuse.
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
            cond_branch_zero(Expr::Reg(Reg::W(8)), Expr::Imm(0x6000), 0x600),
        ];
        let result = fuse_flags(input);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1))
        );
        assert_eq!(
            result[1],
            cond_branch_zero(Expr::Reg(Reg::W(8)), Expr::Imm(0x6000), 0x600)
        );
    }

    // ---- Dead flag elimination tests ----

    #[test]
    fn dead_setflags_removed() {
        // First SetFlags is overwritten by the second before any reader.
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(10)),
            set_flags_sub(Expr::Reg(Reg::X(1)), Expr::Imm(20)),
            cond_branch_flag(Condition::EQ, Expr::Imm(0x5000), 0x500),
        ];
        let result = eliminate_dead_flags(input);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            set_flags_sub(Expr::Reg(Reg::X(1)), Expr::Imm(20))
        );
        assert_eq!(
            result[1],
            cond_branch_flag(Condition::EQ, Expr::Imm(0x5000), 0x500)
        );
    }

    #[test]
    fn setflags_before_cbz() {
        // CBZ doesn't read flags, so SetFlags is dead.
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
            cond_branch_zero(Expr::Reg(Reg::W(8)), Expr::Imm(0x6000), 0x600),
        ];
        let result = eliminate_dead_flags(input);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            cond_branch_zero(Expr::Reg(Reg::W(8)), Expr::Imm(0x6000), 0x600)
        );
    }

    #[test]
    fn setflags_at_block_end() {
        // SetFlags at end of block with no flag reader after it — dead.
        let input = vec![
            assign(Reg::X(0), Expr::Imm(42)),
            set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(1)),
        ];
        let result = eliminate_dead_flags(input);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], assign(Reg::X(0), Expr::Imm(42)));
    }

    #[test]
    fn live_setflags_preserved() {
        // SetFlags followed immediately by a Flag branch — it's live, keep it.
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
            cond_branch_flag(Condition::NE, Expr::Imm(0x1000), 0x104),
        ];
        let result = eliminate_dead_flags(input.clone());
        assert_eq!(result, input);
    }
}
