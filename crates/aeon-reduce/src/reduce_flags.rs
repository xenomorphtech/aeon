//! Flag-expression simplification -- replaces `SetFlags` + `CondBranch`
//! patterns with direct comparisons when the flag-setting expression and
//! the condition code are simple enough (e.g., CMP+BEQ -> branch-if-equal).
//!
//! Two sub-passes:
//! 1. `fuse_flags` — forward scan that rewrites a flag-reading `CondBranch`
//!    into a comparison of the operands of the `SetFlags` it depends on. It
//!    never removes the `SetFlags`.
//! 2. `eliminate_dead_flags` — backward scan that removes a `SetFlags` whose
//!    flags nothing can read. Within one block the flags are assumed live at
//!    the end; `eliminate_dead_flags_cfg` works that out across a function.

use aeonil::{BranchCond, Condition, Expr, IntrinsicOp, Reg, Stmt};

use crate::env::{expr_any, regs_alias, regs_in};
use crate::ssa::cfg::Cfg;

/// What may observe NZCV where control leaves the code being reduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagBoundary {
    /// Nothing is assumed: a call or a return may read the flags.
    Opaque,
    /// AAPCS64: the flags carry nothing into or out of a call or a return.
    Aapcs64,
}

/// What a statement does to NZCV. `reads` means it reads the flags as they
/// were before the statement; `writes` means it replaces all four.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlagEffect {
    reads: bool,
    writes: bool,
}

fn expr_reads_flags(expr: &Expr) -> bool {
    expr_any(expr, &|expr| match expr {
        Expr::CondSelect { .. } | Expr::Reg(Reg::Flags) => true,
        Expr::MrsRead(name) => name.eq_ignore_ascii_case("nzcv"),
        Expr::Intrinsic { name, .. } => matches!(
            name.op(),
            // An intrinsic nothing gives semantics to may be anything.
            IntrinsicOp::Adc | IntrinsicOp::Sbc | IntrinsicOp::Ngc | IntrinsicOp::Other
        ),
        _ => false,
    })
}

fn branch_cond_reads_flags(cond: &BranchCond) -> bool {
    match cond {
        BranchCond::Flag(_) => true,
        BranchCond::Zero(expr)
        | BranchCond::NotZero(expr)
        | BranchCond::BitZero(expr, _)
        | BranchCond::BitNotZero(expr, _) => expr_reads_flags(expr),
        BranchCond::Compare { lhs, rhs, .. } => expr_reads_flags(lhs) || expr_reads_flags(rhs),
    }
}

fn flag_effect(stmt: &Stmt, boundary: FlagBoundary) -> FlagEffect {
    let opaque = boundary == FlagBoundary::Opaque;
    let (reads, writes) = match stmt {
        Stmt::Assign { dst, src } => (expr_reads_flags(src), *dst == Reg::Flags),
        Stmt::Store { addr, value, .. } => (expr_reads_flags(addr) || expr_reads_flags(value), false),
        // `ccmp` is a `SetFlags` of a `CondSelect`: it reads, then writes.
        Stmt::SetFlags { expr } => (expr_reads_flags(expr), true),
        Stmt::Branch { target } => (expr_reads_flags(target), false),
        Stmt::CondBranch { cond, target, .. } => {
            (branch_cond_reads_flags(cond) || expr_reads_flags(target), false)
        }
        // Under AAPCS64 the callee neither receives nor preserves the flags.
        Stmt::Call { target } => (opaque || expr_reads_flags(target), !opaque),
        Stmt::Ret => (opaque, !opaque),
        // An exception handler sees PSTATE.
        Stmt::Trap { .. } => (true, false),
        Stmt::Nop | Stmt::Barrier(_) => (false, false),
        Stmt::Pair(first, second) => {
            let first = flag_effect(first, boundary);
            let second = flag_effect(second, boundary);
            (
                first.reads || (!first.writes && second.reads),
                first.writes || second.writes,
            )
        }
        Stmt::Intrinsic { name, operands } => {
            let operands_read = operands.iter().any(expr_reads_flags);
            match name.op() {
                IntrinsicOp::Adcs
                | IntrinsicOp::Sbcs
                | IntrinsicOp::Ngcs
                | IntrinsicOp::Fccmp
                | IntrinsicOp::Fccmpe => (true, true),
                // `msr nzcv, x` names the register as an intrinsic operand,
                // which `expr_reads_flags` already treats as a read.
                IntrinsicOp::Other => (true, false),
                _ => (operands_read, false),
            }
        }
    };
    FlagEffect { reads, writes }
}

/// The comparison a flag-setting expression stands for under `cond`, as
/// operands of a `Compare` (which is evaluated as `lhs - rhs`), or `None` if
/// that condition cannot be expressed that way.
fn extract_comparison(expr: &Expr, cond: Condition) -> Option<(Expr, Expr)> {
    use Condition::{EQ, GE, GT, LE, LT, MI, NE, PL};
    match expr {
        // CMP: the flags are those of the subtraction itself.
        Expr::Sub(lhs, rhs) => Some((*lhs.clone(), *rhs.clone())),
        // TST: N and Z come from the result and C and V are clear. Comparing
        // the result with zero gives the same N, Z and V but sets C, so
        // only conditions that ignore C carry over.
        Expr::And(..) if matches!(cond, EQ | NE | MI | PL | GE | LT | GT | LE) => {
            Some((expr.clone(), Expr::Imm(0)))
        }
        // CMN: C and V are those of the addition, which a comparison with
        // zero does not reproduce. N and Z still come from the result.
        Expr::Add(..) if matches!(cond, EQ | NE | MI | PL) => Some((expr.clone(), Expr::Imm(0))),
        _ => None,
    }
}

/// True if running `stmt` can change the value of an expression that reads
/// `regs` (and memory, if `reads_memory`).
fn may_change(stmt: &Stmt, regs: &[Reg], reads_memory: bool) -> bool {
    let clobbers = |written: &Reg| regs.iter().any(|reg| regs_alias(written, reg));
    match stmt {
        Stmt::Assign { dst, .. } => clobbers(dst),
        Stmt::Store { .. } => reads_memory,
        Stmt::Call { .. } => true,
        // It may write memory, or any register it names.
        Stmt::Intrinsic { operands, .. } => {
            reads_memory || operands.iter().flat_map(regs_in).any(|reg| clobbers(&reg))
        }
        Stmt::Pair(first, second) => {
            may_change(first, regs, reads_memory) || may_change(second, regs, reads_memory)
        }
        _ => false,
    }
}

/// Forward fusion pass: rewrite a `CondBranch` on a flag condition into a
/// comparison of the operands of the `SetFlags` that produced the flags.
///
/// For `SetFlags { expr: Sub(lhs, rhs) }` ... `CondBranch { cond: Flag(c) }`:
///   -> `CondBranch { cond: Compare { cond: c, lhs, rhs } }`
///
/// `TST` and `CMN` fuse only for the conditions a comparison with zero
/// reproduces. Nothing fuses if a statement in between changes an operand.
/// The `SetFlags` stays; `eliminate_dead_flags` removes it if nothing else
/// reads the flags.
pub fn fuse_flags(stmts: Vec<Stmt>) -> Vec<Stmt> {
    fuse_flags_with_stats(stmts).0
}

pub(crate) fn fuse_flags_with_stats(mut stmts: Vec<Stmt>) -> (Vec<Stmt>, usize) {
    let mut fusions = 0usize;

    for i in 0..stmts.len() {
        let Stmt::SetFlags { expr } = &stmts[i] else {
            continue;
        };
        if expr_reads_flags(expr) {
            continue;
        }
        let expr = expr.clone();
        let regs = regs_in(&expr);
        let reads_memory = expr_any(&expr, &|expr| matches!(expr, Expr::Load { .. }));

        for j in (i + 1)..stmts.len() {
            if let Stmt::CondBranch {
                cond: BranchCond::Flag(cond),
                target,
                fallthrough,
            } = &stmts[j]
            {
                if let Some((lhs, rhs)) = extract_comparison(&expr, *cond) {
                    stmts[j] = Stmt::CondBranch {
                        cond: BranchCond::Compare {
                            cond: *cond,
                            lhs: Box::new(lhs),
                            rhs: Box::new(rhs),
                        },
                        target: target.clone(),
                        fallthrough: *fallthrough,
                    };
                    fusions += 1;
                }
                break;
            }
            // Past here the flags are someone else's, or the operands are
            // no longer what was compared.
            if flag_effect(&stmts[j], FlagBoundary::Opaque).writes
                || may_change(&stmts[j], &regs, reads_memory)
            {
                break;
            }
        }
    }

    (stmts, fusions)
}

/// Backward liveness pass over one block, assuming nothing about what
/// follows it: the flags are live at the end, and a call or return may read
/// them. Removes only a `SetFlags` that is overwritten before any read.
pub fn eliminate_dead_flags(stmts: Vec<Stmt>) -> Vec<Stmt> {
    eliminate_dead_flags_with(stmts, true, FlagBoundary::Opaque)
}

/// Backward liveness pass: remove `SetFlags` statements whose flags are never
/// read. `live_out` says whether anything after the last statement may read
/// the flags.
pub fn eliminate_dead_flags_with(
    stmts: Vec<Stmt>,
    live_out: bool,
    boundary: FlagBoundary,
) -> Vec<Stmt> {
    let mut keep = vec![true; stmts.len()];
    let mut live = live_out;

    for (index, stmt) in stmts.iter().enumerate().rev() {
        if matches!(stmt, Stmt::SetFlags { .. }) && !live {
            // Its only effect is the flags, and nothing reads them.
            keep[index] = false;
            continue;
        }
        let effect = flag_effect(stmt, boundary);
        live = effect.reads || (live && !effect.writes);
    }

    stmts
        .into_iter()
        .zip(keep)
        .filter_map(|(stmt, keep)| keep.then_some(stmt))
        .collect()
}

/// Removes dead `SetFlags` across a function: the flags are live at the end
/// of a block only if a successor reads them before writing them. Calls and
/// returns follow AAPCS64 (see [`FlagBoundary::Aapcs64`]); a block that
/// leaves the function any other way keeps its flags live.
pub fn eliminate_dead_flags_cfg(cfg: &mut Cfg) {
    let boundary = FlagBoundary::Aapcs64;
    let count = cfg.blocks.len();

    // Per block: are the flags read before being written, and are they
    // written at all?
    let summaries: Vec<FlagEffect> = cfg
        .blocks
        .iter()
        .map(|block| {
            block.stmts.iter().rev().fold(
                FlagEffect {
                    reads: false,
                    writes: false,
                },
                |after, stmt| {
                    let effect = flag_effect(stmt, boundary);
                    FlagEffect {
                        reads: effect.reads || (!effect.writes && after.reads),
                        writes: effect.writes || after.writes,
                    }
                },
            )
        })
        .collect();

    let leaves_function = |block: &crate::ssa::cfg::BasicBlock| {
        block.successors.is_empty() && !matches!(block.stmts.last(), Some(Stmt::Ret))
    };
    let mut live_in = vec![false; count];
    let mut live_out: Vec<bool> = cfg.blocks.iter().map(leaves_function).collect();
    let mut changed = true;
    while changed {
        changed = false;
        for index in (0..count).rev() {
            let block = &cfg.blocks[index];
            let out = live_out[index]
                || block
                    .successors
                    .iter()
                    .any(|successor| live_in.get(*successor as usize).copied().unwrap_or(true));
            let summary = summaries[index];
            let into = summary.reads || (out && !summary.writes);
            if out != live_out[index] || into != live_in[index] {
                live_out[index] = out;
                live_in[index] = into;
                changed = true;
            }
        }
    }

    for (block, live_out) in cfg.blocks.iter_mut().zip(live_out) {
        block.stmts =
            eliminate_dead_flags_with(std::mem::take(&mut block.stmts), live_out, boundary);
    }
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

    fn set_flags(expr: Expr) -> Stmt {
        Stmt::SetFlags { expr }
    }

    fn sub(lhs: Expr, rhs: Expr) -> Expr {
        Expr::Sub(Box::new(lhs), Box::new(rhs))
    }

    fn select(cond: Condition) -> Expr {
        Expr::CondSelect {
            cond,
            if_true: Box::new(Expr::Imm(1)),
            if_false: Box::new(Expr::Imm(0)),
        }
    }

    /// Both sub-passes, with the flags dead after the last statement.
    fn fuse_then_drop_dead(stmts: Vec<Stmt>) -> Vec<Stmt> {
        eliminate_dead_flags_with(fuse_flags(stmts), false, FlagBoundary::Opaque)
    }

    // ---- Fusion tests ----

    #[test]
    fn cmp_branch_fuses_and_keeps_the_setflags() {
        let cmp = set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1));
        let input = vec![
            cmp.clone(),
            cond_branch_flag(Condition::NE, Expr::Imm(0x1000), 0x104),
        ];
        let fused = cond_branch_compare(
            Condition::NE,
            Expr::Reg(Reg::X(8)),
            Expr::Imm(1),
            Expr::Imm(0x1000),
            0x104,
        );
        // Fusion alone cannot know the flags are unused afterwards.
        assert_eq!(fuse_flags(input.clone()), vec![cmp, fused.clone()]);
        assert_eq!(fuse_then_drop_dead(input), vec![fused]);
    }

    #[test]
    fn cmp_fuses_for_every_condition() {
        for cond in [Condition::EQ, Condition::HI, Condition::VS, Condition::LT] {
            let input = vec![
                set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(42)),
                cond_branch_flag(cond, Expr::Imm(0x2000), 0x200),
            ];
            assert_eq!(
                fuse_then_drop_dead(input),
                vec![cond_branch_compare(
                    cond,
                    Expr::Reg(Reg::X(0)),
                    Expr::Imm(42),
                    Expr::Imm(0x2000),
                    0x200,
                )]
            );
        }
    }

    #[test]
    fn cmn_fuses_as_a_comparison_of_the_sum_with_zero() {
        let sum = Expr::Add(
            Box::new(Expr::Reg(Reg::X(0))),
            Box::new(Expr::Reg(Reg::X(1))),
        );
        let input = vec![
            set_flags(sum.clone()),
            cond_branch_flag(Condition::MI, Expr::Imm(0x3000), 0x300),
        ];
        assert_eq!(
            fuse_then_drop_dead(input),
            vec![cond_branch_compare(
                Condition::MI,
                sum,
                Expr::Imm(0),
                Expr::Imm(0x3000),
                0x300,
            )]
        );
    }

    #[test]
    fn cmn_does_not_fuse_conditions_that_need_its_carry_or_overflow() {
        for cond in [Condition::CS, Condition::HI, Condition::GE, Condition::VS] {
            let input = vec![
                set_flags_add(Expr::Reg(Reg::X(0)), Expr::Reg(Reg::X(1))),
                cond_branch_flag(cond, Expr::Imm(0x3000), 0x300),
            ];
            assert_eq!(fuse_then_drop_dead(input.clone()), input);
        }
    }

    #[test]
    fn tst_fuses_as_a_comparison_of_the_mask_with_zero() {
        let masked = Expr::And(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(0xFF)));
        let input = vec![
            set_flags(masked.clone()),
            cond_branch_flag(Condition::EQ, Expr::Imm(0x4000), 0x400),
        ];
        assert_eq!(
            fuse_then_drop_dead(input),
            vec![cond_branch_compare(
                Condition::EQ,
                masked,
                Expr::Imm(0),
                Expr::Imm(0x4000),
                0x400,
            )]
        );
    }

    #[test]
    fn tst_does_not_fuse_conditions_that_read_carry() {
        // TST clears C; comparing with zero would set it.
        let input = vec![
            set_flags_and(Expr::Reg(Reg::X(0)), Expr::Imm(0xFF)),
            cond_branch_flag(Condition::HI, Expr::Imm(0x4000), 0x400),
        ];
        assert_eq!(fuse_then_drop_dead(input.clone()), input);
    }

    #[test]
    fn cmp_fuses_across_statements_that_leave_its_operands_alone() {
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
            Stmt::Nop,
            assign(Reg::X(1), Expr::Imm(5)),
            cond_branch_flag(Condition::NE, Expr::Imm(0x1000), 0x104),
        ];
        assert_eq!(
            fuse_then_drop_dead(input),
            vec![
                Stmt::Nop,
                assign(Reg::X(1), Expr::Imm(5)),
                cond_branch_compare(
                    Condition::NE,
                    Expr::Reg(Reg::X(8)),
                    Expr::Imm(1),
                    Expr::Imm(0x1000),
                    0x104,
                ),
            ]
        );
    }

    #[test]
    fn cmp_does_not_fuse_once_an_operand_is_redefined() {
        // The branch must compare the old x8; only the flags still hold it.
        // Writing w8 redefines x8 as well.
        for redefined in [Reg::X(8), Reg::W(8)] {
            let input = vec![
                set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
                assign(redefined, Expr::Imm(5)),
                cond_branch_flag(Condition::NE, Expr::Imm(0x1000), 0x104),
            ];
            assert_eq!(fuse_then_drop_dead(input.clone()), input);
        }
    }

    #[test]
    fn cmp_of_a_load_does_not_fuse_across_a_store() {
        let loaded = Expr::Load {
            addr: Box::new(Expr::Reg(Reg::X(0))),
            size: 8,
        };
        let input = vec![
            set_flags_sub(loaded, Expr::Imm(1)),
            Stmt::Store {
                addr: Expr::Reg(Reg::X(1)),
                value: Expr::Imm(0),
                size: 8,
            },
            cond_branch_flag(Condition::NE, Expr::Imm(0x1000), 0x104),
        ];
        assert_eq!(fuse_then_drop_dead(input.clone()), input);
    }

    #[test]
    fn double_setflags() {
        // Only the second SetFlags reaches the branch; the first is dead.
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(10)),
            set_flags_sub(Expr::Reg(Reg::X(1)), Expr::Imm(20)),
            cond_branch_flag(Condition::EQ, Expr::Imm(0x5000), 0x500),
        ];
        assert_eq!(
            fuse_then_drop_dead(input),
            vec![cond_branch_compare(
                Condition::EQ,
                Expr::Reg(Reg::X(1)),
                Expr::Imm(20),
                Expr::Imm(0x5000),
                0x500,
            )]
        );
    }

    #[test]
    fn cbz_ignores_flags() {
        // CBZ uses Zero condition, not Flag — SetFlags should NOT fuse.
        let input = vec![
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
            cond_branch_zero(Expr::Reg(Reg::W(8)), Expr::Imm(0x6000), 0x600),
        ];
        assert_eq!(fuse_flags(input.clone()), input);
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
        assert_eq!(eliminate_dead_flags(input.clone()), input[1..].to_vec());
    }

    #[test]
    fn flags_are_live_at_the_end_of_a_block_unless_told_otherwise() {
        // CBZ doesn't read flags, but the next block might.
        let input = vec![
            assign(Reg::X(0), Expr::Imm(42)),
            set_flags_sub(Expr::Reg(Reg::X(8)), Expr::Imm(1)),
            cond_branch_zero(Expr::Reg(Reg::W(8)), Expr::Imm(0x6000), 0x600),
        ];
        assert_eq!(eliminate_dead_flags(input.clone()), input);
        assert_eq!(
            eliminate_dead_flags_with(input.clone(), false, FlagBoundary::Opaque),
            vec![input[0].clone(), input[2].clone()]
        );
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

    #[test]
    fn every_kind_of_flag_reader_keeps_the_setflags() {
        let readers = [
            // csel/cset
            assign(Reg::X(9), select(Condition::CS)),
            // adc: an expression that adds the carry
            assign(
                Reg::X(9),
                Expr::Intrinsic {
                    name: "adc".into(),
                    operands: vec![Expr::Reg(Reg::X(1)), Expr::Reg(Reg::X(2))],
                },
            ),
            // adcs: reads the carry, then sets the flags
            Stmt::Intrinsic {
                name: "adcs".into(),
                operands: vec![
                    Expr::Reg(Reg::X(9)),
                    Expr::Reg(Reg::X(1)),
                    Expr::Reg(Reg::X(2)),
                ],
            },
            // mrs x9, nzcv
            assign(Reg::X(9), Expr::MrsRead("nzcv".into())),
        ];
        for reader in readers {
            let input = vec![
                set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(1)),
                reader,
                // Makes the flags dead after the reader.
                set_flags_sub(Expr::Reg(Reg::X(3)), Expr::Imm(1)),
            ];
            let result = eliminate_dead_flags_with(input.clone(), false, FlagBoundary::Opaque);
            assert_eq!(result, input[..2].to_vec(), "{:?}", input[1]);
        }
    }

    #[test]
    fn ccmp_reads_the_flags_it_then_replaces() {
        // ccmp: flags from a compare or an immediate, chosen by the flags.
        let ccmp = set_flags(Expr::CondSelect {
            cond: Condition::EQ,
            if_true: Box::new(sub(Expr::Reg(Reg::X(1)), Expr::Reg(Reg::X(2)))),
            if_false: Box::new(Expr::Imm(4)),
        });
        let cmp = set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(1));
        let live = vec![
            cmp.clone(),
            ccmp.clone(),
            assign(Reg::X(9), select(Condition::NE)),
        ];
        assert_eq!(fuse_then_drop_dead(live.clone()), live);
        // With no reader after it, the ccmp is dead, and then so is the cmp.
        assert_eq!(fuse_then_drop_dead(vec![cmp, ccmp]), vec![]);
    }

    #[test]
    fn calls_and_returns_read_flags_unless_aapcs64_is_assumed() {
        for boundary_stmt in [
            Stmt::Call {
                target: Expr::Imm(0x9000),
            },
            Stmt::Ret,
        ] {
            let input = vec![
                set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(1)),
                boundary_stmt,
            ];
            assert_eq!(
                eliminate_dead_flags_with(input.clone(), false, FlagBoundary::Opaque),
                input
            );
            assert_eq!(
                eliminate_dead_flags_with(input.clone(), true, FlagBoundary::Aapcs64),
                input[1..].to_vec()
            );
        }
    }

    // ---- Function-level liveness ----

    fn cfg_of(blocks: Vec<(Vec<Stmt>, Vec<u32>)>) -> Cfg {
        let blocks = blocks
            .into_iter()
            .enumerate()
            .map(|(id, (stmts, successors))| crate::ssa::cfg::BasicBlock {
                id: id as u32,
                addr: 0x1000 + id as u64 * 0x10,
                stmts,
                successors,
                predecessors: Vec::new(),
            })
            .collect();
        Cfg {
            entry: 0,
            blocks,
            block_map: Default::default(),
        }
    }

    #[test]
    fn cfg_keeps_flags_a_successor_reads_and_drops_the_rest() {
        let cmp = set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(1));
        let mut cfg = cfg_of(vec![
            // Flags read in block 2, through block 1 which leaves them alone.
            (vec![cmp.clone()], vec![1]),
            (vec![assign(Reg::X(5), Expr::Imm(0))], vec![2]),
            (
                vec![assign(Reg::X(9), select(Condition::EQ)), cmp.clone()],
                vec![3],
            ),
            // Nothing after the second compare reads flags before returning.
            (vec![Stmt::Ret], vec![]),
        ]);
        eliminate_dead_flags_cfg(&mut cfg);
        assert_eq!(cfg.blocks[0].stmts, vec![cmp]);
        assert_eq!(
            cfg.blocks[2].stmts,
            vec![assign(Reg::X(9), select(Condition::EQ))]
        );
    }

    #[test]
    fn cfg_keeps_flags_live_where_control_leaves_by_a_tail_jump() {
        let cmp = set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(1));
        let tail = Stmt::Branch {
            target: Expr::Reg(Reg::X(16)),
        };
        let mut cfg = cfg_of(vec![(vec![cmp.clone(), tail.clone()], vec![])]);
        eliminate_dead_flags_cfg(&mut cfg);
        assert_eq!(cfg.blocks[0].stmts, vec![cmp, tail]);
    }

    #[test]
    fn cfg_handles_loops() {
        // Block 1 loops on itself; the compare at its end feeds the select
        // at its start on the next iteration.
        let cmp = set_flags_sub(Expr::Reg(Reg::X(0)), Expr::Imm(1));
        let body = vec![assign(Reg::X(9), select(Condition::EQ)), cmp.clone()];
        let mut cfg = cfg_of(vec![
            (vec![cmp.clone()], vec![1]),
            (body.clone(), vec![1, 2]),
            (vec![Stmt::Ret], vec![]),
        ]);
        eliminate_dead_flags_cfg(&mut cfg);
        assert_eq!(cfg.blocks[0].stmts, vec![cmp]);
        assert_eq!(cfg.blocks[1].stmts, body);
    }
}
