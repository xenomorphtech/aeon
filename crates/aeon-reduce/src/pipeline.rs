//! Reduction pipeline -- sequences the individual peephole passes (const,
//! adrp, movk, pair, flags, ext) in the correct order for intra-block
//! reduction.

use std::collections::HashSet;

use aeonil::{Expr, Stmt};

use crate::reduce_adrp::resolve_adrp_add_with_stats;
use crate::reduce_const::fold_constants;
use crate::reduce_ext::fold_extensions;
use crate::reduce_flags::{eliminate_dead_flags, fuse_flags_with_stats};
use crate::reduce_movk::resolve_movk_chains_with_stats;
use crate::reduce_pair::flatten_pairs;
use crate::reduce_stack::{detect_prologue, recognize_stack_frame, rewrite_stack_accesses};
use crate::ssa::cfg::{build_cfg, Cfg};
use crate::ssa::construct::{build_ssa, SsaFunction};
use crate::ssa::pipeline::optimize_ssa;
use crate::ssa::types::{SsaBranchCond, SsaExpr, SsaStmt, SsaVar};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReductionMetrics {
    pub eligible_stack_accesses: usize,
    pub stack_slots_recognized: usize,
    pub adrp_resolutions: usize,
    pub flag_fusions: usize,
    pub movk_chain_resolutions: usize,
    pub ssa_vars_before_optimization: usize,
    pub ssa_vars_after_optimization: usize,
    pub intrinsic_instructions: usize,
    pub proper_il_instructions: usize,
}

impl ReductionMetrics {
    pub fn intrinsic_to_proper_il_ratio(&self) -> f64 {
        if self.proper_il_instructions == 0 {
            return 0.0;
        }
        self.intrinsic_instructions as f64 / self.proper_il_instructions as f64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct BlockReductionMetrics {
    adrp_resolutions: usize,
    flag_fusions: usize,
    movk_chain_resolutions: usize,
}

fn reduce_block_local_with_metrics(stmts: Vec<Stmt>) -> (Vec<Stmt>, BlockReductionMetrics) {
    let stmts = flatten_pairs(stmts); // 1. structural
    let stmts = fold_constants(stmts); // 2. expression-level
    let (stmts, adrp_resolutions) = resolve_adrp_add_with_stats(stmts); // 3. multi-stmt, RegisterEnv
    let (stmts, movk_chain_resolutions) = resolve_movk_chains_with_stats(stmts); // 4. multi-stmt, RegisterEnv
    let stmts = fold_constants(stmts); // 5. again (ADRP/MOVK may produce foldable exprs)
    let (stmts, flag_fusions) = fuse_flags_with_stats(stmts); // 6. multi-stmt, flag tracking
    let stmts = eliminate_dead_flags(stmts); // 7. liveness
    let stmts = fold_extensions(stmts); // 8. expression-level

    (
        stmts,
        BlockReductionMetrics {
            adrp_resolutions,
            flag_fusions,
            movk_chain_resolutions,
        },
    )
}

/// Apply only the block-local reductions.
pub fn reduce_block_local(stmts: Vec<Stmt>) -> Vec<Stmt> {
    reduce_block_local_with_metrics(stmts).0
}

/// Apply the historical single-block pipeline, including immediate stack-frame
/// recognition when the block contains the full prologue context.
pub fn reduce_block(stmts: Vec<Stmt>) -> Vec<Stmt> {
    recognize_stack_frame(reduce_block_local(stmts))
}

/// Apply the canonical function-level reduction pipeline to a lifted function.
///
/// This is the shared path that should feed SSA, API serialization, evaluation,
/// and future fact extraction. Block-local passes still run per block, but
/// stack-slot rewriting uses one shared prologue from the function entry.
pub fn reduce_function_cfg(instructions: &[(u64, Stmt, Vec<u64>)]) -> Cfg {
    let mut cfg = build_cfg(instructions);

    for block in &mut cfg.blocks {
        block.stmts = reduce_block_local(std::mem::take(&mut block.stmts));
    }

    let prologue = cfg
        .blocks
        .get(cfg.entry as usize)
        .and_then(|entry| detect_prologue(&entry.stmts));

    if let Some(prologue) = prologue.as_ref() {
        for block in &mut cfg.blocks {
            block.stmts = rewrite_stack_accesses(std::mem::take(&mut block.stmts), prologue);
        }
    }

    cfg
}

/// Apply the canonical function-level reduction pipeline and collect
/// reduction/SSA quality metrics from the same canonical path.
pub fn reduce_function_cfg_with_metrics(
    instructions: &[(u64, Stmt, Vec<u64>)],
) -> (Cfg, ReductionMetrics) {
    let mut metrics = ReductionMetrics::default();
    for (_, stmt, _) in instructions {
        accumulate_instruction_quality(stmt, &mut metrics);
    }

    let mut cfg = build_cfg(instructions);
    for block in &mut cfg.blocks {
        let (stmts, block_metrics) =
            reduce_block_local_with_metrics(std::mem::take(&mut block.stmts));
        block.stmts = stmts;
        metrics.adrp_resolutions += block_metrics.adrp_resolutions;
        metrics.flag_fusions += block_metrics.flag_fusions;
        metrics.movk_chain_resolutions += block_metrics.movk_chain_resolutions;
    }

    let prologue = cfg
        .blocks
        .get(cfg.entry as usize)
        .and_then(|entry| detect_prologue(&entry.stmts));

    if let Some(prologue) = prologue.as_ref() {
        metrics.eligible_stack_accesses = cfg
            .blocks
            .iter()
            .map(|block| count_eligible_stack_accesses(&block.stmts, prologue.has_frame_pointer))
            .sum();

        for block in &mut cfg.blocks {
            block.stmts = rewrite_stack_accesses(std::mem::take(&mut block.stmts), prologue);
        }

        metrics.stack_slots_recognized = cfg
            .blocks
            .iter()
            .map(|block| count_recognized_stack_slots(&block.stmts))
            .sum();
    }

    let ssa_before = build_ssa(&cfg);
    metrics.ssa_vars_before_optimization = count_ssa_vars(&ssa_before);

    let mut ssa_after = ssa_before.clone();
    optimize_ssa(&mut ssa_after);
    metrics.ssa_vars_after_optimization = count_ssa_vars(&ssa_after);

    (cfg, metrics)
}

/// Collect only the reduction metrics for a lifted function.
pub fn collect_reduction_metrics(instructions: &[(u64, Stmt, Vec<u64>)]) -> ReductionMetrics {
    reduce_function_cfg_with_metrics(instructions).1
}

fn accumulate_instruction_quality(stmt: &Stmt, metrics: &mut ReductionMetrics) {
    match stmt {
        Stmt::Nop => {}
        Stmt::Intrinsic { .. } => metrics.intrinsic_instructions += 1,
        Stmt::Assign {
            src: Expr::Intrinsic { .. },
            ..
        } => metrics.intrinsic_instructions += 1,
        Stmt::Pair(_, _) => metrics.proper_il_instructions += 1,
        _ => metrics.proper_il_instructions += 1,
    }
}

fn count_eligible_stack_accesses(stmts: &[Stmt], has_frame_pointer: bool) -> usize {
    stmts
        .iter()
        .filter(|stmt| match stmt {
            Stmt::Assign {
                src: Expr::Load { addr, .. },
                ..
            } => is_eligible_stack_addr(addr, has_frame_pointer),
            Stmt::Store { addr, .. } => is_eligible_stack_addr(addr, has_frame_pointer),
            _ => false,
        })
        .count()
}

fn is_eligible_stack_addr(expr: &Expr, has_frame_pointer: bool) -> bool {
    match expr {
        Expr::Reg(aeonil::Reg::SP) => true,
        Expr::Add(base, offset) => match (base.as_ref(), offset.as_ref()) {
            (Expr::Reg(aeonil::Reg::SP), Expr::Imm(_)) => true,
            (Expr::Reg(aeonil::Reg::X(29)), Expr::Imm(_)) if has_frame_pointer => true,
            _ => false,
        },
        Expr::Reg(aeonil::Reg::X(29)) if has_frame_pointer => true,
        _ => false,
    }
}

fn count_recognized_stack_slots(stmts: &[Stmt]) -> usize {
    stmts
        .iter()
        .filter(|stmt| match stmt {
            Stmt::Assign {
                src: Expr::Load { addr, .. },
                ..
            } => matches!(addr.as_ref(), Expr::StackSlot { .. }),
            Stmt::Store { addr, .. } => matches!(addr, Expr::StackSlot { .. }),
            _ => false,
        })
        .count()
}

fn count_ssa_vars(func: &SsaFunction) -> usize {
    let mut vars = HashSet::new();
    for block in &func.blocks {
        for stmt in &block.stmts {
            collect_ssa_vars_in_stmt(stmt, &mut vars);
        }
    }
    vars.len()
}

fn collect_ssa_vars_in_stmt(stmt: &SsaStmt, vars: &mut HashSet<SsaVar>) {
    match stmt {
        SsaStmt::Assign { dst, src } => {
            vars.insert(*dst);
            collect_ssa_vars_in_expr(src, vars);
        }
        SsaStmt::Store { addr, value, .. } => {
            collect_ssa_vars_in_expr(addr, vars);
            collect_ssa_vars_in_expr(value, vars);
        }
        SsaStmt::Branch { target } | SsaStmt::Call { target } => {
            collect_ssa_vars_in_expr(target, vars);
        }
        SsaStmt::CondBranch { cond, target, .. } => {
            collect_ssa_vars_in_branch_cond(cond, vars);
            collect_ssa_vars_in_expr(target, vars);
        }
        SsaStmt::SetFlags { src, expr } => {
            vars.insert(*src);
            collect_ssa_vars_in_expr(expr, vars);
        }
        SsaStmt::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_ssa_vars_in_expr(operand, vars);
            }
        }
        SsaStmt::Pair(a, b) => {
            collect_ssa_vars_in_stmt(a, vars);
            collect_ssa_vars_in_stmt(b, vars);
        }
        SsaStmt::Ret | SsaStmt::Nop | SsaStmt::Barrier(_) | SsaStmt::Trap { .. } => {}
    }
}

fn collect_ssa_vars_in_branch_cond(cond: &SsaBranchCond, vars: &mut HashSet<SsaVar>) {
    match cond {
        SsaBranchCond::Flag(_, var) => {
            vars.insert(*var);
        }
        SsaBranchCond::Zero(expr) | SsaBranchCond::NotZero(expr) => {
            collect_ssa_vars_in_expr(expr, vars);
        }
        SsaBranchCond::BitZero(expr, _) | SsaBranchCond::BitNotZero(expr, _) => {
            collect_ssa_vars_in_expr(expr, vars);
        }
        SsaBranchCond::Compare { lhs, rhs, .. } => {
            collect_ssa_vars_in_expr(lhs, vars);
            collect_ssa_vars_in_expr(rhs, vars);
        }
    }
}

fn collect_ssa_vars_in_expr(expr: &SsaExpr, vars: &mut HashSet<SsaVar>) {
    match expr {
        SsaExpr::Var(var) => {
            vars.insert(*var);
        }
        SsaExpr::Phi(operands) => {
            for (_, var) in operands {
                vars.insert(*var);
            }
        }
        SsaExpr::Load { addr, .. }
        | SsaExpr::Neg(addr)
        | SsaExpr::Abs(addr)
        | SsaExpr::Not(addr)
        | SsaExpr::FNeg(addr)
        | SsaExpr::FAbs(addr)
        | SsaExpr::FSqrt(addr)
        | SsaExpr::FCvt(addr)
        | SsaExpr::IntToFloat(addr)
        | SsaExpr::FloatToInt(addr)
        | SsaExpr::Clz(addr)
        | SsaExpr::Cls(addr)
        | SsaExpr::Rev(addr)
        | SsaExpr::Rbit(addr) => {
            collect_ssa_vars_in_expr(addr, vars);
        }
        SsaExpr::SignExtend { src, .. }
        | SsaExpr::ZeroExtend { src, .. }
        | SsaExpr::Extract { src, .. } => {
            collect_ssa_vars_in_expr(src, vars);
        }
        SsaExpr::Add(lhs, rhs)
        | SsaExpr::Sub(lhs, rhs)
        | SsaExpr::Mul(lhs, rhs)
        | SsaExpr::Div(lhs, rhs)
        | SsaExpr::UDiv(lhs, rhs)
        | SsaExpr::And(lhs, rhs)
        | SsaExpr::Or(lhs, rhs)
        | SsaExpr::Xor(lhs, rhs)
        | SsaExpr::Shl(lhs, rhs)
        | SsaExpr::Lsr(lhs, rhs)
        | SsaExpr::Asr(lhs, rhs)
        | SsaExpr::Ror(lhs, rhs)
        | SsaExpr::FAdd(lhs, rhs)
        | SsaExpr::FSub(lhs, rhs)
        | SsaExpr::FMul(lhs, rhs)
        | SsaExpr::FDiv(lhs, rhs)
        | SsaExpr::FMax(lhs, rhs)
        | SsaExpr::FMin(lhs, rhs) => {
            collect_ssa_vars_in_expr(lhs, vars);
            collect_ssa_vars_in_expr(rhs, vars);
        }
        SsaExpr::Insert { dst, src, .. } => {
            collect_ssa_vars_in_expr(dst, vars);
            collect_ssa_vars_in_expr(src, vars);
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => {
            collect_ssa_vars_in_expr(if_true, vars);
            collect_ssa_vars_in_expr(if_false, vars);
        }
        SsaExpr::Compare { lhs, rhs, .. } => {
            collect_ssa_vars_in_expr(lhs, vars);
            collect_ssa_vars_in_expr(rhs, vars);
        }
        SsaExpr::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_ssa_vars_in_expr(operand, vars);
            }
        }
        SsaExpr::Imm(_)
        | SsaExpr::FImm(_)
        | SsaExpr::StackSlot { .. }
        | SsaExpr::MrsRead(_)
        | SsaExpr::AdrpImm(_)
        | SsaExpr::AdrImm(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, e_load, Expr, Reg};

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

    #[test]
    fn pipeline_recognizes_stack_frame_in_single_block() {
        let input = vec![
            Stmt::Pair(
                Box::new(Stmt::Store {
                    addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-16i64) as u64)),
                    value: Expr::Reg(Reg::X(29)),
                    size: 8,
                }),
                Box::new(Stmt::Store {
                    addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-8i64) as u64)),
                    value: Expr::Reg(Reg::X(30)),
                    size: 8,
                }),
            ),
            Stmt::Assign {
                dst: Reg::X(29),
                src: Expr::Reg(Reg::SP),
            },
            Stmt::Assign {
                dst: Reg::X(0),
                src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
            },
        ];

        let result = reduce_block(input);
        assert_eq!(result.len(), 4);
        assert_eq!(
            result[0],
            Stmt::Store {
                addr: Expr::StackSlot {
                    offset: -16,
                    size: 8,
                },
                value: Expr::Reg(Reg::X(29)),
                size: 8,
            }
        );
        assert_eq!(
            result[1],
            Stmt::Store {
                addr: Expr::StackSlot {
                    offset: -8,
                    size: 8
                },
                value: Expr::Reg(Reg::X(30)),
                size: 8,
            }
        );
        assert_eq!(
            result[3],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Load {
                    addr: Box::new(Expr::StackSlot { offset: 8, size: 8 }),
                    size: 8,
                },
            }
        );
    }

    #[test]
    fn reduce_function_cfg_rewrites_stack_accesses_across_blocks() {
        let instructions = vec![
            (
                0x1000,
                Stmt::Pair(
                    Box::new(Stmt::Store {
                        addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-16i64) as u64)),
                        value: Expr::Reg(Reg::X(29)),
                        size: 8,
                    }),
                    Box::new(Stmt::Store {
                        addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-8i64) as u64)),
                        value: Expr::Reg(Reg::X(30)),
                        size: 8,
                    }),
                ),
                vec![0x1004],
            ),
            (
                0x1004,
                Stmt::Assign {
                    dst: Reg::X(29),
                    src: Expr::Reg(Reg::SP),
                },
                vec![0x1008],
            ),
            (
                0x1008,
                Stmt::CondBranch {
                    cond: aeonil::BranchCond::Zero(Expr::Imm(0)),
                    target: Expr::Imm(0x1010),
                    fallthrough: 0x1014,
                },
                vec![0x1010, 0x1014],
            ),
            (
                0x1010,
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
                },
                vec![0x1014],
            ),
            (0x1014, Stmt::Ret, vec![]),
        ];

        let cfg = reduce_function_cfg(&instructions);
        let load_block = cfg
            .blocks
            .iter()
            .find(|block| block.addr == 0x1010)
            .expect("missing load block");
        assert_eq!(
            load_block.stmts[0],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Load {
                    addr: Box::new(Expr::StackSlot { offset: 8, size: 8 }),
                    size: 8,
                },
            }
        );
    }
}
