use std::collections::{HashMap, HashSet, VecDeque};

use super::construct::SsaFunction;
use super::domtree::DomTree;
use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaValidationIssue {
    pub code: &'static str,
    pub block: Option<BlockId>,
    pub stmt_idx: Option<usize>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsaValidationReport {
    pub is_valid: bool,
    pub issues: Vec<SsaValidationIssue>,
}

pub fn validate_ssa(func: &SsaFunction) -> SsaValidationReport {
    let mut issues = Vec::new();
    let block_map: HashMap<BlockId, _> =
        func.blocks.iter().map(|block| (block.id, block)).collect();
    let defs = collect_def_sites(func, &mut issues);

    validate_cfg_consistency(func, &block_map, &mut issues);
    validate_variable_uses(func, &defs, &mut issues);
    validate_phi_predecessors(func, &mut issues);
    validate_dominators(func, &block_map, &mut issues);
    validate_trivial_phis(func, &mut issues);

    SsaValidationReport {
        is_valid: issues.is_empty(),
        issues,
    }
}

fn collect_def_sites(
    func: &SsaFunction,
    issues: &mut Vec<SsaValidationIssue>,
) -> HashMap<SsaVar, (BlockId, usize)> {
    let mut defs = HashMap::new();
    for block in &func.blocks {
        for (stmt_idx, stmt) in block.stmts.iter().enumerate() {
            match stmt {
                SsaStmt::Assign { dst, .. } => {
                    if let Some((prev_block, prev_stmt_idx)) =
                        defs.insert(*dst, (block.id, stmt_idx))
                    {
                        issues.push(SsaValidationIssue {
                            code: "duplicate_definition",
                            block: Some(block.id),
                            stmt_idx: Some(stmt_idx),
                            message: format!(
                                "SSA variable {:?} is defined more than once (previously at block {} stmt {}).",
                                dst, prev_block, prev_stmt_idx
                            ),
                        });
                    }
                }
                SsaStmt::SetFlags { src, .. } => {
                    if let Some((prev_block, prev_stmt_idx)) =
                        defs.insert(*src, (block.id, stmt_idx))
                    {
                        issues.push(SsaValidationIssue {
                            code: "duplicate_definition",
                            block: Some(block.id),
                            stmt_idx: Some(stmt_idx),
                            message: format!(
                                "SSA variable {:?} is defined more than once (previously at block {} stmt {}).",
                                src, prev_block, prev_stmt_idx
                            ),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    defs
}

fn validate_cfg_consistency(
    func: &SsaFunction,
    block_map: &HashMap<BlockId, &super::construct::SsaBlock>,
    issues: &mut Vec<SsaValidationIssue>,
) {
    for block in &func.blocks {
        for &succ in &block.successors {
            let Some(succ_block) = block_map.get(&succ) else {
                issues.push(SsaValidationIssue {
                    code: "missing_successor_block",
                    block: Some(block.id),
                    stmt_idx: None,
                    message: format!(
                        "Block {} references missing successor block {}.",
                        block.id, succ
                    ),
                });
                continue;
            };
            if !succ_block.predecessors.contains(&block.id) {
                issues.push(SsaValidationIssue {
                    code: "successor_predecessor_mismatch",
                    block: Some(block.id),
                    stmt_idx: None,
                    message: format!(
                        "Block {} lists {} as a successor but the successor does not list it as a predecessor.",
                        block.id, succ
                    ),
                });
            }
        }

        for &pred in &block.predecessors {
            let Some(pred_block) = block_map.get(&pred) else {
                issues.push(SsaValidationIssue {
                    code: "missing_predecessor_block",
                    block: Some(block.id),
                    stmt_idx: None,
                    message: format!(
                        "Block {} references missing predecessor block {}.",
                        block.id, pred
                    ),
                });
                continue;
            };
            if !pred_block.successors.contains(&block.id) {
                issues.push(SsaValidationIssue {
                    code: "predecessor_successor_mismatch",
                    block: Some(block.id),
                    stmt_idx: None,
                    message: format!(
                        "Block {} lists {} as a predecessor but the predecessor does not list it as a successor.",
                        block.id, pred
                    ),
                });
            }
        }
    }
}

fn validate_variable_uses(
    func: &SsaFunction,
    defs: &HashMap<SsaVar, (BlockId, usize)>,
    issues: &mut Vec<SsaValidationIssue>,
) {
    for block in &func.blocks {
        for (stmt_idx, stmt) in block.stmts.iter().enumerate() {
            let mut check_use = |var: SsaVar| {
                if var.version == 0 || defs.contains_key(&var) {
                    return;
                }
                issues.push(SsaValidationIssue {
                    code: "undefined_use",
                    block: Some(block.id),
                    stmt_idx: Some(stmt_idx),
                    message: format!("SSA variable {:?} is used without a definition.", var),
                });
            };

            visit_uses_in_stmt(stmt, &mut check_use);
        }
    }
}

fn validate_phi_predecessors(func: &SsaFunction, issues: &mut Vec<SsaValidationIssue>) {
    for block in &func.blocks {
        let mut expected_preds = block.predecessors.clone();
        expected_preds.sort_unstable();
        expected_preds.dedup();

        for (stmt_idx, stmt) in block.stmts.iter().enumerate() {
            let SsaStmt::Assign {
                src: SsaExpr::Phi(operands),
                ..
            } = stmt
            else {
                continue;
            };

            let mut operand_preds: Vec<_> = operands.iter().map(|(pred, _)| *pred).collect();
            operand_preds.sort_unstable();
            operand_preds.dedup();

            if operand_preds != expected_preds || operands.len() != block.predecessors.len() {
                issues.push(SsaValidationIssue {
                    code: "phi_predecessor_mismatch",
                    block: Some(block.id),
                    stmt_idx: Some(stmt_idx),
                    message: format!(
                        "Phi predecessors {:?} do not match block predecessors {:?}.",
                        operand_preds, expected_preds
                    ),
                });
            }
        }
    }
}

fn validate_dominators(
    func: &SsaFunction,
    block_map: &HashMap<BlockId, &super::construct::SsaBlock>,
    issues: &mut Vec<SsaValidationIssue>,
) {
    if func.blocks.is_empty() {
        return;
    }

    let reachable = compute_reachable(func, block_map, issues);
    let expected_doms = compute_dominators(func, &reachable);
    let dom_tree = DomTree::build(func);

    for block in &func.blocks {
        if !reachable.contains(&block.id) {
            issues.push(SsaValidationIssue {
                code: "unreachable_block",
                block: Some(block.id),
                stmt_idx: None,
                message: format!("Block {} is unreachable from the function entry.", block.id),
            });
            continue;
        }

        if block.id == func.entry {
            if dom_tree.idom(block.id).is_some() {
                issues.push(SsaValidationIssue {
                    code: "entry_has_idom",
                    block: Some(block.id),
                    stmt_idx: None,
                    message: "The entry block should not have an immediate dominator.".to_string(),
                });
            }
            continue;
        }

        let Some(expected_idom) = compute_expected_idom(block.id, &expected_doms) else {
            issues.push(SsaValidationIssue {
                code: "missing_expected_idom",
                block: Some(block.id),
                stmt_idx: None,
                message: format!(
                    "Could not compute an expected immediate dominator for block {}.",
                    block.id
                ),
            });
            continue;
        };

        if dom_tree.idom(block.id) != Some(expected_idom) {
            issues.push(SsaValidationIssue {
                code: "idom_mismatch",
                block: Some(block.id),
                stmt_idx: None,
                message: format!(
                    "Immediate dominator mismatch for block {}: expected {}, got {:?}.",
                    block.id,
                    expected_idom,
                    dom_tree.idom(block.id)
                ),
            });
        }

        for dominator in &reachable {
            let expected = expected_doms
                .get(&block.id)
                .map(|doms| doms.contains(dominator))
                .unwrap_or(false);
            if dom_tree.dominates(*dominator, block.id) != expected {
                issues.push(SsaValidationIssue {
                    code: "dominance_relation_mismatch",
                    block: Some(block.id),
                    stmt_idx: None,
                    message: format!(
                        "Dominance relation mismatch: dominates({}, {}) should be {}.",
                        dominator, block.id, expected
                    ),
                });
            }
        }
    }
}

fn validate_trivial_phis(func: &SsaFunction, issues: &mut Vec<SsaValidationIssue>) {
    for block in &func.blocks {
        for (stmt_idx, stmt) in block.stmts.iter().enumerate() {
            let SsaStmt::Assign {
                dst,
                src: SsaExpr::Phi(operands),
            } = stmt
            else {
                continue;
            };

            if is_trivial_phi(*dst, operands) {
                issues.push(SsaValidationIssue {
                    code: "trivial_phi",
                    block: Some(block.id),
                    stmt_idx: Some(stmt_idx),
                    message: format!("Trivial phi for {:?} survived optimization.", dst),
                });
            }
        }
    }
}

fn compute_reachable(
    func: &SsaFunction,
    block_map: &HashMap<BlockId, &super::construct::SsaBlock>,
    issues: &mut Vec<SsaValidationIssue>,
) -> HashSet<BlockId> {
    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    reachable.insert(func.entry);
    queue.push_back(func.entry);

    while let Some(block_id) = queue.pop_front() {
        let Some(block) = block_map.get(&block_id) else {
            issues.push(SsaValidationIssue {
                code: "missing_entry_block",
                block: Some(block_id),
                stmt_idx: None,
                message: format!("Block {} is missing from the function.", block_id),
            });
            continue;
        };
        for &succ in &block.successors {
            if reachable.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    reachable
}

fn compute_dominators(
    func: &SsaFunction,
    reachable: &HashSet<BlockId>,
) -> HashMap<BlockId, HashSet<BlockId>> {
    let mut doms = HashMap::new();
    for block in &func.blocks {
        if !reachable.contains(&block.id) {
            continue;
        }
        if block.id == func.entry {
            doms.insert(block.id, HashSet::from([block.id]));
        } else {
            doms.insert(block.id, reachable.clone());
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block in &func.blocks {
            if !reachable.contains(&block.id) || block.id == func.entry {
                continue;
            }

            let reachable_preds: Vec<_> = block
                .predecessors
                .iter()
                .copied()
                .filter(|pred| reachable.contains(pred))
                .collect();
            if reachable_preds.is_empty() {
                continue;
            }

            let mut new_set = doms[&reachable_preds[0]].clone();
            for pred in reachable_preds.iter().skip(1) {
                new_set = new_set
                    .intersection(&doms[pred])
                    .copied()
                    .collect::<HashSet<_>>();
            }
            new_set.insert(block.id);

            if doms.get(&block.id) != Some(&new_set) {
                doms.insert(block.id, new_set);
                changed = true;
            }
        }
    }

    doms
}

fn compute_expected_idom(
    block_id: BlockId,
    doms: &HashMap<BlockId, HashSet<BlockId>>,
) -> Option<BlockId> {
    let strict_doms: Vec<_> = doms
        .get(&block_id)?
        .iter()
        .copied()
        .filter(|dom| *dom != block_id)
        .collect();

    strict_doms.into_iter().find(|candidate| {
        doms.get(candidate).is_some_and(|candidate_doms| {
            doms[&block_id]
                .iter()
                .copied()
                .filter(|dom| *dom != block_id && *dom != *candidate)
                .all(|other| candidate_doms.contains(&other))
        })
    })
}

fn is_trivial_phi(dst: SsaVar, operands: &[(BlockId, SsaVar)]) -> bool {
    let mut same = None;
    for &(_, operand) in operands {
        if operand == dst {
            continue;
        }
        match same {
            None => same = Some(operand),
            Some(existing) if existing == operand => {}
            Some(_) => return false,
        }
    }
    same.is_some()
}

fn visit_uses_in_stmt(stmt: &SsaStmt, visit: &mut impl FnMut(SsaVar)) {
    match stmt {
        SsaStmt::Assign { src, .. } => visit_uses_in_expr(src, visit),
        SsaStmt::Store { addr, value, .. } => {
            visit_uses_in_expr(addr, visit);
            visit_uses_in_expr(value, visit);
        }
        SsaStmt::Branch { target } | SsaStmt::Call { target } => {
            visit_uses_in_expr(target, visit);
        }
        SsaStmt::CondBranch { cond, target, .. } => {
            visit_uses_in_branch_cond(cond, visit);
            visit_uses_in_expr(target, visit);
        }
        SsaStmt::SetFlags { src, expr } => {
            visit(*src);
            visit_uses_in_expr(expr, visit);
        }
        SsaStmt::Intrinsic { operands, .. } => {
            for operand in operands {
                visit_uses_in_expr(operand, visit);
            }
        }
        SsaStmt::Pair(a, b) => {
            visit_uses_in_stmt(a, visit);
            visit_uses_in_stmt(b, visit);
        }
        SsaStmt::Ret | SsaStmt::Nop | SsaStmt::Barrier(_) | SsaStmt::Trap { .. } => {}
    }
}

fn visit_uses_in_branch_cond(cond: &SsaBranchCond, visit: &mut impl FnMut(SsaVar)) {
    match cond {
        SsaBranchCond::Flag(_, var) => visit(*var),
        SsaBranchCond::Zero(expr) | SsaBranchCond::NotZero(expr) => {
            visit_uses_in_expr(expr, visit);
        }
        SsaBranchCond::BitZero(expr, _) | SsaBranchCond::BitNotZero(expr, _) => {
            visit_uses_in_expr(expr, visit);
        }
        SsaBranchCond::Compare { lhs, rhs, .. } => {
            visit_uses_in_expr(lhs, visit);
            visit_uses_in_expr(rhs, visit);
        }
    }
}

fn visit_uses_in_expr(expr: &SsaExpr, visit: &mut impl FnMut(SsaVar)) {
    match expr {
        SsaExpr::Var(var) => visit(*var),
        SsaExpr::Phi(operands) => {
            for (_, var) in operands {
                visit(*var);
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
        | SsaExpr::Rbit(addr) => visit_uses_in_expr(addr, visit),
        SsaExpr::SignExtend { src, .. }
        | SsaExpr::ZeroExtend { src, .. }
        | SsaExpr::Extract { src, .. } => visit_uses_in_expr(src, visit),
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
            visit_uses_in_expr(lhs, visit);
            visit_uses_in_expr(rhs, visit);
        }
        SsaExpr::Insert { dst, src, .. } => {
            visit_uses_in_expr(dst, visit);
            visit_uses_in_expr(src, visit);
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => {
            visit_uses_in_expr(if_true, visit);
            visit_uses_in_expr(if_false, visit);
        }
        SsaExpr::Compare { lhs, rhs, .. } => {
            visit_uses_in_expr(lhs, visit);
            visit_uses_in_expr(rhs, visit);
        }
        SsaExpr::Intrinsic { operands, .. } => {
            for operand in operands {
                visit_uses_in_expr(operand, visit);
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
    use crate::ssa::construct::{SsaBlock, SsaFunction};

    fn var(n: u8, version: u32) -> SsaVar {
        SsaVar {
            loc: RegLocation::Gpr(n),
            version,
            width: RegWidth::W64,
        }
    }

    fn block(
        id: BlockId,
        stmts: Vec<SsaStmt>,
        successors: Vec<BlockId>,
        predecessors: Vec<BlockId>,
    ) -> SsaBlock {
        SsaBlock {
            id,
            addr: id as u64 * 4,
            stmts,
            successors,
            predecessors,
        }
    }

    #[test]
    fn validator_accepts_well_formed_ssa() {
        let v1 = var(0, 1);
        let v2 = var(0, 2);
        let v3 = var(0, 3);
        let func = SsaFunction {
            entry: 0,
            blocks: vec![
                block(
                    0,
                    vec![
                        SsaStmt::Assign {
                            dst: v1,
                            src: SsaExpr::Imm(1),
                        },
                        SsaStmt::CondBranch {
                            cond: SsaBranchCond::Zero(SsaExpr::Imm(0)),
                            target: SsaExpr::Imm(0x8),
                            fallthrough: 2,
                        },
                    ],
                    vec![1, 2],
                    vec![],
                ),
                block(
                    1,
                    vec![SsaStmt::Assign {
                        dst: v2,
                        src: SsaExpr::Var(v1),
                    }],
                    vec![2],
                    vec![0],
                ),
                block(
                    2,
                    vec![SsaStmt::Assign {
                        dst: v3,
                        src: SsaExpr::Phi(vec![(0, v1), (1, v2)]),
                    }],
                    vec![],
                    vec![0, 1],
                ),
            ],
        };

        let report = validate_ssa(&func);
        assert!(report.is_valid, "{:?}", report.issues);
    }

    #[test]
    fn validator_reports_undefined_variable_use() {
        let func = SsaFunction {
            entry: 0,
            blocks: vec![block(
                0,
                vec![SsaStmt::Assign {
                    dst: var(0, 1),
                    src: SsaExpr::Var(var(1, 7)),
                }],
                vec![],
                vec![],
            )],
        };

        let report = validate_ssa(&func);
        assert!(!report.is_valid);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.code == "undefined_use"));
    }

    #[test]
    fn validator_reports_phi_predecessor_mismatch() {
        let v1 = var(0, 1);
        let func = SsaFunction {
            entry: 0,
            blocks: vec![
                block(0, vec![], vec![2], vec![]),
                block(1, vec![], vec![2], vec![]),
                block(
                    2,
                    vec![SsaStmt::Assign {
                        dst: var(0, 2),
                        src: SsaExpr::Phi(vec![(0, v1)]),
                    }],
                    vec![],
                    vec![0, 1],
                ),
            ],
        };

        let report = validate_ssa(&func);
        assert!(!report.is_valid);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.code == "phi_predecessor_mismatch"));
    }

    #[test]
    fn validator_reports_unreachable_block_dom_issue() {
        let func = SsaFunction {
            entry: 0,
            blocks: vec![
                block(0, vec![SsaStmt::Ret], vec![], vec![]),
                block(1, vec![SsaStmt::Ret], vec![], vec![]),
            ],
        };

        let report = validate_ssa(&func);
        assert!(!report.is_valid);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.code == "unreachable_block"));
    }

    #[test]
    fn validator_reports_trivial_phi() {
        let v1 = var(0, 1);
        let func = SsaFunction {
            entry: 0,
            blocks: vec![
                block(0, vec![], vec![2], vec![]),
                block(1, vec![], vec![2], vec![]),
                block(
                    2,
                    vec![SsaStmt::Assign {
                        dst: var(0, 2),
                        src: SsaExpr::Phi(vec![(0, v1), (1, v1)]),
                    }],
                    vec![],
                    vec![0, 1],
                ),
            ],
        };

        let report = validate_ssa(&func);
        assert!(!report.is_valid);
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.code == "trivial_phi"));
    }
}
