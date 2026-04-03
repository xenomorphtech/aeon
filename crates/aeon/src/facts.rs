use std::collections::{HashMap, HashSet};

use aeon_reduce::pipeline::reduce_function_cfg;
use aeon_reduce::ssa::construct::{build_ssa, SsaFunction};
use aeon_reduce::ssa::domtree::DomTree;
use aeon_reduce::ssa::types::{BlockId, RegLocation, SsaBranchCond, SsaExpr, SsaStmt, SsaVar};
use aeon_reduce::ssa::use_def::UseDefMap;
use aeonil::Condition;

use crate::il::Stmt;
use crate::lifter;

#[derive(Debug, Clone)]
pub struct LiftedInstruction {
    pub addr: u64,
    pub disasm: String,
    pub stmt: Stmt,
    pub edges: Vec<u64>,
}

pub struct FunctionAnalysis {
    pub func_addr: u64,
    pub lifted: Vec<LiftedInstruction>,
    pub reduced_cfg: aeon_reduce::ssa::cfg::Cfg,
    pub ssa: SsaFunction,
    pub use_def: UseDefMap,
    pub dom_tree: DomTree,
    pub facts: FunctionFacts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StmtSite {
    pub block: BlockId,
    pub stmt_idx: usize,
}

impl StmtSite {
    pub fn encoded_id(self) -> u64 {
        ((self.block as u64) << 32) | self.stmt_idx as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StackSlotId(pub usize);

#[derive(Debug, Clone, PartialEq)]
pub struct DefinitionFact {
    pub stmt: StmtSite,
    pub var: SsaVar,
    pub expr: SsaExpr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UseFact {
    pub var: SsaVar,
    pub stmt: StmtSite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstantFact {
    pub var: SsaVar,
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackAccessFact {
    pub stmt: StmtSite,
    pub slot: StackSlotId,
    pub offset: i64,
    pub width: u8,
    pub is_store: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallTargetFact {
    pub stmt: StmtSite,
    pub addr: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BranchConditionFact {
    pub block: BlockId,
    pub stmt: StmtSite,
    pub cond: SsaBranchCond,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DominatesFact {
    pub dominator: BlockId,
    pub dominated: BlockId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternSpec {
    LoopByteSwap,
    LoopKeystreamXor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternMatch {
    ByteSwap {
        load1: StmtSite,
        load2: StmtSite,
        store1: StmtSite,
        store2: StmtSite,
    },
    KeystreamXor {
        stmt: StmtSite,
    },
}

#[derive(Debug, Clone)]
pub struct FunctionFacts {
    defines: Vec<DefinitionFact>,
    uses: Vec<UseFact>,
    constant_at: Vec<ConstantFact>,
    stack_accesses: Vec<StackAccessFact>,
    call_targets: Vec<CallTargetFact>,
    branch_conditions: Vec<BranchConditionFact>,
    dominates: Vec<DominatesFact>,
    defs_by_var: HashMap<SsaVar, Vec<usize>>,
    uses_by_var: HashMap<SsaVar, Vec<usize>>,
    dominates_lookup: HashSet<(BlockId, BlockId)>,
    loop_blocks: HashSet<BlockId>,
    stmts: HashMap<StmtSite, SsaStmt>,
    stmt_order: Vec<StmtSite>,
    block_addrs: HashMap<BlockId, u64>,
}

pub fn analyze_function(raw_bytes: &[u8], func_addr: u64) -> FunctionAnalysis {
    let lifted = decode_and_lift(raw_bytes, func_addr);
    let instructions: Vec<(u64, Stmt, Vec<u64>)> = lifted
        .iter()
        .map(|inst| (inst.addr, inst.stmt.clone(), inst.edges.clone()))
        .collect();
    let reduced_cfg = reduce_function_cfg(&instructions);
    let ssa = build_ssa(&reduced_cfg);
    let use_def = UseDefMap::build(&ssa);
    let dom_tree = DomTree::build(&ssa);
    let facts = FunctionFacts::from_analysis(&ssa, &use_def, &dom_tree);

    FunctionAnalysis {
        func_addr,
        lifted,
        reduced_cfg,
        ssa,
        use_def,
        dom_tree,
        facts,
    }
}

pub fn extract_function_facts(func: &SsaFunction) -> FunctionFacts {
    FunctionFacts::from_ssa(func)
}

impl FunctionFacts {
    pub fn from_ssa(func: &SsaFunction) -> Self {
        let use_def = UseDefMap::build(func);
        let dom_tree = DomTree::build(func);
        Self::from_analysis(func, &use_def, &dom_tree)
    }

    pub(crate) fn from_analysis(
        func: &SsaFunction,
        _use_def: &UseDefMap,
        dom_tree: &DomTree,
    ) -> Self {
        let mut defines = Vec::new();
        let mut uses = Vec::new();
        let mut uses_seen: HashSet<(SsaVar, StmtSite)> = HashSet::new();
        let mut stack_accesses = Vec::new();
        let mut call_targets = Vec::new();
        let mut branch_conditions = Vec::new();
        let mut stmts = HashMap::new();
        let mut stmt_order = Vec::new();
        let mut block_addrs = HashMap::new();
        let mut stack_slots: HashMap<(i64, u8), StackSlotId> = HashMap::new();
        let mut next_slot_id = 0usize;

        for block in &func.blocks {
            block_addrs.insert(block.id, block.addr);

            for (stmt_idx, stmt) in block.stmts.iter().enumerate() {
                let site = StmtSite {
                    block: block.id,
                    stmt_idx,
                };
                stmt_order.push(site);
                stmts.insert(site, stmt.clone());
                collect_defs_in_stmt(stmt, site, &mut defines);
                collect_uses_in_stmt(stmt, site, &mut uses, &mut uses_seen);
                collect_stmt_structure_facts(
                    stmt,
                    site,
                    block.id,
                    &mut stack_accesses,
                    &mut call_targets,
                    &mut branch_conditions,
                    &mut stack_slots,
                    &mut next_slot_id,
                );
            }
        }

        sort_defs(&mut defines);
        sort_uses(&mut uses);
        sort_stack_accesses(&mut stack_accesses);
        call_targets.sort_by_key(|fact| (fact.stmt.block, fact.stmt.stmt_idx, fact.addr));
        branch_conditions.sort_by_key(|fact| (fact.block, fact.stmt.stmt_idx));
        stmt_order.sort();

        let constant_at = solve_constants(&defines);
        let dominates = collect_dominates(func, dom_tree);
        let dominates_lookup = dominates
            .iter()
            .map(|fact| (fact.dominator, fact.dominated))
            .collect();
        let loop_blocks = collect_loop_blocks(func, dom_tree);

        let mut defs_by_var: HashMap<SsaVar, Vec<usize>> = HashMap::new();
        for (idx, fact) in defines.iter().enumerate() {
            defs_by_var.entry(fact.var).or_default().push(idx);
        }

        let mut uses_by_var: HashMap<SsaVar, Vec<usize>> = HashMap::new();
        for (idx, fact) in uses.iter().enumerate() {
            uses_by_var.entry(fact.var).or_default().push(idx);
        }

        FunctionFacts {
            defines,
            uses,
            constant_at,
            stack_accesses,
            call_targets,
            branch_conditions,
            dominates,
            defs_by_var,
            uses_by_var,
            dominates_lookup,
            loop_blocks,
            stmts,
            stmt_order,
            block_addrs,
        }
    }

    pub fn definitions(&self) -> &[DefinitionFact] {
        &self.defines
    }

    pub fn uses(&self) -> &[UseFact] {
        &self.uses
    }

    pub fn get_defs_of(&self, var: SsaVar) -> Vec<&DefinitionFact> {
        self.defs_by_var
            .get(&var)
            .into_iter()
            .flat_map(|indexes| indexes.iter().map(|idx| &self.defines[*idx]))
            .collect()
    }

    pub fn get_uses_of(&self, var: SsaVar) -> Vec<&UseFact> {
        self.uses_by_var
            .get(&var)
            .into_iter()
            .flat_map(|indexes| indexes.iter().map(|idx| &self.uses[*idx]))
            .collect()
    }

    pub fn get_constants(&self) -> &[ConstantFact] {
        &self.constant_at
    }

    pub fn get_stack_accesses(&self) -> &[StackAccessFact] {
        &self.stack_accesses
    }

    pub fn call_targets(&self) -> &[CallTargetFact] {
        &self.call_targets
    }

    pub fn branch_conditions(&self) -> &[BranchConditionFact] {
        &self.branch_conditions
    }

    pub fn dominance_facts(&self) -> &[DominatesFact] {
        &self.dominates
    }

    pub fn block_dominates(&self, dominator: BlockId, dominated: BlockId) -> bool {
        self.dominates_lookup.contains(&(dominator, dominated))
    }

    pub fn find_pattern(&self, pattern_spec: PatternSpec) -> Vec<PatternMatch> {
        match pattern_spec {
            PatternSpec::LoopByteSwap => self.find_loop_byte_swap(),
            PatternSpec::LoopKeystreamXor => self.find_loop_keystream_xor(),
        }
    }

    pub(crate) fn stmt(&self, site: StmtSite) -> Option<&SsaStmt> {
        self.stmts.get(&site)
    }

    pub(crate) fn stmt_sites(&self) -> &[StmtSite] {
        &self.stmt_order
    }

    pub(crate) fn stmt_address(&self, site: StmtSite) -> u64 {
        self.block_addrs
            .get(&site.block)
            .copied()
            .unwrap_or_default()
            .wrapping_add(site.stmt_idx as u64)
    }

    pub(crate) fn is_in_loop(&self, site: StmtSite) -> bool {
        self.loop_blocks.contains(&site.block)
    }

    pub(crate) fn has_immediate_value(&self, value: u64) -> bool {
        self.defines
            .iter()
            .any(|fact| expr_contains_immediate(&fact.expr, value))
            || self
                .branch_conditions
                .iter()
                .any(|fact| branch_cond_contains_immediate(&fact.cond, value))
    }

    pub(crate) fn has_and_mask(&self, mask: u64) -> bool {
        self.stmt_order
            .iter()
            .filter_map(|site| self.stmts.get(site))
            .any(|stmt| stmt_contains_and_mask(stmt, mask))
    }

    fn find_loop_byte_swap(&self) -> Vec<PatternMatch> {
        let byte_loads: Vec<(StmtSite, SsaVar)> = self
            .defines
            .iter()
            .filter_map(|fact| is_byte_load_expr(&fact.expr).then_some((fact.stmt, fact.var)))
            .collect();
        let byte_stores: Vec<(StmtSite, SsaVar)> = self
            .stmt_order
            .iter()
            .filter_map(|site| match self.stmts.get(site) {
                Some(SsaStmt::Store { value, size: 1, .. }) => {
                    expr_var(value).map(|var| (*site, var))
                }
                _ => None,
            })
            .collect();

        let mut matches = Vec::new();
        for (load1, val_a) in &byte_loads {
            for (load2, val_b) in &byte_loads {
                if load1 == load2 {
                    continue;
                }
                if load1.encoded_id() >= load2.encoded_id() {
                    continue;
                }
                for (store1, stored_val1) in &byte_stores {
                    for (store2, stored_val2) in &byte_stores {
                        if store1 == store2 {
                            continue;
                        }
                        if store1.encoded_id() >= store2.encoded_id() {
                            continue;
                        }
                        if stored_val1 == val_b
                            && stored_val2 == val_a
                            && self.is_in_loop(*load1)
                            && self.is_in_loop(*store1)
                        {
                            matches.push(PatternMatch::ByteSwap {
                                load1: *load1,
                                load2: *load2,
                                store1: *store1,
                                store2: *store2,
                            });
                        }
                    }
                }
            }
        }

        sort_pattern_matches(&mut matches);
        matches.dedup();
        matches
    }

    fn find_loop_keystream_xor(&self) -> Vec<PatternMatch> {
        let byte_load_vars: HashSet<SsaVar> = self
            .defines
            .iter()
            .filter_map(|fact| is_byte_load_expr(&fact.expr).then_some(fact.var))
            .collect();
        let mut matches = Vec::new();

        for fact in &self.defines {
            let SsaExpr::Xor(lhs, rhs) = &fact.expr else {
                continue;
            };
            let lhs_var = expr_var(lhs);
            let rhs_var = expr_var(rhs);
            if !self.is_in_loop(fact.stmt) {
                continue;
            }
            if lhs_var.is_some_and(|var| byte_load_vars.contains(&var))
                || rhs_var.is_some_and(|var| byte_load_vars.contains(&var))
            {
                matches.push(PatternMatch::KeystreamXor { stmt: fact.stmt });
            }
        }

        sort_pattern_matches(&mut matches);
        matches.dedup();
        matches
    }
}

fn decode_and_lift(raw_bytes: &[u8], func_addr: u64) -> Vec<LiftedInstruction> {
    let mut lifted = Vec::new();
    let mut offset = 0usize;
    let mut pc = func_addr;

    while offset + 4 <= raw_bytes.len() {
        let word = u32::from_le_bytes(raw_bytes[offset..offset + 4].try_into().unwrap());
        let next_pc = if offset + 8 <= raw_bytes.len() {
            Some(pc + 4)
        } else {
            None
        };

        let lifted_inst = match bad64::decode(word, pc) {
            Ok(insn) => {
                let result = lifter::lift(&insn, pc, next_pc);
                LiftedInstruction {
                    addr: pc,
                    disasm: result.disasm,
                    stmt: result.stmt,
                    edges: result.edges,
                }
            }
            Err(_) => LiftedInstruction {
                addr: pc,
                disasm: "(invalid)".to_string(),
                stmt: Stmt::Nop,
                edges: next_pc.into_iter().collect(),
            },
        };
        lifted.push(lifted_inst);

        offset += 4;
        pc += 4;
    }

    lifted
}

fn collect_defs_in_stmt(stmt: &SsaStmt, site: StmtSite, defines: &mut Vec<DefinitionFact>) {
    match stmt {
        SsaStmt::Assign { dst, src } => defines.push(DefinitionFact {
            stmt: site,
            var: *dst,
            expr: src.clone(),
        }),
        SsaStmt::SetFlags { src, expr } => defines.push(DefinitionFact {
            stmt: site,
            var: *src,
            expr: expr.clone(),
        }),
        SsaStmt::Pair(a, b) => {
            collect_defs_in_stmt(a, site, defines);
            collect_defs_in_stmt(b, site, defines);
        }
        _ => {}
    }
}

fn collect_uses_in_expr(
    expr: &SsaExpr,
    site: StmtSite,
    uses: &mut Vec<UseFact>,
    uses_seen: &mut HashSet<(SsaVar, StmtSite)>,
) {
    match expr {
        SsaExpr::Var(var) => push_use(*var, site, uses, uses_seen),
        SsaExpr::Phi(operands) => {
            for (_, var) in operands {
                push_use(*var, site, uses, uses_seen);
            }
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
            collect_uses_in_expr(lhs, site, uses, uses_seen);
            collect_uses_in_expr(rhs, site, uses, uses_seen);
        }
        SsaExpr::Insert { dst, src, .. } => {
            collect_uses_in_expr(dst, site, uses, uses_seen);
            collect_uses_in_expr(src, site, uses, uses_seen);
        }
        SsaExpr::Compare { lhs, rhs, .. } => {
            collect_uses_in_expr(lhs, site, uses, uses_seen);
            collect_uses_in_expr(rhs, site, uses, uses_seen);
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => {
            collect_uses_in_expr(if_true, site, uses, uses_seen);
            collect_uses_in_expr(if_false, site, uses, uses_seen);
        }
        SsaExpr::Neg(expr)
        | SsaExpr::Abs(expr)
        | SsaExpr::Not(expr)
        | SsaExpr::FNeg(expr)
        | SsaExpr::FAbs(expr)
        | SsaExpr::FSqrt(expr)
        | SsaExpr::FCvt(expr)
        | SsaExpr::IntToFloat(expr)
        | SsaExpr::FloatToInt(expr)
        | SsaExpr::Clz(expr)
        | SsaExpr::Cls(expr)
        | SsaExpr::Rev(expr)
        | SsaExpr::Rbit(expr) => collect_uses_in_expr(expr, site, uses, uses_seen),
        SsaExpr::SignExtend { src, .. }
        | SsaExpr::ZeroExtend { src, .. }
        | SsaExpr::Extract { src, .. }
        | SsaExpr::Load { addr: src, .. } => collect_uses_in_expr(src, site, uses, uses_seen),
        SsaExpr::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_uses_in_expr(operand, site, uses, uses_seen);
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

fn collect_uses_in_branch_cond(
    cond: &SsaBranchCond,
    site: StmtSite,
    uses: &mut Vec<UseFact>,
    uses_seen: &mut HashSet<(SsaVar, StmtSite)>,
) {
    match cond {
        SsaBranchCond::Flag(_, var) => push_use(*var, site, uses, uses_seen),
        SsaBranchCond::Zero(expr) | SsaBranchCond::NotZero(expr) => {
            collect_uses_in_expr(expr, site, uses, uses_seen);
        }
        SsaBranchCond::BitZero(expr, _) | SsaBranchCond::BitNotZero(expr, _) => {
            collect_uses_in_expr(expr, site, uses, uses_seen);
        }
        SsaBranchCond::Compare { lhs, rhs, .. } => {
            collect_uses_in_expr(lhs, site, uses, uses_seen);
            collect_uses_in_expr(rhs, site, uses, uses_seen);
        }
    }
}

fn collect_uses_in_stmt(
    stmt: &SsaStmt,
    site: StmtSite,
    uses: &mut Vec<UseFact>,
    uses_seen: &mut HashSet<(SsaVar, StmtSite)>,
) {
    match stmt {
        SsaStmt::Assign { src, .. } => collect_uses_in_expr(src, site, uses, uses_seen),
        SsaStmt::Store { addr, value, .. } => {
            collect_uses_in_expr(addr, site, uses, uses_seen);
            collect_uses_in_expr(value, site, uses, uses_seen);
        }
        SsaStmt::Branch { target } => collect_uses_in_expr(target, site, uses, uses_seen),
        SsaStmt::CondBranch { cond, target, .. } => {
            collect_uses_in_branch_cond(cond, site, uses, uses_seen);
            collect_uses_in_expr(target, site, uses, uses_seen);
        }
        SsaStmt::Call { target } => collect_uses_in_expr(target, site, uses, uses_seen),
        SsaStmt::SetFlags { src, expr } => {
            push_use(*src, site, uses, uses_seen);
            collect_uses_in_expr(expr, site, uses, uses_seen);
        }
        SsaStmt::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_uses_in_expr(operand, site, uses, uses_seen);
            }
        }
        SsaStmt::Pair(a, b) => {
            collect_uses_in_stmt(a, site, uses, uses_seen);
            collect_uses_in_stmt(b, site, uses, uses_seen);
        }
        SsaStmt::Ret | SsaStmt::Nop | SsaStmt::Barrier(_) | SsaStmt::Trap => {}
    }
}

fn collect_stmt_structure_facts(
    stmt: &SsaStmt,
    site: StmtSite,
    block: BlockId,
    stack_accesses: &mut Vec<StackAccessFact>,
    call_targets: &mut Vec<CallTargetFact>,
    branch_conditions: &mut Vec<BranchConditionFact>,
    stack_slots: &mut HashMap<(i64, u8), StackSlotId>,
    next_slot_id: &mut usize,
) {
    match stmt {
        SsaStmt::Assign { src, .. } => {
            collect_stack_loads_in_expr(src, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaStmt::Store { addr, value, size } => {
            collect_stack_loads_in_expr(addr, site, stack_accesses, stack_slots, next_slot_id);
            collect_stack_loads_in_expr(value, site, stack_accesses, stack_slots, next_slot_id);
            if let Some((offset, slot_size)) = stack_slot_expr(addr) {
                let slot = intern_stack_slot(offset, slot_size, stack_slots, next_slot_id);
                stack_accesses.push(StackAccessFact {
                    stmt: site,
                    slot,
                    offset,
                    width: *size,
                    is_store: true,
                });
            }
        }
        SsaStmt::Branch { target } => {
            collect_stack_loads_in_expr(target, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaStmt::CondBranch { cond, target, .. } => {
            collect_stack_loads_in_branch_cond(
                cond,
                site,
                stack_accesses,
                stack_slots,
                next_slot_id,
            );
            collect_stack_loads_in_expr(target, site, stack_accesses, stack_slots, next_slot_id);
            branch_conditions.push(BranchConditionFact {
                block,
                stmt: site,
                cond: cond.clone(),
            });
        }
        SsaStmt::Call { target } => {
            collect_stack_loads_in_expr(target, site, stack_accesses, stack_slots, next_slot_id);
            if let Some(addr) = call_target_expr(target) {
                call_targets.push(CallTargetFact { stmt: site, addr });
            }
        }
        SsaStmt::SetFlags { expr, .. } => {
            collect_stack_loads_in_expr(expr, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaStmt::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_stack_loads_in_expr(
                    operand,
                    site,
                    stack_accesses,
                    stack_slots,
                    next_slot_id,
                );
            }
        }
        SsaStmt::Pair(a, b) => {
            collect_stmt_structure_facts(
                a,
                site,
                block,
                stack_accesses,
                call_targets,
                branch_conditions,
                stack_slots,
                next_slot_id,
            );
            collect_stmt_structure_facts(
                b,
                site,
                block,
                stack_accesses,
                call_targets,
                branch_conditions,
                stack_slots,
                next_slot_id,
            );
        }
        SsaStmt::Ret | SsaStmt::Nop | SsaStmt::Barrier(_) | SsaStmt::Trap => {}
    }
}

fn collect_stack_loads_in_expr(
    expr: &SsaExpr,
    site: StmtSite,
    stack_accesses: &mut Vec<StackAccessFact>,
    stack_slots: &mut HashMap<(i64, u8), StackSlotId>,
    next_slot_id: &mut usize,
) {
    match expr {
        SsaExpr::Load { addr, size } => {
            if let Some((offset, slot_size)) = stack_slot_expr(addr) {
                let slot = intern_stack_slot(offset, slot_size, stack_slots, next_slot_id);
                stack_accesses.push(StackAccessFact {
                    stmt: site,
                    slot,
                    offset,
                    width: *size,
                    is_store: false,
                });
            }
            collect_stack_loads_in_expr(addr, site, stack_accesses, stack_slots, next_slot_id);
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
            collect_stack_loads_in_expr(lhs, site, stack_accesses, stack_slots, next_slot_id);
            collect_stack_loads_in_expr(rhs, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaExpr::Insert { dst, src, .. } => {
            collect_stack_loads_in_expr(dst, site, stack_accesses, stack_slots, next_slot_id);
            collect_stack_loads_in_expr(src, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaExpr::Compare { lhs, rhs, .. } => {
            collect_stack_loads_in_expr(lhs, site, stack_accesses, stack_slots, next_slot_id);
            collect_stack_loads_in_expr(rhs, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => {
            collect_stack_loads_in_expr(if_true, site, stack_accesses, stack_slots, next_slot_id);
            collect_stack_loads_in_expr(if_false, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaExpr::Neg(expr)
        | SsaExpr::Abs(expr)
        | SsaExpr::Not(expr)
        | SsaExpr::FNeg(expr)
        | SsaExpr::FAbs(expr)
        | SsaExpr::FSqrt(expr)
        | SsaExpr::FCvt(expr)
        | SsaExpr::IntToFloat(expr)
        | SsaExpr::FloatToInt(expr)
        | SsaExpr::Clz(expr)
        | SsaExpr::Cls(expr)
        | SsaExpr::Rev(expr)
        | SsaExpr::Rbit(expr)
        | SsaExpr::SignExtend { src: expr, .. }
        | SsaExpr::ZeroExtend { src: expr, .. }
        | SsaExpr::Extract { src: expr, .. } => {
            collect_stack_loads_in_expr(expr, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaExpr::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_stack_loads_in_expr(
                    operand,
                    site,
                    stack_accesses,
                    stack_slots,
                    next_slot_id,
                );
            }
        }
        SsaExpr::Phi(_)
        | SsaExpr::Var(_)
        | SsaExpr::Imm(_)
        | SsaExpr::FImm(_)
        | SsaExpr::StackSlot { .. }
        | SsaExpr::MrsRead(_)
        | SsaExpr::AdrpImm(_)
        | SsaExpr::AdrImm(_) => {}
    }
}

fn collect_stack_loads_in_branch_cond(
    cond: &SsaBranchCond,
    site: StmtSite,
    stack_accesses: &mut Vec<StackAccessFact>,
    stack_slots: &mut HashMap<(i64, u8), StackSlotId>,
    next_slot_id: &mut usize,
) {
    match cond {
        SsaBranchCond::Flag(_, _) => {}
        SsaBranchCond::Zero(expr) | SsaBranchCond::NotZero(expr) => {
            collect_stack_loads_in_expr(expr, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaBranchCond::BitZero(expr, _) | SsaBranchCond::BitNotZero(expr, _) => {
            collect_stack_loads_in_expr(expr, site, stack_accesses, stack_slots, next_slot_id);
        }
        SsaBranchCond::Compare { lhs, rhs, .. } => {
            collect_stack_loads_in_expr(lhs, site, stack_accesses, stack_slots, next_slot_id);
            collect_stack_loads_in_expr(rhs, site, stack_accesses, stack_slots, next_slot_id);
        }
    }
}

fn push_use(
    var: SsaVar,
    site: StmtSite,
    uses: &mut Vec<UseFact>,
    uses_seen: &mut HashSet<(SsaVar, StmtSite)>,
) {
    if uses_seen.insert((var, site)) {
        uses.push(UseFact { var, stmt: site });
    }
}

fn sort_defs(defines: &mut [DefinitionFact]) {
    defines.sort_by_key(|fact| {
        (
            fact.stmt.block,
            fact.stmt.stmt_idx,
            loc_sort_key(&fact.var.loc),
            fact.var.version,
        )
    });
}

fn sort_uses(uses: &mut [UseFact]) {
    uses.sort_by_key(|fact| {
        (
            loc_sort_key(&fact.var.loc),
            fact.var.version,
            fact.stmt.block,
            fact.stmt.stmt_idx,
        )
    });
}

fn sort_stack_accesses(accesses: &mut [StackAccessFact]) {
    accesses.sort_by_key(|fact| {
        (
            fact.stmt.block,
            fact.stmt.stmt_idx,
            fact.offset,
            fact.width,
            fact.is_store,
        )
    });
}

fn sort_pattern_matches(matches: &mut [PatternMatch]) {
    matches.sort_by_key(|entry| match entry {
        PatternMatch::ByteSwap {
            load1,
            load2,
            store1,
            store2,
        } => (
            0u8,
            load1.encoded_id(),
            load2.encoded_id(),
            store1.encoded_id(),
            store2.encoded_id(),
        ),
        PatternMatch::KeystreamXor { stmt } => (1u8, stmt.encoded_id(), 0, 0, 0),
    });
}

fn collect_dominates(func: &SsaFunction, dom_tree: &DomTree) -> Vec<DominatesFact> {
    let mut facts = Vec::new();
    for dominator in &func.blocks {
        for dominated in &func.blocks {
            if dom_tree.dominates(dominator.id, dominated.id) {
                facts.push(DominatesFact {
                    dominator: dominator.id,
                    dominated: dominated.id,
                });
            }
        }
    }
    facts.sort_by_key(|fact| (fact.dominator, fact.dominated));
    facts
}

fn collect_loop_blocks(func: &SsaFunction, dom_tree: &DomTree) -> HashSet<BlockId> {
    let mut loop_blocks = HashSet::new();

    for block in &func.blocks {
        for &succ in &block.successors {
            if !dom_tree.dominates(succ, block.id) {
                continue;
            }

            let mut worklist = vec![block.id];
            loop_blocks.insert(succ);

            while let Some(node) = worklist.pop() {
                if !loop_blocks.insert(node) {
                    continue;
                }
                if node == succ {
                    continue;
                }

                let predecessors = func
                    .blocks
                    .iter()
                    .find(|candidate| candidate.id == node)
                    .map(|candidate| candidate.predecessors.clone())
                    .unwrap_or_default();
                worklist.extend(predecessors);
            }
        }
    }

    loop_blocks
}

fn solve_constants(defines: &[DefinitionFact]) -> Vec<ConstantFact> {
    let mut values: HashMap<SsaVar, u64> = HashMap::new();

    for _ in 0..=defines.len() {
        let mut changed = false;
        for fact in defines {
            let Some(value) = eval_const_expr(&fact.expr, &values) else {
                continue;
            };
            if values.get(&fact.var) != Some(&value) {
                values.insert(fact.var, value);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut facts: Vec<ConstantFact> = values
        .into_iter()
        .map(|(var, value)| ConstantFact { var, value })
        .collect();
    facts.sort_by_key(|fact| (loc_sort_key(&fact.var.loc), fact.var.version));
    facts
}

fn eval_const_expr(expr: &SsaExpr, values: &HashMap<SsaVar, u64>) -> Option<u64> {
    match expr {
        SsaExpr::Var(var) => values.get(var).copied(),
        SsaExpr::Imm(value) | SsaExpr::AdrpImm(value) | SsaExpr::AdrImm(value) => Some(*value),
        SsaExpr::Add(lhs, rhs) => {
            Some(eval_const_expr(lhs, values)?.wrapping_add(eval_const_expr(rhs, values)?))
        }
        SsaExpr::Sub(lhs, rhs) => {
            Some(eval_const_expr(lhs, values)?.wrapping_sub(eval_const_expr(rhs, values)?))
        }
        SsaExpr::Mul(lhs, rhs) => {
            Some(eval_const_expr(lhs, values)?.wrapping_mul(eval_const_expr(rhs, values)?))
        }
        SsaExpr::Div(lhs, rhs) | SsaExpr::UDiv(lhs, rhs) => {
            let divisor = eval_const_expr(rhs, values)?;
            (divisor != 0).then_some(eval_const_expr(lhs, values)? / divisor)
        }
        SsaExpr::Neg(inner) => Some(eval_const_expr(inner, values)?.wrapping_neg()),
        SsaExpr::Abs(inner) => {
            let value = eval_const_expr(inner, values)? as i64;
            Some(value.wrapping_abs() as u64)
        }
        SsaExpr::And(lhs, rhs) => {
            Some(eval_const_expr(lhs, values)? & eval_const_expr(rhs, values)?)
        }
        SsaExpr::Or(lhs, rhs) => {
            Some(eval_const_expr(lhs, values)? | eval_const_expr(rhs, values)?)
        }
        SsaExpr::Xor(lhs, rhs) => {
            Some(eval_const_expr(lhs, values)? ^ eval_const_expr(rhs, values)?)
        }
        SsaExpr::Not(inner) => Some(!eval_const_expr(inner, values)?),
        SsaExpr::Shl(lhs, rhs) => {
            let shift = eval_const_expr(rhs, values)?;
            Some(if shift < 64 {
                eval_const_expr(lhs, values)?.wrapping_shl(shift as u32)
            } else {
                0
            })
        }
        SsaExpr::Lsr(lhs, rhs) => {
            let shift = eval_const_expr(rhs, values)?;
            Some(if shift < 64 {
                eval_const_expr(lhs, values)?.wrapping_shr(shift as u32)
            } else {
                0
            })
        }
        SsaExpr::Asr(lhs, rhs) => {
            let shift = eval_const_expr(rhs, values)?;
            let value = eval_const_expr(lhs, values)? as i64;
            Some(if shift < 64 {
                value.wrapping_shr(shift as u32) as u64
            } else if value < 0 {
                u64::MAX
            } else {
                0
            })
        }
        SsaExpr::Ror(lhs, rhs) => {
            let shift = eval_const_expr(rhs, values)?;
            Some(eval_const_expr(lhs, values)?.rotate_right((shift & 63) as u32))
        }
        SsaExpr::SignExtend { src, from_bits } => {
            let bits = *from_bits;
            if bits == 0 || bits >= 64 {
                return eval_const_expr(src, values);
            }
            let value = eval_const_expr(src, values)?;
            let sign_bit = 1u64 << (bits - 1);
            let mask = (1u64 << bits) - 1;
            let truncated = value & mask;
            Some(if truncated & sign_bit != 0 {
                truncated | !mask
            } else {
                truncated
            })
        }
        SsaExpr::ZeroExtend { src, from_bits } => {
            let bits = *from_bits;
            let value = eval_const_expr(src, values)?;
            Some(if bits == 0 || bits >= 64 {
                value
            } else {
                value & ((1u64 << bits) - 1)
            })
        }
        SsaExpr::Extract { src, lsb, width } => {
            let value = eval_const_expr(src, values)?;
            Some(extract_bits(value, *lsb, *width))
        }
        SsaExpr::Insert {
            dst,
            src,
            lsb,
            width,
        } => {
            let dst_value = eval_const_expr(dst, values)?;
            let src_value = eval_const_expr(src, values)?;
            let mask = bit_mask(*width) << *lsb;
            Some((dst_value & !mask) | ((src_value & bit_mask(*width)) << *lsb))
        }
        SsaExpr::Clz(inner) => Some(eval_const_expr(inner, values)?.leading_zeros() as u64),
        SsaExpr::Cls(inner) => {
            let value = eval_const_expr(inner, values)? as i64;
            Some(value.leading_ones() as u64)
        }
        SsaExpr::Rev(inner) => Some(eval_const_expr(inner, values)?.swap_bytes()),
        SsaExpr::Rbit(inner) => Some(eval_const_expr(inner, values)?.reverse_bits()),
        SsaExpr::Compare { cond, lhs, rhs } => Some(eval_condition(
            *cond,
            eval_const_expr(lhs, values)?,
            eval_const_expr(rhs, values)?,
        ) as u64),
        SsaExpr::Phi(operands) => {
            let mut result = None;
            for (_, var) in operands {
                let value = values.get(var).copied()?;
                if let Some(existing) = result {
                    if existing != value {
                        return None;
                    }
                } else {
                    result = Some(value);
                }
            }
            result
        }
        SsaExpr::Load { .. }
        | SsaExpr::FImm(_)
        | SsaExpr::FAdd(_, _)
        | SsaExpr::FSub(_, _)
        | SsaExpr::FMul(_, _)
        | SsaExpr::FDiv(_, _)
        | SsaExpr::FNeg(_)
        | SsaExpr::FAbs(_)
        | SsaExpr::FSqrt(_)
        | SsaExpr::FMax(_, _)
        | SsaExpr::FMin(_, _)
        | SsaExpr::FCvt(_)
        | SsaExpr::IntToFloat(_)
        | SsaExpr::FloatToInt(_)
        | SsaExpr::CondSelect { .. }
        | SsaExpr::StackSlot { .. }
        | SsaExpr::MrsRead(_)
        | SsaExpr::Intrinsic { .. } => None,
    }
}

fn eval_condition(cond: Condition, lhs: u64, rhs: u64) -> bool {
    let lhs_signed = lhs as i64;
    let rhs_signed = rhs as i64;
    match cond {
        Condition::EQ => lhs == rhs,
        Condition::NE => lhs != rhs,
        Condition::CS => lhs >= rhs,
        Condition::CC => lhs < rhs,
        Condition::MI => lhs_signed < 0,
        Condition::PL => lhs_signed >= 0,
        Condition::VS | Condition::VC => false,
        Condition::HI => lhs > rhs,
        Condition::LS => lhs <= rhs,
        Condition::GE => lhs_signed >= rhs_signed,
        Condition::LT => lhs_signed < rhs_signed,
        Condition::GT => lhs_signed > rhs_signed,
        Condition::LE => lhs_signed <= rhs_signed,
        Condition::AL => true,
        Condition::NV => false,
    }
}

fn expr_var(expr: &SsaExpr) -> Option<SsaVar> {
    match expr {
        SsaExpr::Var(var) => Some(*var),
        SsaExpr::SignExtend { src, .. }
        | SsaExpr::ZeroExtend { src, .. }
        | SsaExpr::Extract { src, .. } => expr_var(src),
        _ => None,
    }
}

fn is_byte_load_expr(expr: &SsaExpr) -> bool {
    match expr {
        SsaExpr::Load { size: 1, .. } => true,
        SsaExpr::SignExtend { src, .. }
        | SsaExpr::ZeroExtend { src, .. }
        | SsaExpr::Extract { src, .. } => is_byte_load_expr(src),
        _ => false,
    }
}

fn stack_slot_expr(expr: &SsaExpr) -> Option<(i64, u8)> {
    match expr {
        SsaExpr::StackSlot { offset, size } => Some((*offset, *size)),
        _ => None,
    }
}

fn intern_stack_slot(
    offset: i64,
    size: u8,
    stack_slots: &mut HashMap<(i64, u8), StackSlotId>,
    next_slot_id: &mut usize,
) -> StackSlotId {
    *stack_slots.entry((offset, size)).or_insert_with(|| {
        let slot = StackSlotId(*next_slot_id);
        *next_slot_id += 1;
        slot
    })
}

fn call_target_expr(expr: &SsaExpr) -> Option<u64> {
    match expr {
        SsaExpr::Imm(addr) | SsaExpr::AdrImm(addr) | SsaExpr::AdrpImm(addr) => Some(*addr),
        _ => None,
    }
}

fn expr_contains_immediate(expr: &SsaExpr, value: u64) -> bool {
    match expr {
        SsaExpr::Imm(imm) | SsaExpr::AdrImm(imm) | SsaExpr::AdrpImm(imm) => *imm == value,
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
        | SsaExpr::Rbit(addr)
        | SsaExpr::SignExtend { src: addr, .. }
        | SsaExpr::ZeroExtend { src: addr, .. }
        | SsaExpr::Extract { src: addr, .. } => expr_contains_immediate(addr, value),
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
            expr_contains_immediate(lhs, value) || expr_contains_immediate(rhs, value)
        }
        SsaExpr::Insert { dst, src, .. } => {
            expr_contains_immediate(dst, value) || expr_contains_immediate(src, value)
        }
        SsaExpr::Compare { lhs, rhs, .. } => {
            expr_contains_immediate(lhs, value) || expr_contains_immediate(rhs, value)
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => expr_contains_immediate(if_true, value) || expr_contains_immediate(if_false, value),
        SsaExpr::Intrinsic { operands, .. } => operands
            .iter()
            .any(|operand| expr_contains_immediate(operand, value)),
        SsaExpr::Var(_)
        | SsaExpr::FImm(_)
        | SsaExpr::StackSlot { .. }
        | SsaExpr::MrsRead(_)
        | SsaExpr::Phi(_) => false,
    }
}

fn branch_cond_contains_immediate(cond: &SsaBranchCond, value: u64) -> bool {
    match cond {
        SsaBranchCond::Flag(_, _) => false,
        SsaBranchCond::Zero(expr) | SsaBranchCond::NotZero(expr) => {
            expr_contains_immediate(expr, value)
        }
        SsaBranchCond::BitZero(expr, _) | SsaBranchCond::BitNotZero(expr, _) => {
            expr_contains_immediate(expr, value)
        }
        SsaBranchCond::Compare { lhs, rhs, .. } => {
            expr_contains_immediate(lhs, value) || expr_contains_immediate(rhs, value)
        }
    }
}

fn expr_contains_and_mask(expr: &SsaExpr, mask: u64) -> bool {
    match expr {
        SsaExpr::And(lhs, rhs) => {
            matches!(lhs.as_ref(), SsaExpr::Imm(value) if *value == mask)
                || matches!(rhs.as_ref(), SsaExpr::Imm(value) if *value == mask)
                || expr_contains_and_mask(lhs, mask)
                || expr_contains_and_mask(rhs, mask)
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
        | SsaExpr::Rbit(addr)
        | SsaExpr::SignExtend { src: addr, .. }
        | SsaExpr::ZeroExtend { src: addr, .. }
        | SsaExpr::Extract { src: addr, .. } => expr_contains_and_mask(addr, mask),
        SsaExpr::Add(lhs, rhs)
        | SsaExpr::Sub(lhs, rhs)
        | SsaExpr::Mul(lhs, rhs)
        | SsaExpr::Div(lhs, rhs)
        | SsaExpr::UDiv(lhs, rhs)
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
            expr_contains_and_mask(lhs, mask) || expr_contains_and_mask(rhs, mask)
        }
        SsaExpr::Insert { dst, src, .. } => {
            expr_contains_and_mask(dst, mask) || expr_contains_and_mask(src, mask)
        }
        SsaExpr::Compare { lhs, rhs, .. } => {
            expr_contains_and_mask(lhs, mask) || expr_contains_and_mask(rhs, mask)
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => expr_contains_and_mask(if_true, mask) || expr_contains_and_mask(if_false, mask),
        SsaExpr::Intrinsic { operands, .. } => operands
            .iter()
            .any(|operand| expr_contains_and_mask(operand, mask)),
        SsaExpr::Var(_)
        | SsaExpr::Imm(_)
        | SsaExpr::FImm(_)
        | SsaExpr::StackSlot { .. }
        | SsaExpr::MrsRead(_)
        | SsaExpr::AdrpImm(_)
        | SsaExpr::AdrImm(_)
        | SsaExpr::Phi(_) => false,
    }
}

fn stmt_contains_and_mask(stmt: &SsaStmt, mask: u64) -> bool {
    match stmt {
        SsaStmt::Assign { src, .. } => expr_contains_and_mask(src, mask),
        SsaStmt::Store { addr, value, .. } => {
            expr_contains_and_mask(addr, mask) || expr_contains_and_mask(value, mask)
        }
        SsaStmt::Branch { target } => expr_contains_and_mask(target, mask),
        SsaStmt::CondBranch { cond, target, .. } => {
            branch_cond_contains_and_mask(cond, mask) || expr_contains_and_mask(target, mask)
        }
        SsaStmt::Call { target } => expr_contains_and_mask(target, mask),
        SsaStmt::SetFlags { expr, .. } => expr_contains_and_mask(expr, mask),
        SsaStmt::Intrinsic { operands, .. } => operands
            .iter()
            .any(|operand| expr_contains_and_mask(operand, mask)),
        SsaStmt::Pair(a, b) => stmt_contains_and_mask(a, mask) || stmt_contains_and_mask(b, mask),
        SsaStmt::Ret | SsaStmt::Nop | SsaStmt::Barrier(_) | SsaStmt::Trap => false,
    }
}

fn branch_cond_contains_and_mask(cond: &SsaBranchCond, mask: u64) -> bool {
    match cond {
        SsaBranchCond::Flag(_, _) => false,
        SsaBranchCond::Zero(expr) | SsaBranchCond::NotZero(expr) => {
            expr_contains_and_mask(expr, mask)
        }
        SsaBranchCond::BitZero(expr, _) | SsaBranchCond::BitNotZero(expr, _) => {
            expr_contains_and_mask(expr, mask)
        }
        SsaBranchCond::Compare { lhs, rhs, .. } => {
            expr_contains_and_mask(lhs, mask) || expr_contains_and_mask(rhs, mask)
        }
    }
}

fn extract_bits(value: u64, lsb: u8, width: u8) -> u64 {
    if width == 0 {
        return 0;
    }
    (value >> lsb) & bit_mask(width)
}

fn bit_mask(width: u8) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

fn loc_sort_key(loc: &RegLocation) -> (u8, u8) {
    match loc {
        RegLocation::Gpr(index) => (0, *index),
        RegLocation::Fpr(index) => (1, *index),
        RegLocation::Sp => (2, 0),
        RegLocation::Flags => (3, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeon_reduce::ssa::construct::SsaBlock;
    use aeon_reduce::ssa::types::{RegWidth, SsaBranchCond};

    fn var(index: u8, version: u32) -> SsaVar {
        SsaVar {
            loc: RegLocation::Gpr(index),
            version,
            width: RegWidth::W64,
        }
    }

    fn block(
        id: BlockId,
        addr: u64,
        stmts: Vec<SsaStmt>,
        successors: Vec<BlockId>,
        predecessors: Vec<BlockId>,
    ) -> SsaBlock {
        SsaBlock {
            id,
            addr,
            stmts,
            successors,
            predecessors,
        }
    }

    #[test]
    fn extracts_defs_uses_constants_stack_and_dominance() {
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let func = SsaFunction {
            entry: 0,
            blocks: vec![
                block(
                    0,
                    0x1000,
                    vec![
                        SsaStmt::Assign {
                            dst: v1,
                            src: SsaExpr::Imm(256),
                        },
                        SsaStmt::Assign {
                            dst: v2,
                            src: SsaExpr::Load {
                                addr: Box::new(SsaExpr::StackSlot {
                                    offset: -16,
                                    size: 8,
                                }),
                                size: 1,
                            },
                        },
                        SsaStmt::Store {
                            addr: SsaExpr::StackSlot {
                                offset: -8,
                                size: 8,
                            },
                            value: SsaExpr::Var(v2),
                            size: 1,
                        },
                        SsaStmt::Call {
                            target: SsaExpr::Imm(0x4000),
                        },
                        SsaStmt::CondBranch {
                            cond: SsaBranchCond::Compare {
                                cond: Condition::EQ,
                                lhs: Box::new(SsaExpr::Var(v1)),
                                rhs: Box::new(SsaExpr::Imm(256)),
                            },
                            target: SsaExpr::Imm(0x1010),
                            fallthrough: 1,
                        },
                    ],
                    vec![1],
                    vec![],
                ),
                block(1, 0x1010, vec![SsaStmt::Ret], vec![], vec![0]),
            ],
        };

        let facts = extract_function_facts(&func);
        let defs = facts.get_defs_of(v1);
        let uses = facts.get_uses_of(v2);

        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].expr, SsaExpr::Imm(256));
        assert_eq!(
            uses,
            vec![&UseFact {
                var: v2,
                stmt: StmtSite {
                    block: 0,
                    stmt_idx: 2
                }
            }]
        );
        assert_eq!(
            facts.get_constants(),
            &[ConstantFact {
                var: v1,
                value: 256
            }]
        );
        assert_eq!(facts.get_stack_accesses().len(), 2);
        assert!(facts
            .get_stack_accesses()
            .iter()
            .any(|fact| fact.offset == -16 && fact.width == 1 && !fact.is_store));
        assert!(facts
            .get_stack_accesses()
            .iter()
            .any(|fact| fact.offset == -8 && fact.width == 1 && fact.is_store));
        assert_eq!(
            facts.call_targets(),
            &[CallTargetFact {
                stmt: StmtSite {
                    block: 0,
                    stmt_idx: 3
                },
                addr: 0x4000
            }]
        );
        assert_eq!(facts.branch_conditions().len(), 1);
        assert!(facts.block_dominates(0, 1));
        assert!(!facts.block_dominates(1, 0));
        assert!(facts.has_immediate_value(256));
    }

    #[test]
    fn query_helper_matches_loop_swap_and_keystream_xor() {
        let load_a = var(0, 1);
        let load_b = var(1, 1);
        let key_mix = var(2, 1);
        let loop_counter = var(3, 0);
        let addr_a = var(4, 0);
        let addr_b = var(5, 0);
        let addr_c = var(6, 0);
        let input = var(7, 0);
        let bound = var(8, 1);
        let masked = var(9, 1);

        let func = SsaFunction {
            entry: 0,
            blocks: vec![
                block(
                    0,
                    0x1000,
                    vec![
                        SsaStmt::Assign {
                            dst: bound,
                            src: SsaExpr::Imm(256),
                        },
                        SsaStmt::Assign {
                            dst: masked,
                            src: SsaExpr::And(
                                Box::new(SsaExpr::Var(loop_counter)),
                                Box::new(SsaExpr::Imm(0xff)),
                            ),
                        },
                        SsaStmt::Branch {
                            target: SsaExpr::Imm(0x1100),
                        },
                    ],
                    vec![1],
                    vec![],
                ),
                block(
                    1,
                    0x1100,
                    vec![
                        SsaStmt::Assign {
                            dst: load_a,
                            src: SsaExpr::Load {
                                addr: Box::new(SsaExpr::Var(addr_a)),
                                size: 1,
                            },
                        },
                        SsaStmt::Assign {
                            dst: load_b,
                            src: SsaExpr::Load {
                                addr: Box::new(SsaExpr::Var(addr_b)),
                                size: 1,
                            },
                        },
                        SsaStmt::Store {
                            addr: SsaExpr::Var(addr_a),
                            value: SsaExpr::Var(load_b),
                            size: 1,
                        },
                        SsaStmt::Store {
                            addr: SsaExpr::Var(addr_c),
                            value: SsaExpr::Var(load_a),
                            size: 1,
                        },
                        SsaStmt::Assign {
                            dst: key_mix,
                            src: SsaExpr::Xor(
                                Box::new(SsaExpr::Var(load_a)),
                                Box::new(SsaExpr::Var(input)),
                            ),
                        },
                        SsaStmt::CondBranch {
                            cond: SsaBranchCond::NotZero(SsaExpr::Var(loop_counter)),
                            target: SsaExpr::Imm(0x1000),
                            fallthrough: 2,
                        },
                    ],
                    vec![0, 2],
                    vec![0, 1],
                ),
                block(2, 0x1200, vec![SsaStmt::Ret], vec![], vec![1]),
            ],
        };

        let facts = extract_function_facts(&func);

        assert_eq!(
            facts.find_pattern(PatternSpec::LoopByteSwap),
            vec![PatternMatch::ByteSwap {
                load1: StmtSite {
                    block: 1,
                    stmt_idx: 0
                },
                load2: StmtSite {
                    block: 1,
                    stmt_idx: 1
                },
                store1: StmtSite {
                    block: 1,
                    stmt_idx: 2
                },
                store2: StmtSite {
                    block: 1,
                    stmt_idx: 3
                },
            }]
        );
        assert_eq!(
            facts.find_pattern(PatternSpec::LoopKeystreamXor),
            vec![PatternMatch::KeystreamXor {
                stmt: StmtSite {
                    block: 1,
                    stmt_idx: 4
                }
            }]
        );
        assert!(facts.has_and_mask(0xff));
        assert!(facts.is_in_loop(StmtSite {
            block: 1,
            stmt_idx: 0
        }));
    }
}
