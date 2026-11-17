use std::collections::{BTreeMap, BTreeSet};

use aeon_reduce::pipeline::{reduce_block_local, reduce_function_cfg};
use aeon_reduce::reduce_stack::{detect_prologue, PrologueInfo};
use aeon_reduce::ssa::cfg::{build_cfg, Cfg};
use aeon_reduce::ssa::construct::{build_ssa, SsaFunction};
use aeon_reduce::ssa::pipeline::{optimize_ssa, reduce_and_build_ssa};
use aeon_reduce::ssa::types::{BlockId, SsaBranchCond, SsaExpr, SsaStmt};
use aeonil::{BranchCond, Expr, Reg, Stmt};
use serde::Serialize;
use serde_json::{json, Value};

use crate::analysis::AeonAnalysis;
use crate::elf::{FunctionInfo, LoadedBinary};
use crate::error::Error;
use crate::facts::FunctionFacts;
use crate::lifter;

#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub addr: u64,
    pub word: u32,
    pub asm: String,
    pub stmt: Stmt,
    pub edges: Vec<u64>,
    pub valid: bool,
}

#[derive(Debug, Clone)]
pub struct DecodedFunction {
    pub func_addr: u64,
    pub size: u64,
    pub instructions: Vec<DecodedInstruction>,
}

impl DecodedFunction {
    pub fn instruction_tuples(&self) -> Vec<(u64, Stmt, Vec<u64>)> {
        self.instructions
            .iter()
            .map(|instruction| {
                (
                    instruction.addr,
                    instruction.stmt.clone(),
                    instruction.edges.clone(),
                )
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct FunctionArtifacts {
    decoded: DecodedFunction,
    reduced_cfg: Option<Cfg>,
    stack_frame: Option<Option<PrologueInfo>>,
    ssa: Option<SsaFunction>,
    optimized_ssa: Option<SsaFunction>,
    facts: Option<FunctionFacts>,
}

impl FunctionArtifacts {
    pub fn new(decoded: DecodedFunction) -> Self {
        Self {
            decoded,
            reduced_cfg: None,
            stack_frame: None,
            ssa: None,
            optimized_ssa: None,
            facts: None,
        }
    }

    pub fn decoded(&self) -> &DecodedFunction {
        &self.decoded
    }

    pub fn reduced_cfg(&mut self) -> &Cfg {
        if self.reduced_cfg.is_none() {
            let instructions = self.decoded.instruction_tuples();
            self.reduced_cfg = Some(reduce_function_cfg(&instructions));
        }
        self.reduced_cfg.as_ref().unwrap()
    }

    pub fn stack_frame(&mut self) -> Option<&PrologueInfo> {
        if self.stack_frame.is_none() {
            let instructions = self.decoded.instruction_tuples();
            let cfg = build_cfg(&instructions);
            let prologue = cfg
                .blocks
                .get(cfg.entry as usize)
                .map(|entry| reduce_block_local(entry.stmts.clone()))
                .and_then(|entry| detect_prologue(&entry));
            self.stack_frame = Some(prologue);
        }
        self.stack_frame.as_ref().unwrap().as_ref()
    }

    pub fn ssa(&mut self) -> &SsaFunction {
        if self.ssa.is_none() {
            self.ssa = Some(build_ssa(self.reduced_cfg()));
        }
        self.ssa.as_ref().unwrap()
    }

    /// Datalog-style facts over the (unoptimized) SSA form.
    pub fn facts(&mut self) -> &FunctionFacts {
        if self.facts.is_none() {
            self.facts = Some(FunctionFacts::from_ssa(self.ssa()));
        }
        self.facts.as_ref().unwrap()
    }

    pub fn optimized_ssa(&mut self) -> &SsaFunction {
        if self.optimized_ssa.is_none() {
            let optimized = if let Some(ssa) = &self.ssa {
                let mut optimized = ssa.clone();
                optimize_ssa(&mut optimized);
                optimized
            } else {
                let instructions = self.decoded.instruction_tuples();
                reduce_and_build_ssa(&instructions)
            };
            self.optimized_ssa = Some(optimized);
        }
        self.optimized_ssa.as_ref().unwrap()
    }
}

pub fn decode_function(
    binary: &LoadedBinary,
    func: &FunctionInfo,
) -> Result<DecodedFunction, Error> {
    let bytes = binary.function_bytes(func).ok_or_else(|| {
        Error::out_of_range(format!("Function bytes out of range for 0x{:x}", func.addr))
    })?;

    let mut instructions = Vec::new();
    let mut offset = 0usize;
    let mut pc = func.addr;

    while offset + 4 <= bytes.len() {
        let word = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let next_pc = if offset + 8 <= bytes.len() {
            Some(pc + 4)
        } else {
            None
        };

        let (asm, stmt, edges, valid) = match bad64::decode(word, pc) {
            Ok(insn) => {
                let result = lifter::lift(&insn, pc, next_pc);
                (result.disasm, result.stmt, result.edges, true)
            }
            Err(_) => (
                "(invalid)".to_string(),
                Stmt::Nop,
                next_pc.into_iter().collect(),
                false,
            ),
        };

        instructions.push(DecodedInstruction {
            addr: pc,
            word,
            asm,
            stmt,
            edges,
            valid,
        });

        offset += 4;
        pc += 4;
    }

    Ok(DecodedFunction {
        func_addr: func.addr,
        size: func.size,
        instructions,
    })
}

/// Listing, intra-function edges and reachability for one function.
pub fn function_details(decoded: &DecodedFunction) -> Value {
    let func = decoded.func_addr;
    let mut analysis = AeonAnalysis::default();
    for instruction in &decoded.instructions {
        analysis.inst_in_func.push((func, instruction.addr));
        for &target in &instruction.edges {
            analysis.edge.push((instruction.addr, target));
        }
    }
    analysis.run();

    let il_listing: Vec<Value> = decoded
        .instructions
        .iter()
        .map(|instruction| {
            json!({
                "address": format!("0x{:x}", instruction.addr),
                "disassembly": instruction.asm,
                "il": format!("{:?}", instruction.stmt),
            })
        })
        .collect();

    let internal_edges: Vec<Value> = analysis
        .internal_edge
        .iter()
        .map(|(_, src, dst)| json!({ "src": format!("0x{:x}", src), "dst": format!("0x{:x}", dst) }))
        .collect();

    let terminals: Vec<String> = analysis
        .terminal
        .iter()
        .map(|(_, addr)| format!("0x{:x}", addr))
        .collect();

    json!({
        "function": format!("0x{:x}", func),
        "instruction_count": decoded.instructions.len(),
        "il_listing": il_listing,
        "internal_edges": internal_edges,
        "terminal_blocks": terminals,
        "reachable_paths_count": analysis.reachable.len(),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ReducedFunctionView {
    pub query_addr: String,
    pub function: String,
    pub artifact: &'static str,
    pub instruction_count: usize,
    pub block_count: usize,
    pub reduced_stmt_count: usize,
    pub stack_frame: StackFrameSummaryView,
    pub blocks: Vec<ReducedBlockView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReducedBlockView {
    pub id: BlockId,
    pub addr: String,
    pub preds: Vec<BlockId>,
    pub succs: Vec<BlockId>,
    pub instruction_addrs: Vec<String>,
    /// Statements in serde's default shape for `aeonil::Stmt`.
    pub stmts: Vec<Stmt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SsaFunctionView {
    pub query_addr: String,
    pub function: String,
    pub artifact: &'static str,
    pub optimized: bool,
    pub block_count: usize,
    pub metrics: SsaMetricsView,
    pub blocks: Vec<SsaBlockView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SsaMetricsView {
    pub phi_count: usize,
    pub assign_count: usize,
    pub stack_slot_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SsaBlockView {
    pub id: BlockId,
    pub addr: String,
    pub preds: Vec<BlockId>,
    pub succs: Vec<BlockId>,
    /// Statements in serde's default shape for `SsaStmt`.
    pub stmts: Vec<SsaStmt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackFrameArtifactView {
    pub query_addr: String,
    pub function: String,
    pub artifact: &'static str,
    #[serde(flatten)]
    pub summary: StackFrameSummaryView,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackFrameSummaryView {
    pub detected: bool,
    pub frame_size: Option<u64>,
    pub has_frame_pointer: bool,
    pub prologue_end: Option<usize>,
    pub saved_regs: Vec<SavedRegisterView>,
    pub slots: Vec<StackSlotView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SavedRegisterView {
    pub reg: Reg,
    pub offset: i64,
    pub size: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackSlotView {
    pub offset: i64,
    pub size: u8,
    pub loads: usize,
    pub stores: usize,
    pub block_ids: Vec<BlockId>,
}

impl ReducedFunctionView {
    pub fn from_artifacts(query_addr: u64, artifacts: &mut FunctionArtifacts) -> Self {
        let decoded = artifacts.decoded().clone();
        let stack_frame = artifacts.stack_frame().cloned();
        let cfg = artifacts.reduced_cfg();
        let block_instruction_addrs = instruction_addrs_by_block(cfg, &decoded);
        let blocks = cfg
            .blocks
            .iter()
            .map(|block| ReducedBlockView {
                id: block.id,
                addr: hex(block.addr),
                preds: block.predecessors.clone(),
                succs: block.successors.clone(),
                instruction_addrs: block_instruction_addrs[block.id as usize]
                    .iter()
                    .map(|addr| hex(*addr))
                    .collect(),
                stmts: block.stmts.clone(),
            })
            .collect::<Vec<_>>();
        let slots = collect_stack_slot_summaries(cfg);
        let reduced_stmt_count = cfg.blocks.iter().map(|block| block.stmts.len()).sum();

        Self {
            query_addr: hex(query_addr),
            function: hex(decoded.func_addr),
            artifact: "reduced_il",
            instruction_count: decoded.instructions.len(),
            block_count: cfg.blocks.len(),
            reduced_stmt_count,
            stack_frame: StackFrameSummaryView::new(stack_frame.as_ref(), slots),
            blocks,
        }
    }
}

impl SsaFunctionView {
    pub fn from_artifacts(
        query_addr: u64,
        artifacts: &mut FunctionArtifacts,
        optimized: bool,
    ) -> Self {
        let func_addr = artifacts.decoded().func_addr;
        let ssa = if optimized {
            artifacts.optimized_ssa()
        } else {
            artifacts.ssa()
        };

        let mut phi_count = 0usize;
        let mut assign_count = 0usize;
        let mut stack_slots = BTreeSet::new();

        let blocks = ssa
            .blocks
            .iter()
            .map(|block| {
                let stmts = block
                    .stmts
                    .iter()
                    .map(|stmt| {
                        accumulate_ssa_metrics(
                            stmt,
                            &mut assign_count,
                            &mut phi_count,
                            &mut stack_slots,
                        );
                        stmt.clone()
                    })
                    .collect::<Vec<_>>();

                SsaBlockView {
                    id: block.id,
                    addr: hex(block.addr),
                    preds: block.predecessors.clone(),
                    succs: block.successors.clone(),
                    stmts,
                }
            })
            .collect::<Vec<_>>();

        Self {
            query_addr: hex(query_addr),
            function: hex(func_addr),
            artifact: "ssa",
            optimized,
            block_count: ssa.blocks.len(),
            metrics: SsaMetricsView {
                phi_count,
                assign_count,
                stack_slot_count: stack_slots.len(),
            },
            blocks,
        }
    }
}

impl StackFrameArtifactView {
    pub fn from_artifacts(query_addr: u64, artifacts: &mut FunctionArtifacts) -> Self {
        let stack_frame = artifacts.stack_frame().cloned();
        let slots = collect_stack_slot_summaries(artifacts.reduced_cfg());

        Self {
            query_addr: hex(query_addr),
            function: hex(artifacts.decoded().func_addr),
            artifact: "stack_frame",
            summary: StackFrameSummaryView::new(stack_frame.as_ref(), slots),
        }
    }
}

impl StackFrameSummaryView {
    fn new(prologue: Option<&PrologueInfo>, slots: Vec<StackSlotView>) -> Self {
        match prologue {
            Some(prologue) => Self {
                detected: true,
                frame_size: Some(prologue.frame_size),
                has_frame_pointer: prologue.has_frame_pointer,
                prologue_end: Some(prologue.prologue_end),
                saved_regs: prologue
                    .saved_regs
                    .iter()
                    .map(|(reg, offset)| SavedRegisterView {
                        reg: reg.clone(),
                        offset: *offset,
                        size: 8,
                    })
                    .collect(),
                slots,
            },
            None => Self {
                detected: false,
                frame_size: None,
                has_frame_pointer: false,
                prologue_end: None,
                saved_regs: Vec::new(),
                slots,
            },
        }
    }
}

fn instruction_addrs_by_block(cfg: &Cfg, decoded: &DecodedFunction) -> Vec<Vec<u64>> {
    if cfg.blocks.is_empty() {
        return Vec::new();
    }

    let mut result = vec![Vec::new(); cfg.blocks.len()];
    let mut current_block = cfg.entry;

    for instruction in &decoded.instructions {
        if let Some(&block_id) = cfg.block_map.get(&instruction.addr) {
            current_block = block_id;
        }

        if let Some(addrs) = result.get_mut(current_block as usize) {
            addrs.push(instruction.addr);
        }
    }

    result
}

#[derive(Default)]
struct StackSlotStats {
    loads: usize,
    stores: usize,
    block_ids: BTreeSet<BlockId>,
}

fn collect_stack_slot_summaries(cfg: &Cfg) -> Vec<StackSlotView> {
    let mut stats = BTreeMap::<(i64, u8), StackSlotStats>::new();

    for block in &cfg.blocks {
        for stmt in &block.stmts {
            collect_stmt_stack_slots(stmt, block.id, &mut stats);
        }
    }

    stats
        .into_iter()
        .map(|((offset, size), stats)| StackSlotView {
            offset,
            size,
            loads: stats.loads,
            stores: stats.stores,
            block_ids: stats.block_ids.into_iter().collect(),
        })
        .collect()
}

fn collect_stmt_stack_slots(
    stmt: &Stmt,
    block_id: BlockId,
    stats: &mut BTreeMap<(i64, u8), StackSlotStats>,
) {
    match stmt {
        Stmt::Assign { src, .. } => collect_expr_stack_slots(src, block_id, stats),
        Stmt::Store { addr, value, .. } => {
            if let Expr::StackSlot { offset, size } = addr {
                let entry = stats.entry((*offset, *size)).or_default();
                entry.stores += 1;
                entry.block_ids.insert(block_id);
            } else {
                collect_expr_stack_slots(addr, block_id, stats);
            }
            collect_expr_stack_slots(value, block_id, stats);
        }
        Stmt::Branch { target } | Stmt::Call { target } => {
            collect_expr_stack_slots(target, block_id, stats);
        }
        Stmt::CondBranch { cond, target, .. } => {
            collect_branch_cond_stack_slots(cond, block_id, stats);
            collect_expr_stack_slots(target, block_id, stats);
        }
        Stmt::Pair(first, second) => {
            collect_stmt_stack_slots(first, block_id, stats);
            collect_stmt_stack_slots(second, block_id, stats);
        }
        Stmt::SetFlags { expr } => collect_expr_stack_slots(expr, block_id, stats),
        Stmt::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_expr_stack_slots(operand, block_id, stats);
            }
        }
        Stmt::Ret | Stmt::Nop | Stmt::Barrier(_) | Stmt::Trap { .. } => {}
    }
}

fn collect_branch_cond_stack_slots(
    cond: &BranchCond,
    block_id: BlockId,
    stats: &mut BTreeMap<(i64, u8), StackSlotStats>,
) {
    match cond {
        BranchCond::Flag(_) => {}
        BranchCond::Zero(value)
        | BranchCond::NotZero(value)
        | BranchCond::BitZero(value, _)
        | BranchCond::BitNotZero(value, _) => collect_expr_stack_slots(value, block_id, stats),
        BranchCond::Compare { lhs, rhs, .. } => {
            collect_expr_stack_slots(lhs, block_id, stats);
            collect_expr_stack_slots(rhs, block_id, stats);
        }
    }
}

fn collect_expr_stack_slots(
    expr: &Expr,
    block_id: BlockId,
    stats: &mut BTreeMap<(i64, u8), StackSlotStats>,
) {
    match expr {
        Expr::Load { addr, .. } => {
            if let Expr::StackSlot { offset, size } = addr.as_ref() {
                let entry = stats.entry((*offset, *size)).or_default();
                entry.loads += 1;
                entry.block_ids.insert(block_id);
            } else {
                collect_expr_stack_slots(addr, block_id, stats);
            }
        }
        Expr::Add(lhs, rhs)
        | Expr::Sub(lhs, rhs)
        | Expr::Mul(lhs, rhs)
        | Expr::Div(lhs, rhs)
        | Expr::UDiv(lhs, rhs)
        | Expr::And(lhs, rhs)
        | Expr::Or(lhs, rhs)
        | Expr::Xor(lhs, rhs)
        | Expr::Shl(lhs, rhs)
        | Expr::Lsr(lhs, rhs)
        | Expr::Asr(lhs, rhs)
        | Expr::Ror(lhs, rhs)
        | Expr::FAdd(lhs, rhs)
        | Expr::FSub(lhs, rhs)
        | Expr::FMul(lhs, rhs)
        | Expr::FDiv(lhs, rhs)
        | Expr::FMax(lhs, rhs)
        | Expr::FMin(lhs, rhs) => {
            collect_expr_stack_slots(lhs, block_id, stats);
            collect_expr_stack_slots(rhs, block_id, stats);
        }
        Expr::Neg(src)
        | Expr::Abs(src)
        | Expr::Not(src)
        | Expr::FCvt(src)
        | Expr::FNeg(src)
        | Expr::FAbs(src)
        | Expr::FSqrt(src)
        | Expr::IntToFloat(src)
        | Expr::FloatToInt(src)
        | Expr::Clz(src)
        | Expr::Cls(src)
        | Expr::Rev(src)
        | Expr::Rbit(src) => collect_expr_stack_slots(src, block_id, stats),
        Expr::SignExtend { src, .. } | Expr::ZeroExtend { src, .. } | Expr::Extract { src, .. } => {
            collect_expr_stack_slots(src, block_id, stats)
        }
        Expr::Insert { dst, src, .. } => {
            collect_expr_stack_slots(dst, block_id, stats);
            collect_expr_stack_slots(src, block_id, stats);
        }
        Expr::CondSelect {
            if_true, if_false, ..
        } => {
            collect_expr_stack_slots(if_true, block_id, stats);
            collect_expr_stack_slots(if_false, block_id, stats);
        }
        Expr::Compare { lhs, rhs, .. } => {
            collect_expr_stack_slots(lhs, block_id, stats);
            collect_expr_stack_slots(rhs, block_id, stats);
        }
        Expr::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_expr_stack_slots(operand, block_id, stats);
            }
        }
        Expr::Reg(_)
        | Expr::Imm(_)
        | Expr::FImm(_)
        | Expr::AdrpImm(_)
        | Expr::AdrImm(_)
        | Expr::StackSlot { .. }
        | Expr::MrsRead(_) => {}
    }
}

fn accumulate_ssa_metrics(
    stmt: &SsaStmt,
    assign_count: &mut usize,
    phi_count: &mut usize,
    stack_slots: &mut BTreeSet<(i64, u8)>,
) {
    match stmt {
        SsaStmt::Assign { src, .. } => {
            *assign_count += 1;
            if matches!(src, SsaExpr::Phi(_)) {
                *phi_count += 1;
            }
            collect_ssa_expr_stack_slots(src, stack_slots);
        }
        SsaStmt::Store { addr, value, .. } => {
            collect_ssa_expr_stack_slots(addr, stack_slots);
            collect_ssa_expr_stack_slots(value, stack_slots);
        }
        SsaStmt::Branch { target } | SsaStmt::Call { target } => {
            collect_ssa_expr_stack_slots(target, stack_slots);
        }
        SsaStmt::CondBranch { cond, target, .. } => {
            collect_ssa_branch_cond_stack_slots(cond, stack_slots);
            collect_ssa_expr_stack_slots(target, stack_slots);
        }
        SsaStmt::SetFlags { expr, .. } => collect_ssa_expr_stack_slots(expr, stack_slots),
        SsaStmt::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_ssa_expr_stack_slots(operand, stack_slots);
            }
        }
        SsaStmt::Pair(first, second) => {
            accumulate_ssa_metrics(first, assign_count, phi_count, stack_slots);
            accumulate_ssa_metrics(second, assign_count, phi_count, stack_slots);
        }
        SsaStmt::Ret | SsaStmt::Nop | SsaStmt::Barrier(_) | SsaStmt::Trap { .. } => {}
    }
}

fn collect_ssa_branch_cond_stack_slots(
    cond: &SsaBranchCond,
    stack_slots: &mut BTreeSet<(i64, u8)>,
) {
    match cond {
        SsaBranchCond::Flag(_, _) => {}
        SsaBranchCond::Zero(value)
        | SsaBranchCond::NotZero(value)
        | SsaBranchCond::BitZero(value, _)
        | SsaBranchCond::BitNotZero(value, _) => {
            collect_ssa_expr_stack_slots(value, stack_slots);
        }
        SsaBranchCond::Compare { lhs, rhs, .. } => {
            collect_ssa_expr_stack_slots(lhs, stack_slots);
            collect_ssa_expr_stack_slots(rhs, stack_slots);
        }
    }
}

fn collect_ssa_expr_stack_slots(expr: &SsaExpr, stack_slots: &mut BTreeSet<(i64, u8)>) {
    match expr {
        SsaExpr::Load { addr, .. } => {
            if let SsaExpr::StackSlot { offset, size } = addr.as_ref() {
                stack_slots.insert((*offset, *size));
            } else {
                collect_ssa_expr_stack_slots(addr, stack_slots);
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
            collect_ssa_expr_stack_slots(lhs, stack_slots);
            collect_ssa_expr_stack_slots(rhs, stack_slots);
        }
        SsaExpr::Neg(src)
        | SsaExpr::Abs(src)
        | SsaExpr::Not(src)
        | SsaExpr::FCvt(src)
        | SsaExpr::FNeg(src)
        | SsaExpr::FAbs(src)
        | SsaExpr::FSqrt(src)
        | SsaExpr::IntToFloat(src)
        | SsaExpr::FloatToInt(src)
        | SsaExpr::Clz(src)
        | SsaExpr::Cls(src)
        | SsaExpr::Rev(src)
        | SsaExpr::Rbit(src) => collect_ssa_expr_stack_slots(src, stack_slots),
        SsaExpr::SignExtend { src, .. }
        | SsaExpr::ZeroExtend { src, .. }
        | SsaExpr::Extract { src, .. } => collect_ssa_expr_stack_slots(src, stack_slots),
        SsaExpr::Insert { dst, src, .. } => {
            collect_ssa_expr_stack_slots(dst, stack_slots);
            collect_ssa_expr_stack_slots(src, stack_slots);
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => {
            collect_ssa_expr_stack_slots(if_true, stack_slots);
            collect_ssa_expr_stack_slots(if_false, stack_slots);
        }
        SsaExpr::Compare { lhs, rhs, .. } => {
            collect_ssa_expr_stack_slots(lhs, stack_slots);
            collect_ssa_expr_stack_slots(rhs, stack_slots);
        }
        SsaExpr::Intrinsic { operands, .. } => {
            for operand in operands {
                collect_ssa_expr_stack_slots(operand, stack_slots);
            }
        }
        SsaExpr::Phi(inputs) => {
            for (_, var) in inputs {
                let _ = var;
            }
        }
        SsaExpr::StackSlot { offset, size } => {
            stack_slots.insert((*offset, *size));
        }
        SsaExpr::Var(_)
        | SsaExpr::Imm(_)
        | SsaExpr::FImm(_)
        | SsaExpr::MrsRead(_)
        | SsaExpr::AdrpImm(_)
        | SsaExpr::AdrImm(_) => {}
    }
}

fn hex(value: u64) -> String {
    format!("0x{:x}", value)
}
