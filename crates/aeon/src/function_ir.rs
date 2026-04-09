use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

use aeon_reduce::pipeline::{reduce_block_local, reduce_function_cfg};
use aeon_reduce::reduce_stack::{detect_prologue, PrologueInfo};
use aeon_reduce::ssa::cfg::{build_cfg, BasicBlock, Cfg};
use aeon_reduce::ssa::construct::{build_ssa, SsaBlock, SsaFunction};
use aeon_reduce::ssa::pipeline::{optimize_ssa, reduce_and_build_ssa};
use aeon_reduce::ssa::types::{BlockId, RegLocation, SsaBranchCond, SsaExpr, SsaStmt, SsaVar};
use aeonil::{BranchCond, Condition, Expr, Reg, Stmt, TrapKind};
use serde::Serialize;

use crate::elf::{FunctionInfo, LoadedBinary};
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
}

impl FunctionArtifacts {
    pub fn new(decoded: DecodedFunction) -> Self {
        Self {
            decoded,
            reduced_cfg: None,
            stack_frame: None,
            ssa: None,
            optimized_ssa: None,
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

    pub fn estimated_bytes(&self) -> usize {
        size_of::<Self>()
            + estimate_decoded_function_bytes(&self.decoded)
            + self
                .reduced_cfg
                .as_ref()
                .map(estimate_cfg_bytes)
                .unwrap_or(0)
            + self
                .stack_frame
                .as_ref()
                .map(estimate_stack_frame_cache_bytes)
                .unwrap_or(0)
            + self
                .ssa
                .as_ref()
                .map(estimate_ssa_function_bytes)
                .unwrap_or(0)
            + self
                .optimized_ssa
                .as_ref()
                .map(estimate_ssa_function_bytes)
                .unwrap_or(0)
    }
}

const HASHMAP_ENTRY_OVERHEAD: usize = 24;
const DECODED_STMT_HEAP_OVERHEAD: usize = 96;
const REDUCED_STMT_HEAP_OVERHEAD: usize = 80;
const SSA_STMT_HEAP_OVERHEAD: usize = 96;

fn estimate_decoded_function_bytes(decoded: &DecodedFunction) -> usize {
    size_of::<DecodedFunction>()
        + decoded.instructions.capacity() * size_of::<DecodedInstruction>()
        + decoded
            .instructions
            .iter()
            .map(estimate_decoded_instruction_bytes)
            .sum::<usize>()
}

fn estimate_decoded_instruction_bytes(instruction: &DecodedInstruction) -> usize {
    instruction.asm.capacity()
        + instruction.edges.capacity() * size_of::<u64>()
        + DECODED_STMT_HEAP_OVERHEAD
}

fn estimate_cfg_bytes(cfg: &Cfg) -> usize {
    size_of::<Cfg>()
        + cfg.blocks.capacity() * size_of::<BasicBlock>()
        + cfg.block_map.capacity() * (size_of::<(u64, BlockId)>() + HASHMAP_ENTRY_OVERHEAD)
        + cfg
            .blocks
            .iter()
            .map(estimate_basic_block_bytes)
            .sum::<usize>()
}

fn estimate_basic_block_bytes(block: &BasicBlock) -> usize {
    block.stmts.capacity() * size_of::<Stmt>()
        + block.successors.capacity() * size_of::<BlockId>()
        + block.predecessors.capacity() * size_of::<BlockId>()
        + block.stmts.len() * REDUCED_STMT_HEAP_OVERHEAD
}

fn estimate_stack_frame_cache_bytes(frame: &Option<PrologueInfo>) -> usize {
    size_of::<Option<PrologueInfo>>()
        + frame
            .as_ref()
            .map(|info| info.saved_regs.capacity() * size_of::<(Reg, i64)>())
            .unwrap_or(0)
}

fn estimate_ssa_function_bytes(ssa: &SsaFunction) -> usize {
    size_of::<SsaFunction>()
        + ssa.blocks.capacity() * size_of::<SsaBlock>()
        + ssa
            .blocks
            .iter()
            .map(estimate_ssa_block_bytes)
            .sum::<usize>()
}

fn estimate_ssa_block_bytes(block: &SsaBlock) -> usize {
    block.stmts.capacity() * size_of::<SsaStmt>()
        + block.successors.capacity() * size_of::<BlockId>()
        + block.predecessors.capacity() * size_of::<BlockId>()
        + block.stmts.len() * SSA_STMT_HEAP_OVERHEAD
}

pub fn decode_function(
    binary: &LoadedBinary,
    func: &FunctionInfo,
) -> Result<DecodedFunction, String> {
    let bytes = binary
        .function_bytes(func)
        .ok_or_else(|| format!("Function bytes out of range for 0x{:x}", func.addr))?;

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
    pub stmts: Vec<StmtView>,
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
    pub stmts: Vec<SsaStmtView>,
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
    pub reg: String,
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

#[derive(Debug, Clone, Serialize)]
pub struct SsaVarView {
    pub name: String,
    pub location: &'static str,
    pub index: Option<u8>,
    pub version: u32,
    pub width_bits: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct PhiInputView {
    pub pred: BlockId,
    pub var: SsaVarView,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExprView {
    Reg {
        name: String,
    },
    Imm {
        value: String,
    },
    FImm {
        value: f64,
    },
    Load {
        addr: Box<ExprView>,
        size: u8,
    },
    Add {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Sub {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Mul {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Div {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    UDiv {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Neg {
        src: Box<ExprView>,
    },
    Abs {
        src: Box<ExprView>,
    },
    And {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Or {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Xor {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Not {
        src: Box<ExprView>,
    },
    Shl {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Lsr {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Asr {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Ror {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    SignExtend {
        src: Box<ExprView>,
        from_bits: u8,
    },
    ZeroExtend {
        src: Box<ExprView>,
        from_bits: u8,
    },
    Extract {
        src: Box<ExprView>,
        lsb: u8,
        width: u8,
    },
    Insert {
        dst: Box<ExprView>,
        src: Box<ExprView>,
        lsb: u8,
        width: u8,
    },
    FAdd {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    FSub {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    FMul {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    FDiv {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    FNeg {
        src: Box<ExprView>,
    },
    FAbs {
        src: Box<ExprView>,
    },
    FSqrt {
        src: Box<ExprView>,
    },
    FMax {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    FMin {
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    FCvt {
        src: Box<ExprView>,
    },
    IntToFloat {
        src: Box<ExprView>,
    },
    FloatToInt {
        src: Box<ExprView>,
    },
    CondSelect {
        cc: &'static str,
        if_true: Box<ExprView>,
        if_false: Box<ExprView>,
    },
    Compare {
        cc: &'static str,
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
    Clz {
        src: Box<ExprView>,
    },
    Cls {
        src: Box<ExprView>,
    },
    Rev {
        src: Box<ExprView>,
    },
    Rbit {
        src: Box<ExprView>,
    },
    AdrpImm {
        value: String,
    },
    AdrImm {
        value: String,
    },
    StackSlot {
        offset: i64,
        size: u8,
    },
    MrsRead {
        name: String,
    },
    Intrinsic {
        name: String,
        operands: Vec<ExprView>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BranchCondView {
    Flag {
        cc: &'static str,
    },
    Zero {
        value: ExprView,
    },
    NotZero {
        value: ExprView,
    },
    BitZero {
        value: ExprView,
        bit: u8,
    },
    BitNotZero {
        value: ExprView,
        bit: u8,
    },
    Compare {
        cc: &'static str,
        lhs: Box<ExprView>,
        rhs: Box<ExprView>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StmtView {
    Assign {
        dst: String,
        src: ExprView,
    },
    Store {
        addr: ExprView,
        value: ExprView,
        size: u8,
    },
    Branch {
        target: ExprView,
    },
    CondBranch {
        cond: BranchCondView,
        target: ExprView,
        fallthrough: String,
    },
    Call {
        target: ExprView,
    },
    Ret,
    Nop,
    Pair {
        first: Box<StmtView>,
        second: Box<StmtView>,
    },
    SetFlags {
        expr: ExprView,
    },
    Barrier {
        kind: String,
    },
    Trap {
        kind: String,
        imm: String,
    },
    Intrinsic {
        name: String,
        operands: Vec<ExprView>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SsaExprView {
    Var {
        value: SsaVarView,
    },
    Imm {
        value: String,
    },
    FImm {
        value: f64,
    },
    Load {
        addr: Box<SsaExprView>,
        size: u8,
    },
    Add {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Sub {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Mul {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Div {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    UDiv {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Neg {
        src: Box<SsaExprView>,
    },
    Abs {
        src: Box<SsaExprView>,
    },
    And {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Or {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Xor {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Not {
        src: Box<SsaExprView>,
    },
    Shl {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Lsr {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Asr {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Ror {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    SignExtend {
        src: Box<SsaExprView>,
        from_bits: u8,
    },
    ZeroExtend {
        src: Box<SsaExprView>,
        from_bits: u8,
    },
    Extract {
        src: Box<SsaExprView>,
        lsb: u8,
        width: u8,
    },
    Insert {
        dst: Box<SsaExprView>,
        src: Box<SsaExprView>,
        lsb: u8,
        width: u8,
    },
    FAdd {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    FSub {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    FMul {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    FDiv {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    FNeg {
        src: Box<SsaExprView>,
    },
    FAbs {
        src: Box<SsaExprView>,
    },
    FSqrt {
        src: Box<SsaExprView>,
    },
    FMax {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    FMin {
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    FCvt {
        src: Box<SsaExprView>,
    },
    IntToFloat {
        src: Box<SsaExprView>,
    },
    FloatToInt {
        src: Box<SsaExprView>,
    },
    CondSelect {
        cc: &'static str,
        if_true: Box<SsaExprView>,
        if_false: Box<SsaExprView>,
    },
    Compare {
        cc: &'static str,
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
    Clz {
        src: Box<SsaExprView>,
    },
    Cls {
        src: Box<SsaExprView>,
    },
    Rev {
        src: Box<SsaExprView>,
    },
    Rbit {
        src: Box<SsaExprView>,
    },
    StackSlot {
        offset: i64,
        size: u8,
    },
    MrsRead {
        name: String,
    },
    Intrinsic {
        name: String,
        operands: Vec<SsaExprView>,
    },
    Phi {
        inputs: Vec<PhiInputView>,
    },
    AdrpImm {
        value: String,
    },
    AdrImm {
        value: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SsaBranchCondView {
    Flag {
        cc: &'static str,
        flags: SsaVarView,
    },
    Zero {
        value: SsaExprView,
    },
    NotZero {
        value: SsaExprView,
    },
    BitZero {
        value: SsaExprView,
        bit: u8,
    },
    BitNotZero {
        value: SsaExprView,
        bit: u8,
    },
    Compare {
        cc: &'static str,
        lhs: Box<SsaExprView>,
        rhs: Box<SsaExprView>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SsaStmtView {
    Assign {
        dst: SsaVarView,
        src: SsaExprView,
    },
    Store {
        addr: SsaExprView,
        value: SsaExprView,
        size: u8,
    },
    Branch {
        target: SsaExprView,
    },
    CondBranch {
        cond: SsaBranchCondView,
        target: SsaExprView,
        fallthrough: BlockId,
    },
    Call {
        target: SsaExprView,
    },
    Ret,
    Nop,
    SetFlags {
        src: SsaVarView,
        expr: SsaExprView,
    },
    Barrier {
        kind: String,
    },
    Trap {
        kind: String,
        imm: String,
    },
    Intrinsic {
        name: String,
        operands: Vec<SsaExprView>,
    },
    Pair {
        first: Box<SsaStmtView>,
        second: Box<SsaStmtView>,
    },
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
                stmts: block.stmts.iter().map(StmtView::from_stmt).collect(),
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
                        SsaStmtView::from_stmt(stmt)
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
                        reg: reg_name(reg).to_string(),
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

impl ExprView {
    pub fn from_expr(expr: &Expr) -> Self {
        match expr {
            Expr::Reg(reg) => Self::Reg {
                name: reg_name(reg).to_string(),
            },
            Expr::Imm(value) => Self::Imm { value: hex(*value) },
            Expr::FImm(value) => Self::FImm { value: *value },
            Expr::Load { addr, size } => Self::Load {
                addr: Box::new(Self::from_expr(addr)),
                size: *size,
            },
            Expr::Add(lhs, rhs) => Self::Add {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Sub(lhs, rhs) => Self::Sub {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Mul(lhs, rhs) => Self::Mul {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Div(lhs, rhs) => Self::Div {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::UDiv(lhs, rhs) => Self::UDiv {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Neg(src) => Self::Neg {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::Abs(src) => Self::Abs {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::And(lhs, rhs) => Self::And {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Or(lhs, rhs) => Self::Or {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Xor(lhs, rhs) => Self::Xor {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Not(src) => Self::Not {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::Shl(lhs, rhs) => Self::Shl {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Lsr(lhs, rhs) => Self::Lsr {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Asr(lhs, rhs) => Self::Asr {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Ror(lhs, rhs) => Self::Ror {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::SignExtend { src, from_bits } => Self::SignExtend {
                src: Box::new(Self::from_expr(src)),
                from_bits: *from_bits,
            },
            Expr::ZeroExtend { src, from_bits } => Self::ZeroExtend {
                src: Box::new(Self::from_expr(src)),
                from_bits: *from_bits,
            },
            Expr::Extract { src, lsb, width } => Self::Extract {
                src: Box::new(Self::from_expr(src)),
                lsb: *lsb,
                width: *width,
            },
            Expr::Insert {
                dst,
                src,
                lsb,
                width,
            } => Self::Insert {
                dst: Box::new(Self::from_expr(dst)),
                src: Box::new(Self::from_expr(src)),
                lsb: *lsb,
                width: *width,
            },
            Expr::FAdd(lhs, rhs) => Self::FAdd {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::FSub(lhs, rhs) => Self::FSub {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::FMul(lhs, rhs) => Self::FMul {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::FDiv(lhs, rhs) => Self::FDiv {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::FNeg(src) => Self::FNeg {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::FAbs(src) => Self::FAbs {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::FSqrt(src) => Self::FSqrt {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::FMax(lhs, rhs) => Self::FMax {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::FMin(lhs, rhs) => Self::FMin {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::FCvt(src) => Self::FCvt {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::IntToFloat(src) => Self::IntToFloat {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::FloatToInt(src) => Self::FloatToInt {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::CondSelect {
                cond,
                if_true,
                if_false,
            } => Self::CondSelect {
                cc: condition_name(*cond),
                if_true: Box::new(Self::from_expr(if_true)),
                if_false: Box::new(Self::from_expr(if_false)),
            },
            Expr::Compare { cond, lhs, rhs } => Self::Compare {
                cc: condition_name(*cond),
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            Expr::Clz(src) => Self::Clz {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::Cls(src) => Self::Cls {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::Rev(src) => Self::Rev {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::Rbit(src) => Self::Rbit {
                src: Box::new(Self::from_expr(src)),
            },
            Expr::AdrpImm(value) => Self::AdrpImm { value: hex(*value) },
            Expr::AdrImm(value) => Self::AdrImm { value: hex(*value) },
            Expr::StackSlot { offset, size } => Self::StackSlot {
                offset: *offset,
                size: *size,
            },
            Expr::MrsRead(name) => Self::MrsRead { name: name.clone() },
            Expr::Intrinsic { name, operands } => Self::Intrinsic {
                name: name.clone(),
                operands: operands.iter().map(Self::from_expr).collect(),
            },
        }
    }
}

impl BranchCondView {
    pub fn from_cond(cond: &BranchCond) -> Self {
        match cond {
            BranchCond::Flag(cc) => Self::Flag {
                cc: condition_name(*cc),
            },
            BranchCond::Zero(value) => Self::Zero {
                value: ExprView::from_expr(value),
            },
            BranchCond::NotZero(value) => Self::NotZero {
                value: ExprView::from_expr(value),
            },
            BranchCond::BitZero(value, bit) => Self::BitZero {
                value: ExprView::from_expr(value),
                bit: *bit,
            },
            BranchCond::BitNotZero(value, bit) => Self::BitNotZero {
                value: ExprView::from_expr(value),
                bit: *bit,
            },
            BranchCond::Compare { cond, lhs, rhs } => Self::Compare {
                cc: condition_name(*cond),
                lhs: Box::new(ExprView::from_expr(lhs)),
                rhs: Box::new(ExprView::from_expr(rhs)),
            },
        }
    }
}

impl StmtView {
    pub fn from_stmt(stmt: &Stmt) -> Self {
        match stmt {
            Stmt::Assign { dst, src } => Self::Assign {
                dst: reg_name(dst).to_string(),
                src: ExprView::from_expr(src),
            },
            Stmt::Store { addr, value, size } => Self::Store {
                addr: ExprView::from_expr(addr),
                value: ExprView::from_expr(value),
                size: *size,
            },
            Stmt::Branch { target } => Self::Branch {
                target: ExprView::from_expr(target),
            },
            Stmt::CondBranch {
                cond,
                target,
                fallthrough,
            } => Self::CondBranch {
                cond: BranchCondView::from_cond(cond),
                target: ExprView::from_expr(target),
                fallthrough: hex(*fallthrough),
            },
            Stmt::Call { target } => Self::Call {
                target: ExprView::from_expr(target),
            },
            Stmt::Ret => Self::Ret,
            Stmt::Nop => Self::Nop,
            Stmt::Pair(first, second) => Self::Pair {
                first: Box::new(Self::from_stmt(first)),
                second: Box::new(Self::from_stmt(second)),
            },
            Stmt::SetFlags { expr } => Self::SetFlags {
                expr: ExprView::from_expr(expr),
            },
            Stmt::Barrier(kind) => Self::Barrier { kind: kind.clone() },
            Stmt::Trap { kind, imm } => Self::Trap {
                kind: trap_kind_name(*kind).to_string(),
                imm: hex(u64::from(*imm)),
            },
            Stmt::Intrinsic { name, operands } => Self::Intrinsic {
                name: name.clone(),
                operands: operands.iter().map(ExprView::from_expr).collect(),
            },
        }
    }
}

impl SsaVarView {
    fn from_var(var: &SsaVar) -> Self {
        let (location, index) = match var.loc {
            RegLocation::Gpr(index) => ("gpr", Some(index)),
            RegLocation::Fpr(index) => ("fpr", Some(index)),
            RegLocation::Sp => ("sp", None),
            RegLocation::Flags => ("flags", None),
        };

        let prefix = match var.loc {
            RegLocation::Gpr(index) => format!("gpr{}", index),
            RegLocation::Fpr(index) => format!("fpr{}", index),
            RegLocation::Sp => "sp".to_string(),
            RegLocation::Flags => "flags".to_string(),
        };

        Self {
            name: format!("{}_{}", prefix, var.version),
            location,
            index,
            version: var.version,
            width_bits: var.width.bits(),
        }
    }
}

impl SsaExprView {
    pub fn from_expr(expr: &SsaExpr) -> Self {
        match expr {
            SsaExpr::Var(value) => Self::Var {
                value: SsaVarView::from_var(value),
            },
            SsaExpr::Imm(value) => Self::Imm { value: hex(*value) },
            SsaExpr::FImm(value) => Self::FImm { value: *value },
            SsaExpr::Load { addr, size } => Self::Load {
                addr: Box::new(Self::from_expr(addr)),
                size: *size,
            },
            SsaExpr::Add(lhs, rhs) => Self::Add {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Sub(lhs, rhs) => Self::Sub {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Mul(lhs, rhs) => Self::Mul {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Div(lhs, rhs) => Self::Div {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::UDiv(lhs, rhs) => Self::UDiv {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Neg(src) => Self::Neg {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::Abs(src) => Self::Abs {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::And(lhs, rhs) => Self::And {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Or(lhs, rhs) => Self::Or {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Xor(lhs, rhs) => Self::Xor {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Not(src) => Self::Not {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::Shl(lhs, rhs) => Self::Shl {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Lsr(lhs, rhs) => Self::Lsr {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Asr(lhs, rhs) => Self::Asr {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::Ror(lhs, rhs) => Self::Ror {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::SignExtend { src, from_bits } => Self::SignExtend {
                src: Box::new(Self::from_expr(src)),
                from_bits: *from_bits,
            },
            SsaExpr::ZeroExtend { src, from_bits } => Self::ZeroExtend {
                src: Box::new(Self::from_expr(src)),
                from_bits: *from_bits,
            },
            SsaExpr::Extract { src, lsb, width } => Self::Extract {
                src: Box::new(Self::from_expr(src)),
                lsb: *lsb,
                width: *width,
            },
            SsaExpr::Insert {
                dst,
                src,
                lsb,
                width,
            } => Self::Insert {
                dst: Box::new(Self::from_expr(dst)),
                src: Box::new(Self::from_expr(src)),
                lsb: *lsb,
                width: *width,
            },
            SsaExpr::FAdd(lhs, rhs) => Self::FAdd {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::FSub(lhs, rhs) => Self::FSub {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::FMul(lhs, rhs) => Self::FMul {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::FDiv(lhs, rhs) => Self::FDiv {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::FNeg(src) => Self::FNeg {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::FAbs(src) => Self::FAbs {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::FSqrt(src) => Self::FSqrt {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::FMax(lhs, rhs) => Self::FMax {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::FMin(lhs, rhs) => Self::FMin {
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::FCvt(src) => Self::FCvt {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::IntToFloat(src) => Self::IntToFloat {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::FloatToInt(src) => Self::FloatToInt {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::Clz(src) => Self::Clz {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::Cls(src) => Self::Cls {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::Rev(src) => Self::Rev {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::Rbit(src) => Self::Rbit {
                src: Box::new(Self::from_expr(src)),
            },
            SsaExpr::CondSelect {
                cond,
                if_true,
                if_false,
            } => Self::CondSelect {
                cc: condition_name(*cond),
                if_true: Box::new(Self::from_expr(if_true)),
                if_false: Box::new(Self::from_expr(if_false)),
            },
            SsaExpr::Compare { cond, lhs, rhs } => Self::Compare {
                cc: condition_name(*cond),
                lhs: Box::new(Self::from_expr(lhs)),
                rhs: Box::new(Self::from_expr(rhs)),
            },
            SsaExpr::StackSlot { offset, size } => Self::StackSlot {
                offset: *offset,
                size: *size,
            },
            SsaExpr::MrsRead(name) => Self::MrsRead { name: name.clone() },
            SsaExpr::Intrinsic { name, operands } => Self::Intrinsic {
                name: name.clone(),
                operands: operands.iter().map(Self::from_expr).collect(),
            },
            SsaExpr::Phi(inputs) => Self::Phi {
                inputs: inputs
                    .iter()
                    .map(|(pred, var)| PhiInputView {
                        pred: *pred,
                        var: SsaVarView::from_var(var),
                    })
                    .collect(),
            },
            SsaExpr::AdrpImm(value) => Self::AdrpImm { value: hex(*value) },
            SsaExpr::AdrImm(value) => Self::AdrImm { value: hex(*value) },
        }
    }
}

impl SsaBranchCondView {
    pub fn from_cond(cond: &SsaBranchCond) -> Self {
        match cond {
            SsaBranchCond::Flag(cc, flags) => Self::Flag {
                cc: condition_name(*cc),
                flags: SsaVarView::from_var(flags),
            },
            SsaBranchCond::Zero(value) => Self::Zero {
                value: SsaExprView::from_expr(value),
            },
            SsaBranchCond::NotZero(value) => Self::NotZero {
                value: SsaExprView::from_expr(value),
            },
            SsaBranchCond::BitZero(value, bit) => Self::BitZero {
                value: SsaExprView::from_expr(value),
                bit: *bit,
            },
            SsaBranchCond::BitNotZero(value, bit) => Self::BitNotZero {
                value: SsaExprView::from_expr(value),
                bit: *bit,
            },
            SsaBranchCond::Compare { cond, lhs, rhs } => Self::Compare {
                cc: condition_name(*cond),
                lhs: Box::new(SsaExprView::from_expr(lhs)),
                rhs: Box::new(SsaExprView::from_expr(rhs)),
            },
        }
    }
}

impl SsaStmtView {
    pub fn from_stmt(stmt: &SsaStmt) -> Self {
        match stmt {
            SsaStmt::Assign { dst, src } => Self::Assign {
                dst: SsaVarView::from_var(dst),
                src: SsaExprView::from_expr(src),
            },
            SsaStmt::Store { addr, value, size } => Self::Store {
                addr: SsaExprView::from_expr(addr),
                value: SsaExprView::from_expr(value),
                size: *size,
            },
            SsaStmt::Branch { target } => Self::Branch {
                target: SsaExprView::from_expr(target),
            },
            SsaStmt::CondBranch {
                cond,
                target,
                fallthrough,
            } => Self::CondBranch {
                cond: SsaBranchCondView::from_cond(cond),
                target: SsaExprView::from_expr(target),
                fallthrough: *fallthrough,
            },
            SsaStmt::Call { target } => Self::Call {
                target: SsaExprView::from_expr(target),
            },
            SsaStmt::Ret => Self::Ret,
            SsaStmt::Nop => Self::Nop,
            SsaStmt::SetFlags { src, expr } => Self::SetFlags {
                src: SsaVarView::from_var(src),
                expr: SsaExprView::from_expr(expr),
            },
            SsaStmt::Barrier(kind) => Self::Barrier { kind: kind.clone() },
            SsaStmt::Trap { kind, imm } => Self::Trap {
                kind: trap_kind_name(*kind).to_string(),
                imm: hex(u64::from(*imm)),
            },
            SsaStmt::Intrinsic { name, operands } => Self::Intrinsic {
                name: name.clone(),
                operands: operands.iter().map(SsaExprView::from_expr).collect(),
            },
            SsaStmt::Pair(first, second) => Self::Pair {
                first: Box::new(Self::from_stmt(first)),
                second: Box::new(Self::from_stmt(second)),
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

fn reg_name(reg: &Reg) -> &'static str {
    match reg {
        Reg::X(0) => "x0",
        Reg::X(1) => "x1",
        Reg::X(2) => "x2",
        Reg::X(3) => "x3",
        Reg::X(4) => "x4",
        Reg::X(5) => "x5",
        Reg::X(6) => "x6",
        Reg::X(7) => "x7",
        Reg::X(8) => "x8",
        Reg::X(9) => "x9",
        Reg::X(10) => "x10",
        Reg::X(11) => "x11",
        Reg::X(12) => "x12",
        Reg::X(13) => "x13",
        Reg::X(14) => "x14",
        Reg::X(15) => "x15",
        Reg::X(16) => "x16",
        Reg::X(17) => "x17",
        Reg::X(18) => "x18",
        Reg::X(19) => "x19",
        Reg::X(20) => "x20",
        Reg::X(21) => "x21",
        Reg::X(22) => "x22",
        Reg::X(23) => "x23",
        Reg::X(24) => "x24",
        Reg::X(25) => "x25",
        Reg::X(26) => "x26",
        Reg::X(27) => "x27",
        Reg::X(28) => "x28",
        Reg::X(29) => "x29",
        Reg::X(30) => "x30",
        Reg::X(31) => "x31",
        Reg::W(0) => "w0",
        Reg::W(1) => "w1",
        Reg::W(2) => "w2",
        Reg::W(3) => "w3",
        Reg::W(4) => "w4",
        Reg::W(5) => "w5",
        Reg::W(6) => "w6",
        Reg::W(7) => "w7",
        Reg::W(8) => "w8",
        Reg::W(9) => "w9",
        Reg::W(10) => "w10",
        Reg::W(11) => "w11",
        Reg::W(12) => "w12",
        Reg::W(13) => "w13",
        Reg::W(14) => "w14",
        Reg::W(15) => "w15",
        Reg::W(16) => "w16",
        Reg::W(17) => "w17",
        Reg::W(18) => "w18",
        Reg::W(19) => "w19",
        Reg::W(20) => "w20",
        Reg::W(21) => "w21",
        Reg::W(22) => "w22",
        Reg::W(23) => "w23",
        Reg::W(24) => "w24",
        Reg::W(25) => "w25",
        Reg::W(26) => "w26",
        Reg::W(27) => "w27",
        Reg::W(28) => "w28",
        Reg::W(29) => "w29",
        Reg::W(30) => "w30",
        Reg::W(31) => "w31",
        Reg::SP => "sp",
        Reg::PC => "pc",
        Reg::XZR => "xzr",
        Reg::Flags => "flags",
        Reg::V(0) => "v0",
        Reg::V(1) => "v1",
        Reg::V(2) => "v2",
        Reg::V(3) => "v3",
        Reg::V(4) => "v4",
        Reg::V(5) => "v5",
        Reg::V(6) => "v6",
        Reg::V(7) => "v7",
        Reg::V(8) => "v8",
        Reg::V(9) => "v9",
        Reg::V(10) => "v10",
        Reg::V(11) => "v11",
        Reg::V(12) => "v12",
        Reg::V(13) => "v13",
        Reg::V(14) => "v14",
        Reg::V(15) => "v15",
        Reg::V(16) => "v16",
        Reg::V(17) => "v17",
        Reg::V(18) => "v18",
        Reg::V(19) => "v19",
        Reg::V(20) => "v20",
        Reg::V(21) => "v21",
        Reg::V(22) => "v22",
        Reg::V(23) => "v23",
        Reg::V(24) => "v24",
        Reg::V(25) => "v25",
        Reg::V(26) => "v26",
        Reg::V(27) => "v27",
        Reg::V(28) => "v28",
        Reg::V(29) => "v29",
        Reg::V(30) => "v30",
        Reg::V(31) => "v31",
        Reg::Q(0) => "q0",
        Reg::Q(1) => "q1",
        Reg::Q(2) => "q2",
        Reg::Q(3) => "q3",
        Reg::Q(4) => "q4",
        Reg::Q(5) => "q5",
        Reg::Q(6) => "q6",
        Reg::Q(7) => "q7",
        Reg::Q(8) => "q8",
        Reg::Q(9) => "q9",
        Reg::Q(10) => "q10",
        Reg::Q(11) => "q11",
        Reg::Q(12) => "q12",
        Reg::Q(13) => "q13",
        Reg::Q(14) => "q14",
        Reg::Q(15) => "q15",
        Reg::Q(16) => "q16",
        Reg::Q(17) => "q17",
        Reg::Q(18) => "q18",
        Reg::Q(19) => "q19",
        Reg::Q(20) => "q20",
        Reg::Q(21) => "q21",
        Reg::Q(22) => "q22",
        Reg::Q(23) => "q23",
        Reg::Q(24) => "q24",
        Reg::Q(25) => "q25",
        Reg::Q(26) => "q26",
        Reg::Q(27) => "q27",
        Reg::Q(28) => "q28",
        Reg::Q(29) => "q29",
        Reg::Q(30) => "q30",
        Reg::Q(31) => "q31",
        Reg::D(0) => "d0",
        Reg::D(1) => "d1",
        Reg::D(2) => "d2",
        Reg::D(3) => "d3",
        Reg::D(4) => "d4",
        Reg::D(5) => "d5",
        Reg::D(6) => "d6",
        Reg::D(7) => "d7",
        Reg::D(8) => "d8",
        Reg::D(9) => "d9",
        Reg::D(10) => "d10",
        Reg::D(11) => "d11",
        Reg::D(12) => "d12",
        Reg::D(13) => "d13",
        Reg::D(14) => "d14",
        Reg::D(15) => "d15",
        Reg::D(16) => "d16",
        Reg::D(17) => "d17",
        Reg::D(18) => "d18",
        Reg::D(19) => "d19",
        Reg::D(20) => "d20",
        Reg::D(21) => "d21",
        Reg::D(22) => "d22",
        Reg::D(23) => "d23",
        Reg::D(24) => "d24",
        Reg::D(25) => "d25",
        Reg::D(26) => "d26",
        Reg::D(27) => "d27",
        Reg::D(28) => "d28",
        Reg::D(29) => "d29",
        Reg::D(30) => "d30",
        Reg::D(31) => "d31",
        Reg::S(0) => "s0",
        Reg::S(1) => "s1",
        Reg::S(2) => "s2",
        Reg::S(3) => "s3",
        Reg::S(4) => "s4",
        Reg::S(5) => "s5",
        Reg::S(6) => "s6",
        Reg::S(7) => "s7",
        Reg::S(8) => "s8",
        Reg::S(9) => "s9",
        Reg::S(10) => "s10",
        Reg::S(11) => "s11",
        Reg::S(12) => "s12",
        Reg::S(13) => "s13",
        Reg::S(14) => "s14",
        Reg::S(15) => "s15",
        Reg::S(16) => "s16",
        Reg::S(17) => "s17",
        Reg::S(18) => "s18",
        Reg::S(19) => "s19",
        Reg::S(20) => "s20",
        Reg::S(21) => "s21",
        Reg::S(22) => "s22",
        Reg::S(23) => "s23",
        Reg::S(24) => "s24",
        Reg::S(25) => "s25",
        Reg::S(26) => "s26",
        Reg::S(27) => "s27",
        Reg::S(28) => "s28",
        Reg::S(29) => "s29",
        Reg::S(30) => "s30",
        Reg::S(31) => "s31",
        Reg::H(0) => "h0",
        Reg::H(1) => "h1",
        Reg::H(2) => "h2",
        Reg::H(3) => "h3",
        Reg::H(4) => "h4",
        Reg::H(5) => "h5",
        Reg::H(6) => "h6",
        Reg::H(7) => "h7",
        Reg::H(8) => "h8",
        Reg::H(9) => "h9",
        Reg::H(10) => "h10",
        Reg::H(11) => "h11",
        Reg::H(12) => "h12",
        Reg::H(13) => "h13",
        Reg::H(14) => "h14",
        Reg::H(15) => "h15",
        Reg::H(16) => "h16",
        Reg::H(17) => "h17",
        Reg::H(18) => "h18",
        Reg::H(19) => "h19",
        Reg::H(20) => "h20",
        Reg::H(21) => "h21",
        Reg::H(22) => "h22",
        Reg::H(23) => "h23",
        Reg::H(24) => "h24",
        Reg::H(25) => "h25",
        Reg::H(26) => "h26",
        Reg::H(27) => "h27",
        Reg::H(28) => "h28",
        Reg::H(29) => "h29",
        Reg::H(30) => "h30",
        Reg::H(31) => "h31",
        Reg::VByte(0) => "b0",
        Reg::VByte(1) => "b1",
        Reg::VByte(2) => "b2",
        Reg::VByte(3) => "b3",
        Reg::VByte(4) => "b4",
        Reg::VByte(5) => "b5",
        Reg::VByte(6) => "b6",
        Reg::VByte(7) => "b7",
        Reg::VByte(8) => "b8",
        Reg::VByte(9) => "b9",
        Reg::VByte(10) => "b10",
        Reg::VByte(11) => "b11",
        Reg::VByte(12) => "b12",
        Reg::VByte(13) => "b13",
        Reg::VByte(14) => "b14",
        Reg::VByte(15) => "b15",
        Reg::VByte(16) => "b16",
        Reg::VByte(17) => "b17",
        Reg::VByte(18) => "b18",
        Reg::VByte(19) => "b19",
        Reg::VByte(20) => "b20",
        Reg::VByte(21) => "b21",
        Reg::VByte(22) => "b22",
        Reg::VByte(23) => "b23",
        Reg::VByte(24) => "b24",
        Reg::VByte(25) => "b25",
        Reg::VByte(26) => "b26",
        Reg::VByte(27) => "b27",
        Reg::VByte(28) => "b28",
        Reg::VByte(29) => "b29",
        Reg::VByte(30) => "b30",
        Reg::VByte(31) => "b31",
        _ => "reg",
    }
}

fn trap_kind_name(kind: TrapKind) -> &'static str {
    match kind {
        TrapKind::Brk => "brk",
        TrapKind::Udf => "udf",
    }
}

fn condition_name(condition: Condition) -> &'static str {
    match condition {
        Condition::EQ => "eq",
        Condition::NE => "ne",
        Condition::CS => "cs",
        Condition::CC => "cc",
        Condition::MI => "mi",
        Condition::PL => "pl",
        Condition::VS => "vs",
        Condition::VC => "vc",
        Condition::HI => "hi",
        Condition::LS => "ls",
        Condition::GE => "ge",
        Condition::LT => "lt",
        Condition::GT => "gt",
        Condition::LE => "le",
        Condition::AL => "al",
        Condition::NV => "nv",
    }
}

fn hex(value: u64) -> String {
    format!("0x{:x}", value)
}
