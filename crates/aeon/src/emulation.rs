use std::collections::{BTreeMap, BTreeSet};

use aeonil::{Condition, Expr, IntrinsicName, IntrinsicOp, Reg, Stmt, VectorArrangement};

mod vector;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    U64(u64),
    U128(u128),
    F64(f64),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryLocation {
    Unknown,
    Absolute(u64),
    StackSlot(i64),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemoryCellId {
    pub location: MemoryLocation,
    pub size: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryCell {
    pub id: MemoryCellId,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionResult {
    pub final_registers: BTreeMap<Reg, Value>,
    pub touched_memory: Vec<MemoryCell>,
    pub budget_exhausted: bool,
    pub steps_executed: usize,
}

pub trait BackingStore {
    fn load(&self, addr: u64, size: u8) -> Option<Vec<u8>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryValueSource {
    Overlay,
    BackingStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingMemoryPolicy {
    Stop,
    ContinueAsUnknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryReadObservation {
    pub id: MemoryCellId,
    pub value: Value,
    pub source: Option<MemoryValueSource>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryWriteObservation {
    pub id: MemoryCellId,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockStop {
    Completed,
    StepBudget,
    MissingMemory { location: MemoryLocation, size: u8 },
    SymbolicBranch,
    UnsupportedControlFlow,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockExecutionResult {
    pub final_registers: BTreeMap<Reg, Value>,
    pub final_memory: BTreeMap<MemoryCellId, Value>,
    pub reads: Vec<MemoryReadObservation>,
    pub writes: Vec<MemoryWriteObservation>,
    pub next_pc: Option<u64>,
    pub stop: BlockStop,
    pub steps_executed: usize,
}

pub fn execute_block(
    stmts: &[Stmt],
    initial_registers: BTreeMap<Reg, Value>,
    initial_memory: BTreeMap<MemoryCellId, Value>,
    backing: &dyn BackingStore,
    missing_memory_policy: MissingMemoryPolicy,
    step_budget: usize,
) -> BlockExecutionResult {
    let mut executor = Executor::new(
        initial_registers,
        initial_memory,
        backing,
        missing_memory_policy,
        ExecMode::Block,
    );
    let mut steps_executed = 0usize;

    for (idx, stmt) in stmts.iter().enumerate() {
        if steps_executed == step_budget {
            return executor.finish(BlockStop::StepBudget, steps_executed);
        }
        if !executor.execute_stmt(stmt) {
            let stop = executor.stop.clone();
            return executor.finish(stop, steps_executed + 1);
        }
        steps_executed = idx + 1;
    }

    executor.finish(BlockStop::Completed, steps_executed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Nzcv {
    n: bool,
    z: bool,
    c: bool,
    v: bool,
}

/// What the two entry points treat differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecMode {
    /// A straight-line snippet: control-flow statements are skipped and stack
    /// slots keep their symbolic `StackSlot` identity.
    Snippet,
    /// One basic block: control flow ends the block and stack slots resolve
    /// through SP when it is known.
    Block,
}

struct Executor<'a> {
    registers: BTreeMap<Reg, Value>,
    memory: BTreeMap<MemoryCellId, Value>,
    flags: Option<Nzcv>,
    backing: &'a dyn BackingStore,
    missing_memory_policy: MissingMemoryPolicy,
    mode: ExecMode,
    reads: Vec<MemoryReadObservation>,
    writes: Vec<MemoryWriteObservation>,
    next_pc: Option<u64>,
    stop: BlockStop,
    /// Destination of the assignment being evaluated. Conversions take their
    /// result width from it, since the IL does not carry one.
    assign_dst: Option<Reg>,
}

/// Backing store for snippets, which only ever see memory they wrote.
struct NoBacking;

impl BackingStore for NoBacking {
    fn load(&self, _addr: u64, _size: u8) -> Option<Vec<u8>> {
        None
    }
}

pub fn execute_snippet(
    stmts: &[Stmt],
    initial_registers: BTreeMap<Reg, Value>,
    step_budget: usize,
) -> ExecutionResult {
    let mut executor = Executor::new(
        initial_registers,
        BTreeMap::new(),
        &NoBacking,
        MissingMemoryPolicy::ContinueAsUnknown,
        ExecMode::Snippet,
    );
    let mut steps_executed = 0usize;

    for stmt in stmts {
        if steps_executed == step_budget {
            break;
        }
        executor.execute_stmt(stmt);
        steps_executed += 1;
    }

    let budget_exhausted = steps_executed < stmts.len();
    let touched: BTreeSet<MemoryCellId> = executor
        .reads
        .iter()
        .map(|read| &read.id)
        .chain(executor.writes.iter().map(|write| &write.id))
        .filter(|id| !matches!(id.location, MemoryLocation::Unknown))
        .cloned()
        .collect();
    let touched_memory = touched
        .into_iter()
        .map(|id| MemoryCell {
            value: executor.memory.get(&id).cloned().unwrap_or(Value::Unknown),
            id,
        })
        .collect();

    ExecutionResult {
        final_registers: executor.registers,
        touched_memory,
        budget_exhausted,
        steps_executed,
    }
}

impl<'a> Executor<'a> {
    fn new(
        initial_registers: BTreeMap<Reg, Value>,
        initial_memory: BTreeMap<MemoryCellId, Value>,
        backing: &'a dyn BackingStore,
        missing_memory_policy: MissingMemoryPolicy,
        mode: ExecMode,
    ) -> Self {
        let mut executor = Self {
            registers: BTreeMap::new(),
            memory: initial_memory,
            flags: None,
            backing,
            missing_memory_policy,
            mode,
            reads: Vec::new(),
            writes: Vec::new(),
            next_pc: None,
            stop: BlockStop::Completed,
            assign_dst: None,
        };

        let mut delayed_x_regs = Vec::new();
        for (reg, value) in initial_registers {
            if matches!(reg, Reg::X(_)) {
                delayed_x_regs.push((reg, value));
            } else {
                executor.write_reg(reg, value);
            }
        }
        for (reg, value) in delayed_x_regs {
            executor.write_reg(reg, value);
        }

        executor
    }

    fn finish(self, stop: BlockStop, steps_executed: usize) -> BlockExecutionResult {
        BlockExecutionResult {
            final_registers: self.registers,
            final_memory: self.memory,
            reads: self.reads,
            writes: self.writes,
            next_pc: self.next_pc,
            stop,
            steps_executed,
        }
    }

    /// Returns `false` once the block has stopped. Snippets never stop.
    fn execute_stmt(&mut self, stmt: &Stmt) -> bool {
        if self.mode == ExecMode::Snippet
            && matches!(
                stmt,
                Stmt::Branch { .. }
                    | Stmt::CondBranch { .. }
                    | Stmt::Call { .. }
                    | Stmt::Ret
                    | Stmt::Trap { .. }
            )
        {
            return true;
        }
        match stmt {
            Stmt::Assign { dst, src } => {
                self.assign_dst = Some(dst.clone());
                let value = self.eval_expr(src);
                self.assign_dst = None;
                if !matches!(self.stop, BlockStop::Completed) {
                    return false;
                }
                // A float immediate takes the format of the register it lands in.
                let value = match (value, dst) {
                    (Value::F64(float), Reg::S(_)) => Value::U64(u64::from((float as f32).to_bits())),
                    (Value::F64(float), Reg::D(_)) => Value::U64(float.to_bits()),
                    (value, _) => value,
                };
                self.write_reg(dst.clone(), value);
                true
            }
            Stmt::Store { addr, value, size } => {
                let cell_id =
                    self.resolve_memory_cell(addr, *size)
                        .unwrap_or_else(|| MemoryCellId {
                            location: MemoryLocation::Unknown,
                            size: *size,
                        });
                let stored = mask_value(self.eval_expr(value), *size);
                if !matches!(self.stop, BlockStop::Completed) {
                    return false;
                }
                if matches!(cell_id.location, MemoryLocation::Unknown) {
                    self.writes.push(MemoryWriteObservation {
                        id: cell_id,
                        value: stored,
                    });
                    if matches!(self.missing_memory_policy, MissingMemoryPolicy::Stop) {
                        self.stop = BlockStop::MissingMemory {
                            location: MemoryLocation::Unknown,
                            size: *size,
                        };
                        return false;
                    }
                    return true;
                }
                write_memory_overlay(&mut self.memory, &cell_id, &stored);
                self.writes.push(MemoryWriteObservation {
                    id: cell_id,
                    value: stored,
                });
                true
            }
            Stmt::SetFlags { expr } => {
                self.apply_flags(expr);
                matches!(self.stop, BlockStop::Completed)
            }
            Stmt::Pair(lhs, rhs) => {
                if !self.execute_stmt(lhs) {
                    return false;
                }
                self.execute_stmt(rhs)
            }
            Stmt::Branch { target } => {
                let target = self.eval_expr(target);
                if let Some(next_pc) = target.as_u64() {
                    self.next_pc = Some(next_pc);
                    self.stop = BlockStop::Completed;
                } else if matches!(self.stop, BlockStop::Completed) {
                    self.stop = BlockStop::SymbolicBranch;
                }
                false
            }
            Stmt::CondBranch {
                cond,
                target,
                fallthrough,
            } => {
                let taken = self.eval_branch_cond(cond);
                if !matches!(self.stop, BlockStop::Completed) {
                    return false;
                }
                match taken {
                    Some(true) => {
                        let target = self.eval_expr(target);
                        if let Some(next_pc) = target.as_u64() {
                            self.next_pc = Some(next_pc);
                            self.stop = BlockStop::Completed;
                        } else {
                            self.stop = BlockStop::SymbolicBranch;
                        }
                    }
                    Some(false) => {
                        self.next_pc = Some(*fallthrough);
                        self.stop = BlockStop::Completed;
                    }
                    None => {
                        self.stop = BlockStop::SymbolicBranch;
                    }
                }
                false
            }
            Stmt::Ret => {
                match self.read_reg(&Reg::X(30)).as_u64() {
                    Some(next_pc) => {
                        self.next_pc = Some(next_pc);
                        self.stop = BlockStop::Completed;
                    }
                    None => self.stop = BlockStop::SymbolicBranch,
                }
                false
            }
            Stmt::Call { .. } | Stmt::Trap { .. } => {
                self.stop = BlockStop::UnsupportedControlFlow;
                false
            }
            Stmt::Nop => panic_on_noop_stmt(stmt),
            Stmt::Barrier(kind) => {
                if !is_supported_barrier(kind) {
                    panic_on_unsupported_stmt(stmt);
                }
                true
            }
            Stmt::Intrinsic { name, operands } => self.execute_stmt_intrinsic(name, operands),
        }
    }

    fn eval_expr(&mut self, expr: &Expr) -> Value {
        match expr {
            Expr::Reg(reg) => self.read_reg(reg),
            Expr::Imm(value) | Expr::AdrpImm(value) | Expr::AdrImm(value) => Value::U64(*value),
            Expr::Imm32(value) => Value::U64(u64::from(*value)),
            Expr::FImm(value) => Value::F64(*value),
            Expr::Load { addr, size } => {
                let cell_id =
                    self.resolve_memory_cell(addr, *size)
                        .unwrap_or_else(|| MemoryCellId {
                            location: MemoryLocation::Unknown,
                            size: *size,
                        });
                self.load_memory(&cell_id)
            }
            Expr::Add(lhs, rhs) => self.eval_binary_u64(lhs, rhs, u64::wrapping_add),
            Expr::Sub(lhs, rhs) => self.eval_binary_u64(lhs, rhs, u64::wrapping_sub),
            Expr::Mul(lhs, rhs) => self.eval_binary_u64(lhs, rhs, u64::wrapping_mul),
            // AArch64 division never traps: x / 0 is 0 and MIN / -1 is MIN.
            Expr::Div(lhs, rhs) => {
                let narrow = operand_is_32_bit(lhs, rhs);
                self.eval_binary_u64(lhs, rhs, move |a, b| {
                    if narrow {
                        let (a, b) = (a as i32, b as i32);
                        if b == 0 {
                            0
                        } else {
                            a.wrapping_div(b) as u32 as u64
                        }
                    } else {
                        let (a, b) = (a as i64, b as i64);
                        if b == 0 {
                            0
                        } else {
                            a.wrapping_div(b) as u64
                        }
                    }
                })
            }
            Expr::UDiv(lhs, rhs) => {
                let mask = if operand_is_32_bit(lhs, rhs) {
                    0xffff_ffff
                } else {
                    u64::MAX
                };
                self.eval_binary_u64(lhs, rhs, move |a, b| {
                    let (a, b) = (a & mask, b & mask);
                    if b == 0 {
                        0
                    } else {
                        a / b
                    }
                })
            }
            Expr::Neg(inner) => self.eval_unary_u64(inner, u64::wrapping_neg),
            Expr::Abs(inner) => self.eval_unary_u64(inner, |value| {
                if (value as i64) < 0 {
                    (value as i64).wrapping_abs() as u64
                } else {
                    value
                }
            }),
            Expr::And(lhs, rhs) => self.eval_binary_u64(lhs, rhs, |a, b| a & b),
            Expr::Or(lhs, rhs) => self.eval_binary_u64(lhs, rhs, |a, b| a | b),
            Expr::Xor(lhs, rhs) => self.eval_binary_u64(lhs, rhs, |a, b| a ^ b),
            Expr::Not(inner) => self.eval_unary_u64(inner, |value| !value),
            Expr::Shl(lhs, rhs) => self.eval_shift(lhs, rhs, |a, n, _| a << n),
            Expr::Lsr(lhs, rhs) => self.eval_shift(lhs, rhs, |a, n, _| a >> n),
            Expr::Asr(lhs, rhs) => self.eval_shift(lhs, rhs, |a, n, bits| {
                if bits == 32 {
                    ((a as u32 as i32) >> n) as u32 as u64
                } else {
                    ((a as i64) >> n) as u64
                }
            }),
            Expr::Ror(lhs, rhs) => self.eval_shift(lhs, rhs, |a, n, bits| {
                if bits == 32 {
                    (a as u32).rotate_right(n) as u64
                } else {
                    a.rotate_right(n)
                }
            }),
            Expr::SignExtend { src, from_bits } => {
                self.eval_unary_u64(src, |value| sign_extend(value, *from_bits))
            }
            Expr::ZeroExtend { src, from_bits } => {
                self.eval_unary_u64(src, |value| apply_mask(value, *from_bits))
            }
            Expr::Extract { src, lsb, width } => {
                extract_value_bits(self.eval_expr(src), *lsb, *width)
            }
            Expr::Insert {
                dst,
                src,
                lsb,
                width,
            } => {
                let dst_value = self.eval_expr(dst);
                let src_value = self.eval_expr(src);
                insert_value_bits(dst_value, src_value, *lsb, *width)
            }
            Expr::CondSelect {
                cond,
                if_true,
                if_false,
            } => match eval_condition(self.flags, *cond) {
                Some(true) => self.eval_expr(if_true),
                Some(false) => self.eval_expr(if_false),
                None => Value::Unknown,
            },
            Expr::Compare { cond, lhs, rhs } => {
                let lhs_value = self.eval_expr(lhs);
                let rhs_value = self.eval_expr(rhs);
                match (lhs_value.as_u64(), rhs_value.as_u64()) {
                    (Some(lhs_bits), Some(rhs_bits)) => {
                        match eval_compare(*cond, lhs_bits, rhs_bits) {
                            Some(result) => Value::U64(u64::from(result)),
                            None => Value::Unknown,
                        }
                    }
                    _ => Value::Unknown,
                }
            }
            Expr::StackSlot { offset, .. } => self
                .read_reg(&Reg::SP)
                .as_u64()
                .map(|sp| Value::U64(sp.wrapping_add(*offset as u64)))
                .unwrap_or(Value::Unknown),
            Expr::Intrinsic { name, operands } => self.eval_expr_intrinsic(expr, name, operands),
            Expr::Clz(inner) => self.eval_unary_with_width(inner, leading_zeros_for_width),
            Expr::Cls(inner) => self.eval_unary_with_width(inner, leading_sign_bits_for_width),
            Expr::Rev(inner) => self.eval_unary_with_width(inner, reverse_bytes_for_width),
            Expr::Rbit(inner) => self.eval_unary_with_width(inner, reverse_bits_for_width),
            Expr::FAdd(lhs, rhs) => self.eval_float_binary(expr, lhs, rhs, FloatBinary::Add),
            Expr::FSub(lhs, rhs) => self.eval_float_binary(expr, lhs, rhs, FloatBinary::Sub),
            Expr::FMul(lhs, rhs) => self.eval_float_binary(expr, lhs, rhs, FloatBinary::Mul),
            Expr::FDiv(lhs, rhs) => self.eval_float_binary(expr, lhs, rhs, FloatBinary::Div),
            Expr::FMax(lhs, rhs) => self.eval_float_binary(expr, lhs, rhs, FloatBinary::Max),
            Expr::FMin(lhs, rhs) => self.eval_float_binary(expr, lhs, rhs, FloatBinary::Min),
            Expr::FNeg(inner) => self.eval_float_unary(expr, inner, FloatUnary::Neg),
            Expr::FAbs(inner) => self.eval_float_unary(expr, inner, FloatUnary::Abs),
            Expr::FSqrt(inner) => self.eval_float_unary(expr, inner, FloatUnary::Sqrt),
            Expr::FCvt(inner) => {
                let from = float_bits(inner).unwrap_or(64);
                let to = self.float_result_bits(expr);
                match self.eval_float(inner, from) {
                    Some(value) => encode_float(value, to),
                    None => Value::Unknown,
                }
            }
            Expr::IntToFloat(inner) => self.eval_int_to_float(expr, inner, true),
            Expr::FloatToInt(inner) => self.eval_float_to_int(inner, FloatRounding::Zero, true),
            Expr::MrsRead(_) => panic_on_unsupported_expr(expr),
        }
    }

    fn eval_expr_intrinsic(&mut self, expr: &Expr, name: &IntrinsicName, operands: &[Expr]) -> Value {
        let op = name.op();
        match op {
            IntrinsicOp::Movk => {
                let dst = operands
                    .first()
                    .map(|expr| self.eval_expr(expr))
                    .and_then(|value| value.as_u64());
                let src = operands
                    .get(1)
                    .map(|expr| self.eval_expr(expr))
                    .and_then(|value| value.as_u64());
                // As lifted the immediate is `imm16 << shift`, which says
                // where the field is even when imm16 is zero.
                let shift = match operands.get(1) {
                    Some(Expr::Shl(_, amount)) => match amount.as_ref() {
                        Expr::Imm(shift) => Some(*shift as u32),
                        _ => None,
                    },
                    _ => None,
                };
                eval_movk_bits(dst, src, shift)
            }
            IntrinsicOp::Smulh | IntrinsicOp::Umulh => eval_mul_high(
                operands.first().map(|expr| self.eval_expr(expr)),
                operands.get(1).map(|expr| self.eval_expr(expr)),
                op == IntrinsicOp::Smulh,
            ),
            IntrinsicOp::Adc | IntrinsicOp::Sbc if operands.len() >= 2 => {
                let bits = expr_bit_width(&operands[0])
                    .or_else(|| expr_bit_width(&operands[1]))
                    .unwrap_or(64);
                let lhs = self.eval_expr(&operands[0]).as_u64();
                let rhs = self.eval_expr(&operands[1]).as_u64();
                self.add_with_carry(lhs, rhs, bits, op == IntrinsicOp::Sbc)
                    .map(|(result, _)| Value::U64(result))
                    .unwrap_or(Value::Unknown)
            }
            IntrinsicOp::Ngc if !operands.is_empty() => {
                let bits = expr_bit_width(&operands[0]).unwrap_or(64);
                let rhs = self.eval_expr(&operands[0]).as_u64();
                self.add_with_carry(Some(0), rhs, bits, true)
                    .map(|(result, _)| Value::U64(result))
                    .unwrap_or(Value::Unknown)
            }
            IntrinsicOp::Rev16 | IntrinsicOp::Rev32 if !operands.is_empty() => {
                let group = if op == IntrinsicOp::Rev16 { 2 } else { 4 };
                let width = expr_bit_width(&operands[0]).unwrap_or(64);
                match self.eval_expr(&operands[0]).as_u64() {
                    Some(bits) => Value::U64(reverse_bytes_in_groups(bits, width, group)),
                    None => Value::Unknown,
                }
            }
            _ if name.arrangement().is_some() && !operands.is_empty() => {
                self.eval_vector_conversion(expr, name, &operands[0])
            }
            IntrinsicOp::Scvtf | IntrinsicOp::Ucvtf
                if name.suffix().is_none() && !operands.is_empty() =>
            {
                self.eval_int_to_float(expr, &operands[0], op == IntrinsicOp::Scvtf)
            }
            _ if name.suffix().is_none() && !operands.is_empty() => {
                match float_to_int_mode(op) {
                    Some((rounding, signed)) => {
                        self.eval_float_to_int(&operands[0], rounding, signed)
                    }
                    None => panic_on_unsupported_expr(expr),
                }
            }
            _ => panic_on_unsupported_expr(expr),
        }
    }

    /// `lhs + rhs + C`, or `lhs + !rhs + C` for a subtraction, at `bits`
    /// wide, with the flags it produces. `None` if any input, including the
    /// carry flag, is unknown.
    fn add_with_carry(
        &self,
        lhs: Option<u64>,
        rhs: Option<u64>,
        bits: u8,
        subtract: bool,
    ) -> Option<(u64, Nzcv)> {
        let mask = width_mask(bits);
        let carry_in = u128::from(self.flags?.c);
        let lhs = lhs? & mask;
        let rhs = if subtract { !rhs? & mask } else { rhs? & mask };
        let full = u128::from(lhs) + u128::from(rhs) + carry_in;
        let result = (full as u64) & mask;
        let sign = sign_bit(bits);
        Some((
            result,
            Nzcv {
                n: result & sign != 0,
                z: result == 0,
                c: full > u128::from(mask),
                v: (lhs ^ result) & (rhs ^ result) & sign != 0,
            },
        ))
    }

    /// Width of the float an expression produces: from its operands if they
    /// name a register, otherwise from the assignment's destination.
    fn float_result_bits(&self, expr: &Expr) -> u8 {
        let from_dst = match self.assign_dst {
            Some(Reg::S(_)) => Some(32),
            Some(Reg::D(_)) => Some(64),
            _ => None,
        };
        match expr {
            // Conversions say nothing about their result format.
            Expr::FCvt(_) | Expr::IntToFloat(_) | Expr::Intrinsic { .. } => from_dst.unwrap_or(64),
            _ => float_bits(expr).or(from_dst).unwrap_or(64),
        }
    }

    /// Evaluates `expr` as a float held in `bits` bits. SIMD registers hold
    /// raw bit patterns, so the width decides how they are read.
    fn eval_float(&mut self, expr: &Expr, bits: u8) -> Option<f64> {
        match self.eval_expr(expr) {
            Value::F64(value) => Some(value),
            Value::U64(raw) if bits == 32 => Some(f64::from(f32::from_bits(raw as u32))),
            Value::U64(raw) => Some(f64::from_bits(raw)),
            Value::U128(_) | Value::Unknown => None,
        }
    }

    fn eval_float_binary(&mut self, expr: &Expr, lhs: &Expr, rhs: &Expr, op: FloatBinary) -> Value {
        let bits = self.float_result_bits(expr);
        let (Some(lhs), Some(rhs)) = (self.eval_float(lhs, bits), self.eval_float(rhs, bits)) else {
            return Value::Unknown;
        };
        // A 32-bit operation computed in f64 and rounded once to f32 gives the
        // correctly rounded f32 result for these operations.
        if let Some(nan) = propagated_nan(lhs, rhs) {
            return encode_float(nan, bits);
        }
        let result = match op {
            FloatBinary::Add => lhs + rhs,
            FloatBinary::Sub => lhs - rhs,
            FloatBinary::Mul => lhs * rhs,
            FloatBinary::Div => lhs / rhs,
            // `max`/`min` on equal operands must still order -0.0 below +0.0.
            FloatBinary::Max if lhs == rhs => {
                if lhs.is_sign_negative() { rhs } else { lhs }
            }
            FloatBinary::Min if lhs == rhs => {
                if lhs.is_sign_negative() { lhs } else { rhs }
            }
            FloatBinary::Max => lhs.max(rhs),
            FloatBinary::Min => lhs.min(rhs),
        };
        encode_float(default_nan_if_generated(result, false), bits)
    }

    fn eval_float_unary(&mut self, expr: &Expr, inner: &Expr, op: FloatUnary) -> Value {
        let bits = self.float_result_bits(expr);
        let Some(value) = self.eval_float(inner, bits) else {
            return Value::Unknown;
        };
        let result = match op {
            FloatUnary::Neg => -value,
            FloatUnary::Abs => value.abs(),
            FloatUnary::Sqrt => default_nan_if_generated(value.sqrt(), value.is_nan()),
        };
        encode_float(result, bits)
    }

    fn eval_int_to_float(&mut self, expr: &Expr, inner: &Expr, signed: bool) -> Value {
        let bits = self.float_result_bits(expr);
        let narrow = expr_bit_width(inner) == Some(32);
        let Some(raw) = self.eval_expr(inner).as_u64() else {
            return Value::Unknown;
        };
        // Convert straight to the target format: going through f64 first
        // would round a 64-bit integer twice on its way to f32.
        match (bits, signed, narrow) {
            (32, true, true) => encode_f32(raw as i32 as f32),
            (32, true, false) => encode_f32(raw as i64 as f32),
            (32, false, true) => encode_f32(raw as u32 as f32),
            (32, false, false) => encode_f32(raw as f32),
            (_, true, true) => Value::U64((raw as i32 as f64).to_bits()),
            (_, true, false) => Value::U64((raw as i64 as f64).to_bits()),
            (_, false, true) => Value::U64((raw as u32 as f64).to_bits()),
            (_, false, false) => Value::U64((raw as f64).to_bits()),
        }
    }

    fn eval_float_to_int(&mut self, inner: &Expr, rounding: FloatRounding, signed: bool) -> Value {
        let from = float_bits(inner).unwrap_or(64);
        let narrow = matches!(self.assign_dst, Some(Reg::W(_)));
        let Some(value) = self.eval_float(inner, from) else {
            return Value::Unknown;
        };
        let rounded = round_float(value, rounding);
        // Rust's float-to-int casts saturate and map NaN to 0, as AArch64 does.
        Value::U64(match (signed, narrow) {
            (true, true) => rounded as i32 as u32 as u64,
            (true, false) => rounded as i64 as u64,
            (false, true) => u64::from(rounded as u32),
            (false, false) => rounded as u64,
        })
    }

    fn load_memory(&mut self, cell_id: &MemoryCellId) -> Value {
        if let Some(value) = self.memory.get(cell_id).cloned() {
            self.reads.push(MemoryReadObservation {
                id: cell_id.clone(),
                value: value.clone(),
                source: Some(MemoryValueSource::Overlay),
            });
            return value;
        }

        let backing_addr = match cell_id.location {
            MemoryLocation::Unknown => None,
            MemoryLocation::Absolute(addr) => Some(addr),
            MemoryLocation::StackSlot(offset) => self
                .read_reg(&Reg::SP)
                .as_u64()
                .map(|sp| sp.wrapping_add(offset as u64)),
        };
        let backing = backing_addr.and_then(|addr| self.backing.load(addr, cell_id.size));

        // A load can straddle stores: take each byte from the overlay if it
        // was written, otherwise from the backing store.
        match compose_load(&self.memory, cell_id, backing.as_deref()) {
            ComposedLoad::Bytes { bytes, overlay } => {
                let value = decode_loaded_value(&bytes);
                self.reads.push(MemoryReadObservation {
                    id: cell_id.clone(),
                    value: value.clone(),
                    source: Some(if overlay {
                        MemoryValueSource::Overlay
                    } else {
                        MemoryValueSource::BackingStore
                    }),
                });
                return value;
            }
            ComposedLoad::UnknownByte => {
                self.reads.push(MemoryReadObservation {
                    id: cell_id.clone(),
                    value: Value::Unknown,
                    source: Some(MemoryValueSource::Overlay),
                });
                return Value::Unknown;
            }
            ComposedLoad::Missing => {}
        }

        self.reads.push(MemoryReadObservation {
            id: cell_id.clone(),
            value: Value::Unknown,
            source: None,
        });
        if matches!(self.missing_memory_policy, MissingMemoryPolicy::Stop) {
            self.stop = BlockStop::MissingMemory {
                location: cell_id.location.clone(),
                size: cell_id.size,
            };
        }
        Value::Unknown
    }

    fn eval_binary_u64(&mut self, lhs: &Expr, rhs: &Expr, op: impl Fn(u64, u64) -> u64) -> Value {
        let lhs_value = self.eval_expr(lhs);
        let rhs_value = self.eval_expr(rhs);
        match (lhs_value.as_u64(), rhs_value.as_u64()) {
            (Some(lhs_bits), Some(rhs_bits)) => Value::U64(op(lhs_bits, rhs_bits)),
            _ => Value::Unknown,
        }
    }

    /// Shifts and rotates at the width of the value operand. As on AArch64,
    /// the amount is taken modulo that width, and a 32-bit result does not
    /// carry bits above bit 31.
    fn eval_shift(
        &mut self,
        value: &Expr,
        amount: &Expr,
        op: impl Fn(u64, u32, u32) -> u64,
    ) -> Value {
        let bits: u32 = if is_32_bit_operand(value) { 32 } else { 64 };
        let mask = if bits == 32 { 0xffff_ffff } else { u64::MAX };
        self.eval_binary_u64(value, amount, move |a, n| {
            op(a & mask, (n % u64::from(bits)) as u32, bits) & mask
        })
    }

    fn eval_unary_u64(&mut self, expr: &Expr, op: impl Fn(u64) -> u64) -> Value {
        let value = self.eval_expr(expr);
        match value.as_u64() {
            Some(bits) => Value::U64(op(bits)),
            None => Value::Unknown,
        }
    }

    fn eval_unary_with_width(&mut self, expr: &Expr, op: impl Fn(u64, u8) -> u64) -> Value {
        let value = self.eval_expr(expr);
        let width = expr_bit_width(expr).unwrap_or(64);
        match value.as_u64() {
            Some(bits) => Value::U64(op(bits, width)),
            None => Value::Unknown,
        }
    }

    fn eval_branch_cond(&mut self, cond: &aeonil::BranchCond) -> Option<bool> {
        match cond {
            aeonil::BranchCond::Flag(cond) => eval_condition(self.flags, *cond),
            aeonil::BranchCond::Zero(expr) => self.eval_expr(expr).as_u64().map(|value| value == 0),
            aeonil::BranchCond::NotZero(expr) => {
                self.eval_expr(expr).as_u64().map(|value| value != 0)
            }
            aeonil::BranchCond::BitZero(expr, bit) => self
                .eval_expr(expr)
                .as_u64()
                .map(|value| (value & (1u64 << bit)) == 0),
            aeonil::BranchCond::BitNotZero(expr, bit) => self
                .eval_expr(expr)
                .as_u64()
                .map(|value| (value & (1u64 << bit)) != 0),
            aeonil::BranchCond::Compare { cond, lhs, rhs } => {
                let lhs_value = self.eval_expr(lhs);
                let rhs_value = self.eval_expr(rhs);
                match (lhs_value.as_u64(), rhs_value.as_u64()) {
                    (Some(lhs_bits), Some(rhs_bits)) => eval_compare(*cond, lhs_bits, rhs_bits),
                    _ => None,
                }
            }
        }
    }

    fn resolve_memory_cell(&mut self, expr: &Expr, size: u8) -> Option<MemoryCellId> {
        let location = self.resolve_memory_location(expr)?;
        Some(MemoryCellId { location, size })
    }

    fn resolve_memory_location(&mut self, expr: &Expr) -> Option<MemoryLocation> {
        match expr {
            Expr::Reg(Reg::W(index)) => self
                .read_reg(&Reg::X(*index))
                .as_u64()
                .map(MemoryLocation::Absolute),
            Expr::StackSlot { offset, .. } => match self.mode {
                ExecMode::Snippet => Some(MemoryLocation::StackSlot(*offset)),
                ExecMode::Block => self
                    .read_reg(&Reg::SP)
                    .as_u64()
                    .map(|sp| MemoryLocation::Absolute(sp.wrapping_add(*offset as u64)))
                    .or(Some(MemoryLocation::StackSlot(*offset))),
            },
            Expr::Add(lhs, rhs) => self.add_location(lhs, rhs, false),
            Expr::Sub(lhs, rhs) => self.add_location(lhs, rhs, true),
            _ => self.eval_expr(expr).as_u64().map(MemoryLocation::Absolute),
        }
    }

    fn add_location(&mut self, lhs: &Expr, rhs: &Expr, subtract: bool) -> Option<MemoryLocation> {
        if let Some(location) = self.resolve_memory_location(lhs) {
            let delta = self.eval_expr(rhs).as_u64()? as i64;
            return Some(offset_location(location, delta, subtract));
        }
        if !subtract {
            if let Some(location) = self.resolve_memory_location(rhs) {
                let delta = self.eval_expr(lhs).as_u64()? as i64;
                return Some(offset_location(location, delta, false));
            }
        }
        None
    }

    fn apply_flags(&mut self, expr: &Expr) {
        let flags = self.compute_flags(expr);
        self.set_flags(flags);
    }

    fn compute_flags(&mut self, expr: &Expr) -> Option<Nzcv> {
        match expr {
            Expr::Imm(bits) => Some(Nzcv::from_bits(*bits)),
            Expr::CondSelect {
                cond,
                if_true,
                if_false,
            } => match eval_condition(self.flags, *cond) {
                Some(true) => self.compute_flags(if_true),
                Some(false) => self.compute_flags(if_false),
                None => None,
            },
            Expr::Add(lhs, rhs) => self.compute_add_flags(lhs, rhs),
            Expr::Sub(lhs, rhs) => self.compute_sub_flags(lhs, rhs),
            Expr::And(lhs, rhs) => self.compute_and_flags(lhs, rhs),
            // FCMP is lifted as the flags of a float subtraction.
            Expr::FSub(lhs, rhs) => self.compute_float_compare_flags(lhs, rhs),
            _ => None,
        }
    }

    fn compute_float_compare_flags(&mut self, lhs: &Expr, rhs: &Expr) -> Option<Nzcv> {
        let bits = float_bits(lhs).or_else(|| float_bits(rhs)).unwrap_or(64);
        let lhs = self.eval_float(lhs, bits)?;
        let rhs = self.eval_float(rhs, bits)?;
        Some(Nzcv::from_bits(match lhs.partial_cmp(&rhs) {
            Some(std::cmp::Ordering::Less) => 0b1000,
            Some(std::cmp::Ordering::Equal) => 0b0110,
            Some(std::cmp::Ordering::Greater) => 0b0010,
            None => 0b0011,
        }))
    }

    fn set_flags(&mut self, flags: Option<Nzcv>) {
        self.flags = flags;
        let stored = flags
            .map(|nzcv| Value::U64(nzcv.pack()))
            .unwrap_or(Value::Unknown);
        self.registers.insert(Reg::Flags, stored);
    }

    fn execute_carry_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr]) {
        let negate = name.op() == IntrinsicOp::Ngcs;
        let dst = operands.first().and_then(expr_reg_operand);
        let (lhs_expr, rhs_expr) = if negate {
            (None, operands.get(1))
        } else {
            (operands.get(1), operands.get(2))
        };
        let Some(rhs_expr) = rhs_expr else {
            panic!("aeon emulation: `{name}` is missing operands");
        };
        let bits = match &dst {
            Some(Reg::W(_)) => 32,
            Some(_) => 64,
            None => expr_bit_width(rhs_expr).unwrap_or(64),
        };
        let lhs = match lhs_expr {
            Some(expr) => self.eval_expr(expr).as_u64(),
            None => Some(0),
        };
        let rhs = self.eval_expr(rhs_expr).as_u64();
        let outcome = self.add_with_carry(lhs, rhs, bits, name.op() != IntrinsicOp::Adcs);
        self.set_flags(outcome.map(|(_, flags)| flags));
        if let Some(dst) = dst {
            let value = outcome
                .map(|(result, _)| Value::U64(result))
                .unwrap_or(Value::Unknown);
            self.write_reg(dst, value);
        }
    }

    /// EXTR: operands are `[dst, high, low, lsb]`; the result is `width` bits
    /// of `high:low` starting at `lsb`.
    fn execute_extr_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr]) {
        let (Some(dst), Some(high), Some(low), Some(Expr::Imm(lsb))) = (
            operands.first().and_then(expr_reg_operand),
            operands.get(1),
            operands.get(2),
            operands.get(3),
        ) else {
            panic!("aeon emulation: malformed `{name}` operands");
        };
        let bits: u32 = if matches!(dst, Reg::W(_)) { 32 } else { 64 };
        let mask = width_mask(bits as u8);
        let lsb = (*lsb as u32) % bits;
        let high = self.eval_expr(high).as_u64();
        let low = self.eval_expr(low).as_u64();
        let value = match (high, low) {
            (Some(high), Some(low)) => {
                let (high, low) = (high & mask, low & mask);
                Value::U64(if lsb == 0 {
                    low
                } else {
                    ((high << (bits - lsb)) | (low >> lsb)) & mask
                })
            }
            _ => Value::Unknown,
        };
        self.write_reg(dst, value);
    }

    /// FCCMP: operands are `[lhs, rhs, nzcv, cond]`.
    fn execute_fccmp_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr]) {
        let (Some(lhs), Some(rhs), Some(Expr::Imm(nzcv)), Some(Expr::Imm(cond))) =
            (operands.first(), operands.get(1), operands.get(2), operands.get(3))
        else {
            panic!("aeon emulation: malformed `{name}` operands");
        };
        let flags = match condition_from_code(*cond).and_then(|cond| eval_condition(self.flags, cond)) {
            Some(true) => self.compute_float_compare_flags(lhs, rhs),
            Some(false) => Some(Nzcv::from_bits(*nzcv)),
            None => None,
        };
        self.set_flags(flags);
    }

    fn compute_add_flags(&mut self, lhs: &Expr, rhs: &Expr) -> Option<Nzcv> {
        let bits = expr_bit_width(lhs)
            .or_else(|| expr_bit_width(rhs))
            .unwrap_or(64);
        let mask = width_mask(bits);
        let lhs_value = self.eval_expr(lhs).as_u64()? & mask;
        let rhs_value = self.eval_expr(rhs).as_u64()? & mask;
        let full = lhs_value as u128 + rhs_value as u128;
        let result = lhs_value.wrapping_add(rhs_value) & mask;
        let sign_bit = sign_bit(bits);
        Some(Nzcv {
            n: bits != 0 && (result & sign_bit) != 0,
            z: result == 0,
            c: full > mask as u128,
            v: bits != 0 && (((!(lhs_value ^ rhs_value)) & (lhs_value ^ result)) & sign_bit) != 0,
        })
    }

    fn compute_sub_flags(&mut self, lhs: &Expr, rhs: &Expr) -> Option<Nzcv> {
        let bits = expr_bit_width(lhs)
            .or_else(|| expr_bit_width(rhs))
            .unwrap_or(64);
        let mask = width_mask(bits);
        let lhs_value = self.eval_expr(lhs).as_u64()? & mask;
        let rhs_value = self.eval_expr(rhs).as_u64()? & mask;
        let result = lhs_value.wrapping_sub(rhs_value) & mask;
        let sign_bit = sign_bit(bits);
        Some(Nzcv {
            n: bits != 0 && (result & sign_bit) != 0,
            z: result == 0,
            c: lhs_value >= rhs_value,
            v: bits != 0 && (((lhs_value ^ rhs_value) & (lhs_value ^ result)) & sign_bit) != 0,
        })
    }

    fn compute_and_flags(&mut self, lhs: &Expr, rhs: &Expr) -> Option<Nzcv> {
        let bits = expr_bit_width(lhs)
            .or_else(|| expr_bit_width(rhs))
            .unwrap_or(64);
        let mask = width_mask(bits);
        let lhs_value = self.eval_expr(lhs).as_u64()?;
        let rhs_value = self.eval_expr(rhs).as_u64()?;
        let result = (lhs_value & rhs_value) & mask;
        let sign_bit = sign_bit(bits);
        Some(Nzcv {
            n: bits != 0 && (result & sign_bit) != 0,
            z: result == 0,
            c: false,
            v: false,
        })
    }

    fn execute_stmt_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr]) -> bool {
        match name.op() {
            IntrinsicOp::Movi => self.execute_vector_move_intrinsic(name, operands, false),
            IntrinsicOp::Mvni => self.execute_vector_move_intrinsic(name, operands, true),
            IntrinsicOp::Dup => self.execute_dup_intrinsic(name, operands),
            IntrinsicOp::Umov => self.execute_umov_intrinsic(name, operands),
            IntrinsicOp::Adcs | IntrinsicOp::Sbcs | IntrinsicOp::Ngcs => {
                self.execute_carry_intrinsic(name, operands)
            }
            IntrinsicOp::Extr => self.execute_extr_intrinsic(name, operands),
            IntrinsicOp::Fccmp | IntrinsicOp::Fccmpe => {
                self.execute_fccmp_intrinsic(name, operands)
            }
            op if crc32_intrinsic_info(op).is_some() => {
                self.execute_crc32_intrinsic(name, operands)
            }
            op => {
                if let Some(keep_going) = self.execute_vector_intrinsic(name, operands) {
                    return keep_going;
                }
                if !self.execute_lane_intrinsic(name, operands) && !is_supported_stmt_intrinsic(op) {
                    panic!(
                        "aeon emulation encountered unsupported IL statement intrinsic `{name}`"
                    );
                }
            }
        }
        true
    }

    fn execute_vector_move_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr], invert: bool) {
        let imm = operands
            .get(1)
            .map(|expr| self.eval_expr(expr))
            .and_then(|value| value.as_u64());
        let Some(dst) = operands.first().and_then(expr_reg_operand) else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        if matches!(dst, Reg::V(_) | Reg::Q(_)) {
            let Some(arrangement) = name.arrangement() else {
                panic!("aeon emulation is missing SIMD arrangement for `{name}`");
            };
            let value = imm
                .map(|imm| arranged_immediate_vector(imm, arrangement, invert))
                .map(Value::U128)
                .unwrap_or(Value::Unknown);
            write_arranged_vector_register(&mut self.registers, &dst, arrangement, value);
            return;
        }
        let size = scalar_simd_size(&dst)
            .unwrap_or_else(|| panic!("aeon emulation expected a SIMD destination for `{name}`"));
        let value = imm
            .map(|imm| {
                let bits = if invert { !imm } else { imm };
                scalar_or_unknown_value(Value::U64(bits), size)
            })
            .unwrap_or(Value::Unknown);
        self.write_reg(dst, value);
    }

    /// Runs a SIMD intrinsic that works lane by lane, with operands
    /// `[dst, sources...]`. Returns `false` if `name` is not such an
    /// intrinsic.
    fn execute_lane_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr]) -> bool {
        let op = name.op();
        let reversal_bytes = match op {
            IntrinsicOp::Rev64 => Some(8),
            IntrinsicOp::Rev32 => Some(4),
            IntrinsicOp::Rev16 => Some(2),
            _ => None,
        };
        let lane_op = lane_op(op);
        if lane_op.is_none() && reversal_bytes.is_none() {
            return false;
        }

        let Some(dst) = operands
            .first()
            .and_then(expr_reg_operand)
            .filter(|reg| simd_index(reg).is_some())
        else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        let arrangement = match (name.arrangement(), &dst) {
            (Some(arrangement), _) => arrangement,
            // The scalar forms (`cmeq d0, d1, d2`) work on one 64-bit lane.
            (None, Reg::D(_)) => VectorArrangement {
                lanes: 1,
                lane_bits: 64,
            },
            _ => panic!("aeon emulation is missing SIMD arrangement for `{name}`"),
        };

        // Accumulating operations also read the destination.
        let first_source = match lane_op {
            Some(LaneOp::Accumulate(_)) => 0,
            _ => 1,
        };
        let count = match lane_op {
            Some(LaneOp::Unary(_)) | None => 1,
            Some(LaneOp::Binary(_)) => 2,
            Some(LaneOp::Accumulate(_)) => 3,
        };
        let sources: Option<Vec<[u8; 16]>> = (first_source..first_source + count)
            .map(|index| {
                let expr = operands.get(index)?;
                let value = self.eval_expr(expr);
                vector_operand_bytes(expr, value, arrangement)
            })
            .collect();

        let value = match (sources, lane_op) {
            (None, _) => Value::Unknown,
            (Some(sources), Some(lane_op)) => {
                let bits = u32::from(arrangement.lane_bits);
                let lane_bytes = usize::from(arrangement.lane_bits / 8);
                let mask = width_mask(arrangement.lane_bits);
                let mut result = [0u8; 16];
                for lane in 0..usize::from(arrangement.lanes) {
                    let range = lane * lane_bytes..(lane + 1) * lane_bytes;
                    let read = |bytes: &[u8; 16]| {
                        let mut buf = [0u8; 8];
                        buf[..lane_bytes].copy_from_slice(&bytes[range.clone()]);
                        u64::from_le_bytes(buf)
                    };
                    let computed = match lane_op {
                        LaneOp::Unary(compute) => compute(read(&sources[0]), bits),
                        LaneOp::Binary(compute) => {
                            compute(read(&sources[0]), read(&sources[1]), bits)
                        }
                        LaneOp::Accumulate(compute) => compute(
                            read(&sources[0]),
                            read(&sources[1]),
                            read(&sources[2]),
                            bits,
                        ),
                    };
                    result[range.clone()]
                        .copy_from_slice(&(computed & mask).to_le_bytes()[..lane_bytes]);
                }
                Value::U128(u128::from_le_bytes(result))
            }
            (Some(sources), None) => {
                // REV64/REV32/REV16: reverse the lanes inside each container.
                let container = reversal_bytes.expect("checked above");
                let lane_bytes = usize::from(arrangement.lane_bits / 8);
                let active = usize::from(arrangement.active_bytes());
                let mut result = [0u8; 16];
                for (out, chunk) in result[..active]
                    .chunks_mut(container)
                    .zip(sources[0][..active].chunks(container))
                {
                    for (slot, lane) in out
                        .chunks_mut(lane_bytes)
                        .zip(chunk.chunks(lane_bytes).rev())
                    {
                        slot.copy_from_slice(lane);
                    }
                }
                Value::U128(u128::from_le_bytes(result))
            }
        };
        write_arranged_vector_register(&mut self.registers, &dst, arrangement, value);
        true
    }

    fn execute_dup_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr]) {
        let Some(arrangement) = name.arrangement() else {
            panic!("aeon emulation is missing SIMD arrangement for `{name}`");
        };
        let Some(dst) = operands.first().and_then(vector_reg_from_expr) else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        let value = operands
            .get(1)
            .map(|expr| self.eval_expr(expr))
            .and_then(|value| vector_dup(value, arrangement))
            .map(Value::U128)
            .unwrap_or(Value::Unknown);
        write_arranged_vector_register(&mut self.registers, &dst, arrangement, value);
    }

    fn execute_crc32_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr]) {
        let Some(dst) = operands.first().and_then(expr_reg_operand) else {
            panic!("aeon emulation expected a register destination for `{name}`");
        };
        let acc = operands
            .get(1)
            .map(|expr| self.eval_expr(expr))
            .and_then(|value| value.as_u64());
        let src = operands
            .get(2)
            .map(|expr| self.eval_expr(expr))
            .and_then(|value| value.as_u64());
        let value = match (acc, src, crc32_intrinsic_info(name.op())) {
            (Some(acc), Some(src), Some((poly, width))) => {
                Value::U64(crc32_update(acc as u32, src, width, poly) as u64)
            }
            _ => Value::Unknown,
        };
        self.write_reg(dst, value);
    }

    fn execute_umov_intrinsic(&mut self, name: &IntrinsicName, operands: &[Expr]) {
        let Some(dst) = operands.first().and_then(expr_reg_operand) else {
            panic!("aeon emulation expected a register destination for `{name}`");
        };
        let value = operands
            .get(1)
            .map(|expr| self.eval_expr(expr))
            .map(low_u64_value)
            .unwrap_or(Value::Unknown);
        self.write_reg(dst, value);
    }

    fn read_reg(&self, reg: &Reg) -> Value {
        read_register_value(&self.registers, reg)
    }

    fn write_reg(&mut self, reg: Reg, value: Value) {
        write_register_value(&mut self.registers, &mut self.flags, reg, value);
    }
}

impl Nzcv {
    fn from_bits(bits: u64) -> Self {
        Self {
            n: bits & 0b1000 != 0,
            z: bits & 0b0100 != 0,
            c: bits & 0b0010 != 0,
            v: bits & 0b0001 != 0,
        }
    }

    fn pack(self) -> u64 {
        ((self.n as u64) << 3) | ((self.z as u64) << 2) | ((self.c as u64) << 1) | (self.v as u64)
    }
}

impl Value {
    fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(value) => Some(*value),
            _ => None,
        }
    }
}

fn vector_reg_from_expr(expr: &Expr) -> Option<Reg> {
    match expr {
        Expr::Reg(reg @ (Reg::V(_) | Reg::Q(_))) => Some(reg.clone()),
        _ => None,
    }
}

fn expr_reg_operand(expr: &Expr) -> Option<Reg> {
    match expr {
        Expr::Reg(reg) => Some(reg.clone()),
        _ => None,
    }
}

fn read_register_value(registers: &BTreeMap<Reg, Value>, reg: &Reg) -> Value {
    match reg {
        Reg::XZR => Value::U64(0),
        Reg::W(index) => registers
            .get(reg)
            .cloned()
            .or_else(|| registers.get(&Reg::X(*index)).cloned().map(truncate_to_w))
            .unwrap_or(Value::Unknown),
        Reg::X(index) => registers
            .get(reg)
            .cloned()
            .or_else(|| registers.get(&Reg::W(*index)).cloned().map(zero_extend_w))
            .unwrap_or(Value::Unknown),
        Reg::V(_) | Reg::Q(_) | Reg::D(_) | Reg::S(_) | Reg::H(_) | Reg::VByte(_) => {
            read_simd_register_value(registers, reg).unwrap_or(Value::Unknown)
        }
        _ => registers.get(reg).cloned().unwrap_or(Value::Unknown),
    }
}

fn write_register_value(
    registers: &mut BTreeMap<Reg, Value>,
    flags: &mut Option<Nzcv>,
    reg: Reg,
    value: Value,
) {
    match reg {
        Reg::XZR => {}
        Reg::W(index) => {
            let w_value = truncate_to_w(value);
            let x_value = zero_extend_w(w_value.clone());
            registers.insert(Reg::W(index), w_value);
            registers.insert(Reg::X(index), x_value);
        }
        Reg::X(index) => {
            let w_value = truncate_to_w(value.clone());
            registers.insert(Reg::W(index), w_value);
            registers.insert(Reg::X(index), value);
        }
        Reg::Flags => {
            *flags = value.as_u64().map(Nzcv::from_bits);
            registers.insert(Reg::Flags, value);
        }
        Reg::V(_) | Reg::Q(_) | Reg::D(_) | Reg::S(_) | Reg::H(_) | Reg::VByte(_) => {
            write_simd_register_value(registers, reg, value);
        }
        _ => {
            registers.insert(reg, value);
        }
    }
}

fn simd_index(reg: &Reg) -> Option<u8> {
    match reg {
        Reg::V(index)
        | Reg::Q(index)
        | Reg::D(index)
        | Reg::S(index)
        | Reg::H(index)
        | Reg::VByte(index) => Some(*index),
        _ => None,
    }
}

fn scalar_simd_size(reg: &Reg) -> Option<usize> {
    match reg {
        Reg::D(_) => Some(8),
        Reg::S(_) => Some(4),
        Reg::H(_) => Some(2),
        Reg::VByte(_) => Some(1),
        _ => None,
    }
}

fn read_simd_register_value(registers: &BTreeMap<Reg, Value>, reg: &Reg) -> Option<Value> {
    let index = simd_index(reg)?;
    match reg {
        Reg::V(_) | Reg::Q(_) => {
            let bytes = read_simd_vector_bytes(registers, index)?;
            Some(Value::U128(u128::from_le_bytes(bytes)))
        }
        Reg::D(_) | Reg::S(_) | Reg::H(_) | Reg::VByte(_) => {
            let size = scalar_simd_size(reg)?;
            let bytes = read_simd_scalar_bytes(registers, index, size)?;
            Some(scalar_value_from_bytes(&bytes))
        }
        _ => None,
    }
}

fn read_simd_vector_bytes(registers: &BTreeMap<Reg, Value>, index: u8) -> Option<[u8; 16]> {
    if let Some(bytes) = registers
        .get(&Reg::V(index))
        .or_else(|| registers.get(&Reg::Q(index)))
        .and_then(vector_bytes_from_value)
    {
        return Some(bytes);
    }

    let mut bytes = [0u8; 16];
    let low = registers
        .get(&Reg::D(index))
        .and_then(|value| low_bytes_from_value(value, 8))
        .or_else(|| {
            registers
                .get(&Reg::S(index))
                .and_then(|value| low_bytes_from_value(value, 4))
        })
        .or_else(|| {
            registers
                .get(&Reg::H(index))
                .and_then(|value| low_bytes_from_value(value, 2))
        })
        .or_else(|| {
            registers
                .get(&Reg::VByte(index))
                .and_then(|value| low_bytes_from_value(value, 1))
        })?;
    bytes[..low.len()].copy_from_slice(&low);
    Some(bytes)
}

fn read_simd_scalar_bytes(
    registers: &BTreeMap<Reg, Value>,
    index: u8,
    size: usize,
) -> Option<Vec<u8>> {
    if let Some(bytes) = read_simd_vector_bytes(registers, index) {
        return Some(bytes[..size].to_vec());
    }

    let direct_regs: &[Reg] = match size {
        8 => &[Reg::D(index)],
        4 => &[Reg::S(index), Reg::D(index)],
        2 => &[Reg::H(index), Reg::S(index), Reg::D(index)],
        1 => &[
            Reg::VByte(index),
            Reg::H(index),
            Reg::S(index),
            Reg::D(index),
        ],
        _ => return None,
    };

    for direct in direct_regs {
        if let Some(bytes) = registers
            .get(direct)
            .and_then(|value| low_bytes_from_value(value, size))
        {
            return Some(bytes);
        }
    }

    None
}

fn write_simd_register_value(registers: &mut BTreeMap<Reg, Value>, reg: Reg, value: Value) {
    let Some(index) = simd_index(&reg) else {
        return;
    };

    match reg {
        Reg::V(_) | Reg::Q(_) => {
            clear_all_simd_aliases(registers, index);
            registers.insert(Reg::V(index), canonical_vector_value(value));
        }
        Reg::D(_) | Reg::S(_) | Reg::H(_) | Reg::VByte(_) => {
            // Writing a scalar view clears the rest of the 128-bit register.
            let size = scalar_simd_size(&reg).expect("scalar SIMD size");
            let vector = match low_bytes_from_value(&value, size) {
                Some(low) => {
                    let mut bytes = [0u8; 16];
                    bytes[..size].copy_from_slice(&low);
                    Value::U128(u128::from_le_bytes(bytes))
                }
                None => Value::Unknown,
            };
            clear_all_simd_aliases(registers, index);
            registers.insert(Reg::V(index), vector);
        }
        _ => {}
    }
}

fn clear_all_simd_aliases(registers: &mut BTreeMap<Reg, Value>, index: u8) {
    registers.remove(&Reg::V(index));
    registers.remove(&Reg::Q(index));
    clear_scalar_simd_aliases(registers, index);
}

fn clear_scalar_simd_aliases(registers: &mut BTreeMap<Reg, Value>, index: u8) {
    registers.remove(&Reg::D(index));
    registers.remove(&Reg::S(index));
    registers.remove(&Reg::H(index));
    registers.remove(&Reg::VByte(index));
}

fn canonical_vector_value(value: Value) -> Value {
    match value {
        Value::U128(_) | Value::Unknown => value,
        other => vector_bytes_from_value(&other)
            .map(|bytes| Value::U128(u128::from_le_bytes(bytes)))
            .unwrap_or(Value::Unknown),
    }
}

fn scalar_or_unknown_value(value: Value, size: usize) -> Value {
    low_bytes_from_value(&value, size)
        .map(|bytes| scalar_value_from_bytes(&bytes))
        .unwrap_or(Value::Unknown)
}

fn vector_bytes_from_value(value: &Value) -> Option<[u8; 16]> {
    match value {
        Value::U128(bits) => Some(bits.to_le_bytes()),
        Value::U64(bits) => {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&bits.to_le_bytes());
            Some(bytes)
        }
        Value::F64(value) => {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&value.to_bits().to_le_bytes());
            Some(bytes)
        }
        Value::Unknown => None,
    }
}

fn low_bytes_from_value(value: &Value, size: usize) -> Option<Vec<u8>> {
    if size == 0 || size > 8 {
        return None;
    }
    match value {
        Value::U64(bits) => Some(bits.to_le_bytes()[..size].to_vec()),
        Value::U128(bits) => Some(bits.to_le_bytes()[..size].to_vec()),
        Value::F64(value) => Some(value.to_bits().to_le_bytes()[..size].to_vec()),
        Value::Unknown => None,
    }
}

fn scalar_value_from_bytes(bytes: &[u8]) -> Value {
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    Value::U64(u64::from_le_bytes(buf))
}

/// How a lane-wise SIMD intrinsic computes one result lane. Inputs are
/// zero-extended lanes; the lane width in bits is the last argument; the
/// result is truncated to the lane by the caller.
#[derive(Clone, Copy)]
enum LaneOp {
    Unary(fn(u64, u32) -> u64),
    Binary(fn(u64, u64, u32) -> u64),
    /// Takes the destination's old lane first.
    Accumulate(fn(u64, u64, u64, u32) -> u64),
}

fn lane_signed(value: u64, bits: u32) -> i64 {
    sign_extend(value, bits as u8) as i64
}

fn lane_all_ones(condition: bool) -> u64 {
    if condition {
        u64::MAX
    } else {
        0
    }
}

fn lane_shr(value: u64, amount: u64) -> u64 {
    value.checked_shr(amount as u32).unwrap_or(0)
}

fn lane_shl(value: u64, amount: u64) -> u64 {
    value.checked_shl(amount as u32).unwrap_or(0)
}

fn lane_op(op: IntrinsicOp) -> Option<LaneOp> {
    use LaneOp::{Accumulate, Binary, Unary};
    Some(match op {
        IntrinsicOp::Mov => Unary(|a, _| a),
        IntrinsicOp::Not | IntrinsicOp::Mvn => Unary(|a, _| !a),
        IntrinsicOp::Neg => Unary(|a, _| a.wrapping_neg()),
        IntrinsicOp::Abs => Unary(|a, bits| lane_signed(a, bits).wrapping_abs() as u64),
        IntrinsicOp::Cnt => Unary(|a, _| u64::from(a.count_ones())),

        IntrinsicOp::And => Binary(|a, b, _| a & b),
        IntrinsicOp::Orr => Binary(|a, b, _| a | b),
        IntrinsicOp::Eor => Binary(|a, b, _| a ^ b),
        IntrinsicOp::Bic => Binary(|a, b, _| a & !b),
        IntrinsicOp::Orn => Binary(|a, b, _| a | !b),
        IntrinsicOp::Add => Binary(|a, b, _| a.wrapping_add(b)),
        IntrinsicOp::Sub => Binary(|a, b, _| a.wrapping_sub(b)),
        IntrinsicOp::Mul => Binary(|a, b, _| a.wrapping_mul(b)),
        IntrinsicOp::Cmeq => Binary(|a, b, _| lane_all_ones(a == b)),
        IntrinsicOp::Cmhi => Binary(|a, b, _| lane_all_ones(a > b)),
        IntrinsicOp::Cmhs => Binary(|a, b, _| lane_all_ones(a >= b)),
        IntrinsicOp::Cmgt => {
            Binary(|a, b, bits| lane_all_ones(lane_signed(a, bits) > lane_signed(b, bits)))
        }
        IntrinsicOp::Cmge => {
            Binary(|a, b, bits| lane_all_ones(lane_signed(a, bits) >= lane_signed(b, bits)))
        }
        IntrinsicOp::Umax => Binary(|a, b, _| a.max(b)),
        IntrinsicOp::Umin => Binary(|a, b, _| a.min(b)),
        IntrinsicOp::Smax => {
            Binary(|a, b, bits| lane_signed(a, bits).max(lane_signed(b, bits)) as u64)
        }
        IntrinsicOp::Smin => {
            Binary(|a, b, bits| lane_signed(a, bits).min(lane_signed(b, bits)) as u64)
        }
        // Vector floating point, on 32- and 64-bit lanes.
        IntrinsicOp::Fadd => Binary(|a, b, bits| vector::float_lane(FloatBinary::Add, a, b, bits)),
        IntrinsicOp::Fsub => Binary(|a, b, bits| vector::float_lane(FloatBinary::Sub, a, b, bits)),
        IntrinsicOp::Fmul => Binary(|a, b, bits| vector::float_lane(FloatBinary::Mul, a, b, bits)),
        IntrinsicOp::Fdiv => Binary(|a, b, bits| vector::float_lane(FloatBinary::Div, a, b, bits)),
        // Immediate shifts: the amount arrives replicated into every lane.
        IntrinsicOp::Shl => Binary(|a, n, _| lane_shl(a, n)),
        IntrinsicOp::Ushr => Binary(|a, n, _| lane_shr(a, n)),
        IntrinsicOp::Sshr => {
            Binary(|a, n, bits| (lane_signed(a, bits) >> n.min(u64::from(bits) - 1)) as u64)
        }

        IntrinsicOp::Mla => Accumulate(|d, a, b, _| d.wrapping_add(a.wrapping_mul(b))),
        IntrinsicOp::Mls => Accumulate(|d, a, b, _| d.wrapping_sub(a.wrapping_mul(b))),
        // Bitwise selects: operands are `[dst, n, m]`.
        IntrinsicOp::Bsl => Accumulate(|d, n, m, _| (d & n) | (!d & m)),
        IntrinsicOp::Bit => Accumulate(|d, n, m, _| (d & !m) | (n & m)),
        IntrinsicOp::Bif => Accumulate(|d, n, m, _| (d & m) | (n & !m)),
        // Shift and accumulate or insert: operands are `[dst, n, amount]`.
        IntrinsicOp::Usra => Accumulate(|d, n, amount, _| d.wrapping_add(lane_shr(n, amount))),
        IntrinsicOp::Sli => Accumulate(|d, n, amount, _| {
            let kept = !lane_shl(u64::MAX, amount);
            (d & kept) | lane_shl(n, amount)
        }),
        IntrinsicOp::Sri => Accumulate(|d, n, amount, bits| {
            let lane = width_mask(bits as u8);
            let inserted = lane_shr(lane, amount);
            (d & !inserted) | lane_shr(n & lane, amount)
        }),
        _ => return None,
    })
}

/// Writes `width` bits of `src` into `dst` at `lsb`. The result is as wide
/// as `dst`, so a lane can be inserted into a 128-bit register.
fn insert_value_bits(dst: Value, src: Value, lsb: u8, width: u8) -> Value {
    let wide = matches!(dst, Value::U128(_));
    let as_u128 = |value: &Value| match value {
        Value::U64(bits) => Some(u128::from(*bits)),
        Value::U128(bits) => Some(*bits),
        Value::F64(float) => Some(u128::from(float.to_bits())),
        Value::Unknown => None,
    };
    let (Some(dst_bits), Some(src_bits)) = (as_u128(&dst), as_u128(&src)) else {
        return Value::Unknown;
    };
    if u32::from(lsb) >= 128 {
        return dst;
    }
    let mask = width_mask_u128(width) << u32::from(lsb);
    let inserted = (dst_bits & !mask) | ((src_bits << u32::from(lsb)) & mask);
    if wide {
        Value::U128(inserted)
    } else {
        Value::U64(inserted as u64)
    }
}

fn extract_value_bits(value: Value, lsb: u8, width: u8) -> Value {
    match value {
        Value::U64(bits) => {
            if lsb >= 64 {
                Value::U64(0)
            } else {
                Value::U64(apply_mask(bits >> lsb as u32, width))
            }
        }
        Value::U128(bits) => {
            if lsb >= 128 {
                return if width > 64 {
                    Value::U128(0)
                } else {
                    Value::U64(0)
                };
            }
            let shifted = bits >> lsb as u32;
            if width <= 64 {
                Value::U64((shifted as u64) & width_mask(width))
            } else {
                Value::U128(shifted & width_mask_u128(width))
            }
        }
        Value::F64(bits) => {
            if lsb >= 64 {
                Value::U64(0)
            } else {
                Value::U64(apply_mask(bits.to_bits() >> lsb as u32, width))
            }
        }
        Value::Unknown => Value::Unknown,
    }
}

fn low_u64_value(value: Value) -> Value {
    match value {
        Value::U64(bits) => Value::U64(bits),
        Value::U128(bits) => Value::U64(bits as u64),
        Value::F64(bits) => Value::U64(bits.to_bits()),
        Value::Unknown => Value::Unknown,
    }
}

fn arranged_immediate_vector(imm: u64, arrangement: VectorArrangement, invert: bool) -> u128 {
    let lane_bytes = usize::from(arrangement.lane_bits / 8);
    let active_bytes = usize::from(arrangement.active_bytes());
    let lane_mask = match arrangement.lane_bits {
        0 => 0,
        1..=63 => (1u64 << arrangement.lane_bits) - 1,
        _ => u64::MAX,
    };
    let lane_value = if invert {
        (!imm) & lane_mask
    } else {
        imm & lane_mask
    };
    let lane_bits = lane_value.to_le_bytes();
    let mut bytes = [0u8; 16];
    for lane in 0..usize::from(arrangement.lanes) {
        let start = lane * lane_bytes;
        bytes[start..start + lane_bytes].copy_from_slice(&lane_bits[..lane_bytes]);
    }
    if active_bytes < 16 {
        bytes[active_bytes..].fill(0);
    }
    u128::from_le_bytes(bytes)
}

fn vector_operand_bytes(
    expr: &Expr,
    value: Value,
    arrangement: VectorArrangement,
) -> Option<[u8; 16]> {
    match value {
        Value::U128(bits) => Some(bits.to_le_bytes()),
        Value::U64(bits) => {
            let mut bytes = [0u8; 16];
            // An immediate or a single lane (`v2.s[1]`) applies to every lane.
            if matches!(expr, Expr::Imm(_) | Expr::Extract { .. }) {
                let lane_bytes = usize::from(arrangement.lane_bits / 8);
                let bits = bits.to_le_bytes();
                for lane in 0..usize::from(arrangement.lanes) {
                    let start = lane * lane_bytes;
                    bytes[start..start + lane_bytes].copy_from_slice(&bits[..lane_bytes]);
                }
            } else {
                let low = arrangement.active_bytes().min(8) as usize;
                bytes[..low].copy_from_slice(&bits.to_le_bytes()[..low]);
            }
            Some(bytes)
        }
        Value::F64(value) => {
            let mut bytes = [0u8; 16];
            let low = arrangement.active_bytes().min(8) as usize;
            bytes[..low].copy_from_slice(&value.to_bits().to_le_bytes()[..low]);
            Some(bytes)
        }
        Value::Unknown => None,
    }
}

fn vector_dup(value: Value, arrangement: VectorArrangement) -> Option<u128> {
    let lane_bytes = usize::from(arrangement.lane_bits / 8);
    let lane = low_bytes_from_value(&value, lane_bytes)?;
    let mut result = [0u8; 16];
    for lane_index in 0..usize::from(arrangement.lanes) {
        let start = lane_index * lane_bytes;
        result[start..start + lane_bytes].copy_from_slice(&lane);
    }
    Some(u128::from_le_bytes(result))
}

fn write_arranged_vector_register(
    registers: &mut BTreeMap<Reg, Value>,
    dst: &Reg,
    arrangement: VectorArrangement,
    value: Value,
) {
    let Some(index) = simd_index(dst) else {
        return;
    };

    // An arrangement narrower than the register clears the bytes above it.
    let vector = match vector_bytes_from_value(&value) {
        Some(mut bytes) => {
            bytes[usize::from(arrangement.active_bytes())..].fill(0);
            Value::U128(u128::from_le_bytes(bytes))
        }
        None => Value::Unknown,
    };
    clear_all_simd_aliases(registers, index);
    registers.insert(Reg::V(index), vector);
}

fn decode_loaded_value(bytes: &[u8]) -> Value {
    match bytes.len() {
        0 => Value::Unknown,
        1..=8 => {
            let mut buf = [0u8; 8];
            buf[..bytes.len()].copy_from_slice(bytes);
            Value::U64(u64::from_le_bytes(buf))
        }
        16 => {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(bytes);
            Value::U128(u128::from_le_bytes(buf))
        }
        _ => Value::Unknown,
    }
}

enum ComposedLoad {
    /// Every byte is known. `overlay` says whether any came from a store.
    Bytes { bytes: Vec<u8>, overlay: bool },
    /// A byte was stored with an unknown value.
    UnknownByte,
    /// A byte is in neither the overlay nor the backing store.
    Missing,
}

fn compose_load(
    memory: &BTreeMap<MemoryCellId, Value>,
    cell_id: &MemoryCellId,
    backing: Option<&[u8]>,
) -> ComposedLoad {
    let mut bytes = Vec::with_capacity(cell_id.size as usize);
    let mut overlay = false;
    for index in 0..cell_id.size {
        let stored = byte_location(&cell_id.location, index)
            .and_then(|location| memory.get(&MemoryCellId { location, size: 1 }));
        match (stored, backing.and_then(|bytes| bytes.get(index as usize))) {
            (Some(value), _) => match value.as_u64() {
                Some(byte) => {
                    bytes.push(byte as u8);
                    overlay = true;
                }
                None => return ComposedLoad::UnknownByte,
            },
            (None, Some(byte)) => bytes.push(*byte),
            (None, None) => return ComposedLoad::Missing,
        }
    }
    ComposedLoad::Bytes { bytes, overlay }
}

fn write_memory_overlay(
    memory: &mut BTreeMap<MemoryCellId, Value>,
    cell_id: &MemoryCellId,
    value: &Value,
) {
    clear_overlapping_memory_cells(memory, cell_id);
    memory.insert(cell_id.clone(), value.clone());

    for (index, byte_value) in stored_byte_values(value, cell_id.size)
        .into_iter()
        .enumerate()
    {
        let Some(location) = byte_location(&cell_id.location, index as u8) else {
            continue;
        };
        memory.insert(MemoryCellId { location, size: 1 }, byte_value);
    }
}

fn clear_overlapping_memory_cells(
    memory: &mut BTreeMap<MemoryCellId, Value>,
    cell_id: &MemoryCellId,
) {
    memory.retain(|existing, _| !memory_cells_overlap(existing, cell_id));
}

fn memory_cells_overlap(lhs: &MemoryCellId, rhs: &MemoryCellId) -> bool {
    match (&lhs.location, &rhs.location) {
        (MemoryLocation::Absolute(lhs_addr), MemoryLocation::Absolute(rhs_addr)) => {
            byte_ranges_overlap_u64(*lhs_addr, lhs.size, *rhs_addr, rhs.size)
        }
        (MemoryLocation::StackSlot(lhs_offset), MemoryLocation::StackSlot(rhs_offset)) => {
            byte_ranges_overlap_i64(*lhs_offset, lhs.size, *rhs_offset, rhs.size)
        }
        _ => false,
    }
}

fn byte_ranges_overlap_u64(lhs_start: u64, lhs_size: u8, rhs_start: u64, rhs_size: u8) -> bool {
    let lhs_end = lhs_start as u128 + lhs_size as u128;
    let rhs_end = rhs_start as u128 + rhs_size as u128;
    (lhs_start as u128) < rhs_end && (rhs_start as u128) < lhs_end
}

fn byte_ranges_overlap_i64(lhs_start: i64, lhs_size: u8, rhs_start: i64, rhs_size: u8) -> bool {
    let lhs_end = lhs_start as i128 + lhs_size as i128;
    let rhs_end = rhs_start as i128 + rhs_size as i128;
    (lhs_start as i128) < rhs_end && (rhs_start as i128) < lhs_end
}

fn stored_byte_values(value: &Value, size: u8) -> Vec<Value> {
    let size = size as usize;
    let concrete = vector_bytes_from_value(value).map(|bytes| bytes[..size].to_vec());
    (0..size)
        .map(|index| match concrete.as_ref() {
            Some(bytes) => Value::U64(bytes[index] as u64),
            None => Value::Unknown,
        })
        .collect()
}

fn byte_location(location: &MemoryLocation, index: u8) -> Option<MemoryLocation> {
    match location {
        MemoryLocation::Absolute(addr) => {
            Some(MemoryLocation::Absolute(addr.wrapping_add(index as u64)))
        }
        MemoryLocation::StackSlot(offset) => {
            Some(MemoryLocation::StackSlot(offset.wrapping_add(index as i64)))
        }
        MemoryLocation::Unknown => None,
    }
}

#[derive(Clone, Copy)]
enum FloatBinary {
    Add,
    Sub,
    Mul,
    Div,
    Max,
    Min,
}

#[derive(Clone, Copy)]
enum FloatUnary {
    Neg,
    Abs,
    Sqrt,
}

#[derive(Clone, Copy)]
enum FloatRounding {
    Zero,
    Down,
    Up,
    NearestEven,
    NearestAway,
}

/// Rounding mode and signedness of a scalar float-to-integer intrinsic.
fn round_float(value: f64, rounding: FloatRounding) -> f64 {
    match rounding {
        FloatRounding::Zero => value.trunc(),
        FloatRounding::Down => value.floor(),
        FloatRounding::Up => value.ceil(),
        FloatRounding::NearestEven => value.round_ties_even(),
        FloatRounding::NearestAway => value.round(),
    }
}

fn float_to_int_mode(op: IntrinsicOp) -> Option<(FloatRounding, bool)> {
    Some(match op {
        IntrinsicOp::Fcvtzs => (FloatRounding::Zero, true),
        IntrinsicOp::Fcvtzu => (FloatRounding::Zero, false),
        IntrinsicOp::Fcvtms => (FloatRounding::Down, true),
        IntrinsicOp::Fcvtmu => (FloatRounding::Down, false),
        IntrinsicOp::Fcvtps => (FloatRounding::Up, true),
        IntrinsicOp::Fcvtpu => (FloatRounding::Up, false),
        IntrinsicOp::Fcvtns => (FloatRounding::NearestEven, true),
        IntrinsicOp::Fcvtnu => (FloatRounding::NearestEven, false),
        IntrinsicOp::Fcvtas => (FloatRounding::NearestAway, true),
        IntrinsicOp::Fcvtau => (FloatRounding::NearestAway, false),
        _ => return None,
    })
}

/// Width in bits of the float format an expression is in, when a register
/// in it says so.
fn float_bits(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Reg(Reg::S(_)) => Some(32),
        Expr::Reg(Reg::D(_)) => Some(64),
        Expr::FAdd(lhs, rhs)
        | Expr::FSub(lhs, rhs)
        | Expr::FMul(lhs, rhs)
        | Expr::FDiv(lhs, rhs)
        | Expr::FMax(lhs, rhs)
        | Expr::FMin(lhs, rhs) => float_bits(lhs).or_else(|| float_bits(rhs)),
        Expr::FNeg(inner) | Expr::FAbs(inner) | Expr::FSqrt(inner) => float_bits(inner),
        _ => None,
    }
}

fn encode_float(value: f64, bits: u8) -> Value {
    if bits == 32 {
        encode_f32(value as f32)
    } else {
        Value::U64(value.to_bits())
    }
}

fn encode_f32(value: f32) -> Value {
    Value::U64(u64::from(value.to_bits()))
}

/// AArch64 produces the default NaN (sign clear, no payload) when an
/// operation on non-NaN inputs is invalid; the host may set the sign.
fn default_nan_if_generated(result: f64, input_was_nan: bool) -> f64 {
    if result.is_nan() && !input_was_nan {
        f64::from_bits(0x7ff8_0000_0000_0000)
    } else {
        result
    }
}

/// The NaN an AArch64 operation returns when an operand is one: the first
/// signalling NaN, else the first quiet NaN, in either case quieted.
fn propagated_nan(lhs: f64, rhs: f64) -> Option<f64> {
    const QUIET: u64 = 0x0008_0000_0000_0000;
    let is_signalling = |value: f64| value.is_nan() && value.to_bits() & QUIET == 0;
    let chosen = if is_signalling(lhs) {
        lhs
    } else if is_signalling(rhs) {
        rhs
    } else if lhs.is_nan() {
        lhs
    } else if rhs.is_nan() {
        rhs
    } else {
        return None;
    };
    Some(f64::from_bits(chosen.to_bits() | QUIET))
}

/// Reverses the bytes inside each `group`-byte unit of a `width`-bit value.
fn reverse_bytes_in_groups(value: u64, width: u8, group: usize) -> u64 {
    let mut bytes = value.to_le_bytes();
    let used = usize::from(width / 8).min(8);
    for chunk in bytes[..used].chunks_mut(group) {
        chunk.reverse();
    }
    bytes[used..].fill(0);
    u64::from_le_bytes(bytes)
}

fn condition_from_code(code: u64) -> Option<Condition> {
    Some(match code {
        0 => Condition::EQ,
        1 => Condition::NE,
        2 => Condition::CS,
        3 => Condition::CC,
        4 => Condition::MI,
        5 => Condition::PL,
        6 => Condition::VS,
        7 => Condition::VC,
        8 => Condition::HI,
        9 => Condition::LS,
        10 => Condition::GE,
        11 => Condition::LT,
        12 => Condition::GT,
        13 => Condition::LE,
        14 => Condition::AL,
        15 => Condition::NV,
        _ => return None,
    })
}

/// MOVK: replace one 16-bit field of `dst`. `src` is the immediate already
/// shifted into place. Without an explicit `shift` the field is taken to be
/// the one holding the immediate's lowest set bit, which cannot tell a zero
/// immediate's position.
fn eval_movk_bits(dst: Option<u64>, src: Option<u64>, shift: Option<u32>) -> Value {
    let (Some(dst), Some(src)) = (dst, src) else {
        return Value::Unknown;
    };

    let shift = shift.unwrap_or(if src == 0 {
        0
    } else {
        (src.trailing_zeros() / 16) * 16
    });
    if shift >= 64 {
        return Value::Unknown;
    }

    let imm16 = (src >> shift) & 0xffff;
    let mask = 0xffffu64 << shift;
    Value::U64((dst & !mask) | ((imm16 << shift) & mask))
}

fn eval_mul_high(lhs: Option<Value>, rhs: Option<Value>, signed: bool) -> Value {
    let (Some(lhs), Some(rhs)) = (
        lhs.and_then(|value| value.as_u64()),
        rhs.and_then(|value| value.as_u64()),
    ) else {
        return Value::Unknown;
    };

    if signed {
        let product = (lhs as i64 as i128) * (rhs as i64 as i128);
        Value::U64((product >> 64) as u64)
    } else {
        let product = (lhs as u128) * (rhs as u128);
        Value::U64((product >> 64) as u64)
    }
}

fn truncate_to_w(value: Value) -> Value {
    match value {
        Value::U64(bits) => Value::U64(bits as u32 as u64),
        _ => Value::Unknown,
    }
}

fn zero_extend_w(value: Value) -> Value {
    match value {
        Value::U64(bits) => Value::U64(bits as u32 as u64),
        _ => Value::Unknown,
    }
}

fn mask_value(value: Value, size: u8) -> Value {
    match value {
        Value::U64(bits) if size > 0 && size < 8 => Value::U64(apply_mask(bits, size * 8)),
        other => other,
    }
}

fn apply_mask(value: u64, bits: u8) -> u64 {
    value & width_mask(bits)
}

fn width_mask(bits: u8) -> u64 {
    match bits {
        0 => 0,
        1..=63 => ((1u128 << bits) - 1) as u64,
        _ => u64::MAX,
    }
}

fn width_mask_u128(bits: u8) -> u128 {
    match bits {
        0 => 0,
        1..=127 => (1u128 << bits) - 1,
        _ => u128::MAX,
    }
}

fn sign_bit(bits: u8) -> u64 {
    match bits {
        0 => 0,
        1..=63 => 1u64 << (bits - 1),
        _ => 1u64 << 63,
    }
}

fn sign_extend(value: u64, from_bits: u8) -> u64 {
    if from_bits == 0 || from_bits >= 64 {
        return value;
    }
    let shift = 64 - from_bits as u32;
    ((value << shift) as i64 >> shift) as u64
}

fn leading_zeros_for_width(value: u64, width: u8) -> u64 {
    let bits = normalize_to_width(value, width);
    match width {
        0 => 0,
        1..=63 => (bits.leading_zeros() - (64 - u32::from(width))) as u64,
        _ => bits.leading_zeros() as u64,
    }
}

fn leading_sign_bits_for_width(value: u64, width: u8) -> u64 {
    if width == 0 {
        return 0;
    }
    let bits = normalize_to_width(value, width);
    let sign = ((bits >> (width.saturating_sub(1))) & 1) != 0;
    let adjusted = if sign { !bits } else { bits };
    leading_zeros_for_width(adjusted, width).saturating_sub(1)
}

fn reverse_bytes_for_width(value: u64, width: u8) -> u64 {
    let byte_width = match width {
        0..=8 => 1,
        9..=16 => 2,
        17..=32 => 4,
        _ => 8,
    };
    let mut bytes = value.to_le_bytes();
    bytes[..byte_width].reverse();
    let mut normalized = [0u8; 8];
    normalized[..byte_width].copy_from_slice(&bytes[..byte_width]);
    normalize_to_width(u64::from_le_bytes(normalized), width)
}

fn reverse_bits_for_width(value: u64, width: u8) -> u64 {
    if width == 0 {
        return 0;
    }
    let bits = normalize_to_width(value, width);
    bits.reverse_bits() >> (64 - u32::from(width))
}

fn normalize_to_width(value: u64, width: u8) -> u64 {
    match width {
        0 => 0,
        1..=63 => value & ((1u64 << width) - 1),
        _ => value,
    }
}

fn crc32_intrinsic_info(op: IntrinsicOp) -> Option<(u32, usize)> {
    match op {
        IntrinsicOp::Crc32b => Some((0xedb8_8320, 1)),
        IntrinsicOp::Crc32h => Some((0xedb8_8320, 2)),
        IntrinsicOp::Crc32w => Some((0xedb8_8320, 4)),
        IntrinsicOp::Crc32x => Some((0xedb8_8320, 8)),
        IntrinsicOp::Crc32cb => Some((0x82f6_3b78, 1)),
        IntrinsicOp::Crc32ch => Some((0x82f6_3b78, 2)),
        IntrinsicOp::Crc32cw => Some((0x82f6_3b78, 4)),
        IntrinsicOp::Crc32cx => Some((0x82f6_3b78, 8)),
        _ => None,
    }
}

fn crc32_update(mut crc: u32, value: u64, width: usize, poly: u32) -> u32 {
    let bytes = value.to_le_bytes();
    for byte in bytes.iter().take(width) {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ poly
            } else {
                crc >> 1
            };
        }
    }
    crc
}

fn panic_on_noop_stmt(stmt: &Stmt) -> ! {
    panic!(
        "aeon emulation encountered IL no-op and refuses to continue: {:?}",
        stmt
    );
}

fn panic_on_unsupported_stmt(stmt: &Stmt) -> ! {
    panic!(
        "aeon emulation encountered unsupported IL statement and refuses to continue: {:?}",
        stmt
    );
}

fn panic_on_unsupported_expr(expr: &Expr) -> ! {
    panic!(
        "aeon emulation encountered unsupported IL expression and refuses to continue: {:?}",
        expr
    );
}

fn is_supported_barrier(kind: &str) -> bool {
    matches!(kind, "dmb" | "dsb" | "isb")
}

fn is_supported_stmt_intrinsic(op: IntrinsicOp) -> bool {
    matches!(
        op,
        IntrinsicOp::Nop
            | IntrinsicOp::Yield
            | IntrinsicOp::Hint
            | IntrinsicOp::Paciasp
            | IntrinsicOp::Autiasp
            | IntrinsicOp::Bti
            | IntrinsicOp::Xpaclri
            | IntrinsicOp::Prfm
            | IntrinsicOp::Prfum
            | IntrinsicOp::Clrex
    )
}

fn offset_location(location: MemoryLocation, delta: i64, subtract: bool) -> MemoryLocation {
    match location {
        MemoryLocation::Unknown => MemoryLocation::Unknown,
        MemoryLocation::Absolute(addr) => {
            let offset = if subtract {
                addr.wrapping_sub(delta as u64)
            } else {
                addr.wrapping_add(delta as u64)
            };
            MemoryLocation::Absolute(offset)
        }
        MemoryLocation::StackSlot(offset) => {
            let next = if subtract {
                offset.wrapping_sub(delta)
            } else {
                offset.wrapping_add(delta)
            };
            MemoryLocation::StackSlot(next)
        }
    }
}

fn is_32_bit_operand(expr: &Expr) -> bool {
    expr.is_32_bit_operand()
}

fn operand_is_32_bit(lhs: &Expr, rhs: &Expr) -> bool {
    Expr::binary_is_32_bit(lhs, rhs)
}

fn expr_bit_width(expr: &Expr) -> Option<u8> {
    expr.int_bits()
}

fn eval_condition(flags: Option<Nzcv>, cond: Condition) -> Option<bool> {
    let flags = flags?;
    Some(match cond {
        Condition::EQ => flags.z,
        Condition::NE => !flags.z,
        Condition::CS => flags.c,
        Condition::CC => !flags.c,
        Condition::MI => flags.n,
        Condition::PL => !flags.n,
        Condition::VS => flags.v,
        Condition::VC => !flags.v,
        Condition::HI => flags.c && !flags.z,
        Condition::LS => !flags.c || flags.z,
        Condition::GE => flags.n == flags.v,
        Condition::LT => flags.n != flags.v,
        Condition::GT => !flags.z && (flags.n == flags.v),
        Condition::LE => flags.z || (flags.n != flags.v),
        Condition::AL => true,
        Condition::NV => false,
    })
}

fn eval_compare(cond: Condition, lhs: u64, rhs: u64) -> Option<bool> {
    Some(match cond {
        Condition::EQ => lhs == rhs,
        Condition::NE => lhs != rhs,
        Condition::CS => lhs >= rhs,
        Condition::CC => lhs < rhs,
        Condition::HI => lhs > rhs,
        Condition::LS => lhs <= rhs,
        Condition::GE => (lhs as i64) >= (rhs as i64),
        Condition::LT => (lhs as i64) < (rhs as i64),
        Condition::GT => (lhs as i64) > (rhs as i64),
        Condition::LE => (lhs as i64) <= (rhs as i64),
        Condition::AL => true,
        Condition::NV => false,
        Condition::MI | Condition::PL | Condition::VS | Condition::VC => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, e_compare, e_cond_select, e_load, e_sub};
    use std::collections::BTreeMap;

    struct TestBackingStore {
        cells: BTreeMap<(u64, u8), Vec<u8>>,
    }

    impl BackingStore for TestBackingStore {
        fn load(&self, addr: u64, size: u8) -> Option<Vec<u8>> {
            self.cells.get(&(addr, size)).cloned()
        }
    }

    #[test]
    fn executes_assigns_and_updates_register_aliases() {
        let result = execute_snippet(
            &[
                Stmt::Assign {
                    dst: Reg::W(0),
                    src: e_add(Expr::Reg(Reg::W(1)), Expr::Imm(3)),
                },
                Stmt::Assign {
                    dst: Reg::X(2),
                    src: Expr::Or(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(0x100))),
                },
            ],
            BTreeMap::from([(Reg::X(1), Value::U64(5))]),
            8,
        );

        assert_eq!(result.final_registers.get(&Reg::W(0)), Some(&Value::U64(8)));
        assert_eq!(result.final_registers.get(&Reg::X(0)), Some(&Value::U64(8)));
        assert_eq!(
            result.final_registers.get(&Reg::X(2)),
            Some(&Value::U64(0x108))
        );
        assert!(!result.budget_exhausted);
    }

    #[test]
    fn executes_store_then_load_through_absolute_memory() {
        let result = execute_snippet(
            &[
                Stmt::Store {
                    addr: Expr::Reg(Reg::X(0)),
                    value: Expr::Reg(Reg::X(1)),
                    size: 2,
                },
                Stmt::Assign {
                    dst: Reg::X(2),
                    src: e_load(Expr::Reg(Reg::X(0)), 2),
                },
            ],
            BTreeMap::from([
                (Reg::X(0), Value::U64(0x2000)),
                (Reg::X(1), Value::U64(0x1122_3344)),
            ]),
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(2)),
            Some(&Value::U64(0x3344))
        );
        assert_eq!(
            result.touched_memory,
            vec![MemoryCell {
                id: MemoryCellId {
                    location: MemoryLocation::Absolute(0x2000),
                    size: 2,
                },
                value: Value::U64(0x3344),
            }]
        );
    }

    #[test]
    fn execute_snippet_resolves_w_register_addresses_from_x_aliases() {
        let full_addr = 0x1_0000_2000u64;
        let result = execute_snippet(
            &[
                Stmt::Store {
                    addr: Expr::Reg(Reg::W(0)),
                    value: Expr::Reg(Reg::X(1)),
                    size: 4,
                },
                Stmt::Assign {
                    dst: Reg::X(2),
                    src: e_load(Expr::Reg(Reg::X(0)), 4),
                },
            ],
            BTreeMap::from([
                (Reg::X(0), Value::U64(full_addr)),
                (Reg::X(1), Value::U64(0x1234_5678)),
            ]),
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(2)),
            Some(&Value::U64(0x1234_5678))
        );
    }

    #[test]
    fn executes_stack_slot_memory_and_stops_at_budget() {
        let result = execute_snippet(
            &[
                Stmt::Store {
                    addr: Expr::StackSlot {
                        offset: -16,
                        size: 8,
                    },
                    value: Expr::Imm(0xdead_beef),
                    size: 8,
                },
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: e_load(
                        Expr::StackSlot {
                            offset: -16,
                            size: 8,
                        },
                        8,
                    ),
                },
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: Expr::Imm(1),
                },
            ],
            BTreeMap::new(),
            2,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(0)),
            Some(&Value::U64(0xdead_beef))
        );
        assert_eq!(result.final_registers.get(&Reg::X(1)), None);
        assert!(result.budget_exhausted);
        assert_eq!(result.steps_executed, 2);
        assert_eq!(
            result.touched_memory,
            vec![MemoryCell {
                id: MemoryCellId {
                    location: MemoryLocation::StackSlot(-16),
                    size: 8,
                },
                value: Value::U64(0xdead_beef),
            }]
        );
    }

    #[test]
    fn executes_conditional_flag_updates_and_condselects() {
        let result = execute_snippet(
            &[
                Stmt::SetFlags {
                    expr: e_sub(Expr::Imm(5), Expr::Imm(4)),
                },
                Stmt::SetFlags {
                    expr: e_cond_select(
                        Condition::EQ,
                        e_sub(Expr::Imm(7), Expr::Imm(7)),
                        Expr::Imm(0),
                    ),
                },
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: e_cond_select(Condition::EQ, Expr::Imm(1), Expr::Imm(2)),
                },
            ],
            BTreeMap::new(),
            8,
        );

        assert_eq!(result.final_registers.get(&Reg::X(0)), Some(&Value::U64(2)));
        assert_eq!(
            result.final_registers.get(&Reg::Flags),
            Some(&Value::U64(0))
        );
    }

    #[test]
    fn branches_are_noops_for_straight_line_execution() {
        let result = execute_snippet(
            &[
                Stmt::Branch {
                    target: Expr::Imm(0x4000),
                },
                Stmt::CondBranch {
                    cond: aeonil::BranchCond::Zero(Expr::Imm(0)),
                    target: Expr::Imm(0x5000),
                    fallthrough: 0x5004,
                },
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: e_compare(Condition::LT, Expr::Imm(1), Expr::Imm(2)),
                },
            ],
            BTreeMap::new(),
            8,
        );

        assert_eq!(result.final_registers.get(&Reg::X(0)), Some(&Value::U64(1)));
        assert!(!result.budget_exhausted);
    }

    #[test]
    fn execute_snippet_evaluates_movk_intrinsic() {
        let result = execute_snippet(
            &[Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Intrinsic {
                    name: "movk".into(),
                    operands: vec![Expr::Imm(0x1122_3344_0000_7788), Expr::Imm(0x55aa_0000)],
                },
            }],
            BTreeMap::new(),
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(0)),
            Some(&Value::U64(0x1122_3344_55aa_7788))
        );
    }

    #[test]
    fn execute_block_reads_from_backing_store_and_resolves_next_pc() {
        let backing = TestBackingStore {
            cells: BTreeMap::from([((0x2000, 4), vec![0x78, 0x56, 0x34, 0x12])]),
        };

        let result = execute_block(
            &[
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: e_load(Expr::Imm(0x2000), 4),
                },
                Stmt::Branch {
                    target: e_add(Expr::Imm(0x4000), Expr::Imm(4)),
                },
            ],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(1)),
            Some(&Value::U64(0x1234_5678))
        );
        assert_eq!(result.next_pc, Some(0x4004));
        assert_eq!(result.stop, BlockStop::Completed);
        assert_eq!(result.reads.len(), 1);
        assert_eq!(
            result.reads[0].source,
            Some(MemoryValueSource::BackingStore)
        );
    }

    #[test]
    fn execute_snippet_reads_narrower_loads_from_wider_overlay_store() {
        let result = execute_snippet(
            &[
                Stmt::Store {
                    addr: Expr::Imm(0x2000),
                    value: Expr::Imm(0x1122_3344_5566_7788),
                    size: 8,
                },
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: e_load(Expr::Imm(0x2000), 4),
                },
            ],
            BTreeMap::new(),
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(0)),
            Some(&Value::U64(0x5566_7788))
        );
    }

    #[test]
    fn execute_block_prefers_wider_overlay_store_over_stale_backing_bytes() {
        let backing = TestBackingStore {
            cells: BTreeMap::from([((0x2000, 8), vec![1, 0, 0, 0, 1, 0, 0, 0])]),
        };

        let result = execute_block(
            &[
                Stmt::Store {
                    addr: Expr::Imm(0x2000),
                    value: Expr::Imm(0),
                    size: 16,
                },
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: e_load(Expr::Imm(0x2000), 8),
                },
            ],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );

        assert_eq!(result.final_registers.get(&Reg::X(0)), Some(&Value::U64(0)));
        assert_eq!(result.stop, BlockStop::Completed);
        assert_eq!(result.reads[0].source, Some(MemoryValueSource::Overlay));
    }

    #[test]
    fn execute_block_resolves_w_register_addresses_from_x_aliases() {
        let full_addr = 0x1_0000_3000u64;
        let backing = TestBackingStore {
            cells: BTreeMap::from([((full_addr, 4), vec![0x78, 0x56, 0x34, 0x12])]),
        };

        let result = execute_block(
            &[Stmt::Assign {
                dst: Reg::X(1),
                src: e_load(Expr::Reg(Reg::W(0)), 4),
            }],
            BTreeMap::from([(Reg::X(0), Value::U64(full_addr))]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(1)),
            Some(&Value::U64(0x1234_5678))
        );
        assert_eq!(result.stop, BlockStop::Completed);
    }

    #[test]
    fn execute_block_evaluates_movk_intrinsic() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Intrinsic {
                    name: "movk".into(),
                    operands: vec![Expr::Imm(0x8899_aabb_0000_ccdd), Expr::Imm(0x1234_0000)],
                },
            }],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(0)),
            Some(&Value::U64(0x8899_aabb_1234_ccdd))
        );
        assert_eq!(result.stop, BlockStop::Completed);
    }

    #[test]
    fn execute_block_evaluates_mul_high_intrinsics() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Intrinsic {
                        name: "umulh".into(),
                        operands: vec![Expr::Imm(u64::MAX), Expr::Imm(2)],
                    },
                },
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: Expr::Intrinsic {
                        name: "smulh".into(),
                        operands: vec![Expr::Imm(u64::MAX), Expr::Imm(2)],
                    },
                },
            ],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );

        assert_eq!(result.final_registers.get(&Reg::X(0)), Some(&Value::U64(1)));
        assert_eq!(
            result.final_registers.get(&Reg::X(1)),
            Some(&Value::U64(u64::MAX))
        );
        assert_eq!(result.stop, BlockStop::Completed);
    }

    #[test]
    fn execute_block_stops_when_memory_is_missing_from_backing_store() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[Stmt::Assign {
                dst: Reg::X(0),
                src: e_load(Expr::Imm(0x5000), 8),
            }],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );

        assert_eq!(
            result.stop,
            BlockStop::MissingMemory {
                location: MemoryLocation::Absolute(0x5000),
                size: 8,
            }
        );
        assert!(result.next_pc.is_none());
        assert_eq!(result.final_registers.get(&Reg::X(0)), None);
    }

    #[test]
    fn execute_block_continues_with_unknown_when_missing_memory_is_symbolic() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: e_load(Expr::Imm(0x5000), 8),
                },
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: e_add(Expr::Reg(Reg::X(0)), Expr::Imm(4)),
                },
                Stmt::Branch {
                    target: Expr::Imm(0x6000),
                },
            ],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::ContinueAsUnknown,
            8,
        );

        assert_eq!(result.stop, BlockStop::Completed);
        assert_eq!(result.next_pc, Some(0x6000));
        assert_eq!(
            result.final_registers.get(&Reg::X(0)),
            Some(&Value::Unknown)
        );
        assert_eq!(
            result.final_registers.get(&Reg::X(1)),
            Some(&Value::Unknown)
        );
        assert_eq!(result.reads.len(), 1);
        assert_eq!(result.reads[0].source, None);
    }

    #[test]
    fn execute_block_continues_with_unknown_when_address_cannot_be_resolved() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: e_load(Expr::Reg(Reg::X(0)), 8),
                },
                Stmt::Branch {
                    target: Expr::Imm(0x6000),
                },
            ],
            BTreeMap::from([(Reg::X(0), Value::Unknown)]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::ContinueAsUnknown,
            8,
        );

        assert_eq!(result.stop, BlockStop::Completed);
        assert_eq!(result.next_pc, Some(0x6000));
        assert_eq!(
            result.final_registers.get(&Reg::X(1)),
            Some(&Value::Unknown)
        );
        assert_eq!(result.reads.len(), 1);
        assert_eq!(result.reads[0].id.location, MemoryLocation::Unknown);
        assert_eq!(result.reads[0].source, None);
    }

    #[test]
    fn execute_block_propagates_simd_aliases_and_arranged_intrinsics() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[
                Stmt::Intrinsic {
                    name: "movi.2d".into(),
                    operands: vec![Expr::Reg(Reg::V(0)), Expr::Imm(u64::MAX)],
                },
                Stmt::Intrinsic {
                    name: "movi.2d".into(),
                    operands: vec![Expr::Reg(Reg::V(1)), Expr::Imm(u64::MAX)],
                },
                Stmt::Intrinsic {
                    name: "movi.2d".into(),
                    operands: vec![Expr::Reg(Reg::V(2)), Expr::Imm(u64::MAX)],
                },
                Stmt::Assign {
                    dst: Reg::D(0),
                    src: Expr::Imm(0x4433_2211_ffff_ffff),
                },
                Stmt::Intrinsic {
                    name: "cmeq.2s".into(),
                    operands: vec![
                        Expr::Reg(Reg::V(1)),
                        Expr::Reg(Reg::V(0)),
                        Expr::Reg(Reg::V(1)),
                    ],
                },
                Stmt::Intrinsic {
                    name: "bif.8b".into(),
                    operands: vec![
                        Expr::Reg(Reg::V(2)),
                        Expr::Reg(Reg::V(0)),
                        Expr::Reg(Reg::V(1)),
                    ],
                },
            ],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            16,
        );

        // Scalar and 64-bit-arrangement writes clear the upper half.
        let mut expected_v0 = [0u8; 16];
        expected_v0[..8].copy_from_slice(&0x4433_2211_ffff_ffffu64.to_le_bytes());
        assert_eq!(
            result.final_registers.get(&Reg::V(0)),
            Some(&Value::U128(u128::from_le_bytes(expected_v0)))
        );

        let mut expected_v1 = [0u8; 16];
        expected_v1[..4].fill(0xff);
        assert_eq!(
            result.final_registers.get(&Reg::V(1)),
            Some(&Value::U128(u128::from_le_bytes(expected_v1)))
        );

        let mut expected_v2 = [0u8; 16];
        expected_v2[..8].copy_from_slice(&0x4433_2211_ffff_ffffu64.to_le_bytes());
        assert_eq!(
            result.final_registers.get(&Reg::V(2)),
            Some(&Value::U128(u128::from_le_bytes(expected_v2)))
        );
        assert_eq!(
            read_register_value(&result.final_registers, &Reg::D(0)),
            Value::U64(0x4433_2211_ffff_ffff)
        );
    }

    #[test]
    fn execute_block_scalar_simd_write_replaces_the_vector_register() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[
                Stmt::Intrinsic {
                    name: "movi.2d".into(),
                    operands: vec![Expr::Reg(Reg::V(0)), Expr::Imm(u64::MAX)],
                },
                Stmt::Assign {
                    dst: Reg::H(0),
                    src: Expr::Imm(0x2211),
                },
                Stmt::Assign {
                    dst: Reg::VByte(0),
                    src: Expr::Imm(0x7f),
                },
            ],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );

        // Each scalar write replaces the whole register, as on AArch64.
        assert_eq!(
            result.final_registers.get(&Reg::V(0)),
            Some(&Value::U128(0x7f))
        );
        assert_eq!(
            read_register_value(&result.final_registers, &Reg::H(0)),
            Value::U64(0x7f)
        );
        assert_eq!(
            read_register_value(&result.final_registers, &Reg::D(0)),
            Value::U64(0x7f)
        );
    }

    #[test]
    fn execute_block_marks_simd_intrinsic_unknown_when_any_operand_is_unknown() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[Stmt::Intrinsic {
                name: "cmeq.2s".into(),
                operands: vec![
                    Expr::Reg(Reg::V(1)),
                    Expr::Reg(Reg::V(0)),
                    Expr::Reg(Reg::V(2)),
                ],
            }],
            BTreeMap::from([
                (
                    Reg::V(0),
                    Value::U128(0x0102_0304_0506_0708_1112_1314_1516_1718),
                ),
                (Reg::V(2), Value::Unknown),
            ]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            4,
        );

        assert_eq!(
            result.final_registers.get(&Reg::V(1)),
            Some(&Value::Unknown)
        );
    }

    #[test]
    fn execute_block_extracts_scalar_lane_with_umov() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };
        let lane_bytes = [
            0x11u8, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let result = execute_block(
            &[Stmt::Intrinsic {
                name: "umov".into(),
                operands: vec![Expr::Reg(Reg::W(26)), Expr::Reg(Reg::H(0))],
            }],
            BTreeMap::from([(Reg::V(0), Value::U128(u128::from_le_bytes(lane_bytes)))]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            4,
        );

        assert_eq!(
            result.final_registers.get(&Reg::W(26)),
            Some(&Value::U64(0x2211))
        );
        assert_eq!(
            result.final_registers.get(&Reg::X(26)),
            Some(&Value::U64(0x2211))
        );
    }

    #[test]
    fn execute_block_extracts_umov_from_scalar_d_alias_without_v_register() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[Stmt::Assign {
                dst: Reg::W(26),
                src: Expr::Extract {
                    src: Box::new(Expr::Reg(Reg::V(0))),
                    lsb: 0,
                    width: 16,
                },
            }],
            BTreeMap::from([(Reg::D(0), Value::U64(0xddcc_bbaa_4433_2211))]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            4,
        );

        assert_eq!(
            result.final_registers.get(&Reg::W(26)),
            Some(&Value::U64(0x2211))
        );
        assert_eq!(
            result.final_registers.get(&Reg::X(26)),
            Some(&Value::U64(0x2211))
        );
    }

    #[test]
    fn execute_block_duplicates_scalar_into_vector_lanes() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[Stmt::Intrinsic {
                name: "dup.2d".into(),
                operands: vec![Expr::Reg(Reg::V(1)), Expr::Reg(Reg::X(11))],
            }],
            BTreeMap::from([(Reg::X(11), Value::U64(0x1122_3344_5566_7788))]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            4,
        );

        assert_eq!(
            result.final_registers.get(&Reg::V(1)),
            Some(&Value::U128(0x1122_3344_5566_7788_1122_3344_5566_7788u128))
        );
    }

    #[test]
    fn execute_block_adds_vector_lanes_with_arrangement() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };
        let lhs = u128::from_le_bytes([1, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0]);
        let rhs = u128::from_le_bytes([2, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0]);

        let result = execute_block(
            &[Stmt::Intrinsic {
                name: "add.2d".into(),
                operands: vec![
                    Expr::Reg(Reg::V(0)),
                    Expr::Reg(Reg::V(1)),
                    Expr::Reg(Reg::V(2)),
                ],
            }],
            BTreeMap::from([(Reg::V(1), Value::U128(lhs)), (Reg::V(2), Value::U128(rhs))]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            4,
        );

        assert_eq!(
            result.final_registers.get(&Reg::V(0)),
            Some(&Value::U128(u128::from_le_bytes([
                3, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0,
            ])))
        );
    }

    #[test]
    fn execute_block_writes_scalar_simd_movi_without_arrangement() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[Stmt::Intrinsic {
                name: "movi".into(),
                operands: vec![Expr::Reg(Reg::D(0)), Expr::Imm(0x0000_0000_ffff_ffff)],
            }],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            4,
        );

        assert_eq!(
            read_register_value(&result.final_registers, &Reg::D(0)),
            Value::U64(0x0000_0000_ffff_ffff)
        );
    }

    #[test]
    fn execute_block_evaluates_bit_manipulation_exprs() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Clz(Box::new(Expr::Reg(Reg::X(8)))),
                },
                Stmt::Assign {
                    dst: Reg::W(1),
                    src: Expr::Rev(Box::new(Expr::Reg(Reg::W(9)))),
                },
                Stmt::Assign {
                    dst: Reg::X(2),
                    src: Expr::Rbit(Box::new(Expr::Reg(Reg::X(10)))),
                },
            ],
            BTreeMap::from([
                (Reg::X(8), Value::U64(0x0000_0000_0000_1000)),
                (Reg::W(9), Value::U64(0x1122_3344)),
                (Reg::X(10), Value::U64(1)),
            ]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            16,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(0)),
            Some(&Value::U64(51))
        );
        assert_eq!(
            result.final_registers.get(&Reg::W(1)),
            Some(&Value::U64(0x4433_2211))
        );
        assert_eq!(
            result.final_registers.get(&Reg::X(2)),
            Some(&Value::U64(1u64 << 63))
        );
    }

    #[test]
    fn execute_block_evaluates_crc32_intrinsics() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[
                Stmt::Intrinsic {
                    name: "crc32cx".into(),
                    operands: vec![
                        Expr::Reg(Reg::W(0)),
                        Expr::Reg(Reg::W(1)),
                        Expr::Reg(Reg::X(2)),
                    ],
                },
                Stmt::Intrinsic {
                    name: "crc32w".into(),
                    operands: vec![
                        Expr::Reg(Reg::W(3)),
                        Expr::Reg(Reg::W(4)),
                        Expr::Reg(Reg::W(5)),
                    ],
                },
            ],
            BTreeMap::from([
                (Reg::W(1), Value::U64(0)),
                (Reg::X(2), Value::U64(0x1122_3344_5566_7788)),
                (Reg::W(4), Value::U64(0)),
                (Reg::W(5), Value::U64(0x1234_5678)),
            ]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::W(0)),
            Some(&Value::U64(0x2371_e39c))
        );
        assert_eq!(
            result.final_registers.get(&Reg::W(3)),
            Some(&Value::U64(0x8e29_58ce))
        );
    }

    #[test]
    fn execute_block_evaluates_crc32c_width_variants_and_masks_source_bytes() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[
                Stmt::Intrinsic {
                    name: "crc32cb".into(),
                    operands: vec![
                        Expr::Reg(Reg::W(0)),
                        Expr::Reg(Reg::W(1)),
                        Expr::Reg(Reg::X(2)),
                    ],
                },
                Stmt::Intrinsic {
                    name: "crc32ch".into(),
                    operands: vec![
                        Expr::Reg(Reg::W(3)),
                        Expr::Reg(Reg::W(4)),
                        Expr::Reg(Reg::X(5)),
                    ],
                },
            ],
            BTreeMap::from([
                (Reg::W(1), Value::U64(0)),
                (Reg::X(2), Value::U64(0x1122_3344_5566_7788)),
                (Reg::W(4), Value::U64(0)),
                (Reg::X(5), Value::U64(0x1122_3344_5566_7788)),
            ]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::W(0)),
            Some(&Value::U64(0x082f_63b7))
        );
        assert_eq!(
            result.final_registers.get(&Reg::W(3)),
            Some(&Value::U64(0xc385_09a7))
        );
    }

    #[test]
    fn execute_block_propagates_unknown_crc32_inputs() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[Stmt::Intrinsic {
                name: "crc32cw".into(),
                operands: vec![
                    Expr::Reg(Reg::W(0)),
                    Expr::Reg(Reg::W(1)),
                    Expr::Reg(Reg::W(2)),
                ],
            }],
            BTreeMap::from([
                (Reg::W(1), Value::Unknown),
                (Reg::W(2), Value::U64(0x1234_5678)),
            ]),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            4,
        );

        assert_eq!(
            result.final_registers.get(&Reg::W(0)),
            Some(&Value::Unknown)
        );
    }

    #[test]
    #[should_panic(expected = "IL no-op")]
    fn execute_snippet_panics_on_nop() {
        let _ = execute_snippet(&[Stmt::Nop], BTreeMap::new(), 8);
    }

    #[test]
    fn execute_snippet_allows_supported_barrier() {
        let result = execute_snippet(
            &[
                Stmt::Barrier("dmb".to_string()),
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Imm(0x1234),
                },
            ],
            BTreeMap::new(),
            8,
        );

        assert_eq!(
            result.final_registers.get(&Reg::X(0)),
            Some(&Value::U64(0x1234))
        );
    }

    #[test]
    #[should_panic(expected = "unsupported IL statement")]
    fn execute_snippet_panics_on_unknown_barrier() {
        let _ = execute_snippet(&[Stmt::Barrier("unknown".to_string())], BTreeMap::new(), 8);
    }

    #[test]
    #[should_panic(expected = "unsupported IL statement")]
    fn execute_block_panics_on_stmt_intrinsic() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let _ = execute_block(
            &[Stmt::Intrinsic {
                name: "msr".into(),
                operands: vec![],
            }],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );
    }

    #[test]
    #[should_panic(expected = "unsupported IL expression")]
    fn execute_block_panics_on_unsupported_expr() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let _ = execute_block(
            &[Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Intrinsic {
                    name: "frecpe".into(),
                    operands: vec![Expr::Reg(Reg::D(1))],
                },
            }],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );
    }
}
