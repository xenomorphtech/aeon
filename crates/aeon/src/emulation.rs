use std::collections::{BTreeMap, BTreeSet};

use aeonil::{Condition, Expr, Reg, Stmt};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    U64(u64),
    U128(u128),
    F64(f64),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryLocation {
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
    step_budget: usize,
) -> BlockExecutionResult {
    let mut executor = BlockExecutor::new(initial_registers, initial_memory, backing);
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

struct Executor {
    registers: BTreeMap<Reg, Value>,
    memory: BTreeMap<MemoryCellId, Value>,
    touched: BTreeSet<MemoryCellId>,
    flags: Option<Nzcv>,
}

struct BlockExecutor<'a> {
    registers: BTreeMap<Reg, Value>,
    memory: BTreeMap<MemoryCellId, Value>,
    flags: Option<Nzcv>,
    backing: &'a dyn BackingStore,
    reads: Vec<MemoryReadObservation>,
    writes: Vec<MemoryWriteObservation>,
    next_pc: Option<u64>,
    stop: BlockStop,
}

pub fn execute_snippet(
    stmts: &[Stmt],
    initial_registers: BTreeMap<Reg, Value>,
    step_budget: usize,
) -> ExecutionResult {
    let mut executor = Executor::new(initial_registers);
    let mut steps_executed = 0usize;

    for stmt in stmts {
        if steps_executed == step_budget {
            break;
        }
        executor.execute_stmt(stmt);
        steps_executed += 1;
    }

    let budget_exhausted = steps_executed < stmts.len();
    let touched_memory = executor
        .touched
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

impl Executor {
    fn new(initial_registers: BTreeMap<Reg, Value>) -> Self {
        let mut executor = Self {
            registers: BTreeMap::new(),
            memory: BTreeMap::new(),
            touched: BTreeSet::new(),
            flags: None,
        };

        for (reg, value) in initial_registers {
            executor.write_reg(reg, value);
        }

        executor
    }

    fn execute_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { dst, src } => {
                let value = self.eval_expr(src);
                self.write_reg(dst.clone(), value);
            }
            Stmt::Store { addr, value, size } => {
                if let Some(cell_id) = self.resolve_memory_cell(addr, *size) {
                    let stored = mask_value(self.eval_expr(value), *size);
                    self.touched.insert(cell_id.clone());
                    self.memory.insert(cell_id, stored);
                }
            }
            Stmt::SetFlags { expr } => self.apply_flags(expr),
            Stmt::Pair(lhs, rhs) => {
                self.execute_stmt(lhs);
                self.execute_stmt(rhs);
            }
            Stmt::Branch { .. }
            | Stmt::CondBranch { .. }
            | Stmt::Call { .. }
            | Stmt::Ret
            | Stmt::Nop
            | Stmt::Barrier(_)
            | Stmt::Trap
            | Stmt::Intrinsic { .. } => {}
        }
    }

    fn eval_expr(&mut self, expr: &Expr) -> Value {
        match expr {
            Expr::Reg(reg) => self.read_reg(reg),
            Expr::Imm(value) | Expr::AdrpImm(value) | Expr::AdrImm(value) => Value::U64(*value),
            Expr::FImm(value) => Value::F64(*value),
            Expr::Load { addr, size } => {
                let Some(cell_id) = self.resolve_memory_cell(addr, *size) else {
                    return Value::Unknown;
                };
                self.touched.insert(cell_id.clone());
                self.memory.entry(cell_id).or_insert(Value::Unknown).clone()
            }
            Expr::Add(lhs, rhs) => self.eval_binary_u64(lhs, rhs, u64::wrapping_add),
            Expr::Sub(lhs, rhs) => self.eval_binary_u64(lhs, rhs, u64::wrapping_sub),
            Expr::Mul(lhs, rhs) => self.eval_binary_u64(lhs, rhs, u64::wrapping_mul),
            Expr::Div(lhs, rhs) | Expr::UDiv(lhs, rhs) => {
                self.eval_binary_u64(lhs, rhs, |a, b| if b == 0 { 0 } else { a / b })
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
            Expr::Shl(lhs, rhs) => {
                self.eval_binary_u64(
                    lhs,
                    rhs,
                    |a, b| {
                        if b < 64 {
                            a.wrapping_shl(b as u32)
                        } else {
                            0
                        }
                    },
                )
            }
            Expr::Lsr(lhs, rhs) => {
                self.eval_binary_u64(
                    lhs,
                    rhs,
                    |a, b| {
                        if b < 64 {
                            a.wrapping_shr(b as u32)
                        } else {
                            0
                        }
                    },
                )
            }
            Expr::Asr(lhs, rhs) => self.eval_binary_u64(lhs, rhs, |a, b| {
                let shift = b.min(63) as u32;
                ((a as i64) >> shift) as u64
            }),
            Expr::Ror(lhs, rhs) => {
                self.eval_binary_u64(lhs, rhs, |a, b| a.rotate_right((b % 64) as u32))
            }
            Expr::SignExtend { src, from_bits } => {
                self.eval_unary_u64(src, |value| sign_extend(value, *from_bits))
            }
            Expr::ZeroExtend { src, from_bits } => {
                self.eval_unary_u64(src, |value| apply_mask(value, *from_bits))
            }
            Expr::Extract { src, lsb, width } => {
                self.eval_unary_u64(src, |value| apply_mask(value >> *lsb as u32, *width))
            }
            Expr::Insert {
                dst,
                src,
                lsb,
                width,
            } => {
                let dst_value = self.eval_expr(dst);
                let src_value = self.eval_expr(src);
                match (dst_value.as_u64(), src_value.as_u64()) {
                    (Some(dst_bits), Some(src_bits)) => {
                        let mask = width_mask(*width) << *lsb as u32;
                        let inserted = (dst_bits & !mask)
                            | ((apply_mask(src_bits, *width) << *lsb as u32) & mask);
                        Value::U64(inserted)
                    }
                    _ => Value::Unknown,
                }
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
            Expr::Intrinsic { .. }
            | Expr::MrsRead(_)
            | Expr::FAdd(_, _)
            | Expr::FSub(_, _)
            | Expr::FMul(_, _)
            | Expr::FDiv(_, _)
            | Expr::FNeg(_)
            | Expr::FAbs(_)
            | Expr::FSqrt(_)
            | Expr::FMax(_, _)
            | Expr::FMin(_, _)
            | Expr::FCvt(_)
            | Expr::IntToFloat(_)
            | Expr::FloatToInt(_)
            | Expr::Clz(_)
            | Expr::Cls(_)
            | Expr::Rev(_)
            | Expr::Rbit(_) => Value::Unknown,
        }
    }

    fn eval_binary_u64(&mut self, lhs: &Expr, rhs: &Expr, op: impl Fn(u64, u64) -> u64) -> Value {
        let lhs_value = self.eval_expr(lhs);
        let rhs_value = self.eval_expr(rhs);
        match (lhs_value.as_u64(), rhs_value.as_u64()) {
            (Some(lhs_bits), Some(rhs_bits)) => Value::U64(op(lhs_bits, rhs_bits)),
            _ => Value::Unknown,
        }
    }

    fn eval_unary_u64(&mut self, expr: &Expr, op: impl Fn(u64) -> u64) -> Value {
        let value = self.eval_expr(expr);
        match value.as_u64() {
            Some(bits) => Value::U64(op(bits)),
            None => Value::Unknown,
        }
    }

    fn resolve_memory_cell(&mut self, expr: &Expr, size: u8) -> Option<MemoryCellId> {
        let location = self.resolve_memory_location(expr)?;
        Some(MemoryCellId { location, size })
    }

    fn resolve_memory_location(&mut self, expr: &Expr) -> Option<MemoryLocation> {
        match expr {
            Expr::StackSlot { offset, .. } => Some(MemoryLocation::StackSlot(*offset)),
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
        self.flags = flags;
        let stored = flags
            .map(|nzcv| Value::U64(nzcv.pack()))
            .unwrap_or(Value::Unknown);
        self.registers.insert(Reg::Flags, stored);
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
            _ => None,
        }
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

    fn read_reg(&self, reg: &Reg) -> Value {
        match reg {
            Reg::XZR => Value::U64(0),
            Reg::W(index) => self
                .registers
                .get(reg)
                .cloned()
                .or_else(|| {
                    self.registers
                        .get(&Reg::X(*index))
                        .cloned()
                        .map(truncate_to_w)
                })
                .unwrap_or(Value::Unknown),
            Reg::X(index) => self
                .registers
                .get(reg)
                .cloned()
                .or_else(|| {
                    self.registers
                        .get(&Reg::W(*index))
                        .cloned()
                        .map(zero_extend_w)
                })
                .unwrap_or(Value::Unknown),
            _ => self.registers.get(reg).cloned().unwrap_or(Value::Unknown),
        }
    }

    fn write_reg(&mut self, reg: Reg, value: Value) {
        match reg {
            Reg::XZR => {}
            Reg::W(index) => {
                let w_value = truncate_to_w(value);
                let x_value = zero_extend_w(w_value.clone());
                self.registers.insert(Reg::W(index), w_value);
                self.registers.insert(Reg::X(index), x_value);
            }
            Reg::X(index) => {
                let w_value = truncate_to_w(value.clone());
                self.registers.insert(Reg::W(index), w_value);
                self.registers.insert(Reg::X(index), value);
            }
            Reg::Flags => {
                self.flags = value.as_u64().map(Nzcv::from_bits);
                self.registers.insert(Reg::Flags, value);
            }
            _ => {
                self.registers.insert(reg, value);
            }
        }
    }
}

impl<'a> BlockExecutor<'a> {
    fn new(
        initial_registers: BTreeMap<Reg, Value>,
        initial_memory: BTreeMap<MemoryCellId, Value>,
        backing: &'a dyn BackingStore,
    ) -> Self {
        let mut executor = Self {
            registers: BTreeMap::new(),
            memory: initial_memory,
            flags: None,
            backing,
            reads: Vec::new(),
            writes: Vec::new(),
            next_pc: None,
            stop: BlockStop::Completed,
        };

        for (reg, value) in initial_registers {
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

    fn execute_stmt(&mut self, stmt: &Stmt) -> bool {
        match stmt {
            Stmt::Assign { dst, src } => {
                let value = self.eval_expr(src);
                if !matches!(self.stop, BlockStop::Completed) {
                    return false;
                }
                self.write_reg(dst.clone(), value);
                true
            }
            Stmt::Store { addr, value, size } => {
                let Some(cell_id) = self.resolve_memory_cell(addr, *size) else {
                    self.stop = BlockStop::MissingMemory {
                        location: MemoryLocation::Absolute(0),
                        size: *size,
                    };
                    return false;
                };
                let stored = mask_value(self.eval_expr(value), *size);
                if !matches!(self.stop, BlockStop::Completed) {
                    return false;
                }
                self.memory.insert(cell_id.clone(), stored.clone());
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
            Stmt::Call { .. } | Stmt::Ret | Stmt::Trap => {
                self.stop = BlockStop::UnsupportedControlFlow;
                false
            }
            Stmt::Nop | Stmt::Barrier(_) | Stmt::Intrinsic { .. } => true,
        }
    }

    fn eval_expr(&mut self, expr: &Expr) -> Value {
        match expr {
            Expr::Reg(reg) => self.read_reg(reg),
            Expr::Imm(value) | Expr::AdrpImm(value) | Expr::AdrImm(value) => Value::U64(*value),
            Expr::FImm(value) => Value::F64(*value),
            Expr::Load { addr, size } => {
                let Some(cell_id) = self.resolve_memory_cell(addr, *size) else {
                    self.stop = BlockStop::MissingMemory {
                        location: MemoryLocation::Absolute(0),
                        size: *size,
                    };
                    return Value::Unknown;
                };
                self.load_memory(&cell_id)
            }
            Expr::Add(lhs, rhs) => self.eval_binary_u64(lhs, rhs, u64::wrapping_add),
            Expr::Sub(lhs, rhs) => self.eval_binary_u64(lhs, rhs, u64::wrapping_sub),
            Expr::Mul(lhs, rhs) => self.eval_binary_u64(lhs, rhs, u64::wrapping_mul),
            Expr::Div(lhs, rhs) | Expr::UDiv(lhs, rhs) => {
                self.eval_binary_u64(lhs, rhs, |a, b| if b == 0 { 0 } else { a / b })
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
            Expr::Shl(lhs, rhs) => {
                self.eval_binary_u64(
                    lhs,
                    rhs,
                    |a, b| {
                        if b < 64 {
                            a.wrapping_shl(b as u32)
                        } else {
                            0
                        }
                    },
                )
            }
            Expr::Lsr(lhs, rhs) => {
                self.eval_binary_u64(
                    lhs,
                    rhs,
                    |a, b| {
                        if b < 64 {
                            a.wrapping_shr(b as u32)
                        } else {
                            0
                        }
                    },
                )
            }
            Expr::Asr(lhs, rhs) => self.eval_binary_u64(lhs, rhs, |a, b| {
                let shift = b.min(63) as u32;
                ((a as i64) >> shift) as u64
            }),
            Expr::Ror(lhs, rhs) => {
                self.eval_binary_u64(lhs, rhs, |a, b| a.rotate_right((b % 64) as u32))
            }
            Expr::SignExtend { src, from_bits } => {
                self.eval_unary_u64(src, |value| sign_extend(value, *from_bits))
            }
            Expr::ZeroExtend { src, from_bits } => {
                self.eval_unary_u64(src, |value| apply_mask(value, *from_bits))
            }
            Expr::Extract { src, lsb, width } => {
                self.eval_unary_u64(src, |value| apply_mask(value >> *lsb as u32, *width))
            }
            Expr::Insert {
                dst,
                src,
                lsb,
                width,
            } => {
                let dst_value = self.eval_expr(dst);
                let src_value = self.eval_expr(src);
                match (dst_value.as_u64(), src_value.as_u64()) {
                    (Some(dst_bits), Some(src_bits)) => {
                        let mask = width_mask(*width) << *lsb as u32;
                        let inserted = (dst_bits & !mask)
                            | ((apply_mask(src_bits, *width) << *lsb as u32) & mask);
                        Value::U64(inserted)
                    }
                    _ => Value::Unknown,
                }
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
            Expr::StackSlot { .. } => Value::Unknown,
            Expr::Intrinsic { .. }
            | Expr::MrsRead(_)
            | Expr::FAdd(_, _)
            | Expr::FSub(_, _)
            | Expr::FMul(_, _)
            | Expr::FDiv(_, _)
            | Expr::FNeg(_)
            | Expr::FAbs(_)
            | Expr::FSqrt(_)
            | Expr::FMax(_, _)
            | Expr::FMin(_, _)
            | Expr::FCvt(_)
            | Expr::IntToFloat(_)
            | Expr::FloatToInt(_)
            | Expr::Clz(_)
            | Expr::Cls(_)
            | Expr::Rev(_)
            | Expr::Rbit(_) => Value::Unknown,
        }
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
            MemoryLocation::Absolute(addr) => Some(addr),
            MemoryLocation::StackSlot(offset) => self
                .read_reg(&Reg::SP)
                .as_u64()
                .map(|sp| sp.wrapping_add(offset as u64)),
        };

        if let Some(addr) = backing_addr {
            if let Some(bytes) = self.backing.load(addr, cell_id.size) {
                let value = decode_loaded_value(&bytes);
                self.reads.push(MemoryReadObservation {
                    id: cell_id.clone(),
                    value: value.clone(),
                    source: Some(MemoryValueSource::BackingStore),
                });
                return value;
            }
        }

        self.stop = BlockStop::MissingMemory {
            location: cell_id.location.clone(),
            size: cell_id.size,
        };
        self.reads.push(MemoryReadObservation {
            id: cell_id.clone(),
            value: Value::Unknown,
            source: None,
        });
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

    fn eval_unary_u64(&mut self, expr: &Expr, op: impl Fn(u64) -> u64) -> Value {
        let value = self.eval_expr(expr);
        match value.as_u64() {
            Some(bits) => Value::U64(op(bits)),
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
            Expr::StackSlot { offset, .. } => self
                .read_reg(&Reg::SP)
                .as_u64()
                .map(|sp| MemoryLocation::Absolute(sp.wrapping_add(*offset as u64)))
                .or(Some(MemoryLocation::StackSlot(*offset))),
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
        self.flags = flags;
        let stored = flags
            .map(|nzcv| Value::U64(nzcv.pack()))
            .unwrap_or(Value::Unknown);
        self.registers.insert(Reg::Flags, stored);
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
            _ => None,
        }
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

    fn read_reg(&self, reg: &Reg) -> Value {
        match reg {
            Reg::XZR => Value::U64(0),
            Reg::W(index) => self
                .registers
                .get(reg)
                .cloned()
                .or_else(|| {
                    self.registers
                        .get(&Reg::X(*index))
                        .cloned()
                        .map(truncate_to_w)
                })
                .unwrap_or(Value::Unknown),
            Reg::X(index) => self
                .registers
                .get(reg)
                .cloned()
                .or_else(|| {
                    self.registers
                        .get(&Reg::W(*index))
                        .cloned()
                        .map(zero_extend_w)
                })
                .unwrap_or(Value::Unknown),
            _ => self.registers.get(reg).cloned().unwrap_or(Value::Unknown),
        }
    }

    fn write_reg(&mut self, reg: Reg, value: Value) {
        match reg {
            Reg::XZR => {}
            Reg::W(index) => {
                let w_value = truncate_to_w(value);
                let x_value = zero_extend_w(w_value.clone());
                self.registers.insert(Reg::W(index), w_value);
                self.registers.insert(Reg::X(index), x_value);
            }
            Reg::X(index) => {
                let w_value = truncate_to_w(value.clone());
                self.registers.insert(Reg::W(index), w_value);
                self.registers.insert(Reg::X(index), value);
            }
            Reg::Flags => {
                self.flags = value.as_u64().map(Nzcv::from_bits);
                self.registers.insert(Reg::Flags, value);
            }
            _ => {
                self.registers.insert(reg, value);
            }
        }
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

fn offset_location(location: MemoryLocation, delta: i64, subtract: bool) -> MemoryLocation {
    match location {
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

fn expr_bit_width(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Reg(Reg::W(_)) => Some(32),
        Expr::Reg(Reg::X(_)) | Expr::Reg(Reg::SP) | Expr::Reg(Reg::PC) | Expr::Reg(Reg::Flags) => {
            Some(64)
        }
        Expr::Imm(_) | Expr::AdrpImm(_) | Expr::AdrImm(_) => None,
        Expr::Load { size, .. } | Expr::StackSlot { size, .. } => Some((*size).max(1) * 8),
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
        | Expr::FMin(lhs, rhs)
        | Expr::Compare { lhs, rhs, .. } => expr_bit_width(lhs).or_else(|| expr_bit_width(rhs)),
        Expr::Neg(inner)
        | Expr::Abs(inner)
        | Expr::Not(inner)
        | Expr::FNeg(inner)
        | Expr::FAbs(inner)
        | Expr::FSqrt(inner)
        | Expr::FCvt(inner)
        | Expr::IntToFloat(inner)
        | Expr::FloatToInt(inner)
        | Expr::Clz(inner)
        | Expr::Cls(inner)
        | Expr::Rev(inner)
        | Expr::Rbit(inner)
        | Expr::SignExtend { src: inner, .. }
        | Expr::ZeroExtend { src: inner, .. }
        | Expr::Extract { src: inner, .. } => expr_bit_width(inner),
        Expr::Insert { dst, .. } => expr_bit_width(dst),
        Expr::CondSelect {
            if_true, if_false, ..
        } => expr_bit_width(if_true).or_else(|| expr_bit_width(if_false)),
        Expr::FImm(_)
        | Expr::Intrinsic { .. }
        | Expr::MrsRead(_)
        | Expr::Reg(Reg::V(_))
        | Expr::Reg(Reg::Q(_))
        | Expr::Reg(Reg::D(_))
        | Expr::Reg(Reg::S(_))
        | Expr::Reg(Reg::H(_))
        | Expr::Reg(Reg::VByte(_))
        | Expr::Reg(Reg::XZR) => None,
    }
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
}
