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
    let mut executor = BlockExecutor::new(
        initial_registers,
        initial_memory,
        backing,
        missing_memory_policy,
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
    missing_memory_policy: MissingMemoryPolicy,
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
            Stmt::Nop => panic_on_noop_stmt(stmt),
            Stmt::Intrinsic { name, operands } => self.execute_stmt_intrinsic(name, operands),
            Stmt::Branch { .. }
            | Stmt::CondBranch { .. }
            | Stmt::Call { .. }
            | Stmt::Ret
            | Stmt::Trap => {}
            Stmt::Barrier(kind) => {
                if !is_supported_barrier(kind) {
                    panic_on_unsupported_stmt(stmt);
                }
            }
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
            Expr::Intrinsic { name, operands } if name == "movk" => {
                let dst = operands
                    .first()
                    .map(|expr| self.eval_expr(expr))
                    .and_then(|value| value.as_u64());
                let src = operands
                    .get(1)
                    .map(|expr| self.eval_expr(expr))
                    .and_then(|value| value.as_u64());
                eval_movk_bits(dst, src)
            }
            Expr::Intrinsic { .. } => panic_on_unsupported_expr(expr),
            Expr::Clz(inner) => self.eval_unary_with_width(inner, leading_zeros_for_width),
            Expr::Cls(inner) => self.eval_unary_with_width(inner, leading_sign_bits_for_width),
            Expr::Rev(inner) => self.eval_unary_with_width(inner, reverse_bytes_for_width),
            Expr::Rbit(inner) => self.eval_unary_with_width(inner, reverse_bits_for_width),
            Expr::MrsRead(_)
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
            | Expr::FloatToInt(_) => panic_on_unsupported_expr(expr),
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

    fn eval_unary_with_width(&mut self, expr: &Expr, op: impl Fn(u64, u8) -> u64) -> Value {
        let value = self.eval_expr(expr);
        let width = expr_bit_width(expr).unwrap_or(64);
        match value.as_u64() {
            Some(bits) => Value::U64(op(bits, width)),
            None => Value::Unknown,
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

    fn execute_stmt_intrinsic(&mut self, name: &str, operands: &[Expr]) {
        match intrinsic_base_name(name) {
            "movi" => self.execute_vector_move_intrinsic(name, operands, false),
            "mvni" => self.execute_vector_move_intrinsic(name, operands, true),
            "cmeq" => self.execute_cmeq_intrinsic(name, operands),
            "bif" => self.execute_bif_intrinsic(name, operands),
            _ if crc32_intrinsic_info(name).is_some() => {
                self.execute_crc32_intrinsic(name, operands)
            }
            _ => {
                if !is_supported_stmt_intrinsic(name) {
                    panic!(
                        "aeon emulation encountered unsupported IL statement intrinsic `{name}`"
                    );
                }
            }
        }
    }

    fn execute_vector_move_intrinsic(&mut self, name: &str, operands: &[Expr], invert: bool) {
        let Some(arrangement) = parse_vector_arrangement(name) else {
            panic!("aeon emulation is missing SIMD arrangement for `{name}`");
        };
        let Some(dst) = operands.first().and_then(vector_reg_from_expr) else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        let imm = operands
            .get(1)
            .map(|expr| self.eval_expr(expr))
            .and_then(|value| value.as_u64());
        let value = imm
            .map(|imm| arranged_immediate_vector(imm, arrangement, invert))
            .map(Value::U128)
            .unwrap_or(Value::Unknown);
        write_arranged_vector_register(&mut self.registers, &dst, arrangement, value);
    }

    fn execute_cmeq_intrinsic(&mut self, name: &str, operands: &[Expr]) {
        let Some(arrangement) = parse_vector_arrangement(name) else {
            panic!("aeon emulation is missing SIMD arrangement for `{name}`");
        };
        let Some(dst) = operands.first().and_then(vector_reg_from_expr) else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        let lhs = operands
            .get(1)
            .map(|expr| {
                let value = self.eval_expr(expr);
                vector_operand_bytes(expr, value, arrangement)
            })
            .flatten();
        let rhs = operands
            .get(2)
            .map(|expr| {
                let value = self.eval_expr(expr);
                vector_operand_bytes(expr, value, arrangement)
            })
            .flatten();
        let value = match (lhs, rhs) {
            (Some(lhs), Some(rhs)) => Value::U128(vector_cmeq(lhs, rhs, arrangement)),
            _ => Value::Unknown,
        };
        write_arranged_vector_register(&mut self.registers, &dst, arrangement, value);
    }

    fn execute_bif_intrinsic(&mut self, name: &str, operands: &[Expr]) {
        let Some(arrangement) = parse_vector_arrangement(name) else {
            panic!("aeon emulation is missing SIMD arrangement for `{name}`");
        };
        let Some(dst) = operands.first().and_then(vector_reg_from_expr) else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        let original_dst = self.eval_expr(operands.first().expect("bif destination operand"));
        let src = operands
            .get(1)
            .map(|expr| {
                let value = self.eval_expr(expr);
                vector_operand_bytes(expr, value, arrangement)
            })
            .flatten();
        let mask = operands
            .get(2)
            .map(|expr| {
                let value = self.eval_expr(expr);
                vector_operand_bytes(expr, value, arrangement)
            })
            .flatten();
        let dst_bytes = vector_operand_bytes(
            operands.first().expect("bif destination operand"),
            original_dst,
            arrangement,
        );
        let value = match (dst_bytes, src, mask) {
            (Some(dst_bytes), Some(src), Some(mask)) => {
                Value::U128(vector_bif(dst_bytes, src, mask, arrangement))
            }
            _ => Value::Unknown,
        };
        write_arranged_vector_register(&mut self.registers, &dst, arrangement, value);
    }

    fn execute_crc32_intrinsic(&mut self, name: &str, operands: &[Expr]) {
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
        let value = match (acc, src, crc32_intrinsic_info(name)) {
            (Some(acc), Some(src), Some((poly, width))) => {
                Value::U64(crc32_update(acc as u32, src, width, poly) as u64)
            }
            _ => Value::Unknown,
        };
        self.write_reg(dst, value);
    }

    fn read_reg(&self, reg: &Reg) -> Value {
        read_register_value(&self.registers, reg)
    }

    fn write_reg(&mut self, reg: Reg, value: Value) {
        write_register_value(&mut self.registers, &mut self.flags, reg, value);
    }
}

impl<'a> BlockExecutor<'a> {
    fn new(
        initial_registers: BTreeMap<Reg, Value>,
        initial_memory: BTreeMap<MemoryCellId, Value>,
        backing: &'a dyn BackingStore,
        missing_memory_policy: MissingMemoryPolicy,
    ) -> Self {
        let mut executor = Self {
            registers: BTreeMap::new(),
            memory: initial_memory,
            flags: None,
            backing,
            missing_memory_policy,
            reads: Vec::new(),
            writes: Vec::new(),
            next_pc: None,
            stop: BlockStop::Completed,
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
            Expr::Intrinsic { name, operands } if name == "movk" => {
                let dst = operands
                    .first()
                    .map(|expr| self.eval_expr(expr))
                    .and_then(|value| value.as_u64());
                let src = operands
                    .get(1)
                    .map(|expr| self.eval_expr(expr))
                    .and_then(|value| value.as_u64());
                eval_movk_bits(dst, src)
            }
            Expr::Intrinsic { .. } => panic_on_unsupported_expr(expr),
            Expr::Clz(inner) => self.eval_unary_with_width(inner, leading_zeros_for_width),
            Expr::Cls(inner) => self.eval_unary_with_width(inner, leading_sign_bits_for_width),
            Expr::Rev(inner) => self.eval_unary_with_width(inner, reverse_bytes_for_width),
            Expr::Rbit(inner) => self.eval_unary_with_width(inner, reverse_bits_for_width),
            Expr::MrsRead(_)
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
            | Expr::FloatToInt(_) => panic_on_unsupported_expr(expr),
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

        if let Some(bytes) = overlay_bytes_for_cell(&self.memory, cell_id) {
            let value = decode_loaded_value(&bytes);
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

    fn execute_stmt_intrinsic(&mut self, name: &str, operands: &[Expr]) -> bool {
        match intrinsic_base_name(name) {
            "movi" => self.execute_vector_move_intrinsic(name, operands, false),
            "mvni" => self.execute_vector_move_intrinsic(name, operands, true),
            "cmeq" => self.execute_cmeq_intrinsic(name, operands),
            "bif" => self.execute_bif_intrinsic(name, operands),
            _ if crc32_intrinsic_info(name).is_some() => {
                self.execute_crc32_intrinsic(name, operands)
            }
            _ => {
                if !is_supported_stmt_intrinsic(name) {
                    panic!(
                        "aeon emulation encountered unsupported IL statement intrinsic `{name}`"
                    );
                }
            }
        }
        true
    }

    fn execute_vector_move_intrinsic(&mut self, name: &str, operands: &[Expr], invert: bool) {
        let Some(arrangement) = parse_vector_arrangement(name) else {
            panic!("aeon emulation is missing SIMD arrangement for `{name}`");
        };
        let Some(dst) = operands.first().and_then(vector_reg_from_expr) else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        let imm = operands
            .get(1)
            .map(|expr| self.eval_expr(expr))
            .and_then(|value| value.as_u64());
        let value = imm
            .map(|imm| arranged_immediate_vector(imm, arrangement, invert))
            .map(Value::U128)
            .unwrap_or(Value::Unknown);
        write_arranged_vector_register(&mut self.registers, &dst, arrangement, value);
    }

    fn execute_cmeq_intrinsic(&mut self, name: &str, operands: &[Expr]) {
        let Some(arrangement) = parse_vector_arrangement(name) else {
            panic!("aeon emulation is missing SIMD arrangement for `{name}`");
        };
        let Some(dst) = operands.first().and_then(vector_reg_from_expr) else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        let lhs = operands
            .get(1)
            .map(|expr| {
                let value = self.eval_expr(expr);
                vector_operand_bytes(expr, value, arrangement)
            })
            .flatten();
        let rhs = operands
            .get(2)
            .map(|expr| {
                let value = self.eval_expr(expr);
                vector_operand_bytes(expr, value, arrangement)
            })
            .flatten();
        let value = match (lhs, rhs) {
            (Some(lhs), Some(rhs)) => Value::U128(vector_cmeq(lhs, rhs, arrangement)),
            _ => Value::Unknown,
        };
        write_arranged_vector_register(&mut self.registers, &dst, arrangement, value);
    }

    fn execute_bif_intrinsic(&mut self, name: &str, operands: &[Expr]) {
        let Some(arrangement) = parse_vector_arrangement(name) else {
            panic!("aeon emulation is missing SIMD arrangement for `{name}`");
        };
        let Some(dst) = operands.first().and_then(vector_reg_from_expr) else {
            panic!("aeon emulation expected a SIMD destination for `{name}`");
        };
        let original_dst = self.eval_expr(operands.first().expect("bif destination operand"));
        let src = operands
            .get(1)
            .map(|expr| {
                let value = self.eval_expr(expr);
                vector_operand_bytes(expr, value, arrangement)
            })
            .flatten();
        let mask = operands
            .get(2)
            .map(|expr| {
                let value = self.eval_expr(expr);
                vector_operand_bytes(expr, value, arrangement)
            })
            .flatten();
        let dst_bytes = vector_operand_bytes(
            operands.first().expect("bif destination operand"),
            original_dst,
            arrangement,
        );
        let value = match (dst_bytes, src, mask) {
            (Some(dst_bytes), Some(src), Some(mask)) => {
                Value::U128(vector_bif(dst_bytes, src, mask, arrangement))
            }
            _ => Value::Unknown,
        };
        write_arranged_vector_register(&mut self.registers, &dst, arrangement, value);
    }

    fn execute_crc32_intrinsic(&mut self, name: &str, operands: &[Expr]) {
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
        let value = match (acc, src, crc32_intrinsic_info(name)) {
            (Some(acc), Some(src), Some((poly, width))) => {
                Value::U64(crc32_update(acc as u32, src, width, poly) as u64)
            }
            _ => Value::Unknown,
        };
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VectorArrangement {
    lane_bits: u8,
    lanes: u8,
    active_bytes: u8,
}

fn intrinsic_base_name(name: &str) -> &str {
    name.split_once('.').map(|(base, _)| base).unwrap_or(name)
}

fn parse_vector_arrangement(name: &str) -> Option<VectorArrangement> {
    let (_, suffix) = name.split_once('.')?;
    let split = suffix.find(|ch: char| !ch.is_ascii_digit())?;
    let lanes = suffix[..split].parse::<u8>().ok()?;
    let lane_bits = match suffix[split..].chars().next()? {
        'b' => 8,
        'h' => 16,
        's' => 32,
        'd' => 64,
        _ => return None,
    };
    let active_bytes = lanes.checked_mul(lane_bits / 8)?;
    if active_bytes == 0 || active_bytes > 16 {
        return None;
    }
    Some(VectorArrangement {
        lane_bits,
        lanes,
        active_bytes,
    })
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
    registers
        .get(&Reg::V(index))
        .or_else(|| registers.get(&Reg::Q(index)))
        .and_then(vector_bytes_from_value)
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
            let size = scalar_simd_size(&reg).expect("scalar SIMD size");
            if let Some(mut bytes) = read_simd_vector_bytes(registers, index) {
                if let Some(low) = low_bytes_from_value(&value, size) {
                    bytes[..size].copy_from_slice(&low);
                    clear_all_simd_aliases(registers, index);
                    registers.insert(Reg::V(index), Value::U128(u128::from_le_bytes(bytes)));
                } else {
                    clear_all_simd_aliases(registers, index);
                    registers.insert(Reg::V(index), Value::Unknown);
                }
                return;
            }

            clear_scalar_simd_aliases(registers, index);
            registers.insert(reg, scalar_or_unknown_value(value, size));
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

fn arranged_immediate_vector(imm: u64, arrangement: VectorArrangement, invert: bool) -> u128 {
    let lane_bytes = usize::from(arrangement.lane_bits / 8);
    let active_bytes = usize::from(arrangement.active_bytes);
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
            if matches!(expr, Expr::Imm(_)) {
                let lane_bytes = usize::from(arrangement.lane_bits / 8);
                let bits = bits.to_le_bytes();
                for lane in 0..usize::from(arrangement.lanes) {
                    let start = lane * lane_bytes;
                    bytes[start..start + lane_bytes].copy_from_slice(&bits[..lane_bytes]);
                }
            } else {
                let low = arrangement.active_bytes.min(8) as usize;
                bytes[..low].copy_from_slice(&bits.to_le_bytes()[..low]);
            }
            Some(bytes)
        }
        Value::F64(value) => {
            let mut bytes = [0u8; 16];
            let low = arrangement.active_bytes.min(8) as usize;
            bytes[..low].copy_from_slice(&value.to_bits().to_le_bytes()[..low]);
            Some(bytes)
        }
        Value::Unknown => None,
    }
}

fn vector_cmeq(lhs: [u8; 16], rhs: [u8; 16], arrangement: VectorArrangement) -> u128 {
    let lane_bytes = usize::from(arrangement.lane_bits / 8);
    let mut result = [0u8; 16];
    for lane in 0..usize::from(arrangement.lanes) {
        let start = lane * lane_bytes;
        let end = start + lane_bytes;
        let fill = if lhs[start..end] == rhs[start..end] {
            0xff
        } else {
            0x00
        };
        result[start..end].fill(fill);
    }
    u128::from_le_bytes(result)
}

fn vector_bif(
    dst: [u8; 16],
    src: [u8; 16],
    mask: [u8; 16],
    arrangement: VectorArrangement,
) -> u128 {
    let mut result = [0u8; 16];
    let active_bytes = usize::from(arrangement.active_bytes);
    for index in 0..active_bytes {
        result[index] = (dst[index] & mask[index]) | (src[index] & !mask[index]);
    }
    u128::from_le_bytes(result)
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

    if arrangement.active_bytes == 16 {
        clear_all_simd_aliases(registers, index);
        registers.insert(Reg::V(index), canonical_vector_value(value));
        return;
    }

    let Some(mut existing) = read_simd_vector_bytes(registers, index) else {
        clear_scalar_simd_aliases(registers, index);
        registers.remove(&Reg::Q(index));
        registers.insert(Reg::V(index), Value::Unknown);
        return;
    };
    let Some(updated) = vector_bytes_from_value(&value) else {
        clear_all_simd_aliases(registers, index);
        registers.insert(Reg::V(index), Value::Unknown);
        return;
    };
    let active_bytes = usize::from(arrangement.active_bytes);
    existing[..active_bytes].copy_from_slice(&updated[..active_bytes]);
    clear_all_simd_aliases(registers, index);
    registers.insert(Reg::V(index), Value::U128(u128::from_le_bytes(existing)));
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

fn overlay_bytes_for_cell(
    memory: &BTreeMap<MemoryCellId, Value>,
    cell_id: &MemoryCellId,
) -> Option<Vec<u8>> {
    if cell_id.size <= 1 {
        return None;
    }

    let mut bytes = Vec::with_capacity(cell_id.size as usize);
    for index in 0..cell_id.size {
        let byte_cell = MemoryCellId {
            location: byte_location(&cell_id.location, index)?,
            size: 1,
        };
        let value = memory.get(&byte_cell)?.as_u64()?;
        bytes.push(value as u8);
    }
    Some(bytes)
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

fn eval_movk_bits(dst: Option<u64>, src: Option<u64>) -> Value {
    let (Some(dst), Some(src)) = (dst, src) else {
        return Value::Unknown;
    };

    let shift = if src == 0 {
        0
    } else {
        (src.trailing_zeros() / 16) * 16
    };
    if shift >= 64 {
        return Value::Unknown;
    }

    let imm16 = (src >> shift) & 0xffff;
    let mask = 0xffffu64 << shift;
    Value::U64((dst & !mask) | ((imm16 << shift) & mask))
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

fn crc32_intrinsic_info(name: &str) -> Option<(u32, usize)> {
    match intrinsic_base_name(name) {
        "crc32b" => Some((0xedb8_8320, 1)),
        "crc32h" => Some((0xedb8_8320, 2)),
        "crc32w" => Some((0xedb8_8320, 4)),
        "crc32x" => Some((0xedb8_8320, 8)),
        "crc32cb" => Some((0x82f6_3b78, 1)),
        "crc32ch" => Some((0x82f6_3b78, 2)),
        "crc32cw" => Some((0x82f6_3b78, 4)),
        "crc32cx" => Some((0x82f6_3b78, 8)),
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

fn is_supported_stmt_intrinsic(name: &str) -> bool {
    matches!(
        name,
        "nop"
            | "yield"
            | "hint"
            | "paciasp"
            | "autiasp"
            | "bti"
            | "xpaclri"
            | "prfm"
            | "prfum"
            | "clrex"
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
                    name: "movk".to_string(),
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
                    name: "movk".to_string(),
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
                    name: "movi.2d".to_string(),
                    operands: vec![Expr::Reg(Reg::V(0)), Expr::Imm(u64::MAX)],
                },
                Stmt::Intrinsic {
                    name: "movi.2d".to_string(),
                    operands: vec![Expr::Reg(Reg::V(1)), Expr::Imm(u64::MAX)],
                },
                Stmt::Intrinsic {
                    name: "movi.2d".to_string(),
                    operands: vec![Expr::Reg(Reg::V(2)), Expr::Imm(u64::MAX)],
                },
                Stmt::Assign {
                    dst: Reg::D(0),
                    src: Expr::Imm(0x4433_2211_ffff_ffff),
                },
                Stmt::Intrinsic {
                    name: "cmeq.2s".to_string(),
                    operands: vec![
                        Expr::Reg(Reg::V(1)),
                        Expr::Reg(Reg::V(0)),
                        Expr::Reg(Reg::V(1)),
                    ],
                },
                Stmt::Intrinsic {
                    name: "bif.8b".to_string(),
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

        let mut expected_v0 = [0xffu8; 16];
        expected_v0[..8].copy_from_slice(&0x4433_2211_ffff_ffffu64.to_le_bytes());
        assert_eq!(
            result.final_registers.get(&Reg::V(0)),
            Some(&Value::U128(u128::from_le_bytes(expected_v0)))
        );

        let mut expected_v1 = [0xffu8; 16];
        expected_v1[4..8].fill(0x00);
        assert_eq!(
            result.final_registers.get(&Reg::V(1)),
            Some(&Value::U128(u128::from_le_bytes(expected_v1)))
        );

        let mut expected_v2 = [0xffu8; 16];
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
    fn execute_block_scalar_simd_write_updates_existing_vector_aliases() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[
                Stmt::Intrinsic {
                    name: "movi.2d".to_string(),
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

        let mut expected = [0xffu8; 16];
        expected[0] = 0x7f;
        expected[1] = 0x22;
        assert_eq!(
            result.final_registers.get(&Reg::V(0)),
            Some(&Value::U128(u128::from_le_bytes(expected)))
        );
        assert_eq!(
            read_register_value(&result.final_registers, &Reg::H(0)),
            Value::U64(0x227f)
        );
        assert_eq!(
            read_register_value(&result.final_registers, &Reg::D(0)),
            Value::U64(0xffff_ffff_ffff_227f)
        );
    }

    #[test]
    fn execute_block_marks_simd_intrinsic_unknown_when_any_operand_is_unknown() {
        let backing = TestBackingStore {
            cells: BTreeMap::new(),
        };

        let result = execute_block(
            &[Stmt::Intrinsic {
                name: "cmeq.2s".to_string(),
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
                    name: "crc32cx".to_string(),
                    operands: vec![
                        Expr::Reg(Reg::W(0)),
                        Expr::Reg(Reg::W(1)),
                        Expr::Reg(Reg::X(2)),
                    ],
                },
                Stmt::Intrinsic {
                    name: "crc32w".to_string(),
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
                    name: "crc32cb".to_string(),
                    operands: vec![
                        Expr::Reg(Reg::W(0)),
                        Expr::Reg(Reg::W(1)),
                        Expr::Reg(Reg::X(2)),
                    ],
                },
                Stmt::Intrinsic {
                    name: "crc32ch".to_string(),
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
                name: "crc32cw".to_string(),
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
                name: "msr".to_string(),
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
                src: Expr::FAdd(Box::new(Expr::FImm(1.0)), Box::new(Expr::FImm(2.0))),
            }],
            BTreeMap::new(),
            BTreeMap::new(),
            &backing,
            MissingMemoryPolicy::Stop,
            8,
        );
    }
}
