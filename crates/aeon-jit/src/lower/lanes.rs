//! Lane-wise SIMD statement intrinsics.
//!
//! The lifter emits vector instructions as statements whose first operand is
//! the destination (`add.4s [v8, v0, v1]`). Everything here computes one lane
//! at a time from the lanes of the sources (and, for accumulating forms, the
//! old destination), then writes the whole register: lanes outside the
//! arrangement are zeroed, as on the CPU.
//!
//! A scalar SIMD form (`cmeq d10, d4, d4`) is treated as one 64-bit lane.

use crate::imports::Imports;
use crate::lower::expr::default_nan_if_generated;
use crate::lower::{base_reg_operand, vector_lane_type, LoweredValue, LoweringState};
use crate::JitError;
use aeonil::simd::{permute_source, widen_spec, WidenMode};
use aeonil::{Expr, IntrinsicName, IntrinsicOp, Reg};
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::types::{self, I16X8, I32X4, I64X2, I8X16};
use cranelift_codegen::ir::{InstBuilder, MemFlags, StackSlotData, StackSlotKind, Type, Value};
use cranelift_frontend::FunctionBuilder;
use cranelift_module::Module;

/// How an operation's operands map to lanes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `[dst, a]`
    Unary,
    /// `[dst, a, b]`
    Binary,
    /// `[dst, a, b]`, also reading the old destination lane.
    Accumulate,
    /// `[dst, a, #amount]`
    Shift,
}

/// A source operand: per-lane values, or one value used for every lane.
#[derive(Clone, Copy)]
enum LaneOperand {
    Lanes(Value),
    Scalar(Value),
}

/// The lanes a statement works on.
#[derive(Clone, Copy)]
pub(crate) struct LaneLayout {
    pub(crate) lanes: u8,
    pub(crate) lane_bits: u8,
}

impl LaneLayout {
    pub(crate) fn lane_ty(self) -> Result<Type, JitError> {
        vector_lane_type(self.lane_bits)
    }

    /// The 128-bit vector type with this lane width.
    pub(crate) fn vec_ty(self) -> Result<Type, JitError> {
        full_vector_type(self.lane_bits)
    }
}

pub(crate) fn full_vector_type(lane_bits: u8) -> Result<Type, JitError> {
    match lane_bits {
        8 => Ok(I8X16),
        16 => Ok(I16X8),
        32 => Ok(I32X4),
        64 => Ok(I64X2),
        _ => Err(JitError::UnsupportedStmt("vector lane width")),
    }
}

/// The index of a SIMD register operand, whatever view it is named by.
pub(crate) fn simd_operand_index(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Reg(Reg::V(n) | Reg::Q(n) | Reg::D(n) | Reg::S(n) | Reg::H(n) | Reg::VByte(n)) => {
            Some(*n)
        }
        _ => None,
    }
}

fn constant(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Imm(value) => Some(*value),
        Expr::Shl(value, amount) => {
            let value = constant(value)?;
            let amount = constant(amount)?;
            Some(value.checked_shl(u32::try_from(amount).ok()?).unwrap_or(0))
        }
        _ => None,
    }
}

fn shape_of(op: IntrinsicOp) -> Option<Shape> {
    Some(match op {
        IntrinsicOp::Mov
        | IntrinsicOp::Movi
        | IntrinsicOp::Mvni
        | IntrinsicOp::Dup
        | IntrinsicOp::Not
        | IntrinsicOp::Mvn
        | IntrinsicOp::Neg
        | IntrinsicOp::Abs
        | IntrinsicOp::Cnt => Shape::Unary,
        IntrinsicOp::And
        | IntrinsicOp::Orr
        | IntrinsicOp::Eor
        | IntrinsicOp::Bic
        | IntrinsicOp::Orn
        | IntrinsicOp::Add
        | IntrinsicOp::Sub
        | IntrinsicOp::Mul
        | IntrinsicOp::Cmeq
        | IntrinsicOp::Cmhi
        | IntrinsicOp::Cmhs
        | IntrinsicOp::Cmgt
        | IntrinsicOp::Cmge
        | IntrinsicOp::Umax
        | IntrinsicOp::Umin
        | IntrinsicOp::Smax
        | IntrinsicOp::Smin
        | IntrinsicOp::Fadd
        | IntrinsicOp::Fsub
        | IntrinsicOp::Fmul
        | IntrinsicOp::Fdiv => Shape::Binary,
        IntrinsicOp::Mla
        | IntrinsicOp::Mls
        | IntrinsicOp::Bsl
        | IntrinsicOp::Bit
        | IntrinsicOp::Bif => Shape::Accumulate,
        IntrinsicOp::Shl | IntrinsicOp::Ushr | IntrinsicOp::Sshr => Shape::Shift,
        _ => return None,
    })
}

impl LoweringState {
    /// The lanes a statement intrinsic works on: its arrangement, or a single
    /// 64-bit lane when the destination is a D register.
    pub(crate) fn lane_layout(name: &IntrinsicName, dst: &Expr) -> Result<LaneLayout, JitError> {
        if let Some(arrangement) = name.arrangement() {
            return Ok(LaneLayout {
                lanes: arrangement.lanes,
                lane_bits: arrangement.lane_bits,
            });
        }
        match dst {
            Expr::Reg(Reg::D(_)) => Ok(LaneLayout {
                lanes: 1,
                lane_bits: 64,
            }),
            _ => Err(JitError::UnsupportedStmt("vector arrangement")),
        }
    }

    /// Reads SIMD register `index` in full, as `vec_ty`.
    pub(crate) fn read_full_vector(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        index: u8,
        vec_ty: Type,
    ) -> Result<Value, JitError> {
        let reg = Expr::Reg(Reg::V(index));
        let value = self.lower_expr(module, builder, imports, &reg, Some(I8X16))?;
        let value = self.coerce_value(builder, value, I8X16)?;
        Ok(self.bitcast_value(builder, vec_ty, value.value, value.ty))
    }

    /// Writes a whole SIMD register from a vector of `vec_ty`.
    pub(crate) fn write_full_vector(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: u8,
        value: Value,
        vec_ty: Type,
    ) -> Result<(), JitError> {
        let value = self.bitcast_value(builder, I8X16, value, vec_ty);
        self.write_reg(builder, &Reg::V(index), LoweredValue { value, ty: I8X16 })
    }

    pub(crate) fn zero_vector(
        &self,
        builder: &mut FunctionBuilder<'_>,
        layout: LaneLayout,
    ) -> Result<Value, JitError> {
        let zero = self.zero_for_type(builder, layout.lane_ty()?)?;
        Ok(builder.ins().splat(layout.vec_ty()?, zero))
    }

    fn lane_operand(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        expr: &Expr,
        layout: LaneLayout,
    ) -> Result<LaneOperand, JitError> {
        let lane_ty = layout.lane_ty()?;
        if let Some(index) = simd_operand_index(expr) {
            let vec = self.read_full_vector(module, builder, imports, index, layout.vec_ty()?)?;
            return Ok(LaneOperand::Lanes(vec));
        }
        if let Some(value) = constant(expr) {
            let mask = if layout.lane_bits == 64 {
                u64::MAX
            } else {
                (1u64 << layout.lane_bits) - 1
            };
            return Ok(LaneOperand::Scalar(self.iconst(
                builder,
                lane_ty,
                value & mask,
            )?));
        }
        let value = self.lower_expr(module, builder, imports, expr, Some(lane_ty))?;
        let value = self.coerce_int(builder, value, lane_ty)?;
        Ok(LaneOperand::Scalar(value.value))
    }

    pub(crate) fn lower_lane_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        let op = name.op();
        let shape = shape_of(op).ok_or(JitError::UnsupportedStmt("lane intrinsic"))?;
        let expected = if shape == Shape::Unary { 2 } else { 3 };
        if operands.len() != expected {
            return Err(JitError::UnsupportedStmt("lane intrinsic operand count"));
        }
        let dst_index = simd_operand_index(&operands[0])
            .ok_or(JitError::UnsupportedStmt("lane intrinsic dest"))?;
        let layout = Self::lane_layout(name, &operands[0])?;
        let lane_ty = layout.lane_ty()?;
        let vec_ty = layout.vec_ty()?;

        let old_dst = if shape == Shape::Accumulate {
            Some(self.read_full_vector(module, builder, imports, dst_index, vec_ty)?)
        } else {
            None
        };
        let a = self.lane_operand(module, builder, imports, &operands[1], layout)?;
        let mut shift = 0u32;
        let b = match shape {
            Shape::Unary => None,
            Shape::Shift => {
                shift = match &operands[2] {
                    Expr::Imm(value) => u32::try_from(*value)
                        .map_err(|_| JitError::UnsupportedStmt("vector shift amount"))?,
                    _ => return Err(JitError::UnsupportedStmt("vector shift amount")),
                };
                None
            }
            Shape::Binary | Shape::Accumulate => {
                Some(self.lane_operand(module, builder, imports, &operands[2], layout)?)
            }
        };

        let lane_of =
            |builder: &mut FunctionBuilder<'_>, operand: LaneOperand, lane: u8| match operand {
                LaneOperand::Lanes(vec) => builder.ins().extractlane(vec, lane),
                LaneOperand::Scalar(value) => value,
            };

        let mut out = self.zero_vector(builder, layout)?;
        for lane in 0..layout.lanes {
            let a_lane = lane_of(builder, a, lane);
            let b_lane = b.map(|b| lane_of(builder, b, lane));
            let d_lane = old_dst.map(|vec| builder.ins().extractlane(vec, lane));
            let value = self.lane_value(builder, op, lane_ty, d_lane, a_lane, b_lane, shift)?;
            out = builder.ins().insertlane(out, value, lane);
        }
        self.write_full_vector(builder, dst_index, out, vec_ty)
    }

    #[allow(clippy::too_many_arguments)]
    fn lane_value(
        &self,
        builder: &mut FunctionBuilder<'_>,
        op: IntrinsicOp,
        lane_ty: Type,
        d: Option<Value>,
        a: Value,
        b: Option<Value>,
        shift: u32,
    ) -> Result<Value, JitError> {
        let missing = JitError::UnsupportedStmt("lane intrinsic operand");
        let zero = self.zero_for_type(builder, lane_ty)?;
        let ones = self.all_ones(builder, lane_ty)?;
        let compare = |builder: &mut FunctionBuilder<'_>, cc: IntCC, lhs: Value, rhs: Value| {
            let cond = builder.ins().icmp(cc, lhs, rhs);
            builder.ins().select(cond, ones, zero)
        };
        let pick = |builder: &mut FunctionBuilder<'_>, cc: IntCC, lhs: Value, rhs: Value| {
            let cond = builder.ins().icmp(cc, lhs, rhs);
            builder.ins().select(cond, lhs, rhs)
        };
        let bits = lane_ty.bits();

        Ok(match op {
            IntrinsicOp::Mov | IntrinsicOp::Movi | IntrinsicOp::Dup => a,
            IntrinsicOp::Not | IntrinsicOp::Mvn | IntrinsicOp::Mvni => builder.ins().bnot(a),
            IntrinsicOp::Neg => builder.ins().ineg(a),
            IntrinsicOp::Abs => {
                let negated = builder.ins().ineg(a);
                let negative = builder.ins().icmp(IntCC::SignedLessThan, a, zero);
                builder.ins().select(negative, negated, a)
            }
            IntrinsicOp::Cnt => {
                if bits < 32 {
                    let wide = builder.ins().uextend(types::I32, a);
                    let count = builder.ins().popcnt(wide);
                    builder.ins().ireduce(lane_ty, count)
                } else {
                    builder.ins().popcnt(a)
                }
            }

            IntrinsicOp::Shl => {
                if shift >= bits {
                    zero
                } else {
                    builder.ins().ishl_imm(a, i64::from(shift))
                }
            }
            IntrinsicOp::Ushr => {
                if shift >= bits {
                    zero
                } else {
                    builder.ins().ushr_imm(a, i64::from(shift))
                }
            }
            IntrinsicOp::Sshr => builder.ins().sshr_imm(a, i64::from(shift.min(bits - 1))),

            _ => {
                let b = b.ok_or(missing)?;
                match op {
                    IntrinsicOp::And => builder.ins().band(a, b),
                    IntrinsicOp::Orr => builder.ins().bor(a, b),
                    IntrinsicOp::Eor => builder.ins().bxor(a, b),
                    IntrinsicOp::Bic => builder.ins().band_not(a, b),
                    IntrinsicOp::Orn => builder.ins().bor_not(a, b),
                    IntrinsicOp::Add => builder.ins().iadd(a, b),
                    IntrinsicOp::Sub => builder.ins().isub(a, b),
                    IntrinsicOp::Mul => builder.ins().imul(a, b),
                    IntrinsicOp::Cmeq => compare(builder, IntCC::Equal, a, b),
                    IntrinsicOp::Cmhi => compare(builder, IntCC::UnsignedGreaterThan, a, b),
                    IntrinsicOp::Cmhs => compare(builder, IntCC::UnsignedGreaterThanOrEqual, a, b),
                    IntrinsicOp::Cmgt => compare(builder, IntCC::SignedGreaterThan, a, b),
                    IntrinsicOp::Cmge => compare(builder, IntCC::SignedGreaterThanOrEqual, a, b),
                    IntrinsicOp::Umax => pick(builder, IntCC::UnsignedGreaterThan, a, b),
                    IntrinsicOp::Umin => pick(builder, IntCC::UnsignedLessThan, a, b),
                    IntrinsicOp::Smax => pick(builder, IntCC::SignedGreaterThan, a, b),
                    IntrinsicOp::Smin => pick(builder, IntCC::SignedLessThan, a, b),
                    IntrinsicOp::Fadd
                    | IntrinsicOp::Fsub
                    | IntrinsicOp::Fmul
                    | IntrinsicOp::Fdiv => {
                        let float_ty = match bits {
                            32 => types::F32,
                            64 => types::F64,
                            _ => return Err(JitError::UnsupportedStmt("float lane width")),
                        };
                        let fa = builder.ins().bitcast(float_ty, MemFlags::new(), a);
                        let fb = builder.ins().bitcast(float_ty, MemFlags::new(), b);
                        let result = match op {
                            IntrinsicOp::Fadd => builder.ins().fadd(fa, fb),
                            IntrinsicOp::Fsub => builder.ins().fsub(fa, fb),
                            IntrinsicOp::Fmul => builder.ins().fmul(fa, fb),
                            _ => builder.ins().fdiv(fa, fb),
                        };
                        let result = default_nan_if_generated(builder, result, fa, fb);
                        builder.ins().bitcast(lane_ty, MemFlags::new(), result)
                    }
                    _ => {
                        let d = d.ok_or(JitError::UnsupportedStmt("lane intrinsic"))?;
                        match op {
                            IntrinsicOp::Mla => {
                                let product = builder.ins().imul(a, b);
                                builder.ins().iadd(d, product)
                            }
                            IntrinsicOp::Mls => {
                                let product = builder.ins().imul(a, b);
                                builder.ins().isub(d, product)
                            }
                            // Bitwise selects: operands are `[dst, n, m]`.
                            IntrinsicOp::Bsl => builder.ins().bitselect(d, a, b),
                            IntrinsicOp::Bit => builder.ins().bitselect(b, a, d),
                            IntrinsicOp::Bif => builder.ins().bitselect(b, d, a),
                            _ => return Err(JitError::UnsupportedStmt("lane intrinsic")),
                        }
                    }
                }
            }
        })
    }

    /// `rev16`/`rev32`/`rev64`: reverses the order of the arrangement's
    /// elements inside each 16-, 32- or 64-bit container.
    pub(crate) fn lower_lane_reverse_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
        container_bits: u8,
    ) -> Result<(), JitError> {
        let [dst, src] = operands else {
            return Err(JitError::UnsupportedStmt("vector reverse operand count"));
        };
        let dst_index =
            simd_operand_index(dst).ok_or(JitError::UnsupportedStmt("vector reverse dest"))?;
        let src_index =
            simd_operand_index(src).ok_or(JitError::UnsupportedStmt("vector reverse source"))?;
        let arrangement = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("vector reverse arrangement"))?;
        let element_bits = arrangement.lane_bits;
        if element_bits >= container_bits {
            return Err(JitError::UnsupportedStmt("vector reverse arrangement"));
        }
        let layout = LaneLayout {
            lanes: arrangement.active_bytes() / (container_bits / 8),
            lane_bits: container_bits,
        };
        let lane_ty = layout.lane_ty()?;
        let vec_ty = layout.vec_ty()?;
        let source = self.read_full_vector(module, builder, imports, src_index, vec_ty)?;
        let elements = container_bits / element_bits;
        let mask = self.iconst(builder, lane_ty, (1u64 << element_bits) - 1)?;

        let mut out = self.zero_vector(builder, layout)?;
        for lane in 0..layout.lanes {
            let value = builder.ins().extractlane(source, lane);
            let reversed = if element_bits == 8 {
                builder.ins().bswap(value)
            } else {
                let mut acc = self.zero_for_type(builder, lane_ty)?;
                for element in 0..elements {
                    let from = i64::from(element * element_bits);
                    let to = i64::from((elements - 1 - element) * element_bits);
                    let part = builder.ins().ushr_imm(value, from);
                    let part = builder.ins().band(part, mask);
                    let part = builder.ins().ishl_imm(part, to);
                    acc = builder.ins().bor(acc, part);
                }
                acc
            };
            out = builder.ins().insertlane(out, reversed, lane);
        }
        self.write_full_vector(builder, dst_index, out, vec_ty)
    }
}

/// The registers of a `multi_reg` operand such as `{v0.16b, v1.16b}`.
fn register_list(expr: &Expr) -> Option<Vec<u8>> {
    let Expr::Intrinsic { name, operands } = expr else {
        return None;
    };
    if name.op() != IntrinsicOp::MultiReg || operands.is_empty() {
        return None;
    }
    operands.iter().map(simd_operand_index).collect()
}

impl LoweringState {
    pub(crate) fn lower_lane_widen_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        let spec = widen_spec(name.op()).ok_or(JitError::UnsupportedStmt("widening intrinsic"))?;
        if operands.len() < 2 {
            return Err(JitError::UnsupportedStmt("widening operand count"));
        }
        let dst_index =
            simd_operand_index(&operands[0]).ok_or(JitError::UnsupportedStmt("widening dest"))?;
        let src_index =
            simd_operand_index(&operands[1]).ok_or(JitError::UnsupportedStmt("widening source"))?;
        let arrangement = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("widening arrangement"))?;
        if arrangement.lane_bits < 16 || arrangement.active_bytes() != 16 {
            return Err(JitError::UnsupportedStmt("widening arrangement"));
        }
        let wide = LaneLayout {
            lanes: arrangement.lanes,
            lane_bits: arrangement.lane_bits,
        };
        let narrow = LaneLayout {
            lanes: wide.lanes * 2,
            lane_bits: wide.lane_bits / 2,
        };
        let wide_ty = wide.lane_ty()?;

        let old_dst = if matches!(spec.mode, WidenMode::MulAdd | WidenMode::MulSub) {
            Some(self.read_full_vector(module, builder, imports, dst_index, wide.vec_ty()?)?)
        } else {
            None
        };
        let source =
            self.read_full_vector(module, builder, imports, src_index, narrow.vec_ty()?)?;
        let mut shift = 0u32;
        let factor = if spec.mode == WidenMode::Shift {
            shift = match operands.get(2) {
                None => 0,
                Some(Expr::Imm(value)) => u32::try_from(*value)
                    .map_err(|_| JitError::UnsupportedStmt("vector shift amount"))?,
                Some(_) => return Err(JitError::UnsupportedStmt("vector shift amount")),
            };
            None
        } else {
            let operand = operands
                .get(2)
                .ok_or(JitError::UnsupportedStmt("widening operand count"))?;
            Some(self.lane_operand(module, builder, imports, operand, narrow)?)
        };

        let extend = |builder: &mut FunctionBuilder<'_>, value: Value| {
            if spec.signed {
                builder.ins().sextend(wide_ty, value)
            } else {
                builder.ins().uextend(wide_ty, value)
            }
        };
        let first = if spec.high { wide.lanes } else { 0 };
        let mut out = self.zero_vector(builder, wide)?;
        for lane in 0..wide.lanes {
            let value = builder.ins().extractlane(source, first + lane);
            let value = extend(builder, value);
            let value = match factor {
                None => {
                    if shift == 0 {
                        value
                    } else if shift >= wide_ty.bits() {
                        self.zero_for_type(builder, wide_ty)?
                    } else {
                        builder.ins().ishl_imm(value, i64::from(shift))
                    }
                }
                Some(factor) => {
                    let factor = match factor {
                        LaneOperand::Lanes(vec) => builder.ins().extractlane(vec, first + lane),
                        LaneOperand::Scalar(value) => value,
                    };
                    let factor = extend(builder, factor);
                    let product = builder.ins().imul(value, factor);
                    match (spec.mode, old_dst) {
                        (WidenMode::MulAdd, Some(old)) => {
                            let acc = builder.ins().extractlane(old, lane);
                            builder.ins().iadd(acc, product)
                        }
                        (WidenMode::MulSub, Some(old)) => {
                            let acc = builder.ins().extractlane(old, lane);
                            builder.ins().isub(acc, product)
                        }
                        _ => product,
                    }
                }
            };
            out = builder.ins().insertlane(out, value, lane);
        }
        self.write_full_vector(builder, dst_index, out, wide.vec_ty()?)
    }

    /// `xtn` writes the truncated lanes to the low half and clears the high
    /// half; `xtn2` writes them to the high half and keeps the low half.
    pub(crate) fn lower_lane_narrow_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
        high: bool,
    ) -> Result<(), JitError> {
        let [dst, src] = operands else {
            return Err(JitError::UnsupportedStmt("narrowing operand count"));
        };
        let dst_index =
            simd_operand_index(dst).ok_or(JitError::UnsupportedStmt("narrowing dest"))?;
        let src_index =
            simd_operand_index(src).ok_or(JitError::UnsupportedStmt("narrowing source"))?;
        let arrangement = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("narrowing arrangement"))?;
        if arrangement.lane_bits > 32 {
            return Err(JitError::UnsupportedStmt("narrowing arrangement"));
        }
        let count = 64 / arrangement.lane_bits;
        let narrow = LaneLayout {
            lanes: count * 2,
            lane_bits: arrangement.lane_bits,
        };
        let narrow_ty = narrow.lane_ty()?;
        let source = self.read_full_vector(
            module,
            builder,
            imports,
            src_index,
            full_vector_type(arrangement.lane_bits * 2)?,
        )?;
        let mut out = if high {
            self.read_full_vector(module, builder, imports, dst_index, narrow.vec_ty()?)?
        } else {
            self.zero_vector(builder, narrow)?
        };
        for lane in 0..count {
            let value = builder.ins().extractlane(source, lane);
            let value = builder.ins().ireduce(narrow_ty, value);
            out = builder
                .ins()
                .insertlane(out, value, lane + if high { count } else { 0 });
        }
        self.write_full_vector(builder, dst_index, out, narrow.vec_ty()?)
    }

    /// `zip`, `uzp`, `trn` and `ext`: every result lane is a fixed lane of
    /// one of the two sources.
    pub(crate) fn lower_lane_permute_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        let op = name.op();
        let expected = if op == IntrinsicOp::Ext { 4 } else { 3 };
        if operands.len() != expected {
            return Err(JitError::UnsupportedStmt("permute operand count"));
        }
        let index = |expr: &Expr| {
            simd_operand_index(expr).ok_or(JitError::UnsupportedStmt("permute operand"))
        };
        let dst_index = index(&operands[0])?;
        let arrangement = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("permute arrangement"))?;
        let layout = LaneLayout {
            lanes: arrangement.lanes,
            lane_bits: arrangement.lane_bits,
        };
        let vec_ty = layout.vec_ty()?;
        let imm = match operands.get(3) {
            None => 0,
            Some(Expr::Imm(value)) => {
                u8::try_from(*value).map_err(|_| JitError::UnsupportedStmt("ext offset"))?
            }
            Some(_) => return Err(JitError::UnsupportedStmt("ext offset")),
        };
        let first =
            self.read_full_vector(module, builder, imports, index(&operands[1])?, vec_ty)?;
        let second =
            self.read_full_vector(module, builder, imports, index(&operands[2])?, vec_ty)?;

        let mut out = self.zero_vector(builder, layout)?;
        for lane in 0..layout.lanes {
            let (from_second, source_lane) = permute_source(op, layout.lanes, lane, imm)
                .ok_or(JitError::UnsupportedStmt("permute lane"))?;
            let source = if from_second { second } else { first };
            let value = builder.ins().extractlane(source, source_lane);
            out = builder.ins().insertlane(out, value, lane);
        }
        self.write_full_vector(builder, dst_index, out, vec_ty)
    }

    /// `tbl`/`tbx`: each result byte is looked up in the table registers by
    /// the index byte. Out of range gives 0 (`tbl`) or keeps the destination
    /// byte (`tbx`).
    pub(crate) fn lower_table_lookup_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
        keep_out_of_range: bool,
    ) -> Result<(), JitError> {
        let [dst, table, indices] = operands else {
            return Err(JitError::UnsupportedStmt("table lookup operand count"));
        };
        let dst_index =
            simd_operand_index(dst).ok_or(JitError::UnsupportedStmt("table lookup dest"))?;
        let index_reg =
            simd_operand_index(indices).ok_or(JitError::UnsupportedStmt("table lookup index"))?;
        let table = register_list(table).ok_or(JitError::UnsupportedStmt("table lookup table"))?;
        let arrangement = name
            .arrangement()
            .filter(|arrangement| arrangement.lane_bits == 8)
            .ok_or(JitError::UnsupportedStmt("table lookup arrangement"))?;
        let layout = LaneLayout {
            lanes: arrangement.lanes,
            lane_bits: 8,
        };
        let table_bytes = u32::try_from(table.len() * 16)
            .map_err(|_| JitError::UnsupportedStmt("table lookup table"))?;

        let slot = builder.create_sized_stack_slot(StackSlotData::new(
            StackSlotKind::ExplicitSlot,
            table_bytes,
            4,
        ));
        for (position, reg) in table.iter().enumerate() {
            let value = self.read_full_vector(module, builder, imports, *reg, I8X16)?;
            builder
                .ins()
                .stack_store(value, slot, (position * 16) as i32);
        }
        let indices = self.read_full_vector(module, builder, imports, index_reg, I8X16)?;
        let old_dst = if keep_out_of_range {
            Some(self.read_full_vector(module, builder, imports, dst_index, I8X16)?)
        } else {
            None
        };
        let base = builder.ins().stack_addr(self.pointer_type, slot, 0);
        let zero = builder.ins().iconst(types::I8, 0);
        let limit = builder.ins().iconst(types::I64, i64::from(table_bytes));

        let mut out = self.zero_vector(builder, layout)?;
        for lane in 0..layout.lanes {
            let index = builder.ins().extractlane(indices, lane);
            let index = builder.ins().uextend(types::I64, index);
            let in_range = builder.ins().icmp(IntCC::UnsignedLessThan, index, limit);
            let zero_index = builder.ins().iconst(types::I64, 0);
            let safe_index = builder.ins().select(in_range, index, zero_index);
            let addr = builder.ins().iadd(base, safe_index);
            let byte = builder.ins().load(types::I8, MemFlags::trusted(), addr, 0);
            let fallback = match old_dst {
                Some(old) => builder.ins().extractlane(old, lane),
                None => zero,
            };
            let value = builder.ins().select(in_range, byte, fallback);
            out = builder.ins().insertlane(out, value, lane);
        }
        self.write_full_vector(builder, dst_index, out, I8X16)
    }

    /// Across-lanes reductions (`addv`, `umaxv`, `uaddlv`, scalar `addp`):
    /// the result is one value, written to a scalar SIMD register.
    pub(crate) fn lower_lane_reduce_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        let op = name.op();
        let [dst, src] = operands else {
            return Err(JitError::UnsupportedStmt("reduction operand count"));
        };
        let dst_index =
            simd_operand_index(dst).ok_or(JitError::UnsupportedStmt("reduction dest"))?;
        let src_index =
            simd_operand_index(src).ok_or(JitError::UnsupportedStmt("reduction source"))?;
        let arrangement = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("reduction arrangement"))?;
        let layout = LaneLayout {
            lanes: arrangement.lanes,
            lane_bits: arrangement.lane_bits,
        };
        let long = matches!(op, IntrinsicOp::Uaddlv | IntrinsicOp::Saddlv);
        let result_bits = if long {
            layout.lane_bits * 2
        } else {
            layout.lane_bits
        };
        if result_bits > 64 {
            return Err(JitError::UnsupportedStmt("reduction arrangement"));
        }
        let result_ty = vector_lane_type(result_bits)?;
        let source =
            self.read_full_vector(module, builder, imports, src_index, layout.vec_ty()?)?;

        let mut acc = None;
        for lane in 0..layout.lanes {
            let value = builder.ins().extractlane(source, lane);
            let value = match op {
                IntrinsicOp::Uaddlv => builder.ins().uextend(result_ty, value),
                IntrinsicOp::Saddlv => builder.ins().sextend(result_ty, value),
                _ => value,
            };
            acc = Some(match acc {
                None => value,
                Some(acc) => {
                    let pick = |builder: &mut FunctionBuilder<'_>, cc: IntCC| {
                        let cond = builder.ins().icmp(cc, acc, value);
                        builder.ins().select(cond, acc, value)
                    };
                    match op {
                        IntrinsicOp::Addv
                        | IntrinsicOp::Addp
                        | IntrinsicOp::Uaddlv
                        | IntrinsicOp::Saddlv => builder.ins().iadd(acc, value),
                        IntrinsicOp::Umaxv => pick(builder, IntCC::UnsignedGreaterThan),
                        IntrinsicOp::Uminv => pick(builder, IntCC::UnsignedLessThan),
                        IntrinsicOp::Smaxv => pick(builder, IntCC::SignedGreaterThan),
                        IntrinsicOp::Sminv => pick(builder, IntCC::SignedLessThan),
                        _ => return Err(JitError::UnsupportedStmt("reduction intrinsic")),
                    }
                }
            });
        }
        let acc = acc.ok_or(JitError::UnsupportedStmt("reduction arrangement"))?;
        let result_layout = LaneLayout {
            lanes: 1,
            lane_bits: result_bits,
        };
        let out = self.zero_vector(builder, result_layout)?;
        let out = builder.ins().insertlane(out, acc, 0);
        self.write_full_vector(builder, dst_index, out, result_layout.vec_ty()?)
    }

    /// Vector `addp`: adds adjacent lane pairs of the two sources, the
    /// first source filling the low half of the result.
    pub(crate) fn lower_lane_pairwise_add_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        if operands.len() == 2 {
            return self.lower_lane_reduce_intrinsic(module, builder, imports, name, operands);
        }
        let [dst, first, second] = operands else {
            return Err(JitError::UnsupportedStmt("addp operand count"));
        };
        let index =
            |expr: &Expr| simd_operand_index(expr).ok_or(JitError::UnsupportedStmt("addp operand"));
        let dst_index = index(dst)?;
        let arrangement = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("addp arrangement"))?;
        let layout = LaneLayout {
            lanes: arrangement.lanes,
            lane_bits: arrangement.lane_bits,
        };
        let vec_ty = layout.vec_ty()?;
        let first = self.read_full_vector(module, builder, imports, index(first)?, vec_ty)?;
        let second = self.read_full_vector(module, builder, imports, index(second)?, vec_ty)?;
        let half = layout.lanes / 2;
        let mut out = self.zero_vector(builder, layout)?;
        for lane in 0..layout.lanes {
            let source = if lane < half { first } else { second };
            let pair = 2 * (lane % half);
            let low = builder.ins().extractlane(source, pair);
            let high = builder.ins().extractlane(source, pair + 1);
            let sum = builder.ins().iadd(low, high);
            out = builder.ins().insertlane(out, sum, lane);
        }
        self.write_full_vector(builder, dst_index, out, vec_ty)
    }

    /// Adds the post-index operand of a SIMD load or store, if it has one,
    /// to its base register.
    pub(crate) fn lower_simd_writeback(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        let Some(post_index) = operands.get(2) else {
            return Ok(());
        };
        let base_reg = base_reg_operand(&operands[1])
            .ok_or(JitError::UnsupportedStmt("ld1/st1 post-index base"))?;
        let step = self.lower_expr(
            module,
            builder,
            imports,
            post_index,
            Some(self.pointer_type),
        )?;
        let step = self.coerce_int(builder, step, self.pointer_type)?;
        let current = self.read_reg(builder, &base_reg)?;
        let current = self.coerce_int(builder, current, self.pointer_type)?;
        let value = builder.ins().iadd(current.value, step.value);
        self.write_reg(
            builder,
            &base_reg,
            LoweredValue {
                value,
                ty: self.pointer_type,
            },
        )
    }

    /// `ld1`/`st1` with a register list: consecutive registers use
    /// consecutive memory.
    pub(crate) fn lower_ldst1_list_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
        is_load: bool,
    ) -> Result<(), JitError> {
        let registers = operands.first().and_then(register_list);
        let (Some(registers), Some(base)) = (registers, operands.get(1)) else {
            return Err(JitError::UnsupportedStmt("ld1/st1 register list"));
        };
        if registers.len() == 1 {
            return self
                .lower_ldst1_stmt_intrinsic(module, builder, imports, name, operands, is_load);
        }
        let arrangement = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("ld1/st1 arrangement"))?;
        let step = u64::from(arrangement.active_bytes());
        for (position, reg) in registers.iter().enumerate() {
            let one = [
                Expr::Intrinsic {
                    name: "multi_reg".into(),
                    operands: vec![Expr::Reg(Reg::V(*reg))],
                },
                Expr::Add(
                    Box::new(base.clone()),
                    Box::new(Expr::Imm(position as u64 * step)),
                ),
            ];
            self.lower_ldst1_stmt_intrinsic(module, builder, imports, name, &one, is_load)?;
        }
        self.lower_simd_writeback(module, builder, imports, operands)
    }

    /// `ld1r`: loads one element and replicates it into every lane.
    pub(crate) fn lower_ld1r_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        let registers = operands.first().and_then(register_list);
        let (Some(&[dst_index]), Some(base)) = (registers.as_deref(), operands.get(1)) else {
            return Err(JitError::UnsupportedStmt("ld1r register list"));
        };
        let arrangement = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("ld1r arrangement"))?;
        let layout = LaneLayout {
            lanes: arrangement.lanes,
            lane_bits: arrangement.lane_bits,
        };
        let lane_ty = layout.lane_ty()?;
        let load = Expr::Load {
            addr: Box::new(base.clone()),
            size: layout.lane_bits / 8,
        };
        let value = self.lower_expr(module, builder, imports, &load, Some(lane_ty))?;
        let value = self.coerce_int(builder, value, lane_ty)?;
        let mut out = self.zero_vector(builder, layout)?;
        for lane in 0..layout.lanes {
            out = builder.ins().insertlane(out, value.value, lane);
        }
        self.write_full_vector(builder, dst_index, out, layout.vec_ty()?)?;
        self.lower_simd_writeback(module, builder, imports, operands)
    }
}
