use crate::lower::{
    int_type_for_bits, reg_type, type_for_memory_size, type_size_bytes, LoweredValue, LoweringState,
};
use crate::JitError;
use aeonil::{Condition, Expr};
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::immediates::{Ieee32, Ieee64};
use cranelift_codegen::ir::types::{self, I8X16};
use cranelift_codegen::ir::{Endianness, InstBuilder, MemFlags, Type, Value};
use cranelift_frontend::FunctionBuilder;

impl LoweringState {
    pub(crate) fn resolve_value_type(
        &self,
        hint: Option<Type>,
        a: Option<&Expr>,
        b: Option<&Expr>,
        expr: Option<&Expr>,
    ) -> Result<Type, JitError> {
        if let Some(hint) = hint {
            return Ok(hint);
        }
        if let Some(expr) = expr {
            if let Some(ty) = self.infer_expr_type(expr) {
                return Ok(ty);
            }
        }
        if let Some(expr) = a {
            if let Some(ty) = self.infer_expr_type(expr) {
                return Ok(ty);
            }
        }
        if let Some(expr) = b {
            if let Some(ty) = self.infer_expr_type(expr) {
                return Ok(ty);
            }
        }
        Ok(types::I64)
    }

    pub(crate) fn resolve_int_type(
        &self,
        hint: Option<Type>,
        expr: Option<&Expr>,
    ) -> Result<Type, JitError> {
        if let Some(hint) = hint {
            if hint.is_int() {
                return Ok(hint);
            }
        }
        if let Some(expr) = expr {
            if let Some(ty) = self.infer_expr_type(expr) {
                if ty.is_int() {
                    return Ok(ty);
                }
            }
        }
        Ok(types::I64)
    }

    pub(crate) fn resolve_float_type(
        &self,
        hint: Option<Type>,
        expr: Option<&Expr>,
    ) -> Result<Type, JitError> {
        if let Some(hint) = hint {
            if hint.is_float() {
                return Ok(hint);
            }
        }
        if let Some(expr) = expr {
            if let Some(ty) = self.infer_expr_type(expr) {
                if ty.is_float() {
                    return Ok(ty);
                }
            }
        }
        Ok(types::F64)
    }

    pub(crate) fn infer_expr_type(&self, expr: &Expr) -> Option<Type> {
        match expr {
            Expr::Reg(reg) => reg_type(reg).ok(),
            Expr::Imm(_) | Expr::AdrpImm(_) | Expr::AdrImm(_) | Expr::StackSlot { .. } => {
                Some(types::I64)
            }
            Expr::Imm32(_) => Some(types::I32),
            Expr::FImm(_) => Some(types::F64),
            Expr::Load { size, .. } => type_for_memory_size(*size).ok(),
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
            | Expr::Ror(lhs, rhs) => {
                // An immediate has no width of its own, so `0 - w1` is a
                // 32-bit operation: let the other operand decide.
                let untyped =
                    |expr: &Expr| matches!(expr, Expr::Imm(_) | Expr::AdrpImm(_) | Expr::AdrImm(_));
                let typed = if untyped(lhs) && !untyped(rhs) {
                    self.infer_expr_type(rhs)
                } else {
                    self.infer_expr_type(lhs)
                        .or_else(|| self.infer_expr_type(rhs))
                };
                typed.or(Some(types::I64))
            }
            Expr::Neg(inner)
            | Expr::Abs(inner)
            | Expr::Not(inner)
            | Expr::Clz(inner)
            | Expr::Cls(inner)
            | Expr::Rev(inner)
            | Expr::Rbit(inner) => self.infer_expr_type(inner).or(Some(types::I64)),
            // Sign/zero-extend always widen: a SignExtend{W(n), 32} inside a
            // widening multiply must infer as I64 so the multiply produces 64
            // bits.  If the source is already 64-bit the extend is a no-op, so
            // returning I64 is safe in all cases.
            Expr::SignExtend { .. } | Expr::ZeroExtend { .. } => Some(types::I64),
            Expr::Extract { width, .. } => int_type_for_bits(u16::from(*width)),
            Expr::Insert { dst, .. } => self.infer_expr_type(dst),
            Expr::FAdd(lhs, rhs)
            | Expr::FSub(lhs, rhs)
            | Expr::FMul(lhs, rhs)
            | Expr::FDiv(lhs, rhs)
            | Expr::FMax(lhs, rhs)
            | Expr::FMin(lhs, rhs) => {
                let lhs = self.infer_expr_type(lhs);
                let rhs = self.infer_expr_type(rhs);
                lhs.filter(|ty| ty.is_float())
                    .or_else(|| rhs.filter(|ty| ty.is_float()))
                    .or(Some(types::F64))
            }
            Expr::FNeg(inner) | Expr::FAbs(inner) | Expr::FSqrt(inner) | Expr::FCvt(inner) => self
                .infer_expr_type(inner)
                .filter(|ty| ty.is_float())
                .or(Some(types::F64)),
            Expr::IntToFloat(_) => Some(types::F64),
            Expr::FloatToInt(_) => Some(types::I64),
            Expr::CondSelect {
                if_true, if_false, ..
            } => self
                .infer_expr_type(if_true)
                .or_else(|| self.infer_expr_type(if_false)),
            Expr::Compare { .. } => Some(types::I64),
            Expr::MrsRead(_) | Expr::Intrinsic { .. } => None,
        }
    }

    pub(crate) fn load_type(&self, size: u8, hint: Option<Type>) -> Result<Type, JitError> {
        if let Some(hint) = hint {
            if type_size_bytes(hint) == usize::from(size) && (hint.is_float() || hint.is_vector()) {
                return Ok(hint);
            }
        }
        type_for_memory_size(size)
    }

    pub(crate) fn store_type_for_value(&self, value: &Expr, size: u8) -> Result<Type, JitError> {
        match self.infer_expr_type(value) {
            Some(ty)
                if (ty.is_float() || ty.is_vector())
                    && type_size_bytes(ty) == usize::from(size) =>
            {
                Ok(ty)
            }
            _ => type_for_memory_size(size),
        }
    }

    pub(crate) fn coerce_value(
        &self,
        builder: &mut FunctionBuilder<'_>,
        value: LoweredValue,
        target: Type,
    ) -> Result<LoweredValue, JitError> {
        if value.ty == target {
            return Ok(value);
        }
        if target.is_int() {
            self.coerce_int(builder, value, target)
        } else if target.is_float() {
            self.coerce_float(builder, value, target)
        } else if target.is_vector() && value.ty.is_vector() && value.ty.bits() == target.bits() {
            Ok(LoweredValue {
                value: self.bitcast_value(builder, target, value.value, value.ty),
                ty: target,
            })
        } else {
            Err(JitError::TypeMismatch("value coercion"))
        }
    }

    pub(crate) fn coerce_int(
        &self,
        builder: &mut FunctionBuilder<'_>,
        value: LoweredValue,
        target: Type,
    ) -> Result<LoweredValue, JitError> {
        if value.ty == target {
            return Ok(value);
        }
        if !target.is_int() {
            return Err(JitError::TypeMismatch("integer coercion target"));
        }
        let result = if value.ty.is_int() {
            if value.ty.bits() > target.bits() {
                builder.ins().ireduce(target, value.value)
            } else if value.ty.bits() < target.bits() {
                builder.ins().uextend(target, value.value)
            } else {
                value.value
            }
        } else if value.ty.is_float() && value.ty.bits() == target.bits() {
            self.bitcast_value(builder, target, value.value, value.ty)
        } else {
            return Err(JitError::TypeMismatch("integer coercion source"));
        };
        Ok(LoweredValue {
            value: result,
            ty: target,
        })
    }

    pub(crate) fn coerce_float(
        &self,
        builder: &mut FunctionBuilder<'_>,
        value: LoweredValue,
        target: Type,
    ) -> Result<LoweredValue, JitError> {
        if value.ty == target {
            return Ok(value);
        }
        if !target.is_float() {
            return Err(JitError::TypeMismatch("float coercion target"));
        }
        let result = if value.ty.is_float() {
            if value.ty == types::F32 && target == types::F64 {
                builder.ins().fpromote(target, value.value)
            } else if value.ty == types::F64 && target == types::F32 {
                builder.ins().fdemote(target, value.value)
            } else {
                return Err(JitError::TypeMismatch("float width conversion"));
            }
        } else if value.ty.is_int() {
            let bits_ty = int_type_for_bits(target.bits().try_into().unwrap())
                .ok_or(JitError::TypeMismatch("float bits source"))?;
            let int_value = if value.ty.bits() > target.bits() {
                builder.ins().ireduce(bits_ty, value.value)
            } else if value.ty.bits() < target.bits() {
                builder.ins().uextend(bits_ty, value.value)
            } else {
                value.value
            };
            self.bitcast_value(builder, target, int_value, bits_ty)
        } else {
            return Err(JitError::TypeMismatch("float coercion source"));
        };
        Ok(LoweredValue {
            value: result,
            ty: target,
        })
    }

    pub(crate) fn value_as_u64_bits(
        &self,
        builder: &mut FunctionBuilder<'_>,
        value: LoweredValue,
    ) -> Result<Value, JitError> {
        if value.ty.is_int() {
            return Ok(self.coerce_int(builder, value, types::I64)?.value);
        }
        if value.ty.is_float() {
            let bits_ty = int_type_for_bits(value.ty.bits().try_into().unwrap())
                .ok_or(JitError::TypeMismatch("float bits"))?;
            let bits = self.bitcast_value(builder, bits_ty, value.value, value.ty);
            return Ok(if bits_ty == types::I64 {
                bits
            } else {
                builder.ins().uextend(types::I64, bits)
            });
        }
        if value.ty == I8X16 {
            let i64x2 = self.bitcast_value(builder, types::I64X2, value.value, value.ty);
            return Ok(builder.ins().extractlane(i64x2, 0));
        }
        Err(JitError::TypeMismatch("instrumentation value"))
    }

    pub(crate) fn saturate_signed_value(
        &self,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
        bits: u8,
    ) -> Result<Value, JitError> {
        let ty = builder.func.dfg.value_type(value);
        if ty != types::I64 {
            return Err(JitError::TypeMismatch("signed saturation source"));
        }
        let max = (1i64 << (bits - 1)) - 1;
        let min = -(1i64 << (bits - 1));
        let max_val = builder.ins().iconst(types::I64, max);
        let min_val = builder.ins().iconst(types::I64, min);
        let above = builder.ins().icmp(IntCC::SignedGreaterThan, value, max_val);
        let below = builder.ins().icmp(IntCC::SignedLessThan, value, min_val);
        let clamped_hi = builder.ins().select(above, max_val, value);
        Ok(builder.ins().select(below, min_val, clamped_hi))
    }

    pub(crate) fn saturate_unsigned_value(
        &self,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
        bits: u8,
    ) -> Result<Value, JitError> {
        let ty = builder.func.dfg.value_type(value);
        if ty != types::I64 {
            return Err(JitError::TypeMismatch("unsigned saturation source"));
        }
        let max = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let max_val = self.iconst(builder, types::I64, max)?;
        let above = builder
            .ins()
            .icmp(IntCC::UnsignedGreaterThan, value, max_val);
        Ok(builder.ins().select(above, max_val, value))
    }

    pub(crate) fn bitcast_value(
        &self,
        builder: &mut FunctionBuilder<'_>,
        target: Type,
        value: Value,
        source: Type,
    ) -> Value {
        let needs_explicit_endian = source != target
            && source.bits() == target.bits()
            && (source.is_vector() || target.is_vector());
        let flags = if needs_explicit_endian {
            MemFlags::new().with_endianness(Endianness::Little)
        } else {
            MemFlags::new()
        };
        builder.ins().bitcast(target, flags, value)
    }

    pub(crate) fn zero_for_type(
        &self,
        builder: &mut FunctionBuilder<'_>,
        ty: Type,
    ) -> Result<Value, JitError> {
        if ty.is_int() {
            Ok(builder.ins().iconst(ty, 0))
        } else if ty == types::F32 {
            Ok(builder.ins().f32const(Ieee32::with_float(0.0)))
        } else if ty == types::F64 {
            Ok(builder.ins().f64const(Ieee64::with_float(0.0)))
        } else {
            Err(JitError::TypeMismatch("zero"))
        }
    }

    pub(crate) fn all_ones(
        &self,
        builder: &mut FunctionBuilder<'_>,
        ty: Type,
    ) -> Result<Value, JitError> {
        if !ty.is_int() {
            return Err(JitError::TypeMismatch("all ones"));
        }
        Ok(builder.ins().iconst(ty, -1))
    }

    pub(crate) fn iconst(
        &self,
        builder: &mut FunctionBuilder<'_>,
        ty: Type,
        value: u64,
    ) -> Result<Value, JitError> {
        if !ty.is_int() {
            return Err(JitError::TypeMismatch("iconst"));
        }
        let bits = ty.bits();
        let masked = if bits >= 64 {
            value
        } else if bits == 0 {
            0
        } else {
            value & ((1u64 << bits) - 1)
        };
        Ok(builder.ins().iconst(ty, masked as i64))
    }

    pub(crate) fn mask_for_width(
        &self,
        builder: &mut FunctionBuilder<'_>,
        ty: Type,
        width: u8,
    ) -> Result<Value, JitError> {
        if !ty.is_int() {
            return Err(JitError::TypeMismatch("mask width"));
        }
        let bits = ty.bits();
        let mask = if width == 0 {
            0
        } else if u32::from(width) >= bits {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        self.iconst(builder, ty, mask)
    }

    pub(crate) fn mask_for_bit(
        &self,
        builder: &mut FunctionBuilder<'_>,
        ty: Type,
        bit: u8,
    ) -> Result<Value, JitError> {
        if !ty.is_int() {
            return Err(JitError::TypeMismatch("bit mask"));
        }
        let mask = if u32::from(bit) >= ty.bits() {
            0
        } else {
            1u64 << bit
        };
        self.iconst(builder, ty, mask)
    }

    pub(crate) fn extract_flag(
        &self,
        builder: &mut FunctionBuilder<'_>,
        flags: Value,
        bit: u8,
    ) -> Value {
        let shifted = builder.ins().ushr_imm(flags, i64::from(bit));
        let masked = builder.ins().band_imm(shifted, 1);
        builder.ins().ireduce(types::I8, masked)
    }

    pub(crate) fn is_negative(
        &self,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
        ty: Type,
    ) -> Result<Value, JitError> {
        let zero = self.zero_for_type(builder, ty)?;
        Ok(builder.ins().icmp(IntCC::SignedLessThan, value, zero))
    }

    pub(crate) fn reverse_bits(
        &self,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
        ty: Type,
    ) -> Result<Value, JitError> {
        if !ty.is_int() || ty.bits() > 64 {
            return Err(JitError::UnsupportedExpr("rbit"));
        }
        let mut x = value;
        for (shift, mask) in [
            (1u8, 0x5555_5555_5555_5555u64),
            (2, 0x3333_3333_3333_3333),
            (4, 0x0f0f_0f0f_0f0f_0f0f),
            (8, 0x00ff_00ff_00ff_00ff),
            (16, 0x0000_ffff_0000_ffff),
            (32, 0x0000_0000_ffff_ffff),
        ] {
            if ty.bits() <= u32::from(shift) {
                break;
            }
            let mask = self.iconst(builder, ty, mask)?;
            let banded = builder.ins().band(x, mask);
            let left = builder.ins().ishl_imm(banded, i64::from(shift));
            let shifted = builder.ins().ushr_imm(x, i64::from(shift));
            let right = builder.ins().band(shifted, mask);
            x = builder.ins().bor(left, right);
        }
        Ok(x)
    }

    pub(crate) fn int_cc(&self, cond: Condition) -> Option<IntCC> {
        Some(match cond {
            Condition::EQ => IntCC::Equal,
            Condition::NE => IntCC::NotEqual,
            Condition::CS => IntCC::UnsignedGreaterThanOrEqual,
            Condition::CC => IntCC::UnsignedLessThan,
            Condition::HI => IntCC::UnsignedGreaterThan,
            Condition::LS => IntCC::UnsignedLessThanOrEqual,
            Condition::GE => IntCC::SignedGreaterThanOrEqual,
            Condition::LT => IntCC::SignedLessThan,
            Condition::GT => IntCC::SignedGreaterThan,
            Condition::LE => IntCC::SignedLessThanOrEqual,
            Condition::AL => return None,
            Condition::NV => return None,
            Condition::MI | Condition::PL | Condition::VS | Condition::VC => return None,
        })
    }

    pub(crate) fn float_cc(&self, cond: Condition) -> Result<FloatCC, JitError> {
        match cond {
            Condition::EQ => Ok(FloatCC::Equal),
            Condition::NE => Ok(FloatCC::NotEqual),
            Condition::GE => Ok(FloatCC::GreaterThanOrEqual),
            // After an AArch64 FP compare, LT and LE also hold when the
            // operands are unordered.
            Condition::LT => Ok(FloatCC::UnorderedOrLessThan),
            Condition::GT => Ok(FloatCC::GreaterThan),
            Condition::LE => Ok(FloatCC::UnorderedOrLessThanOrEqual),
            _ => Err(JitError::UnsupportedCondition(cond)),
        }
    }

    pub(crate) fn condition_from_u8(&self, val: u8) -> Result<Condition, JitError> {
        match val {
            0 => Ok(Condition::EQ),
            1 => Ok(Condition::NE),
            2 => Ok(Condition::CS),
            3 => Ok(Condition::CC),
            4 => Ok(Condition::MI),
            5 => Ok(Condition::PL),
            6 => Ok(Condition::VS),
            7 => Ok(Condition::VC),
            8 => Ok(Condition::HI),
            9 => Ok(Condition::LS),
            10 => Ok(Condition::GE),
            11 => Ok(Condition::LT),
            12 => Ok(Condition::GT),
            13 => Ok(Condition::LE),
            14 => Ok(Condition::AL),
            15 => Ok(Condition::NV),
            _ => Err(JitError::UnsupportedCondition(Condition::AL)),
        }
    }
}
