use crate::imports::Imports;
use crate::lower::{LoweredValue, LoweringState};
use crate::JitError;
use aeonil::Expr;
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::immediates::{Ieee32, Ieee64};
use cranelift_codegen::ir::types::{self, I16X8, I32X4, I64X2, I8X16};
use cranelift_codegen::ir::{InstBuilder, MemFlags, Type, Value};
use cranelift_frontend::FunctionBuilder;
use cranelift_module::Module;

impl LoweringState {
    pub(crate) fn lower_expr(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        expr: &Expr,
        hint: Option<Type>,
    ) -> Result<LoweredValue, JitError> {
        match expr {
            Expr::Reg(reg) => self.read_reg(builder, reg),
            Expr::Imm(value) | Expr::AdrpImm(value) | Expr::AdrImm(value) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                Ok(LoweredValue {
                    value: self.iconst(builder, ty, *value)?,
                    ty,
                })
            }
            Expr::FImm(value) => {
                let ty = self.resolve_float_type(hint, Some(expr))?;
                let value = match ty {
                    types::F32 => builder.ins().f32const(Ieee32::with_float(*value as f32)),
                    types::F64 => builder.ins().f64const(Ieee64::with_float(*value)),
                    _ => return Err(JitError::UnsupportedExpr("fimm")),
                };
                Ok(LoweredValue { value, ty })
            }
            Expr::Load { addr, size } => {
                let load_ty = self.load_type(*size, hint)?;
                let addr =
                    self.lower_expr(module, builder, imports, addr, Some(self.pointer_type))?;
                let addr = self.coerce_int(builder, addr, self.pointer_type)?;
                if let Some(callback) = imports.memory_read {
                    if imports.memory_read_addr_only {
                        builder.ins().call(callback, &[addr.value]);
                    } else {
                        let size = builder.ins().iconst(types::I8, i64::from(*size));
                        builder.ins().call(callback, &[addr.value, size]);
                    }
                }
                let value = builder.ins().load(load_ty, MemFlags::new(), addr.value, 0);
                Ok(LoweredValue { value, ty: load_ty })
            }
            Expr::Add(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().iadd(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::Sub(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().isub(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::Mul(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().imul(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::Div(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                // AArch64 SDIV never traps: x / 0 is 0 and MIN / -1 is MIN.
                // Divide by 1 in both cases so the host instruction cannot
                // fault, then zero the result for the divide-by-zero case.
                let by_zero = builder.ins().icmp_imm(IntCC::Equal, rhs.value, 0);
                let by_minus_one = builder.ins().icmp_imm(IntCC::Equal, rhs.value, -1);
                let min = builder.ins().iconst(ty, i64::MIN >> (64 - ty.bits()));
                let lhs_is_min = builder.ins().icmp(IntCC::Equal, lhs.value, min);
                let overflows = builder.ins().band(by_minus_one, lhs_is_min);
                let unsafe_divisor = builder.ins().bor(by_zero, overflows);
                let one = builder.ins().iconst(ty, 1);
                let divisor = builder.ins().select(unsafe_divisor, one, rhs.value);
                let quotient = builder.ins().sdiv(lhs.value, divisor);
                let zero = builder.ins().iconst(ty, 0);
                Ok(LoweredValue {
                    value: builder.ins().select(by_zero, zero, quotient),
                    ty,
                })
            }
            Expr::UDiv(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                // AArch64 UDIV never traps: x / 0 is 0.
                let by_zero = builder.ins().icmp_imm(IntCC::Equal, rhs.value, 0);
                let one = builder.ins().iconst(ty, 1);
                let divisor = builder.ins().select(by_zero, one, rhs.value);
                let quotient = builder.ins().udiv(lhs.value, divisor);
                let zero = builder.ins().iconst(ty, 0);
                Ok(LoweredValue {
                    value: builder.ins().select(by_zero, zero, quotient),
                    ty,
                })
            }
            Expr::Neg(inner) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let inner = self.lower_expr(module, builder, imports, inner, Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                let zero = self.zero_for_type(builder, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().isub(zero, inner.value),
                    ty,
                })
            }
            Expr::Abs(inner) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let inner = self.lower_expr(module, builder, imports, inner, Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                let zero = self.zero_for_type(builder, ty)?;
                let is_neg = builder.ins().icmp(IntCC::SignedLessThan, inner.value, zero);
                let neg = builder.ins().isub(zero, inner.value);
                Ok(LoweredValue {
                    value: builder.ins().select(is_neg, neg, inner.value),
                    ty,
                })
            }
            Expr::And(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().band(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::Or(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().bor(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::Xor(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().bxor(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::Not(inner) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let inner = self.lower_expr(module, builder, imports, inner, Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                let ones = self.all_ones(builder, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().bxor(inner.value, ones),
                    ty,
                })
            }
            Expr::Shl(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().ishl(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::Lsr(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().ushr(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::Asr(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().sshr(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::Ror(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().rotr(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::SignExtend { src, from_bits } => {
                let target = self.resolve_int_type(hint, Some(expr))?;
                let source = self.lower_expr(module, builder, imports, src, Some(target))?;
                let source = self.coerce_int(builder, source, target)?;
                let bits = target.bits();
                if *from_bits == 0 || u32::from(*from_bits) >= bits {
                    return Ok(source);
                }
                let shift = builder
                    .ins()
                    .iconst(target, i64::from(bits as u8 - *from_bits));
                let shl = builder.ins().ishl(source.value, shift);
                Ok(LoweredValue {
                    value: builder.ins().sshr(shl, shift),
                    ty: target,
                })
            }
            Expr::ZeroExtend { src, from_bits } => {
                let target = self.resolve_int_type(hint, Some(expr))?;
                let source = self.lower_expr(module, builder, imports, src, Some(target))?;
                let source = self.coerce_int(builder, source, target)?;
                let mask = self.mask_for_width(builder, target, *from_bits)?;
                Ok(LoweredValue {
                    value: builder.ins().band(source.value, mask),
                    ty: target,
                })
            }
            Expr::Extract { src, lsb, width } => {
                let target = self.resolve_int_type(hint, Some(expr))?;
                let source_ty = self.infer_expr_type(src);
                if matches!(source_ty, Some(ty) if ty.is_vector()) {
                    let source = self.lower_expr(module, builder, imports, src, Some(I8X16))?;
                    let source = self.coerce_value(builder, source, I8X16)?;
                    let (lanes, lane_type, lane_index) = match *width {
                        8 => (source.value, types::I8, usize::from(*lsb / 8)),
                        16 => (
                            self.bitcast_value(builder, I16X8, source.value, source.ty),
                            types::I16,
                            usize::from(*lsb / 16),
                        ),
                        32 => (
                            self.bitcast_value(builder, I32X4, source.value, source.ty),
                            types::I32,
                            usize::from(*lsb / 32),
                        ),
                        64 => (
                            self.bitcast_value(builder, I64X2, source.value, source.ty),
                            types::I64,
                            usize::from(*lsb / 64),
                        ),
                        _ => return Err(JitError::UnsupportedExpr("vector extract width")),
                    };
                    if *lsb % *width != 0 {
                        return Err(JitError::UnsupportedExpr("vector extract alignment"));
                    }
                    let lane_index = u8::try_from(lane_index)
                        .map_err(|_| JitError::UnsupportedExpr("vector extract lane index"))?;
                    let value = builder.ins().extractlane(lanes, lane_index);
                    let lowered = LoweredValue {
                        value,
                        ty: lane_type,
                    };
                    Ok(self.coerce_int(builder, lowered, target)?)
                } else {
                    let source = self.lower_expr(module, builder, imports, src, Some(target))?;
                    let source = self.coerce_int(builder, source, target)?;
                    let shift = builder.ins().iconst(target, i64::from(*lsb));
                    let shifted = builder.ins().ushr(source.value, shift);
                    let mask = self.mask_for_width(builder, target, *width)?;
                    Ok(LoweredValue {
                        value: builder.ins().band(shifted, mask),
                        ty: target,
                    })
                }
            }
            Expr::Insert {
                dst,
                src,
                lsb,
                width,
            } => {
                let target = self.resolve_int_type(hint, Some(expr))?;
                let dst = self.lower_expr(module, builder, imports, dst, Some(target))?;
                let src = self.lower_expr(module, builder, imports, src, Some(target))?;
                let dst = self.coerce_int(builder, dst, target)?;
                let src = self.coerce_int(builder, src, target)?;
                let width_mask = self.mask_for_width(builder, target, *width)?;
                let shift = builder.ins().iconst(target, i64::from(*lsb));
                let mask = builder.ins().ishl(width_mask, shift);
                let all_ones = self.all_ones(builder, target)?;
                let inv_mask = builder.ins().bxor(mask, all_ones);
                let cleared = builder.ins().band(dst.value, inv_mask);
                let inserted_src = builder.ins().band(src.value, width_mask);
                let shifted_src = builder.ins().ishl(inserted_src, shift);
                let masked_shifted = builder.ins().band(shifted_src, mask);
                Ok(LoweredValue {
                    value: builder.ins().bor(cleared, masked_shifted),
                    ty: target,
                })
            }
            Expr::FAdd(lhs, rhs) => {
                self.lower_float_binop(module, builder, imports, lhs, rhs, hint, |b, a, c| {
                    let result = b.ins().fadd(a, c);
                    default_nan_if_generated(b, result, a, c)
                })
            }
            Expr::FSub(lhs, rhs) => {
                self.lower_float_binop(module, builder, imports, lhs, rhs, hint, |b, a, c| {
                    let result = b.ins().fsub(a, c);
                    default_nan_if_generated(b, result, a, c)
                })
            }
            Expr::FMul(lhs, rhs) => {
                self.lower_float_binop(module, builder, imports, lhs, rhs, hint, |b, a, c| {
                    let result = b.ins().fmul(a, c);
                    default_nan_if_generated(b, result, a, c)
                })
            }
            Expr::FDiv(lhs, rhs) => {
                self.lower_float_binop(module, builder, imports, lhs, rhs, hint, |b, a, c| {
                    let result = b.ins().fdiv(a, c);
                    default_nan_if_generated(b, result, a, c)
                })
            }
            Expr::FNeg(inner) => {
                self.lower_float_unop(module, builder, imports, inner, hint, |b, v| {
                    b.ins().fneg(v)
                })
            }
            Expr::FAbs(inner) => {
                self.lower_float_unop(module, builder, imports, inner, hint, |b, v| {
                    b.ins().fabs(v)
                })
            }
            Expr::FSqrt(inner) => {
                self.lower_float_unop(module, builder, imports, inner, hint, |b, v| {
                    let result = b.ins().sqrt(v);
                    default_nan_if_generated(b, result, v, v)
                })
            }
            Expr::FMax(lhs, rhs) => {
                self.lower_float_binop(module, builder, imports, lhs, rhs, hint, |b, a, c| {
                    b.ins().fmax(a, c)
                })
            }
            Expr::FMin(lhs, rhs) => {
                self.lower_float_binop(module, builder, imports, lhs, rhs, hint, |b, a, c| {
                    b.ins().fmin(a, c)
                })
            }
            Expr::FCvt(inner) => {
                let inner = self.lower_expr(module, builder, imports, inner, None)?;
                let target = self.resolve_float_type(hint, Some(expr))?;
                let value = if inner.ty == target {
                    inner.value
                } else if inner.ty == types::F32 && target == types::F64 {
                    builder.ins().fpromote(types::F64, inner.value)
                } else if inner.ty == types::F64 && target == types::F32 {
                    builder.ins().fdemote(types::F32, inner.value)
                } else {
                    return Err(JitError::UnsupportedExpr("fcvt"));
                };
                Ok(LoweredValue { value, ty: target })
            }
            Expr::IntToFloat(inner) => {
                let target = self.resolve_float_type(hint, Some(expr))?;
                let source_ty = self.resolve_int_type(None, Some(inner))?;
                let inner = self.lower_expr(module, builder, imports, inner, Some(source_ty))?;
                let inner = self.coerce_int(builder, inner, source_ty)?;
                Ok(LoweredValue {
                    value: builder.ins().fcvt_from_sint(target, inner.value),
                    ty: target,
                })
            }
            Expr::FloatToInt(inner) => {
                let target = self.resolve_int_type(hint, Some(expr))?;
                let source_ty = self.resolve_float_type(None, Some(inner))?;
                let inner = self.lower_expr(module, builder, imports, inner, Some(source_ty))?;
                let inner = self.coerce_float(builder, inner, source_ty)?;
                Ok(LoweredValue {
                    // FCVTZS saturates and maps NaN to 0; it never traps.
                    value: builder.ins().fcvt_to_sint_sat(target, inner.value),
                    ty: target,
                })
            }
            Expr::CondSelect {
                cond,
                if_true,
                if_false,
            } => {
                let target =
                    self.resolve_value_type(hint, Some(if_true), Some(if_false), Some(expr))?;
                let flags = self.read_flags(builder)?;
                let cond = self.eval_flags_condition(builder, flags, *cond)?;
                let if_true = self.lower_expr(module, builder, imports, if_true, Some(target))?;
                let if_false = self.lower_expr(module, builder, imports, if_false, Some(target))?;
                let if_true = self.coerce_value(builder, if_true, target)?;
                let if_false = self.coerce_value(builder, if_false, target)?;
                Ok(LoweredValue {
                    value: builder.ins().select(cond, if_true.value, if_false.value),
                    ty: target,
                })
            }
            Expr::Compare { cond, lhs, rhs } => {
                let bool_value =
                    self.lower_compare_condition(module, builder, imports, *cond, lhs, rhs)?;
                let target = self.resolve_int_type(hint, Some(expr))?;
                Ok(LoweredValue {
                    value: builder.ins().uextend(target, bool_value),
                    ty: target,
                })
            }
            Expr::Clz(inner) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let inner = self.lower_expr(module, builder, imports, inner, Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().clz(inner.value),
                    ty,
                })
            }
            Expr::Cls(inner) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let inner = self.lower_expr(module, builder, imports, inner, Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                let bits = ty.bits();
                let sign_shift = builder.ins().iconst(ty, i64::from(bits as i16 - 1));
                let sign = builder.ins().sshr(inner.value, sign_shift);
                let folded = builder.ins().bxor(inner.value, sign);
                let clz = builder.ins().clz(folded);
                let one = builder.ins().iconst(ty, 1);
                Ok(LoweredValue {
                    value: builder.ins().isub(clz, one),
                    ty,
                })
            }
            Expr::Rev(inner) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let inner = self.lower_expr(module, builder, imports, inner, Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                let value = if ty == types::I8 {
                    inner.value
                } else {
                    builder.ins().bswap(inner.value)
                };
                Ok(LoweredValue { value, ty })
            }
            Expr::Rbit(inner) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let inner = self.lower_expr(module, builder, imports, inner, Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                Ok(LoweredValue {
                    value: self.reverse_bits(builder, inner.value, ty)?,
                    ty,
                })
            }
            Expr::StackSlot { offset, .. } => {
                let sp = self.read_sp(builder)?;
                let offset = builder.ins().iconst(types::I64, *offset);
                Ok(LoweredValue {
                    value: builder.ins().iadd(sp, offset),
                    ty: types::I64,
                })
            }
            Expr::MrsRead(name) => self.lower_mrs_read(builder, name, hint),
            Expr::Intrinsic { name, operands } => {
                self.lower_expr_intrinsic(module, builder, imports, name, operands, hint)
            }
        }
    }

    pub(crate) fn lower_float_binop(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        lhs: &Expr,
        rhs: &Expr,
        hint: Option<Type>,
        op: impl Fn(&mut FunctionBuilder<'_>, Value, Value) -> Value,
    ) -> Result<LoweredValue, JitError> {
        let ty = self.resolve_float_type(
            hint.filter(|ty| ty.is_float())
                .or_else(|| self.infer_expr_type(lhs))
                .or_else(|| self.infer_expr_type(rhs))
                .filter(|ty| ty.is_float()),
            None,
        )?;
        let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
        let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
        let lhs = self.coerce_float(builder, lhs, ty)?;
        let rhs = self.coerce_float(builder, rhs, ty)?;
        Ok(LoweredValue {
            value: op(builder, lhs.value, rhs.value),
            ty,
        })
    }

    pub(crate) fn lower_float_unop(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        inner: &Expr,
        hint: Option<Type>,
        op: impl Fn(&mut FunctionBuilder<'_>, Value) -> Value,
    ) -> Result<LoweredValue, JitError> {
        let ty = self.resolve_float_type(
            hint.filter(|ty| ty.is_float())
                .or_else(|| self.infer_expr_type(inner))
                .filter(|ty| ty.is_float()),
            None,
        )?;
        let inner = self.lower_expr(module, builder, imports, inner, Some(ty))?;
        let inner = self.coerce_float(builder, inner, ty)?;
        Ok(LoweredValue {
            value: op(builder, inner.value),
            ty,
        })
    }
}

/// AArch64 returns the default NaN (sign clear) when an operation on non-NaN
/// inputs is invalid, such as `0.0 / 0.0`. The host may set the sign bit, so
/// replace a NaN that did not come from an operand.
fn default_nan_if_generated(
    builder: &mut FunctionBuilder<'_>,
    result: Value,
    lhs: Value,
    rhs: Value,
) -> Value {
    let ty = builder.func.dfg.value_type(result);
    let result_is_nan = builder.ins().fcmp(FloatCC::Unordered, result, result);
    let inputs_ordered = builder.ins().fcmp(FloatCC::Ordered, lhs, rhs);
    let generated = builder.ins().band(result_is_nan, inputs_ordered);
    let default_nan = if ty == types::F32 {
        builder.ins().f32const(Ieee32::with_bits(0x7fc0_0000))
    } else {
        builder
            .ins()
            .f64const(Ieee64::with_bits(0x7ff8_0000_0000_0000))
    };
    builder.ins().select(generated, default_nan, result)
}
