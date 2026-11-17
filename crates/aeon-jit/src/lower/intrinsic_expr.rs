use crate::imports::Imports;
use crate::lower::{LoweredValue, LoweringState};
use crate::{JitContext, JitError};
use aeonil::{Expr, IntrinsicName, IntrinsicOp};
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::immediates::Ieee64;
use cranelift_codegen::ir::types::{self, F64X2, I64X2, I8X16};
use cranelift_codegen::ir::{InstBuilder, MemFlags, Type, Value};
use cranelift_frontend::FunctionBuilder;
use cranelift_module::Module;
use std::mem::offset_of;

impl LoweringState {
    pub(crate) fn lower_mrs_read(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        name: &str,
        hint: Option<Type>,
    ) -> Result<LoweredValue, JitError> {
        let ty = self.resolve_int_type(hint, None)?;
        match name {
            "nzcv" => {
                // NZCV is stored as our flags field shifted to bits [31:28]
                let flags = self.read_flags(builder)?;
                let shifted = builder.ins().ishl_imm(flags, 28);
                let value = if ty != types::I64 {
                    builder.ins().ireduce(ty, shifted)
                } else {
                    shifted
                };
                Ok(LoweredValue { value, ty })
            }
            "tpidr_el0" => {
                // Load from JitContext.tpidr_el0
                let offset = offset_of!(JitContext, tpidr_el0) as i32;
                let value =
                    builder
                        .ins()
                        .load(types::I64, MemFlags::trusted(), self.ctx_ptr, offset);
                let value = if ty != types::I64 {
                    builder.ins().ireduce(ty, value)
                } else {
                    value
                };
                Ok(LoweredValue { value, ty })
            }
            // Unknown system registers return 0
            _ => Ok(LoweredValue {
                value: builder.ins().iconst(ty, 0),
                ty,
            }),
        }
    }

    pub(crate) fn lower_expr_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
        hint: Option<Type>,
    ) -> Result<LoweredValue, JitError> {
        match name.op() {
            IntrinsicOp::Scvtf | IntrinsicOp::Ucvtf | IntrinsicOp::Fcvtzs | IntrinsicOp::Fcvtzu => {
                self.lower_vector_conversion_intrinsic(module, builder, imports, name, operands)
            }
            // Bitwise vector operations (arrangement-independent)
            IntrinsicOp::And => {
                self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                    b.ins().band(a, c)
                })
            }
            IntrinsicOp::Orr => {
                self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                    b.ins().bor(a, c)
                })
            }
            IntrinsicOp::Eor => {
                self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                    b.ins().bxor(a, c)
                })
            }
            IntrinsicOp::Orn => {
                self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                    let not_c = b.ins().bnot(c);
                    b.ins().bor(a, not_c)
                })
            }
            IntrinsicOp::Bic => {
                self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                    let not_c = b.ins().bnot(c);
                    b.ins().band(a, not_c)
                })
            }
            IntrinsicOp::Bsl => {
                // BSL: bitselect - result = (op1 & mask) | (op2 & ~mask)
                // operands: [mask, op1, op2]
                if operands.len() < 3 {
                    return Err(JitError::UnsupportedExpr("bsl operand count"));
                }
                let mask = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
                let mask = self.coerce_value(builder, mask, I8X16)?;
                let op1 = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
                let op1 = self.coerce_value(builder, op1, I8X16)?;
                let op2 = self.lower_expr(module, builder, imports, &operands[2], Some(I8X16))?;
                let op2 = self.coerce_value(builder, op2, I8X16)?;
                Ok(LoweredValue {
                    value: builder.ins().bitselect(mask.value, op1.value, op2.value),
                    ty: I8X16,
                })
            }
            IntrinsicOp::Bit => {
                // BIT: dst = (src & mask) | (dst & ~mask)  (insert if bit set)
                // operands: [dst, src, mask]
                if operands.len() < 3 {
                    return Err(JitError::UnsupportedExpr("bit operand count"));
                }
                let dst = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
                let dst = self.coerce_value(builder, dst, I8X16)?;
                let src = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
                let src = self.coerce_value(builder, src, I8X16)?;
                let mask = self.lower_expr(module, builder, imports, &operands[2], Some(I8X16))?;
                let mask = self.coerce_value(builder, mask, I8X16)?;
                Ok(LoweredValue {
                    value: builder.ins().bitselect(mask.value, src.value, dst.value),
                    ty: I8X16,
                })
            }
            IntrinsicOp::Bif => {
                // BIF: dst = (dst & mask) | (src & ~mask)  (insert if bit clear)
                // operands: [dst, src, mask]
                if operands.len() < 3 {
                    return Err(JitError::UnsupportedExpr("bif operand count"));
                }
                let dst = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
                let dst = self.coerce_value(builder, dst, I8X16)?;
                let src = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
                let src = self.coerce_value(builder, src, I8X16)?;
                let mask = self.lower_expr(module, builder, imports, &operands[2], Some(I8X16))?;
                let mask = self.coerce_value(builder, mask, I8X16)?;
                // BIF is bitselect with inverted mask: select dst where mask=1, src where mask=0
                Ok(LoweredValue {
                    value: builder.ins().bitselect(mask.value, dst.value, src.value),
                    ty: I8X16,
                })
            }
            IntrinsicOp::Mvn | IntrinsicOp::Not => {
                if operands.is_empty() {
                    return Err(JitError::UnsupportedExpr("not operand count"));
                }
                let inner = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
                let inner = self.coerce_value(builder, inner, I8X16)?;
                Ok(LoweredValue {
                    value: builder.ins().bnot(inner.value),
                    ty: I8X16,
                })
            }
            // FP rounding intrinsics
            IntrinsicOp::Frintz => self.lower_float_rounding_intrinsic(
                module,
                builder,
                imports,
                operands,
                hint,
                |b, v| b.ins().trunc(v),
            ),
            IntrinsicOp::Frintm => self.lower_float_rounding_intrinsic(
                module,
                builder,
                imports,
                operands,
                hint,
                |b, v| b.ins().floor(v),
            ),
            IntrinsicOp::Frintp => self.lower_float_rounding_intrinsic(
                module,
                builder,
                imports,
                operands,
                hint,
                |b, v| b.ins().ceil(v),
            ),
            IntrinsicOp::Frintn | IntrinsicOp::Frinta | IntrinsicOp::Frintx => self
                .lower_float_rounding_intrinsic(
                    module,
                    builder,
                    imports,
                    operands,
                    hint,
                    |b, v| b.ins().nearest(v),
                ),
            // FNMADD: -(a*b) + c  →  fneg(fma(a, b, fneg(c)))
            // Actually: FNMADD rd, rn, rm, ra = -(rn*rm) - ra
            IntrinsicOp::Fnmadd => {
                if operands.len() < 3 {
                    return Err(JitError::UnsupportedExpr("fnmadd operand count"));
                }
                let ty = self.resolve_float_type(hint, None)?;
                let n = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                let n = self.coerce_float(builder, n, ty)?;
                let m = self.lower_expr(module, builder, imports, &operands[1], Some(ty))?;
                let m = self.coerce_float(builder, m, ty)?;
                let a = self.lower_expr(module, builder, imports, &operands[2], Some(ty))?;
                let a = self.coerce_float(builder, a, ty)?;
                // -(n*m) - a = fneg(fma(n, m, a))... actually just compute with basic ops
                let prod = builder.ins().fmul(n.value, m.value);
                let neg_prod = builder.ins().fneg(prod);
                Ok(LoweredValue {
                    value: builder.ins().fsub(neg_prod, a.value),
                    ty,
                })
            }
            // FNMSUB: (a*b) - c
            // Actually: FNMSUB rd, rn, rm, ra = rn*rm - ra
            IntrinsicOp::Fnmsub => {
                if operands.len() < 3 {
                    return Err(JitError::UnsupportedExpr("fnmsub operand count"));
                }
                let ty = self.resolve_float_type(hint, None)?;
                let n = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                let n = self.coerce_float(builder, n, ty)?;
                let m = self.lower_expr(module, builder, imports, &operands[1], Some(ty))?;
                let m = self.coerce_float(builder, m, ty)?;
                let a = self.lower_expr(module, builder, imports, &operands[2], Some(ty))?;
                let a = self.coerce_float(builder, a, ty)?;
                let prod = builder.ins().fmul(n.value, m.value);
                Ok(LoweredValue {
                    value: builder.ins().fsub(prod, a.value),
                    ty,
                })
            }
            // Byte reversal within halfwords/words
            IntrinsicOp::Rev16 => {
                // REV16: reverse bytes within each 16-bit halfword
                if operands.is_empty() {
                    return Err(JitError::UnsupportedExpr("rev16 operand count"));
                }
                let ty = self.resolve_int_type(hint, Some(&operands[0]))?;
                let inner = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                // Swap adjacent bytes: (x & 0x00FF00FF...) << 8 | (x & 0xFF00FF00...) >> 8
                let mask_lo = if ty == types::I32 {
                    0x00FF00FFu64
                } else {
                    0x00FF00FF00FF00FFu64
                };
                let mask_hi = if ty == types::I32 {
                    0xFF00FF00u64
                } else {
                    0xFF00FF00FF00FF00u64
                };
                let m_lo = self.iconst(builder, ty, mask_lo)?;
                let m_hi = self.iconst(builder, ty, mask_hi)?;
                let lo = builder.ins().band(inner.value, m_lo);
                let hi = builder.ins().band(inner.value, m_hi);
                let lo_shifted = builder.ins().ishl_imm(lo, 8);
                let hi_shifted = builder.ins().ushr_imm(hi, 8);
                Ok(LoweredValue {
                    value: builder.ins().bor(lo_shifted, hi_shifted),
                    ty,
                })
            }
            IntrinsicOp::Rev32 => {
                // REV32: reverse bytes within each 32-bit word (for 64-bit registers)
                if operands.is_empty() {
                    return Err(JitError::UnsupportedExpr("rev32 operand count"));
                }
                let ty = self.resolve_int_type(hint, Some(&operands[0]))?;
                let inner = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                if ty == types::I32 {
                    // For 32-bit, this is just bswap
                    Ok(LoweredValue {
                        value: builder.ins().bswap(inner.value),
                        ty,
                    })
                } else {
                    // For 64-bit: bswap each 32-bit half, then swap the halves back
                    let swapped = builder.ins().bswap(inner.value);
                    // bswap reverses all 8 bytes; we want to reverse within each 32-bit word
                    // So rotate by 32 to swap the two words back to original position
                    let thirty_two = builder.ins().iconst(ty, 32);
                    Ok(LoweredValue {
                        value: builder.ins().rotr(swapped, thirty_two),
                        ty,
                    })
                }
            }
            IntrinsicOp::Cnt => {
                // CNT: population count (count set bits)
                if operands.is_empty() {
                    return Err(JitError::UnsupportedExpr("cnt operand count"));
                }
                let ty = self.resolve_int_type(hint, Some(&operands[0]))?;
                let inner = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().popcnt(inner.value),
                    ty,
                })
            }
            IntrinsicOp::Ngc => {
                // NGC: negate with carry: Rd = 0 - Rm - !C
                // In the simplified form: Rd = -Rm - 1 + C
                if operands.is_empty() {
                    return Err(JitError::UnsupportedExpr("ngc operand count"));
                }
                let ty = self.resolve_int_type(hint, Some(&operands[0]))?;
                let inner = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                let inner = self.coerce_int(builder, inner, ty)?;
                let flags = self.read_flags(builder)?;
                let carry = self.extract_flag(builder, flags, 1);
                let carry_ext = builder.ins().uextend(ty, carry);
                let zero = builder.ins().iconst(ty, 0);
                let neg = builder.ins().isub(zero, inner.value);
                let minus_one = builder.ins().iconst(ty, -1i64);
                let neg_minus_not_carry = builder.ins().iadd(neg, minus_one);
                Ok(LoweredValue {
                    value: builder.ins().iadd(neg_minus_not_carry, carry_ext),
                    ty,
                })
            }
            // Carry arithmetic
            IntrinsicOp::Adc => {
                // ADC: Rd = Rn + Rm + C
                if operands.len() < 2 {
                    return Err(JitError::UnsupportedExpr("adc operand count"));
                }
                let ty = self.resolve_int_type(hint, Some(&operands[0]))?;
                let lhs = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.lower_expr(module, builder, imports, &operands[1], Some(ty))?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                let flags = self.read_flags(builder)?;
                let carry = self.extract_flag(builder, flags, 1);
                let carry_ext = builder.ins().uextend(ty, carry);
                let sum = builder.ins().iadd(lhs.value, rhs.value);
                Ok(LoweredValue {
                    value: builder.ins().iadd(sum, carry_ext),
                    ty,
                })
            }
            IntrinsicOp::Sbc => {
                // SBC: Rd = Rn - Rm - !C = Rn + ~Rm + C
                if operands.len() < 2 {
                    return Err(JitError::UnsupportedExpr("sbc operand count"));
                }
                let ty = self.resolve_int_type(hint, Some(&operands[0]))?;
                let lhs = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.lower_expr(module, builder, imports, &operands[1], Some(ty))?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                let flags = self.read_flags(builder)?;
                let carry = self.extract_flag(builder, flags, 1);
                let carry_ext = builder.ins().uextend(ty, carry);
                let not_rhs = builder.ins().bnot(rhs.value);
                let sum = builder.ins().iadd(lhs.value, not_rhs);
                Ok(LoweredValue {
                    value: builder.ins().iadd(sum, carry_ext),
                    ty,
                })
            }
            // Multiply high
            IntrinsicOp::Smulh => {
                // SMULH: Rd = (sext(Rn) * sext(Rm)) >> 64
                if operands.len() < 2 {
                    return Err(JitError::UnsupportedExpr("smulh operand count"));
                }
                let lhs =
                    self.lower_expr(module, builder, imports, &operands[0], Some(types::I64))?;
                let lhs = self.coerce_int(builder, lhs, types::I64)?;
                let rhs =
                    self.lower_expr(module, builder, imports, &operands[1], Some(types::I64))?;
                let rhs = self.coerce_int(builder, rhs, types::I64)?;
                // Cranelift doesn't have mulhi; emulate with 4 x 32-bit multiplies
                let value = self.emit_smulh(builder, lhs.value, rhs.value)?;
                Ok(LoweredValue {
                    value,
                    ty: types::I64,
                })
            }
            IntrinsicOp::Umulh => {
                // UMULH: Rd = (Rn * Rm) >> 64 (unsigned)
                if operands.len() < 2 {
                    return Err(JitError::UnsupportedExpr("umulh operand count"));
                }
                let lhs =
                    self.lower_expr(module, builder, imports, &operands[0], Some(types::I64))?;
                let lhs = self.coerce_int(builder, lhs, types::I64)?;
                let rhs =
                    self.lower_expr(module, builder, imports, &operands[1], Some(types::I64))?;
                let rhs = self.coerce_int(builder, rhs, types::I64)?;
                let value = self.emit_umulh(builder, lhs.value, rhs.value)?;
                Ok(LoweredValue {
                    value,
                    ty: types::I64,
                })
            }
            IntrinsicOp::Movk => {
                // MOVK: insert 16-bit immediate at a shifted position, keep other bits.
                // operands[0] = Expr::Reg(Rd) (current value)
                // operands[1] = shifted immediate (already has LSL applied)
                if operands.len() < 2 {
                    return Err(JitError::UnsupportedExpr("movk operand count"));
                }
                let ty = self.resolve_int_type(hint, Some(&operands[0]))?;
                let reg_val = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                let reg_val = self.coerce_int(builder, reg_val, ty)?;
                // Extract the shift amount from the expression tree
                let (imm_val, shift_amount) = match &operands[1] {
                    Expr::Shl(inner, shift) => {
                        let v = self.lower_expr(module, builder, imports, inner, Some(ty))?;
                        let v = self.coerce_int(builder, v, ty)?;
                        let shift_imm = match shift.as_ref() {
                            Expr::Imm(s) => *s as u8,
                            _ => 0,
                        };
                        (v, shift_imm)
                    }
                    _ => {
                        let v =
                            self.lower_expr(module, builder, imports, &operands[1], Some(ty))?;
                        let v = self.coerce_int(builder, v, ty)?;
                        (v, 0u8)
                    }
                };
                // mask = 0xFFFF << shift_amount
                let mask_val = 0xFFFFu64 << shift_amount;
                let mask = self.iconst(builder, ty, mask_val)?;
                let inv_mask = self.iconst(builder, ty, !mask_val)?;
                // Clear the 16-bit window, then insert the shifted immediate
                let cleared = builder.ins().band(reg_val.value, inv_mask);
                let shifted_imm = if shift_amount > 0 {
                    let shift = builder.ins().iconst(ty, i64::from(shift_amount));
                    builder.ins().ishl(imm_val.value, shift)
                } else {
                    imm_val.value
                };
                // Mask the shifted immediate to 16 bits at the right position
                let masked_imm = builder.ins().band(shifted_imm, mask);
                Ok(LoweredValue {
                    value: builder.ins().bor(cleared, masked_imm),
                    ty,
                })
            }
            _ => Err(JitError::UnsupportedExpr("expr intrinsic")),
        }
    }

    pub(crate) fn lower_simd_binop(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        operands: &[Expr],
        op: impl Fn(&mut FunctionBuilder<'_>, Value, Value) -> Value,
    ) -> Result<LoweredValue, JitError> {
        if operands.len() < 2 {
            return Err(JitError::UnsupportedExpr("simd binop operand count"));
        }
        let lhs = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
        let lhs = self.coerce_value(builder, lhs, I8X16)?;
        let rhs = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
        let rhs = self.coerce_value(builder, rhs, I8X16)?;
        Ok(LoweredValue {
            value: op(builder, lhs.value, rhs.value),
            ty: I8X16,
        })
    }

    pub(crate) fn lower_vector_conversion_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<LoweredValue, JitError> {
        if operands.is_empty() {
            return Err(JitError::UnsupportedExpr("vector conversion operand count"));
        }
        let arrangement = name
            .suffix()
            .ok_or(JitError::UnsupportedExpr("vector conversion arrangement"))?;
        let src = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
        let src = self.coerce_value(builder, src, I8X16)?;

        match (name.op(), arrangement) {
            (IntrinsicOp::Scvtf, "2d") => {
                let ints = self.bitcast_value(builder, I64X2, src.value, src.ty);
                let zero = builder.ins().f64const(Ieee64::with_float(0.0));
                let mut floats = builder.ins().splat(F64X2, zero);
                for lane in 0..2 {
                    let value = builder.ins().extractlane(ints, lane);
                    let value = builder.ins().fcvt_from_sint(types::F64, value);
                    floats = builder.ins().insertlane(floats, value, lane);
                }
                Ok(LoweredValue {
                    value: self.bitcast_value(builder, I8X16, floats, F64X2),
                    ty: I8X16,
                })
            }
            (IntrinsicOp::Ucvtf, "2d") => {
                let ints = self.bitcast_value(builder, I64X2, src.value, src.ty);
                let zero = builder.ins().f64const(Ieee64::with_float(0.0));
                let mut floats = builder.ins().splat(F64X2, zero);
                for lane in 0..2 {
                    let value = builder.ins().extractlane(ints, lane);
                    let value = builder.ins().fcvt_from_uint(types::F64, value);
                    floats = builder.ins().insertlane(floats, value, lane);
                }
                Ok(LoweredValue {
                    value: self.bitcast_value(builder, I8X16, floats, F64X2),
                    ty: I8X16,
                })
            }
            (IntrinsicOp::Fcvtzs, "2d") => {
                let floats = self.bitcast_value(builder, F64X2, src.value, src.ty);
                let zero = builder.ins().iconst(types::I64, 0);
                let mut ints = builder.ins().splat(I64X2, zero);
                for lane in 0..2 {
                    let value = builder.ins().extractlane(floats, lane);
                    let value = builder.ins().fcvt_to_sint(types::I64, value);
                    ints = builder.ins().insertlane(ints, value, lane);
                }
                Ok(LoweredValue {
                    value: self.bitcast_value(builder, I8X16, ints, I64X2),
                    ty: I8X16,
                })
            }
            (IntrinsicOp::Fcvtzu, "2d") => {
                let floats = self.bitcast_value(builder, F64X2, src.value, src.ty);
                let zero = builder.ins().iconst(types::I64, 0);
                let mut ints = builder.ins().splat(I64X2, zero);
                for lane in 0..2 {
                    let value = builder.ins().extractlane(floats, lane);
                    let value = builder.ins().fcvt_to_uint(types::I64, value);
                    ints = builder.ins().insertlane(ints, value, lane);
                }
                Ok(LoweredValue {
                    value: self.bitcast_value(builder, I8X16, ints, I64X2),
                    ty: I8X16,
                })
            }
            _ => Err(JitError::UnsupportedExpr("vector conversion arrangement")),
        }
    }

    pub(crate) fn lower_float_rounding_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        operands: &[Expr],
        hint: Option<Type>,
        op: impl Fn(&mut FunctionBuilder<'_>, Value) -> Value,
    ) -> Result<LoweredValue, JitError> {
        if operands.is_empty() {
            return Err(JitError::UnsupportedExpr("float rounding operand count"));
        }
        let ty = self.resolve_float_type(hint, Some(&operands[0]))?;
        let inner = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
        let inner = self.coerce_float(builder, inner, ty)?;
        Ok(LoweredValue {
            value: op(builder, inner.value),
            ty,
        })
    }

    /// Emit unsigned 64×64→128 multiply, return upper 64 bits.
    /// Uses the identity: (a_hi*2^32 + a_lo) * (b_hi*2^32 + b_lo)
    ///   = a_hi*b_hi*2^64 + (a_hi*b_lo + a_lo*b_hi)*2^32 + a_lo*b_lo
    /// Carefully tracks carries in the middle terms to avoid overflow.
    pub(crate) fn emit_umulh(
        &self,
        builder: &mut FunctionBuilder<'_>,
        a: Value,
        b: Value,
    ) -> Result<Value, JitError> {
        let mask32 = builder.ins().iconst(types::I64, 0xFFFF_FFFF_i64);
        let a_lo = builder.ins().band(a, mask32);
        let a_hi = builder.ins().ushr_imm(a, 32);
        let b_lo = builder.ins().band(b, mask32);
        let b_hi = builder.ins().ushr_imm(b, 32);

        // Four partial products (each fits in 64 bits since inputs are 32-bit)
        let lo_lo = builder.ins().imul(a_lo, b_lo);
        let lo_hi = builder.ins().imul(a_lo, b_hi);
        let hi_lo = builder.ins().imul(a_hi, b_lo);
        let hi_hi = builder.ins().imul(a_hi, b_hi);

        // Add the middle terms carefully to detect carry.
        // mid1 = lo_hi + (lo_lo >> 32) — cannot overflow since both ≤ 2^63
        let lo_lo_upper = builder.ins().ushr_imm(lo_lo, 32);
        let mid1 = builder.ins().iadd(lo_hi, lo_lo_upper);
        // mid1_carry = mid1 >> 32 (upper bits from first mid accumulation)
        let mid1_lo = builder.ins().band(mid1, mask32);

        // mid2 = mid1_lo + hi_lo — cannot overflow since both ≤ 2^32 * (2^32-1)
        let mid2 = builder.ins().iadd(mid1_lo, hi_lo);

        // result_hi = hi_hi + (mid1 >> 32) + (mid2 >> 32)
        let mid1_hi = builder.ins().ushr_imm(mid1, 32);
        let mid2_hi = builder.ins().ushr_imm(mid2, 32);
        let result = builder.ins().iadd(hi_hi, mid1_hi);
        Ok(builder.ins().iadd(result, mid2_hi))
    }

    /// Emit signed 64×64→128 multiply, return upper 64 bits.
    /// Uses umulh and adjusts: smulh(a,b) = umulh(a,b) - (a<0?b:0) - (b<0?a:0)
    pub(crate) fn emit_smulh(
        &self,
        builder: &mut FunctionBuilder<'_>,
        a: Value,
        b: Value,
    ) -> Result<Value, JitError> {
        let umulh = self.emit_umulh(builder, a, b)?;

        // Correction for signed: if a is negative, subtract b; if b is negative, subtract a
        let zero = builder.ins().iconst(types::I64, 0);
        let a_neg = builder.ins().icmp(IntCC::SignedLessThan, a, zero);
        let b_neg = builder.ins().icmp(IntCC::SignedLessThan, b, zero);
        let a_adj = builder.ins().select(a_neg, b, zero);
        let b_adj = builder.ins().select(b_neg, a, zero);
        let adjusted = builder.ins().isub(umulh, a_adj);
        Ok(builder.ins().isub(adjusted, b_adj))
    }
}
