use crate::imports::Imports;
use crate::lower::{reg_type, LoweredValue, LoweringState, VectorShiftKind};
use crate::JitError;
use aeonil::{Expr, IntrinsicName, IntrinsicOp, Reg};
use cranelift_codegen::ir::types::{self};
use cranelift_codegen::ir::{InstBuilder, MemFlags, Value};
use cranelift_frontend::FunctionBuilder;
use cranelift_module::Module;

impl LoweringState {
    pub(crate) fn lower_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        match name.op() {
            IntrinsicOp::Nop
            | IntrinsicOp::Yield
            | IntrinsicOp::Hint
            | IntrinsicOp::Paciasp
            | IntrinsicOp::Autiasp
            | IntrinsicOp::Bti
            | IntrinsicOp::Xpaclri
            | IntrinsicOp::Prfm
            | IntrinsicOp::Prfum
            | IntrinsicOp::Clrex => Ok(()),
            IntrinsicOp::Ushr => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Ushr,
            ),
            IntrinsicOp::Urshr => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Urshr,
            ),
            IntrinsicOp::Usra => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Usra,
            ),
            IntrinsicOp::Ursra => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Ursra,
            ),
            IntrinsicOp::Sli => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Sli,
            ),
            IntrinsicOp::Sri => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Sri,
            ),
            IntrinsicOp::Sqshlu => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Sqshlu,
            ),
            IntrinsicOp::Uqshl => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Uqshl,
            ),
            IntrinsicOp::Uxtl => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Uxtl,
            ),
            IntrinsicOp::Ushll2 => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Ushll2,
            ),
            IntrinsicOp::Ld1 => {
                self.lower_ldst1_stmt_intrinsic(module, builder, imports, name, operands, true)
            }
            IntrinsicOp::St1 => {
                self.lower_ldst1_stmt_intrinsic(module, builder, imports, name, operands, false)
            }
            IntrinsicOp::Movi => {
                self.lower_vector_immediate_stmt_intrinsic(builder, name, operands, false)
            }
            IntrinsicOp::Mvni => {
                self.lower_vector_immediate_stmt_intrinsic(builder, name, operands, true)
            }
            IntrinsicOp::Uqrshrn2 => {
                self.lower_uqrshrn2_stmt_intrinsic(module, builder, imports, name, operands)
            }
            IntrinsicOp::Fcmla => {
                self.lower_fcmla_stmt_intrinsic(module, builder, imports, name, operands)
            }
            IntrinsicOp::Fmulx => {
                self.lower_fmulx_stmt_intrinsic(module, builder, imports, name, operands)
            }
            IntrinsicOp::Sqrdmlah => {
                self.lower_sqrdmlx_stmt_intrinsic(module, builder, imports, name, operands, false)
            }
            IntrinsicOp::Sqrdmlsh => {
                self.lower_sqrdmlx_stmt_intrinsic(module, builder, imports, name, operands, true)
            }
            IntrinsicOp::Mla => {
                self.lower_vector_mul_acc_intrinsic(module, builder, imports, name, operands, false)
            }
            IntrinsicOp::Mls => {
                self.lower_vector_mul_acc_intrinsic(module, builder, imports, name, operands, true)
            }
            IntrinsicOp::Umull2 => {
                self.lower_widening_lane_mul_intrinsic(module, builder, imports, operands, false)
            }
            IntrinsicOp::Umlal2 => self.lower_widening_lane_mul_acc_intrinsic(
                module, builder, imports, operands, false, false,
            ),
            IntrinsicOp::Umlsl2 => self.lower_widening_lane_mul_acc_intrinsic(
                module, builder, imports, operands, false, true,
            ),
            IntrinsicOp::Smull2 => {
                self.lower_widening_lane_mul_intrinsic(module, builder, imports, operands, true)
            }
            IntrinsicOp::Msr => {
                // MSR nzcv, Xn  →  write flags from register
                // operands: [sysreg_intrinsic, value_expr]
                if operands.len() >= 2 {
                    if let Expr::Intrinsic {
                        name: ref sr_name, ..
                    } = operands[0]
                    {
                        if sr_name == "nzcv" {
                            let value = self.lower_expr(
                                module,
                                builder,
                                imports,
                                &operands[1],
                                Some(types::I64),
                            )?;
                            let value = self.coerce_int(builder, value, types::I64)?;
                            // Extract NZCV from bits [31:28]
                            let shifted = builder.ins().ushr_imm(value.value, 28);
                            let masked = builder.ins().band_imm(shifted, 0xF);
                            self.write_flags_value(builder, masked)?;
                            return Ok(());
                        }
                    }
                }
                Err(JitError::UnsupportedStmt("msr target"))
            }
            IntrinsicOp::Fccmp | IntrinsicOp::Fccmpe => {
                // FCCMP Sn, Sm, #nzcv, cond → if cond then flags=fcmp(Sn,Sm) else flags=nzcv
                // operands: [Sn, Sm, nzcv_imm, cond_imm]
                if operands.len() >= 4 {
                    let nzcv_imm = match &operands[2] {
                        Expr::Imm(v) => *v,
                        _ => 0,
                    };
                    let cond_val = match &operands[3] {
                        Expr::Imm(v) => *v as u8,
                        _ => return Err(JitError::UnsupportedStmt("fccmp cond")),
                    };
                    let cond = self.condition_from_u8(cond_val)?;
                    let flags = self.read_flags(builder)?;
                    let cond_true = self.eval_flags_condition(builder, flags, cond)?;

                    // Compute fcmp flags
                    let ty = self.resolve_float_type(None, Some(&operands[0]))?;
                    let a = self.lower_expr(module, builder, imports, &operands[0], Some(ty))?;
                    let a = self.coerce_float(builder, a, ty)?;
                    let b = self.lower_expr(module, builder, imports, &operands[1], Some(ty))?;
                    let b = self.coerce_float(builder, b, ty)?;
                    // Compute SUB-style flags from float comparison
                    let fsub_result = builder.ins().fsub(a.value, b.value);
                    let result_bits = if ty == types::F32 {
                        let bits = builder
                            .ins()
                            .bitcast(types::I32, MemFlags::new(), fsub_result);
                        builder.ins().uextend(types::I64, bits)
                    } else {
                        builder
                            .ins()
                            .bitcast(types::I64, MemFlags::new(), fsub_result)
                    };
                    let fcmp_flags =
                        self.pack_nzcv(builder, result_bits, types::I64, None, None)?;

                    // Select: if condition, use fcmp flags; else use immediate nzcv
                    let imm_flags = builder.ins().iconst(types::I64, nzcv_imm as i64);
                    let selected = builder.ins().select(cond_true, fcmp_flags, imm_flags);
                    self.write_flags_value(builder, selected)?;
                    return Ok(());
                }
                Err(JitError::UnsupportedStmt("fccmp operand count"))
            }
            // Bitfield operations: lift_intrinsic_all passes all operands
            // including destination, so operands[0] is the dest register.
            IntrinsicOp::Ubfx => {
                // UBFX Rd, Rn, #lsb, #width → Rd = (Rn >> lsb) & mask(width)
                self.lower_bitfield_stmt(
                    module,
                    builder,
                    imports,
                    operands,
                    |this, b, src, lsb, width| {
                        let ty = b.func.dfg.value_type(src);
                        let shift = b.ins().iconst(ty, i64::from(lsb));
                        let shifted = b.ins().ushr(src, shift);
                        let mask = this.mask_for_width(b, ty, width)?;
                        Ok(b.ins().band(shifted, mask))
                    },
                )
            }
            IntrinsicOp::Ubfiz => {
                // UBFIZ Rd, Rn, #lsb, #width → Rd = (Rn & mask(width)) << lsb
                self.lower_bitfield_stmt(
                    module,
                    builder,
                    imports,
                    operands,
                    |this, b, src, lsb, width| {
                        let ty = b.func.dfg.value_type(src);
                        let mask = this.mask_for_width(b, ty, width)?;
                        let masked = b.ins().band(src, mask);
                        let shift = b.ins().iconst(ty, i64::from(lsb));
                        Ok(b.ins().ishl(masked, shift))
                    },
                )
            }
            IntrinsicOp::Sbfx => {
                // SBFX Rd, Rn, #lsb, #width → Rd = sign_extend((Rn >> lsb)[width-1:0])
                self.lower_bitfield_stmt(
                    module,
                    builder,
                    imports,
                    operands,
                    |_this, b, src, lsb, width| {
                        let ty = b.func.dfg.value_type(src);
                        let bits = ty.bits() as u8;
                        let shift_right = b.ins().iconst(ty, i64::from(lsb));
                        let shifted = b.ins().ushr(src, shift_right);
                        // Sign-extend from `width` bits using shift-left then arithmetic-shift-right
                        let sext_shift = b.ins().iconst(ty, i64::from(bits - width));
                        let shl = b.ins().ishl(shifted, sext_shift);
                        Ok(b.ins().sshr(shl, sext_shift))
                    },
                )
            }
            IntrinsicOp::Sbfiz => {
                // SBFIZ Rd, Rn, #lsb, #width → Rd = sign_extend(Rn[width-1:0]) << lsb
                self.lower_bitfield_stmt(
                    module,
                    builder,
                    imports,
                    operands,
                    |_this, b, src, lsb, width| {
                        let ty = b.func.dfg.value_type(src);
                        let bits = ty.bits() as u8;
                        // Sign-extend from width bits
                        let sext_shift = b.ins().iconst(ty, i64::from(bits - width));
                        let shl = b.ins().ishl(src, sext_shift);
                        let sext = b.ins().sshr(shl, sext_shift);
                        let shift = b.ins().iconst(ty, i64::from(lsb));
                        Ok(b.ins().ishl(sext, shift))
                    },
                )
            }
            IntrinsicOp::Bfi => {
                // BFI Rd, Rn, #lsb, #width → Rd[lsb+width-1:lsb] = Rn[width-1:0]
                // This reads the current Rd and inserts bits from Rn
                if operands.len() < 4 {
                    return Err(JitError::UnsupportedStmt("bfi operand count"));
                }
                let (dst_reg, dst_val, src_val, lsb, width) =
                    self.extract_bitfield_operands(module, builder, imports, operands)?;
                let ty = builder.func.dfg.value_type(dst_val);
                let width_mask = self.mask_for_width(builder, ty, width)?;
                let shift = builder.ins().iconst(ty, i64::from(lsb));
                let field_mask = builder.ins().ishl(width_mask, shift);
                let all_ones = self.all_ones(builder, ty)?;
                let inv_mask = builder.ins().bxor(field_mask, all_ones);
                let cleared = builder.ins().band(dst_val, inv_mask);
                let src_masked = builder.ins().band(src_val, width_mask);
                let src_shifted = builder.ins().ishl(src_masked, shift);
                let result = builder.ins().bor(cleared, src_shifted);
                let result_ty = builder.func.dfg.value_type(result);
                self.write_reg(
                    builder,
                    &dst_reg,
                    LoweredValue {
                        value: result,
                        ty: result_ty,
                    },
                )
            }
            IntrinsicOp::Bfxil => {
                // BFXIL Rd, Rn, #lsb, #width → Rd[width-1:0] = Rn[lsb+width-1:lsb]
                if operands.len() < 4 {
                    return Err(JitError::UnsupportedStmt("bfxil operand count"));
                }
                let (dst_reg, dst_val, src_val, lsb, width) =
                    self.extract_bitfield_operands(module, builder, imports, operands)?;
                let ty = builder.func.dfg.value_type(dst_val);
                let width_mask = self.mask_for_width(builder, ty, width)?;
                let shift = builder.ins().iconst(ty, i64::from(lsb));
                let extracted = builder.ins().ushr(src_val, shift);
                let src_masked = builder.ins().band(extracted, width_mask);
                let all_ones = self.all_ones(builder, ty)?;
                let inv_mask = builder.ins().bxor(width_mask, all_ones);
                let cleared = builder.ins().band(dst_val, inv_mask);
                let result = builder.ins().bor(cleared, src_masked);
                let result_ty = builder.func.dfg.value_type(result);
                self.write_reg(
                    builder,
                    &dst_reg,
                    LoweredValue {
                        value: result,
                        ty: result_ty,
                    },
                )
            }
            IntrinsicOp::Extr => {
                // EXTR Rd, Rn, Rm, #shift → Rd = (Rn:Rm >> shift)[reg_size-1:0]
                if operands.len() < 4 {
                    return Err(JitError::UnsupportedStmt("extr operand count"));
                }
                let dst_reg = match &operands[0] {
                    Expr::Reg(r) => r.clone(),
                    _ => return Err(JitError::UnsupportedStmt("extr dest")),
                };
                let hint = Some(reg_type(&dst_reg)?);
                let ty = self.resolve_int_type(hint, None)?;
                let hi = self.lower_expr(module, builder, imports, &operands[1], Some(ty))?;
                let hi = self.coerce_int(builder, hi, ty)?;
                let lo = self.lower_expr(module, builder, imports, &operands[2], Some(ty))?;
                let lo = self.coerce_int(builder, lo, ty)?;
                let shift_amt = match &operands[3] {
                    Expr::Imm(v) => *v as u8,
                    _ => return Err(JitError::UnsupportedStmt("extr shift")),
                };
                let bits = ty.bits() as u8;
                let result = if shift_amt == 0 {
                    lo.value
                } else {
                    // (hi << (bits - shift)) | (lo >> shift)
                    let hi_shift = builder.ins().iconst(ty, i64::from(bits - shift_amt));
                    let lo_shift = builder.ins().iconst(ty, i64::from(shift_amt));
                    let hi_part = builder.ins().ishl(hi.value, hi_shift);
                    let lo_part = builder.ins().ushr(lo.value, lo_shift);
                    builder.ins().bor(hi_part, lo_part)
                };
                self.write_reg(builder, &dst_reg, LoweredValue { value: result, ty })
            }
            _ => Err(JitError::UnsupportedStmt("stmt intrinsic")),
        }
    }

    pub(crate) fn extract_bitfield_operands(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        operands: &[Expr],
    ) -> Result<(Reg, Value, Value, u8, u8), JitError> {
        let dst_reg = match &operands[0] {
            Expr::Reg(r) => r.clone(),
            _ => return Err(JitError::UnsupportedStmt("bitfield dest")),
        };
        let hint = Some(reg_type(&dst_reg)?);
        let dst_val = self.lower_expr(module, builder, imports, &operands[0], hint)?;
        let src_val = self.lower_expr(module, builder, imports, &operands[1], hint)?;
        let ty = self.resolve_int_type(hint, None)?;
        let dst_val = self.coerce_int(builder, dst_val, ty)?;
        let src_val = self.coerce_int(builder, src_val, ty)?;
        let lsb = match &operands[2] {
            Expr::Imm(v) => *v as u8,
            _ => return Err(JitError::UnsupportedStmt("bitfield lsb")),
        };
        let width = match &operands[3] {
            Expr::Imm(v) => *v as u8,
            _ => return Err(JitError::UnsupportedStmt("bitfield width")),
        };
        Ok((dst_reg, dst_val.value, src_val.value, lsb, width))
    }

    pub(crate) fn lower_bitfield_stmt(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        operands: &[Expr],
        compute: impl FnOnce(
            &mut Self,
            &mut FunctionBuilder<'_>,
            Value,
            u8,
            u8,
        ) -> Result<Value, JitError>,
    ) -> Result<(), JitError> {
        if operands.len() < 4 {
            return Err(JitError::UnsupportedStmt("bitfield operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(r) => r.clone(),
            _ => return Err(JitError::UnsupportedStmt("bitfield dest")),
        };
        let hint = Some(reg_type(&dst_reg)?);
        let ty = self.resolve_int_type(hint, None)?;
        let src = self.lower_expr(module, builder, imports, &operands[1], Some(ty))?;
        let src = self.coerce_int(builder, src, ty)?;
        let lsb = match &operands[2] {
            Expr::Imm(v) => *v as u8,
            _ => return Err(JitError::UnsupportedStmt("bitfield lsb")),
        };
        let width = match &operands[3] {
            Expr::Imm(v) => *v as u8,
            _ => return Err(JitError::UnsupportedStmt("bitfield width")),
        };
        let result = compute(self, builder, src.value, lsb, width)?;
        let result_ty = builder.func.dfg.value_type(result);
        self.write_reg(
            builder,
            &dst_reg,
            LoweredValue {
                value: result,
                ty: result_ty,
            },
        )
    }
}
