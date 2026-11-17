use crate::imports::Imports;
use crate::lower::{
    base_reg_operand, parse_single_multi_reg_operand, vector_lane_type, vector_type_for_layout,
    LoweredValue, LoweringState, VectorShiftKind,
};
use crate::JitError;
use aeonil::{Expr, IntrinsicName, Reg};
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::immediates::Ieee64;
use cranelift_codegen::ir::types::{self, F64X2, I16X8, I32X4, I64X2, I8X16};
use cranelift_codegen::ir::{InstBuilder, MemFlags, Type, Value};
use cranelift_frontend::FunctionBuilder;
use cranelift_module::Module;

impl LoweringState {
    pub(crate) fn lower_vector_mul_acc_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
        subtract: bool,
    ) -> Result<(), JitError> {
        if operands.len() < 3 {
            return Err(JitError::UnsupportedStmt("vector mul-acc operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("vector mul-acc dest")),
        };
        let layout = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("vector mul-acc arrangement"))?;
        let vec_ty = vector_type_for_layout(layout)?;
        let lane_ty = vector_lane_type(layout.lane_bits)?;

        let dst = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
        let dst = self.coerce_value(builder, dst, I8X16)?;
        let dst_vec = self.bitcast_value(builder, vec_ty, dst.value, dst.ty);

        let src = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
        let src = self.coerce_value(builder, src, I8X16)?;
        let src_vec = self.bitcast_value(builder, vec_ty, src.value, src.ty);

        let scalar = self.lower_expr(module, builder, imports, &operands[2], Some(lane_ty))?;
        let scalar = self.coerce_int(builder, scalar, lane_ty)?;

        let zero_lane = self.zero_for_type(builder, lane_ty)?;
        let mut out = builder.ins().splat(vec_ty, zero_lane);
        for lane in 0..layout.lanes {
            let acc = builder.ins().extractlane(dst_vec, lane);
            let mul_lhs = builder.ins().extractlane(src_vec, lane);
            let product = builder.ins().imul(mul_lhs, scalar.value);
            let value = if subtract {
                builder.ins().isub(acc, product)
            } else {
                builder.ins().iadd(acc, product)
            };
            out = builder.ins().insertlane(out, value, lane);
        }

        let result = self.bitcast_value(builder, I8X16, out, vec_ty);
        self.write_reg(
            builder,
            &dst_reg,
            LoweredValue {
                value: result,
                ty: I8X16,
            },
        )
    }

    pub(crate) fn lower_sqrdmlx_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
        subtract: bool,
    ) -> Result<(), JitError> {
        if operands.len() < 3 {
            return Err(JitError::UnsupportedStmt("sqrdmlx operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("sqrdmlx dest")),
        };
        let layout = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("sqrdmlx arrangement"))?;
        if (layout.lanes, layout.lane_bits) != (8, 16) {
            return Err(JitError::UnsupportedStmt("sqrdmlx arrangement"));
        }

        let dst = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
        let dst = self.coerce_value(builder, dst, I8X16)?;
        let dst_vec = self.bitcast_value(builder, I16X8, dst.value, dst.ty);

        let src = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
        let src = self.coerce_value(builder, src, I8X16)?;
        let src_vec = self.bitcast_value(builder, I16X8, src.value, src.ty);

        let scalar = self.lower_expr(module, builder, imports, &operands[2], Some(types::I16))?;
        let scalar = self.coerce_int(builder, scalar, types::I16)?;
        let scalar = builder.ins().sextend(types::I64, scalar.value);

        let zero = builder.ins().iconst(types::I16, 0);
        let mut out = builder.ins().splat(I16X8, zero);
        let rounding = builder.ins().iconst(types::I64, 1 << 15);
        for lane in 0..8 {
            let acc = builder.ins().extractlane(dst_vec, lane);
            let acc = builder.ins().sextend(types::I64, acc);
            let lhs = builder.ins().extractlane(src_vec, lane);
            let lhs = builder.ins().sextend(types::I64, lhs);
            let product = builder.ins().imul(lhs, scalar);
            let doubled = builder.ins().ishl_imm(product, 1);
            let rounded = builder.ins().iadd(doubled, rounding);
            let high = builder.ins().sshr_imm(rounded, 16);
            let combined = if subtract {
                builder.ins().isub(acc, high)
            } else {
                builder.ins().iadd(acc, high)
            };
            let saturated = self.saturate_signed_value(builder, combined, 16)?;
            let narrowed = builder.ins().ireduce(types::I16, saturated);
            out = builder.ins().insertlane(out, narrowed, lane);
        }

        let result = self.bitcast_value(builder, I8X16, out, I16X8);
        self.write_reg(
            builder,
            &dst_reg,
            LoweredValue {
                value: result,
                ty: I8X16,
            },
        )
    }

    pub(crate) fn lower_vector_immediate_stmt_intrinsic(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        name: &IntrinsicName,
        operands: &[Expr],
        invert: bool,
    ) -> Result<(), JitError> {
        if operands.len() < 2 {
            return Err(JitError::UnsupportedStmt("vector immediate operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("vector immediate dest")),
        };
        let layout = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("vector immediate arrangement"))?;
        let vec_ty = vector_type_for_layout(layout)?;
        let lane_ty = vector_lane_type(layout.lane_bits)?;
        let imm = match operands[1] {
            Expr::Imm(value) => value,
            _ => return Err(JitError::UnsupportedStmt("vector immediate value")),
        };
        let lane_mask = if layout.lane_bits == 64 {
            u64::MAX
        } else {
            (1u64 << layout.lane_bits) - 1
        };
        let lane_imm = if invert {
            (!imm) & lane_mask
        } else {
            imm & lane_mask
        };
        let lane_value = self.iconst(builder, lane_ty, lane_imm)?;
        let vec = builder.ins().splat(vec_ty, lane_value);
        let result = self.bitcast_value(builder, I8X16, vec, vec_ty);
        self.write_reg(
            builder,
            &dst_reg,
            LoweredValue {
                value: result,
                ty: I8X16,
            },
        )
    }

    pub(crate) fn lower_uqrshrn2_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        if operands.len() < 3 {
            return Err(JitError::UnsupportedStmt("uqrshrn2 operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("uqrshrn2 dest")),
        };
        let layout = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("uqrshrn2 arrangement"))?;
        if (layout.lanes, layout.lane_bits) != (4, 32) {
            return Err(JitError::UnsupportedStmt("uqrshrn2 arrangement"));
        }
        let shift = match operands[2] {
            Expr::Imm(value) => {
                u8::try_from(value).map_err(|_| JitError::UnsupportedStmt("uqrshrn2 shift"))?
            }
            _ => return Err(JitError::UnsupportedStmt("uqrshrn2 shift")),
        };

        let dst = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
        let dst = self.coerce_value(builder, dst, I8X16)?;
        let mut out = self.bitcast_value(builder, I32X4, dst.value, dst.ty);

        let src = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
        let src = self.coerce_value(builder, src, I8X16)?;
        let src_vec = self.bitcast_value(builder, I64X2, src.value, src.ty);

        let rounding = if shift == 0 {
            None
        } else {
            Some(builder.ins().iconst(types::I64, 1i64 << (shift - 1)))
        };
        let max_u64 = self.iconst(builder, types::I64, u64::MAX)?;
        for lane in 0..2 {
            let value = builder.ins().extractlane(src_vec, lane);
            let rounded = if let Some(rounding) = rounding {
                let threshold = builder.ins().isub(max_u64, rounding);
                let overflow = builder
                    .ins()
                    .icmp(IntCC::UnsignedGreaterThan, value, threshold);
                let added = builder.ins().iadd(value, rounding);
                builder.ins().select(overflow, max_u64, added)
            } else {
                value
            };
            let shifted = if shift == 0 {
                rounded
            } else if u32::from(shift) >= 64 {
                builder.ins().iconst(types::I64, 0)
            } else {
                builder.ins().ushr_imm(rounded, i64::from(shift))
            };
            let saturated = self.saturate_unsigned_value(builder, shifted, 32)?;
            let narrowed = builder.ins().ireduce(types::I32, saturated);
            out = builder.ins().insertlane(out, narrowed, lane + 2);
        }

        let result = self.bitcast_value(builder, I8X16, out, I32X4);
        self.write_reg(
            builder,
            &dst_reg,
            LoweredValue {
                value: result,
                ty: I8X16,
            },
        )
    }

    pub(crate) fn lower_fcmla_stmt_intrinsic(
        &mut self,
        _module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        if operands.len() < 4 {
            return Err(JitError::UnsupportedStmt("fcmla operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("fcmla dest")),
        };
        let src_reg = match &operands[1] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("fcmla src")),
        };
        let layout = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("fcmla arrangement"))?;
        if (layout.lanes, layout.lane_bits) != (8, 16) {
            return Err(JitError::UnsupportedStmt("fcmla arrangement"));
        }

        let dst_index = match &dst_reg {
            Reg::V(index) | Reg::Q(index) => self.simd_index(*index, &dst_reg)?,
            _ => return Err(JitError::UnsupportedStmt("fcmla dest")),
        };
        let src_index = match &src_reg {
            Reg::V(index) | Reg::Q(index) => self.simd_index(*index, &src_reg)?,
            _ => return Err(JitError::UnsupportedStmt("fcmla src")),
        };

        let (scalar_reg, scalar_lsb) = match &operands[2] {
            Expr::Extract { src, lsb, .. } => match src.as_ref() {
                Expr::Reg(Reg::V(index)) | Expr::Reg(Reg::Q(index)) => (*index, *lsb),
                _ => return Err(JitError::UnsupportedStmt("fcmla scalar source")),
            },
            _ => return Err(JitError::UnsupportedStmt("fcmla scalar source")),
        };
        if scalar_lsb % 16 != 0 {
            return Err(JitError::UnsupportedStmt("fcmla scalar alignment"));
        }
        let real_lane = usize::from(scalar_lsb / 16);
        let imag_lane = real_lane + 1;
        if imag_lane >= 8 {
            return Err(JitError::UnsupportedStmt("fcmla scalar lane"));
        }
        let scalar_reg = Reg::V(scalar_reg);
        let scalar_vec = self.read_reg(builder, &scalar_reg)?;
        let scalar_vec = self.coerce_value(builder, scalar_vec, I8X16)?;
        let scalar_lanes = self.bitcast_value(builder, I16X8, scalar_vec.value, scalar_vec.ty);
        let scalar_re = builder.ins().extractlane(
            scalar_lanes,
            u8::try_from(real_lane).map_err(|_| JitError::UnsupportedStmt("fcmla scalar lane"))?,
        );
        let scalar_im = builder.ins().extractlane(
            scalar_lanes,
            u8::try_from(imag_lane).map_err(|_| JitError::UnsupportedStmt("fcmla scalar lane"))?,
        );
        let scalar_re = builder.ins().uextend(types::I64, scalar_re);
        let scalar_im = builder.ins().uextend(types::I64, scalar_im);
        let scalar_im_shifted = builder.ins().ishl_imm(scalar_im, 16);
        let scalar_pair_bits = builder.ins().bor(scalar_re, scalar_im_shifted);

        let rotation = match operands[3] {
            Expr::Imm(value) => value,
            _ => return Err(JitError::UnsupportedStmt("fcmla rotation")),
        };
        let helper = imports
            .fcmla_8h
            .ok_or(JitError::UnsupportedStmt("fcmla helper"))?;
        let dst_index_value = builder.ins().iconst(types::I64, dst_index as i64);
        let src_index_value = builder.ins().iconst(types::I64, src_index as i64);
        let rotation_value = builder.ins().iconst(types::I64, rotation as i64);
        builder.ins().call(
            helper,
            &[
                self.ctx_ptr,
                dst_index_value,
                src_index_value,
                scalar_pair_bits,
                rotation_value,
            ],
        );
        self.invalidate_all_simd_views_for_index(dst_index);
        Ok(())
    }

    pub(crate) fn lower_fmulx_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        if operands.len() < 3 {
            return Err(JitError::UnsupportedStmt("fmulx operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("fmulx dest")),
        };
        let layout = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("fmulx arrangement"))?;
        if (layout.lanes, layout.lane_bits) != (2, 64) {
            return Err(JitError::UnsupportedStmt("fmulx arrangement"));
        }

        let src = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
        let src = self.coerce_value(builder, src, I8X16)?;
        let src_vec = self.bitcast_value(builder, F64X2, src.value, src.ty);

        let scalar = match &operands[2] {
            Expr::Extract { .. } => {
                let bits =
                    self.lower_expr(module, builder, imports, &operands[2], Some(types::I64))?;
                let bits = self.coerce_int(builder, bits, types::I64)?;
                self.bitcast_value(builder, types::F64, bits.value, bits.ty)
            }
            _ => {
                let vec = self.lower_expr(module, builder, imports, &operands[2], Some(I8X16))?;
                let vec = self.coerce_value(builder, vec, I8X16)?;
                let vec = self.bitcast_value(builder, F64X2, vec.value, vec.ty);
                builder.ins().extractlane(vec, 0)
            }
        };

        let zero = builder.ins().f64const(Ieee64::with_float(0.0));
        let mut out = builder.ins().splat(F64X2, zero);
        for lane in 0..2 {
            let lhs = builder.ins().extractlane(src_vec, lane);
            let product = builder.ins().fmul(lhs, scalar);
            out = builder.ins().insertlane(out, product, lane);
        }

        let result = self.bitcast_value(builder, I8X16, out, F64X2);
        self.write_reg(
            builder,
            &dst_reg,
            LoweredValue {
                value: result,
                ty: I8X16,
            },
        )
    }

    pub(crate) fn lower_ldst1_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
        is_load: bool,
    ) -> Result<(), JitError> {
        if operands.len() < 2 {
            return Err(JitError::UnsupportedStmt("ld1/st1 operand count"));
        }
        let layout = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("ld1/st1 arrangement"))?;
        let byte_len = u8::try_from((u16::from(layout.lanes) * u16::from(layout.lane_bits)) / 8)
            .map_err(|_| JitError::UnsupportedStmt("ld1/st1 byte length"))?;
        let reg = parse_single_multi_reg_operand(&operands[0])
            .ok_or(JitError::UnsupportedStmt("ld1/st1 register list"))?;
        let addr = self.lower_expr(
            module,
            builder,
            imports,
            &operands[1],
            Some(self.pointer_type),
        )?;
        let addr = self.coerce_int(builder, addr, self.pointer_type)?;

        if is_load {
            if let Some(callback) = imports.memory_read {
                if imports.memory_read_addr_only {
                    builder.ins().call(callback, &[addr.value]);
                } else {
                    let size = builder.ins().iconst(types::I8, i64::from(byte_len));
                    builder.ins().call(callback, &[addr.value, size]);
                }
            }
            let result = match byte_len {
                16 => builder.ins().load(I8X16, MemFlags::new(), addr.value, 0),
                8 => {
                    let current = self.read_reg(builder, &reg)?;
                    let current = self.coerce_value(builder, current, I8X16)?;
                    let lanes = self.bitcast_value(builder, I64X2, current.value, current.ty);
                    let loaded = builder
                        .ins()
                        .load(types::I64, MemFlags::new(), addr.value, 0);
                    let merged = builder.ins().insertlane(lanes, loaded, 0);
                    self.bitcast_value(builder, I8X16, merged, I64X2)
                }
                _ => return Err(JitError::UnsupportedStmt("ld1/st1 byte length")),
            };
            self.write_reg(
                builder,
                &reg,
                LoweredValue {
                    value: result,
                    ty: I8X16,
                },
            )?;
        } else {
            let value = self.read_reg(builder, &reg)?;
            let value = self.coerce_value(builder, value, I8X16)?;
            match byte_len {
                16 => {
                    if let Some(callback) = imports.memory_write {
                        let size = builder.ins().iconst(types::I8, i64::from(byte_len));
                        let callback_value = self.value_as_u64_bits(builder, value)?;
                        builder
                            .ins()
                            .call(callback, &[addr.value, size, callback_value]);
                    }
                    builder
                        .ins()
                        .store(MemFlags::new(), value.value, addr.value, 0);
                }
                8 => {
                    let lanes = self.bitcast_value(builder, I64X2, value.value, value.ty);
                    let low = builder.ins().extractlane(lanes, 0);
                    if let Some(callback) = imports.memory_write {
                        let size = builder.ins().iconst(types::I8, i64::from(byte_len));
                        let callback_value = self.value_as_u64_bits(
                            builder,
                            LoweredValue {
                                value: low,
                                ty: types::I64,
                            },
                        )?;
                        builder
                            .ins()
                            .call(callback, &[addr.value, size, callback_value]);
                    }
                    builder.ins().store(MemFlags::new(), low, addr.value, 0);
                }
                _ => return Err(JitError::UnsupportedStmt("ld1/st1 byte length")),
            }
        }

        if let (Some(base_reg), Some(Expr::Imm(writeback))) =
            (base_reg_operand(&operands[1]), operands.get(2))
        {
            let current = self.read_reg(builder, &base_reg)?;
            let current = self.coerce_int(builder, current, self.pointer_type)?;
            let value = builder.ins().iadd_imm(current.value, *writeback as i64);
            self.write_reg(
                builder,
                &base_reg,
                LoweredValue {
                    value,
                    ty: self.pointer_type,
                },
            )?;
        }

        Ok(())
    }

    pub(crate) fn lower_widening_lane_mul_acc_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        operands: &[Expr],
        signed: bool,
        subtract: bool,
    ) -> Result<(), JitError> {
        if operands.len() < 3 {
            return Err(JitError::UnsupportedStmt(
                "widening lane mul-acc operand count",
            ));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("widening lane mul-acc dest")),
        };
        let dst = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
        let dst = self.coerce_value(builder, dst, I8X16)?;
        let src_vec = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
        let src_vec = self.coerce_value(builder, src_vec, I8X16)?;
        let scalar_ty = self
            .infer_expr_type(&operands[2])
            .filter(|ty| ty.is_int())
            .unwrap_or(types::I16);
        let scalar = self.lower_expr(module, builder, imports, &operands[2], Some(scalar_ty))?;
        let scalar = self.coerce_int(builder, scalar, scalar_ty)?;

        let result = match scalar_ty {
            types::I16 => {
                let acc_vec = self.bitcast_value(builder, I32X4, dst.value, dst.ty);
                let lanes = self.bitcast_value(builder, I16X8, src_vec.value, src_vec.ty);
                let scalar = if signed {
                    builder.ins().sextend(types::I32, scalar.value)
                } else {
                    builder.ins().uextend(types::I32, scalar.value)
                };
                let mut out = acc_vec;
                for lane in 0..4 {
                    let acc = builder.ins().extractlane(out, lane);
                    let lane_value = builder.ins().extractlane(lanes, lane + 4);
                    let lane_value = if signed {
                        builder.ins().sextend(types::I32, lane_value)
                    } else {
                        builder.ins().uextend(types::I32, lane_value)
                    };
                    let product = builder.ins().imul(lane_value, scalar);
                    let value = if subtract {
                        builder.ins().isub(acc, product)
                    } else {
                        builder.ins().iadd(acc, product)
                    };
                    out = builder.ins().insertlane(out, value, lane);
                }
                self.bitcast_value(builder, I8X16, out, I32X4)
            }
            types::I32 => {
                let acc_vec = self.bitcast_value(builder, I64X2, dst.value, dst.ty);
                let lanes = self.bitcast_value(builder, I32X4, src_vec.value, src_vec.ty);
                let scalar = if signed {
                    builder.ins().sextend(types::I64, scalar.value)
                } else {
                    builder.ins().uextend(types::I64, scalar.value)
                };
                let mut out = acc_vec;
                for lane in 0..2 {
                    let acc = builder.ins().extractlane(out, lane);
                    let lane_value = builder.ins().extractlane(lanes, lane + 2);
                    let lane_value = if signed {
                        builder.ins().sextend(types::I64, lane_value)
                    } else {
                        builder.ins().uextend(types::I64, lane_value)
                    };
                    let product = builder.ins().imul(lane_value, scalar);
                    let value = if subtract {
                        builder.ins().isub(acc, product)
                    } else {
                        builder.ins().iadd(acc, product)
                    };
                    out = builder.ins().insertlane(out, value, lane);
                }
                self.bitcast_value(builder, I8X16, out, I64X2)
            }
            _ => {
                return Err(JitError::UnsupportedStmt(
                    "widening lane mul-acc scalar width",
                ))
            }
        };

        self.write_reg(
            builder,
            &dst_reg,
            LoweredValue {
                value: result,
                ty: I8X16,
            },
        )
    }

    pub(crate) fn lower_widening_lane_mul_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        operands: &[Expr],
        signed: bool,
    ) -> Result<(), JitError> {
        if operands.len() < 3 {
            return Err(JitError::UnsupportedStmt("widening lane mul operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("widening lane mul dest")),
        };
        let src_vec = self.lower_expr(module, builder, imports, &operands[1], Some(I8X16))?;
        let src_vec = self.coerce_value(builder, src_vec, I8X16)?;
        let scalar_ty = self
            .infer_expr_type(&operands[2])
            .filter(|ty| ty.is_int())
            .unwrap_or(types::I16);
        let scalar = self.lower_expr(module, builder, imports, &operands[2], Some(scalar_ty))?;
        let scalar = self.coerce_int(builder, scalar, scalar_ty)?;

        let result = match scalar_ty {
            types::I16 => {
                let lanes = self.bitcast_value(builder, I16X8, src_vec.value, src_vec.ty);
                let scalar = if signed {
                    builder.ins().sextend(types::I32, scalar.value)
                } else {
                    builder.ins().uextend(types::I32, scalar.value)
                };
                let zero = builder.ins().iconst(types::I32, 0);
                let mut out = builder.ins().splat(I32X4, zero);
                for lane in 0..4 {
                    let lane_value = builder.ins().extractlane(lanes, lane + 4);
                    let lane_value = if signed {
                        builder.ins().sextend(types::I32, lane_value)
                    } else {
                        builder.ins().uextend(types::I32, lane_value)
                    };
                    let product = builder.ins().imul(lane_value, scalar);
                    out = builder.ins().insertlane(out, product, lane);
                }
                self.bitcast_value(builder, I8X16, out, I32X4)
            }
            types::I32 => {
                let lanes = self.bitcast_value(builder, I32X4, src_vec.value, src_vec.ty);
                let scalar = if signed {
                    builder.ins().sextend(types::I64, scalar.value)
                } else {
                    builder.ins().uextend(types::I64, scalar.value)
                };
                let zero = builder.ins().iconst(types::I64, 0);
                let mut out = builder.ins().splat(I64X2, zero);
                for lane in 0..2 {
                    let lane_value = builder.ins().extractlane(lanes, lane + 2);
                    let lane_value = if signed {
                        builder.ins().sextend(types::I64, lane_value)
                    } else {
                        builder.ins().uextend(types::I64, lane_value)
                    };
                    let product = builder.ins().imul(lane_value, scalar);
                    out = builder.ins().insertlane(out, product, lane);
                }
                self.bitcast_value(builder, I8X16, out, I64X2)
            }
            _ => return Err(JitError::UnsupportedStmt("widening lane mul scalar width")),
        };

        self.write_reg(
            builder,
            &dst_reg,
            LoweredValue {
                value: result,
                ty: I8X16,
            },
        )
    }

    pub(crate) fn lower_vector_shift_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &IntrinsicName,
        operands: &[Expr],
        kind: VectorShiftKind,
    ) -> Result<(), JitError> {
        if operands.len() < 2 {
            return Err(JitError::UnsupportedStmt("vector shift operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("vector shift dest")),
        };
        let layout = name
            .arrangement()
            .ok_or(JitError::UnsupportedStmt("vector shift arrangement"))?;
        let vec_ty = vector_type_for_layout(layout)?;
        let lane_ty = vector_lane_type(layout.lane_bits)?;

        let dst_input = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
        let dst_input = self.coerce_value(builder, dst_input, I8X16)?;
        let dst_vec = self.bitcast_value(builder, vec_ty, dst_input.value, dst_input.ty);

        let src_index = if matches!(kind, VectorShiftKind::Uxtl | VectorShiftKind::Ushll2) {
            1
        } else {
            1
        };
        let src = self.lower_expr(module, builder, imports, &operands[src_index], Some(I8X16))?;
        let src = self.coerce_value(builder, src, I8X16)?;

        let shift = match kind {
            VectorShiftKind::Uxtl => 0,
            VectorShiftKind::Ushll2 => match operands.get(2) {
                Some(Expr::Imm(value)) => u8::try_from(*value)
                    .map_err(|_| JitError::UnsupportedStmt("vector shift amount"))?,
                _ => return Err(JitError::UnsupportedStmt("vector shift amount")),
            },
            _ => match operands.get(2) {
                Some(Expr::Imm(value)) => u8::try_from(*value)
                    .map_err(|_| JitError::UnsupportedStmt("vector shift amount"))?,
                _ => return Err(JitError::UnsupportedStmt("vector shift amount")),
            },
        };

        let zero_lane = self.zero_for_type(builder, lane_ty)?;
        let mut out = builder.ins().splat(vec_ty, zero_lane);
        match kind {
            VectorShiftKind::Uxtl | VectorShiftKind::Ushll2 => {
                let src_lane_bits = layout.lane_bits / 2;
                let src_vec_ty = match src_lane_bits {
                    8 => I8X16,
                    16 => I16X8,
                    32 => I32X4,
                    _ => return Err(JitError::UnsupportedStmt("uxtl source layout")),
                };
                let src_vec = self.bitcast_value(builder, src_vec_ty, src.value, src.ty);
                let start_lane = if matches!(kind, VectorShiftKind::Ushll2) {
                    layout.lanes
                } else {
                    0
                };
                for lane in 0..layout.lanes {
                    let value = builder.ins().extractlane(src_vec, lane + start_lane);
                    let widened = builder.ins().uextend(lane_ty, value);
                    let widened = if shift == 0 {
                        widened
                    } else if u32::from(shift) >= lane_ty.bits() {
                        zero_lane
                    } else {
                        builder.ins().ishl_imm(widened, i64::from(shift))
                    };
                    out = builder.ins().insertlane(out, widened, lane);
                }
            }
            _ => {
                let src_vec = self.bitcast_value(builder, vec_ty, src.value, src.ty);
                for lane in 0..layout.lanes {
                    let src_lane = builder.ins().extractlane(src_vec, lane);
                    let dst_lane = builder.ins().extractlane(dst_vec, lane);
                    let value = self.lower_vector_shift_lane(
                        builder,
                        lane_ty,
                        src_lane,
                        dst_lane,
                        layout.lane_bits,
                        shift,
                        kind,
                    )?;
                    out = builder.ins().insertlane(out, value, lane);
                }
            }
        }

        let result = self.bitcast_value(builder, I8X16, out, vec_ty);
        self.write_reg(
            builder,
            &dst_reg,
            LoweredValue {
                value: result,
                ty: I8X16,
            },
        )
    }

    pub(crate) fn lower_vector_shift_lane(
        &self,
        builder: &mut FunctionBuilder<'_>,
        lane_ty: Type,
        src_lane: Value,
        dst_lane: Value,
        lane_bits: u8,
        shift: u8,
        kind: VectorShiftKind,
    ) -> Result<Value, JitError> {
        let zero = self.zero_for_type(builder, lane_ty)?;
        let all_ones = self.all_ones(builder, lane_ty)?;
        let shifted = |b: &mut FunctionBuilder<'_>, value: Value, amount: u8| {
            if amount == 0 {
                value
            } else if u32::from(amount) >= lane_ty.bits() {
                zero
            } else {
                b.ins().ushr_imm(value, i64::from(amount))
            }
        };
        let rounded_shift =
            |b: &mut FunctionBuilder<'_>, value: Value, amount: u8| -> Result<Value, JitError> {
                if amount == 0 {
                    Ok(value)
                } else if u32::from(amount) >= lane_ty.bits() {
                    Ok(zero)
                } else {
                    let bias = self.iconst(b, lane_ty, 1u64 << (amount - 1))?;
                    let added = b.ins().iadd(value, bias);
                    Ok(b.ins().ushr_imm(added, i64::from(amount)))
                }
            };

        Ok(match kind {
            VectorShiftKind::Ushr => shifted(builder, src_lane, shift),
            VectorShiftKind::Urshr => rounded_shift(builder, src_lane, shift)?,
            VectorShiftKind::Usra => {
                let addend = shifted(builder, src_lane, shift);
                builder.ins().iadd(dst_lane, addend)
            }
            VectorShiftKind::Ursra => {
                let addend = rounded_shift(builder, src_lane, shift)?;
                builder.ins().iadd(dst_lane, addend)
            }
            VectorShiftKind::Sli => {
                if shift == 0 {
                    src_lane
                } else {
                    let low_mask = self.mask_for_width(builder, lane_ty, shift)?;
                    let preserved = builder.ins().band(dst_lane, low_mask);
                    let inserted = if u32::from(shift) >= lane_ty.bits() {
                        zero
                    } else {
                        builder.ins().ishl_imm(src_lane, i64::from(shift))
                    };
                    builder.ins().bor(inserted, preserved)
                }
            }
            VectorShiftKind::Sri => {
                if shift == 0 {
                    src_lane
                } else {
                    let preserved_bits = lane_bits.saturating_sub(shift);
                    let low_mask = if preserved_bits == 0 {
                        zero
                    } else {
                        self.mask_for_width(builder, lane_ty, preserved_bits)?
                    };
                    let high_mask = builder.ins().bxor(low_mask, all_ones);
                    let preserved = builder.ins().band(dst_lane, high_mask);
                    let inserted = shifted(builder, src_lane, shift);
                    builder.ins().bor(inserted, preserved)
                }
            }
            VectorShiftKind::Sqshlu => {
                let src_neg = builder.ins().icmp(IntCC::SignedLessThan, src_lane, zero);
                let shifted = if shift == 0 {
                    src_lane
                } else if u32::from(shift) >= lane_ty.bits() {
                    zero
                } else {
                    builder.ins().ishl_imm(src_lane, i64::from(shift))
                };
                let threshold = if shift == 0 {
                    all_ones
                } else if u32::from(shift) >= lane_ty.bits() {
                    zero
                } else {
                    builder.ins().ushr_imm(all_ones, i64::from(shift))
                };
                let overflow = if shift == 0 {
                    builder.ins().iconst(types::I8, 0)
                } else {
                    builder
                        .ins()
                        .icmp(IntCC::UnsignedGreaterThan, src_lane, threshold)
                };
                let saturated = builder.ins().select(overflow, all_ones, shifted);
                builder.ins().select(src_neg, zero, saturated)
            }
            VectorShiftKind::Uqshl => {
                let shifted = if shift == 0 {
                    src_lane
                } else if u32::from(shift) >= lane_ty.bits() {
                    zero
                } else {
                    builder.ins().ishl_imm(src_lane, i64::from(shift))
                };
                let overflow = if shift == 0 {
                    builder.ins().iconst(types::I8, 0)
                } else if u32::from(shift) >= lane_ty.bits() {
                    builder.ins().icmp(IntCC::NotEqual, src_lane, zero)
                } else {
                    let threshold = builder.ins().ushr_imm(all_ones, i64::from(shift));
                    builder
                        .ins()
                        .icmp(IntCC::UnsignedGreaterThan, src_lane, threshold)
                };
                builder.ins().select(overflow, all_ones, shifted)
            }
            VectorShiftKind::Uxtl | VectorShiftKind::Ushll2 => {
                unreachable!("uxtl/ushll2 handled separately")
            }
        })
    }
}
