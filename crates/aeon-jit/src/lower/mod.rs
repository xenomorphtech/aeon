use crate::imports::Imports;
use crate::{JitContext, JitError};
use aeonil::{BranchCond, Expr, IntrinsicOp, Reg, Stmt, TrapKind, VectorArrangement};
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::types::{self, I16X8, I32X4, I64X2, I8X16};
use cranelift_codegen::ir::{InstBuilder, MemFlags, Type, Value};
use cranelift_frontend::{FunctionBuilder, Variable};
use cranelift_module::Module;
use std::mem::offset_of;

mod coerce;
mod expr;
mod flags;
mod intrinsic_expr;
mod intrinsic_stmt;
mod lanes;
mod regs;
mod simd;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ScalarVar {
    pub(crate) var: Option<Variable>,
    pub(crate) dirty: bool,
}

impl ScalarVar {
    pub(crate) const fn new() -> Self {
        Self {
            var: None,
            dirty: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SimdVar {
    pub(crate) var: Option<Variable>,
    pub(crate) valid: bool,
}

impl SimdVar {
    pub(crate) const fn new() -> Self {
        Self {
            var: None,
            valid: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LoweredValue {
    pub(crate) value: Value,
    pub(crate) ty: Type,
}

pub(crate) struct LoweringState {
    ctx_ptr: Value,
    pointer_type: Type,
    block_addr: u64,
    _block_id: u64,
    pub(crate) terminated: bool,
    _next_variable: u32,
    x_regs: [ScalarVar; 31],
    w_regs: [ScalarVar; 31],
    sp: ScalarVar,
    pc: ScalarVar,
    flags: ScalarVar,
    vec_regs: [SimdVar; 32],
    d_regs: [SimdVar; 32],
    s_regs: [SimdVar; 32],
    h_regs: [SimdVar; 32],
    vbyte_regs: [SimdVar; 32],
}

#[derive(Clone, Copy)]
pub(crate) struct ScalarDirtySnapshot {
    x_regs: [bool; 31],
    sp: bool,
    pc: bool,
    flags: bool,
}

impl LoweringState {
    pub(crate) fn new(ctx_ptr: Value, pointer_type: Type, block_addr: u64, block_id: u64) -> Self {
        Self {
            ctx_ptr,
            pointer_type,
            block_addr,
            _block_id: block_id,
            terminated: false,
            _next_variable: 0,
            x_regs: [ScalarVar::new(); 31],
            w_regs: [ScalarVar::new(); 31],
            sp: ScalarVar::new(),
            pc: ScalarVar::new(),
            flags: ScalarVar::new(),
            vec_regs: [SimdVar::new(); 32],
            d_regs: [SimdVar::new(); 32],
            s_regs: [SimdVar::new(); 32],
            h_regs: [SimdVar::new(); 32],
            vbyte_regs: [SimdVar::new(); 32],
        }
    }

    pub(crate) fn lower_stmts(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        stmts: &[Stmt],
    ) -> Result<(), JitError> {
        for stmt in stmts {
            if self.terminated {
                return Err(JitError::StatementAfterTerminator);
            }
            self.lower_stmt(module, builder, imports, stmt)?;
        }
        Ok(())
    }

    pub(crate) fn lower_stmt(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        stmt: &Stmt,
    ) -> Result<(), JitError> {
        match stmt {
            Stmt::Assign { dst, src } => {
                let hint = Some(reg_type(dst)?);
                let value = self.lower_expr(module, builder, imports, src, hint)?;
                self.write_reg(builder, dst, value)?;
            }
            Stmt::Store { addr, value, size } => {
                let store_ty = self.store_type_for_value(value, *size)?;
                let addr =
                    self.lower_expr(module, builder, imports, addr, Some(self.pointer_type))?;
                let addr = self.coerce_int(builder, addr, self.pointer_type)?;
                let value = self.lower_expr(module, builder, imports, value, Some(store_ty))?;
                let value = self.coerce_value(builder, value, store_ty)?;
                if let Some(callback) = imports.memory_write {
                    let size = builder.ins().iconst(types::I8, i64::from(*size));
                    let callback_value = self.value_as_u64_bits(builder, value)?;
                    imports.call_hook(builder, callback, &[addr.value, size, callback_value]);
                }
                builder
                    .ins()
                    .store(MemFlags::new(), value.value, addr.value, 0);
            }
            Stmt::Branch { target } => {
                let target = self.lower_expr(module, builder, imports, target, Some(types::I64))?;
                let target = self.coerce_int(builder, target, types::I64)?;
                self.lower_branch_exit(builder, imports, target.value)?;
            }
            Stmt::CondBranch {
                cond,
                target,
                fallthrough,
            } => {
                let cond = self.lower_branch_cond(module, builder, imports, cond)?;
                // Each arm must flush the same pending register state. Flushing
                // the first arm clears dirty bits, so restore them before
                // lowering the fallthrough arm.
                let dirty_snapshot = self.snapshot_scalar_dirty();
                let then_block = builder.create_block();
                let else_block = builder.create_block();
                builder.ins().brif(cond, then_block, &[], else_block, &[]);

                builder.switch_to_block(then_block);
                let target = self.lower_expr(module, builder, imports, target, Some(types::I64))?;
                let target = self.coerce_int(builder, target, types::I64)?;
                self.lower_branch_exit(builder, imports, target.value)?;
                builder.seal_block(then_block);

                self.restore_scalar_dirty(dirty_snapshot);
                builder.switch_to_block(else_block);
                let fallthrough = builder.ins().iconst(types::I64, *fallthrough as i64);
                self.lower_branch_exit(builder, imports, fallthrough)?;
                builder.seal_block(else_block);
                self.terminated = true;
            }
            Stmt::Call { target } => {
                self.flush_scalars(builder)?;
                let target =
                    self.lower_expr(module, builder, imports, target, Some(self.pointer_type))?;
                let target = self.coerce_int(builder, target, self.pointer_type)?;
                if let Some(translator) = imports.branch_translate {
                    let translated_call = imports.call_hook(builder, translator, &[target.value]);
                    let translated_raw = builder.inst_results(translated_call)[0];
                    let translated_block = builder.create_block();
                    let unresolved_block = builder.create_block();
                    let continue_block = builder.create_block();
                    let translated_exists =
                        builder
                            .ins()
                            .icmp(IntCC::NotEqual, translated_raw, target.value);
                    builder.ins().brif(
                        translated_exists,
                        translated_block,
                        &[],
                        unresolved_block,
                        &[],
                    );

                    builder.switch_to_block(translated_block);
                    if let Some(sig) = imports.call_sig {
                        let translated = self.coerce_int(
                            builder,
                            LoweredValue {
                                value: translated_raw,
                                ty: types::I64,
                            },
                            self.pointer_type,
                        )?;
                        builder
                            .ins()
                            .call_indirect(sig, translated.value, &[self.ctx_ptr]);
                        builder.ins().jump(continue_block, &[]);
                    } else {
                        return Err(JitError::UnsupportedStmt(
                            "call translation without imported signature",
                        ));
                    }
                    builder.seal_block(translated_block);

                    builder.switch_to_block(unresolved_block);
                    if let Some(bridge) = imports.branch_bridge {
                        imports.call_hook(builder, bridge, &[self.ctx_ptr, target.value]);
                        builder.ins().jump(continue_block, &[]);
                    } else if let Some(sig) = imports.call_sig {
                        builder
                            .ins()
                            .call_indirect(sig, target.value, &[self.ctx_ptr]);
                        builder.ins().jump(continue_block, &[]);
                    } else {
                        return Err(JitError::UnsupportedStmt("call without imported signature"));
                    }
                    builder.seal_block(unresolved_block);

                    builder.switch_to_block(continue_block);
                    builder.seal_block(continue_block);
                } else if let Some(sig) = imports.call_sig {
                    builder
                        .ins()
                        .call_indirect(sig, target.value, &[self.ctx_ptr]);
                } else {
                    return Err(JitError::UnsupportedStmt("call without imported signature"));
                }
                self.invalidate_scalars();
                self.invalidate_all_simd_views();
            }
            Stmt::Ret => {
                self.flush_scalars(builder)?;
                let ret = self.read_x(builder, 30)?;
                builder.ins().return_(&[ret]);
                self.terminated = true;
            }
            Stmt::Nop => return Err(JitError::UnsupportedStmt("nop")),
            Stmt::Barrier(kind) => {
                if !is_supported_barrier(kind) {
                    return Err(JitError::UnsupportedStmt("barrier"));
                }
            }
            Stmt::Pair(lhs, rhs) => {
                self.lower_stmt(module, builder, imports, lhs)?;
                if !self.terminated {
                    self.lower_stmt(module, builder, imports, rhs)?;
                }
            }
            Stmt::SetFlags { expr } => {
                let flags = self.lower_flags_expr(module, builder, imports, expr)?;
                self.write_flags_value(builder, flags)?;
            }
            Stmt::Trap { kind, imm } => {
                if let Some(callback) = imports.trap_hook {
                    let block_addr = builder.ins().iconst(types::I64, self.block_addr as i64);
                    let kind = builder.ins().iconst(types::I64, trap_kind_code(*kind));
                    let imm = builder.ins().iconst(types::I64, i64::from(*imm));
                    imports.call_hook(builder, callback, &[block_addr, kind, imm]);
                }
                builder
                    .ins()
                    .trap(cranelift_codegen::ir::TrapCode::unwrap_user(1));
                self.terminated = true;
            }
            Stmt::Intrinsic { name, operands } => {
                self.lower_stmt_intrinsic(module, builder, imports, name, operands)?;
            }
        }
        Ok(())
    }

    pub(crate) fn lower_branch_exit(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        target: Value,
    ) -> Result<(), JitError> {
        if let Some(translator) = imports.branch_translate {
            // Branch translation / bridging may need to inspect guest register
            // state, especially x30 after call-to-branch rewriting. Flush the
            // current scalar state before crossing that boundary.
            self.flush_scalars(builder)?;
            let translated_call = imports.call_hook(builder, translator, &[target]);
            let translated_raw = builder.inst_results(translated_call)[0];
            let dynamic_block = builder.create_block();
            let dispatch_block = builder.create_block();
            let translated_block = builder.create_block();
            let unresolved_block = builder.create_block();
            let translated_is_dynamic = builder.ins().icmp_imm(IntCC::Equal, translated_raw, 0);
            builder.ins().brif(
                translated_is_dynamic,
                dynamic_block,
                &[],
                dispatch_block,
                &[],
            );

            builder.switch_to_block(dynamic_block);
            self.write_pc_value(builder, target)?;
            self.flush_scalars(builder)?;
            builder.ins().return_(&[target]);
            builder.seal_block(dynamic_block);

            builder.switch_to_block(dispatch_block);
            let translated_exists = builder.ins().icmp(IntCC::NotEqual, translated_raw, target);
            builder.ins().brif(
                translated_exists,
                translated_block,
                &[],
                unresolved_block,
                &[],
            );
            builder.seal_block(dispatch_block);

            builder.switch_to_block(translated_block);
            self.flush_scalars(builder)?;
            if let Some(sig) = imports.call_sig {
                let translated = self.coerce_int(
                    builder,
                    LoweredValue {
                        value: translated_raw,
                        ty: types::I64,
                    },
                    self.pointer_type,
                )?;
                let translated_call =
                    builder
                        .ins()
                        .call_indirect(sig, translated.value, &[self.ctx_ptr]);
                let next_target = builder.inst_results(translated_call)[0];
                builder.ins().return_(&[next_target]);
            } else {
                return Err(JitError::UnsupportedStmt(
                    "branch translation without imported signature",
                ));
            }
            builder.seal_block(translated_block);

            builder.switch_to_block(unresolved_block);
            self.flush_scalars(builder)?;
            if let Some(bridge) = imports.branch_bridge {
                let bridge_call = imports.call_hook(builder, bridge, &[self.ctx_ptr, target]);
                let next_target = builder.inst_results(bridge_call)[0];
                builder.ins().return_(&[next_target]);
            } else {
                self.write_pc_value(builder, target)?;
                builder.ins().return_(&[target]);
            }
            builder.seal_block(unresolved_block);
            self.terminated = true;
            return Ok(());
        }

        self.write_pc_value(builder, target)?;
        self.flush_scalars(builder)?;
        builder.ins().return_(&[target]);
        self.terminated = true;
        Ok(())
    }

    pub(crate) fn lower_branch_cond(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        cond: &BranchCond,
    ) -> Result<Value, JitError> {
        match cond {
            BranchCond::Flag(cond) => {
                let flags = self.read_flags(builder)?;
                self.eval_flags_condition(builder, flags, *cond)
            }
            BranchCond::Zero(expr) => {
                let value = self.lower_expr(module, builder, imports, expr, None)?;
                let zero = self.zero_for_type(builder, value.ty)?;
                Ok(builder.ins().icmp(IntCC::Equal, value.value, zero))
            }
            BranchCond::NotZero(expr) => {
                let value = self.lower_expr(module, builder, imports, expr, None)?;
                let zero = self.zero_for_type(builder, value.ty)?;
                Ok(builder.ins().icmp(IntCC::NotEqual, value.value, zero))
            }
            BranchCond::BitZero(expr, bit) => {
                let value = self.lower_expr(module, builder, imports, expr, None)?;
                let value =
                    self.coerce_int(builder, value, self.resolve_int_type(None, Some(expr))?)?;
                let mask = self.mask_for_bit(builder, value.ty, *bit)?;
                let masked = builder.ins().band(value.value, mask);
                let zero = self.zero_for_type(builder, value.ty)?;
                Ok(builder.ins().icmp(IntCC::Equal, masked, zero))
            }
            BranchCond::BitNotZero(expr, bit) => {
                let value = self.lower_expr(module, builder, imports, expr, None)?;
                let value =
                    self.coerce_int(builder, value, self.resolve_int_type(None, Some(expr))?)?;
                let mask = self.mask_for_bit(builder, value.ty, *bit)?;
                let masked = builder.ins().band(value.value, mask);
                let zero = self.zero_for_type(builder, value.ty)?;
                Ok(builder.ins().icmp(IntCC::NotEqual, masked, zero))
            }
            BranchCond::Compare { cond, lhs, rhs } => {
                self.lower_compare_condition(module, builder, imports, *cond, lhs, rhs)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SimdKind {
    Vec,
    D,
    S,
    H,
    VByte,
}

#[derive(Clone, Copy)]
pub(crate) enum VectorShiftKind {
    Urshr,
    Usra,
    Ursra,
    Sli,
    Sri,
    Sqshlu,
    Uqshl,
}

pub(crate) fn reg_type(reg: &Reg) -> Result<Type, JitError> {
    match reg {
        Reg::X(_) | Reg::SP | Reg::PC | Reg::Flags | Reg::XZR => Ok(types::I64),
        Reg::W(_) => Ok(types::I32),
        Reg::V(_) | Reg::Q(_) => Ok(I8X16),
        Reg::D(_) => Ok(types::F64),
        Reg::S(_) => Ok(types::F32),
        Reg::H(_) => Ok(types::I16),
        Reg::VByte(_) => Ok(types::I8),
    }
}

pub(crate) fn vector_lane_type(bits: u8) -> Result<Type, JitError> {
    match bits {
        8 => Ok(types::I8),
        16 => Ok(types::I16),
        32 => Ok(types::I32),
        64 => Ok(types::I64),
        _ => Err(JitError::UnsupportedExpr("vector lane type")),
    }
}

pub(crate) fn vector_type_for_layout(layout: VectorArrangement) -> Result<Type, JitError> {
    match (layout.lanes, layout.lane_bits) {
        (16, 8) => Ok(I8X16),
        (8, 16) => Ok(I16X8),
        (4, 32) => Ok(I32X4),
        (2, 64) => Ok(I64X2),
        _ => Err(JitError::UnsupportedExpr("vector layout")),
    }
}

pub(crate) fn parse_single_multi_reg_operand(expr: &Expr) -> Option<Reg> {
    let Expr::Intrinsic { name, operands } = expr else {
        return None;
    };
    if name.op() != IntrinsicOp::MultiReg || operands.len() != 1 {
        return None;
    }
    match &operands[0] {
        Expr::Reg(reg) => Some(reg.clone()),
        _ => None,
    }
}

pub(crate) fn base_reg_operand(expr: &Expr) -> Option<Reg> {
    match expr {
        Expr::Reg(reg) => Some(reg.clone()),
        _ => None,
    }
}

pub(crate) fn is_supported_barrier(kind: &str) -> bool {
    matches!(kind, "dmb" | "dsb" | "isb")
}

pub(crate) fn trap_kind_code(kind: TrapKind) -> i64 {
    match kind {
        TrapKind::Brk => 1,
        TrapKind::Udf => 2,
    }
}

pub(crate) fn type_for_memory_size(size: u8) -> Result<Type, JitError> {
    match size {
        1 => Ok(types::I8),
        2 => Ok(types::I16),
        4 => Ok(types::I32),
        8 => Ok(types::I64),
        16 => Ok(I8X16),
        _ => Err(JitError::InvalidMemorySize(size)),
    }
}

pub(crate) fn int_type_for_bits(bits: u16) -> Option<Type> {
    match bits {
        0..=8 => Some(types::I8),
        9..=16 => Some(types::I16),
        17..=32 => Some(types::I32),
        33..=64 => Some(types::I64),
        65..=128 => Some(types::I128),
        _ => None,
    }
}

pub(crate) fn type_size_bytes(ty: Type) -> usize {
    ty.bytes() as usize
}

pub(crate) fn x_offset(index: usize) -> usize {
    offset_of!(JitContext, x) + index * std::mem::size_of::<u64>()
}

pub(crate) fn simd_offset(index: usize) -> usize {
    offset_of!(JitContext, simd) + index * 16
}
