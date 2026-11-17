use crate::lower::{
    simd_offset, x_offset, LoweredValue, LoweringState, ScalarDirtySnapshot, ScalarVar, SimdKind,
    SimdVar,
};
use crate::{JitContext, JitError};
use aeonil::Reg;
use cranelift_codegen::ir::types::{self, I8X16};
use cranelift_codegen::ir::{InstBuilder, MemFlags, Type, Value};
use cranelift_frontend::FunctionBuilder;
use std::mem::offset_of;

impl LoweringState {
    pub(crate) fn read_reg(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        reg: &Reg,
    ) -> Result<LoweredValue, JitError> {
        match reg {
            Reg::X(index) => {
                let index = self.gpr_index(*index, reg)?;
                Ok(LoweredValue {
                    value: self.read_x(builder, index)?,
                    ty: types::I64,
                })
            }
            Reg::W(index) => {
                let index = self.gpr_index(*index, reg)?;
                Ok(LoweredValue {
                    value: self.read_w(builder, index)?,
                    ty: types::I32,
                })
            }
            Reg::SP => Ok(LoweredValue {
                value: self.read_sp(builder)?,
                ty: types::I64,
            }),
            Reg::PC => Ok(LoweredValue {
                value: self.read_pc(builder)?,
                ty: types::I64,
            }),
            Reg::XZR => Ok(LoweredValue {
                value: builder.ins().iconst(types::I64, 0),
                ty: types::I64,
            }),
            Reg::Flags => Ok(LoweredValue {
                value: self.read_flags(builder)?,
                ty: types::I64,
            }),
            Reg::V(index) | Reg::Q(index) => {
                let index = self.simd_index(*index, reg)?;
                Ok(LoweredValue {
                    value: self.read_vec(builder, index)?,
                    ty: I8X16,
                })
            }
            Reg::D(index) => {
                let index = self.simd_index(*index, reg)?;
                Ok(LoweredValue {
                    value: self.read_d(builder, index)?,
                    ty: types::F64,
                })
            }
            Reg::S(index) => {
                let index = self.simd_index(*index, reg)?;
                Ok(LoweredValue {
                    value: self.read_s(builder, index)?,
                    ty: types::F32,
                })
            }
            Reg::H(index) => {
                let index = self.simd_index(*index, reg)?;
                Ok(LoweredValue {
                    value: self.read_h(builder, index)?,
                    ty: types::I16,
                })
            }
            Reg::VByte(index) => {
                let index = self.simd_index(*index, reg)?;
                Ok(LoweredValue {
                    value: self.read_vbyte(builder, index)?,
                    ty: types::I8,
                })
            }
        }
    }

    pub(crate) fn write_reg(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        reg: &Reg,
        value: LoweredValue,
    ) -> Result<(), JitError> {
        match reg {
            Reg::X(index) => {
                let index = self.gpr_index(*index, reg)?;
                let value = self.coerce_int(builder, value, types::I64)?;
                self.write_x(builder, index, value.value)
            }
            Reg::W(index) => {
                let index = self.gpr_index(*index, reg)?;
                let value = self.coerce_int(builder, value, types::I32)?;
                self.write_w(builder, index, value.value)
            }
            Reg::SP => {
                let value = self.coerce_int(builder, value, types::I64)?;
                Self::write_scalar(builder, &mut self.sp, value.value, types::I64);
                Ok(())
            }
            Reg::PC => {
                let value = self.coerce_int(builder, value, types::I64)?;
                Self::write_scalar(builder, &mut self.pc, value.value, types::I64);
                Ok(())
            }
            Reg::XZR => Ok(()),
            Reg::Flags => {
                let value = self.coerce_int(builder, value, types::I64)?;
                Self::write_scalar(builder, &mut self.flags, value.value, types::I64);
                Ok(())
            }
            Reg::V(index) | Reg::Q(index) => {
                let index = self.simd_index(*index, reg)?;
                let value = self.coerce_value(builder, value, I8X16)?;
                self.write_simd_view(builder, index, value.value, I8X16, SimdKind::Vec)
            }
            Reg::D(index) => {
                let index = self.simd_index(*index, reg)?;
                let value = self.coerce_value(builder, value, types::F64)?;
                self.write_simd_view(builder, index, value.value, types::F64, SimdKind::D)
            }
            Reg::S(index) => {
                let index = self.simd_index(*index, reg)?;
                let value = self.coerce_value(builder, value, types::F32)?;
                self.write_simd_view(builder, index, value.value, types::F32, SimdKind::S)
            }
            Reg::H(index) => {
                let index = self.simd_index(*index, reg)?;
                let value = self.coerce_value(builder, value, types::I16)?;
                self.write_simd_view(builder, index, value.value, types::I16, SimdKind::H)
            }
            Reg::VByte(index) => {
                let index = self.simd_index(*index, reg)?;
                let value = self.coerce_value(builder, value, types::I8)?;
                self.write_simd_view(builder, index, value.value, types::I8, SimdKind::VByte)
            }
        }
    }

    pub(crate) fn read_x(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        if let Some(var) = self.x_regs[index].var {
            return Ok(builder.use_var(var));
        }
        // No X variable yet means the register has not been written in this
        // block (write_w and write_x both define it). A W variable may still
        // exist from an earlier 32-bit read, but that only holds the low half,
        // so the full value has to come from the context.
        let var = builder.declare_var(types::I64);
        let value = Self::load_ctx_scalar(self.ctx_ptr, builder, types::I64, x_offset(index));
        builder.def_var(var, value);
        self.x_regs[index].var = Some(var);
        Ok(value)
    }

    pub(crate) fn write_x(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
        value: Value,
    ) -> Result<(), JitError> {
        Self::write_scalar(builder, &mut self.x_regs[index], value, types::I64);
        let w_var = match self.w_regs[index].var {
            Some(var) => var,
            None => {
                let var = builder.declare_var(types::I32);
                self.w_regs[index].var = Some(var);
                var
            }
        };
        let w_value = builder.ins().ireduce(types::I32, value);
        builder.def_var(w_var, w_value);
        Ok(())
    }

    pub(crate) fn read_w(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        if let Some(var) = self.w_regs[index].var {
            return Ok(builder.use_var(var));
        }
        let var = builder.declare_var(types::I32);
        let value = if let Some(x_var) = self.x_regs[index].var {
            let x = builder.use_var(x_var);
            builder.ins().ireduce(types::I32, x)
        } else {
            let x = Self::load_ctx_scalar(self.ctx_ptr, builder, types::I64, x_offset(index));
            builder.ins().ireduce(types::I32, x)
        };
        builder.def_var(var, value);
        self.w_regs[index].var = Some(var);
        Ok(value)
    }

    pub(crate) fn write_w(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
        value: Value,
    ) -> Result<(), JitError> {
        Self::write_scalar(builder, &mut self.w_regs[index], value, types::I32);
        let x_var = match self.x_regs[index].var {
            Some(var) => var,
            None => {
                let var = builder.declare_var(types::I64);
                self.x_regs[index].var = Some(var);
                var
            }
        };
        let x_value = builder.ins().uextend(types::I64, value);
        builder.def_var(x_var, x_value);
        self.x_regs[index].dirty = true;
        Ok(())
    }

    pub(crate) fn read_sp(&mut self, builder: &mut FunctionBuilder<'_>) -> Result<Value, JitError> {
        Self::read_scalar(
            self.ctx_ptr,
            builder,
            &mut self.sp,
            types::I64,
            offset_of!(JitContext, sp),
        )
    }

    pub(crate) fn read_pc(&mut self, builder: &mut FunctionBuilder<'_>) -> Result<Value, JitError> {
        if let Some(var) = self.pc.var {
            return Ok(builder.use_var(var));
        }
        let var = builder.declare_var(types::I64);
        let value = builder.ins().iconst(types::I64, self.block_addr as i64);
        builder.def_var(var, value);
        self.pc.var = Some(var);
        self.pc.dirty = true;
        Ok(value)
    }

    pub(crate) fn write_pc_immediate(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        value: u64,
    ) -> Result<(), JitError> {
        let value = builder.ins().iconst(types::I64, value as i64);
        self.write_pc_value(builder, value)
    }

    pub(crate) fn write_pc_value(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
    ) -> Result<(), JitError> {
        Self::write_scalar(builder, &mut self.pc, value, types::I64);
        Ok(())
    }

    pub(crate) fn read_flags(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
    ) -> Result<Value, JitError> {
        Self::read_scalar(
            self.ctx_ptr,
            builder,
            &mut self.flags,
            types::I64,
            offset_of!(JitContext, flags),
        )
    }

    pub(crate) fn write_flags_value(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
    ) -> Result<(), JitError> {
        Self::write_scalar(builder, &mut self.flags, value, types::I64);
        Ok(())
    }

    pub(crate) fn read_scalar(
        ctx_ptr: Value,
        builder: &mut FunctionBuilder<'_>,
        scalar: &mut ScalarVar,
        ty: Type,
        offset: usize,
    ) -> Result<Value, JitError> {
        if let Some(var) = scalar.var {
            return Ok(builder.use_var(var));
        }
        let var = builder.declare_var(ty);
        let value = Self::load_ctx_scalar(ctx_ptr, builder, ty, offset);
        builder.def_var(var, value);
        scalar.var = Some(var);
        Ok(value)
    }

    pub(crate) fn write_scalar(
        builder: &mut FunctionBuilder<'_>,
        scalar: &mut ScalarVar,
        value: Value,
        ty: Type,
    ) {
        let var = match scalar.var {
            Some(var) => var,
            None => {
                let var = builder.declare_var(ty);
                scalar.var = Some(var);
                var
            }
        };
        builder.def_var(var, value);
        scalar.dirty = true;
    }

    pub(crate) fn read_vec(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, I8X16, SimdKind::Vec)
    }

    pub(crate) fn read_d(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, types::F64, SimdKind::D)
    }

    pub(crate) fn read_s(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, types::F32, SimdKind::S)
    }

    pub(crate) fn read_h(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, types::I16, SimdKind::H)
    }

    pub(crate) fn read_vbyte(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, types::I8, SimdKind::VByte)
    }

    pub(crate) fn read_simd_view(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
        ty: Type,
        kind: SimdKind,
    ) -> Result<Value, JitError> {
        let slot = self.simd_slot(kind, index);
        if slot.valid {
            if let Some(var) = slot.var {
                return Ok(builder.use_var(var));
            }
        }
        let var = match slot.var {
            Some(var) => var,
            None => {
                let var = builder.declare_var(ty);
                self.simd_slot_mut(kind, index).var = Some(var);
                var
            }
        };
        let value = Self::load_ctx_scalar(self.ctx_ptr, builder, ty, simd_offset(index));
        builder.def_var(var, value);
        self.simd_slot_mut(kind, index).valid = true;
        Ok(value)
    }

    pub(crate) fn write_simd_view(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
        value: Value,
        ty: Type,
        kind: SimdKind,
    ) -> Result<(), JitError> {
        let var = match self.simd_slot(kind, index).var {
            Some(var) => var,
            None => {
                let var = builder.declare_var(ty);
                self.simd_slot_mut(kind, index).var = Some(var);
                var
            }
        };
        builder.def_var(var, value);
        self.simd_slot_mut(kind, index).valid = true;
        if kind != SimdKind::Vec {
            // Writing a scalar view clears the rest of the 128-bit register.
            let zero = builder.ins().iconst(types::I64, 0);
            Self::store_ctx_scalar(self.ctx_ptr, builder, zero, simd_offset(index));
            Self::store_ctx_scalar(self.ctx_ptr, builder, zero, simd_offset(index) + 8);
        }
        Self::store_ctx_scalar(self.ctx_ptr, builder, value, simd_offset(index));
        self.invalidate_simd_aliases(index, kind);
        Ok(())
    }

    pub(crate) fn invalidate_scalars(&mut self) {
        self.x_regs = [ScalarVar::new(); 31];
        self.w_regs = [ScalarVar::new(); 31];
        self.sp = ScalarVar::new();
        self.pc = ScalarVar::new();
        self.flags = ScalarVar::new();
    }

    pub(crate) fn invalidate_all_simd_views(&mut self) {
        self.vec_regs = [SimdVar::new(); 32];
        self.d_regs = [SimdVar::new(); 32];
        self.s_regs = [SimdVar::new(); 32];
        self.h_regs = [SimdVar::new(); 32];
        self.vbyte_regs = [SimdVar::new(); 32];
    }

    pub(crate) fn invalidate_simd_aliases(&mut self, index: usize, keep: SimdKind) {
        for kind in [
            SimdKind::Vec,
            SimdKind::D,
            SimdKind::S,
            SimdKind::H,
            SimdKind::VByte,
        ] {
            if kind == keep {
                continue;
            }
            self.simd_slot_mut(kind, index).valid = false;
        }
    }

    pub(crate) fn invalidate_all_simd_views_for_index(&mut self, index: usize) {
        for kind in [
            SimdKind::Vec,
            SimdKind::D,
            SimdKind::S,
            SimdKind::H,
            SimdKind::VByte,
        ] {
            self.simd_slot_mut(kind, index).valid = false;
        }
    }

    pub(crate) fn snapshot_scalar_dirty(&self) -> ScalarDirtySnapshot {
        ScalarDirtySnapshot {
            x_regs: std::array::from_fn(|index| self.x_regs[index].dirty),
            sp: self.sp.dirty,
            pc: self.pc.dirty,
            flags: self.flags.dirty,
        }
    }

    pub(crate) fn restore_scalar_dirty(&mut self, snapshot: ScalarDirtySnapshot) {
        for (slot, dirty) in self.x_regs.iter_mut().zip(snapshot.x_regs) {
            slot.dirty = dirty;
        }
        self.sp.dirty = snapshot.sp;
        self.pc.dirty = snapshot.pc;
        self.flags.dirty = snapshot.flags;
    }

    pub(crate) fn flush_scalars(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
    ) -> Result<(), JitError> {
        for index in 0..31 {
            if self.x_regs[index].dirty {
                if let Some(var) = self.x_regs[index].var {
                    let value = builder.use_var(var);
                    Self::store_ctx_scalar(self.ctx_ptr, builder, value, x_offset(index));
                    self.x_regs[index].dirty = false;
                }
            }
        }
        Self::flush_scalar(
            self.ctx_ptr,
            builder,
            &mut self.sp,
            offset_of!(JitContext, sp),
        );
        Self::flush_scalar(
            self.ctx_ptr,
            builder,
            &mut self.pc,
            offset_of!(JitContext, pc),
        );
        Self::flush_scalar(
            self.ctx_ptr,
            builder,
            &mut self.flags,
            offset_of!(JitContext, flags),
        );
        Ok(())
    }

    pub(crate) fn flush_scalar(
        ctx_ptr: Value,
        builder: &mut FunctionBuilder<'_>,
        scalar: &mut ScalarVar,
        offset: usize,
    ) {
        if !scalar.dirty {
            return;
        }
        if let Some(var) = scalar.var {
            let value = builder.use_var(var);
            Self::store_ctx_scalar(ctx_ptr, builder, value, offset);
            scalar.dirty = false;
        }
    }

    pub(crate) fn load_ctx_scalar(
        ctx_ptr: Value,
        builder: &mut FunctionBuilder<'_>,
        ty: Type,
        offset: usize,
    ) -> Value {
        let addr = builder.ins().iadd_imm(ctx_ptr, offset as i64);
        builder.ins().load(ty, MemFlags::new(), addr, 0)
    }

    pub(crate) fn store_ctx_scalar(
        ctx_ptr: Value,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
        offset: usize,
    ) {
        let addr = builder.ins().iadd_imm(ctx_ptr, offset as i64);
        builder.ins().store(MemFlags::new(), value, addr, 0);
    }

    pub(crate) fn gpr_index(&self, index: u8, reg: &Reg) -> Result<usize, JitError> {
        if index > 30 {
            return Err(JitError::InvalidRegisterIndex(reg.clone()));
        }
        Ok(index as usize)
    }

    pub(crate) fn simd_index(&self, index: u8, reg: &Reg) -> Result<usize, JitError> {
        if index > 31 {
            return Err(JitError::InvalidRegisterIndex(reg.clone()));
        }
        Ok(index as usize)
    }

    pub(crate) fn simd_slot(&self, kind: SimdKind, index: usize) -> SimdVar {
        match kind {
            SimdKind::Vec => self.vec_regs[index],
            SimdKind::D => self.d_regs[index],
            SimdKind::S => self.s_regs[index],
            SimdKind::H => self.h_regs[index],
            SimdKind::VByte => self.vbyte_regs[index],
        }
    }

    pub(crate) fn simd_slot_mut(&mut self, kind: SimdKind, index: usize) -> &mut SimdVar {
        match kind {
            SimdKind::Vec => &mut self.vec_regs[index],
            SimdKind::D => &mut self.d_regs[index],
            SimdKind::S => &mut self.s_regs[index],
            SimdKind::H => &mut self.h_regs[index],
            SimdKind::VByte => &mut self.vbyte_regs[index],
        }
    }
}
