use crate::imports::Imports;
use crate::lower::LoweringState;
use crate::{
    JitConfig, JitContext, JitError, FCMLA_8H_HELPER, HELPER_PAD_INSTRUCTIONS,
    OBJECT_BLOCK_ENTER_HOOK, OBJECT_BRANCH_BRIDGE_HOOK, OBJECT_BRANCH_TRANSLATE_HOOK,
    OBJECT_HELPER_PAD, OBJECT_MEMORY_READ_HOOK, OBJECT_TRAP_HOOK, OBJECT_UNKNOWN_BLOCK_HOOK,
};
use aeonil::Stmt;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::types::{self, I8X16};
use cranelift_codegen::ir::{
    AbiParam, Endianness, InstBuilder, MemFlags, StackSlotData, StackSlotKind, Type, UserFuncName,
    Value,
};
use cranelift_codegen::isa::lookup;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_module::{default_libcall_names, FuncId, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use std::collections::BTreeMap;
use std::mem::offset_of;
use target_lexicon::Triple;

pub struct ObjectCompiler {
    config: JitConfig,
    module: ObjectModule,
    next_function_ordinal: u64,
    next_block_id: u64,
    block_ids: BTreeMap<u64, u64>,
    block_symbols: BTreeMap<u64, String>,
    memory_read_hook_symbol: Option<String>,
    trap_hook_symbol: Option<String>,
    branch_translate_hook_symbol: Option<String>,
    branch_bridge_hook_symbol: Option<String>,
    unknown_block_hook_symbol: Option<String>,
    block_enter_hook_symbol: Option<String>,
    memory_read_hook_func: Option<FuncId>,
    trap_hook_func: Option<FuncId>,
    branch_translate_hook_func: Option<FuncId>,
    branch_bridge_hook_func: Option<FuncId>,
    unknown_block_hook_func: Option<FuncId>,
    memory_write_hook_func: Option<FuncId>,
    block_counter_hook_func: Option<FuncId>,
    fcmla_8h_helper_func: Option<FuncId>,
}

pub struct ObjectArtifact {
    pub bytes: Vec<u8>,
    pub block_symbols: BTreeMap<u64, String>,
    pub block_ids: BTreeMap<u64, u64>,
    pub memory_read_hook_symbol: Option<String>,
    pub trap_hook_symbol: Option<String>,
    pub branch_translate_hook_symbol: Option<String>,
    pub branch_bridge_hook_symbol: Option<String>,
    pub unknown_block_hook_symbol: Option<String>,
    pub block_enter_hook_symbol: Option<String>,
}

impl ObjectCompiler {
    pub fn new_aarch64(config: JitConfig) -> Result<Self, JitError> {
        let effective_config = JitConfig {
            instrument_memory: false,
            instrument_blocks: config.instrument_blocks,
        };
        let triple: Triple = "aarch64-unknown-linux-gnu"
            .parse()
            .map_err(|err| JitError::Backend(format!("parse triple: {err}")))?;
        let mut isa_builder =
            lookup(triple).map_err(|err| JitError::Backend(format!("lookup target isa: {err}")))?;
        isa_builder
            .set("has_fp16", "true")
            .map_err(|err| JitError::Backend(format!("set has_fp16: {err}")))?;
        let flags = settings::Flags::new(settings::builder());
        let isa = isa_builder
            .finish(flags)
            .map_err(|err| JitError::Backend(format!("finish target isa: {err}")))?;
        let builder =
            ObjectBuilder::new(isa, "aeon_translated".to_string(), default_libcall_names())
                .map_err(|err| JitError::Backend(format!("object builder: {err}")))?;
        let mut module = ObjectModule::new(builder);
        let pointer_type = module.target_config().pointer_type();
        Self::define_helper_pad(&mut module)?;

        let memory_read_hook_func = if config.instrument_memory {
            Some(Self::define_void_helper(
                &mut module,
                OBJECT_MEMORY_READ_HOOK,
                &[types::I64],
            )?)
        } else {
            None
        };
        let trap_hook_func = if config.instrument_memory {
            Some(Self::define_void_helper(
                &mut module,
                OBJECT_TRAP_HOOK,
                &[types::I64, types::I64, types::I64],
            )?)
        } else {
            None
        };
        let branch_translate_hook_func = Some(Self::define_identity_u64_helper(
            &mut module,
            OBJECT_BRANCH_TRANSLATE_HOOK,
        )?);
        let branch_bridge_hook_func = Some(Self::define_ctx_target_bridge_helper(
            &mut module,
            OBJECT_BRANCH_BRIDGE_HOOK,
            pointer_type,
        )?);
        let unknown_block_hook_func = Some(Self::define_void_helper(
            &mut module,
            OBJECT_UNKNOWN_BLOCK_HOOK,
            &[types::I64],
        )?);
        let memory_write_hook_func = None;
        let block_counter_hook_func = if config.instrument_blocks {
            Some(Self::define_void_helper(
                &mut module,
                OBJECT_BLOCK_ENTER_HOOK,
                &[types::I64],
            )?)
        } else {
            None
        };
        Ok(Self {
            config: effective_config,
            module,
            next_function_ordinal: 0,
            next_block_id: 0,
            block_ids: BTreeMap::new(),
            block_symbols: BTreeMap::new(),
            memory_read_hook_symbol: memory_read_hook_func
                .map(|_| OBJECT_MEMORY_READ_HOOK.to_string()),
            trap_hook_symbol: trap_hook_func.map(|_| OBJECT_TRAP_HOOK.to_string()),
            branch_translate_hook_symbol: branch_translate_hook_func
                .map(|_| OBJECT_BRANCH_TRANSLATE_HOOK.to_string()),
            branch_bridge_hook_symbol: branch_bridge_hook_func
                .map(|_| OBJECT_BRANCH_BRIDGE_HOOK.to_string()),
            unknown_block_hook_symbol: unknown_block_hook_func
                .map(|_| OBJECT_UNKNOWN_BLOCK_HOOK.to_string()),
            block_enter_hook_symbol: block_counter_hook_func
                .map(|_| OBJECT_BLOCK_ENTER_HOOK.to_string()),
            memory_read_hook_func,
            trap_hook_func,
            branch_translate_hook_func,
            branch_bridge_hook_func,
            unknown_block_hook_func,
            memory_write_hook_func,
            block_counter_hook_func,
            fcmla_8h_helper_func: None,
        })
    }

    pub fn compile_block(&mut self, block_addr: u64, stmts: &[Stmt]) -> Result<String, JitError> {
        let block_id = match self.block_ids.get(&block_addr).copied() {
            Some(id) => id,
            None => {
                let id = self.next_block_id;
                self.next_block_id += 1;
                self.block_ids.insert(block_addr, id);
                id
            }
        };

        let pointer_type = self.module.target_config().pointer_type();
        let func_name = format!(
            "aeon_jit_block_{block_addr:016x}_{}",
            self.next_function_ordinal
        );
        self.next_function_ordinal += 1;

        let mut signature = self.module.make_signature();
        signature.params.push(AbiParam::new(pointer_type));
        signature.returns.push(AbiParam::new(types::I64));
        let signature_template = signature.clone();

        let func_id = self
            .module
            .declare_function(&func_name, Linkage::Export, &signature)?;
        let mut ctx = self.module.make_context();
        ctx.func.signature = signature;
        ctx.func.name = UserFuncName::user(0, func_id.as_u32());

        let mut imports = Imports::new();
        let lower_result = {
            let mut func_ctx = FunctionBuilderContext::new();
            let mut builder = FunctionBuilder::new(&mut ctx.func, &mut func_ctx);
            let entry = builder.create_block();
            builder.switch_to_block(entry);
            builder.append_block_params_for_function_params(entry);
            builder.seal_block(entry);

            let ctx_ptr = builder.block_params(entry)[0];
            imports.declare(
                &mut self.module,
                &mut builder,
                pointer_type,
                self.config,
                self.memory_read_hook_func,
                self.trap_hook_func,
                self.branch_translate_hook_func,
                self.branch_bridge_hook_func,
                self.unknown_block_hook_func,
                self.memory_write_hook_func,
                self.block_counter_hook_func,
                self.fcmla_8h_helper_func,
                true,
                false,
                // Object code links against the runtime's own hook symbols.
                None,
            )?;

            let mut state = LoweringState::new(ctx_ptr, pointer_type, block_addr, block_id);
            state.write_pc_immediate(&mut builder, block_addr)?;

            if let Some(counter) = imports.block_counter {
                let block_id_value = builder.ins().iconst(types::I64, block_id as i64);
                builder.ins().call(counter, &[block_id_value]);
            }

            if let Err(err) = state.lower_stmts(&mut self.module, &mut builder, &imports, stmts) {
                Err(err)
            } else {
                if !state.terminated {
                    state.flush_scalars(&mut builder)?;
                    let ret = builder.ins().iconst(types::I64, 0);
                    builder.ins().return_(&[ret]);
                }

                builder.seal_all_blocks();
                builder.finalize();
                Ok(())
            }
        };

        if let Err(err) = lower_result {
            let mut trap_ctx = self.module.make_context();
            trap_ctx.func.signature = signature_template;
            trap_ctx.func.name = UserFuncName::user(0, func_id.as_u32());
            {
                let mut func_ctx = FunctionBuilderContext::new();
                let mut builder = FunctionBuilder::new(&mut trap_ctx.func, &mut func_ctx);
                let entry = builder.create_block();
                builder.switch_to_block(entry);
                builder.append_block_params_for_function_params(entry);
                builder.seal_block(entry);
                builder
                    .ins()
                    .trap(cranelift_codegen::ir::TrapCode::unwrap_user(1));
                builder.seal_all_blocks();
                builder.finalize();
            }
            self.module.define_function(func_id, &mut trap_ctx)?;
            self.module.clear_context(&mut trap_ctx);
            self.block_symbols.insert(block_addr, func_name.clone());
            return Err(err);
        }

        self.module.define_function(func_id, &mut ctx)?;
        self.module.clear_context(&mut ctx);
        self.block_symbols.insert(block_addr, func_name.clone());
        Ok(func_name)
    }

    pub fn finish(self) -> Result<ObjectArtifact, JitError> {
        let object = self.module.finish();
        let bytes = object
            .emit()
            .map_err(|err| JitError::Backend(format!("emit object: {err}")))?;
        Ok(ObjectArtifact {
            bytes,
            block_symbols: self.block_symbols,
            block_ids: self.block_ids,
            memory_read_hook_symbol: self.memory_read_hook_symbol,
            trap_hook_symbol: self.trap_hook_symbol,
            branch_translate_hook_symbol: self.branch_translate_hook_symbol,
            branch_bridge_hook_symbol: self.branch_bridge_hook_symbol,
            unknown_block_hook_symbol: self.unknown_block_hook_symbol,
            block_enter_hook_symbol: self.block_enter_hook_symbol,
        })
    }

    pub(crate) fn define_void_helper(
        module: &mut ObjectModule,
        name: &str,
        params: &[Type],
    ) -> Result<FuncId, JitError> {
        let mut signature = module.make_signature();
        for param in params {
            signature.params.push(AbiParam::new(*param));
        }
        let func_id = module.declare_function(name, Linkage::Export, &signature)?;
        let mut ctx = module.make_context();
        ctx.func.signature = signature;
        ctx.func.name = UserFuncName::user(0, func_id.as_u32());
        {
            let mut fb_ctx = FunctionBuilderContext::new();
            let mut builder = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);
            let entry = builder.create_block();
            builder.switch_to_block(entry);
            builder.append_block_params_for_function_params(entry);
            builder.seal_block(entry);
            let stack_slots = Self::spill_helper_params(&mut builder, params);
            for (slot, ty) in stack_slots.into_iter().zip(params.iter().copied()) {
                let value = builder.ins().stack_load(ty, slot, 0);
                Self::burn_helper_value(&mut builder, value, ty);
            }
            builder.ins().return_(&[]);
            builder.seal_all_blocks();
            builder.finalize();
        }
        module.define_function(func_id, &mut ctx)?;
        module.clear_context(&mut ctx);
        Ok(func_id)
    }

    pub(crate) fn define_identity_u64_helper(
        module: &mut ObjectModule,
        name: &str,
    ) -> Result<FuncId, JitError> {
        let mut signature = module.make_signature();
        signature.params.push(AbiParam::new(types::I64));
        signature.returns.push(AbiParam::new(types::I64));
        let func_id = module.declare_function(name, Linkage::Export, &signature)?;
        let mut ctx = module.make_context();
        ctx.func.signature = signature;
        ctx.func.name = UserFuncName::user(0, func_id.as_u32());
        {
            let mut fb_ctx = FunctionBuilderContext::new();
            let mut builder = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);
            let entry = builder.create_block();
            builder.switch_to_block(entry);
            builder.append_block_params_for_function_params(entry);
            builder.seal_block(entry);
            let params = builder.block_params(entry).to_vec();
            let stack_slots = Self::spill_helper_values(&mut builder, &[(params[0], types::I64)]);
            let ret = builder.ins().stack_load(types::I64, stack_slots[0], 0);
            Self::burn_helper_value(&mut builder, ret, types::I64);
            let ret = builder.ins().stack_load(types::I64, stack_slots[0], 0);
            builder.ins().return_(&[ret]);
            builder.seal_all_blocks();
            builder.finalize();
        }
        module.define_function(func_id, &mut ctx)?;
        module.clear_context(&mut ctx);
        Ok(func_id)
    }

    pub(crate) fn define_ctx_target_bridge_helper(
        module: &mut ObjectModule,
        name: &str,
        pointer_type: Type,
    ) -> Result<FuncId, JitError> {
        let mut signature = module.make_signature();
        signature.params.push(AbiParam::new(pointer_type));
        signature.params.push(AbiParam::new(types::I64));
        signature.returns.push(AbiParam::new(types::I64));
        let func_id = module.declare_function(name, Linkage::Export, &signature)?;
        let mut ctx = module.make_context();
        ctx.func.signature = signature;
        ctx.func.name = UserFuncName::user(0, func_id.as_u32());
        {
            let mut fb_ctx = FunctionBuilderContext::new();
            let mut builder = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);
            let entry = builder.create_block();
            builder.switch_to_block(entry);
            builder.append_block_params_for_function_params(entry);
            builder.seal_block(entry);
            let params = builder.block_params(entry).to_vec();
            let stack_slots = Self::spill_helper_values(
                &mut builder,
                &[(params[0], pointer_type), (params[1], types::I64)],
            );
            let ctx_param = builder.ins().stack_load(pointer_type, stack_slots[0], 0);
            Self::burn_helper_value(&mut builder, ctx_param, pointer_type);
            let ret = builder.ins().stack_load(types::I64, stack_slots[1], 0);
            Self::burn_helper_value(&mut builder, ret, types::I64);
            let ret = builder.ins().stack_load(types::I64, stack_slots[1], 0);
            builder.ins().return_(&[ret]);
            builder.seal_all_blocks();
            builder.finalize();
        }
        module.define_function(func_id, &mut ctx)?;
        module.clear_context(&mut ctx);
        Ok(func_id)
    }

    pub(crate) fn define_helper_pad(module: &mut ObjectModule) -> Result<FuncId, JitError> {
        let signature = module.make_signature();
        let func_id = module.declare_function(OBJECT_HELPER_PAD, Linkage::Local, &signature)?;
        let mut ctx = module.make_context();
        ctx.func.signature = signature;
        ctx.func.name = UserFuncName::user(0, func_id.as_u32());
        {
            let mut fb_ctx = FunctionBuilderContext::new();
            let mut builder = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);
            let entry = builder.create_block();
            builder.switch_to_block(entry);
            builder.append_block_params_for_function_params(entry);
            builder.seal_block(entry);
            let mut acc = builder.ins().iconst(types::I64, 0x41);
            for idx in 0..HELPER_PAD_INSTRUCTIONS {
                let delta = builder.ins().iconst(types::I64, (idx as i64) + 1);
                acc = builder.ins().iadd(acc, delta);
            }
            Self::burn_helper_value(&mut builder, acc, types::I64);
            builder.ins().return_(&[]);
            builder.seal_all_blocks();
            builder.finalize();
        }
        module.define_function(func_id, &mut ctx)?;
        module.clear_context(&mut ctx);
        Ok(func_id)
    }

    pub(crate) fn spill_helper_params(
        builder: &mut FunctionBuilder<'_>,
        params: &[Type],
    ) -> Vec<cranelift_codegen::ir::StackSlot> {
        let values = builder
            .block_params(builder.current_block().expect("current block"))
            .iter()
            .copied()
            .zip(params.iter().copied())
            .collect::<Vec<_>>();
        Self::spill_helper_values(builder, &values)
    }

    pub(crate) fn spill_helper_values(
        builder: &mut FunctionBuilder<'_>,
        values: &[(Value, Type)],
    ) -> Vec<cranelift_codegen::ir::StackSlot> {
        values
            .iter()
            .map(|(value, ty)| {
                let slot = builder.func.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    ty.bytes().max(8),
                    3,
                ));
                builder.ins().stack_store(*value, slot, 0);
                slot
            })
            .collect()
    }

    pub(crate) fn burn_helper_value(builder: &mut FunctionBuilder<'_>, value: Value, ty: Type) {
        match ty {
            types::I8 | types::I16 | types::I32 | types::I64 => {
                let zero = builder.ins().iconst(ty, 0);
                let sink = builder.ins().bxor(value, zero);
                let _ = sink;
            }
            _ => {}
        }
    }

    #[allow(dead_code)]
    pub(crate) fn define_fcmla_8h_helper(
        module: &mut ObjectModule,
        pointer_type: Type,
    ) -> Result<FuncId, JitError> {
        let mut signature = module.make_signature();
        signature.params.push(AbiParam::new(pointer_type));
        signature.params.push(AbiParam::new(types::I64));
        signature.params.push(AbiParam::new(types::I64));
        signature.params.push(AbiParam::new(types::I64));
        signature.params.push(AbiParam::new(types::I64));
        let func_id = module.declare_function(FCMLA_8H_HELPER, Linkage::Export, &signature)?;
        let mut ctx = module.make_context();
        ctx.func.signature = signature;
        ctx.func.name = UserFuncName::user(0, func_id.as_u32());
        {
            let mut fb_ctx = FunctionBuilderContext::new();
            let mut builder = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);
            let entry = builder.create_block();
            builder.switch_to_block(entry);
            builder.append_block_params_for_function_params(entry);
            builder.seal_block(entry);

            let params = builder.block_params(entry).to_vec();
            let ctx_ptr = params[0];
            let dst_index = params[1];
            let src_index = params[2];
            let scalar_pair_bits = params[3];
            let rotation = params[4];

            let f16x8 = types::F16
                .by(8)
                .ok_or_else(|| JitError::Backend("F16X8 unavailable".to_string()))?;
            let vec_flags = MemFlags::new().with_endianness(Endianness::Little);
            let simd_base = builder
                .ins()
                .iadd_imm(ctx_ptr, offset_of!(JitContext, simd) as i64);
            let dst_offset = builder.ins().ishl_imm(dst_index, 4);
            let src_offset = builder.ins().ishl_imm(src_index, 4);
            let dst_addr = builder.ins().iadd(simd_base, dst_offset);
            let src_addr = builder.ins().iadd(simd_base, src_offset);
            let dst_raw = builder.ins().load(I8X16, MemFlags::new(), dst_addr, 0);
            let src_raw = builder.ins().load(I8X16, MemFlags::new(), src_addr, 0);
            let dst_vec = builder.ins().bitcast(f16x8, vec_flags, dst_raw);
            let src_vec = builder.ins().bitcast(f16x8, vec_flags, src_raw);

            let pair_bits = builder.ins().ireduce(types::I32, scalar_pair_bits);
            let scalar_re_bits = builder.ins().ireduce(types::I16, pair_bits);
            let pair_bits_hi = builder.ins().ushr_imm(pair_bits, 16);
            let scalar_im_bits = builder.ins().ireduce(types::I16, pair_bits_hi);
            let scalar_re = builder
                .ins()
                .bitcast(types::F16, MemFlags::new(), scalar_re_bits);
            let scalar_im = builder
                .ins()
                .bitcast(types::F16, MemFlags::new(), scalar_im_bits);
            let neg_re = builder.ins().fneg(scalar_re);
            let neg_im = builder.ins().fneg(scalar_im);
            let is_rot_90 = builder.ins().icmp_imm(IntCC::Equal, rotation, 0x5a);
            let is_rot_180 = builder.ins().icmp_imm(IntCC::Equal, rotation, 0xb4);
            let is_rot_270 = builder.ins().icmp_imm(IntCC::Equal, rotation, 0x10e);
            let rot_re_fallback = builder.ins().select(is_rot_270, scalar_im, scalar_re);
            let rot_re_non90 = builder.ins().select(is_rot_180, neg_re, rot_re_fallback);
            let rot_re = builder.ins().select(is_rot_90, neg_im, rot_re_non90);
            let rot_im_fallback = builder.ins().select(is_rot_270, neg_re, scalar_im);
            let rot_im_non90 = builder.ins().select(is_rot_180, neg_im, rot_im_fallback);
            let rot_im = builder.ins().select(is_rot_90, scalar_re, rot_im_non90);

            let mut out = dst_vec;
            for pair in 0..4u8 {
                let re_lane = pair * 2;
                let im_lane = re_lane + 1;
                let acc_re = builder.ins().extractlane(dst_vec, re_lane);
                let acc_im = builder.ins().extractlane(dst_vec, im_lane);
                let src_re = builder.ins().extractlane(src_vec, re_lane);
                let src_im = builder.ins().extractlane(src_vec, im_lane);
                let src_re_mul_rot_re = builder.ins().fmul(src_re, rot_re);
                let src_im_mul_rot_im = builder.ins().fmul(src_im, rot_im);
                let prod_re = builder.ins().fsub(src_re_mul_rot_re, src_im_mul_rot_im);
                let src_re_mul_rot_im = builder.ins().fmul(src_re, rot_im);
                let src_im_mul_rot_re = builder.ins().fmul(src_im, rot_re);
                let prod_im = builder.ins().fadd(src_re_mul_rot_im, src_im_mul_rot_re);
                let next_re = builder.ins().fadd(acc_re, prod_re);
                out = builder.ins().insertlane(out, next_re, re_lane);
                let next_im = builder.ins().fadd(acc_im, prod_im);
                out = builder.ins().insertlane(out, next_im, im_lane);
            }

            let out_raw = builder.ins().bitcast(I8X16, vec_flags, out);
            builder.ins().store(MemFlags::new(), out_raw, dst_addr, 0);
            builder.ins().return_(&[]);
            builder.seal_all_blocks();
            builder.finalize();
        }
        module.define_function(func_id, &mut ctx)?;
        module.clear_context(&mut ctx);
        Ok(func_id)
    }
}
