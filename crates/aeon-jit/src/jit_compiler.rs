use crate::imports::Imports;
use crate::lower::LoweringState;
use crate::runtime::{
    aeon_fcmla_8h, on_block_enter, on_branch_bridge, on_branch_translate, on_memory_read,
    on_memory_write, BLOCK_COUNTERS_LEN, BLOCK_COUNTERS_PTR, BLOCK_ENTER_CALLBACK,
    BRANCH_BRIDGE_CALLBACK, BRANCH_TRANSLATE_CALLBACK, MEMORY_READ_CALLBACK, MEMORY_WRITE_CALLBACK,
};
use crate::{
    BlockEnterCallback, BranchBridgeCallback, BranchTranslateCallback, JitConfig, JitError,
    MemoryReadCallback, MemoryWriteCallback, FCMLA_8H_HELPER,
};
use aeonil::Stmt;
use cranelift_codegen::ir::types::{self};
use cranelift_codegen::ir::{AbiParam, InstBuilder, UserFuncName};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{default_libcall_names, Linkage, Module};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

pub struct JitCompiler {
    config: JitConfig,
    module: JITModule,
    next_function_ordinal: u64,
    next_block_id: u64,
    block_ids: BTreeMap<u64, u64>,
}

impl JitCompiler {
    pub fn new(config: JitConfig) -> Self {
        let mut builder = JITBuilder::new(default_libcall_names()).expect("native JIT builder");
        builder
            .symbol("on_memory_read", on_memory_read as *const u8)
            .symbol("on_memory_write", on_memory_write as *const u8)
            .symbol("on_branch_translate", on_branch_translate as *const u8)
            .symbol("on_branch_bridge", on_branch_bridge as *const u8)
            .symbol("on_block_enter", on_block_enter as *const u8)
            .symbol(FCMLA_8H_HELPER, aeon_fcmla_8h as *const u8);

        Self {
            config,
            module: JITModule::new(builder),
            next_function_ordinal: 0,
            next_block_id: 0,
            block_ids: BTreeMap::new(),
        }
    }

    pub fn set_memory_read_callback(&mut self, callback: Option<MemoryReadCallback>) {
        MEMORY_READ_CALLBACK.store(
            callback.map(|cb| cb as usize).unwrap_or(0),
            Ordering::SeqCst,
        );
    }

    pub fn set_memory_write_callback(&mut self, callback: Option<MemoryWriteCallback>) {
        MEMORY_WRITE_CALLBACK.store(
            callback.map(|cb| cb as usize).unwrap_or(0),
            Ordering::SeqCst,
        );
    }

    pub fn set_branch_translate_callback(&mut self, callback: Option<BranchTranslateCallback>) {
        BRANCH_TRANSLATE_CALLBACK.store(
            callback.map(|cb| cb as usize).unwrap_or(0),
            Ordering::SeqCst,
        );
    }

    pub fn set_branch_bridge_callback(&mut self, callback: Option<BranchBridgeCallback>) {
        BRANCH_BRIDGE_CALLBACK.store(
            callback.map(|cb| cb as usize).unwrap_or(0),
            Ordering::SeqCst,
        );
    }

    pub fn set_block_counters(&mut self, counters: *mut u64, len: usize) {
        BLOCK_COUNTERS_PTR.store(counters, Ordering::SeqCst);
        BLOCK_COUNTERS_LEN.store(len, Ordering::SeqCst);
    }

    pub fn set_block_enter_callback(&mut self, callback: Option<BlockEnterCallback>) {
        BLOCK_ENTER_CALLBACK.store(
            callback.map(|cb| cb as usize).unwrap_or(0),
            Ordering::SeqCst,
        );
    }

    pub fn block_id(&self, block_addr: u64) -> Option<u64> {
        self.block_ids.get(&block_addr).copied()
    }

    pub fn compile_block(
        &mut self,
        block_addr: u64,
        stmts: &[Stmt],
    ) -> Result<*const u8, JitError> {
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
            .declare_function(&func_name, Linkage::Local, &signature)?;
        let mut ctx = self.module.make_context();
        ctx.func.signature = signature;
        ctx.func.name = UserFuncName::user(0, func_id.as_u32());

        let mut imports = Imports::new();
        let enable_branch_runtime_hooks = BRANCH_TRANSLATE_CALLBACK.load(Ordering::SeqCst) != 0
            || BRANCH_BRIDGE_CALLBACK.load(Ordering::SeqCst) != 0;
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
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                enable_branch_runtime_hooks,
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
            return Err(err);
        }

        self.module.define_function(func_id, &mut ctx)?;
        self.module.clear_context(&mut ctx);
        self.module.finalize_definitions()?;
        Ok(self.module.get_finalized_function(func_id))
    }
}
