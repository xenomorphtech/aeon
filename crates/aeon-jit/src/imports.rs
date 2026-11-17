use crate::{JitConfig, JitError, FCMLA_8H_HELPER};
use cranelift_codegen::ir::types::{self};
use cranelift_codegen::ir::{AbiParam, FuncRef, Signature, Type};
use cranelift_frontend::FunctionBuilder;
use cranelift_module::{FuncId, Linkage, Module};

#[derive(Default)]
pub(crate) struct Imports {
    pub(crate) memory_read: Option<FuncRef>,
    pub(crate) trap_hook: Option<FuncRef>,
    pub(crate) branch_translate: Option<FuncRef>,
    pub(crate) branch_bridge: Option<FuncRef>,
    pub(crate) unknown_block: Option<FuncRef>,
    pub(crate) memory_write: Option<FuncRef>,
    pub(crate) block_counter: Option<FuncRef>,
    pub(crate) fcmla_8h: Option<FuncRef>,
    pub(crate) call_sig: Option<cranelift_codegen::ir::SigRef>,
    pub(crate) memory_read_addr_only: bool,
}

impl Imports {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn declare<M: Module>(
        &mut self,
        module: &mut M,
        builder: &mut FunctionBuilder<'_>,
        pointer_type: Type,
        config: JitConfig,
        memory_read_func: Option<FuncId>,
        trap_hook_func: Option<FuncId>,
        branch_translate_hook_func: Option<FuncId>,
        branch_bridge_hook_func: Option<FuncId>,
        unknown_block_hook_func: Option<FuncId>,
        memory_write_func: Option<FuncId>,
        block_counter_func: Option<FuncId>,
        fcmla_8h_func: Option<FuncId>,
        memory_read_addr_only: bool,
        enable_branch_runtime_hooks: bool,
    ) -> Result<(), JitError> {
        if config.instrument_memory || memory_read_func.is_some() {
            let mut read_sig = module.make_signature();
            read_sig.params.push(AbiParam::new(types::I64));
            if !memory_read_addr_only {
                read_sig.params.push(AbiParam::new(types::I8));
            }
            let read = match memory_read_func {
                Some(id) => id,
                None => module.declare_function("on_memory_read", Linkage::Import, &read_sig)?,
            };
            self.memory_read = Some(module.declare_func_in_func(read, builder.func));
            self.memory_read_addr_only = memory_read_addr_only;
        }

        if let Some(trap) = trap_hook_func {
            self.trap_hook = Some(module.declare_func_in_func(trap, builder.func));
        }

        if branch_translate_hook_func.is_some() || enable_branch_runtime_hooks {
            let mut sig = module.make_signature();
            sig.params.push(AbiParam::new(types::I64));
            sig.returns.push(AbiParam::new(types::I64));
            let branch_translate = match branch_translate_hook_func {
                Some(id) => id,
                None => module.declare_function("on_branch_translate", Linkage::Import, &sig)?,
            };
            self.branch_translate =
                Some(module.declare_func_in_func(branch_translate, builder.func));
        }

        if branch_bridge_hook_func.is_some() || enable_branch_runtime_hooks {
            let mut sig = module.make_signature();
            sig.params.push(AbiParam::new(pointer_type));
            sig.params.push(AbiParam::new(types::I64));
            sig.returns.push(AbiParam::new(types::I64));
            let branch_bridge = match branch_bridge_hook_func {
                Some(id) => id,
                None => module.declare_function("on_branch_bridge", Linkage::Import, &sig)?,
            };
            self.branch_bridge = Some(module.declare_func_in_func(branch_bridge, builder.func));
        }

        if let Some(unknown_block) = unknown_block_hook_func {
            self.unknown_block = Some(module.declare_func_in_func(unknown_block, builder.func));
        }

        if config.instrument_memory || memory_write_func.is_some() {
            let mut write_sig = module.make_signature();
            write_sig.params.push(AbiParam::new(types::I64));
            write_sig.params.push(AbiParam::new(types::I8));
            write_sig.params.push(AbiParam::new(types::I64));
            let write = match memory_write_func {
                Some(id) => id,
                None => module.declare_function("on_memory_write", Linkage::Import, &write_sig)?,
            };
            self.memory_write = Some(module.declare_func_in_func(write, builder.func));
        }

        if config.instrument_blocks || block_counter_func.is_some() {
            let mut sig = module.make_signature();
            sig.params.push(AbiParam::new(types::I64));
            let block = match block_counter_func {
                Some(id) => id,
                None => module.declare_function("on_block_enter", Linkage::Import, &sig)?,
            };
            self.block_counter = Some(module.declare_func_in_func(block, builder.func));
        }

        let mut fcmla_sig = module.make_signature();
        fcmla_sig.params.push(AbiParam::new(pointer_type));
        fcmla_sig.params.push(AbiParam::new(types::I64));
        fcmla_sig.params.push(AbiParam::new(types::I64));
        fcmla_sig.params.push(AbiParam::new(types::I64));
        fcmla_sig.params.push(AbiParam::new(types::I64));
        let fcmla = match fcmla_8h_func {
            Some(id) => id,
            None => module.declare_function(FCMLA_8H_HELPER, Linkage::Import, &fcmla_sig)?,
        };
        self.fcmla_8h = Some(module.declare_func_in_func(fcmla, builder.func));

        let mut call_sig = Signature::new(module.isa().default_call_conv());
        call_sig.params.push(AbiParam::new(pointer_type));
        call_sig.returns.push(AbiParam::new(types::I64));
        self.call_sig = Some(builder.import_signature(call_sig));
        Ok(())
    }
}
