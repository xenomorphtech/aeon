use aeonil::{BranchCond, Condition, Expr, Reg, Stmt, TrapKind};
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::immediates::{Ieee32, Ieee64};
use cranelift_codegen::ir::types::{self, F64X2, I16X8, I32X4, I64X2, I8X16};
use cranelift_codegen::ir::{
    AbiParam, Endianness, FuncRef, InstBuilder, MemFlags, Signature, StackSlotData, StackSlotKind,
    Type, UserFuncName, Value,
};
use cranelift_codegen::isa::lookup;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{default_libcall_names, FuncId, Linkage, Module, ModuleError};
use cranelift_object::{ObjectBuilder, ObjectModule};
use half::f16;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem::offset_of;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use target_lexicon::Triple;

pub type MemoryReadCallback = extern "C" fn(u64, u8);
pub type MemoryWriteCallback = extern "C" fn(u64, u8, u64);
pub type BranchTranslateCallback = extern "C" fn(u64) -> u64;
pub type BranchBridgeCallback = extern "C" fn(*mut JitContext, u64) -> u64;
pub type BlockEnterCallback = extern "C" fn(u64);
pub type JitEntry = unsafe extern "C" fn(*mut JitContext) -> u64;
const OBJECT_MEMORY_READ_HOOK: &str = "aeon_log_mem_read";
const OBJECT_TRAP_HOOK: &str = "aeon_log_trap";
const OBJECT_BRANCH_TRANSLATE_HOOK: &str = "aeon_translate_branch_target";
const OBJECT_BRANCH_BRIDGE_HOOK: &str = "aeon_bridge_branch_target";
const OBJECT_UNKNOWN_BLOCK_HOOK: &str = "aeon_unknown_block_addr";
const OBJECT_BLOCK_ENTER_HOOK: &str = "on_block_enter";
const FCMLA_8H_HELPER: &str = "aeon_fcmla_8h";
const OBJECT_HELPER_PAD: &str = "__aeon_helper_pad";
const HELPER_PAD_INSTRUCTIONS: usize = 16;

#[derive(Debug, Clone, Copy, Default)]
pub struct JitConfig {
    pub instrument_memory: bool,
    pub instrument_blocks: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct JitContext {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub flags: u64,
    pub simd: [[u8; 16]; 32],
    /// Thread-local storage base (tpidr_el0). Set this to a valid address
    /// before execution if the target binary reads TLS (stack canaries, etc).
    pub tpidr_el0: u64,
}

#[derive(Debug)]
pub enum JitError {
    Module(ModuleError),
    Backend(String),
    UnsupportedExpr(&'static str),
    UnsupportedStmt(&'static str),
    UnsupportedReg(Reg),
    UnsupportedCondition(Condition),
    InvalidRegisterIndex(Reg),
    InvalidMemorySize(u8),
    StatementAfterTerminator,
    TypeMismatch(&'static str),
}

impl fmt::Display for JitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Module(err) => write!(f, "{err}"),
            Self::Backend(err) => write!(f, "{err}"),
            Self::UnsupportedExpr(kind) => write!(f, "unsupported expression lowering for {kind}"),
            Self::UnsupportedStmt(kind) => write!(f, "unsupported statement lowering for {kind}"),
            Self::UnsupportedReg(reg) => write!(f, "unsupported register {reg:?}"),
            Self::UnsupportedCondition(cond) => write!(f, "unsupported condition {cond:?}"),
            Self::InvalidRegisterIndex(reg) => write!(f, "invalid register index for {reg:?}"),
            Self::InvalidMemorySize(size) => write!(f, "invalid memory size {size}"),
            Self::StatementAfterTerminator => {
                write!(f, "statements after a terminator are not supported")
            }
            Self::TypeMismatch(context) => write!(f, "type mismatch while lowering {context}"),
        }
    }
}

impl Error for JitError {}

impl From<ModuleError> for JitError {
    fn from(value: ModuleError) -> Self {
        Self::Module(value)
    }
}

static MEMORY_READ_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static MEMORY_WRITE_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static BRANCH_TRANSLATE_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static BRANCH_BRIDGE_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static BLOCK_ENTER_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static BLOCK_COUNTERS_PTR: AtomicPtr<u64> = AtomicPtr::new(std::ptr::null_mut());
static BLOCK_COUNTERS_LEN: AtomicUsize = AtomicUsize::new(0);

fn native_log_path() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "/data/user/0/com.netmarble.thered/files/aeon_jit_native.log"
    }
    #[cfg(not(target_os = "android"))]
    {
        "/tmp/aeon_jit_native.log"
    }
}

fn native_log_line(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(native_log_path())
    {
        let _ = writeln!(file, "{message}");
    }
}

pub extern "C" fn on_memory_read(addr: u64, size: u8) {
    native_log_line(&format!("mem_read addr=0x{addr:x} size={size}"));
    let callback = MEMORY_READ_CALLBACK.load(Ordering::SeqCst);
    if callback == 0 {
        return;
    }
    let callback: MemoryReadCallback = unsafe { std::mem::transmute(callback) };
    callback(addr, size);
}

pub extern "C" fn on_memory_write(addr: u64, size: u8, value: u64) {
    native_log_line(&format!(
        "mem_write addr=0x{addr:x} size={size} value=0x{value:x}"
    ));
    let callback = MEMORY_WRITE_CALLBACK.load(Ordering::SeqCst);
    if callback == 0 {
        return;
    }
    let callback: MemoryWriteCallback = unsafe { std::mem::transmute(callback) };
    callback(addr, size, value);
}

pub extern "C" fn on_branch_translate(target: u64) -> u64 {
    native_log_line(&format!("branch_translate in=0x{target:x}"));
    let callback = BRANCH_TRANSLATE_CALLBACK.load(Ordering::SeqCst);
    if callback == 0 {
        return target;
    }
    let callback: BranchTranslateCallback = unsafe { std::mem::transmute(callback) };
    callback(target)
}

pub extern "C" fn on_branch_bridge(ctx: *mut JitContext, target: u64) -> u64 {
    let ctx_pc = unsafe { ctx.as_ref().map(|c| c.pc).unwrap_or(0) };
    native_log_line(&format!(
        "branch_bridge ctx_pc=0x{ctx_pc:x} target=0x{target:x}"
    ));
    let callback = BRANCH_BRIDGE_CALLBACK.load(Ordering::SeqCst);
    if callback == 0 {
        return target;
    }
    let callback: BranchBridgeCallback = unsafe { std::mem::transmute(callback) };
    callback(ctx, target)
}

pub extern "C" fn on_block_enter(block_id: u64) {
    native_log_line(&format!("block_enter id=0x{block_id:x}"));
    let callback = BLOCK_ENTER_CALLBACK.load(Ordering::SeqCst);
    if callback != 0 {
        let callback: BlockEnterCallback = unsafe { std::mem::transmute(callback) };
        callback(block_id);
    }
    let counters = BLOCK_COUNTERS_PTR.load(Ordering::SeqCst);
    let len = BLOCK_COUNTERS_LEN.load(Ordering::SeqCst);
    if counters.is_null() || block_id as usize >= len {
        return;
    }
    unsafe {
        let slot = counters.add(block_id as usize);
        *slot = (*slot).wrapping_add(1);
    }
}

pub extern "C" fn aeon_fcmla_8h(
    ctx: *mut JitContext,
    dst_index: u64,
    src_index: u64,
    scalar_pair_bits: u64,
    rotation: u64,
) {
    let Some(ctx) = (unsafe { ctx.as_mut() }) else {
        return;
    };
    let Ok(dst_index) = usize::try_from(dst_index) else {
        return;
    };
    let Ok(src_index) = usize::try_from(src_index) else {
        return;
    };
    if dst_index >= ctx.simd.len() || src_index >= ctx.simd.len() {
        return;
    }

    let dst = unpack_f16_lanes(ctx.simd[dst_index]);
    let src = unpack_f16_lanes(ctx.simd[src_index]);
    let scalar_lo = f16::from_bits((scalar_pair_bits & 0xffff) as u16);
    let scalar_hi = f16::from_bits(((scalar_pair_bits >> 16) & 0xffff) as u16);
    let (rot_re, rot_im) = rotate_complex_pair_f16(scalar_lo, scalar_hi, rotation);

    let mut out = dst;
    for pair in 0..4 {
        let re_lane = pair * 2;
        let im_lane = re_lane + 1;
        let src_re = src[re_lane];
        let src_im = src[im_lane];
        let acc_re = dst[re_lane];
        let acc_im = dst[im_lane];
        let prod_re = src_re * rot_re - src_im * rot_im;
        let prod_im = src_re * rot_im + src_im * rot_re;
        out[re_lane] = acc_re + prod_re;
        out[im_lane] = acc_im + prod_im;
    }
    ctx.simd[dst_index] = pack_f16_lanes(out);
}

fn unpack_f16_lanes(bytes: [u8; 16]) -> [f16; 8] {
    std::array::from_fn(|lane| {
        let offset = lane * 2;
        f16::from_bits(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
    })
}

fn pack_f16_lanes(values: [f16; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (lane, value) in values.into_iter().enumerate() {
        let offset = lane * 2;
        out[offset..offset + 2].copy_from_slice(&value.to_bits().to_le_bytes());
    }
    out
}

fn rotate_complex_pair_f16(re: f16, im: f16, rotation: u64) -> (f16, f16) {
    match rotation {
        0x0 => (re, im),
        0x5a => (-im, re),
        0xb4 => (-re, -im),
        0x10e => (im, -re),
        _ => (re, im),
    }
}

pub struct JitCompiler {
    config: JitConfig,
    module: JITModule,
    next_function_ordinal: u64,
    next_block_id: u64,
    block_ids: BTreeMap<u64, u64>,
}

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

    fn define_void_helper(
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

    fn define_identity_u64_helper(
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

    fn define_ctx_target_bridge_helper(
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

    fn define_helper_pad(module: &mut ObjectModule) -> Result<FuncId, JitError> {
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

    fn spill_helper_params(
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

    fn spill_helper_values(
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

    fn burn_helper_value(builder: &mut FunctionBuilder<'_>, value: Value, ty: Type) {
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
    fn define_fcmla_8h_helper(
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

#[derive(Default)]
struct Imports {
    memory_read: Option<FuncRef>,
    trap_hook: Option<FuncRef>,
    branch_translate: Option<FuncRef>,
    branch_bridge: Option<FuncRef>,
    unknown_block: Option<FuncRef>,
    memory_write: Option<FuncRef>,
    block_counter: Option<FuncRef>,
    fcmla_8h: Option<FuncRef>,
    call_sig: Option<cranelift_codegen::ir::SigRef>,
    memory_read_addr_only: bool,
}

impl Imports {
    fn new() -> Self {
        Self::default()
    }

    fn declare<M: Module>(
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

#[derive(Clone, Copy, Debug)]
struct ScalarVar {
    var: Option<Variable>,
    dirty: bool,
}

impl ScalarVar {
    const fn new() -> Self {
        Self {
            var: None,
            dirty: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SimdVar {
    var: Option<Variable>,
    valid: bool,
}

impl SimdVar {
    const fn new() -> Self {
        Self {
            var: None,
            valid: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LoweredValue {
    value: Value,
    ty: Type,
}

struct LoweringState {
    ctx_ptr: Value,
    pointer_type: Type,
    block_addr: u64,
    _block_id: u64,
    terminated: bool,
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
struct ScalarDirtySnapshot {
    x_regs: [bool; 31],
    sp: bool,
    pc: bool,
    flags: bool,
}

impl LoweringState {
    fn new(ctx_ptr: Value, pointer_type: Type, block_addr: u64, block_id: u64) -> Self {
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

    fn lower_stmts(
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

    fn lower_stmt(
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
                    builder
                        .ins()
                        .call(callback, &[addr.value, size, callback_value]);
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
                    let translated_call = builder.ins().call(translator, &[target.value]);
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
                        builder.ins().call(bridge, &[self.ctx_ptr, target.value]);
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
                let ret = builder.ins().iconst(types::I64, 0);
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
                    builder.ins().call(callback, &[block_addr, kind, imm]);
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

    fn lower_branch_exit(
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
            let translated_call = builder.ins().call(translator, &[target]);
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
                let bridge_call = builder.ins().call(bridge, &[self.ctx_ptr, target]);
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

    fn lower_branch_cond(
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

    fn lower_expr(
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
                Ok(LoweredValue {
                    value: builder.ins().sdiv(lhs.value, rhs.value),
                    ty,
                })
            }
            Expr::UDiv(lhs, rhs) => {
                let ty = self.resolve_int_type(hint, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                Ok(LoweredValue {
                    value: builder.ins().udiv(lhs.value, rhs.value),
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
                    b.ins().fadd(a, c)
                })
            }
            Expr::FSub(lhs, rhs) => {
                self.lower_float_binop(module, builder, imports, lhs, rhs, hint, |b, a, c| {
                    b.ins().fsub(a, c)
                })
            }
            Expr::FMul(lhs, rhs) => {
                self.lower_float_binop(module, builder, imports, lhs, rhs, hint, |b, a, c| {
                    b.ins().fmul(a, c)
                })
            }
            Expr::FDiv(lhs, rhs) => {
                self.lower_float_binop(module, builder, imports, lhs, rhs, hint, |b, a, c| {
                    b.ins().fdiv(a, c)
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
                    b.ins().sqrt(v)
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
                    value: builder.ins().fcvt_to_sint(target, inner.value),
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

    fn lower_float_binop(
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

    fn lower_float_unop(
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

    fn lower_compare_condition(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        cond: Condition,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<Value, JitError> {
        let inferred = self
            .infer_expr_type(lhs)
            .or_else(|| self.infer_expr_type(rhs));
        if matches!(inferred, Some(types::F32 | types::F64)) {
            let ty = self.resolve_float_type(inferred, None)?;
            let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
            let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
            let lhs = self.coerce_float(builder, lhs, ty)?;
            let rhs = self.coerce_float(builder, rhs, ty)?;
            let cc = self.float_cc(cond)?;
            Ok(builder.ins().fcmp(cc, lhs.value, rhs.value))
        } else {
            let ty = self.resolve_int_type(inferred, None)?;
            let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
            let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
            let lhs = self.coerce_int(builder, lhs, ty)?;
            let rhs = self.coerce_int(builder, rhs, ty)?;
            match self.int_cc(cond) {
                Some(cc) => Ok(builder.ins().icmp(cc, lhs.value, rhs.value)),
                None => {
                    let flags = self.compute_sub_flags(builder, lhs.value, rhs.value, ty)?;
                    self.eval_flags_condition(builder, flags, cond)
                }
            }
        }
    }

    fn lower_flags_expr(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        expr: &Expr,
    ) -> Result<Value, JitError> {
        if let Some(ty) = self.infer_expr_type(expr).filter(|ty| ty.is_float()) {
            let value = self.lower_expr(module, builder, imports, expr, Some(ty))?;
            let value = self.coerce_float(builder, value, ty)?;
            let bits_ty = int_type_for_bits(ty.bits().try_into().unwrap())
                .ok_or(JitError::TypeMismatch("float flags bits"))?;
            let bits = builder.ins().bitcast(bits_ty, MemFlags::new(), value.value);
            return self.pack_nzcv(builder, bits, bits_ty, None, None);
        }
        match expr {
            Expr::Imm(bits) => Ok(builder.ins().iconst(types::I64, *bits as i64)),
            Expr::CondSelect {
                cond,
                if_true,
                if_false,
            } => {
                let flags = self.read_flags(builder)?;
                let cond = self.eval_flags_condition(builder, flags, *cond)?;
                let if_true = self.lower_flags_expr(module, builder, imports, if_true)?;
                let if_false = self.lower_flags_expr(module, builder, imports, if_false)?;
                Ok(builder.ins().select(cond, if_true, if_false))
            }
            Expr::Add(lhs, rhs) => {
                let ty = self.resolve_int_type(None, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                self.compute_add_flags(builder, lhs.value, rhs.value, ty)
            }
            Expr::Sub(lhs, rhs) => {
                let ty = self.resolve_int_type(None, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                self.compute_sub_flags(builder, lhs.value, rhs.value, ty)
            }
            Expr::And(lhs, rhs) => {
                let ty = self.resolve_int_type(None, Some(expr))?;
                let lhs = self.lower_expr(module, builder, imports, lhs, Some(ty))?;
                let rhs = self.lower_expr(module, builder, imports, rhs, Some(ty))?;
                let lhs = self.coerce_int(builder, lhs, ty)?;
                let rhs = self.coerce_int(builder, rhs, ty)?;
                let result = builder.ins().band(lhs.value, rhs.value);
                self.pack_nzcv(builder, result, ty, None, None)
            }
            _ => {
                let ty = self.resolve_int_type(None, Some(expr))?;
                let value = self.lower_expr(module, builder, imports, expr, Some(ty))?;
                let value = self.coerce_int(builder, value, ty)?;
                self.pack_nzcv(builder, value.value, ty, None, None)
            }
        }
    }

    fn compute_add_flags(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        lhs: Value,
        rhs: Value,
        ty: Type,
    ) -> Result<Value, JitError> {
        let result = builder.ins().iadd(lhs, rhs);
        let carry = builder.ins().icmp(IntCC::UnsignedLessThan, result, lhs);
        let lhs_neg = self.is_negative(builder, lhs, ty)?;
        let rhs_neg = self.is_negative(builder, rhs, ty)?;
        let res_neg = self.is_negative(builder, result, ty)?;
        let same_sign = builder.ins().icmp(IntCC::Equal, lhs_neg, rhs_neg);
        let sign_changed = builder.ins().icmp(IntCC::NotEqual, lhs_neg, res_neg);
        let overflow = builder.ins().band(same_sign, sign_changed);
        self.pack_nzcv(builder, result, ty, Some(carry), Some(overflow))
    }

    fn compute_sub_flags(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        lhs: Value,
        rhs: Value,
        ty: Type,
    ) -> Result<Value, JitError> {
        let result = builder.ins().isub(lhs, rhs);
        let carry = builder
            .ins()
            .icmp(IntCC::UnsignedGreaterThanOrEqual, lhs, rhs);
        let lhs_neg = self.is_negative(builder, lhs, ty)?;
        let rhs_neg = self.is_negative(builder, rhs, ty)?;
        let res_neg = self.is_negative(builder, result, ty)?;
        let operands_differ = builder.ins().icmp(IntCC::NotEqual, lhs_neg, rhs_neg);
        let sign_changed = builder.ins().icmp(IntCC::NotEqual, lhs_neg, res_neg);
        let overflow = builder.ins().band(operands_differ, sign_changed);
        self.pack_nzcv(builder, result, ty, Some(carry), Some(overflow))
    }

    fn pack_nzcv(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        result: Value,
        ty: Type,
        carry: Option<Value>,
        overflow: Option<Value>,
    ) -> Result<Value, JitError> {
        let n = self.is_negative(builder, result, ty)?;
        let zero = self.zero_for_type(builder, ty)?;
        let z = builder.ins().icmp(IntCC::Equal, result, zero);
        let c = carry.unwrap_or_else(|| builder.ins().iconst(types::I8, 0));
        let v = overflow.unwrap_or_else(|| builder.ins().iconst(types::I8, 0));
        let n = builder.ins().uextend(types::I64, n);
        let z = builder.ins().uextend(types::I64, z);
        let c = builder.ins().uextend(types::I64, c);
        let v = builder.ins().uextend(types::I64, v);
        let n = builder.ins().ishl_imm(n, 3);
        let z = builder.ins().ishl_imm(z, 2);
        let c = builder.ins().ishl_imm(c, 1);
        let nz = builder.ins().bor(n, z);
        let cv = builder.ins().bor(c, v);
        Ok(builder.ins().bor(nz, cv))
    }

    fn eval_flags_condition(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        flags: Value,
        cond: Condition,
    ) -> Result<Value, JitError> {
        let n = self.extract_flag(builder, flags, 3);
        let z = self.extract_flag(builder, flags, 2);
        let c = self.extract_flag(builder, flags, 1);
        let v = self.extract_flag(builder, flags, 0);
        let one = builder.ins().iconst(types::I8, 1);
        let zero = builder.ins().iconst(types::I8, 0);
        let not = |b: &mut FunctionBuilder<'_>, value: Value| b.ins().bxor(value, one);
        Ok(match cond {
            Condition::EQ => z,
            Condition::NE => not(builder, z),
            Condition::CS => c,
            Condition::CC => not(builder, c),
            Condition::MI => n,
            Condition::PL => not(builder, n),
            Condition::VS => v,
            Condition::VC => not(builder, v),
            Condition::HI => {
                let not_z = not(builder, z);
                builder.ins().band(c, not_z)
            }
            Condition::LS => {
                let not_c = not(builder, c);
                builder.ins().bor(not_c, z)
            }
            Condition::GE => builder.ins().icmp(IntCC::Equal, n, v),
            Condition::LT => builder.ins().icmp(IntCC::NotEqual, n, v),
            Condition::GT => {
                let not_z = not(builder, z);
                let nv_equal = builder.ins().icmp(IntCC::Equal, n, v);
                builder.ins().band(not_z, nv_equal)
            }
            Condition::LE => {
                let nv_not_equal = builder.ins().icmp(IntCC::NotEqual, n, v);
                builder.ins().bor(z, nv_not_equal)
            }
            Condition::AL => one,
            Condition::NV => zero,
        })
    }

    fn read_reg(
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

    fn write_reg(
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

    fn read_x(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        if let Some(var) = self.x_regs[index].var {
            return Ok(builder.use_var(var));
        }
        let var = builder.declare_var(types::I64);
        let value = if let Some(w_var) = self.w_regs[index].var {
            let w = builder.use_var(w_var);
            builder.ins().uextend(types::I64, w)
        } else {
            Self::load_ctx_scalar(self.ctx_ptr, builder, types::I64, x_offset(index))
        };
        builder.def_var(var, value);
        self.x_regs[index].var = Some(var);
        Ok(value)
    }

    fn write_x(
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

    fn read_w(
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

    fn write_w(
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

    fn read_sp(&mut self, builder: &mut FunctionBuilder<'_>) -> Result<Value, JitError> {
        Self::read_scalar(
            self.ctx_ptr,
            builder,
            &mut self.sp,
            types::I64,
            offset_of!(JitContext, sp),
        )
    }

    fn read_pc(&mut self, builder: &mut FunctionBuilder<'_>) -> Result<Value, JitError> {
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

    fn write_pc_immediate(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        value: u64,
    ) -> Result<(), JitError> {
        let value = builder.ins().iconst(types::I64, value as i64);
        self.write_pc_value(builder, value)
    }

    fn write_pc_value(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
    ) -> Result<(), JitError> {
        Self::write_scalar(builder, &mut self.pc, value, types::I64);
        Ok(())
    }

    fn read_flags(&mut self, builder: &mut FunctionBuilder<'_>) -> Result<Value, JitError> {
        Self::read_scalar(
            self.ctx_ptr,
            builder,
            &mut self.flags,
            types::I64,
            offset_of!(JitContext, flags),
        )
    }

    fn write_flags_value(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
    ) -> Result<(), JitError> {
        Self::write_scalar(builder, &mut self.flags, value, types::I64);
        Ok(())
    }

    fn read_scalar(
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

    fn write_scalar(
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

    fn read_vec(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, I8X16, SimdKind::Vec)
    }

    fn read_d(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, types::F64, SimdKind::D)
    }

    fn read_s(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, types::F32, SimdKind::S)
    }

    fn read_h(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, types::I16, SimdKind::H)
    }

    fn read_vbyte(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        index: usize,
    ) -> Result<Value, JitError> {
        self.read_simd_view(builder, index, types::I8, SimdKind::VByte)
    }

    fn read_simd_view(
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

    fn write_simd_view(
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
        Self::store_ctx_scalar(self.ctx_ptr, builder, value, simd_offset(index));
        self.invalidate_simd_aliases(index, kind);
        Ok(())
    }

    fn invalidate_scalars(&mut self) {
        self.x_regs = [ScalarVar::new(); 31];
        self.w_regs = [ScalarVar::new(); 31];
        self.sp = ScalarVar::new();
        self.pc = ScalarVar::new();
        self.flags = ScalarVar::new();
    }

    fn invalidate_all_simd_views(&mut self) {
        self.vec_regs = [SimdVar::new(); 32];
        self.d_regs = [SimdVar::new(); 32];
        self.s_regs = [SimdVar::new(); 32];
        self.h_regs = [SimdVar::new(); 32];
        self.vbyte_regs = [SimdVar::new(); 32];
    }

    fn invalidate_simd_aliases(&mut self, index: usize, keep: SimdKind) {
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

    fn invalidate_all_simd_views_for_index(&mut self, index: usize) {
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

    fn snapshot_scalar_dirty(&self) -> ScalarDirtySnapshot {
        ScalarDirtySnapshot {
            x_regs: std::array::from_fn(|index| self.x_regs[index].dirty),
            sp: self.sp.dirty,
            pc: self.pc.dirty,
            flags: self.flags.dirty,
        }
    }

    fn restore_scalar_dirty(&mut self, snapshot: ScalarDirtySnapshot) {
        for (slot, dirty) in self.x_regs.iter_mut().zip(snapshot.x_regs) {
            slot.dirty = dirty;
        }
        self.sp.dirty = snapshot.sp;
        self.pc.dirty = snapshot.pc;
        self.flags.dirty = snapshot.flags;
    }

    fn lower_mrs_read(
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

    fn lower_expr_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
        operands: &[Expr],
        hint: Option<Type>,
    ) -> Result<LoweredValue, JitError> {
        match intrinsic_base_name(name) {
            "scvtf" | "ucvtf" | "fcvtzs" | "fcvtzu" => {
                self.lower_vector_conversion_intrinsic(module, builder, imports, name, operands)
            }
            // Bitwise vector operations (arrangement-independent)
            "and" => self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                b.ins().band(a, c)
            }),
            "orr" => self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                b.ins().bor(a, c)
            }),
            "eor" => self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                b.ins().bxor(a, c)
            }),
            "orn" => self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                let not_c = b.ins().bnot(c);
                b.ins().bor(a, not_c)
            }),
            "bic" => self.lower_simd_binop(module, builder, imports, operands, |b, a, c| {
                let not_c = b.ins().bnot(c);
                b.ins().band(a, not_c)
            }),
            "bsl" => {
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
            "bit" => {
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
            "bif" => {
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
            "mvn" | "not" => {
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
            "frintz" => self.lower_float_rounding_intrinsic(
                module,
                builder,
                imports,
                operands,
                hint,
                |b, v| b.ins().trunc(v),
            ),
            "frintm" => self.lower_float_rounding_intrinsic(
                module,
                builder,
                imports,
                operands,
                hint,
                |b, v| b.ins().floor(v),
            ),
            "frintp" => self.lower_float_rounding_intrinsic(
                module,
                builder,
                imports,
                operands,
                hint,
                |b, v| b.ins().ceil(v),
            ),
            "frintn" | "frinta" | "frintx" => self.lower_float_rounding_intrinsic(
                module,
                builder,
                imports,
                operands,
                hint,
                |b, v| b.ins().nearest(v),
            ),
            // FNMADD: -(a*b) + c  →  fneg(fma(a, b, fneg(c)))
            // Actually: FNMADD rd, rn, rm, ra = -(rn*rm) - ra
            "fnmadd" => {
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
            "fnmsub" => {
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
            "rev16" => {
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
            "rev32" => {
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
            "cnt" => {
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
            "ngc" => {
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
            "adc" => {
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
            "sbc" => {
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
            "smulh" => {
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
            "umulh" => {
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
            "movk" => {
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

    fn lower_simd_binop(
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

    fn lower_vector_conversion_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
        operands: &[Expr],
    ) -> Result<LoweredValue, JitError> {
        if operands.is_empty() {
            return Err(JitError::UnsupportedExpr("vector conversion operand count"));
        }
        let arrangement = intrinsic_arrangement(name)
            .ok_or(JitError::UnsupportedExpr("vector conversion arrangement"))?;
        let src = self.lower_expr(module, builder, imports, &operands[0], Some(I8X16))?;
        let src = self.coerce_value(builder, src, I8X16)?;

        match (intrinsic_base_name(name), arrangement) {
            ("scvtf", "2d") => {
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
            ("ucvtf", "2d") => {
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
            ("fcvtzs", "2d") => {
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
            ("fcvtzu", "2d") => {
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

    fn lower_float_rounding_intrinsic(
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

    fn lower_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        match intrinsic_base_name(name) {
            "nop" | "yield" | "hint" | "paciasp" | "autiasp" | "bti" | "xpaclri" | "prfm"
            | "prfum" | "clrex" => Ok(()),
            "ushr" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Ushr,
            ),
            "urshr" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Urshr,
            ),
            "usra" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Usra,
            ),
            "ursra" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Ursra,
            ),
            "sli" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Sli,
            ),
            "sri" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Sri,
            ),
            "sqshlu" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Sqshlu,
            ),
            "uqshl" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Uqshl,
            ),
            "uxtl" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Uxtl,
            ),
            "ushll2" => self.lower_vector_shift_stmt_intrinsic(
                module,
                builder,
                imports,
                name,
                operands,
                VectorShiftKind::Ushll2,
            ),
            "ld1" => {
                self.lower_ldst1_stmt_intrinsic(module, builder, imports, name, operands, true)
            }
            "st1" => {
                self.lower_ldst1_stmt_intrinsic(module, builder, imports, name, operands, false)
            }
            "movi" => self.lower_vector_immediate_stmt_intrinsic(builder, name, operands, false),
            "mvni" => self.lower_vector_immediate_stmt_intrinsic(builder, name, operands, true),
            "uqrshrn2" => {
                self.lower_uqrshrn2_stmt_intrinsic(module, builder, imports, name, operands)
            }
            "fcmla" => self.lower_fcmla_stmt_intrinsic(module, builder, imports, name, operands),
            "fmulx" => self.lower_fmulx_stmt_intrinsic(module, builder, imports, name, operands),
            "sqrdmlah" => {
                self.lower_sqrdmlx_stmt_intrinsic(module, builder, imports, name, operands, false)
            }
            "sqrdmlsh" => {
                self.lower_sqrdmlx_stmt_intrinsic(module, builder, imports, name, operands, true)
            }
            "mla" => {
                self.lower_vector_mul_acc_intrinsic(module, builder, imports, name, operands, false)
            }
            "mls" => {
                self.lower_vector_mul_acc_intrinsic(module, builder, imports, name, operands, true)
            }
            "umull2" => {
                self.lower_widening_lane_mul_intrinsic(module, builder, imports, operands, false)
            }
            "umlal2" => self.lower_widening_lane_mul_acc_intrinsic(
                module, builder, imports, operands, false, false,
            ),
            "umlsl2" => self.lower_widening_lane_mul_acc_intrinsic(
                module, builder, imports, operands, false, true,
            ),
            "smull2" => {
                self.lower_widening_lane_mul_intrinsic(module, builder, imports, operands, true)
            }
            "msr" => {
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
            "fccmp" | "fccmpe" => {
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
            "ubfx" => {
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
            "ubfiz" => {
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
            "sbfx" => {
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
            "sbfiz" => {
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
            "bfi" => {
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
            "bfxil" => {
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
            "extr" => {
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

    fn lower_vector_mul_acc_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
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
        let layout = parse_vector_arrangement(name)
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

    fn lower_sqrdmlx_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
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
        let layout = parse_vector_arrangement(name)
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

    fn lower_vector_immediate_stmt_intrinsic(
        &mut self,
        builder: &mut FunctionBuilder<'_>,
        name: &str,
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
        let layout = parse_vector_arrangement(name)
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

    fn lower_uqrshrn2_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        if operands.len() < 3 {
            return Err(JitError::UnsupportedStmt("uqrshrn2 operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("uqrshrn2 dest")),
        };
        let layout = parse_vector_arrangement(name)
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

    fn lower_fcmla_stmt_intrinsic(
        &mut self,
        _module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
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
        let layout =
            parse_vector_arrangement(name).ok_or(JitError::UnsupportedStmt("fcmla arrangement"))?;
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

    fn lower_fmulx_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        if operands.len() < 3 {
            return Err(JitError::UnsupportedStmt("fmulx operand count"));
        }
        let dst_reg = match &operands[0] {
            Expr::Reg(reg) => reg.clone(),
            _ => return Err(JitError::UnsupportedStmt("fmulx dest")),
        };
        let layout =
            parse_vector_arrangement(name).ok_or(JitError::UnsupportedStmt("fmulx arrangement"))?;
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

    fn lower_ldst1_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
        operands: &[Expr],
        is_load: bool,
    ) -> Result<(), JitError> {
        if operands.len() < 2 {
            return Err(JitError::UnsupportedStmt("ld1/st1 operand count"));
        }
        let layout = parse_vector_arrangement(name)
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

    fn lower_widening_lane_mul_acc_intrinsic(
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

    fn lower_widening_lane_mul_intrinsic(
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

    fn lower_vector_shift_stmt_intrinsic(
        &mut self,
        module: &mut impl Module,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
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
        let layout = parse_vector_arrangement(name)
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

    fn lower_vector_shift_lane(
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

    /// Emit unsigned 64×64→128 multiply, return upper 64 bits.
    /// Uses the identity: (a_hi*2^32 + a_lo) * (b_hi*2^32 + b_lo)
    ///   = a_hi*b_hi*2^64 + (a_hi*b_lo + a_lo*b_hi)*2^32 + a_lo*b_lo
    /// Carefully tracks carries in the middle terms to avoid overflow.
    fn emit_umulh(
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
    fn emit_smulh(
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

    fn extract_bitfield_operands(
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

    fn lower_bitfield_stmt(
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

    fn flush_scalars(&mut self, builder: &mut FunctionBuilder<'_>) -> Result<(), JitError> {
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

    fn flush_scalar(
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

    fn load_ctx_scalar(
        ctx_ptr: Value,
        builder: &mut FunctionBuilder<'_>,
        ty: Type,
        offset: usize,
    ) -> Value {
        let addr = builder.ins().iadd_imm(ctx_ptr, offset as i64);
        builder.ins().load(ty, MemFlags::new(), addr, 0)
    }

    fn store_ctx_scalar(
        ctx_ptr: Value,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
        offset: usize,
    ) {
        let addr = builder.ins().iadd_imm(ctx_ptr, offset as i64);
        builder.ins().store(MemFlags::new(), value, addr, 0);
    }

    fn resolve_value_type(
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

    fn resolve_int_type(&self, hint: Option<Type>, expr: Option<&Expr>) -> Result<Type, JitError> {
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

    fn resolve_float_type(
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

    fn infer_expr_type(&self, expr: &Expr) -> Option<Type> {
        match expr {
            Expr::Reg(reg) => reg_type(reg).ok(),
            Expr::Imm(_) | Expr::AdrpImm(_) | Expr::AdrImm(_) | Expr::StackSlot { .. } => {
                Some(types::I64)
            }
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
            | Expr::Ror(lhs, rhs) => self
                .infer_expr_type(lhs)
                .or_else(|| self.infer_expr_type(rhs))
                .or(Some(types::I64)),
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

    fn load_type(&self, size: u8, hint: Option<Type>) -> Result<Type, JitError> {
        if let Some(hint) = hint {
            if type_size_bytes(hint) == usize::from(size) && (hint.is_float() || hint.is_vector()) {
                return Ok(hint);
            }
        }
        type_for_memory_size(size)
    }

    fn store_type_for_value(&self, value: &Expr, size: u8) -> Result<Type, JitError> {
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

    fn coerce_value(
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

    fn coerce_int(
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

    fn coerce_float(
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

    fn value_as_u64_bits(
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

    fn saturate_signed_value(
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

    fn saturate_unsigned_value(
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

    fn bitcast_value(
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

    fn zero_for_type(
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

    fn all_ones(&self, builder: &mut FunctionBuilder<'_>, ty: Type) -> Result<Value, JitError> {
        if !ty.is_int() {
            return Err(JitError::TypeMismatch("all ones"));
        }
        Ok(builder.ins().iconst(ty, -1))
    }

    fn iconst(
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

    fn mask_for_width(
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

    fn mask_for_bit(
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

    fn extract_flag(&self, builder: &mut FunctionBuilder<'_>, flags: Value, bit: u8) -> Value {
        let shifted = builder.ins().ushr_imm(flags, i64::from(bit));
        let masked = builder.ins().band_imm(shifted, 1);
        builder.ins().ireduce(types::I8, masked)
    }

    fn is_negative(
        &self,
        builder: &mut FunctionBuilder<'_>,
        value: Value,
        ty: Type,
    ) -> Result<Value, JitError> {
        let zero = self.zero_for_type(builder, ty)?;
        Ok(builder.ins().icmp(IntCC::SignedLessThan, value, zero))
    }

    fn reverse_bits(
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

    fn int_cc(&self, cond: Condition) -> Option<IntCC> {
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

    fn float_cc(&self, cond: Condition) -> Result<FloatCC, JitError> {
        match cond {
            Condition::EQ => Ok(FloatCC::Equal),
            Condition::NE => Ok(FloatCC::NotEqual),
            Condition::GE => Ok(FloatCC::GreaterThanOrEqual),
            Condition::LT => Ok(FloatCC::LessThan),
            Condition::GT => Ok(FloatCC::GreaterThan),
            Condition::LE => Ok(FloatCC::LessThanOrEqual),
            _ => Err(JitError::UnsupportedCondition(cond)),
        }
    }

    fn condition_from_u8(&self, val: u8) -> Result<Condition, JitError> {
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

    fn gpr_index(&self, index: u8, reg: &Reg) -> Result<usize, JitError> {
        if index > 30 {
            return Err(JitError::InvalidRegisterIndex(reg.clone()));
        }
        Ok(index as usize)
    }

    fn simd_index(&self, index: u8, reg: &Reg) -> Result<usize, JitError> {
        if index > 31 {
            return Err(JitError::InvalidRegisterIndex(reg.clone()));
        }
        Ok(index as usize)
    }

    fn simd_slot(&self, kind: SimdKind, index: usize) -> SimdVar {
        match kind {
            SimdKind::Vec => self.vec_regs[index],
            SimdKind::D => self.d_regs[index],
            SimdKind::S => self.s_regs[index],
            SimdKind::H => self.h_regs[index],
            SimdKind::VByte => self.vbyte_regs[index],
        }
    }

    fn simd_slot_mut(&mut self, kind: SimdKind, index: usize) -> &mut SimdVar {
        match kind {
            SimdKind::Vec => &mut self.vec_regs[index],
            SimdKind::D => &mut self.d_regs[index],
            SimdKind::S => &mut self.s_regs[index],
            SimdKind::H => &mut self.h_regs[index],
            SimdKind::VByte => &mut self.vbyte_regs[index],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SimdKind {
    Vec,
    D,
    S,
    H,
    VByte,
}

#[derive(Clone, Copy)]
struct ParsedVectorArrangement {
    lanes: u8,
    lane_bits: u8,
}

#[derive(Clone, Copy)]
enum VectorShiftKind {
    Ushr,
    Urshr,
    Usra,
    Ursra,
    Sli,
    Sri,
    Sqshlu,
    Uqshl,
    Uxtl,
    Ushll2,
}

fn reg_type(reg: &Reg) -> Result<Type, JitError> {
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

fn intrinsic_base_name(name: &str) -> &str {
    name.split('.').next().unwrap_or(name)
}

fn intrinsic_arrangement(name: &str) -> Option<&str> {
    name.split_once('.').map(|(_, arrangement)| arrangement)
}

fn parse_vector_arrangement(name: &str) -> Option<ParsedVectorArrangement> {
    let arrangement = intrinsic_arrangement(name)?;
    let split = arrangement
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(index, _)| index)?;
    let lanes = arrangement[..split].parse::<u8>().ok()?;
    let lane_bits = match &arrangement[split..] {
        "b" => 8,
        "h" => 16,
        "s" => 32,
        "d" => 64,
        _ => return None,
    };
    Some(ParsedVectorArrangement { lanes, lane_bits })
}

fn vector_lane_type(bits: u8) -> Result<Type, JitError> {
    match bits {
        8 => Ok(types::I8),
        16 => Ok(types::I16),
        32 => Ok(types::I32),
        64 => Ok(types::I64),
        _ => Err(JitError::UnsupportedExpr("vector lane type")),
    }
}

fn vector_type_for_layout(layout: ParsedVectorArrangement) -> Result<Type, JitError> {
    match (layout.lanes, layout.lane_bits) {
        (16, 8) => Ok(I8X16),
        (8, 16) => Ok(I16X8),
        (4, 32) => Ok(I32X4),
        (2, 64) => Ok(I64X2),
        _ => Err(JitError::UnsupportedExpr("vector layout")),
    }
}

fn parse_single_multi_reg_operand(expr: &Expr) -> Option<Reg> {
    let Expr::Intrinsic { name, operands } = expr else {
        return None;
    };
    if name != "multi_reg" || operands.len() != 1 {
        return None;
    }
    match &operands[0] {
        Expr::Reg(reg) => Some(reg.clone()),
        _ => None,
    }
}

fn base_reg_operand(expr: &Expr) -> Option<Reg> {
    match expr {
        Expr::Reg(reg) => Some(reg.clone()),
        _ => None,
    }
}

fn is_supported_barrier(kind: &str) -> bool {
    matches!(kind, "dmb" | "dsb" | "isb")
}

fn trap_kind_code(kind: TrapKind) -> i64 {
    match kind {
        TrapKind::Brk => 1,
        TrapKind::Udf => 2,
    }
}

fn type_for_memory_size(size: u8) -> Result<Type, JitError> {
    match size {
        1 => Ok(types::I8),
        2 => Ok(types::I16),
        4 => Ok(types::I32),
        8 => Ok(types::I64),
        16 => Ok(I8X16),
        _ => Err(JitError::InvalidMemorySize(size)),
    }
}

fn int_type_for_bits(bits: u16) -> Option<Type> {
    match bits {
        0..=8 => Some(types::I8),
        9..=16 => Some(types::I16),
        17..=32 => Some(types::I32),
        33..=64 => Some(types::I64),
        65..=128 => Some(types::I128),
        _ => None,
    }
}

fn type_size_bytes(ty: Type) -> usize {
    ty.bytes() as usize
}

fn x_offset(index: usize) -> usize {
    offset_of!(JitContext, x) + index * std::mem::size_of::<u64>()
}

fn simd_offset(index: usize) -> usize {
    offset_of!(JitContext, simd) + index * 16
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    static READ_COUNT: AtomicUsize = AtomicUsize::new(0);
    static WRITE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static BRIDGE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static LAST_READ_ADDR: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_ADDR: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_VALUE: AtomicU64 = AtomicU64::new(0);
    static LAST_TRANSLATE_TARGET: AtomicU64 = AtomicU64::new(0);
    static LAST_BRIDGE_TARGET: AtomicU64 = AtomicU64::new(0);
    static LAST_BRIDGE_CTX_X30: AtomicU64 = AtomicU64::new(0);

    extern "C" fn test_on_memory_read(addr: u64, _size: u8) {
        READ_COUNT.fetch_add(1, Ordering::SeqCst);
        LAST_READ_ADDR.store(addr, Ordering::SeqCst);
    }

    extern "C" fn test_on_memory_write(addr: u64, _size: u8, value: u64) {
        WRITE_COUNT.fetch_add(1, Ordering::SeqCst);
        LAST_WRITE_ADDR.store(addr, Ordering::SeqCst);
        LAST_WRITE_VALUE.store(value, Ordering::SeqCst);
    }

    extern "C" fn test_branch_translate_dynamic(target: u64) -> u64 {
        LAST_TRANSLATE_TARGET.store(target, Ordering::SeqCst);
        0
    }

    extern "C" fn test_branch_translate_identity(target: u64) -> u64 {
        LAST_TRANSLATE_TARGET.store(target, Ordering::SeqCst);
        target
    }

    extern "C" fn test_branch_bridge_count(_ctx: *mut JitContext, target: u64) -> u64 {
        BRIDGE_COUNT.fetch_add(1, Ordering::SeqCst);
        LAST_BRIDGE_TARGET.store(target, Ordering::SeqCst);
        target
    }

    extern "C" fn test_branch_bridge_capture_x30(ctx: *mut JitContext, target: u64) -> u64 {
        BRIDGE_COUNT.fetch_add(1, Ordering::SeqCst);
        LAST_BRIDGE_TARGET.store(target, Ordering::SeqCst);
        let x30 = unsafe { ctx.as_ref().map(|ctx| ctx.x[30]).unwrap_or(0) };
        LAST_BRIDGE_CTX_X30.store(x30, Ordering::SeqCst);
        x30
    }

    fn pack_u16_lanes(lanes: [u16; 8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (index, lane) in lanes.into_iter().enumerate() {
            out[index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        out
    }

    fn unpack_u16_lanes(bytes: [u8; 16]) -> [u16; 8] {
        std::array::from_fn(|index| {
            u16::from_le_bytes(bytes[index * 2..index * 2 + 2].try_into().unwrap())
        })
    }

    fn reference_fcmla_8h(
        dst: [u16; 8],
        src: [u16; 8],
        scalar_pair: u32,
        rotation: u64,
    ) -> [u16; 8] {
        let scalar_re = f16::from_bits((scalar_pair & 0xffff) as u16);
        let scalar_im = f16::from_bits((scalar_pair >> 16) as u16);
        let (rot_re, rot_im) = rotate_complex_pair_f16(scalar_re, scalar_im, rotation);
        let mut out = dst;
        for pair in 0..4 {
            let re_lane = pair * 2;
            let im_lane = re_lane + 1;
            let src_re = f16::from_bits(src[re_lane]);
            let src_im = f16::from_bits(src[im_lane]);
            let acc_re = f16::from_bits(dst[re_lane]);
            let acc_im = f16::from_bits(dst[im_lane]);
            let prod_re = src_re * rot_re - src_im * rot_im;
            let prod_im = src_re * rot_im + src_im * rot_re;
            out[re_lane] = (acc_re + prod_re).to_bits();
            out[im_lane] = (acc_im + prod_im).to_bits();
        }
        out
    }

    #[test]
    fn compiles_and_executes_a_basic_block() {
        READ_COUNT.store(0, Ordering::SeqCst);
        WRITE_COUNT.store(0, Ordering::SeqCst);
        LAST_READ_ADDR.store(0, Ordering::SeqCst);
        LAST_WRITE_ADDR.store(0, Ordering::SeqCst);
        LAST_WRITE_VALUE.store(0, Ordering::SeqCst);

        let mut compiler = JitCompiler::new(JitConfig {
            instrument_memory: true,
            instrument_blocks: true,
        });
        compiler.set_memory_read_callback(Some(test_on_memory_read));
        compiler.set_memory_write_callback(Some(test_on_memory_write));

        let mut counters = [0u64; 1];
        compiler.set_block_counters(counters.as_mut_ptr(), counters.len());

        let stmts = vec![
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(7),
            },
            Stmt::Assign {
                dst: Reg::W(1),
                src: Expr::Add(Box::new(Expr::Reg(Reg::W(0))), Box::new(Expr::Imm(5))),
            },
            Stmt::Store {
                addr: Expr::Reg(Reg::X(2)),
                value: Expr::Reg(Reg::X(1)),
                size: 8,
            },
            Stmt::Assign {
                dst: Reg::X(3),
                src: Expr::Load {
                    addr: Box::new(Expr::Reg(Reg::X(2))),
                    size: 8,
                },
            },
            Stmt::SetFlags {
                expr: Expr::Sub(Box::new(Expr::Reg(Reg::W(1))), Box::new(Expr::Imm(12))),
            },
            Stmt::CondBranch {
                cond: BranchCond::Flag(Condition::EQ),
                target: Expr::Imm(0x2000),
                fallthrough: 0x1004,
            },
        ];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let mut slot = 0u64;
        let mut ctx = JitContext::default();
        ctx.x[2] = (&mut slot as *mut u64) as u64;

        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let next = unsafe { func(&mut ctx) };

        assert_eq!(next, 0x2000);
        assert_eq!(ctx.x[0], 7);
        assert_eq!(ctx.x[1], 12);
        assert_eq!(ctx.x[3], 12);
        assert_eq!(ctx.flags, 0b0110);
        assert_eq!(ctx.pc, 0x2000);
        assert_eq!(slot, 12);
        assert_eq!(compiler.block_id(0x1000), Some(0));
        assert_eq!(counters[0], 1);
        assert_eq!(READ_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(WRITE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(
            LAST_READ_ADDR.load(Ordering::SeqCst),
            (&mut slot as *mut u64) as u64
        );
        assert_eq!(
            LAST_WRITE_ADDR.load(Ordering::SeqCst),
            (&mut slot as *mut u64) as u64
        );
        assert_eq!(LAST_WRITE_VALUE.load(Ordering::SeqCst), 12);
    }

    #[test]
    fn branch_translate_zero_returns_raw_target_without_bridge() {
        BRIDGE_COUNT.store(0, Ordering::SeqCst);
        LAST_TRANSLATE_TARGET.store(0, Ordering::SeqCst);
        LAST_BRIDGE_TARGET.store(0, Ordering::SeqCst);
        LAST_BRIDGE_CTX_X30.store(0, Ordering::SeqCst);

        let mut compiler = JitCompiler::new(JitConfig::default());
        compiler.set_branch_translate_callback(Some(test_branch_translate_dynamic));
        compiler.set_branch_bridge_callback(Some(test_branch_bridge_count));

        let code = compiler
            .compile_block(
                0x1000,
                &[Stmt::Branch {
                    target: Expr::Imm(0x2000),
                }],
            )
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.pc = 0x1000;
        let next = unsafe { func(&mut ctx) };

        assert_eq!(next, 0x2000);
        assert_eq!(ctx.pc, 0x2000);
        assert_eq!(LAST_TRANSLATE_TARGET.load(Ordering::SeqCst), 0x2000);
        assert_eq!(BRIDGE_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(LAST_BRIDGE_TARGET.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unresolved_branch_bridge_sees_flushed_x30() {
        BRIDGE_COUNT.store(0, Ordering::SeqCst);
        LAST_TRANSLATE_TARGET.store(0, Ordering::SeqCst);
        LAST_BRIDGE_TARGET.store(0, Ordering::SeqCst);
        LAST_BRIDGE_CTX_X30.store(0, Ordering::SeqCst);

        let mut compiler = JitCompiler::new(JitConfig::default());
        compiler.set_branch_translate_callback(Some(test_branch_translate_identity));
        compiler.set_branch_bridge_callback(Some(test_branch_bridge_capture_x30));

        let code = compiler
            .compile_block(
                0x1000,
                &[
                    Stmt::Assign {
                        dst: Reg::X(17),
                        src: Expr::Imm(0x7000),
                    },
                    Stmt::Assign {
                        dst: Reg::X(30),
                        src: Expr::Imm(0x2000),
                    },
                    Stmt::Branch {
                        target: Expr::Reg(Reg::X(17)),
                    },
                ],
            )
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.pc = 0x1000;
        ctx.x[30] = 0xdeadbeef;
        let next = unsafe { func(&mut ctx) };

        assert_eq!(LAST_TRANSLATE_TARGET.load(Ordering::SeqCst), 0x7000);
        assert_eq!(BRIDGE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_BRIDGE_TARGET.load(Ordering::SeqCst), 0x7000);
        assert_eq!(LAST_BRIDGE_CTX_X30.load(Ordering::SeqCst), 0x2000);
        assert_eq!(next, 0x2000);
    }

    #[test]
    fn branches_on_ne_after_64bit_compare() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![
            Stmt::SetFlags {
                expr: Expr::Sub(
                    Box::new(Expr::Reg(Reg::X(2))),
                    Box::new(Expr::Reg(Reg::X(3))),
                ),
            },
            Stmt::CondBranch {
                cond: BranchCond::Flag(Condition::NE),
                target: Expr::Imm(0x2000),
                fallthrough: 0x1004,
            },
        ];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.x[2] = 1;
        ctx.x[3] = 2;
        let next = unsafe { func(&mut ctx) };
        assert_eq!(next, 0x2000);

        let mut ctx = JitContext::default();
        ctx.x[2] = 2;
        ctx.x[3] = 2;
        let next = unsafe { func(&mut ctx) };
        assert_eq!(next, 0x1004);
    }

    #[test]
    fn executes_checksum_loop_block_with_post_index_load() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::W(1),
                src: Expr::Lsr(Box::new(Expr::Reg(Reg::W(0))), Box::new(Expr::Imm(1))),
            },
            Stmt::Assign {
                dst: Reg::W(0),
                src: Expr::Xor(
                    Box::new(Expr::Reg(Reg::W(1))),
                    Box::new(Expr::Shl(
                        Box::new(Expr::Reg(Reg::W(0))),
                        Box::new(Expr::Imm(3)),
                    )),
                ),
            },
            Stmt::Pair(
                Box::new(Stmt::Assign {
                    dst: Reg::W(1),
                    src: Expr::Load {
                        addr: Box::new(Expr::Reg(Reg::X(2))),
                        size: 1,
                    },
                }),
                Box::new(Stmt::Assign {
                    dst: Reg::X(2),
                    src: Expr::Add(Box::new(Expr::Reg(Reg::X(2))), Box::new(Expr::Imm(1))),
                }),
            ),
            Stmt::Assign {
                dst: Reg::W(0),
                src: Expr::Xor(
                    Box::new(Expr::Reg(Reg::W(1))),
                    Box::new(Expr::Reg(Reg::W(0))),
                ),
            },
            Stmt::SetFlags {
                expr: Expr::Sub(
                    Box::new(Expr::Reg(Reg::X(2))),
                    Box::new(Expr::Reg(Reg::X(3))),
                ),
            },
            Stmt::CondBranch {
                cond: BranchCond::Flag(Condition::NE),
                target: Expr::Imm(0x400638),
                fallthrough: 0x400650,
            },
        ];

        let code = compiler
            .compile_block(0x400638, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let payload = [5u8, 6u8];
        let mut ctx = JitContext::default();
        ctx.x[0] = 19_088_312;
        ctx.x[2] = payload.as_ptr() as u64;
        ctx.x[3] = ctx.x[2] + 2;

        let next = unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], payload.as_ptr() as u64 + 1);
        assert_eq!(ctx.x[0], 160_152_601);
        assert_eq!(ctx.flags, 0x8);
        assert_eq!(next, 0x400638);

        let next = unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], payload.as_ptr() as u64 + 2);
        assert_eq!(next, 0x400650);
    }

    #[test]
    fn mrs_nzcv_reads_flags_shifted() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // Set flags, then read NZCV into a register
        let stmts = vec![
            Stmt::SetFlags {
                expr: Expr::Sub(
                    Box::new(Expr::Reg(Reg::X(0))),
                    Box::new(Expr::Reg(Reg::X(1))),
                ),
            },
            Stmt::Assign {
                dst: Reg::X(2),
                src: Expr::MrsRead("nzcv".to_string()),
            },
        ];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // 5 - 3 = 2: positive, no zero, carry set (no borrow), no overflow
        // NZCV = 0b0010 → flags = 0x2, MRS nzcv → 0x2 << 28 = 0x20000000
        let mut ctx = JitContext::default();
        ctx.x[0] = 5;
        ctx.x[1] = 3;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.flags, 0x2); // C set
        assert_eq!(ctx.x[2], 0x2000_0000);

        // 3 - 3 = 0: zero, carry set, no negative, no overflow
        // NZCV = 0b0110 → flags = 0x6, MRS nzcv → 0x6 << 28 = 0x60000000
        let mut ctx = JitContext::default();
        ctx.x[0] = 3;
        ctx.x[1] = 3;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.flags, 0x6); // Z and C set
        assert_eq!(ctx.x[2], 0x6000_0000);
    }

    #[test]
    fn mrs_tpidr_el0_reads_from_context() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::MrsRead("tpidr_el0".to_string()),
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.tpidr_el0 = 0x1234_5678_ABCD_0000;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0], 0x1234_5678_ABCD_0000);

        // Default (0) should also work
        let mut ctx2 = JitContext::default();
        ctx2.x[0] = 0xDEAD;
        unsafe { func(&mut ctx2) };
        assert_eq!(ctx2.x[0], 0);
    }

    #[test]
    fn msr_nzcv_writes_flags() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // MSR nzcv, x0 → write flags from x0 bits [31:28]
        let stmts = vec![Stmt::Intrinsic {
            name: "msr".to_string(),
            operands: vec![
                Expr::Intrinsic {
                    name: "nzcv".to_string(),
                    operands: vec![],
                },
                Expr::Reg(Reg::X(0)),
            ],
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // Set NZCV = 0b1010 (N=1, Z=0, C=1, V=0) → x0 = 0xA0000000
        let mut ctx = JitContext::default();
        ctx.x[0] = 0xA000_0000;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.flags, 0xA); // N=1, C=1

        // Set NZCV = 0b0100 (Z only) → x0 = 0x40000000
        let mut ctx = JitContext::default();
        ctx.x[0] = 0x4000_0000;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.flags, 0x4); // Z=1
    }

    #[test]
    fn compile_block_rejects_nop() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let err = compiler
            .compile_block(0x1000, &[Stmt::Nop])
            .expect_err("nop should fail fast");
        assert!(matches!(err, JitError::UnsupportedStmt("nop")));
    }

    #[test]
    fn compile_block_allows_supported_barrier() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let code = compiler
            .compile_block(
                0x1000,
                &[
                    Stmt::Barrier("dmb".to_string()),
                    Stmt::Assign {
                        dst: Reg::X(0),
                        src: Expr::Imm(0x1234),
                    },
                ],
            )
            .expect("supported barrier should compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0], 0x1234);
    }

    #[test]
    fn compile_block_rejects_unknown_barrier() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let err = compiler
            .compile_block(0x1000, &[Stmt::Barrier("unknown".to_string())])
            .expect_err("unknown barrier should fail fast");
        assert!(matches!(err, JitError::UnsupportedStmt("barrier")));
    }

    #[test]
    fn compile_block_rejects_non_nzcv_msr() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let err = compiler
            .compile_block(
                0x1000,
                &[Stmt::Intrinsic {
                    name: "msr".to_string(),
                    operands: vec![
                        Expr::Intrinsic {
                            name: "tpidr_el0".to_string(),
                            operands: vec![],
                        },
                        Expr::Reg(Reg::X(0)),
                    ],
                }],
            )
            .expect_err("non-nzcv msr should fail fast");
        assert!(matches!(err, JitError::UnsupportedStmt("msr target")));
    }

    #[test]
    fn simd_vector_and() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::V(2),
            src: Expr::Intrinsic {
                name: "and".to_string(),
                operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0xFF; 16];
        ctx.simd[1] = [0x0F; 16];
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.simd[2], [0x0F; 16]);
    }

    #[test]
    fn simd_vector_orr() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::V(2),
            src: Expr::Intrinsic {
                name: "orr".to_string(),
                operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0xF0; 16];
        ctx.simd[1] = [0x0F; 16];
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.simd[2], [0xFF; 16]);
    }

    #[test]
    fn simd_vector_eor() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::V(2),
            src: Expr::Intrinsic {
                name: "eor".to_string(),
                operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0xFF; 16];
        ctx.simd[1] = [0xAA; 16];
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.simd[2], [0x55; 16]);
    }

    #[test]
    fn simd_vector_bic() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::V(2),
            src: Expr::Intrinsic {
                name: "bic".to_string(),
                operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0xFF; 16];
        ctx.simd[1] = [0x0F; 16];
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.simd[2], [0xF0; 16]);
    }

    #[test]
    fn simd_vector_orn() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::V(2),
            src: Expr::Intrinsic {
                name: "orn".to_string(),
                operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0x00; 16];
        ctx.simd[1] = [0x0F; 16];
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.simd[2], [0xF0; 16]); // 0x00 | ~0x0F = 0xF0
    }

    #[test]
    fn simd_vector_not() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::V(1),
            src: Expr::Intrinsic {
                name: "not".to_string(),
                operands: vec![Expr::Reg(Reg::V(0))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0xAA; 16];
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.simd[1], [0x55; 16]);
    }

    #[test]
    fn simd_bsl_bitselect() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // BSL v0, v1, v2 → (v0 & v1) | (~v0 & v2)
        let stmts = vec![Stmt::Assign {
            dst: Reg::V(3),
            src: Expr::Intrinsic {
                name: "bsl".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(0)), // mask
                    Expr::Reg(Reg::V(1)), // if bit set
                    Expr::Reg(Reg::V(2)), // if bit clear
                ],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0xF0; 16]; // mask: upper nibble from v1, lower from v2
        ctx.simd[1] = [0xAA; 16]; // source 1
        ctx.simd[2] = [0x55; 16]; // source 2
        unsafe { func(&mut ctx) };
        // (0xF0 & 0xAA) | (~0xF0 & 0x55) = 0xA0 | 0x05 = 0xA5
        assert_eq!(ctx.simd[3], [0xA5; 16]);
    }

    #[test]
    fn simd_ushr_2d_shifts_each_lane() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "ushr.2d".to_string(),
            operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1)), Expr::Imm(8)],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[1][..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        ctx.simd[1][8..16].copy_from_slice(&0xff00_0000_0000_0000u64.to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(
            u64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap()),
            0x0011_2233_4455_6677
        );
        assert_eq!(
            u64::from_le_bytes(ctx.simd[0][8..16].try_into().unwrap()),
            0x00ff_0000_0000_0000
        );
    }

    #[test]
    fn simd_usra_2d_accumulates_shifted_lanes() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "usra.2d".to_string(),
            operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1)), Expr::Imm(4)],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0][..8].copy_from_slice(&3u64.to_le_bytes());
        ctx.simd[0][8..16].copy_from_slice(&5u64.to_le_bytes());
        ctx.simd[1][..8].copy_from_slice(&0x40u64.to_le_bytes());
        ctx.simd[1][8..16].copy_from_slice(&0x90u64.to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(u64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap()), 7);
        assert_eq!(
            u64::from_le_bytes(ctx.simd[0][8..16].try_into().unwrap()),
            14
        );
    }

    #[test]
    fn simd_sli_2d_inserts_low_bits_from_destination() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "sli.2d".to_string(),
            operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1)), Expr::Imm(8)],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0][..8].copy_from_slice(&0x0000_0000_0000_00aau64.to_le_bytes());
        ctx.simd[1][..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(
            u64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap()),
            0x2233_4455_6677_88aa
        );
    }

    #[test]
    fn simd_sri_2d_inserts_high_bits_from_destination() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "sri.2d".to_string(),
            operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1)), Expr::Imm(8)],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0][..8].copy_from_slice(&0xaa00_0000_0000_0000u64.to_le_bytes());
        ctx.simd[1][..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(
            u64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap()),
            0xaa11_2233_4455_6677
        );
    }

    #[test]
    fn simd_sqshlu_2d_saturates_negative_and_overflowing_lanes() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "sqshlu.2d".to_string(),
            operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1)), Expr::Imm(4)],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[1][..8].copy_from_slice(&(-1i64).to_le_bytes());
        ctx.simd[1][8..16].copy_from_slice(&(i64::MAX).to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(u64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(ctx.simd[0][8..16].try_into().unwrap()),
            u64::MAX
        );
    }

    #[test]
    fn simd_uqshl_2d_saturates_unsigned_overflowing_lanes() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "uqshl.2d".to_string(),
            operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1)), Expr::Imm(4)],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[1][..8].copy_from_slice(&3u64.to_le_bytes());
        ctx.simd[1][8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(u64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap()), 48);
        assert_eq!(
            u64::from_le_bytes(ctx.simd[0][8..16].try_into().unwrap()),
            u64::MAX
        );
    }

    #[test]
    fn simd_uxtl_8h_zero_extends_lower_bytes() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "uxtl.8h".to_string(),
            operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1))],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[1] = [
            1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        ];
        unsafe { func(&mut ctx) };
        let lanes = [
            u16::from_le_bytes(ctx.simd[0][0..2].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][2..4].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][4..6].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][6..8].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][8..10].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][10..12].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][12..14].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][14..16].try_into().unwrap()),
        ];
        assert_eq!(lanes, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn simd_ushll2_2d_zero_extends_upper_words_and_shifts() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "ushll2.2d".to_string(),
            operands: vec![Expr::Reg(Reg::V(0)), Expr::Reg(Reg::V(1)), Expr::Imm(1)],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        for (index, lane) in [1u32, 2, 3, 4].into_iter().enumerate() {
            ctx.simd[1][index * 4..index * 4 + 4].copy_from_slice(&lane.to_le_bytes());
        }
        unsafe { func(&mut ctx) };
        assert_eq!(u64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap()), 6);
        assert_eq!(
            u64::from_le_bytes(ctx.simd[0][8..16].try_into().unwrap()),
            8
        );
    }

    #[test]
    fn simd_sqrdmlah_8h_rounds_multiplies_and_accumulates() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "sqrdmlah.8h".to_string(),
            operands: vec![
                Expr::Reg(Reg::V(0)),
                Expr::Reg(Reg::V(1)),
                Expr::Extract {
                    src: Box::new(Expr::Reg(Reg::V(2))),
                    lsb: 0,
                    width: 16,
                },
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        for (index, lane) in [100i16; 8].into_iter().enumerate() {
            ctx.simd[0][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        for (index, lane) in [32767i16; 8].into_iter().enumerate() {
            ctx.simd[1][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        ctx.simd[2][0..2].copy_from_slice(&32767i16.to_le_bytes());
        unsafe { func(&mut ctx) };
        let lanes = [
            i16::from_le_bytes(ctx.simd[0][0..2].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][2..4].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][4..6].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][6..8].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][8..10].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][10..12].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][12..14].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][14..16].try_into().unwrap()),
        ];
        assert_eq!(lanes, [32767; 8]);
    }

    #[test]
    fn simd_sqrdmlsh_8h_rounds_multiplies_and_subtracts() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "sqrdmlsh.8h".to_string(),
            operands: vec![
                Expr::Reg(Reg::V(0)),
                Expr::Reg(Reg::V(1)),
                Expr::Extract {
                    src: Box::new(Expr::Reg(Reg::V(2))),
                    lsb: 64,
                    width: 16,
                },
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        for (index, lane) in [100i16; 8].into_iter().enumerate() {
            ctx.simd[0][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        for (index, lane) in [16384i16; 8].into_iter().enumerate() {
            ctx.simd[1][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        ctx.simd[2][8..10].copy_from_slice(&16384i16.to_le_bytes());
        unsafe { func(&mut ctx) };
        let lanes = [
            i16::from_le_bytes(ctx.simd[0][0..2].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][2..4].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][4..6].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][6..8].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][8..10].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][10..12].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][12..14].try_into().unwrap()),
            i16::from_le_bytes(ctx.simd[0][14..16].try_into().unwrap()),
        ];
        assert_eq!(lanes, [-8092; 8]);
    }

    #[test]
    fn simd_stmt_movi_16b_splats_immediate() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "movi.16b".to_string(),
            operands: vec![Expr::Reg(Reg::V(0)), Expr::Imm(0x5a)],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.simd[0], [0x5a; 16]);
    }

    #[test]
    fn simd_uqrshrn2_4s_rounds_narrows_into_upper_half() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "uqrshrn2.4s".to_string(),
            operands: vec![Expr::Reg(Reg::V(8)), Expr::Reg(Reg::V(24)), Expr::Imm(2)],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        for (index, lane) in [11u32, 22, 33, 44].into_iter().enumerate() {
            ctx.simd[8][index * 4..index * 4 + 4].copy_from_slice(&lane.to_le_bytes());
        }
        ctx.simd[24][..8].copy_from_slice(&9u64.to_le_bytes());
        ctx.simd[24][8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        unsafe { func(&mut ctx) };
        let lanes = [
            u32::from_le_bytes(ctx.simd[8][0..4].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[8][4..8].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[8][8..12].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[8][12..16].try_into().unwrap()),
        ];
        assert_eq!(lanes, [11, 22, 2, u32::MAX]);
    }

    #[test]
    fn simd_fmulx_2d_multiplies_each_lane_by_scalar_lane() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "fmulx.2d".to_string(),
            operands: vec![
                Expr::Reg(Reg::V(24)),
                Expr::Reg(Reg::V(1)),
                Expr::Extract {
                    src: Box::new(Expr::Reg(Reg::V(4))),
                    lsb: 0,
                    width: 64,
                },
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[1][..8].copy_from_slice(&1.5f64.to_le_bytes());
        ctx.simd[1][8..16].copy_from_slice(&(-2.0f64).to_le_bytes());
        ctx.simd[4][..8].copy_from_slice(&3.0f64.to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(
            f64::from_le_bytes(ctx.simd[24][..8].try_into().unwrap()),
            4.5
        );
        assert_eq!(
            f64::from_le_bytes(ctx.simd[24][8..16].try_into().unwrap()),
            -6.0
        );
    }

    #[test]
    fn simd_fcmla_8h_handles_all_rotations() {
        let src = [
            0x3c00, 0x4000, // 1.0, 2.0
            0x4200, 0x4400, // 3.0, 4.0
            0xbc00, 0x3c00, // -1.0, 1.0
            0x3800, 0xb800, // 0.5, -0.5
        ];
        let dst = [
            0x0000, 0x0000, // 0.0, 0.0
            0x3800, 0x3800, // 0.5, 0.5
            0xbc00, 0x0000, // -1.0, 0.0
            0x3c00, 0x0000, // 1.0, 0.0
        ];
        let scalar_lanes = [
            0x3555, // 0.33325 (junk)
            0x4000, // 2.0 (real)
            0x3800, // 0.5 (imag)
            0x3c00, // 1.0 (junk)
            0, 0, 0, 0,
        ];
        for rotation in [0x0_u64, 0x5a, 0xb4, 0x10e] {
            let mut compiler = JitCompiler::new(JitConfig::default());
            let stmts = vec![Stmt::Intrinsic {
                name: "fcmla.8h".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(0)),
                    Expr::Reg(Reg::V(1)),
                    Expr::Extract {
                        src: Box::new(Expr::Reg(Reg::V(2))),
                        lsb: 16,
                        width: 16,
                    },
                    Expr::Imm(rotation),
                ],
            }];
            let code = compiler.compile_block(0x1000, &stmts).expect("compile");
            let func: JitEntry = unsafe { std::mem::transmute(code) };

            let mut ctx = JitContext::default();
            ctx.simd[0] = pack_u16_lanes(dst);
            ctx.simd[1] = pack_u16_lanes(src);
            ctx.simd[2] = pack_u16_lanes(scalar_lanes);
            unsafe { func(&mut ctx) };

            let expected = reference_fcmla_8h(dst, src, 0x3800_4000, rotation);
            assert_eq!(
                unpack_u16_lanes(ctx.simd[0]),
                expected,
                "rotation {rotation:#x}"
            );
        }
    }

    #[test]
    fn object_compiler_compiles_fcmla_8h_block() {
        let mut compiler = ObjectCompiler::new_aarch64(JitConfig::default()).expect("compiler");
        let symbol = compiler
            .compile_block(
                0x1000,
                &[Stmt::Intrinsic {
                    name: "fcmla.8h".to_string(),
                    operands: vec![
                        Expr::Reg(Reg::V(0)),
                        Expr::Reg(Reg::V(1)),
                        Expr::Extract {
                            src: Box::new(Expr::Reg(Reg::V(2))),
                            lsb: 16,
                            width: 16,
                        },
                        Expr::Imm(0x5a),
                    ],
                }],
            )
            .expect("compile block");
        assert!(symbol.contains("0000000000001000"));
    }

    #[test]
    fn simd_ld1_8b_loads_low_half_and_updates_base() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "ld1.8b".to_string(),
            operands: vec![
                Expr::Intrinsic {
                    name: "multi_reg".to_string(),
                    operands: vec![Expr::Reg(Reg::V(31))],
                },
                Expr::Reg(Reg::X(3)),
                Expr::Imm(8),
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut backing = [0u8; 16];
        backing[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut ctx = JitContext::default();
        ctx.simd[31] = [0xaa; 16];
        ctx.x[3] = backing.as_ptr() as u64;
        unsafe { func(&mut ctx) };
        assert_eq!(&ctx.simd[31][..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&ctx.simd[31][8..], &[0xaa; 8]);
        assert_eq!(ctx.x[3], backing.as_ptr() as u64 + 8);
    }

    #[test]
    fn simd_st1_8h_stores_full_vector_and_updates_base() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "st1.8h".to_string(),
            operands: vec![
                Expr::Intrinsic {
                    name: "multi_reg".to_string(),
                    operands: vec![Expr::Reg(Reg::V(31))],
                },
                Expr::Reg(Reg::X(16)),
                Expr::Imm(16),
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut backing = [0u8; 32];
        let mut ctx = JitContext::default();
        ctx.simd[31] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        ctx.x[16] = backing.as_mut_ptr() as u64;
        unsafe { func(&mut ctx) };
        assert_eq!(&backing[..16], &ctx.simd[31]);
        assert_eq!(ctx.x[16], backing.as_mut_ptr() as u64 + 16);
    }

    #[test]
    fn simd_mla_8h_multiplies_by_scalar_lane_and_accumulates() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "mla.8h".to_string(),
            operands: vec![
                Expr::Reg(Reg::V(0)),
                Expr::Reg(Reg::V(1)),
                Expr::Extract {
                    src: Box::new(Expr::Reg(Reg::V(2))),
                    lsb: 16,
                    width: 16,
                },
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        for (index, lane) in [10u16, 20, 30, 40, 50, 60, 70, 80].into_iter().enumerate() {
            ctx.simd[0][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        for (index, lane) in [1u16, 2, 3, 4, 5, 6, 7, 8].into_iter().enumerate() {
            ctx.simd[1][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        ctx.simd[2][2..4].copy_from_slice(&3u16.to_le_bytes());
        unsafe { func(&mut ctx) };
        let lanes = [
            u16::from_le_bytes(ctx.simd[0][0..2].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][2..4].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][4..6].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][6..8].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][8..10].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][10..12].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][12..14].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][14..16].try_into().unwrap()),
        ];
        assert_eq!(lanes, [13, 26, 39, 52, 65, 78, 91, 104]);
    }

    #[test]
    fn simd_mls_8h_multiplies_by_scalar_lane_and_subtracts() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "mls.8h".to_string(),
            operands: vec![
                Expr::Reg(Reg::V(0)),
                Expr::Reg(Reg::V(1)),
                Expr::Extract {
                    src: Box::new(Expr::Reg(Reg::V(2))),
                    lsb: 16,
                    width: 16,
                },
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        for (index, lane) in [100u16, 110, 120, 130, 140, 150, 160, 170]
            .into_iter()
            .enumerate()
        {
            ctx.simd[0][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        for (index, lane) in [1u16, 2, 3, 4, 5, 6, 7, 8].into_iter().enumerate() {
            ctx.simd[1][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        ctx.simd[2][2..4].copy_from_slice(&4u16.to_le_bytes());
        unsafe { func(&mut ctx) };
        let lanes = [
            u16::from_le_bytes(ctx.simd[0][0..2].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][2..4].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][4..6].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][6..8].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][8..10].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][10..12].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][12..14].try_into().unwrap()),
            u16::from_le_bytes(ctx.simd[0][14..16].try_into().unwrap()),
        ];
        assert_eq!(lanes, [96, 102, 108, 114, 120, 126, 132, 138]);
    }

    #[test]
    fn simd_umlal2_4s_accumulates_upper_half_products() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "umlal2.4s".to_string(),
            operands: vec![
                Expr::Reg(Reg::V(0)),
                Expr::Reg(Reg::V(1)),
                Expr::Extract {
                    src: Box::new(Expr::Reg(Reg::V(2))),
                    lsb: 16,
                    width: 16,
                },
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        for (index, lane) in [100u32, 200, 300, 400].into_iter().enumerate() {
            ctx.simd[0][index * 4..index * 4 + 4].copy_from_slice(&lane.to_le_bytes());
        }
        for (index, lane) in [1u16, 2, 3, 4, 5, 6, 7, 8].into_iter().enumerate() {
            ctx.simd[1][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        ctx.simd[2][2..4].copy_from_slice(&9u16.to_le_bytes());
        unsafe { func(&mut ctx) };
        let lanes = [
            u32::from_le_bytes(ctx.simd[0][0..4].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[0][4..8].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[0][8..12].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[0][12..16].try_into().unwrap()),
        ];
        assert_eq!(lanes, [145, 254, 363, 472]);
    }

    #[test]
    fn simd_umlsl2_4s_subtracts_upper_half_products() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "umlsl2.4s".to_string(),
            operands: vec![
                Expr::Reg(Reg::V(0)),
                Expr::Reg(Reg::V(1)),
                Expr::Extract {
                    src: Box::new(Expr::Reg(Reg::V(2))),
                    lsb: 16,
                    width: 16,
                },
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        for (index, lane) in [500u32, 600, 700, 800].into_iter().enumerate() {
            ctx.simd[0][index * 4..index * 4 + 4].copy_from_slice(&lane.to_le_bytes());
        }
        for (index, lane) in [1u16, 2, 3, 4, 5, 6, 7, 8].into_iter().enumerate() {
            ctx.simd[1][index * 2..index * 2 + 2].copy_from_slice(&lane.to_le_bytes());
        }
        ctx.simd[2][2..4].copy_from_slice(&7u16.to_le_bytes());
        unsafe { func(&mut ctx) };
        let lanes = [
            u32::from_le_bytes(ctx.simd[0][0..4].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[0][4..8].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[0][8..12].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[0][12..16].try_into().unwrap()),
        ];
        assert_eq!(lanes, [465, 558, 651, 744]);
    }

    #[test]
    fn float_rounding_frintz_truncate() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::D(1),
            src: Expr::Intrinsic {
                name: "frintz".to_string(),
                operands: vec![Expr::Reg(Reg::D(0))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0; 16];
        ctx.simd[0][..8].copy_from_slice(&3.7f64.to_le_bytes());
        unsafe { func(&mut ctx) };
        let result = f64::from_le_bytes(ctx.simd[1][..8].try_into().unwrap());
        assert_eq!(result, 3.0);

        // Negative truncation
        ctx.simd[0][..8].copy_from_slice(&(-2.9f64).to_le_bytes());
        unsafe { func(&mut ctx) };
        let result = f64::from_le_bytes(ctx.simd[1][..8].try_into().unwrap());
        assert_eq!(result, -2.0);
    }

    #[test]
    fn float_rounding_frintm_floor() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::D(1),
            src: Expr::Intrinsic {
                name: "frintm".to_string(),
                operands: vec![Expr::Reg(Reg::D(0))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0; 16];
        ctx.simd[0][..8].copy_from_slice(&(-2.3f64).to_le_bytes());
        unsafe { func(&mut ctx) };
        let result = f64::from_le_bytes(ctx.simd[1][..8].try_into().unwrap());
        assert_eq!(result, -3.0);
    }

    #[test]
    fn float_rounding_frintp_ceil() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::D(1),
            src: Expr::Intrinsic {
                name: "frintp".to_string(),
                operands: vec![Expr::Reg(Reg::D(0))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0; 16];
        ctx.simd[0][..8].copy_from_slice(&2.3f64.to_le_bytes());
        unsafe { func(&mut ctx) };
        let result = f64::from_le_bytes(ctx.simd[1][..8].try_into().unwrap());
        assert_eq!(result, 3.0);
    }

    #[test]
    fn fnmadd_neg_mul_sub() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // FNMADD: -(n*m) - a
        let stmts = vec![Stmt::Assign {
            dst: Reg::D(3),
            src: Expr::Intrinsic {
                name: "fnmadd".to_string(),
                operands: vec![
                    Expr::Reg(Reg::D(0)),
                    Expr::Reg(Reg::D(1)),
                    Expr::Reg(Reg::D(2)),
                ],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0; 16];
        ctx.simd[1] = [0; 16];
        ctx.simd[2] = [0; 16];
        ctx.simd[0][..8].copy_from_slice(&2.0f64.to_le_bytes());
        ctx.simd[1][..8].copy_from_slice(&3.0f64.to_le_bytes());
        ctx.simd[2][..8].copy_from_slice(&1.0f64.to_le_bytes());
        unsafe { func(&mut ctx) };
        // -(2*3) - 1 = -7
        let result = f64::from_le_bytes(ctx.simd[3][..8].try_into().unwrap());
        assert_eq!(result, -7.0);
    }

    #[test]
    fn fnmsub_mul_sub() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // FNMSUB: n*m - a
        let stmts = vec![Stmt::Assign {
            dst: Reg::D(3),
            src: Expr::Intrinsic {
                name: "fnmsub".to_string(),
                operands: vec![
                    Expr::Reg(Reg::D(0)),
                    Expr::Reg(Reg::D(1)),
                    Expr::Reg(Reg::D(2)),
                ],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.simd[0] = [0; 16];
        ctx.simd[1] = [0; 16];
        ctx.simd[2] = [0; 16];
        ctx.simd[0][..8].copy_from_slice(&2.0f64.to_le_bytes());
        ctx.simd[1][..8].copy_from_slice(&3.0f64.to_le_bytes());
        ctx.simd[2][..8].copy_from_slice(&1.0f64.to_le_bytes());
        unsafe { func(&mut ctx) };
        // 2*3 - 1 = 5
        let result = f64::from_le_bytes(ctx.simd[3][..8].try_into().unwrap());
        assert_eq!(result, 5.0);
    }

    #[test]
    fn smull_widening_multiply_positive_values() {
        // SMULL pattern: X2 = Mul(SignExtend(W0, 32), SignExtend(W1, 32))
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(2),
            src: Expr::Mul(
                Box::new(Expr::SignExtend {
                    src: Box::new(Expr::Reg(Reg::W(0))),
                    from_bits: 32,
                }),
                Box::new(Expr::SignExtend {
                    src: Box::new(Expr::Reg(Reg::W(1))),
                    from_bits: 32,
                }),
            ),
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // 100 * 200 = 20000
        let mut ctx = JitContext::default();
        ctx.x[0] = 100;
        ctx.x[1] = 200;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], 20000);
    }

    #[test]
    fn smull_widening_multiply_negative_operand() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(2),
            src: Expr::Mul(
                Box::new(Expr::SignExtend {
                    src: Box::new(Expr::Reg(Reg::W(0))),
                    from_bits: 32,
                }),
                Box::new(Expr::SignExtend {
                    src: Box::new(Expr::Reg(Reg::W(1))),
                    from_bits: 32,
                }),
            ),
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // (-5) * 3 = -15
        let mut ctx = JitContext::default();
        ctx.x[0] = (-5i32) as u32 as u64;
        ctx.x[1] = 3;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2] as i64, -15);
    }

    #[test]
    fn smull_lsr_div_by_3_magic_constant() {
        // Real div-by-3 pattern from compiled C code:
        //   SMULL X2, W3, W6    → X2 = sext(W3) * sext(W6)
        //   LSR   X2, X2, #32  → X2 = X2 >> 32 (unsigned)
        //   SUB   W2, W2, W3, ASR #31
        //   ADD   W2, W2, W2, LSL #1
        //   SUBS  W2, W3, W2   → remainder = val - quotient*3
        let mut compiler = JitCompiler::new(JitConfig::default());
        let magic: u32 = 0x55555556; // magic constant for signed div by 3
        let stmts = vec![
            // X2 = smull(W3, W6)
            Stmt::Assign {
                dst: Reg::X(2),
                src: Expr::Mul(
                    Box::new(Expr::SignExtend {
                        src: Box::new(Expr::Reg(Reg::W(3))),
                        from_bits: 32,
                    }),
                    Box::new(Expr::SignExtend {
                        src: Box::new(Expr::Reg(Reg::W(6))),
                        from_bits: 32,
                    }),
                ),
            },
            // X2 = X2 >> 32
            Stmt::Assign {
                dst: Reg::X(2),
                src: Expr::Lsr(Box::new(Expr::Reg(Reg::X(2))), Box::new(Expr::Imm(32))),
            },
            // W2 = W2 - (W3 >> 31)  (adjust for negative)
            Stmt::Assign {
                dst: Reg::W(2),
                src: Expr::Sub(
                    Box::new(Expr::Reg(Reg::W(2))),
                    Box::new(Expr::Asr(
                        Box::new(Expr::Reg(Reg::W(3))),
                        Box::new(Expr::Imm(31)),
                    )),
                ),
            },
            // W2 = W2 + W2 * 2 = W2 * 3 (quotient * 3)
            Stmt::Assign {
                dst: Reg::W(2),
                src: Expr::Add(
                    Box::new(Expr::Reg(Reg::W(2))),
                    Box::new(Expr::Shl(
                        Box::new(Expr::Reg(Reg::W(2))),
                        Box::new(Expr::Imm(1)),
                    )),
                ),
            },
            // W2 = W3 - W2 (remainder)
            Stmt::Assign {
                dst: Reg::W(2),
                src: Expr::Sub(
                    Box::new(Expr::Reg(Reg::W(3))),
                    Box::new(Expr::Reg(Reg::W(2))),
                ),
            },
        ];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // Test various values modulo 3 (C-style truncating modulo)
        for val in [0i32, 1, 2, 3, 4, 5, 6, 7, 47, 100, -1, -3, -7] {
            let mut ctx = JitContext::default();
            ctx.x[3] = val as u32 as u64;
            ctx.x[6] = magic as u64;
            unsafe { func(&mut ctx) };
            let remainder = ctx.x[2] as u32 as i32;
            let expected = val % 3; // C-style truncating modulo
            assert_eq!(
                remainder, expected,
                "val={val}: got remainder {remainder}, expected {expected}"
            );
        }
    }

    #[test]
    fn smull_both_negative() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(2),
            src: Expr::Mul(
                Box::new(Expr::SignExtend {
                    src: Box::new(Expr::Reg(Reg::W(0))),
                    from_bits: 32,
                }),
                Box::new(Expr::SignExtend {
                    src: Box::new(Expr::Reg(Reg::W(1))),
                    from_bits: 32,
                }),
            ),
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // (-1000) * (-2000) = 2000000
        let mut ctx = JitContext::default();
        ctx.x[0] = (-1000i32) as u32 as u64;
        ctx.x[1] = (-2000i32) as u32 as u64;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], 2_000_000);
    }

    #[test]
    fn smull_large_values_upper_bits() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![
            // X2 = smull(W0, W1)
            Stmt::Assign {
                dst: Reg::X(2),
                src: Expr::Mul(
                    Box::new(Expr::SignExtend {
                        src: Box::new(Expr::Reg(Reg::W(0))),
                        from_bits: 32,
                    }),
                    Box::new(Expr::SignExtend {
                        src: Box::new(Expr::Reg(Reg::W(1))),
                        from_bits: 32,
                    }),
                ),
            },
            // X3 = X2 >> 32 (upper 32 bits)
            Stmt::Assign {
                dst: Reg::X(3),
                src: Expr::Lsr(Box::new(Expr::Reg(Reg::X(2))), Box::new(Expr::Imm(32))),
            },
        ];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // i32::MAX * 2 = 4294967294 which needs upper bits
        let mut ctx = JitContext::default();
        ctx.x[0] = 0x7FFFFFFF; // i32::MAX
        ctx.x[1] = 2;
        unsafe { func(&mut ctx) };
        let product = ctx.x[2] as i64;
        assert_eq!(product, 2 * 0x7FFFFFFF_i64);
        assert_eq!(ctx.x[3], 0); // upper 32 bits are 0 (positive product)

        // i32::MIN * 2 — negative product, upper bits should be 0xFFFFFFFF
        let mut ctx = JitContext::default();
        ctx.x[0] = 0x80000000; // i32::MIN
        ctx.x[1] = 2;
        unsafe { func(&mut ctx) };
        let product = ctx.x[2] as i64;
        assert_eq!(product, -2i64 * 0x80000000i64); // -4294967296
        assert_eq!(ctx.x[3], 0xFFFFFFFF); // upper 32 bits of negative result
    }

    #[test]
    fn rev16_swaps_bytes_in_halfwords() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::W(0),
            src: Expr::Intrinsic {
                name: "rev16".to_string(),
                operands: vec![Expr::Reg(Reg::W(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.x[1] = 0xAABBCCDD;
        unsafe { func(&mut ctx) };
        // Swap bytes in each halfword: 0xAABB→0xBBAA, 0xCCDD→0xDDCC
        assert_eq!(ctx.x[0] as u32, 0xBBAADDCC);
    }

    #[test]
    fn rev32_reverses_bytes_in_words() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::W(0),
            src: Expr::Intrinsic {
                name: "rev32".to_string(),
                operands: vec![Expr::Reg(Reg::W(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.x[1] = 0xAABBCCDD;
        unsafe { func(&mut ctx) };
        // Reverse bytes in 32-bit word: 0xDDCCBBAA
        assert_eq!(ctx.x[0] as u32, 0xDDCCBBAA);
    }

    #[test]
    fn cnt_popcount() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::W(0),
            src: Expr::Intrinsic {
                name: "cnt".to_string(),
                operands: vec![Expr::Reg(Reg::W(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.x[1] = 0xFF; // 8 bits set
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as u32, 8);

        ctx.x[1] = 0xAAAAAAAA; // 16 bits set
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as u32, 16);

        ctx.x[1] = 0;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as u32, 0);
    }

    #[test]
    fn movk_builds_constant() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // Build 0x55555556 via MOV + MOVK (as the lifter does)
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::W(0),
                src: Expr::Imm(0x5556),
            },
            Stmt::Assign {
                dst: Reg::W(0),
                src: Expr::Intrinsic {
                    name: "movk".to_string(),
                    operands: vec![
                        Expr::Reg(Reg::W(0)),
                        Expr::Shl(Box::new(Expr::Imm(0x5555)), Box::new(Expr::Imm(16))),
                    ],
                },
            },
        ];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as u32, 0x55555556);
    }

    #[test]
    fn bitfield_ubfx_extract() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // UBFX W0, W1, #4, #8 → extract 8 bits starting at bit 4
        let stmts = vec![Stmt::Intrinsic {
            name: "ubfx".to_string(),
            operands: vec![
                Expr::Reg(Reg::W(0)),
                Expr::Reg(Reg::W(1)),
                Expr::Imm(4),
                Expr::Imm(8),
            ],
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.x[1] = 0xDEAD_BEF0;
        unsafe { func(&mut ctx) };
        // Extract 8 bits from bit 4: (0xBEF0 >> 4) & 0xFF = 0xEF
        assert_eq!(ctx.x[0] as u32, 0xEF);
    }

    #[test]
    fn bitfield_sbfx_signed_extract() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // SBFX W0, W1, #4, #8 → signed extract
        let stmts = vec![Stmt::Intrinsic {
            name: "sbfx".to_string(),
            operands: vec![
                Expr::Reg(Reg::W(0)),
                Expr::Reg(Reg::W(1)),
                Expr::Imm(4),
                Expr::Imm(8),
            ],
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // Extract 8 bits from bit 4, value = 0xFF (sign bit set → -1)
        let mut ctx = JitContext::default();
        ctx.x[1] = 0xFF0; // bits [11:4] = 0xFF
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as u32 as i32, -1); // 0xFF sign-extended = -1

        // Extract 8 bits from bit 4, value = 0x7F (positive)
        let mut ctx = JitContext::default();
        ctx.x[1] = 0x7F0; // bits [11:4] = 0x7F
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as u32, 0x7F);
    }

    #[test]
    fn bitfield_extr_rotate() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // EXTR W0, W1, W2, #16 → (W1:W2 >> 16)[31:0]
        let stmts = vec![Stmt::Intrinsic {
            name: "extr".to_string(),
            operands: vec![
                Expr::Reg(Reg::W(0)),
                Expr::Reg(Reg::W(1)),
                Expr::Reg(Reg::W(2)),
                Expr::Imm(16),
            ],
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.x[1] = 0xAABBCCDD;
        ctx.x[2] = 0x11223344;
        unsafe { func(&mut ctx) };
        // (0xAABBCCDD << 16) | (0x11223344 >> 16) = 0xCCDD1122
        assert_eq!(ctx.x[0] as u32, 0xCCDD1122);
    }

    // ── Flag condition tests ──────────────────────────────────────────
    // Helper: compile a SetFlags(Sub(X0, X1)) + CondBranch block and
    // return the branch target for the given register values.
    fn branch_result(cond: Condition, x0: u64, x1: u64) -> u64 {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![
            Stmt::SetFlags {
                expr: Expr::Sub(
                    Box::new(Expr::Reg(Reg::X(0))),
                    Box::new(Expr::Reg(Reg::X(1))),
                ),
            },
            Stmt::CondBranch {
                cond: BranchCond::Flag(cond),
                target: Expr::Imm(0x2000),
                fallthrough: 0x1004,
            },
        ];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        ctx.x[0] = x0;
        ctx.x[1] = x1;
        unsafe { func(&mut ctx) }
    }

    #[test]
    fn flag_cond_eq_and_ne() {
        // equal
        assert_eq!(branch_result(Condition::EQ, 5, 5), 0x2000);
        assert_eq!(branch_result(Condition::NE, 5, 5), 0x1004);
        // not equal
        assert_eq!(branch_result(Condition::EQ, 5, 3), 0x1004);
        assert_eq!(branch_result(Condition::NE, 5, 3), 0x2000);
    }

    #[test]
    fn flag_cond_cs_cc_unsigned_carry() {
        // 5 - 3 = 2 → carry set (no borrow)
        assert_eq!(branch_result(Condition::CS, 5, 3), 0x2000);
        assert_eq!(branch_result(Condition::CC, 5, 3), 0x1004);
        // 3 - 5 → borrow → carry clear
        assert_eq!(branch_result(Condition::CS, 3, 5), 0x1004);
        assert_eq!(branch_result(Condition::CC, 3, 5), 0x2000);
    }

    #[test]
    fn flag_cond_mi_pl_negative() {
        // 3 - 5 = -2 → negative
        assert_eq!(branch_result(Condition::MI, 3, 5), 0x2000);
        assert_eq!(branch_result(Condition::PL, 3, 5), 0x1004);
        // 5 - 3 = 2 → positive
        assert_eq!(branch_result(Condition::MI, 5, 3), 0x1004);
        assert_eq!(branch_result(Condition::PL, 5, 3), 0x2000);
        // 5 - 5 = 0 → not negative → PL
        assert_eq!(branch_result(Condition::MI, 5, 5), 0x1004);
        assert_eq!(branch_result(Condition::PL, 5, 5), 0x2000);
    }

    #[test]
    fn flag_cond_hi_ls_unsigned_greater() {
        // HI = unsigned higher (C && !Z)
        assert_eq!(branch_result(Condition::HI, 5, 3), 0x2000);
        assert_eq!(branch_result(Condition::LS, 5, 3), 0x1004);
        // equal → not HI
        assert_eq!(branch_result(Condition::HI, 5, 5), 0x1004);
        assert_eq!(branch_result(Condition::LS, 5, 5), 0x2000);
        // lower → not HI
        assert_eq!(branch_result(Condition::HI, 3, 5), 0x1004);
        assert_eq!(branch_result(Condition::LS, 3, 5), 0x2000);
    }

    #[test]
    fn flag_cond_ge_lt_signed() {
        // signed: 5 >= 3
        assert_eq!(branch_result(Condition::GE, 5, 3), 0x2000);
        assert_eq!(branch_result(Condition::LT, 5, 3), 0x1004);
        // signed: 3 < 5
        assert_eq!(branch_result(Condition::GE, 3, 5), 0x1004);
        assert_eq!(branch_result(Condition::LT, 3, 5), 0x2000);
        // equal → GE
        assert_eq!(branch_result(Condition::GE, 5, 5), 0x2000);
        assert_eq!(branch_result(Condition::LT, 5, 5), 0x1004);
        // negative values: -1 (0xFFFF...) vs 1
        let neg1 = u64::MAX; // -1 as signed
        assert_eq!(branch_result(Condition::LT, neg1, 1), 0x2000);
        assert_eq!(branch_result(Condition::GE, neg1, 1), 0x1004);
    }

    #[test]
    fn flag_cond_gt_le_signed() {
        // 5 > 3
        assert_eq!(branch_result(Condition::GT, 5, 3), 0x2000);
        assert_eq!(branch_result(Condition::LE, 5, 3), 0x1004);
        // 3 <= 5
        assert_eq!(branch_result(Condition::GT, 3, 5), 0x1004);
        assert_eq!(branch_result(Condition::LE, 3, 5), 0x2000);
        // equal → LE but not GT
        assert_eq!(branch_result(Condition::GT, 5, 5), 0x1004);
        assert_eq!(branch_result(Condition::LE, 5, 5), 0x2000);
    }

    #[test]
    fn flag_cond_vs_vc_overflow() {
        // Signed overflow: MAX_POSITIVE - (-1) = MAX+1 → overflow
        let max_pos = i64::MAX as u64; // 0x7FFFFFFFFFFFFFFF
        let neg1 = u64::MAX; // -1
        assert_eq!(branch_result(Condition::VS, max_pos, neg1), 0x2000);
        assert_eq!(branch_result(Condition::VC, max_pos, neg1), 0x1004);
        // No overflow: 5 - 3 = 2
        assert_eq!(branch_result(Condition::VS, 5, 3), 0x1004);
        assert_eq!(branch_result(Condition::VC, 5, 3), 0x2000);
    }

    // ── Bitfield insert tests ─────────────────────────────────────────

    #[test]
    fn bitfield_ubfiz_insert() {
        // UBFIZ X0, X1, #8, #4  → X0 = (X1 & 0xF) << 8
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "ubfiz".to_string(),
            operands: vec![
                Expr::Reg(Reg::X(0)),
                Expr::Reg(Reg::X(1)),
                Expr::Imm(8),
                Expr::Imm(4),
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        ctx.x[1] = 0xAB;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0], 0x0B00); // (0xAB & 0xF) << 8 = 0xB << 8
    }

    #[test]
    fn bitfield_sbfiz_signed_insert() {
        // SBFIZ X0, X1, #4, #8  → X0 = sign_extend(X1[7:0]) << 4
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "sbfiz".to_string(),
            operands: vec![
                Expr::Reg(Reg::X(0)),
                Expr::Reg(Reg::X(1)),
                Expr::Imm(4),
                Expr::Imm(8),
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        // Positive value: 0x7F → sign_extend(0x7F, 8) = 0x7F, << 4 = 0x7F0
        let mut ctx = JitContext::default();
        ctx.x[1] = 0x7F;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0], 0x7F0);
        // Negative value: 0x80 → sign_extend = 0xFFFFFFFFFFFFFF80, << 4
        let mut ctx = JitContext::default();
        ctx.x[1] = 0x80;
        unsafe { func(&mut ctx) };
        assert_eq!(
            ctx.x[0],
            0xFFFFFFFFFFFF8000_u64 as u64 >> 0 | 0xFFFFFFFFFFFFF800
        );
        // Actually: sign_extend(0x80, 8) = 0xFFFFFFFFFFFFFF80, << 4 = 0xFFFFFFFFFFFFF800
        assert_eq!(ctx.x[0], 0xFFFFFFFFFFFFF800);
    }

    #[test]
    fn bitfield_bfi_insert_into_dest() {
        // BFI X0, X1, #8, #4  → X0[11:8] = X1[3:0], other bits preserved
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "bfi".to_string(),
            operands: vec![
                Expr::Reg(Reg::X(0)),
                Expr::Reg(Reg::X(1)),
                Expr::Imm(8),
                Expr::Imm(4),
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        ctx.x[0] = 0xFFFF_FFFF;
        ctx.x[1] = 0x05;
        unsafe { func(&mut ctx) };
        // Bits [11:8] replaced with 0x5, rest unchanged
        assert_eq!(ctx.x[0], 0xFFFFF5FF);
    }

    #[test]
    fn bitfield_bfxil_extract_insert_low() {
        // BFXIL X0, X1, #8, #4  → X0[3:0] = X1[11:8], other bits preserved
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "bfxil".to_string(),
            operands: vec![
                Expr::Reg(Reg::X(0)),
                Expr::Reg(Reg::X(1)),
                Expr::Imm(8),
                Expr::Imm(4),
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        ctx.x[0] = 0xFFFF_FFF0;
        ctx.x[1] = 0xABCD;
        unsafe { func(&mut ctx) };
        // X1[11:8] = 0xB, insert into X0[3:0] → 0xFFFF_FFFB
        assert_eq!(ctx.x[0], 0xFFFF_FFFB);
    }

    // ── Float conversion tests ────────────────────────────────────────

    #[test]
    fn int_to_float_scvtf() {
        // SCVTF D0, X1  → D0 = (double)X1_signed
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::D(0),
            src: Expr::IntToFloat(Box::new(Expr::Reg(Reg::X(1)))),
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        ctx.x[1] = 42;
        unsafe { func(&mut ctx) };
        let result = f64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap());
        assert_eq!(result, 42.0);
        // Negative
        let mut ctx = JitContext::default();
        ctx.x[1] = (-7i64) as u64;
        unsafe { func(&mut ctx) };
        let result = f64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap());
        assert_eq!(result, -7.0);
    }

    #[test]
    fn float_to_int_fcvtzs() {
        // FCVTZS X0, D1  → X0 = (int64_t)D1 (truncate toward zero)
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::FloatToInt(Box::new(Expr::Reg(Reg::D(1)))),
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        ctx.simd[1][..8].copy_from_slice(&3.7f64.to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as i64, 3);
        // Negative
        let mut ctx = JitContext::default();
        ctx.simd[1][..8].copy_from_slice(&(-9.9f64).to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as i64, -9);
    }

    #[test]
    fn setflags_fsub_with_inline_f32_load_compiles() {
        // Reduced fcmp-style blocks inline the compared float load. These
        // must stay on the float path even when flag lowering does not pass a
        // float hint through.
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![
            Stmt::SetFlags {
                expr: Expr::FSub(
                    Box::new(Expr::Reg(Reg::S(0))),
                    Box::new(Expr::Load {
                        addr: Box::new(Expr::Imm(0x9b5ff100)),
                        size: 4,
                    }),
                ),
            },
            Stmt::CondBranch {
                cond: BranchCond::BitZero(Expr::Reg(Reg::W(3)), 31),
                target: Expr::Imm(0x2000),
                fallthrough: 0x1004,
            },
        ];

        compiler.compile_block(0x1000, &stmts).expect("compile");
    }

    #[test]
    fn setflags_fsub_with_inline_f32_load_on_lhs_compiles() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![
            Stmt::SetFlags {
                expr: Expr::FSub(
                    Box::new(Expr::Load {
                        addr: Box::new(Expr::Add(
                            Box::new(Expr::Reg(Reg::X(0))),
                            Box::new(Expr::Imm(0x14)),
                        )),
                        size: 4,
                    }),
                    Box::new(Expr::Reg(Reg::S(0))),
                ),
            },
            Stmt::CondBranch {
                cond: BranchCond::NotZero(Expr::Reg(Reg::W(1))),
                target: Expr::Imm(0x2000),
                fallthrough: 0x1004,
            },
        ];

        compiler.compile_block(0x1000, &stmts).expect("compile");
    }

    #[test]
    fn write_s_reg_from_xzr_reduces_to_32_bits() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::S(0),
            src: Expr::Reg(Reg::XZR),
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        unsafe { func(&mut ctx) };
        assert_eq!(&ctx.simd[0][..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn vector_ucvtf_2d_converts_u64_lanes_to_f64() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::V(0),
            src: Expr::Intrinsic {
                name: "ucvtf.2d".to_string(),
                operands: vec![Expr::Reg(Reg::V(1))],
            },
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        ctx.simd[1][..8].copy_from_slice(&42u64.to_le_bytes());
        ctx.simd[1][8..16].copy_from_slice(&7u64.to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(
            f64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap()),
            42.0
        );
        assert_eq!(
            f64::from_le_bytes(ctx.simd[0][8..16].try_into().unwrap()),
            7.0
        );
    }

    #[test]
    fn vector_fcvtzu_2d_converts_f64_lanes_to_u64() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::V(0),
            src: Expr::Intrinsic {
                name: "fcvtzu.2d".to_string(),
                operands: vec![Expr::Reg(Reg::V(1))],
            },
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        ctx.simd[1][..8].copy_from_slice(&3.75f64.to_le_bytes());
        ctx.simd[1][8..16].copy_from_slice(&9.0f64.to_le_bytes());
        unsafe { func(&mut ctx) };
        assert_eq!(u64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap()), 3);
        assert_eq!(
            u64::from_le_bytes(ctx.simd[0][8..16].try_into().unwrap()),
            9
        );
    }

    #[test]
    fn umull2_4s_multiplies_upper_half_u16_lanes_by_scalar_lane() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Intrinsic {
            name: "umull2.4s".to_string(),
            operands: vec![
                Expr::Reg(Reg::V(0)),
                Expr::Reg(Reg::V(1)),
                Expr::Extract {
                    src: Box::new(Expr::Reg(Reg::V(2))),
                    lsb: 16,
                    width: 16,
                },
            ],
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        for (index, lane) in [1u16, 2, 3, 4, 5, 6, 7, 8].into_iter().enumerate() {
            let start = index * 2;
            ctx.simd[1][start..start + 2].copy_from_slice(&lane.to_le_bytes());
        }
        for (index, lane) in [2u16, 3, 4, 5, 6, 7, 8, 9].into_iter().enumerate() {
            let start = index * 2;
            ctx.simd[2][start..start + 2].copy_from_slice(&lane.to_le_bytes());
        }
        unsafe { func(&mut ctx) };
        let lanes = [
            u32::from_le_bytes(ctx.simd[0][0..4].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[0][4..8].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[0][8..12].try_into().unwrap()),
            u32::from_le_bytes(ctx.simd[0][12..16].try_into().unwrap()),
        ];
        assert_eq!(lanes, [15, 18, 21, 24]);
    }

    #[test]
    fn fcvt_f32_to_f64() {
        // FCVT D0, S1  → promote f32 to f64
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::D(0),
            src: Expr::FCvt(Box::new(Expr::Reg(Reg::S(2)))),
        }];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        let mut ctx = JitContext::default();
        ctx.simd[2][..4].copy_from_slice(&2.5f32.to_le_bytes());
        unsafe { func(&mut ctx) };
        let result = f64::from_le_bytes(ctx.simd[0][..8].try_into().unwrap());
        assert_eq!(result, 2.5);
    }

    // ── CondSelect test ───────────────────────────────────────────────

    #[test]
    fn condselect_picks_correct_value() {
        // SetFlags(Sub(X0, X1)) then CondSelect EQ → X2 if true, X3 if false
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![
            Stmt::SetFlags {
                expr: Expr::Sub(
                    Box::new(Expr::Reg(Reg::X(0))),
                    Box::new(Expr::Reg(Reg::X(1))),
                ),
            },
            Stmt::Assign {
                dst: Reg::X(4),
                src: Expr::CondSelect {
                    cond: Condition::EQ,
                    if_true: Box::new(Expr::Reg(Reg::X(2))),
                    if_false: Box::new(Expr::Reg(Reg::X(3))),
                },
            },
            Stmt::Branch {
                target: Expr::Imm(0),
            },
        ];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        // Equal: select if_true (X2)
        let mut ctx = JitContext::default();
        ctx.x[0] = 10;
        ctx.x[1] = 10;
        ctx.x[2] = 100;
        ctx.x[3] = 200;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[4], 100);
        // Not equal: select if_false (X3)
        let mut ctx = JitContext::default();
        ctx.x[0] = 10;
        ctx.x[1] = 20;
        ctx.x[2] = 100;
        ctx.x[3] = 200;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[4], 200);
    }

    #[test]
    fn condselect_lt_signed_comparison() {
        // CondSelect LT with signed values
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![
            Stmt::SetFlags {
                expr: Expr::Sub(
                    Box::new(Expr::Reg(Reg::X(0))),
                    Box::new(Expr::Reg(Reg::X(1))),
                ),
            },
            Stmt::Assign {
                dst: Reg::X(2),
                src: Expr::CondSelect {
                    cond: Condition::LT,
                    if_true: Box::new(Expr::Imm(1)),
                    if_false: Box::new(Expr::Imm(0)),
                },
            },
            Stmt::Branch {
                target: Expr::Imm(0),
            },
        ];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        // -1 < 1 → LT true
        let mut ctx = JitContext::default();
        ctx.x[0] = u64::MAX; // -1
        ctx.x[1] = 1;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], 1);
        // 5 < 3 → LT false
        let mut ctx = JitContext::default();
        ctx.x[0] = 5;
        ctx.x[1] = 3;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], 0);
    }

    #[test]
    fn adc_add_with_carry() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // Set carry flag, then ADC
        let stmts = vec![
            // Set flags with 0xFFFFFFFF + 1 → carry set
            Stmt::SetFlags {
                expr: Expr::Add(Box::new(Expr::Reg(Reg::W(2))), Box::new(Expr::Imm(1))),
            },
            // W0 = ADC(W0, W1) = W0 + W1 + C
            Stmt::Assign {
                dst: Reg::W(0),
                src: Expr::Intrinsic {
                    name: "adc".to_string(),
                    operands: vec![Expr::Reg(Reg::W(0)), Expr::Reg(Reg::W(1))],
                },
            },
        ];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        let mut ctx = JitContext::default();
        ctx.x[0] = 10;
        ctx.x[1] = 20;
        ctx.x[2] = 0xFFFFFFFF; // will cause carry when +1
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as u32, 31); // 10 + 20 + 1(carry)
    }

    #[test]
    fn sbc_subtract_with_carry() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        // Set carry flag (= no borrow), then SBC
        let stmts = vec![
            // CMP 5, 3 → carry set (no borrow)
            Stmt::SetFlags {
                expr: Expr::Sub(
                    Box::new(Expr::Reg(Reg::W(2))),
                    Box::new(Expr::Reg(Reg::W(3))),
                ),
            },
            // W0 = SBC(W0, W1) = W0 - W1 - !C = W0 + ~W1 + C
            Stmt::Assign {
                dst: Reg::W(0),
                src: Expr::Intrinsic {
                    name: "sbc".to_string(),
                    operands: vec![Expr::Reg(Reg::W(0)), Expr::Reg(Reg::W(1))],
                },
            },
        ];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // With carry set: SBC = 100 - 30 - 0 = 70
        let mut ctx = JitContext::default();
        ctx.x[0] = 100;
        ctx.x[1] = 30;
        ctx.x[2] = 5; // > 3 → carry set
        ctx.x[3] = 3;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as u32, 70);
    }

    #[test]
    fn umulh_unsigned_multiply_high() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(2),
            src: Expr::Intrinsic {
                name: "umulh".to_string(),
                operands: vec![Expr::Reg(Reg::X(0)), Expr::Reg(Reg::X(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // Small values: upper 64 bits should be 0
        let mut ctx = JitContext::default();
        ctx.x[0] = 100;
        ctx.x[1] = 200;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], 0);

        // Large values: 2^63 * 2 = 2^64, upper = 1
        let mut ctx = JitContext::default();
        ctx.x[0] = 1u64 << 63;
        ctx.x[1] = 2;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], 1);

        // u64::MAX * u64::MAX: upper bits
        let mut ctx = JitContext::default();
        ctx.x[0] = u64::MAX;
        ctx.x[1] = u64::MAX;
        unsafe { func(&mut ctx) };
        // (2^64-1)^2 = 2^128 - 2^65 + 1, upper 64 bits = 2^64 - 2 = 0xFFFFFFFFFFFFFFFE
        assert_eq!(ctx.x[2], u64::MAX - 1);
    }

    #[test]
    fn smulh_signed_multiply_high() {
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(2),
            src: Expr::Intrinsic {
                name: "smulh".to_string(),
                operands: vec![Expr::Reg(Reg::X(0)), Expr::Reg(Reg::X(1))],
            },
        }];

        let code = compiler
            .compile_block(0x1000, &stmts)
            .expect("compile block");
        let func: JitEntry = unsafe { std::mem::transmute(code) };

        // Small positive: upper should be 0
        let mut ctx = JitContext::default();
        ctx.x[0] = 100;
        ctx.x[1] = 200;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], 0);

        // -1 * 1 = -1, upper 64 bits = -1 (all ones)
        let mut ctx = JitContext::default();
        ctx.x[0] = u64::MAX; // -1 as i64
        ctx.x[1] = 1;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], u64::MAX); // -1

        // i64::MIN * 2: (-2^63) * 2 = -2^64, upper = -1
        let mut ctx = JitContext::default();
        ctx.x[0] = 1u64 << 63; // i64::MIN
        ctx.x[1] = 2;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], u64::MAX); // -1

        // Large positive: i64::MAX * 2 = 2^64 - 2, upper = 0
        let mut ctx = JitContext::default();
        ctx.x[0] = i64::MAX as u64;
        ctx.x[1] = 2;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[2], 0);
    }

    #[test]
    fn ngc_negate_with_carry() {
        // NGC X0, X1 → X0 = -X1 - 1 + C
        let mut compiler = JitCompiler::new(JitConfig::default());
        let stmts = vec![
            // 5 - 3 → carry set (C=1)
            Stmt::SetFlags {
                expr: Expr::Sub(
                    Box::new(Expr::Reg(Reg::X(2))),
                    Box::new(Expr::Reg(Reg::X(3))),
                ),
            },
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Intrinsic {
                    name: "ngc".to_string(),
                    operands: vec![Expr::Reg(Reg::X(1))],
                },
            },
            Stmt::Branch {
                target: Expr::Imm(0),
            },
        ];
        let code = compiler.compile_block(0x1000, &stmts).expect("compile");
        let func: JitEntry = unsafe { std::mem::transmute(code) };
        // C=1: NGC X0, 10 → -10 -1 + 1 = -10
        let mut ctx = JitContext::default();
        ctx.x[1] = 10;
        ctx.x[2] = 5;
        ctx.x[3] = 3;
        unsafe { func(&mut ctx) };
        assert_eq!(ctx.x[0] as i64, -10);
    }

    #[test]
    fn object_compiler_emits_block_memory_trap_branch_and_bridge_hook_symbols() {
        use object::{Object, ObjectSymbol};

        let mut compiler = ObjectCompiler::new_aarch64(JitConfig {
            instrument_memory: true,
            instrument_blocks: false,
        })
        .expect("object compiler");
        compiler
            .compile_block(
                0x1000,
                &[
                    Stmt::Assign {
                        dst: Reg::X(0),
                        src: Expr::Load {
                            addr: Box::new(Expr::Imm(0x2000)),
                            size: 8,
                        },
                    },
                    Stmt::Branch {
                        target: Expr::Imm(0),
                    },
                ],
            )
            .expect("compile block");
        let artifact = compiler.finish().expect("finish object");
        let file = object::File::parse(artifact.bytes.as_slice()).expect("parse object");
        let mut names = Vec::new();
        for symbol in file.symbols() {
            if let Ok(name) = symbol.name() {
                names.push(name.to_string());
            }
        }
        assert!(names
            .iter()
            .any(|name| name.contains("aeon_jit_block_0000000000001000")));
        assert!(names.iter().any(|name| name == OBJECT_MEMORY_READ_HOOK));
        assert!(names.iter().any(|name| name == OBJECT_TRAP_HOOK));
        assert!(names
            .iter()
            .any(|name| name == OBJECT_BRANCH_TRANSLATE_HOOK));
        assert!(names.iter().any(|name| name == OBJECT_BRANCH_BRIDGE_HOOK));
        assert!(names.iter().any(|name| name == OBJECT_UNKNOWN_BLOCK_HOOK));
        assert_eq!(
            artifact.branch_translate_hook_symbol.as_deref(),
            Some(OBJECT_BRANCH_TRANSLATE_HOOK)
        );
        assert_eq!(
            artifact.branch_bridge_hook_symbol.as_deref(),
            Some(OBJECT_BRANCH_BRIDGE_HOOK)
        );
        assert_eq!(
            artifact.unknown_block_hook_symbol.as_deref(),
            Some(OBJECT_UNKNOWN_BLOCK_HOOK)
        );
    }
}
