use aeonil::{BranchCond, Condition, Expr, Reg, Stmt};
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::immediates::{Ieee32, Ieee64};
use cranelift_codegen::ir::types::{self, I8X16};
use cranelift_codegen::ir::{
    AbiParam, FuncRef, InstBuilder, MemFlags, Signature, Type, UserFuncName, Value,
};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{default_libcall_names, Linkage, Module, ModuleError};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::mem::offset_of;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

pub type MemoryReadCallback = extern "C" fn(u64, u8);
pub type MemoryWriteCallback = extern "C" fn(u64, u8, u64);
pub type JitEntry = unsafe extern "C" fn(*mut JitContext) -> u64;

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
static BLOCK_COUNTERS_PTR: AtomicPtr<u64> = AtomicPtr::new(std::ptr::null_mut());
static BLOCK_COUNTERS_LEN: AtomicUsize = AtomicUsize::new(0);

pub extern "C" fn on_memory_read(addr: u64, size: u8) {
    let callback = MEMORY_READ_CALLBACK.load(Ordering::SeqCst);
    if callback == 0 {
        return;
    }
    let callback: MemoryReadCallback = unsafe { std::mem::transmute(callback) };
    callback(addr, size);
}

pub extern "C" fn on_memory_write(addr: u64, size: u8, value: u64) {
    let callback = MEMORY_WRITE_CALLBACK.load(Ordering::SeqCst);
    if callback == 0 {
        return;
    }
    let callback: MemoryWriteCallback = unsafe { std::mem::transmute(callback) };
    callback(addr, size, value);
}

pub extern "C" fn on_block_enter(block_id: u64) {
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

pub struct JitCompiler {
    config: JitConfig,
    module: JITModule,
    func_ctx: FunctionBuilderContext,
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
            .symbol("on_block_enter", on_block_enter as *const u8);

        Self {
            config,
            module: JITModule::new(builder),
            func_ctx: FunctionBuilderContext::new(),
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

    pub fn set_block_counters(&mut self, counters: *mut u64, len: usize) {
        BLOCK_COUNTERS_PTR.store(counters, Ordering::SeqCst);
        BLOCK_COUNTERS_LEN.store(len, Ordering::SeqCst);
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

        let func_id = self
            .module
            .declare_function(&func_name, Linkage::Local, &signature)?;
        let mut ctx = self.module.make_context();
        ctx.func.signature = signature;
        ctx.func.name = UserFuncName::user(0, func_id.as_u32());

        let mut imports = Imports::new();
        {
            let mut builder = FunctionBuilder::new(&mut ctx.func, &mut self.func_ctx);
            let entry = builder.create_block();
            builder.switch_to_block(entry);
            builder.append_block_params_for_function_params(entry);
            builder.seal_block(entry);

            let ctx_ptr = builder.block_params(entry)[0];
            imports.declare(&mut self.module, &mut builder, pointer_type, self.config)?;

            let mut state =
                LoweringState::new(ctx_ptr, pointer_type, block_addr, block_id, self.config);
            state.write_pc_immediate(&mut builder, block_addr)?;

            if let Some(counter) = imports.block_counter {
                let block_id_value = builder.ins().iconst(types::I64, block_id as i64);
                builder.ins().call(counter, &[block_id_value]);
            }

            state.lower_stmts(&mut self.module, &mut builder, &imports, stmts)?;
            if !state.terminated {
                state.flush_scalars(&mut builder)?;
                let ret = builder.ins().iconst(types::I64, 0);
                builder.ins().return_(&[ret]);
            }

            builder.seal_all_blocks();
            builder.finalize();
        }

        self.module.define_function(func_id, &mut ctx)?;
        self.module.clear_context(&mut ctx);
        self.module.finalize_definitions()?;
        Ok(self.module.get_finalized_function(func_id))
    }
}

#[derive(Default)]
struct Imports {
    memory_read: Option<FuncRef>,
    memory_write: Option<FuncRef>,
    block_counter: Option<FuncRef>,
    call_sig: Option<cranelift_codegen::ir::SigRef>,
}

impl Imports {
    fn new() -> Self {
        Self::default()
    }

    fn declare(
        &mut self,
        module: &mut JITModule,
        builder: &mut FunctionBuilder<'_>,
        pointer_type: Type,
        config: JitConfig,
    ) -> Result<(), JitError> {
        if config.instrument_memory {
            let mut read_sig = module.make_signature();
            read_sig.params.push(AbiParam::new(types::I64));
            read_sig.params.push(AbiParam::new(types::I8));
            let read = module.declare_function("on_memory_read", Linkage::Import, &read_sig)?;
            self.memory_read = Some(module.declare_func_in_func(read, builder.func));

            let mut write_sig = module.make_signature();
            write_sig.params.push(AbiParam::new(types::I64));
            write_sig.params.push(AbiParam::new(types::I8));
            write_sig.params.push(AbiParam::new(types::I64));
            let write = module.declare_function("on_memory_write", Linkage::Import, &write_sig)?;
            self.memory_write = Some(module.declare_func_in_func(write, builder.func));
        }

        if config.instrument_blocks {
            let mut sig = module.make_signature();
            sig.params.push(AbiParam::new(types::I64));
            let block = module.declare_function("on_block_enter", Linkage::Import, &sig)?;
            self.block_counter = Some(module.declare_func_in_func(block, builder.func));
        }

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
    config: JitConfig,
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
    fn new(
        ctx_ptr: Value,
        pointer_type: Type,
        block_addr: u64,
        block_id: u64,
        config: JitConfig,
    ) -> Self {
        Self {
            ctx_ptr,
            pointer_type,
            block_addr,
            _block_id: block_id,
            config,
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
        module: &mut JITModule,
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
        module: &mut JITModule,
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
                if self.config.instrument_memory {
                    if let Some(callback) = imports.memory_write {
                        let size = builder.ins().iconst(types::I8, i64::from(*size));
                        let callback_value = self.value_as_u64_bits(builder, value)?;
                        builder
                            .ins()
                            .call(callback, &[addr.value, size, callback_value]);
                    }
                }
                builder
                    .ins()
                    .store(MemFlags::new(), value.value, addr.value, 0);
            }
            Stmt::Branch { target } => {
                let target = self.lower_expr(module, builder, imports, target, Some(types::I64))?;
                let target = self.coerce_int(builder, target, types::I64)?;
                self.write_pc_value(builder, target.value)?;
                self.flush_scalars(builder)?;
                builder.ins().return_(&[target.value]);
                self.terminated = true;
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
                self.write_pc_value(builder, target.value)?;
                self.flush_scalars(builder)?;
                builder.ins().return_(&[target.value]);
                builder.seal_block(then_block);

                self.restore_scalar_dirty(dirty_snapshot);
                builder.switch_to_block(else_block);
                let fallthrough = builder.ins().iconst(types::I64, *fallthrough as i64);
                self.write_pc_value(builder, fallthrough)?;
                self.flush_scalars(builder)?;
                builder.ins().return_(&[fallthrough]);
                builder.seal_block(else_block);
                self.terminated = true;
            }
            Stmt::Call { target } => {
                self.flush_scalars(builder)?;
                let target =
                    self.lower_expr(module, builder, imports, target, Some(self.pointer_type))?;
                let target = self.coerce_int(builder, target, self.pointer_type)?;
                if let Some(sig) = imports.call_sig {
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
            Stmt::Nop | Stmt::Barrier(_) => {}
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
            Stmt::Trap => {
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

    fn lower_branch_cond(
        &mut self,
        module: &mut JITModule,
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
        module: &mut JITModule,
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
                if self.config.instrument_memory {
                    if let Some(callback) = imports.memory_read {
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
        module: &mut JITModule,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        lhs: &Expr,
        rhs: &Expr,
        hint: Option<Type>,
        op: impl Fn(&mut FunctionBuilder<'_>, Value, Value) -> Value,
    ) -> Result<LoweredValue, JitError> {
        let ty = self.resolve_float_type(hint, None)?;
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
        module: &mut JITModule,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        inner: &Expr,
        hint: Option<Type>,
        op: impl Fn(&mut FunctionBuilder<'_>, Value) -> Value,
    ) -> Result<LoweredValue, JitError> {
        let ty = self.resolve_float_type(hint, None)?;
        let inner = self.lower_expr(module, builder, imports, inner, Some(ty))?;
        let inner = self.coerce_float(builder, inner, ty)?;
        Ok(LoweredValue {
            value: op(builder, inner.value),
            ty,
        })
    }

    fn lower_compare_condition(
        &mut self,
        module: &mut JITModule,
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
        module: &mut JITModule,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        expr: &Expr,
    ) -> Result<Value, JitError> {
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
        module: &mut JITModule,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
        operands: &[Expr],
        hint: Option<Type>,
    ) -> Result<LoweredValue, JitError> {
        match name {
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
        module: &mut JITModule,
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

    fn lower_float_rounding_intrinsic(
        &mut self,
        module: &mut JITModule,
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
        module: &mut JITModule,
        builder: &mut FunctionBuilder<'_>,
        imports: &Imports,
        name: &str,
        operands: &[Expr],
    ) -> Result<(), JitError> {
        match name {
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
                // Other MSR targets: treat as nop
                Ok(())
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
                Ok(())
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
        module: &mut JITModule,
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
        module: &mut JITModule,
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
            | Expr::FMin(lhs, rhs) => self
                .infer_expr_type(lhs)
                .or_else(|| self.infer_expr_type(rhs))
                .or(Some(types::F64)),
            Expr::FNeg(inner) | Expr::FAbs(inner) | Expr::FSqrt(inner) | Expr::FCvt(inner) => {
                self.infer_expr_type(inner).or(Some(types::F64))
            }
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
                value: builder.ins().bitcast(target, MemFlags::new(), value.value),
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
            builder.ins().bitcast(target, MemFlags::new(), value.value)
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
        } else if value.ty.is_int() && value.ty.bits() == target.bits() {
            builder.ins().bitcast(target, MemFlags::new(), value.value)
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
            let bits = builder.ins().bitcast(bits_ty, MemFlags::new(), value.value);
            return Ok(if bits_ty == types::I64 {
                bits
            } else {
                builder.ins().uextend(types::I64, bits)
            });
        }
        if value.ty == I8X16 {
            let i64x2 = builder
                .ins()
                .bitcast(types::I64X2, MemFlags::new(), value.value);
            return Ok(builder.ins().extractlane(i64x2, 0));
        }
        Err(JitError::TypeMismatch("instrumentation value"))
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
    static LAST_READ_ADDR: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_ADDR: AtomicU64 = AtomicU64::new(0);
    static LAST_WRITE_VALUE: AtomicU64 = AtomicU64::new(0);

    extern "C" fn test_on_memory_read(addr: u64, _size: u8) {
        READ_COUNT.fetch_add(1, Ordering::SeqCst);
        LAST_READ_ADDR.store(addr, Ordering::SeqCst);
    }

    extern "C" fn test_on_memory_write(addr: u64, _size: u8, value: u64) {
        WRITE_COUNT.fetch_add(1, Ordering::SeqCst);
        LAST_WRITE_ADDR.store(addr, Ordering::SeqCst);
        LAST_WRITE_VALUE.store(value, Ordering::SeqCst);
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
}
