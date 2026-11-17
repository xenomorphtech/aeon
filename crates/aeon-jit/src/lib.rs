//! Cranelift backend for AeonIL.
//!
//! - `jit_compiler`: in-process JIT (`JitCompiler`).
//! - `object_compiler`: ahead-of-time AArch64 object emission (`ObjectCompiler`).
//! - `imports`: the helper and hook functions a compiled block may call.
//! - `runtime`: callback registry and `extern "C"` hooks called from compiled
//!   code. All of the crate's `unsafe` lives here.
//! - `lower`: AeonIL to Cranelift IR. `LoweringState` is defined in
//!   `lower/mod.rs` with statement and control-flow lowering; its other methods
//!   are grouped by concern in `expr`, `flags`, `regs`, `coerce`,
//!   `intrinsic_expr`, `intrinsic_stmt` and `simd`.

use aeonil::{Condition, Reg};
use cranelift_module::ModuleError;
use std::error::Error;
use std::fmt;

mod imports;
mod jit_compiler;
mod lower;
mod object_compiler;
mod runtime;
#[cfg(all(test, target_arch = "x86_64"))]
mod tests;

pub use jit_compiler::JitCompiler;
pub use object_compiler::{ObjectArtifact, ObjectCompiler};
pub use runtime::{
    aeon_fcmla_8h, on_block_enter, on_branch_bridge, on_branch_translate, on_memory_read,
    on_memory_write,
};

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
