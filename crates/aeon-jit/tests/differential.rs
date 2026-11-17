#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

//! Differential test: Unicorn vs. the IL interpreter vs. the JIT.
//!
//! Each case is a short AArch64 snippet (see `differential/gen_cases.py`). It
//! runs three ways from the same initial state:
//!
//! 1. natively under Unicorn, which is the reference;
//! 2. lifted to AeonIL and interpreted (`aeon::emulation::execute_block`);
//! 3. lifted to AeonIL, JIT-compiled and executed on the host.
//!
//! Afterwards x0-x30, SP, NZCV, v0-v31 and a data region must match the
//! reference. Snippets may branch: the interpreter and the JIT work a block at
//! a time, so both are driven block by block until control reaches the end of
//! the snippet.
//!
//! The data region is mapped at the same address in Unicorn and in this
//! process, because JIT-compiled code dereferences guest addresses directly.
//! x20 points into it and SP is its upper part.
//!
//! Engines that are known to disagree are listed in `KNOWN`; the test fails
//! when an unlisted engine disagrees and also when a listed one starts
//! agreeing, so the list cannot go stale.

use aeon::emulation::{
    execute_block, BackingStore, BlockStop, MemoryLocation, MissingMemoryPolicy, Value,
};
use aeon_jit::{JitCompiler, JitConfig, JitContext, JitEntry};
use aeonil::{Expr, Reg, Stmt};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

pub struct Case {
    pub name: &'static str,
    pub asm: &'static str,
    pub words: &'static [u32],
}

include!("differential/cases.rs");

const BASE: u64 = 0x10000;
/// Data region shared by all engines. x20 starts at `DATA_PTR`, SP at
/// `STACK_TOP`.
const DATA: u64 = 0x2000_0000;
const DATA_SIZE: usize = 0x2000;
const DATA_PTR: u64 = DATA + 0x800;
const STACK_TOP: u64 = DATA + 0x1800;
/// Blocks a snippet may execute before it is declared stuck.
const MAX_BLOCKS: usize = 256;

/// Everything the engines are compared on.
#[derive(Clone, PartialEq, Eq)]
struct State {
    x: [u64; 31],
    sp: u64,
    /// NZCV as a 4-bit value.
    nzcv: u64,
    v: [u128; 32],
    mem: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Engine {
    Interpreter,
    Jit,
    /// The JIT fed with IL that went through `aeon_reduce`'s block-local
    /// pipeline first, as `aeon-instrument` does.
    ReducedJit,
}

/// Why an engine did not reproduce the reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gap {
    /// Ran, and produced a different register or flag value.
    Wrong,
    /// The interpreter left a register it should have computed as `Unknown`.
    Unknown,
    /// Refused the IL: a JIT compile error or an interpreter panic.
    Unsupported,
    /// The compiled code killed the process with a signal.
    Crash,
}

/// Engines currently known not to match Unicorn. Keep this list shrinking.
const KNOWN: &[(&str, Engine, Gap)] = &[
    // Every scalar, memory and branch case agrees. What is left is SIMD the
    // engines do not implement; none of it gives a wrong answer.
    //
    // Neither engine: widening, narrowing, permutes, table lookup,
    // reductions, vector floating point and multi-register LD1/ST1.
    ("uxtl2 v9.4s, v1.8h", Engine::Interpreter, Gap::Unsupported),
    ("uxtl2 v9.4s, v1.8h", Engine::Jit, Gap::Unsupported),
    ("sxtl v10.2d, v2.2s", Engine::Interpreter, Gap::Unsupported),
    ("sxtl v10.2d, v2.2s", Engine::Jit, Gap::Unsupported),
    (
        "ushll v11.4s, v3.4h, #3",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("ushll v11.4s, v3.4h, #3", Engine::Jit, Gap::Unsupported),
    (
        "umull v12.2d, v4.2s, v5.2s",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("umull v12.2d, v4.2s, v5.2s", Engine::Jit, Gap::Unsupported),
    (
        "umull2 v13.8h, v6.16b, v7.16b",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    (
        "umull2 v13.8h, v6.16b, v7.16b",
        Engine::Jit,
        Gap::Unsupported,
    ),
    ("xtn v14.8b, v0.8h", Engine::Interpreter, Gap::Unsupported),
    ("xtn v14.8b, v0.8h", Engine::Jit, Gap::Unsupported),
    (
        "zip1 v8.16b, v0.16b, v1.16b",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("zip1 v8.16b, v0.16b, v1.16b", Engine::Jit, Gap::Unsupported),
    (
        "zip2 v9.4s, v2.4s, v3.4s",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("zip2 v9.4s, v2.4s, v3.4s", Engine::Jit, Gap::Unsupported),
    (
        "uzp1 v10.8h, v4.8h, v5.8h",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("uzp1 v10.8h, v4.8h, v5.8h", Engine::Jit, Gap::Unsupported),
    (
        "uzp2 v11.2d, v6.2d, v7.2d",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("uzp2 v11.2d, v6.2d, v7.2d", Engine::Jit, Gap::Unsupported),
    (
        "trn1 v12.4s, v0.4s, v1.4s",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("trn1 v12.4s, v0.4s, v1.4s", Engine::Jit, Gap::Unsupported),
    (
        "ext v13.16b, v2.16b, v3.16b, #5",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    (
        "ext v13.16b, v2.16b, v3.16b, #5",
        Engine::Jit,
        Gap::Unsupported,
    ),
    (
        "tbl v16.16b, {v6.16b}, v7.16b",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    (
        "tbl v16.16b, {v6.16b}, v7.16b",
        Engine::Jit,
        Gap::Unsupported,
    ),
    ("addv b8, v0.16b", Engine::Interpreter, Gap::Unsupported),
    ("addv b8, v0.16b", Engine::Jit, Gap::Unsupported),
    ("addv s9, v1.4s", Engine::Interpreter, Gap::Unsupported),
    ("addv s9, v1.4s", Engine::Jit, Gap::Unsupported),
    ("umaxv b10, v2.16b", Engine::Interpreter, Gap::Unsupported),
    ("umaxv b10, v2.16b", Engine::Jit, Gap::Unsupported),
    ("uminv h11, v3.8h", Engine::Interpreter, Gap::Unsupported),
    ("uminv h11, v3.8h", Engine::Jit, Gap::Unsupported),
    ("addp d12, v4.2d", Engine::Interpreter, Gap::Unsupported),
    ("addp d12, v4.2d", Engine::Jit, Gap::Unsupported),
    ("uaddlv h14, v6.16b", Engine::Interpreter, Gap::Unsupported),
    ("uaddlv h14, v6.16b", Engine::Jit, Gap::Unsupported),
    (
        "fadd v10.2d, v8.2d, v9.2d",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("fadd v10.2d, v8.2d, v9.2d", Engine::Jit, Gap::Unsupported),
    (
        "fmul v11.2d, v8.2d, v9.2d",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("fmul v11.2d, v8.2d, v9.2d", Engine::Jit, Gap::Unsupported),
    (
        "ld1r {v10.4s}, [x20]",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("ld1r {v10.4s}, [x20]", Engine::Jit, Gap::Unsupported),
    (
        "ld1 {v11.16b, v12.16b}, [x20]",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    (
        "ld1 {v11.16b, v12.16b}, [x20]",
        Engine::Jit,
        Gap::Unsupported,
    ),
    (
        "st1 {v1.16b, v2.16b}, [x20]",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("st1 {v1.16b, v2.16b}, [x20]", Engine::Jit, Gap::Unsupported),
    (
        "fadd v10.2d, v0.2d, v1.2d",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("fadd v10.2d, v0.2d, v1.2d", Engine::Jit, Gap::Unsupported),
    (
        "fmul v11.4s, v0.4s, v1.4s",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("fmul v11.4s, v0.4s, v1.4s", Engine::Jit, Gap::Unsupported),
    // Interpreter only: vector conversions and single-register LD1/ST1.
    ("uxtl v8.8h, v0.8b", Engine::Interpreter, Gap::Unsupported),
    ("scvtf v8.2d, v0.2d", Engine::Interpreter, Gap::Unsupported),
    ("ucvtf v9.2d, v1.2d", Engine::Interpreter, Gap::Unsupported),
    (
        "fcvtzs v12.2d, v10.2d",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    (
        "fcvtzu v13.2d, v11.2d",
        Engine::Interpreter,
        Gap::Unsupported,
    ),
    ("ld1 {v8.16b}, [x20]", Engine::Interpreter, Gap::Unsupported),
    ("ld1 {v9.2d}, [x20]", Engine::Interpreter, Gap::Unsupported),
    ("ld1 {v9.4s}, [x20]", Engine::Interpreter, Gap::Unsupported),
    ("st1 {v0.16b}, [x20]", Engine::Interpreter, Gap::Unsupported),
    ("st1 {v0.4s}, [x20]", Engine::Interpreter, Gap::Unsupported),
    ("simd_post_index", Engine::Interpreter, Gap::Unsupported),
    // JIT only. The JIT has lowerings for many of these as expression
    // intrinsics, but the lifter emits them as statements
    // (`add.4s [dst, a, b]`), which it does not accept.
    ("and v8.16b, v0.16b, v1.16b", Engine::Jit, Gap::Unsupported),
    ("orr v9.16b, v0.16b, v1.16b", Engine::Jit, Gap::Unsupported),
    ("eor v10.16b, v2.16b, v3.16b", Engine::Jit, Gap::Unsupported),
    ("bic v11.16b, v2.16b, v3.16b", Engine::Jit, Gap::Unsupported),
    ("orn v12.16b, v4.16b, v5.16b", Engine::Jit, Gap::Unsupported),
    ("mvn v13.16b, v6.16b", Engine::Jit, Gap::Unsupported),
    ("bsl v0.16b, v1.16b, v2.16b", Engine::Jit, Gap::Unsupported),
    ("bif v3.16b, v4.16b, v5.16b", Engine::Jit, Gap::Unsupported),
    ("bit v6.16b, v7.16b, v1.16b", Engine::Jit, Gap::Unsupported),
    ("add v8.16b, v0.16b, v1.16b", Engine::Jit, Gap::Unsupported),
    ("add v9.8h, v0.8h, v1.8h", Engine::Jit, Gap::Unsupported),
    ("add v10.4s, v2.4s, v3.4s", Engine::Jit, Gap::Unsupported),
    ("add v11.2d, v2.2d, v3.2d", Engine::Jit, Gap::Unsupported),
    ("sub v12.4s, v4.4s, v5.4s", Engine::Jit, Gap::Unsupported),
    ("sub v13.2d, v6.2d, v7.2d", Engine::Jit, Gap::Unsupported),
    ("add v14.8b, v0.8b, v1.8b", Engine::Jit, Gap::Unsupported),
    ("mul v8.4s, v0.4s, v1.4s", Engine::Jit, Gap::Unsupported),
    ("mul v9.8h, v2.8h, v3.8h", Engine::Jit, Gap::Unsupported),
    ("mla v4.4s, v5.4s, v6.4s", Engine::Jit, Gap::Unsupported),
    ("mls v7.16b, v0.16b, v1.16b", Engine::Jit, Gap::Unsupported),
    ("cmeq v8.16b, v0.16b, v1.16b", Engine::Jit, Gap::Unsupported),
    ("cmeq v9.2d, v2.2d, v2.2d", Engine::Jit, Gap::Unsupported),
    ("cmhi v10.4s, v0.4s, v1.4s", Engine::Jit, Gap::Unsupported),
    ("cmgt v11.8h, v2.8h, v3.8h", Engine::Jit, Gap::Unsupported),
    ("cmge v12.2d, v4.2d, v5.2d", Engine::Jit, Gap::Unsupported),
    (
        "cmhs v13.16b, v6.16b, v7.16b",
        Engine::Jit,
        Gap::Unsupported,
    ),
    ("cmeq v14.4s, v0.4s, #0", Engine::Jit, Gap::Unsupported),
    ("shl v8.2d, v0.2d, #7", Engine::Jit, Gap::Unsupported),
    ("sshr v10.8h, v2.8h, #5", Engine::Jit, Gap::Unsupported),
    ("shl v12.4s, v4.4s, #31", Engine::Jit, Gap::Unsupported),
    ("movi v9.4s, #0x12, lsl #8", Engine::Jit, Gap::Unsupported),
    (
        "movi d12, #0xffff0000ffff0000",
        Engine::Jit,
        Gap::Unsupported,
    ),
    ("dup v12.4s, w0", Engine::Jit, Gap::Unsupported),
    ("dup v13.2d, x1", Engine::Jit, Gap::Unsupported),
    ("dup v14.16b, w2", Engine::Jit, Gap::Unsupported),
    ("dup v16.8h, v4.h[3]", Engine::Jit, Gap::Unsupported),
    ("ins v3.s[1], w0", Engine::Jit, Gap::Unsupported),
    ("ins v4.d[1], x1", Engine::Jit, Gap::Unsupported),
    ("ins v5.b[9], v6.b[2]", Engine::Jit, Gap::Unsupported),
    ("fmov v7.d[1], x2", Engine::Jit, Gap::Unsupported),
    ("rev64 v14.16b, v4.16b", Engine::Jit, Gap::Unsupported),
    ("rev32 v15.8h, v5.8h", Engine::Jit, Gap::Unsupported),
    ("cnt v13.16b, v5.16b", Engine::Jit, Gap::Unsupported),
    ("umax v8.16b, v0.16b, v1.16b", Engine::Jit, Gap::Unsupported),
    ("umin v9.4s, v2.4s, v3.4s", Engine::Jit, Gap::Unsupported),
    ("smax v10.8h, v4.8h, v5.8h", Engine::Jit, Gap::Unsupported),
    (
        "smin v11.16b, v6.16b, v7.16b",
        Engine::Jit,
        Gap::Unsupported,
    ),
    ("abs v12.4s, v0.4s", Engine::Jit, Gap::Unsupported),
    ("neg v13.2d, v1.2d", Engine::Jit, Gap::Unsupported),
    ("cmeq d10, d4, d4", Engine::Jit, Gap::Unsupported),
    ("shl d11, d5, #9", Engine::Jit, Gap::Unsupported),
    ("ushr d12, d6, #3", Engine::Jit, Gap::Unsupported),
    ("cmeq v8.8b, v0.8b, v1.8b", Engine::Jit, Gap::Unsupported),
    ("bif v3.8b, v4.8b, v5.8b", Engine::Jit, Gap::Unsupported),
    ("and v8.8b, v0.8b, v1.8b", Engine::Jit, Gap::Unsupported),
    ("movi v8.8b, #0x5a", Engine::Jit, Gap::Unsupported),
    ("dup v12.2s, w0", Engine::Jit, Gap::Unsupported),
    ("sub v12.16b, v4.16b, v5.16b", Engine::Jit, Gap::Unsupported),
    ("sub v12.8h, v4.8h, v5.8h", Engine::Jit, Gap::Unsupported),
    ("mov v15.d[0], x1", Engine::Jit, Gap::Unsupported),
    // ── Reduced IL ──────────────────────────────────────────────────
    // `aeon_reduce::pipeline::reduce_block_local` does not preserve
    // behaviour, so code compiled from its output computes wrong results.
    // Causes identified so far:
    //  - a flag-setting statement is dropped when a conditional select or a
    //    later block still reads the flags;
    //  - `MIN / -1` is folded to 0;
    //  - a register copy is forwarded past a redefinition of its source
    //    (`mov x29, sp` after SP moved) and into an operand that an
    //    intrinsic writes (post-index LD1);
    //  - a folded `movk #0` no longer says which field it clears.
    ("div_overflow", Engine::ReducedJit, Gap::Wrong),
    ("adds_flags", Engine::ReducedJit, Gap::Wrong),
    ("subs_flags", Engine::ReducedJit, Gap::Wrong),
    ("adds_w_flags", Engine::ReducedJit, Gap::Wrong),
    ("subs_w_flags", Engine::ReducedJit, Gap::Wrong),
    ("cmp_conditions", Engine::ReducedJit, Gap::Wrong),
    ("cmp_w_conditions", Engine::ReducedJit, Gap::Wrong),
    ("cmp_imm", Engine::ReducedJit, Gap::Wrong),
    ("cmn", Engine::ReducedJit, Gap::Wrong),
    ("tst_ands", Engine::ReducedJit, Gap::Wrong),
    ("bics", Engine::ReducedJit, Gap::Wrong),
    ("negs", Engine::ReducedJit, Gap::Wrong),
    ("adc_sbc", Engine::ReducedJit, Gap::Wrong),
    ("adcs_sbcs", Engine::ReducedJit, Gap::Wrong),
    ("ccmn", Engine::ReducedJit, Gap::Wrong),
    ("csel_family", Engine::ReducedJit, Gap::Wrong),
    ("csel_w", Engine::ReducedJit, Gap::Wrong),
    ("movk_zero", Engine::ReducedJit, Gap::Wrong),
    ("carry_aliased", Engine::ReducedJit, Gap::Wrong),
    ("fp_ccmp", Engine::ReducedJit, Gap::Wrong),
    ("mem_stack_frame", Engine::ReducedJit, Gap::Wrong),
    ("br_cond_fwd", Engine::ReducedJit, Gap::Wrong),
    ("br_cbz", Engine::ReducedJit, Gap::Wrong),
    ("br_loop", Engine::ReducedJit, Gap::Wrong),
    ("br_conditions", Engine::ReducedJit, Gap::Wrong),
    ("simd_post_index", Engine::ReducedJit, Gap::Wrong),
    // A GPR-to-FP move is forwarded as if it kept its type, leaving float
    // operations on integer registers that the JIT rejects.
    ("fp_convert", Engine::ReducedJit, Gap::Unsupported),
    ("fp_unsigned", Engine::ReducedJit, Gap::Unsupported),
    ("fp_single", Engine::ReducedJit, Gap::Unsupported),
    ("fp_convert_width", Engine::ReducedJit, Gap::Unsupported),
    ("fp_imm", Engine::ReducedJit, Gap::Unsupported),
    // SIMD the JIT does not implement, as above.
    (
        "and v8.16b, v0.16b, v1.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "orr v9.16b, v0.16b, v1.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "eor v10.16b, v2.16b, v3.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "bic v11.16b, v2.16b, v3.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "orn v12.16b, v4.16b, v5.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("mvn v13.16b, v6.16b", Engine::ReducedJit, Gap::Unsupported),
    (
        "bsl v0.16b, v1.16b, v2.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "bif v3.16b, v4.16b, v5.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "bit v6.16b, v7.16b, v1.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "add v8.16b, v0.16b, v1.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "add v9.8h, v0.8h, v1.8h",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "add v10.4s, v2.4s, v3.4s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "add v11.2d, v2.2d, v3.2d",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "sub v12.4s, v4.4s, v5.4s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "sub v13.2d, v6.2d, v7.2d",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "add v14.8b, v0.8b, v1.8b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "mul v8.4s, v0.4s, v1.4s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "mul v9.8h, v2.8h, v3.8h",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "mla v4.4s, v5.4s, v6.4s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "mls v7.16b, v0.16b, v1.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "cmeq v8.16b, v0.16b, v1.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "cmeq v9.2d, v2.2d, v2.2d",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "cmhi v10.4s, v0.4s, v1.4s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "cmgt v11.8h, v2.8h, v3.8h",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "cmge v12.2d, v4.2d, v5.2d",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "cmhs v13.16b, v6.16b, v7.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "cmeq v14.4s, v0.4s, #0",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("shl v8.2d, v0.2d, #7", Engine::ReducedJit, Gap::Unsupported),
    (
        "sshr v10.8h, v2.8h, #5",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "shl v12.4s, v4.4s, #31",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "movi d12, #0xffff0000ffff0000",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("dup v12.4s, w0", Engine::ReducedJit, Gap::Unsupported),
    ("dup v13.2d, x1", Engine::ReducedJit, Gap::Unsupported),
    ("dup v14.16b, w2", Engine::ReducedJit, Gap::Unsupported),
    ("dup v16.8h, v4.h[3]", Engine::ReducedJit, Gap::Unsupported),
    ("ins v3.s[1], w0", Engine::ReducedJit, Gap::Unsupported),
    ("ins v4.d[1], x1", Engine::ReducedJit, Gap::Unsupported),
    ("ins v5.b[9], v6.b[2]", Engine::ReducedJit, Gap::Unsupported),
    ("fmov v7.d[1], x2", Engine::ReducedJit, Gap::Unsupported),
    ("uxtl2 v9.4s, v1.8h", Engine::ReducedJit, Gap::Unsupported),
    ("sxtl v10.2d, v2.2s", Engine::ReducedJit, Gap::Unsupported),
    (
        "ushll v11.4s, v3.4h, #3",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "umull v12.2d, v4.2s, v5.2s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "umull2 v13.8h, v6.16b, v7.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("xtn v14.8b, v0.8h", Engine::ReducedJit, Gap::Unsupported),
    (
        "zip1 v8.16b, v0.16b, v1.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "zip2 v9.4s, v2.4s, v3.4s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "uzp1 v10.8h, v4.8h, v5.8h",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "uzp2 v11.2d, v6.2d, v7.2d",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "trn1 v12.4s, v0.4s, v1.4s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "ext v13.16b, v2.16b, v3.16b, #5",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "rev64 v14.16b, v4.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("rev32 v15.8h, v5.8h", Engine::ReducedJit, Gap::Unsupported),
    (
        "tbl v16.16b, {v6.16b}, v7.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("addv b8, v0.16b", Engine::ReducedJit, Gap::Unsupported),
    ("addv s9, v1.4s", Engine::ReducedJit, Gap::Unsupported),
    ("umaxv b10, v2.16b", Engine::ReducedJit, Gap::Unsupported),
    ("uminv h11, v3.8h", Engine::ReducedJit, Gap::Unsupported),
    ("addp d12, v4.2d", Engine::ReducedJit, Gap::Unsupported),
    ("cnt v13.16b, v5.16b", Engine::ReducedJit, Gap::Unsupported),
    ("uaddlv h14, v6.16b", Engine::ReducedJit, Gap::Unsupported),
    (
        "umax v8.16b, v0.16b, v1.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "umin v9.4s, v2.4s, v3.4s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "smax v10.8h, v4.8h, v5.8h",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "smin v11.16b, v6.16b, v7.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("abs v12.4s, v0.4s", Engine::ReducedJit, Gap::Unsupported),
    ("neg v13.2d, v1.2d", Engine::ReducedJit, Gap::Unsupported),
    (
        "fadd v10.2d, v8.2d, v9.2d",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "fmul v11.2d, v8.2d, v9.2d",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("cmeq d10, d4, d4", Engine::ReducedJit, Gap::Unsupported),
    ("shl d11, d5, #9", Engine::ReducedJit, Gap::Unsupported),
    ("ushr d12, d6, #3", Engine::ReducedJit, Gap::Unsupported),
    (
        "cmeq v8.8b, v0.8b, v1.8b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "bif v3.8b, v4.8b, v5.8b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "and v8.8b, v0.8b, v1.8b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("movi v8.8b, #0x5a", Engine::ReducedJit, Gap::Unsupported),
    ("dup v12.2s, w0", Engine::ReducedJit, Gap::Unsupported),
    (
        "sub v12.16b, v4.16b, v5.16b",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "sub v12.8h, v4.8h, v5.8h",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("ld1r {v10.4s}, [x20]", Engine::ReducedJit, Gap::Unsupported),
    (
        "ld1 {v11.16b, v12.16b}, [x20]",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "st1 {v1.16b, v2.16b}, [x20]",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "fadd v10.2d, v0.2d, v1.2d",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    (
        "fmul v11.4s, v0.4s, v1.4s",
        Engine::ReducedJit,
        Gap::Unsupported,
    ),
    ("mov v15.d[0], x1", Engine::ReducedJit, Gap::Unsupported),
];

struct Finding {
    gap: Gap,
    detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.gap, self.detail)
    }
}

// ── inputs ───────────────────────────────────────────────────────────

/// Values for x0-x7. The fixed rows hit sign, carry and width boundaries; the
/// rest are pseudo-random.
fn input_vectors() -> Vec<[u64; 8]> {
    const EDGE: [u64; 8] = [
        0,
        1,
        u64::MAX,
        0x8000_0000_0000_0000,
        0x7fff_ffff_ffff_ffff,
        0x0000_0000_8000_0000,
        0x0000_0000_7fff_ffff,
        0x0000_0000_ffff_ffff,
    ];
    let mut vectors = Vec::new();
    for rotation in 0..EDGE.len() {
        let mut row = EDGE;
        row.rotate_left(rotation);
        vectors.push(row);
    }
    vectors.push([0; 8]);
    vectors.push([u64::MAX; 8]);
    vectors.push([5, 5, 5, 5, 5, 5, 5, 5]);

    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..24 {
        let mut row = [0u64; 8];
        for (index, slot) in row.iter_mut().enumerate() {
            let value = next();
            // Mix full-width values with small ones so shifts and 32-bit
            // forms see realistic operands too.
            *slot = match (value >> 60, index % 2) {
                (0..=3, _) => value & 0xff,
                (4..=7, 1) => value & 0xffff_ffff,
                _ => value,
            };
        }
        vectors.push(row);
    }
    vectors
}

fn initial_state(inputs: &[u64; 8]) -> State {
    let mut x = [0u64; 31];
    for (index, slot) in x.iter_mut().enumerate() {
        // Non-input registers get distinct junk so a stale upper half or a
        // clobbered bystander shows up.
        *slot = 0xa5a5_0000_0000_0000 | ((index as u64) << 32) | 0xdead_0000 | index as u64;
    }
    x[..8].copy_from_slice(inputs);
    x[20] = DATA_PTR;

    let mut v = [0u128; 32];
    for (index, slot) in v.iter_mut().enumerate() {
        // v0-v7 carry the inputs; every register has a non-zero upper half so
        // a scalar write that fails to clear it is visible.
        let low = inputs[index % 8].rotate_left(index as u32 / 8 * 13);
        let high = inputs[(index + 3) % 8] ^ 0x5a5a_0000_0000_0000 ^ index as u64;
        *slot = (u128::from(high) << 64) | u128::from(low);
    }

    let mut seed = inputs[0] ^ inputs[1].rotate_left(17) ^ 0x2545_f491_4f6c_dd1d;
    let mut mem = vec![0u8; DATA_SIZE];
    for chunk in mem.chunks_mut(8) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        chunk.copy_from_slice(&seed.to_le_bytes());
    }

    State {
        x,
        sp: STACK_TOP,
        nzcv: 0,
        v,
        mem,
    }
}

// ── reference ────────────────────────────────────────────────────────

fn run_unicorn(case: &Case, start: &State) -> State {
    let fail = |what: &str, err: &dyn fmt::Debug| -> ! {
        panic!("{}: unicorn {what} failed: {err:?}", case.name)
    };
    let code: Vec<u8> = case
        .words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    let end = BASE + code.len() as u64;

    let mut uc =
        Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).unwrap_or_else(|err| fail("init", &err));
    uc.mem_map(BASE, 0x1000, Prot::ALL)
        .unwrap_or_else(|err| fail("code map", &err));
    uc.mem_write(BASE, &code)
        .unwrap_or_else(|err| fail("code write", &err));
    uc.mem_map(DATA, DATA_SIZE as u64, Prot::READ | Prot::WRITE)
        .unwrap_or_else(|err| fail("data map", &err));
    uc.mem_write(DATA, &start.mem)
        .unwrap_or_else(|err| fail("data write", &err));

    // Allow FP and SIMD instructions at EL0 (CPACR_EL1.FPEN).
    let _ = uc.reg_write(RegisterARM64::CPACR_EL1, 0b11 << 20);
    for (index, value) in start.x.iter().enumerate() {
        uc.reg_write(x_reg(index), *value)
            .unwrap_or_else(|err| fail("register write", &err));
    }
    uc.reg_write(RegisterARM64::SP, start.sp)
        .unwrap_or_else(|err| fail("sp write", &err));
    uc.reg_write(RegisterARM64::NZCV, start.nzcv << 28)
        .unwrap_or_else(|err| fail("nzcv write", &err));
    for (index, value) in start.v.iter().enumerate() {
        uc.reg_write_long(
            RegisterARM64::V0 as i32 + index as i32,
            &value.to_le_bytes(),
        )
        .unwrap_or_else(|err| fail("vector write", &err));
    }

    uc.emu_start(BASE, end, 0, 10_000)
        .unwrap_or_else(|err| fail("run", &err));
    let pc = uc.reg_read(RegisterARM64::PC).unwrap_or(0);
    assert_eq!(pc, end, "{}: unicorn stopped at {pc:#x}", case.name);

    let mut x = [0u64; 31];
    for (index, slot) in x.iter_mut().enumerate() {
        *slot = uc
            .reg_read(x_reg(index))
            .unwrap_or_else(|err| fail("register read", &err));
    }
    let mut v = [0u128; 32];
    for (index, slot) in v.iter_mut().enumerate() {
        let bytes = uc
            .reg_read_long(RegisterARM64::V0 as i32 + index as i32)
            .unwrap_or_else(|err| fail("vector read", &err));
        *slot = u128::from_le_bytes(bytes[..16].try_into().expect("128-bit register"));
    }
    State {
        x,
        sp: uc.reg_read(RegisterARM64::SP).unwrap_or(0),
        nzcv: (uc.reg_read(RegisterARM64::NZCV).unwrap_or(0) >> 28) & 0xf,
        v,
        mem: uc
            .mem_read_as_vec(DATA, DATA_SIZE)
            .unwrap_or_else(|err| fail("data read", &err)),
    }
}

fn x_reg(index: usize) -> i32 {
    match index {
        29 => RegisterARM64::X29 as i32,
        30 => RegisterARM64::X30 as i32,
        _ => RegisterARM64::X0 as i32 + index as i32,
    }
}

// ── lifting and block structure ──────────────────────────────────────

fn lift(case: &Case) -> Vec<Stmt> {
    case.words
        .iter()
        .enumerate()
        .map(|(index, word)| {
            let pc = BASE + 4 * index as u64;
            let insn = bad64::decode(*word, pc)
                .unwrap_or_else(|err| panic!("{}: cannot decode {word:#010x}: {err:?}", case.name));
            aeon::lifter::lift(&insn, pc, Some(pc + 4)).stmt
        })
        .collect()
}

fn is_terminator(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Branch { .. }
        | Stmt::CondBranch { .. }
        | Stmt::Call { .. }
        | Stmt::Ret
        | Stmt::Trap { .. } => true,
        Stmt::Pair(first, second) => is_terminator(first) || is_terminator(second),
        _ => false,
    }
}

/// One past the last statement of the block that starts at `start`: it runs
/// up to and including the first terminator.
fn block_end(stmts: &[Stmt], start: usize) -> usize {
    stmts[start..]
        .iter()
        .position(is_terminator)
        .map_or(stmts.len(), |offset| start + offset + 1)
}

/// Statement index for a guest address inside the snippet (its end included).
fn index_of(pc: u64, len: usize) -> Option<usize> {
    let offset = pc.checked_sub(BASE)?;
    (offset % 4 == 0 && offset / 4 <= len as u64).then_some((offset / 4) as usize)
}

// ── interpreter ──────────────────────────────────────────────────────

struct InitialMemory<'a>(&'a [u8]);

impl BackingStore for InitialMemory<'_> {
    fn load(&self, addr: u64, size: u8) -> Option<Vec<u8>> {
        let start = usize::try_from(addr.checked_sub(DATA)?).ok()?;
        self.0
            .get(start..start.checked_add(usize::from(size))?)
            .map(<[u8]>::to_vec)
    }
}

fn run_interpreter(stmts: &[Stmt], start: &State) -> Result<State, Finding> {
    std::panic::catch_unwind(|| interpret(stmts, start)).unwrap_or_else(|panic| {
        Err(Finding {
            gap: Gap::Unsupported,
            detail: panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|text| text.to_string()))
                .unwrap_or_else(|| "interpreter panicked".to_string()),
        })
    })
}

fn interpret(stmts: &[Stmt], start: &State) -> Result<State, Finding> {
    let unknown = |detail: String| Finding {
        gap: Gap::Unknown,
        detail,
    };

    let mut registers = BTreeMap::new();
    for (index, value) in start.x.iter().enumerate() {
        registers.insert(Reg::X(index as u8), Value::U64(*value));
    }
    registers.insert(Reg::SP, Value::U64(start.sp));
    registers.insert(Reg::Flags, Value::U64(start.nzcv));
    for (index, value) in start.v.iter().enumerate() {
        registers.insert(Reg::V(index as u8), Value::U128(*value));
    }
    let mut memory = BTreeMap::new();
    let backing = InitialMemory(&start.mem);

    let mut index = 0;
    let mut blocks = 0;
    while index < stmts.len() {
        blocks += 1;
        if blocks > MAX_BLOCKS {
            return Err(Finding {
                gap: Gap::Wrong,
                detail: "did not reach the end of the snippet".to_string(),
            });
        }
        let end = block_end(stmts, index);
        let result = execute_block(
            &stmts[index..end],
            registers,
            memory,
            &backing,
            MissingMemoryPolicy::Stop,
            end - index + 1,
        );
        if result.stop != BlockStop::Completed {
            return Err(Finding {
                gap: Gap::Unsupported,
                detail: format!(
                    "block at {:#x} stopped: {:?}",
                    BASE + 4 * index as u64,
                    result.stop
                ),
            });
        }
        registers = result.final_registers;
        memory = result.final_memory;
        let next = result.next_pc.unwrap_or(BASE + 4 * end as u64);
        index = index_of(next, stmts.len()).ok_or_else(|| Finding {
            gap: Gap::Wrong,
            detail: format!("branched to {next:#x}"),
        })?;
    }

    let scalar = |reg: Reg, label: String| match registers.get(&reg) {
        Some(Value::U64(value)) => Ok(*value),
        other => Err(unknown(format!("{label} is {other:?}"))),
    };
    let mut x = [0u64; 31];
    for (index, slot) in x.iter_mut().enumerate() {
        *slot = scalar(Reg::X(index as u8), format!("x{index}"))?;
    }
    let mut v = [0u128; 32];
    for (index, slot) in v.iter_mut().enumerate() {
        let number = index as u8;
        // A register last written through a scalar view is held under that
        // view; the rest of it is zero.
        let held = [
            Reg::V(number),
            Reg::Q(number),
            Reg::D(number),
            Reg::S(number),
            Reg::H(number),
            Reg::VByte(number),
        ]
        .into_iter()
        .find_map(|reg| registers.get(&reg));
        *slot = match held {
            Some(Value::U128(value)) => *value,
            Some(Value::U64(value)) => u128::from(*value),
            other => return Err(unknown(format!("v{index} is {other:?}"))),
        };
    }

    let mut mem = start.mem.clone();
    for (cell, value) in &memory {
        let MemoryLocation::Absolute(addr) = cell.location else {
            return Err(unknown(format!("wrote to {:?}", cell.location)));
        };
        let bytes = match value {
            Value::U64(bits) => u128::from(*bits).to_le_bytes(),
            Value::U128(bits) => bits.to_le_bytes(),
            Value::F64(float) => u128::from(float.to_bits()).to_le_bytes(),
            Value::Unknown => return Err(unknown(format!("memory at {addr:#x} is unknown"))),
        };
        let size = usize::from(cell.size);
        let slot = addr
            .checked_sub(DATA)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| mem.get_mut(offset..offset + size))
            .ok_or_else(|| Finding {
                gap: Gap::Wrong,
                detail: format!("wrote {size} bytes at {addr:#x}, outside the data region"),
            })?;
        slot.copy_from_slice(&bytes[..size]);
    }

    Ok(State {
        x,
        sp: scalar(Reg::SP, "sp".to_string())?,
        nzcv: scalar(Reg::Flags, "nzcv".to_string())?,
        v,
        mem,
    })
}

// ── JIT ──────────────────────────────────────────────────────────────

/// Maps the data region into this process at its guest address, once.
fn host_data() -> *mut u8 {
    static MAPPED: OnceLock<usize> = OnceLock::new();
    *MAPPED.get_or_init(|| {
        let mapped = unsafe {
            libc::mmap(
                DATA as *mut libc::c_void,
                DATA_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_eq!(
            mapped as u64, DATA,
            "could not map the data region at {DATA:#x}"
        );
        mapped as usize
    }) as *mut u8
}

struct CompiledBlock {
    end: usize,
    terminated: bool,
    entry: JitEntry,
}

/// Fixed-layout result the child writes back, followed by the data region.
#[repr(C)]
struct JitOutcome {
    x: [u64; 31],
    sp: u64,
    flags: u64,
    simd: [[u8; 16]; 32],
}

const CHILD_BAD_TARGET: i32 = 4;
const CHILD_STUCK: i32 = 5;
const CHILD_WRITE_FAILED: i32 = 6;

/// A snippet compiled once and run for every input vector. A block is
/// compiled at each instruction, since an indirect branch may land on any.
struct JitProgram {
    blocks: Vec<CompiledBlock>,
    len: usize,
    /// Owns the executable memory the blocks live in.
    _compiler: JitCompiler,
}

fn compile_jit(stmts: &[Stmt], reduce: bool) -> Result<JitProgram, Finding> {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let mut blocks = Vec::new();
    for begin in 0..stmts.len() {
        let end = block_end(stmts, begin);
        let block = if reduce {
            aeon_reduce::pipeline::reduce_block_local(stmts[begin..end].to_vec())
        } else {
            stmts[begin..end].to_vec()
        };
        let entry = compiler
            .compile_block(BASE + 4 * begin as u64, &block)
            .map_err(|err| Finding {
                gap: Gap::Unsupported,
                detail: err.to_string(),
            })?;
        blocks.push(CompiledBlock {
            end,
            terminated: is_terminator(&stmts[end - 1]),
            entry: unsafe { std::mem::transmute::<*const u8, JitEntry>(entry) },
        });
    }
    Ok(JitProgram {
        blocks,
        len: stmts.len(),
        _compiler: compiler,
    })
}

/// Runs the compiled blocks in a forked child, so that a fault in generated
/// code is reported as a finding instead of taking the test process down.
fn run_jit(program: &JitProgram, start: &State) -> Result<State, Finding> {
    let JitProgram { blocks, len, .. } = program;
    let len = *len;
    let mut ctx = JitContext::default();
    ctx.x = start.x;
    ctx.sp = start.sp;
    ctx.pc = BASE;
    ctx.flags = start.nzcv;
    for (slot, value) in ctx.simd.iter_mut().zip(&start.v) {
        *slot = value.to_le_bytes();
    }

    let data = host_data();
    unsafe { std::ptr::copy_nonoverlapping(start.mem.as_ptr(), data, DATA_SIZE) };

    let mut pipe = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0, "pipe");
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // Child: run the blocks and write the result. No allocation.
        unsafe {
            let mut index = 0;
            let mut executed = 0;
            while index < len {
                executed += 1;
                if executed > MAX_BLOCKS {
                    libc::_exit(CHILD_STUCK);
                }
                let block = &blocks[index];
                let returned = (block.entry)(&mut ctx);
                let next = if block.terminated {
                    returned
                } else {
                    BASE + 4 * block.end as u64
                };
                match index_of(next, len) {
                    Some(next_index) => index = next_index,
                    None => libc::_exit(CHILD_BAD_TARGET),
                }
            }
            let outcome = JitOutcome {
                x: ctx.x,
                sp: ctx.sp,
                flags: ctx.flags,
                simd: ctx.simd,
            };
            let header = std::slice::from_raw_parts(
                (&outcome as *const JitOutcome).cast::<u8>(),
                std::mem::size_of::<JitOutcome>(),
            );
            let memory = std::slice::from_raw_parts(data, DATA_SIZE);
            for part in [header, memory] {
                let written = libc::write(pipe[1], part.as_ptr().cast(), part.len());
                if written != part.len() as isize {
                    libc::_exit(CHILD_WRITE_FAILED);
                }
            }
            libc::_exit(0);
        }
    }

    // Parent. The whole result fits in the pipe buffer, so the child never
    // blocks on the write.
    let mut received = vec![0u8; std::mem::size_of::<JitOutcome>() + DATA_SIZE];
    let mut filled = 0;
    let mut status = 0i32;
    unsafe {
        libc::close(pipe[1]);
        while filled < received.len() {
            let count = libc::read(
                pipe[0],
                received[filled..].as_mut_ptr().cast(),
                received.len() - filled,
            );
            if count <= 0 {
                break;
            }
            filled += count as usize;
        }
        libc::close(pipe[0]);
        libc::waitpid(pid, &mut status, 0);
    }
    if libc::WIFSIGNALED(status) {
        return Err(Finding {
            gap: Gap::Crash,
            detail: format!("signal {}", libc::WTERMSIG(status)),
        });
    }
    match libc::WEXITSTATUS(status) {
        0 => {}
        CHILD_BAD_TARGET => {
            return Err(Finding {
                gap: Gap::Wrong,
                detail: "branched outside the snippet".to_string(),
            })
        }
        CHILD_STUCK => {
            return Err(Finding {
                gap: Gap::Wrong,
                detail: "did not reach the end of the snippet".to_string(),
            })
        }
        code => panic!("JIT child exited with {code}"),
    }
    assert_eq!(filled, received.len(), "short read from JIT child");

    let (header, mem) = received.split_at(std::mem::size_of::<JitOutcome>());
    let outcome: JitOutcome = unsafe { std::ptr::read_unaligned(header.as_ptr().cast()) };
    Ok(State {
        x: outcome.x,
        sp: outcome.sp,
        nzcv: outcome.flags & 0xf,
        v: outcome.simd.map(u128::from_le_bytes),
        mem: mem.to_vec(),
    })
}

// ── comparison ───────────────────────────────────────────────────────

fn first_difference(reference: &State, actual: &State) -> Option<String> {
    for index in 0..31 {
        if reference.x[index] != actual.x[index] {
            return Some(format!(
                "x{index} = {:#018x}, reference {:#018x}",
                actual.x[index], reference.x[index]
            ));
        }
    }
    if reference.sp != actual.sp {
        return Some(format!(
            "sp = {:#x}, reference {:#x}",
            actual.sp, reference.sp
        ));
    }
    if reference.nzcv != actual.nzcv {
        return Some(format!(
            "nzcv = {:04b}, reference {:04b}",
            actual.nzcv, reference.nzcv
        ));
    }
    for index in 0..32 {
        if reference.v[index] != actual.v[index] {
            return Some(format!(
                "v{index} = {:#034x}, reference {:#034x}",
                actual.v[index], reference.v[index]
            ));
        }
    }
    let offset = reference
        .mem
        .iter()
        .zip(&actual.mem)
        .position(|(expected, got)| expected != got)?;
    Some(format!(
        "memory at {:#x} = {:#04x}, reference {:#04x}",
        DATA + offset as u64,
        actual.mem[offset],
        reference.mem[offset]
    ))
}

fn check(reference: &State, outcome: Result<State, Finding>) -> Option<Finding> {
    match outcome {
        Err(finding) => Some(finding),
        Ok(actual) => first_difference(reference, &actual).map(|detail| Finding {
            gap: Gap::Wrong,
            detail,
        }),
    }
}

#[test]
fn engines_agree_with_unicorn() {
    // Interpreter panics are caught and reported; keep them off stderr.
    std::panic::set_hook(Box::new(|_| {}));

    let vectors = input_vectors();
    let mut findings: Vec<(&str, Engine, Finding, [u64; 8])> = Vec::new();

    for case in CASES {
        let stmts = lift(case);
        let programs = [compile_jit(&stmts, false), compile_jit(&stmts, true)];
        // Record the first disagreement per engine; one is enough to act on.
        let mut seen: [Option<(Finding, [u64; 8])>; 3] = [None, None, None];
        for inputs in &vectors {
            let start = initial_state(inputs);
            let reference = run_unicorn(case, &start);
            if seen[0].is_none() {
                seen[0] = check(&reference, run_interpreter(&stmts, &start)).map(|f| (f, *inputs));
            }
            for (slot, program) in seen[1..].iter_mut().zip(&programs) {
                if slot.is_some() {
                    continue;
                }
                let outcome = match program {
                    Ok(program) => run_jit(program, &start),
                    Err(finding) => Err(Finding {
                        gap: finding.gap,
                        detail: finding.detail.clone(),
                    }),
                };
                *slot = check(&reference, outcome).map(|f| (f, *inputs));
            }
        }
        let engines = [Engine::Interpreter, Engine::Jit, Engine::ReducedJit];
        for (engine, slot) in engines.into_iter().zip(seen) {
            if let Some((finding, inputs)) = slot {
                findings.push((case.name, engine, finding, inputs));
            }
        }
    }
    let _ = std::panic::take_hook();

    let mut problems = Vec::new();
    for (name, engine, finding, inputs) in &findings {
        let listed = KNOWN
            .iter()
            .find(|(known, known_engine, _)| known == name && known_engine == engine);
        match listed {
            Some((_, _, gap)) if *gap == finding.gap => {}
            Some((_, _, gap)) => problems.push(format!(
                "{name} [{engine:?}] is listed as {gap:?} but is now {finding}"
            )),
            None => {
                let asm = CASES.iter().find(|case| case.name == *name).unwrap().asm;
                problems.push(format!(
                    "{name} [{engine:?}] {finding}\n    asm:    {asm}\n    x0..x7: {inputs:x?}"
                ));
            }
        }
    }
    for (name, engine, gap) in KNOWN {
        let still_failing = findings
            .iter()
            .any(|(found, found_engine, _, _)| found == name && found_engine == engine);
        if !still_failing {
            problems.push(format!(
                "{name} [{engine:?}] is listed as {gap:?} but now matches; remove it from KNOWN"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "{} of {} cases x {} input vectors disagree with the KNOWN list:\n\n{}\n",
        problems.len(),
        CASES.len(),
        vectors.len(),
        problems.join("\n\n")
    );
}

/// Debugging aid for working down `KNOWN`: prints the IL of every case whose
/// name contains `AEON_DIFF_CASE`, as lifted and as reduced.
///
/// `AEON_DIFF_CASE='ins v3' cargo test -p aeon-jit --test differential -- --ignored --nocapture`
#[test]
#[ignore = "prints lifted IL on request"]
fn show_lifted_il() {
    let filter = std::env::var("AEON_DIFF_CASE").unwrap_or_default();
    for case in CASES.iter().filter(|case| case.name.contains(&filter)) {
        println!("{}", case.name);
        let stmts = lift(case);
        for stmt in &stmts {
            println!("    {stmt:?}");
        }
        println!("  reduced, first block:");
        let end = block_end(&stmts, 0);
        for stmt in aeon_reduce::pipeline::reduce_block_local(stmts[..end].to_vec()) {
            println!("    {stmt:?}");
        }
    }
}
