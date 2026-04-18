// Dynamic JIT runtime
//
// This is the lightweight exact-PC execution layer we want for live JIT
// diversion. Unlike the translated-ELF path, it does not require a
// precomputed block map. It lazily compiles blocks from the exact current PC
// using DynCfg, then executes them through aeon-jit.

use aeon_jit::{JitCompiler, JitContext};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::context::MemoryProvider;
use crate::dyncfg::DynCfg;
use crate::dynffi::AEON_DYN_BAIL_SENTINEL;
#[cfg(target_arch = "aarch64")]
use crate::dynffi::{
    aeon_dyn_branch_bridge_ctx_pc, aeon_dyn_branch_bridge_last_target,
    aeon_dyn_branch_bridge_resume_target, aeon_dyn_branch_bridge_saved_x30,
    aeon_dyn_branch_bridge_stage,
};

static DYN_TRACE_RUN_ID: AtomicU64 = AtomicU64::new(1);
static DYN_TRACE_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn dyn_trace_write_lock() -> &'static Mutex<()> {
    DYN_TRACE_WRITE_LOCK.get_or_init(|| Mutex::new(()))
}

fn dyn_current_tid() -> u64 {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    unsafe {
        libc::syscall(libc::SYS_gettid) as u64
    }

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        0
    }
}

fn dyn_trace_path() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "/data/user/0/com.netmarble.thered/files/aeon_dyn_runtime.log"
    }
    #[cfg(not(target_os = "android"))]
    {
        "/tmp/aeon_dyn_runtime.log"
    }
}

fn dyn_trace_line(message: &str) {
    use std::io::Write;
    let _guard = dyn_trace_write_lock().lock().ok();
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dyn_trace_path())
    {
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(
                dyn_trace_path(),
                std::fs::Permissions::from_mode(0o644),
            );
        }
        let _ = writeln!(file, "tid={} {message}", dyn_current_tid());
    }
}

fn dyn_trace_json_path() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "/data/user/0/com.netmarble.thered/files/aeon_dyn_trace.jsonl"
    }
    #[cfg(not(target_os = "android"))]
    {
        "/tmp/aeon_dyn_trace.jsonl"
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn dyn_trace_json_line(message: &str) {
    use std::io::Write;
    let _guard = dyn_trace_write_lock().lock().ok();
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dyn_trace_json_path())
    {
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(
                dyn_trace_json_path(),
                std::fs::Permissions::from_mode(0o644),
            );
        }
        let tid = dyn_current_tid();
        if let Some(rest) = message.strip_prefix('{') {
            let _ = writeln!(file, "{{\"tid\":{tid},{rest}");
        } else {
            let _ = writeln!(file, "{message}");
        }
    }
}

fn fmt_hex_opt(value: Option<u64>) -> String {
    match value {
        Some(v) => format!("\"0x{v:x}\""),
        None => "null".to_string(),
    }
}

fn dyn_trace_step_json(
    run_id: u64,
    kind: &str,
    step: usize,
    pc: u64,
    ctx: &JitContext,
) {
    dyn_trace_json_line(&format!(
        "{{\"kind\":\"{kind}\",\"run_id\":{run_id},\"step\":{step},\"pc\":\"0x{pc:x}\",\"x0\":\"0x{:x}\",\"x1\":\"0x{:x}\",\"x2\":\"0x{:x}\",\"x3\":\"0x{:x}\",\"x19\":\"0x{:x}\",\"x20\":\"0x{:x}\",\"x21\":\"0x{:x}\",\"sp\":\"0x{:x}\",\"lr\":\"0x{:x}\"}}",
        ctx.x[0], ctx.x[1], ctx.x[2], ctx.x[3], ctx.x[19], ctx.x[20], ctx.x[21], ctx.sp, ctx.x[30],
    ));
}

fn read_u32_maybe(addr: u64) -> Option<u32> {
    if addr == 0 {
        return None;
    }
    unsafe { Some((addr as *const u32).read_unaligned()) }
}

fn decode_ldr_unsigned_x(insn: u32) -> Option<(usize, usize, u64)> {
    if (insn & 0xffc0_0000) != 0xf940_0000 {
        return None;
    }
    let rt = (insn & 0x1f) as usize;
    let rn = ((insn >> 5) & 0x1f) as usize;
    let imm12 = ((insn >> 10) & 0x0fff) as u64;
    let size = (insn >> 30) & 0x3;
    let scale = match size {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => return None,
    };
    Some((rt, rn, imm12 * scale))
}

fn decode_ldr_literal_x(insn: u32) -> Option<(usize, i64)> {
    if (insn & 0xff00_0000) != 0x5800_0000 {
        return None;
    }
    let rt = (insn & 0x1f) as usize;
    let imm19 = ((insn >> 5) & 0x7ffff) as i32;
    let signed = ((imm19 << 13) >> 13) as i64;
    Some((rt, signed * 4))
}

fn decode_blr_reg(insn: u32) -> Option<usize> {
    if (insn & 0xffff_fc1f) != 0xd63f_0000 {
        return None;
    }
    Some(((insn >> 5) & 0x1f) as usize)
}

fn dyn_trace_dynamic_call_target(run_id: u64, step: usize, addr: u64, ctx: &JitContext) {
    let Some(insn0) = read_u32_maybe(addr) else { return; };
    let Some(insn1) = read_u32_maybe(addr.wrapping_add(4)) else { return; };
    if let (Some((rt, rn, offset)), Some(blr_reg)) =
        (decode_ldr_unsigned_x(insn0), decode_blr_reg(insn1))
    {
        if rt != blr_reg || rn >= 31 || rt >= 31 {
            return;
        }
        let base = ctx.x[rn];
        let target_addr = base.wrapping_add(offset);
        let target_u64 = unsafe { (target_addr as *const u64).read_unaligned() };
        dyn_trace_line(&format!(
            "calltarget addr=0x{addr:x} reg=x{rt} base_reg=x{rn} base=0x{base:x} offset=0x{offset:x} slot=0x{target_addr:x} target=0x{target_u64:x}"
        ));
        dyn_trace_json_line(&format!(
            "{{\"kind\":\"dynamic_call_target\",\"run_id\":{run_id},\"step\":{step},\"addr\":\"0x{addr:x}\",\"target_reg\":\"x{rt}\",\"base_reg\":\"x{rn}\",\"base\":\"0x{base:x}\",\"offset\":\"0x{offset:x}\",\"slot\":\"0x{target_addr:x}\",\"target\":\"0x{target_u64:x}\"}}"
        ));
        return;
    }

    let Some(insn2) = read_u32_maybe(addr.wrapping_add(8)) else { return; };
    if let (Some((mid_reg, base_reg, base_off)), Some((target_reg, mid_base_reg, slot_off)), Some(blr_reg)) = (
        decode_ldr_unsigned_x(insn0),
        decode_ldr_unsigned_x(insn1),
        decode_blr_reg(insn2),
    ) {
        if mid_reg == mid_base_reg
            && target_reg == blr_reg
            && base_reg < 31
            && mid_reg < 31
            && target_reg < 31
        {
            let base = ctx.x[base_reg];
            let mid_slot_addr = base.wrapping_add(base_off);
            let mid_base = unsafe { (mid_slot_addr as *const u64).read_unaligned() };
            let target_addr = mid_base.wrapping_add(slot_off);
            let target_u64 = unsafe { (target_addr as *const u64).read_unaligned() };
            dyn_trace_line(&format!(
                "calltarget addr=0x{addr:x} base_reg=x{base_reg} base=0x{base:x} mid_reg=x{mid_reg} mid_slot=0x{mid_slot_addr:x} mid_base=0x{mid_base:x} target_reg=x{target_reg} slot=0x{target_addr:x} target=0x{target_u64:x}"
            ));
            dyn_trace_json_line(&format!(
                "{{\"kind\":\"dynamic_call_target\",\"run_id\":{run_id},\"step\":{step},\"addr\":\"0x{addr:x}\",\"base_reg\":\"x{base_reg}\",\"base\":\"0x{base:x}\",\"mid_reg\":\"x{mid_reg}\",\"mid_slot\":\"0x{mid_slot_addr:x}\",\"mid_base\":\"0x{mid_base:x}\",\"target_reg\":\"x{target_reg}\",\"slot\":\"0x{target_addr:x}\",\"target\":\"0x{target_u64:x}\"}}"
            ));
            return;
        }
    }

    let Some(insn3) = read_u32_maybe(addr.wrapping_add(12)) else { return; };
    let Some((literal_reg, literal_off)) = decode_ldr_literal_x(insn1) else { return; };
    let Some((target_reg, base_reg, slot_off)) = decode_ldr_unsigned_x(insn2) else { return; };
    let Some(blr_reg) = decode_blr_reg(insn3) else { return; };
    if literal_reg != base_reg || target_reg != blr_reg || literal_reg >= 31 || target_reg >= 31 {
        return;
    }
    let literal_addr = if literal_off >= 0 {
        addr.wrapping_add(4).wrapping_add(literal_off as u64)
    } else {
        addr.wrapping_add(4).wrapping_sub((-literal_off) as u64)
    };
    let base = unsafe { (literal_addr as *const u64).read_unaligned() };
    let target_addr = base.wrapping_add(slot_off);
    let target_u64 = unsafe { (target_addr as *const u64).read_unaligned() };
    dyn_trace_line(&format!(
        "calltarget addr=0x{addr:x} literal_reg=x{literal_reg} literal_addr=0x{literal_addr:x} base=0x{base:x} target_reg=x{target_reg} slot=0x{target_addr:x} target=0x{target_u64:x}"
    ));
    dyn_trace_json_line(&format!(
        "{{\"kind\":\"dynamic_call_target\",\"run_id\":{run_id},\"step\":{step},\"addr\":\"0x{addr:x}\",\"literal_reg\":\"x{literal_reg}\",\"literal_addr\":\"0x{literal_addr:x}\",\"base\":\"0x{base:x}\",\"target_reg\":\"x{target_reg}\",\"slot\":\"0x{target_addr:x}\",\"target\":\"0x{target_u64:x}\"}}"
    ));
}

fn dyn_trace_bridge_bail_json(run_id: u64, steps: usize, final_pc: u64) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        dyn_trace_json_line(&format!(
            "{{\"kind\":\"stop\",\"run_id\":{run_id},\"reason\":\"bridge_bail\",\"step\":{steps},\"final_pc\":\"0x{final_pc:x}\",\"bridge_stage\":\"0x{:x}\",\"bridge_target\":\"0x{:x}\",\"bridge_resume\":\"0x{:x}\",\"bridge_saved_x30\":\"0x{:x}\",\"bridge_ctx_pc\":\"0x{:x}\"}}",
            aeon_dyn_branch_bridge_stage,
            aeon_dyn_branch_bridge_last_target,
            aeon_dyn_branch_bridge_resume_target,
            aeon_dyn_branch_bridge_saved_x30,
            aeon_dyn_branch_bridge_ctx_pc,
        ));
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        dyn_trace_json_line(&format!(
            "{{\"kind\":\"stop\",\"run_id\":{run_id},\"reason\":\"bridge_bail\",\"step\":{steps},\"final_pc\":\"0x{final_pc:x}\"}}"
        ));
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DynamicRuntimeConfig {
    pub max_steps: usize,
    pub code_range: Option<(u64, u64)>,
}

impl Default for DynamicRuntimeConfig {
    fn default() -> Self {
        Self {
            max_steps: 4096,
            code_range: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicRuntimeStop {
    Halted,
    MaxSteps,
    CodeRangeExit(u64),
    LiftError(u64, String),
}

#[derive(Debug, Clone)]
pub struct DynamicRuntimeResult {
    pub start_pc: u64,
    pub final_pc: u64,
    pub steps: usize,
    pub path: Vec<u64>,
    pub compiled_blocks: usize,
    pub stop: DynamicRuntimeStop,
}

pub struct DynamicRuntime {
    cfg: DynCfg,
}

impl DynamicRuntime {
    pub fn new() -> Self {
        Self { cfg: DynCfg::new() }
    }

    pub fn compiler_mut(&mut self) -> &mut JitCompiler {
        self.cfg.compiler_mut()
    }

    pub fn block_count(&self) -> usize {
        self.cfg.block_count()
    }

    pub fn has_block(&self, addr: u64) -> bool {
        self.cfg.has_block(addr)
    }

    pub fn source_for_block_id(&self, block_id: u64) -> Option<u64> {
        self.cfg
            .addresses()
            .into_iter()
            .find(|addr| {
                self.cfg
                    .get_block(*addr)
                    .map(|block| block.block_id == block_id)
                    .unwrap_or(false)
            })
    }

    pub fn run(
        &mut self,
        ctx: &mut JitContext,
        memory: &dyn MemoryProvider,
        config: DynamicRuntimeConfig,
    ) -> DynamicRuntimeResult {
        let run_id = DYN_TRACE_RUN_ID.fetch_add(1, Ordering::Relaxed);
        let start_pc = ctx.pc;
        let mut path = Vec::new();
        let mut steps = 0usize;
        dyn_trace_line(&format!(
            "run start_pc=0x{start_pc:x} max_steps={} range={:?}",
            config.max_steps, config.code_range
        ));
        let (range_start, range_end) = match config.code_range {
            Some((start, end)) => (Some(start), Some(end)),
            None => (None, None),
        };
        dyn_trace_json_line(&format!(
            "{{\"kind\":\"run_start\",\"run_id\":{run_id},\"start_pc\":\"0x{start_pc:x}\",\"max_steps\":{},\"range_start\":{},\"range_end\":{}}}",
            config.max_steps,
            fmt_hex_opt(range_start),
            fmt_hex_opt(range_end),
        ));

        loop {
            let pc = ctx.pc;
            dyn_trace_line(&format!("step={steps} pc=0x{pc:x}"));
            dyn_trace_step_json(run_id, "step", steps, pc, ctx);
            if let Some((start, end)) = config.code_range {
                if pc < start || pc >= end {
                    dyn_trace_line(&format!("stop=code_range_exit pc=0x{pc:x}"));
                    dyn_trace_json_line(&format!(
                        "{{\"kind\":\"stop\",\"run_id\":{run_id},\"reason\":\"code_range_exit\",\"step\":{steps},\"final_pc\":\"0x{pc:x}\"}}"
                    ));
                    return DynamicRuntimeResult {
                        start_pc,
                        final_pc: pc,
                        steps,
                        path,
                        compiled_blocks: self.cfg.block_count(),
                        stop: DynamicRuntimeStop::CodeRangeExit(pc),
                    };
                }
            }

            if steps >= config.max_steps {
                dyn_trace_line(&format!("stop=max_steps pc=0x{pc:x}"));
                dyn_trace_json_line(&format!(
                    "{{\"kind\":\"stop\",\"run_id\":{run_id},\"reason\":\"max_steps\",\"step\":{steps},\"final_pc\":\"0x{pc:x}\"}}"
                ));
                return DynamicRuntimeResult {
                    start_pc,
                    final_pc: pc,
                    steps,
                    path,
                    compiled_blocks: self.cfg.block_count(),
                    stop: DynamicRuntimeStop::MaxSteps,
                };
            }

            let block = match self.cfg.get_or_compile(pc, memory) {
                Ok(block) => {
                    dyn_trace_line(&format!(
                        "compiled addr=0x{:x} id=0x{:x} size=0x{:x} term={:?}",
                        block.addr, block.block_id, block.size_bytes, block.terminator
                    ));
                    dyn_trace_json_line(&format!(
                        "{{\"kind\":\"compiled\",\"run_id\":{run_id},\"step\":{steps},\"addr\":\"0x{:x}\",\"block_id\":\"0x{:x}\",\"size_bytes\":{},\"terminator\":\"{:?}\"}}",
                        block.addr,
                        block.block_id,
                        block.size_bytes,
                        block.terminator,
                    ));
                    block
                }
                Err(err) => {
                    dyn_trace_line(&format!("stop=lift_error pc=0x{pc:x} err={err:?}"));
                    dyn_trace_json_line(&format!(
                        "{{\"kind\":\"stop\",\"run_id\":{run_id},\"reason\":\"lift_error\",\"step\":{steps},\"final_pc\":\"0x{pc:x}\",\"error\":\"{}\"}}",
                        json_escape(&format!("{err:?}"))
                    ));
                    return DynamicRuntimeResult {
                        start_pc,
                        final_pc: pc,
                        steps,
                        path,
                        compiled_blocks: self.cfg.block_count(),
                        stop: DynamicRuntimeStop::LiftError(pc, format!("{err:?}")),
                    };
                }
            };

            path.push(block.addr);
            if matches!(block.terminator, crate::dyncfg::BlockTerminator::DynamicCall) {
                dyn_trace_line(&format!(
                    "callsite addr=0x{:x} x0=0x{:x} x1=0x{:x} x2=0x{:x} x3=0x{:x} x19=0x{:x} x20=0x{:x} x21=0x{:x} sp=0x{:x} lr=0x{:x}",
                    block.addr,
                    ctx.x[0],
                    ctx.x[1],
                    ctx.x[2],
                    ctx.x[3],
                    ctx.x[19],
                    ctx.x[20],
                    ctx.x[21],
                    ctx.sp,
                    ctx.x[30],
                ));
                dyn_trace_dynamic_call_target(run_id, steps, block.addr, ctx);
                dyn_trace_json_line(&format!(
                    "{{\"kind\":\"dynamic_call\",\"run_id\":{run_id},\"step\":{steps},\"addr\":\"0x{:x}\",\"x0\":\"0x{:x}\",\"x1\":\"0x{:x}\",\"x2\":\"0x{:x}\",\"x3\":\"0x{:x}\",\"x19\":\"0x{:x}\",\"x20\":\"0x{:x}\",\"x21\":\"0x{:x}\",\"sp\":\"0x{:x}\",\"lr\":\"0x{:x}\"}}",
                    block.addr,
                    ctx.x[0],
                    ctx.x[1],
                    ctx.x[2],
                    ctx.x[3],
                    ctx.x[19],
                    ctx.x[20],
                    ctx.x[21],
                    ctx.sp,
                    ctx.x[30],
                ));
            }
            dyn_trace_line(&format!("enter addr=0x{:x}", block.addr));
            let mut next_pc = unsafe { (block.entry)(ctx as *mut JitContext) };
            if matches!(block.terminator, crate::dyncfg::BlockTerminator::Return) {
                next_pc = ctx.x[30];
            }
            steps += 1;
            dyn_trace_line(&format!("leave addr=0x{:x} next=0x{next_pc:x}", block.addr));
            dyn_trace_json_line(&format!(
                "{{\"kind\":\"leave\",\"run_id\":{run_id},\"step\":{},\"addr\":\"0x{:x}\",\"next_pc\":\"0x{next_pc:x}\"}}",
                steps - 1,
                block.addr,
            ));

            if next_pc == AEON_DYN_BAIL_SENTINEL {
                let bail_pc = ctx.pc;
                dyn_trace_line(&format!("stop=bridge_bail pc=0x{bail_pc:x}"));
                dyn_trace_bridge_bail_json(run_id, steps, bail_pc);
                return DynamicRuntimeResult {
                    start_pc,
                    final_pc: bail_pc,
                    steps,
                    path,
                    compiled_blocks: self.cfg.block_count(),
                    stop: DynamicRuntimeStop::CodeRangeExit(bail_pc),
                };
            }

            if next_pc == 0 {
                ctx.pc = 0;
                dyn_trace_line("stop=halted");
                dyn_trace_json_line(&format!(
                    "{{\"kind\":\"stop\",\"run_id\":{run_id},\"reason\":\"halted\",\"step\":{steps},\"final_pc\":\"0x0\"}}"
                ));
                return DynamicRuntimeResult {
                    start_pc,
                    final_pc: 0,
                    steps,
                    path,
                    compiled_blocks: self.cfg.block_count(),
                    stop: DynamicRuntimeStop::Halted,
                };
            }

            ctx.pc = next_pc;
        }
    }
}

impl Default for DynamicRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::SnapshotMemory;

    fn push_word(buf: &mut Vec<u8>, word: u32) {
        buf.extend_from_slice(&word.to_le_bytes());
    }

    #[test]
    fn run_starts_from_exact_mid_block_pc() {
        let mut mem = SnapshotMemory::new();
        let mut code = Vec::new();
        push_word(&mut code, 0xd2800020); // mov x0, #1
        push_word(&mut code, 0xd2800041); // mov x1, #2
        push_word(&mut code, 0xd65f03c0); // ret
        mem.add_region(0x1000, code);

        let mut ctx = JitContext::default();
        ctx.pc = 0x1004;
        ctx.x[30] = 0;

        let mut runtime = DynamicRuntime::new();
        let result = runtime.run(
            &mut ctx,
            &mem,
            DynamicRuntimeConfig {
                max_steps: 8,
                code_range: Some((0x1000, 0x2000)),
            },
        );

        assert_eq!(result.stop, DynamicRuntimeStop::Halted);
        assert_eq!(result.steps, 1);
        assert_eq!(result.path, vec![0x1004]);
        assert_eq!(ctx.pc, 0);
        assert_eq!(ctx.x[0], 0);
        assert_eq!(ctx.x[1], 2);
        assert!(!runtime.has_block(0x1000));
        assert!(runtime.has_block(0x1004));
    }

    #[test]
    fn run_compiles_direct_callee_and_exact_post_call_pc() {
        let mut mem = SnapshotMemory::new();

        let mut caller = Vec::new();
        push_word(&mut caller, 0x94000400); // bl 0x2000
        push_word(&mut caller, 0xd2800041); // mov x1, #2
        push_word(&mut caller, 0xd280001e); // mov x30, #0
        push_word(&mut caller, 0xd65f03c0); // ret
        mem.add_region(0x1000, caller);

        let mut callee = Vec::new();
        push_word(&mut callee, 0xd28000a2); // mov x2, #5
        push_word(&mut callee, 0xd65f03c0); // ret
        mem.add_region(0x2000, callee);

        let mut ctx = JitContext::default();
        ctx.pc = 0x1000;
        ctx.x[30] = 0;

        let mut runtime = DynamicRuntime::new();
        let result = runtime.run(
            &mut ctx,
            &mem,
            DynamicRuntimeConfig {
                max_steps: 8,
                code_range: Some((0x1000, 0x4000)),
            },
        );

        assert_eq!(result.stop, DynamicRuntimeStop::Halted);
        assert_eq!(result.steps, 3);
        assert_eq!(result.path, vec![0x1000, 0x2000, 0x1004]);
        assert_eq!(ctx.pc, 0);
        assert_eq!(ctx.x[1], 2);
        assert_eq!(ctx.x[2], 5);
        assert!(runtime.has_block(0x1000));
        assert!(runtime.has_block(0x2000));
        assert!(runtime.has_block(0x1004));
    }

    #[test]
    fn run_uses_x30_for_return_blocks() {
        let mut mem = SnapshotMemory::new();
        let mut code = Vec::new();
        push_word(&mut code, 0xd65f03c0); // ret
        mem.add_region(0x1000, code);

        let mut ctx = JitContext::default();
        ctx.pc = 0x1000;
        ctx.x[30] = 0x2000;

        let mut runtime = DynamicRuntime::new();
        let result = runtime.run(
            &mut ctx,
            &mem,
            DynamicRuntimeConfig {
                max_steps: 8,
                code_range: Some((0x1000, 0x1004)),
            },
        );

        assert_eq!(result.path, vec![0x1000]);
        assert_eq!(result.steps, 1);
        assert_eq!(result.final_pc, 0x2000);
        assert_eq!(ctx.pc, 0x2000);
        assert_eq!(result.stop, DynamicRuntimeStop::CodeRangeExit(0x2000));
    }
}
