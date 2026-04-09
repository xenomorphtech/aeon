use std::ptr;

use aeon_jit::{
    BlockEnterCallback, BranchBridgeCallback, BranchTranslateCallback, JitContext,
    MemoryReadCallback, MemoryWriteCallback,
};

use crate::context::MemoryProvider;
use crate::dynruntime::{DynamicRuntime, DynamicRuntimeConfig, DynamicRuntimeStop};

fn dynffi_trace_path() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "/data/user/0/com.netmarble.thered/files/aeon_dyn_runtime.log"
    }
    #[cfg(not(target_os = "android"))]
    {
        "/tmp/aeon_dyn_runtime.log"
    }
}

fn dynffi_trace_line(message: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dynffi_trace_path())
    {
        let _ = writeln!(file, "{message}");
    }
}

struct CodeWindowMemory {
    base: u64,
    size: usize,
}

impl CodeWindowMemory {
    fn contains(&self, addr: u64, size: usize) -> bool {
        let end = match addr.checked_add(size as u64) {
            Some(end) => end,
            None => return false,
        };
        addr >= self.base && end <= self.base + self.size as u64
    }
}

impl MemoryProvider for CodeWindowMemory {
    fn read(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        if !self.contains(addr, size) {
            return None;
        }
        let mut out = vec![0u8; size];
        unsafe {
            ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), size);
        }
        Some(out)
    }
}

struct DynamicRuntimeHandle {
    runtime: DynamicRuntime,
    memory: CodeWindowMemory,
    config: DynamicRuntimeConfig,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AeonDynRuntimeResult {
    pub stop_code: u32,
    pub start_pc: u64,
    pub final_pc: u64,
    pub steps: u64,
    pub compiled_blocks: u64,
    pub info_pc: u64,
}

const STOP_HALTED: u32 = 0;
const STOP_MAX_STEPS: u32 = 1;
const STOP_CODE_RANGE_EXIT: u32 = 2;
const STOP_LIFT_ERROR: u32 = 3;
const STOP_INVALID_ARGUMENT: u32 = 0xffff_ffff;
pub const AEON_DYN_TRAMPOLINE_BRK_IMM: u16 = 0x0ae0;
pub const AEON_DYN_BRIDGE_SCRATCH_SIZE: usize = 0x140;
pub const AEON_DYN_RESUME_HANDOFF_SIZE: usize = 0x30;
pub const AEON_DYN_BAIL_SENTINEL: u64 = u64::MAX;

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_host_sp: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_ctx: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_saved_x30: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_stage: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_last_target: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_tail_mode: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_arg_x0: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_arg_x1: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_arg_x18: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_arg_x19: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_arg_x21: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_arg_x28: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_arg_sp: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_outgoing_x30: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_post_call_x30: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_resume_target: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_branch_bridge_ctx_pc: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_code_range_start: u64 = 0;
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub static mut aeon_dyn_code_range_end: u64 = 0;

#[cfg(target_arch = "aarch64")]
fn dynamic_code_range() -> Option<(u64, u64)> {
    unsafe {
        if aeon_dyn_code_range_start != 0 && aeon_dyn_code_range_start < aeon_dyn_code_range_end {
            Some((aeon_dyn_code_range_start, aeon_dyn_code_range_end))
        } else {
            None
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn dynamic_ptr_in_code_range(value: u64) -> bool {
    let Some((start, end)) = dynamic_code_range() else {
        return false;
    };
    value >= start && value < end
}

#[cfg(target_arch = "aarch64")]
fn dynamic_looks_code_aligned(value: u64) -> bool {
    value != 0 && (value & 0x3) == 0
}

#[cfg(target_arch = "aarch64")]
fn dynamic_has_executable_mapping(value: u64) -> bool {
    dynamic_mapping_has_perm(value, 1, 'x')
}

#[cfg(target_arch = "aarch64")]
fn dynamic_strip_ptr_tag(value: u64) -> u64 {
    value & 0x00ff_ffff_ffff_ffff
}

#[cfg(target_arch = "aarch64")]
fn dynamic_mapping_has_perm(value: u64, size: usize, perm: char) -> bool {
    let value = dynamic_strip_ptr_tag(value);
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return false;
    };
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else {
            continue;
        };
        let Some(perms) = parts.next() else {
            continue;
        };
        if !perms.contains(perm) {
            continue;
        }
        let Some((start_hex, end_hex)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            u64::from_str_radix(start_hex, 16),
            u64::from_str_radix(end_hex, 16),
        ) else {
            continue;
        };
        let Some(limit) = value.checked_add(size as u64) else {
            continue;
        };
        if value >= start && limit <= end {
            return true;
        }
    }
    false
}

#[cfg(target_arch = "aarch64")]
fn dynamic_module_file_offset(value: u64, module_suffix: &str) -> Option<u64> {
    let value = dynamic_strip_ptr_tag(value);
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let _perms = parts.next()?;
        let file_off_hex = parts.next()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let path = parts.next().unwrap_or("");
        if !path.ends_with(module_suffix) {
            continue;
        }
        let (start_hex, end_hex) = range.split_once('-')?;
        let start = u64::from_str_radix(start_hex, 16).ok()?;
        let end = u64::from_str_radix(end_hex, 16).ok()?;
        if value < start || value >= end {
            continue;
        }
        let file_off = u64::from_str_radix(file_off_hex, 16).ok()?;
        let load_bias = start.checked_sub(file_off)?;
        return value.checked_sub(load_bias);
    }
    None
}

#[cfg(target_arch = "aarch64")]
fn dynamic_has_readable_mapping(value: u64, size: usize) -> bool {
    dynamic_mapping_has_perm(value, size, 'r')
}

#[cfg(target_arch = "aarch64")]
fn dynamic_mapping_label_and_offset(value: u64) -> Option<(String, u64)> {
    let value = dynamic_strip_ptr_tag(value);
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let _perms = parts.next()?;
        let file_off_hex = parts.next()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let path = parts.next().unwrap_or("");
        let (start_hex, end_hex) = range.split_once('-')?;
        let start = u64::from_str_radix(start_hex, 16).ok()?;
        let end = u64::from_str_radix(end_hex, 16).ok()?;
        if value < start || value >= end {
            continue;
        }
        let file_off = u64::from_str_radix(file_off_hex, 16).ok()?;
        let load_bias = start.checked_sub(file_off)?;
        let module_off = value.checked_sub(load_bias)?;
        let label = if path.is_empty() {
            "[anonymous]".to_string()
        } else {
            path.to_string()
        };
        return Some((label, module_off));
    }
    None
}

#[cfg(target_arch = "aarch64")]
fn dynamic_is_callable_external_target(value: u64) -> bool {
    if value == 0 {
        return false;
    }
    if dynamic_ptr_in_code_range(value) {
        return false;
    }
    if !dynamic_looks_code_aligned(value) {
        return false;
    }
    dynamic_has_executable_mapping(value)
}

#[cfg(target_arch = "aarch64")]
fn dynamic_is_non_callable_external_target(value: u64) -> bool {
    if value == 0 {
        return true;
    }
    if dynamic_ptr_in_code_range(value) {
        return false;
    }
    if !dynamic_looks_code_aligned(value) {
        return true;
    }
    !dynamic_has_executable_mapping(value)
}

#[cfg(target_arch = "aarch64")]
const LIBART_JNI_METHOD_START_OFFSET: u64 = 0x7392fc;
#[cfg(target_arch = "aarch64")]
const LIBART_JNI_METHOD_START_SYNC_OFFSET: u64 = 0x7394a8;
#[cfg(target_arch = "aarch64")]
const LIBART_VISIBLY_INITIALIZED_CALLBACK_RUN_OFFSET: u64 = 0x2cd3c8;
#[cfg(target_arch = "aarch64")]
const LIBART_ART_QUICK_TO_INTERPRETER_BRIDGE_OFFSET: u64 = 0x222320;
#[cfg(target_arch = "aarch64")]
const LIBART_ART_QUICK_LOCK_OBJECT_OFFSET: u64 = 0x218d80;
#[cfg(target_arch = "aarch64")]
const LIBART_NTERP_COMMON_INVOKE_STATIC_OFFSET: u64 = 0x21160c;
#[cfg(target_arch = "aarch64")]
const LIBART_ART_QUICK_INVOKE_STUB_OFFSET: u64 = 0x218968;

#[cfg(target_arch = "aarch64")]
fn dynamic_should_bail_art_checkpoint_jni_start(ctx: &JitContext, target: u64) -> bool {
    let Some(target_off) = dynamic_module_file_offset(target, "libart.so") else {
        return false;
    };
    if target_off != LIBART_JNI_METHOD_START_OFFSET
        && target_off != LIBART_JNI_METHOD_START_SYNC_OFFSET
    {
        return false;
    }
    let x0 = dynamic_strip_ptr_tag(ctx.x[0]);
    if !dynamic_has_readable_mapping(x0, 0x1a80) {
        return false;
    }
    let state = unsafe { *(x0 as *const u32) };
    if (state & 0x2) == 0 {
        return false;
    }
    let checkpoint_closure = unsafe { *((x0 + 0x170) as *const u64) };
    if checkpoint_closure == 0 || !dynamic_has_readable_mapping(checkpoint_closure, 0x18) {
        return true;
    }
    let closure_vtable = unsafe { *(dynamic_strip_ptr_tag(checkpoint_closure) as *const u64) };
    if closure_vtable == 0 || !dynamic_has_readable_mapping(closure_vtable, 0x18) {
        return true;
    }
    let closure_run = unsafe { *((dynamic_strip_ptr_tag(closure_vtable) + 0x10) as *const u64) };
    let Some(run_off) = dynamic_module_file_offset(closure_run, "libart.so") else {
        return true;
    };
    run_off == LIBART_VISIBLY_INITIALIZED_CALLBACK_RUN_OFFSET
}

#[cfg(target_arch = "aarch64")]
fn dynamic_should_bail_art_runtime_stub(target: u64) -> Option<&'static str> {
    let target_off = dynamic_module_file_offset(target, "libart.so")?;
    match target_off {
        LIBART_ART_QUICK_TO_INTERPRETER_BRIDGE_OFFSET => Some("art_quick_to_interpreter_bridge"),
        LIBART_ART_QUICK_LOCK_OBJECT_OFFSET => Some("art_quick_lock_object"),
        LIBART_NTERP_COMMON_INVOKE_STATIC_OFFSET => Some("nterp_common_invoke_static"),
        LIBART_ART_QUICK_INVOKE_STUB_OFFSET => Some("art_quick_invoke_stub"),
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
fn dynamic_choose_bail_resume_pc(ctx: &JitContext) -> u64 {
    if dynamic_ptr_in_code_range(ctx.x[30]) {
        ctx.x[30]
    } else if ctx.pc != 0 {
        ctx.pc
    } else {
        ctx.x[30]
    }
}

#[cfg(target_arch = "aarch64")]
fn dynffi_trace_resume_frame(ctx: &JitContext, result: &AeonDynRuntimeResult) {
    let final_pc = result.final_pc;
    let kind = match final_pc {
        0x7c3fe18968 => "art_quick_invoke_stub_epilogue",
        0x7c3fe18bec => "art_quick_invoke_static_stub_epilogue",
        0x7c3fe12524 => "nterp_common_invoke_resume",
        _ => return,
    };
    dynffi_trace_line(&format!(
        "resume_frame kind={kind} final=0x{final_pc:x} x29=0x{:x} sp=0x{:x} lr=0x{:x} x4=0x{:x} x5=0x{:x} x22=0x{:x} x24=0x{:x}",
        ctx.x[29], ctx.sp, ctx.x[30], ctx.x[4], ctx.x[5], ctx.x[22], ctx.x[24]
    ));
    if final_pc == 0x7c3fe18968 || final_pc == 0x7c3fe18bec {
        let fp = ctx.x[29];
        if dynamic_has_readable_mapping(fp, 48) {
            unsafe {
                let frame = fp as *const u64;
                let frame_x4 = *frame.add(0);
                let frame_x5 = *frame.add(1);
                let frame_x19 = *frame.add(2);
                let frame_x20 = *frame.add(3);
                let frame_fp = *frame.add(4);
                let frame_lr = *frame.add(5);
                dynffi_trace_line(&format!(
                    "resume_frame_slots kind={kind} fp=0x{fp:x} [fp+0]=0x{frame_x4:x} [fp+8]=0x{frame_x5:x} [fp+16]=0x{frame_x19:x} [fp+24]=0x{frame_x20:x} [fp+32]=0x{frame_fp:x} [fp+40]=0x{frame_lr:x}"
                ));
            }
        } else {
            dynffi_trace_line(&format!(
                "resume_frame_slots kind={kind} fp=0x{fp:x} readable=false"
            ));
        }
    } else if final_pc == 0x7c3fe12524 {
        let x22 = ctx.x[22];
        if dynamic_has_readable_mapping(x22, 10) {
            unsafe {
                let word6 = *(x22.wrapping_add(6) as *const u16);
                let word8 = *(x22.wrapping_add(8) as *const u16);
                dynffi_trace_line(&format!(
                    "resume_nterp kind={kind} x22=0x{x22:x} word6=0x{word6:x} word8=0x{word8:x} x24=0x{:x}",
                    ctx.x[24]
                ));
            }
        } else {
            dynffi_trace_line(&format!(
                "resume_nterp kind={kind} x22=0x{x22:x} readable=false x24=0x{:x}",
                ctx.x[24]
            ));
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn dynffi_trace_bridge_probe(ctx: &JitContext, target: u64) {
    let interesting = ctx.pc == 0x9cf7c0cc
        || target == 0x7c403392fc
        || ctx.x[30] == 0x7c3fe1160c
        || ctx.x[30] == 0x7c3fe18968
        || ctx.x[30] == 0x7c3fe18bec;
    if !interesting {
        return;
    }
    let tail_mode = dynamic_ptr_in_code_range(ctx.x[30]);
    dynffi_trace_line(&format!(
        "bridge_probe ctx_pc=0x{:x} target=0x{:x} saved_x30=0x{:x} tail_mode={} x0=0x{:x} x19=0x{:x} x22=0x{:x} x24=0x{:x} x28=0x{:x} sp=0x{:x}",
        ctx.pc,
        target,
        ctx.x[30],
        if tail_mode { 1 } else { 0 },
        ctx.x[0],
        ctx.x[19],
        ctx.x[22],
        ctx.x[24],
        ctx.x[28],
        ctx.sp
    ));
    let x0 = ctx.x[0];
    let x0_untagged = dynamic_strip_ptr_tag(x0);
    dynffi_trace_line(&format!(
        "bridge_probe_ptr x0=0x{x0:x} x0_untagged=0x{x0_untagged:x}"
    ));
    if dynamic_has_readable_mapping(x0, 216) {
        unsafe {
            let thread_state = *(x0_untagged as *const u32);
            dynffi_trace_line(&format!(
                "bridge_probe_state x0=0x{x0:x} state=0x{thread_state:x} checkpoint={} empty_checkpoint={} suspend_barrier={} suspend_pending={}",
                (thread_state & 0x2) != 0,
                (thread_state & 0x4) != 0,
                (thread_state & 0x8) != 0,
                (thread_state & 0xe) != 0,
            ));
            if dynamic_has_readable_mapping(x0, 0x1a80) {
                let checkpoint_closure = *((x0_untagged + 0x170) as *const u64);
                let checkpoint_head = *((x0_untagged + 0x1a70) as *const u64);
                let checkpoint_count = *((x0_untagged + 0x1a78) as *const u64);
                dynffi_trace_line(&format!(
                    "bridge_probe_checkpoint x0=0x{x0:x} closure=0x{checkpoint_closure:x} head=0x{checkpoint_head:x} count=0x{checkpoint_count:x}"
                ));
                if dynamic_has_readable_mapping(checkpoint_closure, 0x18) {
                    let closure_vtable = *(checkpoint_closure as *const u64);
                    let closure_run = if dynamic_has_readable_mapping(closure_vtable, 0x18) {
                        *((closure_vtable + 0x10) as *const u64)
                    } else {
                        0
                    };
                    dynffi_trace_line(&format!(
                        "bridge_probe_checkpoint_closure closure=0x{checkpoint_closure:x} vtable=0x{closure_vtable:x} run=0x{closure_run:x}"
                    ));
                } else {
                    dynffi_trace_line(&format!(
                        "bridge_probe_checkpoint_closure closure=0x{checkpoint_closure:x} readable=false"
                    ));
                }
            } else {
                dynffi_trace_line(&format!(
                    "bridge_probe_checkpoint x0=0x{x0:x} readable=false"
                ));
            }
            let jni_state_ptr = *((x0_untagged + 0xd0) as *const u64);
            dynffi_trace_line(&format!(
                "bridge_probe_jni_state x0=0x{x0:x} jni_state=0x{jni_state_ptr:x}"
            ));
            if dynamic_has_readable_mapping(jni_state_ptr, 0x24) {
                let prev = *((jni_state_ptr + 0x18) as *const u32);
                let next = *((jni_state_ptr + 0x20) as *const u32);
                dynffi_trace_line(&format!(
                    "bridge_probe_jni_state_words jni_state=0x{jni_state_ptr:x} [0x18]=0x{prev:x} [0x20]=0x{next:x}"
                ));
            } else {
                dynffi_trace_line(&format!(
                    "bridge_probe_jni_state_words jni_state=0x{jni_state_ptr:x} readable=false"
                ));
            }
            let thread_tls = *((x0_untagged + 208) as *const u64);
            dynffi_trace_line(&format!(
                "bridge_probe_thread x0=0x{x0:x} thread_tls=0x{thread_tls:x}"
            ));
            if dynamic_has_readable_mapping(thread_tls, 40) {
                let field24 = *((thread_tls + 24) as *const u32);
                let field32 = *((thread_tls + 32) as *const u32);
                dynffi_trace_line(&format!(
                    "bridge_probe_thread_tls thread_tls=0x{thread_tls:x} [24]=0x{field24:x} [32]=0x{field32:x}"
                ));
            } else {
                dynffi_trace_line(&format!(
                    "bridge_probe_thread_tls thread_tls=0x{thread_tls:x} readable=false"
                ));
            }
        }
    } else {
        dynffi_trace_line(&format!("bridge_probe_thread x0=0x{x0:x} readable=false"));
    }
}

#[no_mangle]
pub extern "C" fn aeon_dyn_runtime_branch_translate(target: u64) -> u64 {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if aeon_dyn_code_range_start != 0
            && target >= aeon_dyn_code_range_start
            && target < aeon_dyn_code_range_end
        {
            return 0;
        }
    }
    target
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn aeon_dyn_runtime_resume_trampoline_impl(
        handle: *mut std::ffi::c_void,
        ctx: *mut JitContext,
        out_result: *mut AeonDynRuntimeResult,
    ) -> u64;
    fn aeon_dyn_runtime_branch_bridge_impl(ctx: *mut JitContext, target: u64) -> u64;
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_resume_trampoline(
    handle: *mut std::ffi::c_void,
    ctx: *mut JitContext,
    out_result: *mut AeonDynRuntimeResult,
) -> u64 {
    aeon_dyn_runtime_resume_trampoline_impl(handle, ctx, out_result)
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_branch_bridge(ctx: *mut JitContext, target: u64) -> u64 {
    if let Some(ctx_ref) = ctx.as_mut() {
        // If the guest LR points back into the translated corridor, returning
        // directly to the raw JIT page can confuse ART stack walking. We still
        // record that condition as tail_mode for diagnostics, but the bridge
        // now routes both cases through the call-and-capture path below.
        let tail_mode = dynamic_ptr_in_code_range(ctx_ref.x[30]);
        let target_desc = if let Some((label, off)) = dynamic_mapping_label_and_offset(target) {
            format!("{label}+0x{off:x}")
        } else {
            "unmapped".to_string()
        };
        dynffi_trace_line(&format!(
            "branch_bridge enter ctx_pc=0x{:x} target=0x{:x} target_desc={} saved_x30=0x{:x} tail_mode={} x0=0x{:x} x1=0x{:x} sp=0x{:x}",
            ctx_ref.pc,
            target,
            target_desc,
            ctx_ref.x[30],
            if tail_mode { 1 } else { 0 },
            ctx_ref.x[0],
            ctx_ref.x[1],
            ctx_ref.sp
        ));
        dynffi_trace_bridge_probe(ctx_ref, target);
        if dynamic_should_bail_art_checkpoint_jni_start(ctx_ref, target) {
            let resume_pc = ctx_ref.pc;
            dynffi_trace_line(&format!(
                "branch_bridge special_bail kind=art_jni_checkpoint ctx_pc=0x{:x} target=0x{:x} resume=0x{:x} lr=0x{:x}",
                ctx_ref.pc, target, resume_pc, ctx_ref.x[30]
            ));
            ctx_ref.pc = resume_pc;
            aeon_dyn_branch_bridge_stage = 0xbabe;
            aeon_dyn_branch_bridge_last_target = target;
            aeon_dyn_branch_bridge_saved_x30 = ctx_ref.x[30];
            aeon_dyn_branch_bridge_resume_target = resume_pc;
            aeon_dyn_branch_bridge_ctx_pc = ctx_ref.pc;
            return AEON_DYN_BAIL_SENTINEL;
        }
        if let Some(kind) = dynamic_should_bail_art_runtime_stub(target) {
            let resume_pc = ctx_ref.pc;
            dynffi_trace_line(&format!(
                "branch_bridge special_bail kind={kind} ctx_pc=0x{:x} target=0x{:x} resume=0x{:x} lr=0x{:x}",
                ctx_ref.pc, target, resume_pc, ctx_ref.x[30]
            ));
            ctx_ref.pc = resume_pc;
            aeon_dyn_branch_bridge_stage = 0xbabf;
            aeon_dyn_branch_bridge_last_target = target;
            aeon_dyn_branch_bridge_saved_x30 = ctx_ref.x[30];
            aeon_dyn_branch_bridge_resume_target = resume_pc;
            aeon_dyn_branch_bridge_ctx_pc = ctx_ref.pc;
            return AEON_DYN_BAIL_SENTINEL;
        }
        if dynamic_is_non_callable_external_target(target) {
            let resume_pc = dynamic_choose_bail_resume_pc(ctx_ref);
            dynffi_trace_line(&format!(
                "branch_bridge bail ctx_pc=0x{:x} target=0x{:x} resume=0x{:x} lr=0x{:x}",
                ctx_ref.pc, target, resume_pc, ctx_ref.x[30]
            ));
            ctx_ref.pc = resume_pc;
            aeon_dyn_branch_bridge_stage = 0xba11;
            aeon_dyn_branch_bridge_last_target = target;
            aeon_dyn_branch_bridge_saved_x30 = ctx_ref.x[30];
            aeon_dyn_branch_bridge_resume_target = resume_pc;
            aeon_dyn_branch_bridge_ctx_pc = ctx_ref.pc;
            return AEON_DYN_BAIL_SENTINEL;
        }
    }
    aeon_dyn_runtime_branch_bridge_impl(ctx, target)
}

#[cfg(not(target_arch = "aarch64"))]
#[no_mangle]
pub extern "C" fn aeon_dyn_runtime_branch_bridge(_ctx: *mut JitContext, target: u64) -> u64 {
    target
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .text
    .equ AEON_HANDOFF_HANDLE,   0x00
    .equ AEON_HANDOFF_CTX,      0x08
    .equ AEON_HANDOFF_OUT,      0x10
    .equ AEON_HANDOFF_ORIG_X0,  0x18
    .equ AEON_HANDOFF_ORIG_PC,  0x20
    .equ AEON_HANDOFF_ORIG_X30, 0x28
    .equ AEON_SCRATCH_HOST_SP,   0x00
    .equ AEON_SCRATCH_CTX,       0x08
    .equ AEON_SCRATCH_SAVED_X30, 0x10
    .equ AEON_SCRATCH_STAGE,     0x18
    .equ AEON_SCRATCH_LAST_TGT,  0x20
    .equ AEON_SCRATCH_TAILMODE,  0x28
    .equ AEON_SCRATCH_SAVEAREA,  0x30
    .equ AEON_SCRATCH_HOST_X18,  0x118
    .equ AEON_SCRATCH_DBG_OUT_X30, 0x120
    .equ AEON_SCRATCH_DBG_POST_X30, 0x128
    .equ AEON_SCRATCH_DBG_RESUME, 0x130
    .equ AEON_SCRATCH_DBG_CTX_PC, 0x138
    .equ AEON_SCRATCH_SIZE,      0x140

    .global aeon_dyn_runtime_resume_trampoline_impl
    .type aeon_dyn_runtime_resume_trampoline_impl, %function
aeon_dyn_runtime_resume_trampoline_impl:
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    ldr x0, [sp, #16]
    ldr x1, [x0, #AEON_HANDOFF_CTX]
    ldr x2, [x0, #AEON_HANDOFF_ORIG_X0]
    str x2, [x1, #0]
    ldr x2, [sp, #24]
    str x2, [x1, #8]
    ldr x2, [sp, #0]
    str x2, [x1, #16]
    ldr x2, [sp, #8]
    str x2, [x1, #24]
    str x4, [x1, #32]
    str x5, [x1, #40]
    str x6, [x1, #48]
    str x7, [x1, #56]
    str x8, [x1, #64]
    str x9, [x1, #72]
    str x10, [x1, #80]
    str x11, [x1, #88]
    str x12, [x1, #96]
    str x13, [x1, #104]
    str x14, [x1, #112]
    str x15, [x1, #120]
    str x16, [x1, #128]
    str x17, [x1, #136]
    str x18, [x1, #144]
    str x19, [x1, #152]
    str x20, [x1, #160]
    str x21, [x1, #168]
    str x22, [x1, #176]
    str x23, [x1, #184]
    str x24, [x1, #192]
    str x25, [x1, #200]
    str x26, [x1, #208]
    str x27, [x1, #216]
    str x28, [x1, #224]
    str x29, [x1, #232]
    ldr x2, [x0, #AEON_HANDOFF_ORIG_X30]
    str x2, [x1, #240]
    add x2, sp, #32
    str x2, [x1, #248]
    ldr x2, [x0, #AEON_HANDOFF_ORIG_PC]
    str x2, [x1, #256]
    mrs x2, NZCV
    str x2, [x1, #264]
    str q0, [x1, #272]
    str q1, [x1, #288]
    str q2, [x1, #304]
    str q3, [x1, #320]
    str q4, [x1, #336]
    str q5, [x1, #352]
    str q6, [x1, #368]
    str q7, [x1, #384]
    str q8, [x1, #400]
    str q9, [x1, #416]
    str q10, [x1, #432]
    str q11, [x1, #448]
    str q12, [x1, #464]
    str q13, [x1, #480]
    str q14, [x1, #496]
    str q15, [x1, #512]
    str q16, [x1, #528]
    str q17, [x1, #544]
    str q18, [x1, #560]
    str q19, [x1, #576]
    str q20, [x1, #592]
    str q21, [x1, #608]
    str q22, [x1, #624]
    str q23, [x1, #640]
    str q24, [x1, #656]
    str q25, [x1, #672]
    str q26, [x1, #688]
    str q27, [x1, #704]
    str q28, [x1, #720]
    str q29, [x1, #736]
    str q30, [x1, #752]
    str q31, [x1, #768]
    mrs x2, tpidr_el0
    str x2, [x1, #784]
    ldr x2, [x0, #AEON_HANDOFF_OUT]
    ldr x0, [x0, #AEON_HANDOFF_HANDLE]
    bl aeon_dyn_runtime_run_out
    add sp, sp, #32
    brk #{brk_imm}
    ret

    .global aeon_dyn_runtime_branch_bridge_impl
    .type aeon_dyn_runtime_branch_bridge_impl, %function
aeon_dyn_runtime_branch_bridge_impl:
    sub  x13, x0, #AEON_SCRATCH_SIZE

    mov  x14, #0x1
    str  x14, [x13, #AEON_SCRATCH_STAGE]
    adrp x15, :got:aeon_dyn_branch_bridge_stage
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_stage]
    str  x14, [x15]
    str  x1, [x13, #AEON_SCRATCH_LAST_TGT]
    adrp x15, :got:aeon_dyn_branch_bridge_last_target
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_last_target]
    str  x1, [x15]
    ldr  x14, [x0, #256]
    str  x14, [x13, #AEON_SCRATCH_DBG_CTX_PC]
    adrp x15, :got:aeon_dyn_branch_bridge_ctx_pc
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_ctx_pc]
    str  x14, [x15]
    add  x12, x13, #AEON_SCRATCH_SAVEAREA
    stp q8, q9, [x12, #0x00]
    stp q10, q11, [x12, #0x20]
    stp q12, q13, [x12, #0x40]
    stp q14, q15, [x12, #0x60]
    stp x19, x20, [x12, #0x80]
    stp x21, x22, [x12, #0x90]
    stp x23, x24, [x12, #0xa0]
    stp x25, x26, [x12, #0xb0]
    stp x27, x28, [x12, #0xc0]
    stp x29, x30, [x12, #0xd0]
    mrs x19, tpidr_el0
    str x19, [x12, #0xe0]
    str x18, [x13, #AEON_SCRATCH_HOST_X18]
    mov x19, x13

    mov  x20, sp
    str  x20, [x19, #AEON_SCRATCH_HOST_SP]
    adrp x12, :got:aeon_dyn_branch_bridge_host_sp
    ldr  x12, [x12, #:got_lo12:aeon_dyn_branch_bridge_host_sp]
    str  x20, [x12]

    str  x0, [x19, #AEON_SCRATCH_CTX]
    adrp x12, :got:aeon_dyn_branch_bridge_ctx
    ldr  x12, [x12, #:got_lo12:aeon_dyn_branch_bridge_ctx]
    str  x0, [x12]
    mov  x14, #0x2
    str  x14, [x19, #AEON_SCRATCH_STAGE]
    adrp x15, :got:aeon_dyn_branch_bridge_stage
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_stage]
    str  x14, [x15]

    ldr  x19, [x0, #240]
    str  x19, [x13, #AEON_SCRATCH_SAVED_X30]
    adrp x20, :got:aeon_dyn_branch_bridge_saved_x30
    ldr  x20, [x20, #:got_lo12:aeon_dyn_branch_bridge_saved_x30]
    str  x19, [x20]
    adrp x21, :got:aeon_dyn_code_range_start
    ldr  x21, [x21, #:got_lo12:aeon_dyn_code_range_start]
    ldr  x21, [x21]
    adrp x22, :got:aeon_dyn_code_range_end
    ldr  x22, [x22, #:got_lo12:aeon_dyn_code_range_end]
    ldr  x22, [x22]
    mov  x23, #0x0
    cbz  x21, 1f
    cmp  x19, x21
    b.lo 1f
    cmp  x19, x22
    b.hs 1f
    mov  x23, #0x1
1:
    str  x23, [x13, #AEON_SCRATCH_TAILMODE]
    adrp x24, :got:aeon_dyn_branch_bridge_tail_mode
    ldr  x24, [x24, #:got_lo12:aeon_dyn_branch_bridge_tail_mode]
    str  x23, [x24]
    ldr  x14, [x0, #0]
    adrp x15, :got:aeon_dyn_branch_bridge_arg_x0
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_arg_x0]
    str  x14, [x15]
    ldr  x14, [x0, #8]
    adrp x15, :got:aeon_dyn_branch_bridge_arg_x1
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_arg_x1]
    str  x14, [x15]
    ldr  x14, [x0, #144]
    adrp x15, :got:aeon_dyn_branch_bridge_arg_x18
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_arg_x18]
    str  x14, [x15]
    ldr  x14, [x0, #152]
    adrp x15, :got:aeon_dyn_branch_bridge_arg_x19
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_arg_x19]
    str  x14, [x15]
    ldr  x14, [x0, #168]
    adrp x15, :got:aeon_dyn_branch_bridge_arg_x21
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_arg_x21]
    str  x14, [x15]
    ldr  x14, [x0, #224]
    adrp x15, :got:aeon_dyn_branch_bridge_arg_x28
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_arg_x28]
    str  x14, [x15]
    ldr  x14, [x0, #248]
    adrp x15, :got:aeon_dyn_branch_bridge_arg_sp
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_arg_sp]
    str  x14, [x15]
    mov  x19, x13

    ldr  q0, [x0, #272]
    ldr  q1, [x0, #288]
    ldr  q2, [x0, #304]
    ldr  q3, [x0, #320]
    ldr  q4, [x0, #336]
    ldr  q5, [x0, #352]
    ldr  q6, [x0, #368]
    ldr  q7, [x0, #384]
    ldr  q8, [x0, #400]
    ldr  q9, [x0, #416]
    ldr  q10, [x0, #432]
    ldr  q11, [x0, #448]
    ldr  q12, [x0, #464]
    ldr  q13, [x0, #480]
    ldr  q14, [x0, #496]
    ldr  q15, [x0, #512]
    ldr  q16, [x0, #528]
    ldr  q17, [x0, #544]
    ldr  q18, [x0, #560]
    ldr  q19, [x0, #576]
    ldr  q20, [x0, #592]
    ldr  q21, [x0, #608]
    ldr  q22, [x0, #624]
    ldr  q23, [x0, #640]
    ldr  q24, [x0, #656]
    ldr  q25, [x0, #672]
    ldr  q26, [x0, #688]
    ldr  q27, [x0, #704]
    ldr  q28, [x0, #720]
    ldr  q29, [x0, #736]
    ldr  q30, [x0, #752]
    ldr  q31, [x0, #768]
    mov  x14, #0x3
    str  x14, [x19, #AEON_SCRATCH_STAGE]
    adrp x15, :got:aeon_dyn_branch_bridge_stage
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_stage]
    str  x14, [x15]
    mov  x14, #0x4
    str  x14, [x19, #AEON_SCRATCH_STAGE]
    adrp x15, :got:aeon_dyn_branch_bridge_stage
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_stage]
    str  x14, [x15]

    mov  x17, x1
    ldr  x0, [x0, #0]
    ldr  x30, [x19, #AEON_SCRATCH_CTX]
    ldr  x1, [x30, #8]
    ldr  x2, [x30, #16]
    ldr  x3, [x30, #24]
    ldr  x4, [x30, #32]
    ldr  x5, [x30, #40]
    ldr  x6, [x30, #48]
    ldr  x7, [x30, #56]
    ldr  x8, [x30, #64]
    ldr  x9, [x30, #72]
    ldr  x10, [x30, #80]
    ldr  x11, [x30, #88]
    ldr  x12, [x30, #96]
    ldr  x13, [x30, #104]
    ldr  x14, [x30, #112]
    ldr  x15, [x30, #120]
    ldr  x16, [x30, #128]
    ldr  x18, [x30, #144]
    b    2f
2:
    adr  x12, 3f
    str  x12, [x19, #AEON_SCRATCH_DBG_OUT_X30]
    adrp x14, :got:aeon_dyn_branch_bridge_outgoing_x30
    ldr  x14, [x14, #:got_lo12:aeon_dyn_branch_bridge_outgoing_x30]
    str  x12, [x14]
    mov  x12, #0x0
    str  x12, [x19, #AEON_SCRATCH_DBG_POST_X30]
    adrp x14, :got:aeon_dyn_branch_bridge_post_call_x30
    ldr  x14, [x14, #:got_lo12:aeon_dyn_branch_bridge_post_call_x30]
    str  x12, [x14]
    str  x12, [x19, #AEON_SCRATCH_DBG_RESUME]
    adrp x14, :got:aeon_dyn_branch_bridge_resume_target
    ldr  x14, [x14, #:got_lo12:aeon_dyn_branch_bridge_resume_target]
    str  x12, [x14]
    ldr  x11, [x30, #248]
    mov  sp, x11
    ldr  x11, [x30, #88]
    ldr  x20, [x30, #160]
    ldr  x21, [x30, #168]
    ldr  x22, [x30, #176]
    ldr  x23, [x30, #184]
    ldr  x24, [x30, #192]
    ldr  x25, [x30, #200]
    ldr  x26, [x30, #208]
    ldr  x27, [x30, #216]
    ldr  x28, [x30, #224]
    ldr  x29, [x30, #232]
    ldr  x12, [x30, #152]
    mov  x19, x12
    blr  x17
3:
    mov  x12, x30
    str  x12, [x19, #AEON_SCRATCH_DBG_POST_X30]
    adrp x14, :got:aeon_dyn_branch_bridge_post_call_x30
    ldr  x14, [x14, #:got_lo12:aeon_dyn_branch_bridge_post_call_x30]
    str  x12, [x14]
    adrp x30, :got:aeon_dyn_branch_bridge_ctx
    ldr  x30, [x30, #:got_lo12:aeon_dyn_branch_bridge_ctx]
    ldr  x30, [x30]
    sub  x30, x30, #AEON_SCRATCH_SIZE
    ldr  x16, [x30, #AEON_SCRATCH_CTX]
    str  x0, [x16, #0]
    str  x1, [x16, #8]
    str  x2, [x16, #16]
    str  x3, [x16, #24]
    str  x4, [x16, #32]
    str  x5, [x16, #40]
    str  x6, [x16, #48]
    str  x7, [x16, #56]
    str  x8, [x16, #64]
    str  x9, [x16, #72]
    str  x10, [x16, #80]
    str  x11, [x16, #88]
    str  x12, [x16, #96]
    str  x13, [x16, #104]
    str  x14, [x16, #112]
    str  x17, [x16, #136]
    mov  x14, #0x5
    str  x14, [x30, #AEON_SCRATCH_STAGE]
    adrp x15, :got:aeon_dyn_branch_bridge_stage
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_stage]
    str  x14, [x15]
    str  x18, [x16, #144]
    str  x19, [x16, #152]
    str  x20, [x16, #160]
    str  x21, [x16, #168]
    str  x22, [x16, #176]
    str  x23, [x16, #184]
    str  x24, [x16, #192]
    str  x25, [x16, #200]
    str  x26, [x16, #208]
    str  x27, [x16, #216]
    str  x28, [x16, #224]
    str  x29, [x16, #232]
    mov  x29, sp
    str  x29, [x16, #248]
    str  q0, [x16, #272]
    str  q1, [x16, #288]
    str  q2, [x16, #304]
    str  q3, [x16, #320]
    str  q4, [x16, #336]
    str  q5, [x16, #352]
    str  q6, [x16, #368]
    str  q7, [x16, #384]
    str  q8, [x16, #400]
    str  q9, [x16, #416]
    str  q10, [x16, #432]
    str  q11, [x16, #448]
    str  q12, [x16, #464]
    str  q13, [x16, #480]
    str  q14, [x16, #496]
    str  q15, [x16, #512]
    str  q16, [x16, #528]
    str  q17, [x16, #544]
    str  q18, [x16, #560]
    str  q19, [x16, #576]
    str  q20, [x16, #592]
    str  q21, [x16, #608]
    str  q22, [x16, #624]
    str  q23, [x16, #640]
    str  q24, [x16, #656]
    str  q25, [x16, #672]
    str  q26, [x16, #688]
    str  q27, [x16, #704]
    str  q28, [x16, #720]
    str  q29, [x16, #736]
    str  q30, [x16, #752]
    str  q31, [x16, #768]
    mrs  x12, tpidr_el0
    str  x12, [x16, #784]
    ldr  x11, [x30, #AEON_SCRATCH_SAVED_X30]
    str  x11, [x16, #240]
    str  x11, [x30, #AEON_SCRATCH_DBG_RESUME]
    adrp x14, :got:aeon_dyn_branch_bridge_resume_target
    ldr  x14, [x14, #:got_lo12:aeon_dyn_branch_bridge_resume_target]
    str  x11, [x14]
    mov  x14, #0x6
    str  x14, [x30, #AEON_SCRATCH_STAGE]
    adrp x15, :got:aeon_dyn_branch_bridge_stage
    ldr  x15, [x15, #:got_lo12:aeon_dyn_branch_bridge_stage]
    str  x14, [x15]

    ldr  x12, [x30, #AEON_SCRATCH_HOST_SP]
    mov  sp, x12
    add  x12, x30, #AEON_SCRATCH_SAVEAREA
    ldr  x14, [x12, #0xe0]
    msr  tpidr_el0, x14
    ldr  x18, [x30, #AEON_SCRATCH_HOST_X18]
    mov  x0, x11
    ldp  q8, q9, [x12, #0x00]
    ldp  q10, q11, [x12, #0x20]
    ldp  q12, q13, [x12, #0x40]
    ldp  q14, q15, [x12, #0x60]
    ldp  x19, x20, [x12, #0x80]
    ldp  x21, x22, [x12, #0x90]
    ldp  x23, x24, [x12, #0xa0]
    ldp  x25, x26, [x12, #0xb0]
    ldp  x27, x28, [x12, #0xc0]
    ldp  x29, x30, [x12, #0xd0]
    ret

    "#,
    brk_imm = const AEON_DYN_TRAMPOLINE_BRK_IMM,
);

#[no_mangle]
pub extern "C" fn aeon_dyn_runtime_resume_trampoline_brk_imm() -> u32 {
    AEON_DYN_TRAMPOLINE_BRK_IMM as u32
}

#[no_mangle]
pub extern "C" fn aeon_dyn_runtime_bridge_scratch_size() -> usize {
    AEON_DYN_BRIDGE_SCRATCH_SIZE
}

#[no_mangle]
pub extern "C" fn aeon_dyn_runtime_resume_handoff_size() -> usize {
    AEON_DYN_RESUME_HANDOFF_SIZE
}

fn stop_to_result(result: crate::dynruntime::DynamicRuntimeResult) -> AeonDynRuntimeResult {
    let (stop_code, info_pc) = match result.stop {
        DynamicRuntimeStop::Halted => (STOP_HALTED, 0),
        DynamicRuntimeStop::MaxSteps => (STOP_MAX_STEPS, 0),
        DynamicRuntimeStop::CodeRangeExit(pc) => (STOP_CODE_RANGE_EXIT, pc),
        DynamicRuntimeStop::LiftError(pc, _) => (STOP_LIFT_ERROR, pc),
    };
    AeonDynRuntimeResult {
        stop_code,
        start_pc: result.start_pc,
        final_pc: result.final_pc,
        steps: result.steps as u64,
        compiled_blocks: result.compiled_blocks as u64,
        info_pc,
    }
}

#[no_mangle]
pub extern "C" fn aeon_dyn_runtime_create(
    source_base: u64,
    source_size: usize,
) -> *mut std::ffi::c_void {
    if source_base == 0 || source_size == 0 {
        return ptr::null_mut();
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        aeon_dyn_code_range_start = source_base;
        aeon_dyn_code_range_end = source_base + source_size as u64;
    }
    let handle = DynamicRuntimeHandle {
        runtime: DynamicRuntime::new(),
        memory: CodeWindowMemory {
            base: source_base,
            size: source_size,
        },
        config: DynamicRuntimeConfig {
            max_steps: 4096,
            code_range: Some((source_base, source_base + source_size as u64)),
        },
    };
    Box::into_raw(Box::new(handle)) as *mut std::ffi::c_void
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_destroy(handle: *mut std::ffi::c_void) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut DynamicRuntimeHandle));
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_set_max_steps(
    handle: *mut std::ffi::c_void,
    max_steps: usize,
) {
    let Some(handle) = (handle as *mut DynamicRuntimeHandle).as_mut() else {
        return;
    };
    if max_steps > 0 {
        handle.config.max_steps = max_steps;
    }
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_set_code_range(
    handle: *mut std::ffi::c_void,
    start: u64,
    end: u64,
) {
    let Some(handle) = (handle as *mut DynamicRuntimeHandle).as_mut() else {
        return;
    };
    if start < end {
        handle.config.code_range = Some((start, end));
        #[cfg(target_arch = "aarch64")]
        {
            aeon_dyn_code_range_start = start;
            aeon_dyn_code_range_end = end;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_clear_code_range(handle: *mut std::ffi::c_void) {
    let Some(handle) = (handle as *mut DynamicRuntimeHandle).as_mut() else {
        return;
    };
    handle.config.code_range = None;
    #[cfg(target_arch = "aarch64")]
    {
        aeon_dyn_code_range_start = 0;
        aeon_dyn_code_range_end = 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_set_memory_read_callback(
    handle: *mut std::ffi::c_void,
    callback: Option<MemoryReadCallback>,
) {
    let Some(handle) = (handle as *mut DynamicRuntimeHandle).as_mut() else {
        return;
    };
    handle
        .runtime
        .compiler_mut()
        .set_memory_read_callback(callback);
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_set_memory_write_callback(
    handle: *mut std::ffi::c_void,
    callback: Option<MemoryWriteCallback>,
) {
    let Some(handle) = (handle as *mut DynamicRuntimeHandle).as_mut() else {
        return;
    };
    handle
        .runtime
        .compiler_mut()
        .set_memory_write_callback(callback);
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_set_branch_translate_callback(
    handle: *mut std::ffi::c_void,
    callback: Option<BranchTranslateCallback>,
) {
    let Some(handle) = (handle as *mut DynamicRuntimeHandle).as_mut() else {
        return;
    };
    handle
        .runtime
        .compiler_mut()
        .set_branch_translate_callback(callback);
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_set_branch_bridge_callback(
    handle: *mut std::ffi::c_void,
    callback: Option<BranchBridgeCallback>,
) {
    let Some(handle) = (handle as *mut DynamicRuntimeHandle).as_mut() else {
        return;
    };
    handle
        .runtime
        .compiler_mut()
        .set_branch_bridge_callback(callback);
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_set_block_enter_callback(
    handle: *mut std::ffi::c_void,
    callback: Option<BlockEnterCallback>,
) {
    let Some(handle) = (handle as *mut DynamicRuntimeHandle).as_mut() else {
        return;
    };
    handle
        .runtime
        .compiler_mut()
        .set_block_enter_callback(callback);
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_compiled_blocks(
    handle: *const std::ffi::c_void,
) -> usize {
    let Some(handle) = (handle as *const DynamicRuntimeHandle).as_ref() else {
        return 0;
    };
    handle.runtime.block_count()
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_lookup_block_source(
    handle: *const std::ffi::c_void,
    block_id: u64,
) -> u64 {
    let Some(handle) = (handle as *const DynamicRuntimeHandle).as_ref() else {
        return 0;
    };
    handle.runtime.source_for_block_id(block_id).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_run(
    handle: *mut std::ffi::c_void,
    ctx: *mut JitContext,
) -> AeonDynRuntimeResult {
    let Some(handle) = (handle as *mut DynamicRuntimeHandle).as_mut() else {
        return AeonDynRuntimeResult {
            stop_code: STOP_INVALID_ARGUMENT,
            start_pc: 0,
            final_pc: 0,
            steps: 0,
            compiled_blocks: 0,
            info_pc: 0,
        };
    };
    let Some(ctx) = ctx.as_mut() else {
        return AeonDynRuntimeResult {
            stop_code: STOP_INVALID_ARGUMENT,
            start_pc: 0,
            final_pc: 0,
            steps: 0,
            compiled_blocks: handle.runtime.block_count() as u64,
            info_pc: 0,
        };
    };
    stop_to_result(handle.runtime.run(ctx, &handle.memory, handle.config))
}

#[no_mangle]
pub extern "C" fn aeon_dyn_runtime_result_size() -> usize {
    std::mem::size_of::<AeonDynRuntimeResult>()
}

#[no_mangle]
pub unsafe extern "C" fn aeon_dyn_runtime_run_out(
    handle: *mut std::ffi::c_void,
    ctx: *mut JitContext,
    out_result: *mut AeonDynRuntimeResult,
) -> u32 {
    dynffi_trace_line(&format!(
        "run_out enter handle=0x{:x} ctx=0x{:x} out=0x{:x}",
        handle as usize, ctx as usize, out_result as usize
    ));
    if let Some(handle_ref) = (handle as *mut DynamicRuntimeHandle).as_ref() {
        dynffi_trace_line(&format!(
            "run_out cfg max_steps={} range={:?} block_count={}",
            handle_ref.config.max_steps,
            handle_ref.config.code_range,
            handle_ref.runtime.block_count()
        ));
    } else {
        dynffi_trace_line("run_out cfg handle=<null>");
    }
    if let Some(ctx_ref) = ctx.as_ref() {
        dynffi_trace_line(&format!(
            "run_out ctx pc=0x{:x} x0=0x{:x} sp=0x{:x} lr=0x{:x}",
            ctx_ref.pc, ctx_ref.x[0], ctx_ref.sp, ctx_ref.x[30]
        ));
    } else {
        dynffi_trace_line("run_out ctx=<null>");
    }
    let result = aeon_dyn_runtime_run(handle, ctx);
    #[cfg(target_arch = "aarch64")]
    if result.stop_code == STOP_CODE_RANGE_EXIT {
        if let Some(ctx_ref) = ctx.as_ref() {
            dynffi_trace_resume_frame(ctx_ref, &result);
        }
    }
    if !out_result.is_null() {
        ptr::write(out_result, result);
    }
    dynffi_trace_line(&format!(
        "run_out leave stop={} start=0x{:x} final=0x{:x} steps={} compiled={} info=0x{:x}",
        result.stop_code,
        result.start_pc,
        result.final_pc,
        result.steps,
        result.compiled_blocks,
        result.info_pc
    ));
    result.stop_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::SnapshotMemory;

    fn push_word(buf: &mut Vec<u8>, word: u32) {
        buf.extend_from_slice(&word.to_le_bytes());
    }

    #[test]
    fn code_window_memory_reads_within_bounds() {
        let bytes = Box::leak(Box::new([0x11u8, 0x22, 0x33, 0x44]));
        let base = bytes.as_ptr() as u64;
        let mem = CodeWindowMemory {
            base,
            size: bytes.len(),
        };
        assert_eq!(mem.read(base + 1, 2).unwrap(), vec![0x22, 0x33]);
        assert!(mem.read(base + 3, 2).is_none());
    }

    #[test]
    fn ffi_lookup_block_source_returns_compiled_pc() {
        let mut memory = SnapshotMemory::new();
        let mut code = Vec::new();
        push_word(&mut code, 0xd2800020); // mov x0, #1
        push_word(&mut code, 0xd65f03c0); // ret
        memory.add_region(0x1000, code);

        let mut handle = DynamicRuntimeHandle {
            runtime: DynamicRuntime::new(),
            memory: CodeWindowMemory {
                base: 0x1000,
                size: 0x1000,
            },
            config: DynamicRuntimeConfig {
                max_steps: 8,
                code_range: Some((0x1000, 0x2000)),
            },
        };

        let mut ctx = JitContext::default();
        ctx.pc = 0x1000;
        ctx.x[30] = 0;
        let result = handle.runtime.run(&mut ctx, &memory, handle.config);
        assert_eq!(result.stop, DynamicRuntimeStop::Halted);
        assert_eq!(handle.runtime.block_count(), 1);

        let source = unsafe {
            aeon_dyn_runtime_lookup_block_source(
                (&handle as *const DynamicRuntimeHandle).cast::<std::ffi::c_void>(),
                0,
            )
        };
        assert_eq!(source, 0x1000);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn enc_movz_x(rd: u32, imm16: u16, shift: u32) -> u32 {
        let hw = (shift / 16) & 0x3;
        0xD280_0000 | ((hw & 0x3) << 21) | ((imm16 as u32) << 5) | (rd & 0x1f)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn enc_movk_x(rd: u32, imm16: u16, shift: u32) -> u32 {
        let hw = (shift / 16) & 0x3;
        0xF280_0000 | ((hw & 0x3) << 21) | ((imm16 as u32) << 5) | (rd & 0x1f)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn enc_br(rn: u32) -> u32 {
        0xD61F_0000 | ((rn & 0x1f) << 5)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn emit_u32(buf: &mut Vec<u8>, word: u32) {
        buf.extend_from_slice(&word.to_le_bytes());
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn emit_load_imm64(buf: &mut Vec<u8>, rd: u32, value: u64) {
        emit_u32(buf, enc_movz_x(rd, (value & 0xffff) as u16, 0));
        emit_u32(buf, enc_movk_x(rd, ((value >> 16) & 0xffff) as u16, 16));
        emit_u32(buf, enc_movk_x(rd, ((value >> 32) & 0xffff) as u16, 32));
        emit_u32(buf, enc_movk_x(rd, ((value >> 48) & 0xffff) as u16, 48));
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[inline(always)]
    fn current_sp() -> u64 {
        let sp: u64;
        unsafe {
            std::arch::asm!("mov {out}, sp", out = out(reg) sp);
        }
        sp
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    extern "C" fn continuation(a: u64, b: u64) -> u64 {
        a + b
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    static TRAP_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    extern "C" fn trap_resume_handler(
        _sig: std::os::raw::c_int,
        _info: *mut libc::siginfo_t,
        uctx: *mut std::ffi::c_void,
    ) {
        use std::sync::atomic::Ordering;
        if !TRAP_ACTIVE.load(Ordering::SeqCst) {
            return;
        }
        let _ = unsafe { libc::write(2, b"trap_resume_handler\n".as_ptr().cast(), 20) };

        let uc = unsafe { &mut *(uctx as *mut libc::ucontext_t) };
        let original_regs = uc.uc_mcontext.regs;
        let ctx_ptr = original_regs[27] as *const JitContext;
        let out_ptr = original_regs[28] as *const AeonDynRuntimeResult;
        if ctx_ptr.is_null() || out_ptr.is_null() {
            return;
        }
        let ctx = unsafe { &*ctx_ptr };
        let out = unsafe { &*out_ptr };

        for i in 0..19 {
            uc.uc_mcontext.regs[i] = ctx.x[i];
        }
        for i in 19..30 {
            uc.uc_mcontext.regs[i] = original_regs[i];
        }
        uc.uc_mcontext.regs[30] = original_regs[26];
        uc.uc_mcontext.sp = ctx.sp;
        uc.uc_mcontext.pc = out.final_pc;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    struct SigtrapGuard {
        old: libc::sigaction,
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    impl SigtrapGuard {
        fn install() -> Self {
            let mut new_action =
                unsafe { std::mem::MaybeUninit::<libc::sigaction>::zeroed().assume_init() };
            let mut old_action =
                unsafe { std::mem::MaybeUninit::<libc::sigaction>::zeroed().assume_init() };
            new_action.sa_sigaction = trap_resume_handler as *const () as usize;
            new_action.sa_flags = libc::SA_SIGINFO;
            unsafe {
                libc::sigemptyset(&mut new_action.sa_mask);
                let rc = libc::sigaction(libc::SIGTRAP, &new_action, &mut old_action);
                assert_eq!(rc, 0, "sigaction install");
            }
            Self { old: old_action }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    impl Drop for SigtrapGuard {
        fn drop(&mut self) {
            unsafe {
                libc::sigaction(libc::SIGTRAP, &self.old, std::ptr::null_mut());
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[test]
    #[ignore = "verified by external C harness; normal Rust return path after resume is not ABI-clean yet"]
    fn aarch64_resume_trampoline_runs_runtime_then_resumes_at_continuation() {
        let _sigtrap = SigtrapGuard::install();

        let continuation_addr = continuation as *const () as u64;
        let mut code = Vec::new();
        emit_u32(&mut code, enc_movz_x(0, 0x11, 0));
        emit_u32(&mut code, enc_movz_x(1, 0x22, 0));
        emit_load_imm64(&mut code, 16, continuation_addr);
        emit_u32(&mut code, enc_br(16));
        let boxed = code.into_boxed_slice();
        let source_base = boxed.as_ptr() as u64;
        let source_size = boxed.len();

        let handle = aeon_dyn_runtime_create(source_base, source_size);
        assert!(!handle.is_null(), "runtime handle");

        let mut ctx = JitContext::default();
        ctx.pc = source_base;
        ctx.sp = current_sp();

        let mut out = AeonDynRuntimeResult::default();
        eprintln!("before direct run_out");
        let direct_stop = unsafe { aeon_dyn_runtime_run_out(handle, &mut ctx, &mut out) };
        eprintln!(
            "after direct run_out stop={} final_pc=0x{:x} x0=0x{:x} x1=0x{:x}",
            direct_stop, out.final_pc, ctx.x[0], ctx.x[1]
        );
        assert_eq!(direct_stop, STOP_CODE_RANGE_EXIT);
        ctx.pc = source_base;
        ctx.x[0] = 0;
        ctx.x[1] = 0;
        ctx.sp = current_sp();
        out = AeonDynRuntimeResult::default();

        eprintln!("before trampoline");
        TRAP_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
        let ret = unsafe { aeon_dyn_runtime_resume_trampoline(handle, &mut ctx, &mut out) };
        TRAP_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
        eprintln!("after trampoline ret=0x{ret:x}");

        unsafe { aeon_dyn_runtime_destroy(handle) };
        drop(boxed);

        assert_eq!(ret, 0x33);
        assert_eq!(out.stop_code, STOP_CODE_RANGE_EXIT);
        assert_eq!(out.steps, 1);
        assert_eq!(ctx.x[0], 0x11);
        assert_eq!(ctx.x[1], 0x22);
        assert_eq!(out.final_pc, continuation_addr);
    }
}
