use crate::{
    BlockEnterCallback, BranchBridgeCallback, BranchTranslateCallback, JitContext,
    MemoryReadCallback, MemoryWriteCallback,
};
use half::f16;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

pub(crate) static MEMORY_READ_CALLBACK: AtomicUsize = AtomicUsize::new(0);
pub(crate) static MEMORY_WRITE_CALLBACK: AtomicUsize = AtomicUsize::new(0);
pub(crate) static BRANCH_TRANSLATE_CALLBACK: AtomicUsize = AtomicUsize::new(0);
pub(crate) static BRANCH_BRIDGE_CALLBACK: AtomicUsize = AtomicUsize::new(0);
pub(crate) static BLOCK_ENTER_CALLBACK: AtomicUsize = AtomicUsize::new(0);
pub(crate) static BLOCK_COUNTERS_PTR: AtomicPtr<u64> = AtomicPtr::new(std::ptr::null_mut());
pub(crate) static BLOCK_COUNTERS_LEN: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn native_log_path() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "/data/local/tmp/aeon_jit_native.log"
    }
    #[cfg(not(target_os = "android"))]
    {
        "/tmp/aeon_jit_native.log"
    }
}

pub(crate) fn native_log_line(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(native_log_path())
    {
        #[cfg(unix)]
        {
            let _ =
                std::fs::set_permissions(native_log_path(), std::fs::Permissions::from_mode(0o644));
        }
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
    let out = callback(ctx, target);
    native_log_line(&format!(
        "branch_bridge out ctx_pc=0x{ctx_pc:x} target=0x{target:x} out=0x{out:x}"
    ));
    out
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

pub(crate) fn unpack_f16_lanes(bytes: [u8; 16]) -> [f16; 8] {
    std::array::from_fn(|lane| {
        let offset = lane * 2;
        f16::from_bits(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
    })
}

pub(crate) fn pack_f16_lanes(values: [f16; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (lane, value) in values.into_iter().enumerate() {
        let offset = lane * 2;
        out[offset..offset + 2].copy_from_slice(&value.to_bits().to_le_bytes());
    }
    out
}

pub(crate) fn rotate_complex_pair_f16(re: f16, im: f16, rotation: u64) -> (f16, f16) {
    match rotation {
        0x0 => (re, im),
        0x5a => (-im, re),
        0xb4 => (-re, -im),
        0x10e => (im, -re),
        _ => (re, im),
    }
}
