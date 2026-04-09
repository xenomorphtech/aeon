use aeon_jit::{JitCompiler, JitConfig, JitContext};
use aeonil::{Expr, Reg, Stmt};
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::atomic::{AtomicUsize, Ordering};

static EXPECTED_BRIDGE_TARGET: AtomicUsize = AtomicUsize::new(0);

static PRINTF_FMT: &[u8] = b"bridged printf [%s] %d 0x%llx %c %u\n\0";
static PRINTF_STR: &[u8] = b"ok\0";

unsafe extern "C" {
    fn printf(format: *const c_char, ...) -> c_int;
}

extern "C" fn test_branch_bridge(ctx: *mut JitContext, target: u64) -> u64 {
    let expected = EXPECTED_BRIDGE_TARGET.load(Ordering::SeqCst) as u64;
    if target != expected {
        return target;
    }
    let ctx = unsafe { &mut *ctx };
    let fmt = ctx.x[0] as *const c_char;
    let arg1 = ctx.x[1] as *const c_char;
    let arg2 = ctx.x[2] as c_int;
    let arg3 = ctx.x[3] as u64;
    let arg4 = ctx.x[4] as c_int;
    let arg5 = ctx.x[5] as c_uint;
    let printed = unsafe { printf(fmt, arg1, arg2, arg3, arg4, arg5) };
    ctx.x[0] = printed as u64;
    0
}

fn main() {
    let printf_target = printf as *const () as usize;
    EXPECTED_BRIDGE_TARGET.store(printf_target, Ordering::SeqCst);

    let mut compiler = JitCompiler::new(JitConfig::default());
    compiler.set_branch_bridge_callback(Some(test_branch_bridge));

    let caller = vec![
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(PRINTF_FMT.as_ptr() as u64),
        },
        Stmt::Assign {
            dst: Reg::X(1),
            src: Expr::Imm(PRINTF_STR.as_ptr() as u64),
        },
        Stmt::Assign {
            dst: Reg::X(2),
            src: Expr::Imm((-7i64) as u64),
        },
        Stmt::Assign {
            dst: Reg::X(3),
            src: Expr::Imm(0x1234_abcd),
        },
        Stmt::Assign {
            dst: Reg::X(4),
            src: Expr::Imm('Z' as u64),
        },
        Stmt::Assign {
            dst: Reg::X(5),
            src: Expr::Imm(99),
        },
        Stmt::Assign {
            dst: Reg::X(30),
            src: Expr::Imm(printf_target as u64),
        },
        Stmt::Call {
            target: Expr::Reg(Reg::X(30)),
        },
        Stmt::Ret,
    ];

    let code = compiler.compile_block(0x3000, &caller).expect("compile");
    let bytes = unsafe { std::slice::from_raw_parts(code, 192) };
    let out = "/tmp/aeon_printf_bridge_block.bin";
    std::fs::write(out, bytes).expect("write block bytes");
    println!("code_ptr=0x{:x}", code as usize);
    println!("raw_bin={out}");
}
