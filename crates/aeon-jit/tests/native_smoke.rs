use aeon_jit::{JitCompiler, JitConfig, JitContext, JitEntry};
use aeonil::{Expr, Reg, Stmt};
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static EXPECTED_BRIDGE_TARGET: AtomicUsize = AtomicUsize::new(0);
static BRIDGE_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);

static PRINTF_FMT: &[u8] = b"bridged printf [%s] %d 0x%llx %c %u\n\0";
static PRINTF_STR: &[u8] = b"ok\0";

unsafe extern "C" {
    fn printf(format: *const c_char, ...) -> c_int;
}

fn test_lock() -> &'static Mutex<()> {
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

extern "C" fn test_branch_bridge(ctx: *mut JitContext, target: u64) -> u64 {
    let expected = EXPECTED_BRIDGE_TARGET.load(Ordering::SeqCst) as u64;
    if target != expected {
        return target;
    }
    BRIDGE_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
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

fn capture_stdout<F: FnOnce()>(f: F) -> String {
    unsafe {
        let mut pipe_fds = [0; 2];
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0, "pipe");
        let saved_stdout = libc::dup(libc::STDOUT_FILENO);
        assert!(saved_stdout >= 0, "dup stdout");
        assert_eq!(
            libc::dup2(pipe_fds[1], libc::STDOUT_FILENO),
            libc::STDOUT_FILENO,
            "dup2 stdout"
        );
        libc::close(pipe_fds[1]);

        f();
        libc::fflush(std::ptr::null_mut());

        assert_eq!(
            libc::dup2(saved_stdout, libc::STDOUT_FILENO),
            libc::STDOUT_FILENO,
            "restore stdout"
        );
        libc::close(saved_stdout);

        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let read = libc::read(pipe_fds[0], buf.as_mut_ptr().cast(), buf.len());
            assert!(read >= 0, "read pipe");
            if read == 0 {
                break;
            }
            out.extend_from_slice(&buf[..read as usize]);
        }
        libc::close(pipe_fds[0]);
        String::from_utf8(out).expect("utf8 stdout")
    }
}

#[test]
fn native_jit_executes_two_block_chain() {
    let _guard = test_lock().lock().unwrap();
    let mut compiler = JitCompiler::new(JitConfig::default());

    let block1 = vec![
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(41),
        },
        Stmt::Branch {
            target: Expr::Imm(0x2000),
        },
    ];
    let block2 = vec![
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Add(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(1))),
        },
        Stmt::Ret,
    ];

    let code1 = compiler
        .compile_block(0x1000, &block1)
        .expect("compile block1");
    let code2 = compiler
        .compile_block(0x2000, &block2)
        .expect("compile block2");

    let entry1: JitEntry = unsafe { std::mem::transmute(code1) };
    let entry2: JitEntry = unsafe { std::mem::transmute(code2) };

    let mut ctx = JitContext::default();

    let next = unsafe { entry1(&mut ctx) };
    assert_eq!(next, 0x2000);
    assert_eq!(ctx.x[0], 41);

    let next = unsafe { entry2(&mut ctx) };
    assert_eq!(next, 0);
    assert_eq!(ctx.x[0], 42);
}

#[test]
fn native_jit_indirect_call_via_x30_invokes_callee() {
    let _guard = test_lock().lock().unwrap();
    let mut compiler = JitCompiler::new(JitConfig::default());

    let callee = vec![
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Add(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(1))),
        },
        Stmt::Ret,
    ];
    let callee_code = compiler
        .compile_block(0x2000, &callee)
        .expect("compile callee");
    let callee_ptr = callee_code as u64;

    let caller = vec![
        Stmt::Assign {
            dst: Reg::X(30),
            src: Expr::Imm(callee_ptr),
        },
        Stmt::Call {
            target: Expr::Reg(Reg::X(30)),
        },
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Add(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(41))),
        },
        Stmt::Ret,
    ];
    let caller_code = compiler
        .compile_block(0x1000, &caller)
        .expect("compile caller");
    let entry: JitEntry = unsafe { std::mem::transmute(caller_code) };

    let mut ctx = JitContext::default();
    let next = unsafe { entry(&mut ctx) };
    assert_eq!(next, 0);
    assert_eq!(ctx.x[0], 42);
}

#[test]
fn native_jit_indirect_call_via_x30_bridges_to_printf() {
    let _guard = test_lock().lock().unwrap();
    let printf_target = printf as *const () as usize;
    EXPECTED_BRIDGE_TARGET.store(printf_target, Ordering::SeqCst);
    BRIDGE_CALL_COUNT.store(0, Ordering::SeqCst);

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
    let caller_code = compiler
        .compile_block(0x3000, &caller)
        .expect("compile caller");

    let entry: JitEntry = unsafe { std::mem::transmute(caller_code) };
    let mut ctx = JitContext::default();
    let out = capture_stdout(|| {
        let next = unsafe { entry(&mut ctx) };
        assert_eq!(next, 0);
    });
    compiler.set_branch_bridge_callback(None);
    EXPECTED_BRIDGE_TARGET.store(0, Ordering::SeqCst);
    assert_eq!(BRIDGE_CALL_COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(out, "bridged printf [ok] -7 0x1234abcd Z 99\n");
    assert_eq!(ctx.x[0] as usize, out.len());
}
