use crate::runtime::*;
use crate::*;
use aeonil::{BranchCond, Condition, Expr, Reg, Stmt};
use half::f16;

// NOTE: Tests must be run serially with `cargo test -- --test-threads=1`
// Parallel execution causes failures due to JitCompiler not being Send/Sync.
// This is a known limitation tracked in AEON_JIT_COMPREHENSIVE_EVALUATION.md

use std::cell::RefCell;

thread_local! {
    static READ_COUNT: RefCell<usize> = RefCell::new(0);
    static WRITE_COUNT: RefCell<usize> = RefCell::new(0);
    static BRIDGE_COUNT: RefCell<usize> = RefCell::new(0);
    static LAST_READ_ADDR: RefCell<u64> = RefCell::new(0);
    static LAST_WRITE_ADDR: RefCell<u64> = RefCell::new(0);
    static LAST_WRITE_VALUE: RefCell<u64> = RefCell::new(0);
    static LAST_TRANSLATE_TARGET: RefCell<u64> = RefCell::new(0);
    static LAST_BRIDGE_TARGET: RefCell<u64> = RefCell::new(0);
    static LAST_BRIDGE_CTX_X30: RefCell<u64> = RefCell::new(0);
}

fn reset_test_statics() {
    READ_COUNT.with(|v| *v.borrow_mut() = 0);
    WRITE_COUNT.with(|v| *v.borrow_mut() = 0);
    BRIDGE_COUNT.with(|v| *v.borrow_mut() = 0);
    LAST_READ_ADDR.with(|v| *v.borrow_mut() = 0);
    LAST_WRITE_ADDR.with(|v| *v.borrow_mut() = 0);
    LAST_WRITE_VALUE.with(|v| *v.borrow_mut() = 0);
    LAST_TRANSLATE_TARGET.with(|v| *v.borrow_mut() = 0);
    LAST_BRIDGE_TARGET.with(|v| *v.borrow_mut() = 0);
    LAST_BRIDGE_CTX_X30.with(|v| *v.borrow_mut() = 0);
}

extern "C" fn test_on_memory_read(addr: u64, _size: u8) {
    READ_COUNT.with(|v| *v.borrow_mut() += 1);
    LAST_READ_ADDR.with(|v| *v.borrow_mut() = addr);
}

extern "C" fn test_on_memory_write(addr: u64, _size: u8, value: u64) {
    WRITE_COUNT.with(|v| *v.borrow_mut() += 1);
    LAST_WRITE_ADDR.with(|v| *v.borrow_mut() = addr);
    LAST_WRITE_VALUE.with(|v| *v.borrow_mut() = value);
}

extern "C" fn test_branch_translate_dynamic(target: u64) -> u64 {
    LAST_TRANSLATE_TARGET.with(|v| *v.borrow_mut() = target);
    0
}

extern "C" fn test_branch_translate_identity(target: u64) -> u64 {
    LAST_TRANSLATE_TARGET.with(|v| *v.borrow_mut() = target);
    target
}

extern "C" fn test_branch_bridge_count(_ctx: *mut JitContext, target: u64) -> u64 {
    BRIDGE_COUNT.with(|v| *v.borrow_mut() += 1);
    LAST_BRIDGE_TARGET.with(|v| *v.borrow_mut() = target);
    target
}

extern "C" fn test_branch_bridge_capture_x30(ctx: *mut JitContext, target: u64) -> u64 {
    BRIDGE_COUNT.with(|v| *v.borrow_mut() += 1);
    LAST_BRIDGE_TARGET.with(|v| *v.borrow_mut() = target);
    let x30 = unsafe { ctx.as_ref().map(|ctx| ctx.x[30]).unwrap_or(0) };
    LAST_BRIDGE_CTX_X30.with(|v| *v.borrow_mut() = x30);
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

fn reference_fcmla_8h(dst: [u16; 8], src: [u16; 8], scalar_pair: u32, rotation: u64) -> [u16; 8] {
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
    reset_test_statics();

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
    assert_eq!(READ_COUNT.with(|v| *v.borrow()), 1);
    assert_eq!(WRITE_COUNT.with(|v| *v.borrow()), 1);
    assert_eq!(
        LAST_READ_ADDR.with(|v| *v.borrow()),
        (&mut slot as *mut u64) as u64
    );
    assert_eq!(
        LAST_WRITE_ADDR.with(|v| *v.borrow()),
        (&mut slot as *mut u64) as u64
    );
    assert_eq!(LAST_WRITE_VALUE.with(|v| *v.borrow()), 12);
}

#[test]
fn branch_translate_zero_returns_raw_target_without_bridge() {
    reset_test_statics();

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
    assert_eq!(LAST_TRANSLATE_TARGET.with(|v| *v.borrow()), 0x2000);
    assert_eq!(BRIDGE_COUNT.with(|v| *v.borrow()), 0);
    assert_eq!(LAST_BRIDGE_TARGET.with(|v| *v.borrow()), 0);

    // Cleanup: clear callbacks to avoid polluting subsequent tests
    {
        let mut cleanup = JitCompiler::new(JitConfig::default());
        cleanup.set_branch_translate_callback(None);
        cleanup.set_branch_bridge_callback(None);
    }
}

#[test]
fn unresolved_branch_bridge_sees_flushed_x30() {
    reset_test_statics();

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

    assert_eq!(LAST_TRANSLATE_TARGET.with(|v| *v.borrow()), 0x7000);
    assert_eq!(BRIDGE_COUNT.with(|v| *v.borrow()), 1);
    assert_eq!(LAST_BRIDGE_TARGET.with(|v| *v.borrow()), 0x7000);
    assert_eq!(LAST_BRIDGE_CTX_X30.with(|v| *v.borrow()), 0x2000);
    assert_eq!(next, 0x2000);

    // Cleanup: clear callbacks to avoid polluting subsequent tests
    {
        let mut cleanup = JitCompiler::new(JitConfig::default());
        cleanup.set_branch_translate_callback(None);
        cleanup.set_branch_bridge_callback(None);
    }
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
    reset_test_statics();
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
        name: "msr".into(),
        operands: vec![
            Expr::Intrinsic {
                name: "nzcv".into(),
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
                name: "msr".into(),
                operands: vec![
                    Expr::Intrinsic {
                        name: "tpidr_el0".into(),
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
            name: "and".into(),
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
            name: "orr".into(),
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
            name: "eor".into(),
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
            name: "bic".into(),
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
            name: "orn".into(),
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
            name: "not".into(),
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
            name: "bsl".into(),
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
        name: "ushr.2d".into(),
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
        name: "usra.2d".into(),
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
        name: "sli.2d".into(),
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
        name: "sri.2d".into(),
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
        name: "sqshlu.2d".into(),
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
        name: "uqshl.2d".into(),
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
        name: "uxtl.8h".into(),
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
        name: "ushll2.2d".into(),
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
        name: "sqrdmlah.8h".into(),
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
        name: "sqrdmlsh.8h".into(),
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
        name: "movi.16b".into(),
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
        name: "uqrshrn2.4s".into(),
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
        name: "fmulx.2d".into(),
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
            name: "fcmla.8h".into(),
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
                name: "fcmla.8h".into(),
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
        name: "ld1.8b".into(),
        operands: vec![
            Expr::Intrinsic {
                name: "multi_reg".into(),
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
        name: "st1.8h".into(),
        operands: vec![
            Expr::Intrinsic {
                name: "multi_reg".into(),
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
        name: "mla.8h".into(),
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
        name: "mls.8h".into(),
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
        name: "umlal2.4s".into(),
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
        name: "umlsl2.4s".into(),
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
            name: "frintz".into(),
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
            name: "frintm".into(),
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
            name: "frintp".into(),
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
            name: "fnmadd".into(),
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
            name: "fnmsub".into(),
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
            name: "rev16".into(),
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
            name: "rev32".into(),
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
            name: "cnt".into(),
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
                name: "movk".into(),
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
        name: "ubfx".into(),
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
        name: "sbfx".into(),
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
        name: "extr".into(),
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
    reset_test_statics();
    // equal
    assert_eq!(branch_result(Condition::EQ, 5, 5), 0x2000);
    assert_eq!(branch_result(Condition::NE, 5, 5), 0x1004);
    // not equal
    assert_eq!(branch_result(Condition::EQ, 5, 3), 0x1004);
    assert_eq!(branch_result(Condition::NE, 5, 3), 0x2000);
}

#[test]
fn flag_cond_cs_cc_unsigned_carry() {
    reset_test_statics();
    // 5 - 3 = 2 → carry set (no borrow)
    assert_eq!(branch_result(Condition::CS, 5, 3), 0x2000);
    assert_eq!(branch_result(Condition::CC, 5, 3), 0x1004);
    // 3 - 5 → borrow → carry clear
    assert_eq!(branch_result(Condition::CS, 3, 5), 0x1004);
    assert_eq!(branch_result(Condition::CC, 3, 5), 0x2000);
}

#[test]
fn flag_cond_mi_pl_negative() {
    reset_test_statics();
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
    reset_test_statics();
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
    reset_test_statics();
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
    reset_test_statics();
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
    reset_test_statics();
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
        name: "ubfiz".into(),
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
        name: "sbfiz".into(),
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
        name: "bfi".into(),
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
        name: "bfxil".into(),
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
            name: "ucvtf.2d".into(),
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
            name: "fcvtzu.2d".into(),
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
        name: "umull2.4s".into(),
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
                name: "adc".into(),
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
                name: "sbc".into(),
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
            name: "umulh".into(),
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
            name: "smulh".into(),
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
                name: "ngc".into(),
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

// ── Error Path Tests ──────────────────────────────────────────────

#[test]
fn compile_block_rejects_invalid_memory_size_zero() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let err = compiler
        .compile_block(
            0x1000,
            &[Stmt::Store {
                addr: Expr::Reg(Reg::X(0)),
                value: Expr::Reg(Reg::X(1)),
                size: 0, // Invalid: zero size
            }],
        )
        .expect_err("zero-byte store should fail");
    assert!(matches!(err, JitError::InvalidMemorySize(0)));
}

#[test]
fn compile_block_rejects_invalid_memory_size_non_power_of_two() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let err = compiler
        .compile_block(
            0x1000,
            &[Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Load {
                    addr: Box::new(Expr::Reg(Reg::X(1))),
                    size: 3, // Invalid: not power of 2
                },
            }],
        )
        .expect_err("3-byte load should fail");
    assert!(matches!(err, JitError::InvalidMemorySize(3)));
}

#[test]
fn compile_block_rejects_invalid_memory_size_too_large() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let err = compiler
        .compile_block(
            0x1000,
            &[Stmt::Store {
                addr: Expr::Reg(Reg::X(0)),
                value: Expr::Reg(Reg::X(1)),
                size: 32, // Invalid: too large (16 is I8X16, but 32 is not supported)
            }],
        )
        .expect_err("32-byte store should fail");
    assert!(matches!(err, JitError::InvalidMemorySize(32)));
}

#[test]
fn compile_block_handles_large_immediate_values() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let large_imm = 0xDEADBEEFCAFEBABE_u64;
    let code = compiler
        .compile_block(
            0x1000,
            &[Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(large_imm),
            }],
        )
        .expect("large immediate should compile");

    let func: JitEntry = unsafe { std::mem::transmute(code) };
    let mut ctx = JitContext::default();
    unsafe { func(&mut ctx) };
    assert_eq!(
        ctx.x[0], large_imm,
        "large immediate should be loaded correctly"
    );
}

#[test]
fn compile_block_handles_maximum_imm64() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let max_imm = u64::MAX;
    let code = compiler
        .compile_block(
            0x1000,
            &[Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(max_imm),
            }],
        )
        .expect("max u64 immediate should compile");

    let func: JitEntry = unsafe { std::mem::transmute(code) };
    let mut ctx = JitContext::default();
    unsafe { func(&mut ctx) };
    assert_eq!(ctx.x[0], max_imm);
}

#[test]
fn compile_block_handles_deep_expression_nesting() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    // (((1 + 2) + 3) + 4) + 5
    let code = compiler
        .compile_block(
            0x1000,
            &[Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Add(
                    Box::new(Expr::Add(
                        Box::new(Expr::Add(
                            Box::new(Expr::Add(Box::new(Expr::Imm(1)), Box::new(Expr::Imm(2)))),
                            Box::new(Expr::Imm(3)),
                        )),
                        Box::new(Expr::Imm(4)),
                    )),
                    Box::new(Expr::Imm(5)),
                ),
            }],
        )
        .expect("deeply nested expression should compile");

    let func: JitEntry = unsafe { std::mem::transmute(code) };
    let mut ctx = JitContext::default();
    unsafe { func(&mut ctx) };
    assert_eq!(ctx.x[0], 15, "nested addition should evaluate correctly");
}

#[test]
fn compile_block_handles_all_gpr_registers() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let mut stmts = Vec::new();

    // Initialize each GPR
    for i in 0..31 {
        stmts.push(Stmt::Assign {
            dst: Reg::X(i),
            src: Expr::Imm((i as u64) * 100),
        });
    }

    let code = compiler
        .compile_block(0x1000, &stmts)
        .expect("all GPR assignments should compile");

    let func: JitEntry = unsafe { std::mem::transmute(code) };
    let mut ctx = JitContext::default();
    unsafe { func(&mut ctx) };

    for i in 0..31 {
        assert_eq!(
            ctx.x[i],
            (i as u64) * 100,
            "register x{} should have correct value",
            i
        );
    }
}

#[test]
fn compile_block_handles_all_simd_registers() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let mut stmts = Vec::new();

    // Perform operations on SIMD registers (AND with themselves, which is supported)
    for i in 0..32 {
        stmts.push(Stmt::Assign {
            dst: Reg::V(i),
            src: Expr::Intrinsic {
                name: "and".into(),
                operands: vec![Expr::Reg(Reg::V(i)), Expr::Reg(Reg::V(i))],
            },
        });
    }

    let code = compiler
        .compile_block(0x1000, &stmts)
        .expect("all SIMD register operations should compile");

    let func: JitEntry = unsafe { std::mem::transmute(code) };
    let mut ctx = JitContext::default();
    unsafe { func(&mut ctx) };

    // Test passed - all SIMD operations were compiled and executed
}

#[test]
fn compile_block_rejects_unsupported_barrier_kind() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let err = compiler
        .compile_block(
            0x1000,
            &[Stmt::Barrier("isb_completely_custom".to_string())],
        )
        .expect_err("unsupported barrier should fail");
    assert!(matches!(err, JitError::UnsupportedStmt("barrier")));
}

#[test]
fn compile_block_compiles_call_to_immediate() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let code = compiler
        .compile_block(
            0x1000,
            &[Stmt::Call {
                target: Expr::Imm(0x4000),
            }],
        )
        .expect("call to immediate should compile");

    // Just verify it compiled - code is a raw pointer
    assert!(!code.is_null(), "call should produce code");
}

#[test]
fn compile_block_handles_minimum_stack_offset() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let code = compiler
        .compile_block(
            0x1000,
            &[Stmt::Store {
                addr: Expr::Reg(Reg::SP),
                value: Expr::Imm(0x1234),
                size: 8,
            }],
        )
        .expect("store at sp should compile");

    let func: JitEntry = unsafe { std::mem::transmute(code) };
    let mut ctx = JitContext::default();
    ctx.sp = 0x4000;
    let mut stack_slot = 0u64;
    unsafe {
        // Manually set sp to point to our stack location
        ctx.sp = (&mut stack_slot as *mut u64) as u64;
        func(&mut ctx);
    }
    assert_eq!(stack_slot, 0x1234, "stack write should succeed at sp");
}

#[test]
fn compile_block_handles_large_stack_offset() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    // Load from sp + 4096 (typical stack offset range)
    let code = compiler
        .compile_block(
            0x1000,
            &[Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Load {
                    addr: Box::new(Expr::Add(
                        Box::new(Expr::Reg(Reg::SP)),
                        Box::new(Expr::Imm(4096)),
                    )),
                    size: 8,
                },
            }],
        )
        .expect("load from sp + 4096 should compile");

    let func: JitEntry = unsafe { std::mem::transmute(code) };
    let mut ctx = JitContext::default();
    let mut data = [0u8; 8192];
    let test_value = 0xCAFEBABEDEADBEEF_u64;
    data[4096..4104].copy_from_slice(&test_value.to_le_bytes());

    ctx.sp = data.as_ptr() as u64;
    unsafe { func(&mut ctx) };
    assert_eq!(
        ctx.x[0], test_value,
        "should load from offset stack address"
    );
}

#[test]
fn compile_block_handles_sequential_operations() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let code = compiler
        .compile_block(
            0x1000,
            &[
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Imm(10),
                },
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: Expr::Add(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(5))),
                },
                Stmt::Assign {
                    dst: Reg::X(2),
                    src: Expr::Mul(Box::new(Expr::Reg(Reg::X(1))), Box::new(Expr::Imm(2))),
                },
            ],
        )
        .expect("sequential operations should compile");

    let func: JitEntry = unsafe { std::mem::transmute(code) };
    let mut ctx = JitContext::default();
    unsafe { func(&mut ctx) };
    assert_eq!(ctx.x[0], 10);
    assert_eq!(ctx.x[1], 15);
    assert_eq!(
        ctx.x[2], 30,
        "sequential operations should produce correct result"
    );
}

// ── Performance Benchmarks ────────────────────────────────────

#[test]
fn benchmark_compile_small_block() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let stmts = vec![
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(42),
        },
        Stmt::Assign {
            dst: Reg::X(1),
            src: Expr::Imm(100),
        },
    ];

    let start = std::time::Instant::now();
    let code = compiler
        .compile_block(0x1000, &stmts)
        .expect("compile should succeed");
    let elapsed = start.elapsed();

    assert!(!code.is_null(), "code should be generated");
    println!(
        "Small block (2 stmts) compiled in {:.2?} ({} µs)",
        elapsed,
        elapsed.as_micros()
    );
    // Expect compilation < 10ms for small block
    assert!(
        elapsed.as_millis() < 10,
        "small block should compile quickly (< 10ms), took {:.2?}",
        elapsed
    );
}

#[test]
fn benchmark_compile_medium_block() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let mut stmts = Vec::new();

    // Generate 50 sequential assignment statements
    for i in 0..50 {
        stmts.push(Stmt::Assign {
            dst: Reg::X(i % 31),
            src: Expr::Imm((i as u64) * 10),
        });
    }

    let start = std::time::Instant::now();
    let code = compiler
        .compile_block(0x1000, &stmts)
        .expect("compile should succeed");
    let elapsed = start.elapsed();

    assert!(!code.is_null(), "code should be generated");
    println!(
        "Medium block (50 stmts) compiled in {:.2?} ({} µs)",
        elapsed,
        elapsed.as_micros()
    );
    // Expect compilation < 50ms for medium block
    assert!(
        elapsed.as_millis() < 50,
        "medium block should compile reasonably (< 50ms), took {:.2?}",
        elapsed
    );
}

#[test]
fn benchmark_compile_complex_block_with_branches() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let stmts = vec![
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(100),
        },
        Stmt::Assign {
            dst: Reg::X(1),
            src: Expr::Imm(50),
        },
        Stmt::SetFlags {
            expr: Expr::Sub(
                Box::new(Expr::Reg(Reg::X(0))),
                Box::new(Expr::Reg(Reg::X(1))),
            ),
        },
        Stmt::CondBranch {
            cond: BranchCond::Flag(Condition::GT),
            target: Expr::Imm(0x2000),
            fallthrough: 0x1010,
        },
    ];

    let start = std::time::Instant::now();
    let code = compiler
        .compile_block(0x1000, &stmts)
        .expect("compile should succeed");
    let elapsed = start.elapsed();

    assert!(!code.is_null(), "code should be generated");
    println!(
        "Complex block (branches, flags) compiled in {:.2?}",
        elapsed
    );
    assert!(
        elapsed.as_millis() < 20,
        "complex block should compile quickly (< 20ms), took {:.2?}",
        elapsed
    );
}

#[test]
fn benchmark_compile_simd_heavy_block() {
    let mut compiler = JitCompiler::new(JitConfig::default());
    let mut stmts = Vec::new();

    // Generate SIMD operations on all 32 SIMD registers
    for i in 0..32 {
        stmts.push(Stmt::Assign {
            dst: Reg::V(i),
            src: Expr::Intrinsic {
                name: "and".into(),
                operands: vec![Expr::Reg(Reg::V(i)), Expr::Reg(Reg::V((i + 1) % 32))],
            },
        });
    }

    let start = std::time::Instant::now();
    let code = compiler
        .compile_block(0x1000, &stmts)
        .expect("compile should succeed");
    let elapsed = start.elapsed();

    assert!(!code.is_null(), "code should be generated");
    println!("SIMD-heavy block (32 stmts) compiled in {:.2?}", elapsed);
    assert!(
        elapsed.as_millis() < 100,
        "SIMD block should compile within 100ms, took {:.2?}",
        elapsed
    );
}

#[test]
fn benchmark_code_generation_efficiency() {
    let mut compiler = JitCompiler::new(JitConfig::default());

    // Simple block with just a few operations
    let stmts = vec![
        Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(0xDEADBEEFCAFEBABE_u64),
        },
        Stmt::Assign {
            dst: Reg::X(1),
            src: Expr::Reg(Reg::X(0)),
        },
    ];

    let code = compiler
        .compile_block(0x1000, &stmts)
        .expect("compile should succeed");

    // Code should be a valid pointer
    assert!(!code.is_null());

    // Execute and verify correctness
    let func: JitEntry = unsafe { std::mem::transmute(code) };
    let mut ctx = JitContext::default();
    unsafe { func(&mut ctx) };

    assert_eq!(ctx.x[0], 0xDEADBEEFCAFEBABE_u64);
    assert_eq!(ctx.x[1], 0xDEADBEEFCAFEBABE_u64);

    println!("Code generation produces correct executable output");
}

#[test]
fn benchmark_multiple_blocks_same_compiler() {
    let mut compiler = JitCompiler::new(JitConfig::default());

    let start = std::time::Instant::now();

    // Compile 10 different blocks
    for i in 0..10 {
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(i as u64),
        }];

        let code = compiler
            .compile_block(0x1000 + i * 0x100, &stmts)
            .expect("compile should succeed");
        assert!(!code.is_null());
    }

    let elapsed = start.elapsed();

    println!(
        "Compiled 10 blocks sequentially in {:.2?} (avg {:.2?} per block)",
        elapsed,
        elapsed / 10
    );

    // 10 blocks should compile in < 100ms
    assert!(
        elapsed.as_millis() < 100,
        "10 blocks should compile within 100ms, took {:.2?}",
        elapsed
    );
}

#[test]
fn benchmark_memory_usage_estimation() {
    // Create a JitContext and measure its size
    let ctx = JitContext::default();
    let ctx_size = std::mem::size_of_val(&ctx);

    println!(
        "JitContext size: {} bytes ({:.2} KB)",
        ctx_size,
        ctx_size as f64 / 1024.0
    );

    // Expected: ~792 bytes (31 GPR x 8 + 32 SIMD x 16 + flags + pc + sp + padding)
    assert!(
        ctx_size > 700 && ctx_size < 900,
        "JitContext should be ~792 bytes"
    );

    // Create a JitCompiler and verify it's reasonable
    let compiler = JitCompiler::new(JitConfig::default());
    let compiler_size = std::mem::size_of_val(&compiler);

    println!(
        "JitCompiler size: {} bytes ({:.2} KB)",
        compiler_size,
        compiler_size as f64 / 1024.0
    );

    // JitCompiler should be < 10KB (contains Cranelift module + builder context)
    assert!(
        compiler_size < 10_000,
        "JitCompiler should be < 10KB, is {} bytes",
        compiler_size
    );
}
