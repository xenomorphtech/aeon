#!/usr/bin/env python3
"""Regenerate cases.rs for the differential test.

Each case is a straight-line AArch64 snippet: no branches, no memory access.
x0-x7 are inputs seeded by the harness; write results to any register.

Usage (needs aarch64-linux-gnu binutils):
    python3 crates/aeon-jit/tests/differential/gen_cases.py
"""
import pathlib
import struct
import subprocess
import tempfile

def simd(asm: str) -> tuple[str, str]:
    return (asm, asm)


CASES = [
    # ── integer arithmetic ─────────────────────────────────────────────
    ("add_sub_reg", "add x8, x0, x1; sub x9, x0, x1; add w10, w2, w3; sub w11, w2, w3"),
    ("add_sub_imm", "add x8, x0, #0xfff; sub x9, x1, #1, lsl #12; add w10, w2, #7; sub w11, w3, #0x123"),
    ("add_sub_shifted", "add x8, x0, x1, lsl #3; sub x9, x0, x1, lsr #7; add x10, x2, x3, asr #63; add w11, w2, w3, lsl #31"),
    ("add_sub_extended", "add x8, x0, w1, uxtb; add x9, x0, w1, sxth #2; sub x10, x2, w3, sxtw; add x11, x2, w3, uxtw #3"),
    ("neg", "neg x8, x0; neg w9, w1; neg x10, x2, lsl #4"),
    ("mul_family", "mul x8, x0, x1; mul w9, w2, w3; madd x10, x0, x1, x2; msub x11, x0, x1, x2; mneg x12, x3, x4"),
    ("mul_widening", "smull x8, w0, w1; umull x9, w0, w1; smaddl x10, w2, w3, x4; umsubl x11, w2, w3, x4"),
    ("mul_high", "smulh x8, x0, x1; umulh x9, x0, x1; smulh x10, x2, x3; umulh x11, x4, x5"),
    ("div", "sdiv x8, x0, x1; udiv x9, x0, x1; sdiv w10, w2, w3; udiv w11, w2, w3"),
    ("div_by_zero", "mov x1, #0; sdiv x8, x0, x1; udiv x9, x0, x1; sdiv w10, w2, w1; udiv w11, w2, w1"),
    ("div_overflow", "mov x0, #0x8000000000000000; mov x1, #-1; sdiv x8, x0, x1; mov w2, #0x80000000; sdiv w9, w2, w1"),
    # ── flags ──────────────────────────────────────────────────────────
    ("adds_flags", "adds x8, x0, x1; cset x9, cs; cset x10, vs; cset x11, mi; cset x12, eq"),
    ("subs_flags", "subs x8, x0, x1; cset x9, cs; cset x10, vs; cset x11, mi; cset x12, eq"),
    ("adds_w_flags", "adds w8, w0, w1; cset x9, cs; cset x10, vs; cset x11, mi; cset x12, eq"),
    ("subs_w_flags", "subs w8, w0, w1; cset x9, cs; cset x10, vs; cset x11, mi; cset x12, eq"),
    ("cmp_conditions", "cmp x0, x1; cset x8, hi; cset x9, ls; cset x10, ge; cset x11, lt; cset x12, gt; cset x13, le; cset x14, ne"),
    ("cmp_w_conditions", "cmp w0, w1; cset x8, hi; cset x9, ls; cset x10, ge; cset x11, lt; cset x12, gt; cset x13, le"),
    ("cmp_imm", "cmp x0, #0; cset x8, eq; cmp w1, #0xfff; cset x9, lo; cmn x2, #1; cset x10, eq; cset x11, cs"),
    ("cmn", "cmn x0, x1; cset x8, cs; cset x9, vs; cmn w2, w3; cset x10, mi; cset x11, eq"),
    ("tst_ands", "tst x0, x1; cset x8, eq; cset x9, mi; ands w10, w2, w3; cset x11, eq; cset x12, mi"),
    ("bics", "bics x8, x0, x1; cset x9, eq; cset x10, mi; bics w11, w2, w3; cset x12, eq"),
    ("negs", "negs x8, x0; cset x9, cs; cset x10, vs; negs w11, w1; cset x12, eq; cset x13, mi"),
    ("adc_sbc", "cmp x0, x1; adc x8, x2, x3; sbc x9, x2, x3; adc w10, w4, w5; sbc w11, w4, w5; ngc x12, x6"),
    ("adcs_sbcs", "cmp x0, x1; adcs x8, x2, x3; cset x9, cs; cset x10, vs; sbcs x11, x4, x5; cset x12, cs; cset x13, vs"),
    ("ccmp", "cmp x0, x1; ccmp x2, x3, #0x4, ne; cset x8, eq; cset x9, hi; ccmp w4, w5, #0xb, lt; cset x10, mi; cset x11, vs"),
    ("ccmn", "cmp x0, x1; ccmn x2, x3, #0x2, hs; cset x8, eq; cset x9, cs; ccmn x4, #5, #0x8, lt; cset x10, mi"),
    ("csel_family", "cmp x0, x1; csel x8, x2, x3, lt; csinc x9, x2, x3, hs; csinv x10, x4, x5, eq; csneg x11, x4, x5, gt; csetm x12, lo; cinc x13, x6, mi"),
    ("csel_w", "cmp w0, w1; csel w8, w2, w3, ge; csinc w9, w2, w3, lo; csinv w10, w4, w5, ne; csneg w11, w4, w5, le"),
    # ── logic and shifts ───────────────────────────────────────────────
    ("logic_reg", "and x8, x0, x1; orr x9, x0, x1; eor x10, x0, x1; bic x11, x2, x3; orn x12, x2, x3; eon x13, x4, x5; mvn x14, x6"),
    ("logic_w", "and w8, w0, w1; orr w9, w0, w1; eor w10, w0, w1; bic w11, w2, w3; orn w12, w2, w3; eon w13, w4, w5; mvn w14, w6"),
    ("logic_imm", "and x8, x0, #0xff00ff00ff00ff00; orr x9, x1, #0x5555555555555555; eor x10, x2, #0xfffffffffffffffe; and w11, w3, #0x0ff00ff0"),
    ("logic_shifted", "and x8, x0, x1, lsl #5; orr x9, x0, x1, lsr #60; eor x10, x2, x3, asr #17; bic x11, x2, x3, ror #9; orr w12, w4, w5, ror #31"),
    ("shift_imm", "lsl x8, x0, #1; lsr x9, x0, #63; asr x10, x1, #17; ror x11, x1, #40; lsl w12, w2, #31; lsr w13, w2, #5; asr w14, w3, #31; ror w15, w3, #3"),
    ("shift_reg", "lsl x8, x0, x1; lsr x9, x0, x1; asr x10, x2, x3; ror x11, x2, x3; lsl w12, w4, w5; lsr w13, w4, w5; asr w14, w6, w7; ror w15, w6, w7"),
    # ── bitfield and extension ─────────────────────────────────────────
    ("bitfield_extract", "ubfx x8, x0, #5, #17; sbfx x9, x0, #5, #17; ubfx w10, w1, #30, #2; sbfx w11, w1, #0, #1; ubfx x12, x2, #63, #1"),
    ("bitfield_insert_zero", "ubfiz x8, x0, #9, #20; sbfiz x9, x0, #9, #20; ubfiz w10, w1, #31, #1; sbfiz w11, w1, #3, #8"),
    ("bitfield_insert", "mov x8, x2; bfi x8, x0, #12, #24; mov x9, x3; bfxil x9, x1, #40, #20; mov w10, w4; bfi w10, w5, #1, #30"),
    ("extr", "extr x8, x0, x1, #13; extr w9, w2, w3, #31; extr x10, x4, x5, #63"),
    ("extend", "sxtb x8, w0; sxth x9, w0; sxtw x10, w0; uxtb w11, w1; uxth w12, w1; sxtb w13, w2; sxth w14, w2"),
    # ── moves ──────────────────────────────────────────────────────────
    ("mov_wide", "movz x8, #0x1234, lsl #48; movn x9, #0x5678, lsl #16; movz w10, #0xffff, lsl #16; movn w11, #0"),
    ("movk_chain", "movz x8, #0x1111; movk x8, #0x2222, lsl #16; movk x8, #0x3333, lsl #32; movk x8, #0x4444, lsl #48; mov x9, x0; movk x9, #0xbeef, lsl #16; mov w10, w1; movk w10, #0xdead, lsl #16"),
    ("movk_zero", "mov x8, x0; movk x8, #0, lsl #16; mov x9, x1; movk x9, #0, lsl #48; mov w10, w2; movk w10, #0"),
    ("mov_w_zero_extends", "mov w8, w0; orr w9, wzr, w1; add w10, w2, #0; mov x11, x3"),
    # ── bit manipulation ───────────────────────────────────────────────
    ("clz_cls", "clz x8, x0; clz w9, w1; cls x10, x2; cls w11, w3"),
    ("rbit_rev", "rbit x8, x0; rbit w9, w1; rev x10, x2; rev w11, w3; rev16 x12, x4; rev16 w13, w5; rev32 x14, x6"),
    ("crc32", "crc32b w8, w0, w1; crc32h w9, w0, w1; crc32w w10, w2, w3; crc32x w11, w2, x3; crc32cb w12, w4, w5; crc32cx w13, w6, x7"),
    # ── scalar floating point, observed through integer registers ──────
    ("fp_convert", "scvtf d0, x0; ucvtf d1, x1; fadd d2, d0, d1; fcvtzs x8, d2; fmov x9, d2; scvtf s3, w2; fmov w10, s3"),
    ("fp_arith", "scvtf d0, x0; scvtf d1, x1; fmul d2, d0, d1; fsub d3, d2, d0; fdiv d4, d3, d1; fmov x8, d2; fmov x9, d3; fmov x10, d4"),
    ("fp_compare", "scvtf d0, x0; scvtf d1, x1; fcmp d0, d1; cset x8, mi; cset x9, eq; cset x10, gt; cset x11, vs"),
    ("carry_aliased", "cmp x0, x1; adcs x2, x2, x2; cset x8, cs; sbcs x3, x4, x3; cset x9, vs; ngcs x5, x5; cset x10, cs; adcs w6, w6, w7; cset x11, cs; ngc w12, w0"),
    ("fp_unsigned", "ucvtf d0, x0; fmov x8, d0; ucvtf s1, w1; fmov w9, s1; ucvtf s2, x2; fmov w10, s2; scvtf s3, x3; fmov w11, s3; ucvtf d4, w4; fmov x12, d4"),
    ("fp_to_int", "scvtf d0, x0; fmov d1, x1; fcvtzs x8, d0; fcvtzu x9, d0; fcvtzs w10, d1; fcvtzu w11, d1; fcvtzs x12, d1; fcvtzu x13, d1"),
    ("fp_to_int_rounded", "fmov d0, x0; fmov d1, x1; fcvtms x8, d0; fcvtps x9, d0; fcvtns x10, d1; fcvtmu x11, d1; fcvtpu w12, d0; fcvtnu w13, d1"),
    ("fp_single", "fmov s0, w0; fmov s1, w1; fadd s2, s0, s1; fmul s3, s0, s1; fdiv s4, s0, s1; fsub s5, s0, s1; fmov w8, s2; fmov w9, s3; fmov w10, s4; fmov w11, s5"),
    ("fp_unary", "fmov d0, x0; fneg d1, d0; fabs d2, d0; fsqrt d3, d0; fmov x8, d1; fmov x9, d2; fmov x10, d3; scvtf d4, x1; fsqrt d5, d4; fmov x11, d5"),
    ("fp_minmax", "scvtf d0, x0; scvtf d1, x1; fmax d2, d0, d1; fmin d3, d0, d1; fmov x8, d2; fmov x9, d3; fmov d4, x2; fmax d5, d4, d0; fmov x10, d5"),
    ("fp_convert_width", "scvtf d0, x0; fcvt s1, d0; fmov w8, s1; fmov s2, w1; fcvt d3, s2; fmov x9, d3"),
    ("fp_compare_raw", "fmov d0, x0; fmov d1, x1; fcmp d0, d1; cset x8, mi; cset x9, eq; cset x10, hi; cset x11, vs; cset x12, lt; fcmp d0, #0.0; cset x13, ge"),
    ("fp_ccmp", "scvtf d0, x0; scvtf d1, x1; cmp x2, x3; fccmp d0, d1, #0x4, ne; cset x8, eq; cset x9, mi; cset x10, hi"),
    ("fp_imm", "fmov d0, #1.5; fmov s1, #-2.0; fmov x8, d0; fmov w9, s1; scvtf d2, x0; fadd d3, d2, d0; fmov x10, d3"),
    # ── memory: x20 points into a data region, sp is usable ────────────
    ("mem_load_sizes", "ldr x8, [x20]; ldr w9, [x20, #8]; ldrh w10, [x20, #12]; ldrb w11, [x20, #15]; ldrsw x12, [x20, #16]; ldrsh x13, [x20, #20]; ldrsb w14, [x20, #22]; ldur x15, [x20, #-7]"),
    ("mem_store_sizes", "str x0, [x20]; str w1, [x20, #8]; strh w2, [x20, #12]; strb w3, [x20, #15]; stur x4, [x20, #-9]; ldr x8, [x20, #-8]; ldr x9, [x20, #8]"),
    ("mem_pre_post_index", "mov x21, x20; ldr x8, [x21], #8; ldr x9, [x21, #8]!; str x0, [x21], #-16; str x1, [x21, #24]!; mov x10, x21"),
    ("mem_pair", "stp x0, x1, [x20]; ldp x8, x9, [x20]; stp w2, w3, [x20, #16]; ldp w10, w11, [x20, #16]; ldpsw x12, x13, [x20, #16]"),
    ("mem_pair_index", "mov x21, x20; stp x0, x1, [x21, #-16]!; ldp x8, x9, [x21], #32; stp x2, x3, [x21], #16; ldp x10, x11, [x21, #-48]!; mov x12, x21"),
    ("mem_stack_frame", "stp x29, x30, [sp, #-32]!; mov x29, sp; str x0, [sp, #16]; ldr x8, [x29, #16]; ldp x9, x10, [sp], #32"),
    ("mem_reg_offset", "and x9, x0, #0x7f8; ldr x8, [x20, x9]; and w10, w1, #0xff; ldr x11, [x20, w10, uxtw #3]; str x2, [x20, x9]; ldrb w12, [x20, x10]; and x13, x3, #0x3f; ldr w14, [x20, x13, lsl #2]"),
    ("mem_alias_base", "mov x8, x20; ldr x8, [x8]; mov x10, x20; ldp x10, x11, [x10, #16]; mov x12, x20; ldrb w12, [x12, #3]"),
    ("mem_overlap", "str x0, [x20]; strb w1, [x20, #3]; ldr x8, [x20]; str w2, [x20, #6]; ldr x9, [x20, #4]; ldrh w10, [x20, #7]"),
    ("mem_fp", "ldr d0, [x20]; ldr s1, [x20, #8]; str d0, [x20, #16]; str s1, [x20, #28]; ldr q2, [x20, #32]; str q2, [x20, #64]; stp d0, d0, [x20, #96]; ldp q3, q4, [x20, #128]"),
    ("adr", "adr x8, .; adrp x9, .; adr x10, . + 12; add x11, x9, #0x123"),
    # ── control flow inside the snippet ────────────────────────────────
    ("br_cond_fwd", "cmp x0, x1; b.lt 1f; add x8, x2, #1; b 2f; 1: sub x8, x2, #1; 2: mov x9, x8"),
    ("br_cbz", "mov x8, #0; cbz x0, 1f; add x8, x8, #1; 1: cbnz w1, 2f; add x8, x8, #2; 2: add x8, x8, #4"),
    ("br_tbz", "mov x8, #0; tbz x0, #63, 1f; orr x8, x8, #1; 1: tbnz w1, #0, 2f; orr x8, x8, #2; 2: tbz x2, #31, 3f; orr x8, x8, #4; 3: mov x9, x8"),
    ("br_loop", "and x9, x0, #0xf; mov x8, #0; 1: add x8, x8, x9; subs x9, x9, #1; b.pl 1b; mov x10, x8"),
    ("br_conditions", "cmp x0, x1; mov x8, #0; b.hi 1f; orr x8, x8, #1; 1: b.ls 2f; orr x8, x8, #2; 2: b.ge 3f; orr x8, x8, #4; 3: b.vs 4f; orr x8, x8, #8; 4: b.mi 5f; orr x8, x8, #16; 5: mov x9, x8"),
    ("br_fp_condition", "scvtf d0, x0; scvtf d1, x1; fcmp d0, d1; mov x8, #0; b.gt 1f; orr x8, x8, #1; 1: b.mi 2f; orr x8, x8, #2; 2: mov x9, x8"),
    ("br_indirect", "adr x9, 1f; br x9; mov x8, #1; 1: mov x10, #2"),
    ("br_ret", "adr x30, 1f; ret; mov x8, #1; 1: mov x10, #2"),
    # ── SIMD: one instruction per case, named by the instruction, so a
    # gap is reported for exactly the instruction that has it ───────────
    simd("and v8.16b, v0.16b, v1.16b"),
    simd("orr v9.16b, v0.16b, v1.16b"),
    simd("eor v10.16b, v2.16b, v3.16b"),
    simd("bic v11.16b, v2.16b, v3.16b"),
    simd("orn v12.16b, v4.16b, v5.16b"),
    simd("mvn v13.16b, v6.16b"),
    simd("bsl v0.16b, v1.16b, v2.16b"),
    simd("bif v3.16b, v4.16b, v5.16b"),
    simd("bit v6.16b, v7.16b, v1.16b"),
    simd("add v8.16b, v0.16b, v1.16b"),
    simd("add v9.8h, v0.8h, v1.8h"),
    simd("add v10.4s, v2.4s, v3.4s"),
    simd("add v11.2d, v2.2d, v3.2d"),
    simd("sub v12.4s, v4.4s, v5.4s"),
    simd("sub v13.2d, v6.2d, v7.2d"),
    simd("add v14.8b, v0.8b, v1.8b"),
    simd("mul v8.4s, v0.4s, v1.4s"),
    simd("mul v9.8h, v2.8h, v3.8h"),
    simd("mla v4.4s, v5.4s, v6.4s"),
    simd("mls v7.16b, v0.16b, v1.16b"),
    simd("cmeq v8.16b, v0.16b, v1.16b"),
    simd("cmeq v9.2d, v2.2d, v2.2d"),
    simd("cmhi v10.4s, v0.4s, v1.4s"),
    simd("cmgt v11.8h, v2.8h, v3.8h"),
    simd("cmge v12.2d, v4.2d, v5.2d"),
    simd("cmhs v13.16b, v6.16b, v7.16b"),
    simd("cmeq v14.4s, v0.4s, #0"),
    simd("shl v8.2d, v0.2d, #7"),
    simd("ushr v9.4s, v1.4s, #3"),
    simd("sshr v10.8h, v2.8h, #5"),
    simd("ushr v11.16b, v3.16b, #1"),
    simd("shl v12.4s, v4.4s, #31"),
    simd("sli v5.2d, v6.2d, #8"),
    simd("sri v7.4s, v0.4s, #4"),
    simd("usra v1.2d, v2.2d, #9"),
    simd("movi v8.16b, #0x5a"),
    simd("movi v9.4s, #0x12, lsl #8"),
    simd("mvni v10.8h, #0x34"),
    simd("movi v11.2d, #0xff00ff00ff00ff00"),
    simd("movi d12, #0xffff0000ffff0000"),
    simd("dup v12.4s, w0"),
    simd("dup v13.2d, x1"),
    simd("dup v14.16b, w2"),
    simd("mov v15.16b, v3.16b"),
    simd("dup v16.8h, v4.h[3]"),
    simd("umov w8, v0.b[5]"),
    simd("umov w9, v0.h[3]"),
    simd("mov w10, v1.s[2]"),
    simd("mov x11, v1.d[1]"),
    simd("smov x12, v2.b[7]"),
    simd("smov w13, v2.h[1]"),
    simd("fmov x14, v7.d[1]"),
    simd("ins v3.s[1], w0"),
    simd("ins v4.d[1], x1"),
    simd("ins v5.b[9], v6.b[2]"),
    simd("fmov v7.d[1], x2"),
    simd("uxtl v8.8h, v0.8b"),
    simd("uxtl2 v9.4s, v1.8h"),
    simd("sxtl v10.2d, v2.2s"),
    simd("ushll v11.4s, v3.4h, #3"),
    simd("umull v12.2d, v4.2s, v5.2s"),
    simd("umull2 v13.8h, v6.16b, v7.16b"),
    simd("xtn v14.8b, v0.8h"),
    simd("zip1 v8.16b, v0.16b, v1.16b"),
    simd("zip2 v9.4s, v2.4s, v3.4s"),
    simd("uzp1 v10.8h, v4.8h, v5.8h"),
    simd("uzp2 v11.2d, v6.2d, v7.2d"),
    simd("trn1 v12.4s, v0.4s, v1.4s"),
    simd("ext v13.16b, v2.16b, v3.16b, #5"),
    simd("rev64 v14.16b, v4.16b"),
    simd("rev32 v15.8h, v5.8h"),
    simd("tbl v16.16b, {v6.16b}, v7.16b"),
    simd("addv b8, v0.16b"),
    simd("addv s9, v1.4s"),
    simd("umaxv b10, v2.16b"),
    simd("uminv h11, v3.8h"),
    simd("addp d12, v4.2d"),
    simd("cnt v13.16b, v5.16b"),
    simd("uaddlv h14, v6.16b"),
    simd("umax v8.16b, v0.16b, v1.16b"),
    simd("umin v9.4s, v2.4s, v3.4s"),
    simd("smax v10.8h, v4.8h, v5.8h"),
    simd("smin v11.16b, v6.16b, v7.16b"),
    simd("abs v12.4s, v0.4s"),
    simd("neg v13.2d, v1.2d"),
    simd("scvtf v8.2d, v0.2d"),
    simd("ucvtf v9.2d, v1.2d"),
    simd("fadd v10.2d, v8.2d, v9.2d"),
    simd("fmul v11.2d, v8.2d, v9.2d"),
    simd("fcvtzs v12.2d, v10.2d"),
    simd("fcvtzu v13.2d, v11.2d"),
    simd("add d8, d0, d1"),
    simd("sub d9, d2, d3"),
    simd("cmeq d10, d4, d4"),
    simd("shl d11, d5, #9"),
    simd("ushr d12, d6, #3"),
    simd("neg d13, d7"),
    simd("fmov d14, x0"),
    simd("cmeq v8.8b, v0.8b, v1.8b"),
    simd("bif v3.8b, v4.8b, v5.8b"),
    simd("and v8.8b, v0.8b, v1.8b"),
    simd("movi v8.8b, #0x5a"),
    simd("dup v12.2s, w0"),
    simd("sub v12.16b, v4.16b, v5.16b"),
    simd("sub v12.8h, v4.8h, v5.8h"),
    simd("ld1 {v8.16b}, [x20]"),
    simd("ld1 {v9.2d}, [x20]"),
    simd("ld1 {v9.4s}, [x20]"),
    simd("st1 {v0.16b}, [x20]"),
    simd("st1 {v0.4s}, [x20]"),
    simd("ld1r {v10.4s}, [x20]"),
    simd("ld1 {v11.16b, v12.16b}, [x20]"),
    simd("st1 {v1.16b, v2.16b}, [x20]"),
    simd("ldr q8, [x20, #16]"),
    simd("str q0, [x20, #16]"),
    simd("ldp q8, q9, [x20]"),
    simd("stp q0, q1, [x20, #32]"),
    simd("fadd v10.2d, v0.2d, v1.2d"),
    simd("fmul v11.4s, v0.4s, v1.4s"),
    simd("fmov s14, w0"),
    simd("mov v15.d[0], x1"),
    ("simd_post_index", "mov x21, x20; ld1 {v9.2d}, [x21], #16; st1 {v0.4s}, [x21], #16; mov x8, x21"),
]


def assemble(asm: str) -> list[int]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / "c.s").write_text(".arch armv8-a+crc\n.text\n" + asm.replace(";", "\n") + "\n")
        subprocess.run(["aarch64-linux-gnu-as", "-o", tmp / "c.o", tmp / "c.s"], check=True)
        subprocess.run(
            ["aarch64-linux-gnu-objcopy", "-O", "binary", "-j", ".text", tmp / "c.o", tmp / "c.bin"],
            check=True,
        )
        data = (tmp / "c.bin").read_bytes()
    return list(struct.unpack(f"<{len(data) // 4}I", data))


def main() -> None:
    lines = [
        "// Generated by gen_cases.py. Do not edit by hand.",
        "",
        "pub const CASES: &[Case] = &[",
    ]
    for name, asm in CASES:
        words = ", ".join(f"0x{w:08x}" for w in assemble(asm))
        lines += [
            "    Case {",
            f'        name: "{name}",',
            f'        asm: "{asm}",',
            f"        words: &[{words}],",
            "    },",
        ]
    lines += ["];", ""]
    out = pathlib.Path(__file__).with_name("cases.rs")
    out.write_text("\n".join(lines))
    print(f"wrote {len(CASES)} cases to {out}")


if __name__ == "__main__":
    main()
