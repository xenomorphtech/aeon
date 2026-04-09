use crate::il::*;
use bad64::{Imm, Instruction, Op, Operand, Shift};

pub struct LiftResult {
    pub disasm: String,
    pub stmt: Stmt,
    pub edges: Vec<u64>,
}

// ═══════════════════════════════════════════════════════════════════════
// Main entry point
// ═══════════════════════════════════════════════════════════════════════

pub fn lift(insn: &Instruction, pc: u64, next_pc: Option<u64>) -> LiftResult {
    let disasm = format!("{}", insn);
    let operands = insn.operands();
    let mut edges = Vec::new();

    let stmt = match insn.op() {
        // ── Data movement ──────────────────────────────────────────
        Op::MOV | Op::MOVZ | Op::MOVN => {
            let dst = reg_op(operands, 0);
            let src = expr_op(operands, 1);
            ft(&mut edges, next_pc);
            Stmt::Assign { dst, src }
        }
        Op::MOVK => {
            // MOVK Xd, #imm, LSL #shift — keeps other bits
            let dst = reg_op(operands, 0);
            let src = expr_op(operands, 1);
            ft(&mut edges, next_pc);
            let dst_expr = Expr::Reg(dst.clone());
            Stmt::Assign {
                dst,
                src: e_intrinsic("movk", vec![dst_expr, src]),
            }
        }
        Op::FMOV => {
            let dst = reg_op(operands, 0);
            let src = expr_op(operands, 1);
            ft(&mut edges, next_pc);
            Stmt::Assign { dst, src }
        }
        Op::MOVI => {
            ft(&mut edges, next_pc);
            lift_vector_immediate_intrinsic(&disasm, operands, "movi")
        }
        Op::MVNI => {
            ft(&mut edges, next_pc);
            lift_vector_immediate_intrinsic(&disasm, operands, "mvni")
        }
        Op::UMOV => {
            ft(&mut edges, next_pc);
            lift_lane_move(&disasm, operands, false)
        }
        Op::SMOV => {
            ft(&mut edges, next_pc);
            lift_lane_move(&disasm, operands, true)
        }
        Op::ADRP => {
            let dst = reg_op(operands, 0);
            let addr = label_val(operands, 1);
            ft(&mut edges, next_pc);
            Stmt::Assign {
                dst,
                src: Expr::AdrpImm(addr),
            }
        }
        Op::ADR => {
            let dst = reg_op(operands, 0);
            let addr = label_val(operands, 1);
            ft(&mut edges, next_pc);
            Stmt::Assign {
                dst,
                src: Expr::AdrImm(addr),
            }
        }

        // ── Extensions ─────────────────────────────────────────────
        Op::SXTW => {
            ft(&mut edges, next_pc);
            lift_unary(operands, |s| e_sign_extend(s, 32))
        }
        Op::SXTH => {
            ft(&mut edges, next_pc);
            lift_unary(operands, |s| e_sign_extend(s, 16))
        }
        Op::SXTB => {
            ft(&mut edges, next_pc);
            lift_unary(operands, |s| e_sign_extend(s, 8))
        }
        Op::UXTB => {
            ft(&mut edges, next_pc);
            lift_unary(operands, |s| e_zero_extend(s, 8))
        }
        Op::UXTH => {
            ft(&mut edges, next_pc);
            lift_unary(operands, |s| e_zero_extend(s, 16))
        }

        // ── Loads (basic) ──────────────────────────────────────────
        Op::LDR | Op::LDUR | Op::LDAR | Op::LDTR | Op::LDLAR => {
            ft(&mut edges, next_pc);
            lift_load(operands, 0, false)
        }
        Op::LDAXR | Op::LDXR => {
            ft(&mut edges, next_pc);
            lift_load(operands, 0, false)
        }

        // Byte loads
        Op::LDRB | Op::LDURB | Op::LDARB => {
            ft(&mut edges, next_pc);
            lift_load(operands, 1, false)
        }
        Op::LDAXRB | Op::LDXRB => {
            ft(&mut edges, next_pc);
            lift_load(operands, 1, false)
        }

        // Half loads
        Op::LDRH | Op::LDURH | Op::LDARH => {
            ft(&mut edges, next_pc);
            lift_load(operands, 2, false)
        }
        Op::LDAXRH | Op::LDXRH => {
            ft(&mut edges, next_pc);
            lift_load(operands, 2, false)
        }

        // Sign-extending loads
        Op::LDRSW | Op::LDURSW => {
            ft(&mut edges, next_pc);
            lift_load(operands, 4, true)
        }
        Op::LDRSH | Op::LDURSH => {
            ft(&mut edges, next_pc);
            lift_load(operands, 2, true)
        }
        Op::LDRSB | Op::LDURSB => {
            ft(&mut edges, next_pc);
            lift_load(operands, 1, true)
        }

        // Load pair
        Op::LDP | Op::LDNP | Op::LDPSW => {
            ft(&mut edges, next_pc);
            lift_load_pair(operands, insn.op() == Op::LDPSW)
        }

        // Load-acquire/other loads
        Op::LDAPUR | Op::LDAPURB | Op::LDAPURH | Op::LDAPURSB | Op::LDAPURSH | Op::LDAPURSW => {
            ft(&mut edges, next_pc);
            let size = match insn.op() {
                Op::LDAPURB | Op::LDAPURSB => 1,
                Op::LDAPURH | Op::LDAPURSH => 2,
                Op::LDAPURSW => 4,
                _ => 0,
            };
            let signed = matches!(insn.op(), Op::LDAPURSB | Op::LDAPURSH | Op::LDAPURSW);
            lift_load(operands, size, signed)
        }

        Op::LDRAA | Op::LDRAB => {
            ft(&mut edges, next_pc);
            lift_load(operands, 0, false)
        }

        // ── Stores (basic) ─────────────────────────────────────────
        Op::STR | Op::STUR | Op::STLR | Op::STTR | Op::STLLR => {
            ft(&mut edges, next_pc);
            lift_store(operands, 0)
        }
        Op::STLXR | Op::STXR => {
            ft(&mut edges, next_pc);
            lift_store_exclusive(operands, 0)
        }

        // Byte stores
        Op::STRB | Op::STURB | Op::STLRB | Op::STLLRB => {
            ft(&mut edges, next_pc);
            lift_store(operands, 1)
        }
        Op::STLXRB | Op::STXRB => {
            ft(&mut edges, next_pc);
            lift_store_exclusive(operands, 1)
        }

        // Half stores
        Op::STRH | Op::STURH | Op::STLRH | Op::STLLRH => {
            ft(&mut edges, next_pc);
            lift_store(operands, 2)
        }
        Op::STLXRH | Op::STXRH => {
            ft(&mut edges, next_pc);
            lift_store_exclusive(operands, 2)
        }

        // Store pair
        Op::STP | Op::STNP => {
            ft(&mut edges, next_pc);
            lift_store_pair(operands)
        }

        // Store release/other
        Op::STLUR | Op::STLURB | Op::STLURH | Op::STTRB | Op::STTRH => {
            ft(&mut edges, next_pc);
            let size = match insn.op() {
                Op::STLURB | Op::STTRB => 1,
                Op::STLURH | Op::STTRH => 2,
                _ => 0,
            };
            lift_store(operands, size)
        }

        // ── Arithmetic ─────────────────────────────────────────────
        Op::ADD => {
            ft(&mut edges, next_pc);
            if first_vector_arrangement(&disasm).is_some()
                && matches!(reg_op(operands, 0), Reg::V(_) | Reg::Q(_))
            {
                lift_intrinsic_all_with_arrangement(&disasm, operands, "add")
            } else {
                lift_binary(operands, e_add)
            }
        }
        Op::ADDS => {
            ft(&mut edges, next_pc);
            lift_binary_with_flags(operands, e_add)
        }
        Op::SUB => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_sub)
        }
        Op::SUBS => {
            ft(&mut edges, next_pc);
            lift_binary_with_flags(operands, e_sub)
        }
        Op::MUL => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_mul)
        }
        Op::SDIV => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_div)
        }
        Op::UDIV => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_udiv)
        }
        Op::NEG | Op::NEGS => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_neg)
        }

        Op::MADD => {
            // MADD Xd, Xn, Xm, Xa → Xd = Xa + Xn * Xm
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            let a = expr_op(operands, 3);
            Stmt::Assign {
                dst,
                src: e_add(a, e_mul(n, m)),
            }
        }
        Op::MSUB => {
            // MSUB Xd, Xn, Xm, Xa → Xd = Xa - Xn * Xm
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            let a = expr_op(operands, 3);
            Stmt::Assign {
                dst,
                src: e_sub(a, e_mul(n, m)),
            }
        }
        Op::MNEG => {
            // MNEG Xd, Xn, Xm → Xd = -(Xn * Xm)
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            Stmt::Assign {
                dst,
                src: e_neg(e_mul(n, m)),
            }
        }
        Op::SMADDL => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            let a = expr_op(operands, 3);
            Stmt::Assign {
                dst,
                src: e_add(a, e_mul(e_sign_extend(n, 32), e_sign_extend(m, 32))),
            }
        }
        Op::SMULL => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            Stmt::Assign {
                dst,
                src: e_mul(e_sign_extend(n, 32), e_sign_extend(m, 32)),
            }
        }
        Op::UMADDL => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            let a = expr_op(operands, 3);
            Stmt::Assign {
                dst,
                src: e_add(a, e_mul(e_zero_extend(n, 32), e_zero_extend(m, 32))),
            }
        }
        Op::UMULL => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            Stmt::Assign {
                dst,
                src: e_mul(e_zero_extend(n, 32), e_zero_extend(m, 32)),
            }
        }
        Op::SMULH | Op::UMULH => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            let name = if insn.op() == Op::SMULH {
                "smulh"
            } else {
                "umulh"
            };
            Stmt::Assign {
                dst,
                src: e_intrinsic(name, vec![n, m]),
            }
        }
        Op::SMSUBL | Op::UMSUBL => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            let a = expr_op(operands, 3);
            Stmt::Assign {
                dst,
                src: e_sub(a, e_mul(n, m)),
            }
        }

        // Carry ops
        Op::ADC => {
            ft(&mut edges, next_pc);
            lift_binary_intrinsic(operands, "adc")
        }
        Op::ADCS => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let a = expr_op(operands, 1);
            let b = expr_op(operands, 2);
            let expr = e_intrinsic("adc", vec![a.clone(), b.clone()]);
            Stmt::Pair(
                Box::new(Stmt::SetFlags { expr: expr.clone() }),
                Box::new(Stmt::Assign { dst, src: expr }),
            )
        }
        Op::SBC => {
            ft(&mut edges, next_pc);
            lift_binary_intrinsic(operands, "sbc")
        }
        Op::SBCS => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let a = expr_op(operands, 1);
            let b = expr_op(operands, 2);
            let expr = e_intrinsic("sbc", vec![a.clone(), b.clone()]);
            Stmt::Pair(
                Box::new(Stmt::SetFlags { expr: expr.clone() }),
                Box::new(Stmt::Assign { dst, src: expr }),
            )
        }
        Op::NGC => {
            ft(&mut edges, next_pc);
            lift_unary_intrinsic(operands, "ngc")
        }
        Op::NGCS => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let a = expr_op(operands, 1);
            let expr = e_intrinsic("ngc", vec![a]);
            Stmt::Pair(
                Box::new(Stmt::SetFlags { expr: expr.clone() }),
                Box::new(Stmt::Assign { dst, src: expr }),
            )
        }

        // ── Logic ──────────────────────────────────────────────────
        Op::AND => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_and)
        }
        Op::ANDS => {
            ft(&mut edges, next_pc);
            lift_binary_with_flags(operands, e_and)
        }
        Op::ORR => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_or)
        }
        Op::EOR => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_xor)
        }
        Op::BIC => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let a = expr_op(operands, 1);
            let b = expr_op(operands, 2);
            Stmt::Assign {
                dst,
                src: e_and(a, e_not(b)),
            }
        }
        Op::BICS => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let a = expr_op(operands, 1);
            let b = expr_op(operands, 2);
            let expr = e_and(a.clone(), e_not(b.clone()));
            Stmt::Pair(
                Box::new(Stmt::SetFlags { expr: expr.clone() }),
                Box::new(Stmt::Assign { dst, src: expr }),
            )
        }
        Op::ORN => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let a = expr_op(operands, 1);
            let b = expr_op(operands, 2);
            Stmt::Assign {
                dst,
                src: e_or(a, e_not(b)),
            }
        }
        Op::EON => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let a = expr_op(operands, 1);
            let b = expr_op(operands, 2);
            Stmt::Assign {
                dst,
                src: e_xor(a, e_not(b)),
            }
        }
        Op::MVN => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_not)
        }

        // ── Shifts ─────────────────────────────────────────────────
        Op::LSL => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_shl)
        }
        Op::LSR => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_lsr)
        }
        Op::ASR => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_asr)
        }
        Op::ROR => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_ror)
        }

        // ── Bitfield ───────────────────────────────────────────────
        Op::BFI | Op::BFXIL | Op::SBFIZ | Op::SBFX | Op::UBFX | Op::UBFIZ => {
            ft(&mut edges, next_pc);
            lift_bitfield(insn.op(), operands)
        }
        Op::EXTR => {
            ft(&mut edges, next_pc);
            lift_intrinsic_all(operands, "extr")
        }

        // ── Bit manipulation ───────────────────────────────────────
        Op::CLZ => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_clz)
        }
        Op::CLS => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_cls)
        }
        Op::RBIT => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_rbit)
        }
        Op::REV | Op::REV64 => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_rev)
        }
        Op::REV16 => {
            ft(&mut edges, next_pc);
            lift_unary_intrinsic(operands, "rev16")
        }
        Op::REV32 => {
            ft(&mut edges, next_pc);
            lift_unary_intrinsic(operands, "rev32")
        }
        Op::CNT => {
            ft(&mut edges, next_pc);
            lift_unary_intrinsic(operands, "cnt")
        }

        // ── Compare ────────────────────────────────────────────────
        Op::CMP => {
            ft(&mut edges, next_pc);
            let a = expr_op(operands, 0);
            let b = expr_op(operands, 1);
            Stmt::SetFlags { expr: e_sub(a, b) }
        }
        Op::CMN => {
            ft(&mut edges, next_pc);
            let a = expr_op(operands, 0);
            let b = expr_op(operands, 1);
            Stmt::SetFlags { expr: e_add(a, b) }
        }
        Op::TST => {
            ft(&mut edges, next_pc);
            let a = expr_op(operands, 0);
            let b = expr_op(operands, 1);
            Stmt::SetFlags { expr: e_and(a, b) }
        }
        Op::CCMP | Op::CCMN => {
            ft(&mut edges, next_pc);
            lift_cond_compare(operands, insn.op() == Op::CCMN)
        }

        // ── Conditional select ─────────────────────────────────────
        Op::CSEL => {
            ft(&mut edges, next_pc);
            lift_csel(operands, |t, f, c| e_cond_select(c, t, f))
        }
        Op::CSINC | Op::CINC => {
            ft(&mut edges, next_pc);
            lift_csel(operands, |t, f, c| {
                e_cond_select(c, t, e_add(f, Expr::Imm(1)))
            })
        }
        Op::CSINV | Op::CINV => {
            ft(&mut edges, next_pc);
            lift_csel(operands, |t, f, c| e_cond_select(c, t, e_not(f)))
        }
        Op::CSNEG | Op::CNEG => {
            ft(&mut edges, next_pc);
            lift_csel(operands, |t, f, c| e_cond_select(c, t, e_neg(f)))
        }
        Op::CSET => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let cond = cond_op(operands, 1);
            Stmt::Assign {
                dst,
                src: e_cond_select(cond, Expr::Imm(1), Expr::Imm(0)),
            }
        }
        Op::CSETM => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let cond = cond_op(operands, 1);
            Stmt::Assign {
                dst,
                src: e_cond_select(cond, Expr::Imm(u64::MAX), Expr::Imm(0)),
            }
        }
        Op::FCSEL => {
            ft(&mut edges, next_pc);
            lift_csel(operands, |t, f, c| e_cond_select(c, t, f))
        }

        // ── MRS / MSR ─────────────────────────────────────────────
        Op::MRS => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let sysreg_name = if operands.len() > 1 {
                format!("{}", DisplayOperand(&operands[1]))
            } else {
                "unknown".to_string()
            };
            Stmt::Assign {
                dst,
                src: Expr::MrsRead(sysreg_name),
            }
        }
        Op::MSR => {
            ft(&mut edges, next_pc);
            lift_intrinsic_all(operands, "msr")
        }

        // ── Branches ───────────────────────────────────────────────
        Op::B => {
            let target = label_val(operands, 0);
            edges.push(target);
            Stmt::Branch {
                target: Expr::Imm(target),
            }
        }
        Op::BR => {
            let target = expr_op(operands, 0);
            Stmt::Branch { target }
        }
        Op::BL => {
            let target = label_val(operands, 0);
            ft(&mut edges, next_pc);
            Stmt::Call {
                target: Expr::Imm(target),
            }
        }
        Op::BLR => {
            let target = expr_op(operands, 0);
            ft(&mut edges, next_pc);
            Stmt::Call { target }
        }
        Op::RET => Stmt::Ret,

        // Conditional branches (B.cond)
        Op::B_EQ
        | Op::B_NE
        | Op::B_CS
        | Op::B_CC
        | Op::B_MI
        | Op::B_PL
        | Op::B_VS
        | Op::B_VC
        | Op::B_HI
        | Op::B_LS
        | Op::B_GE
        | Op::B_LT
        | Op::B_GT
        | Op::B_LE
        | Op::B_AL
        | Op::B_NV => {
            let cond = cond_from_branch_op(insn.op());
            let target = label_val(operands, 0);
            edges.push(target);
            if let Some(npc) = next_pc {
                edges.push(npc);
            }
            Stmt::CondBranch {
                cond: BranchCond::Flag(cond),
                target: Expr::Imm(target),
                fallthrough: next_pc.unwrap_or(pc + 4),
            }
        }

        // Compare and branch
        Op::CBZ => {
            let reg = expr_op(operands, 0);
            let target = label_val(operands, 1);
            edges.push(target);
            if let Some(npc) = next_pc {
                edges.push(npc);
            }
            Stmt::CondBranch {
                cond: BranchCond::Zero(reg),
                target: Expr::Imm(target),
                fallthrough: next_pc.unwrap_or(pc + 4),
            }
        }
        Op::CBNZ => {
            let reg = expr_op(operands, 0);
            let target = label_val(operands, 1);
            edges.push(target);
            if let Some(npc) = next_pc {
                edges.push(npc);
            }
            Stmt::CondBranch {
                cond: BranchCond::NotZero(reg),
                target: Expr::Imm(target),
                fallthrough: next_pc.unwrap_or(pc + 4),
            }
        }

        // Test and branch
        Op::TBZ => {
            let reg = expr_op(operands, 0);
            let bit = imm_val(operands, 1) as u8;
            let target = label_val(operands, 2);
            edges.push(target);
            if let Some(npc) = next_pc {
                edges.push(npc);
            }
            Stmt::CondBranch {
                cond: BranchCond::BitZero(reg, bit),
                target: Expr::Imm(target),
                fallthrough: next_pc.unwrap_or(pc + 4),
            }
        }
        Op::TBNZ => {
            let reg = expr_op(operands, 0);
            let bit = imm_val(operands, 1) as u8;
            let target = label_val(operands, 2);
            edges.push(target);
            if let Some(npc) = next_pc {
                edges.push(npc);
            }
            Stmt::CondBranch {
                cond: BranchCond::BitNotZero(reg, bit),
                target: Expr::Imm(target),
                fallthrough: next_pc.unwrap_or(pc + 4),
            }
        }

        // ── Floating point arithmetic ──────────────────────────────
        Op::FADD => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_fadd)
        }
        Op::FSUB => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_fsub)
        }
        Op::FMUL => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_fmul)
        }
        Op::FDIV => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_fdiv)
        }
        Op::FNEG => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_fneg)
        }
        Op::FABS => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_fabs)
        }
        Op::FSQRT => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_fsqrt)
        }
        Op::FNMUL => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let a = expr_op(operands, 1);
            let b = expr_op(operands, 2);
            Stmt::Assign {
                dst,
                src: e_fneg(e_fmul(a, b)),
            }
        }

        // FP multiply-accumulate
        Op::FMADD => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            let a = expr_op(operands, 3);
            Stmt::Assign {
                dst,
                src: e_fadd(a, e_fmul(n, m)),
            }
        }
        Op::FMSUB => {
            ft(&mut edges, next_pc);
            let dst = reg_op(operands, 0);
            let n = expr_op(operands, 1);
            let m = expr_op(operands, 2);
            let a = expr_op(operands, 3);
            Stmt::Assign {
                dst,
                src: e_fsub(a, e_fmul(n, m)),
            }
        }
        Op::FNMADD | Op::FNMSUB => {
            ft(&mut edges, next_pc);
            lift_intrinsic_all(
                operands,
                if insn.op() == Op::FNMADD {
                    "fnmadd"
                } else {
                    "fnmsub"
                },
            )
        }

        // FP compare
        Op::FCMP | Op::FCMPE => {
            ft(&mut edges, next_pc);
            let a = expr_op(operands, 0);
            let b = if operands.len() > 1 {
                expr_op(operands, 1)
            } else {
                Expr::FImm(0.0)
            };
            Stmt::SetFlags { expr: e_fsub(a, b) }
        }
        Op::FCCMP | Op::FCCMPE => {
            ft(&mut edges, next_pc);
            lift_intrinsic_all(operands, "fccmp")
        }

        // FP min/max
        Op::FMAXNM => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_fmax)
        }
        Op::FMINNM => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_fmin)
        }
        Op::FMAX => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_fmax)
        }
        Op::FMIN => {
            ft(&mut edges, next_pc);
            lift_binary(operands, e_fmin)
        }

        // FP conversions
        Op::FCVT => {
            ft(&mut edges, next_pc);
            lift_unary(operands, e_fcvt)
        }
        Op::SCVTF => {
            ft(&mut edges, next_pc);
            if first_vector_arrangement(&disasm).is_some() {
                lift_unary_intrinsic_with_arrangement(&disasm, operands, "scvtf")
            } else {
                lift_unary(operands, e_int_to_float)
            }
        }
        Op::UCVTF => {
            ft(&mut edges, next_pc);
            if first_vector_arrangement(&disasm).is_some() {
                lift_unary_intrinsic_with_arrangement(&disasm, operands, "ucvtf")
            } else {
                lift_unary(operands, e_int_to_float)
            }
        }
        Op::FCVTZS
        | Op::FCVTZU
        | Op::FCVTMS
        | Op::FCVTMU
        | Op::FCVTPS
        | Op::FCVTPU
        | Op::FCVTAS
        | Op::FCVTAU
        | Op::FCVTNS
        | Op::FCVTNU => {
            ft(&mut edges, next_pc);
            if first_vector_arrangement(&disasm).is_some() {
                let name = format!("{:?}", insn.op()).to_lowercase();
                lift_unary_intrinsic_with_arrangement(&disasm, operands, &name)
            } else {
                lift_unary(operands, e_float_to_int)
            }
        }

        // FP rounding
        Op::FRINTZ | Op::FRINTM | Op::FRINTP | Op::FRINTN | Op::FRINTA | Op::FRINTX => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_unary_intrinsic(operands, &name)
        }

        // FP reciprocal estimates
        Op::FRECPE | Op::FRECPS | Op::FRSQRTE | Op::FRSQRTS => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all_with_arrangement(&disasm, operands, &name)
        }

        Op::UMULL2 | Op::SMULL2 | Op::UMLAL2 | Op::UMLSL2 => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_widening_lane_mul_intrinsic(&disasm, operands, &name)
        }

        // ── SIMD / NEON (as intrinsics with proper operand extraction) ─
        Op::DUP
        | Op::INS
        | Op::EXT
        | Op::ZIP1
        | Op::ZIP2
        | Op::UZP1
        | Op::UZP2
        | Op::TRN1
        | Op::TRN2
        | Op::TBL
        | Op::TBX
        | Op::BSL
        | Op::BIT
        | Op::BIF
        | Op::ADDV
        | Op::UMAXV
        | Op::UMINV
        | Op::SMAXV
        | Op::SMINV
        | Op::UADDLV
        | Op::SADDLV
        | Op::FADDP
        | Op::SMAX
        | Op::SMIN
        | Op::UMAX
        | Op::UMIN
        | Op::SMAXP
        | Op::SMINP
        | Op::UMAXP
        | Op::UMINP
        | Op::SHL
        | Op::SRI
        | Op::USHR
        | Op::SSHR
        | Op::SLI
        | Op::SSRA
        | Op::USRA
        | Op::SRSHR
        | Op::SRSRA
        | Op::URSHR
        | Op::URSRA
        | Op::ADDP
        | Op::ADDHN
        | Op::ADDHN2
        | Op::SUBHN
        | Op::SUBHN2
        | Op::XTN
        | Op::XTN2
        | Op::SXTL
        | Op::SXTL2
        | Op::UXTL
        | Op::UXTL2
        | Op::SHLL
        | Op::SHLL2
        | Op::SHRN
        | Op::SHRN2
        | Op::SSHLL
        | Op::SSHLL2
        | Op::USHLL
        | Op::USHLL2
        | Op::FCVTN
        | Op::FCVTN2
        | Op::FCVTL
        | Op::FCVTL2
        | Op::SQXTUN
        | Op::SQXTUN2
        | Op::SQXTN
        | Op::SQXTN2
        | Op::SQDMULH
        | Op::SQRDMULH
        | Op::CMEQ
        | Op::CMGT
        | Op::CMGE
        | Op::CMHI
        | Op::CMHS
        | Op::CMLT
        | Op::CMLE
        | Op::CMTST
        | Op::FCMGT
        | Op::FCMGE
        | Op::FCMLT
        | Op::FCMLE
        | Op::FCMEQ
        | Op::ABS
        | Op::FABD
        | Op::FMLA
        | Op::FMLS
        | Op::SABD
        | Op::UABD
        | Op::UABDL
        | Op::UABDL2
        | Op::SADDW
        | Op::SADDW2
        | Op::UADDW
        | Op::UADDW2
        | Op::SADDL
        | Op::SADDL2
        | Op::UADDL
        | Op::UADDL2
        | Op::SSUBL
        | Op::SSUBL2
        | Op::USUBL
        | Op::USUBL2
        | Op::UMLAL
        | Op::SMLAL
        | Op::SMLAL2
        | Op::PMULL
        | Op::PMULL2
        | Op::FMAXNMP
        | Op::FMINNMP
        | Op::FMINP
        | Op::SQSHLU
        | Op::SQSHRUN
        | Op::SQSHRUN2
        | Op::SQRSHRUN
        | Op::UQRSHL
        | Op::SQRSHL
        | Op::SRSHL
        | Op::URSHL
        | Op::SSHL
        | Op::USHL
        | Op::SQDMULL
        | Op::SQDMULL2
        | Op::SQDMLAL
        | Op::SQDMLAL2
        | Op::SQDMLSL
        | Op::SQDMLSL2
        | Op::RADDHN
        | Op::RADDHN2
        | Op::UADALP
        | Op::SADDLP
        | Op::UADDLP
        | Op::SHADD
        | Op::URHADD
        | Op::SRHADD
        | Op::UHADD
        | Op::UHSUB
        | Op::SQSHL
        | Op::UQSHL
        | Op::SQSUB
        | Op::UQSUB
        | Op::UQADD
        | Op::SQADD
        | Op::FCADD
        | Op::SQRSHRN2
        | Op::UQRSHRN
        | Op::UQRSHRN2
        | Op::USQADD
        | Op::FMAXV
        | Op::FMINV => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all_with_arrangement(&disasm, operands, &name)
        }

        Op::MLA | Op::MLS | Op::SQRDMLAH | Op::SQRDMLSH | Op::FCMLA | Op::FMULX => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_with_lane_operand(&disasm, operands, &name, 2)
        }

        // SIMD loads/stores
        Op::LD1
        | Op::LD2
        | Op::LD3
        | Op::LD4
        | Op::LD1R
        | Op::LD2R
        | Op::LD3R
        | Op::LD4R
        | Op::ST1
        | Op::ST2
        | Op::ST3
        | Op::ST4 => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all_with_arrangement(&disasm, operands, &name)
        }

        // ── Atomics ────────────────────────────────────────────────
        Op::LDADD
        | Op::LDADDA
        | Op::LDADDAL
        | Op::LDADDL
        | Op::LDCLRL
        | Op::LDCLRAL
        | Op::LDSETAL
        | Op::LDSETA
        | Op::LDSETL
        | Op::LDSET
        | Op::SWP
        | Op::SWPA
        | Op::SWPAL
        | Op::SWPL
        | Op::CAS
        | Op::CASA
        | Op::CASAL
        | Op::CASL => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all(operands, &name)
        }
        Op::LDAXP | Op::LDXP => {
            ft(&mut edges, next_pc);
            lift_load_pair_exclusive(operands)
        }
        Op::STLXP | Op::STXP => {
            ft(&mut edges, next_pc);
            lift_store_pair_exclusive(operands)
        }

        // ── Crypto ─────────────────────────────────────────────────
        Op::AESE
        | Op::AESD
        | Op::AESMC
        | Op::AESIMC
        | Op::SHA1H
        | Op::SHA1C
        | Op::SHA1M
        | Op::SHA1P
        | Op::SHA1SU0
        | Op::SHA1SU1
        | Op::SHA256H
        | Op::SHA256H2
        | Op::SHA256SU0
        | Op::SHA256SU1
        | Op::SHA512H
        | Op::SHA512H2
        | Op::SHA512SU0
        | Op::SHA512SU1
        | Op::EOR3
        | Op::XAR
        | Op::BCAX
        | Op::RAX1 => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all(operands, &name)
        }

        // ── System / NOP / Hints ───────────────────────────────────
        Op::NOP | Op::YIELD | Op::HINT => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all(operands, &name)
        }
        Op::PACIASP | Op::AUTIASP | Op::BTI | Op::XPACLRI => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all(operands, &name)
        }
        Op::PRFM | Op::PRFUM => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all(operands, &name)
        }
        Op::DMB | Op::DSB | Op::ISB => {
            ft(&mut edges, next_pc);
            Stmt::Barrier(format!("{:?}", insn.op()).to_lowercase())
        }
        Op::CLREX => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all(operands, &name)
        }
        Op::BRK => Stmt::Trap {
            kind: TrapKind::Brk,
            imm: imm_val(operands, 0) as u16,
        },
        Op::UDF => Stmt::Trap {
            kind: TrapKind::Udf,
            imm: imm_val(operands, 0) as u16,
        },
        Op::SVC | Op::HVC | Op::SMC => {
            ft(&mut edges, next_pc);
            lift_intrinsic_all(operands, &format!("{:?}", insn.op()).to_lowercase())
        }
        Op::SYS | Op::SYSL => {
            ft(&mut edges, next_pc);
            lift_intrinsic_all(operands, "sys")
        }

        // ── MTE (Memory Tagging) ──────────────────────────────────
        Op::ADDG
        | Op::SUBG
        | Op::STG
        | Op::STZG
        | Op::ST2G
        | Op::STZ2G
        | Op::LDG
        | Op::STGP
        | Op::SUBPS => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all(operands, &name)
        }

        // ── Catch-all: everything else → named intrinsic ───────────
        _ => {
            ft(&mut edges, next_pc);
            let name = format!("{:?}", insn.op()).to_lowercase();
            lift_intrinsic_all(operands, &name)
        }
    };

    LiftResult {
        disasm,
        stmt,
        edges,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Pattern handlers
// ═══════════════════════════════════════════════════════════════════════

fn lift_binary(operands: &[Operand], make: fn(Expr, Expr) -> Expr) -> Stmt {
    let dst = reg_op(operands, 0);
    let a = expr_op(operands, 1);
    let b = expr_op(operands, 2);
    Stmt::Assign {
        dst,
        src: make(a, b),
    }
}

fn lift_binary_with_flags(operands: &[Operand], make: fn(Expr, Expr) -> Expr) -> Stmt {
    let dst = reg_op(operands, 0);
    let a = expr_op(operands, 1);
    let b = expr_op(operands, 2);
    Stmt::Pair(
        Box::new(Stmt::SetFlags {
            expr: make(a.clone(), b.clone()),
        }),
        Box::new(Stmt::Assign {
            dst,
            src: make(a, b),
        }),
    )
}

fn lift_unary(operands: &[Operand], make: fn(Expr) -> Expr) -> Stmt {
    let dst = reg_op(operands, 0);
    let a = expr_op(operands, 1);
    Stmt::Assign { dst, src: make(a) }
}

fn lift_binary_intrinsic(operands: &[Operand], name: &str) -> Stmt {
    let dst = reg_op(operands, 0);
    let a = expr_op(operands, 1);
    let b = expr_op(operands, 2);
    Stmt::Assign {
        dst,
        src: e_intrinsic(name, vec![a, b]),
    }
}

fn lift_unary_intrinsic(operands: &[Operand], name: &str) -> Stmt {
    let dst = reg_op(operands, 0);
    let a = expr_op(operands, 1);
    Stmt::Assign {
        dst,
        src: e_intrinsic(name, vec![a]),
    }
}

fn lift_unary_intrinsic_with_arrangement(disasm: &str, operands: &[Operand], name: &str) -> Stmt {
    let dst = reg_op(operands, 0);
    let a = expr_op(operands, 1);
    Stmt::Assign {
        dst,
        src: e_intrinsic(&intrinsic_name_with_arrangement(disasm, name), vec![a]),
    }
}

fn lift_intrinsic_all(operands: &[Operand], name: &str) -> Stmt {
    let ops: Vec<Expr> = operands.iter().map(|o| expr_from_operand(o)).collect();
    Stmt::Intrinsic {
        name: name.to_string(),
        operands: ops,
    }
}

fn lift_intrinsic_all_with_arrangement(disasm: &str, operands: &[Operand], name: &str) -> Stmt {
    lift_intrinsic_all(operands, &intrinsic_name_with_arrangement(disasm, name))
}

fn lift_vector_immediate_intrinsic(disasm: &str, operands: &[Operand], name: &str) -> Stmt {
    let mut ops = Vec::with_capacity(operands.len());
    if let Some(dst) = operands.first().and_then(operand_to_reg) {
        ops.push(Expr::Reg(dst));
    }
    ops.extend(operands.iter().skip(1).map(expr_from_operand));
    Stmt::Intrinsic {
        name: intrinsic_name_with_arrangement(disasm, name),
        operands: ops,
    }
}

fn lift_intrinsic_with_lane_operand(
    disasm: &str,
    operands: &[Operand],
    name: &str,
    lane_operand_index: usize,
) -> Stmt {
    let mut ops = Vec::with_capacity(operands.len());
    for (index, operand) in operands.iter().enumerate() {
        let expr = if index == lane_operand_index {
            parse_lane_operand(disasm, index)
                .map(|(reg, lsb, width)| e_extract(Expr::Reg(reg), lsb, width))
                .unwrap_or_else(|| expr_from_operand(operand))
        } else {
            expr_from_operand(operand)
        };
        ops.push(expr);
    }
    Stmt::Intrinsic {
        name: intrinsic_name_with_arrangement(disasm, name),
        operands: ops,
    }
}

fn lift_widening_lane_mul_intrinsic(disasm: &str, operands: &[Operand], name: &str) -> Stmt {
    let mut ops = Vec::with_capacity(3);
    ops.push(Expr::Reg(reg_op(operands, 0)));
    ops.push(expr_op(operands, 1));
    let scalar = parse_lane_operand(disasm, 2)
        .map(|(reg, lsb, width)| e_extract(Expr::Reg(reg), lsb, width))
        .unwrap_or_else(|| expr_op(operands, 2));
    ops.push(scalar);
    Stmt::Intrinsic {
        name: intrinsic_name_with_arrangement(disasm, name),
        operands: ops,
    }
}

fn lift_lane_move(disasm: &str, operands: &[Operand], signed: bool) -> Stmt {
    let dst = reg_op(operands, 0);
    let Some((src_reg, lsb, width)) = parse_lane_operand(disasm, 1) else {
        let name = if signed { "smov" } else { "umov" };
        return lift_intrinsic_all(operands, name);
    };

    let extracted = e_extract(Expr::Reg(src_reg), lsb, width);
    let src = if signed {
        e_sign_extend(extracted, width)
    } else {
        extracted
    };
    Stmt::Assign { dst, src }
}

fn intrinsic_name_with_arrangement(disasm: &str, name: &str) -> String {
    match first_vector_arrangement(disasm) {
        Some(arrangement) => format!("{name}.{arrangement}"),
        None => name.to_string(),
    }
}

fn first_vector_arrangement(disasm: &str) -> Option<String> {
    let (_, operands) = disasm.split_once(' ')?;
    let first = operands
        .split(',')
        .next()?
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}');
    let (_, arrangement) = first.split_once('.')?;
    if arrangement.chars().next()?.is_ascii_digit() {
        Some(arrangement.to_string())
    } else {
        None
    }
}

fn parse_lane_operand(disasm: &str, operand_index: usize) -> Option<(Reg, u8, u8)> {
    let (_, operands) = disasm.split_once(' ')?;
    let operand = operands.split(',').nth(operand_index)?.trim();
    let (base, lane_spec) = operand.split_once('.')?;
    let reg = reg_from_string(base)?;
    let (lane_name, lane_index) = lane_spec.split_once('[')?;
    let lane_index = lane_index.strip_suffix(']')?.parse::<u8>().ok()?;
    let lane_bits = match lane_name.chars().next()? {
        'b' => 8,
        'h' => 16,
        's' => 32,
        'd' => 64,
        _ => return None,
    };
    let lsb = lane_index.checked_mul(lane_bits)?;
    Some((reg, lsb, lane_bits))
}

fn lift_bitfield(op: Op, operands: &[Operand]) -> Stmt {
    let dst = reg_op(operands, 0);
    let src = expr_op(operands, 1);
    let lsb = imm_val(operands, 2) as u8;
    let width = imm_val(operands, 3) as u8;
    let reg_bits = operand_reg_size(operands, 0).max(1) * 8;

    let src_low = e_extract(src.clone(), 0, width);
    let src_field = e_extract(src, lsb, width);

    let bitfield = match op {
        Op::UBFIZ => e_shl(src_low, Expr::Imm(lsb as u64)),
        Op::UBFX => src_field,
        Op::SBFIZ => e_sign_extend(
            e_shl(src_low, Expr::Imm(lsb as u64)),
            (lsb + width).min(reg_bits),
        ),
        Op::SBFX => e_sign_extend(src_field, width.min(reg_bits)),
        Op::BFI => e_insert(Expr::Reg(dst.clone()), src_low, lsb, width),
        Op::BFXIL => e_insert(Expr::Reg(dst.clone()), src_field, 0, width),
        _ => unreachable!("unsupported bitfield op: {:?}", op),
    };

    Stmt::Assign { dst, src: bitfield }
}

fn lift_load(operands: &[Operand], explicit_size: u8, signed: bool) -> Stmt {
    let dst = reg_op(operands, 0);
    let size = if explicit_size == 0 {
        operand_reg_size(operands, 0)
    } else {
        explicit_size
    };
    let addr = if operands.len() > 1 {
        expr_from_operand(&operands[1])
    } else {
        Expr::Imm(0)
    };
    let load_expr = e_load(addr, size);
    let src = if signed {
        e_sign_extend(load_expr, size * 8)
    } else {
        load_expr
    };
    let stmt = Stmt::Assign { dst, src };
    if let Some(mem) = operands.get(1) {
        wrap_mem_writeback(mem, stmt)
    } else {
        stmt
    }
}

fn lift_load_pair(operands: &[Operand], signed: bool) -> Stmt {
    let dst1 = reg_op(operands, 0);
    let dst2 = reg_op(operands, 1);
    let size = if signed {
        4
    } else {
        operand_reg_size(operands, 0)
    };
    let addr = if operands.len() > 2 {
        mem_to_addr(&operands[2])
    } else {
        Expr::Imm(0)
    };
    let load1 = e_load(addr.clone(), size);
    let load2 = e_load(e_add(addr, Expr::Imm(size as u64)), size);
    let src1 = if signed {
        e_sign_extend(load1, 32)
    } else {
        load1
    };
    let src2 = if signed {
        e_sign_extend(load2, 32)
    } else {
        load2
    };
    let stmt = Stmt::Pair(
        Box::new(Stmt::Assign {
            dst: dst1,
            src: src1,
        }),
        Box::new(Stmt::Assign {
            dst: dst2,
            src: src2,
        }),
    );
    if let Some(mem) = operands.get(2) {
        wrap_mem_writeback(mem, stmt)
    } else {
        stmt
    }
}

fn lift_load_pair_exclusive(operands: &[Operand]) -> Stmt {
    lift_load_pair(operands, false)
}

fn lift_store(operands: &[Operand], explicit_size: u8) -> Stmt {
    let value_expr = expr_op(operands, 0);
    let size = if explicit_size == 0 {
        operand_reg_size(operands, 0)
    } else {
        explicit_size
    };
    let addr = if operands.len() > 1 {
        mem_to_addr(&operands[1])
    } else {
        Expr::Imm(0)
    };
    let stmt = Stmt::Store {
        addr,
        value: value_expr,
        size,
    };
    if let Some(mem) = operands.get(1) {
        wrap_mem_writeback(mem, stmt)
    } else {
        stmt
    }
}

fn lift_store_exclusive(operands: &[Operand], explicit_size: u8) -> Stmt {
    // STLXR Ws, Xt, [Xn] — operands[0]=status, operands[1]=data, operands[2]=addr
    if operands.len() >= 3 {
        let value_expr = expr_op(operands, 1);
        let size = if explicit_size == 0 {
            operand_reg_size(operands, 1)
        } else {
            explicit_size
        };
        let addr = mem_to_addr(&operands[2]);
        let stmt = Stmt::Pair(
            Box::new(Stmt::Store {
                addr,
                value: value_expr,
                size,
            }),
            Box::new(Stmt::Assign {
                dst: reg_op(operands, 0),
                src: Expr::Imm(0),
            }),
        );
        if let Some(mem) = operands.get(2) {
            wrap_mem_writeback(mem, stmt)
        } else {
            stmt
        }
    } else {
        lift_store(operands, explicit_size)
    }
}

fn lift_store_pair_exclusive(operands: &[Operand]) -> Stmt {
    // STXP Ws, Xt1, Xt2, [Xn]
    if operands.len() >= 4 {
        let val1 = expr_op(operands, 1);
        let val2 = expr_op(operands, 2);
        let size = operand_reg_size(operands, 1);
        let addr = mem_to_addr(&operands[3]);
        let stmt = Stmt::Pair(
            Box::new(Stmt::Pair(
                Box::new(Stmt::Store {
                    addr: addr.clone(),
                    value: val1,
                    size,
                }),
                Box::new(Stmt::Store {
                    addr: e_add(addr, Expr::Imm(size as u64)),
                    value: val2,
                    size,
                }),
            )),
            Box::new(Stmt::Assign {
                dst: reg_op(operands, 0),
                src: Expr::Imm(0),
            }),
        );
        if let Some(mem) = operands.get(3) {
            wrap_mem_writeback(mem, stmt)
        } else {
            stmt
        }
    } else {
        lift_store_pair(operands)
    }
}

fn lift_store_pair(operands: &[Operand]) -> Stmt {
    let val1 = expr_op(operands, 0);
    let val2 = expr_op(operands, 1);
    let size = operand_reg_size(operands, 0);
    let addr = if operands.len() > 2 {
        mem_to_addr(&operands[2])
    } else {
        Expr::Imm(0)
    };
    let stmt = Stmt::Pair(
        Box::new(Stmt::Store {
            addr: addr.clone(),
            value: val1,
            size,
        }),
        Box::new(Stmt::Store {
            addr: e_add(addr, Expr::Imm(size as u64)),
            value: val2,
            size,
        }),
    );
    if let Some(mem) = operands.get(2) {
        wrap_mem_writeback(mem, stmt)
    } else {
        stmt
    }
}

fn lift_csel(operands: &[Operand], make: fn(Expr, Expr, Condition) -> Expr) -> Stmt {
    let dst = reg_op(operands, 0);
    let t = expr_op(operands, 1);
    let f = if operands.len() > 2 {
        expr_op(operands, 2)
    } else {
        t.clone()
    };
    let cond = if operands.len() > 3 {
        cond_op(operands, 3)
    } else if operands.len() > 2 {
        cond_op(operands, 2)
    } else {
        Condition::AL
    };
    Stmt::Assign {
        dst,
        src: make(t, f, cond),
    }
}

fn lift_cond_compare(operands: &[Operand], is_add: bool) -> Stmt {
    let lhs = expr_op(operands, 0);
    let rhs = expr_op(operands, 1);
    let nzcv = Expr::Imm(imm_val(operands, 2) & 0xf);
    let cond = cond_op(operands, 3);
    let compare_expr = if is_add {
        e_add(lhs, rhs)
    } else {
        e_sub(lhs, rhs)
    };

    Stmt::SetFlags {
        expr: e_cond_select(cond, compare_expr, nzcv),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Operand extraction
// ═══════════════════════════════════════════════════════════════════════

fn ft(edges: &mut Vec<u64>, next_pc: Option<u64>) {
    if let Some(npc) = next_pc {
        edges.push(npc);
    }
}

fn reg_op(operands: &[Operand], idx: usize) -> Reg {
    operands
        .get(idx)
        .and_then(|o| operand_to_reg(o))
        .unwrap_or(Reg::XZR)
}

fn operand_reg_size(operands: &[Operand], idx: usize) -> u8 {
    operands
        .get(idx)
        .and_then(size_from_operand)
        .unwrap_or_else(|| reg_size(&reg_op(operands, idx)))
}

fn size_from_operand(op: &Operand) -> Option<u8> {
    let reg = match op {
        Operand::Reg { reg, .. } | Operand::ShiftReg { reg, .. } => *reg,
        _ => return None,
    };

    let reg_name = format!("{}", reg);
    let size = match reg_name.as_str() {
        "sp" => 8,
        _ if reg_name.starts_with('w') => 4,
        _ if reg_name.starts_with('x') => 8,
        _ if reg_name.starts_with('d') => 8,
        _ if reg_name.starts_with('s') => 4,
        _ if reg_name.starts_with('h') => 2,
        _ if reg_name.starts_with('b') => 1,
        _ if reg_name.starts_with('v') || reg_name.starts_with('q') => 16,
        _ => reg_from_bad64(reg).map(|r| reg_size(&r)).unwrap_or(8),
    };

    Some(size)
}

fn expr_op(operands: &[Operand], idx: usize) -> Expr {
    operands
        .get(idx)
        .map(|o| expr_from_operand(o))
        .unwrap_or(Expr::Imm(0))
}

fn label_val(operands: &[Operand], idx: usize) -> u64 {
    match operands.get(idx) {
        Some(Operand::Label(imm)) => imm_to_u64(imm),
        Some(Operand::Imm64 { imm, .. }) => imm_to_u64(imm),
        Some(Operand::Imm32 { imm, .. }) => imm_to_u64(imm),
        Some(other) => {
            // Try to extract address from any operand
            if let Some(_r) = operand_to_reg(other) {
                0 // Register branch target — unknown at lift time
            } else {
                0
            }
        }
        None => 0,
    }
}

fn imm_val(operands: &[Operand], idx: usize) -> u64 {
    match operands.get(idx) {
        Some(Operand::Imm64 { imm, .. }) => imm_to_u64(imm),
        Some(Operand::Imm32 { imm, .. }) => imm_to_u64(imm),
        Some(Operand::Label(imm)) => imm_to_u64(imm),
        _ => 0,
    }
}

fn cond_op(operands: &[Operand], idx: usize) -> Condition {
    match operands.get(idx) {
        Some(Operand::Cond(c)) => cond_from_bad64(*c),
        _ => Condition::AL,
    }
}

fn imm_to_u64(imm: &Imm) -> u64 {
    match *imm {
        Imm::Signed(v) => v as u64,
        Imm::Unsigned(v) => v,
    }
}

fn operand_to_reg(op: &Operand) -> Option<Reg> {
    match op {
        Operand::Reg { reg, .. } => reg_from_bad64(*reg),
        Operand::ShiftReg { reg, .. } => reg_from_bad64(*reg),
        _ => None,
    }
}

fn expr_from_operand(op: &Operand) -> Expr {
    match op {
        Operand::Reg { reg, .. } => reg_from_bad64(*reg).map(Expr::Reg).unwrap_or(Expr::Imm(0)),
        Operand::ShiftReg { reg, shift } => {
            let base = reg_from_bad64(*reg).map(Expr::Reg).unwrap_or(Expr::Imm(0));
            apply_shift(base, *shift)
        }
        Operand::Imm64 { imm, shift } => {
            let val = Expr::Imm(imm_to_u64(imm));
            if let Some(s) = shift {
                apply_shift(val, *s)
            } else {
                val
            }
        }
        Operand::Imm32 { imm, shift } => {
            let val = Expr::Imm(imm_to_u64(imm));
            if let Some(s) = shift {
                apply_shift(val, *s)
            } else {
                val
            }
        }
        Operand::FImm32(bits) => Expr::FImm(f32::from_le_bytes(bits.to_le_bytes()) as f64),
        Operand::Label(imm) => Expr::Imm(imm_to_u64(imm)),
        Operand::Cond(c) => Expr::Imm(cond_from_bad64(*c) as u64),

        // Memory operands → produce the address expression
        Operand::MemReg(_)
        | Operand::MemOffset { .. }
        | Operand::MemPreIdx { .. }
        | Operand::MemPostIdxImm { .. }
        | Operand::MemPostIdxReg(_)
        | Operand::MemExt { .. } => mem_to_addr(op),

        Operand::SysReg(sr) => Expr::Intrinsic {
            name: format!("{}", sr),
            operands: vec![],
        },
        Operand::MultiReg { regs, .. } => {
            let reg_exprs: Vec<Expr> = regs
                .iter()
                .filter_map(|r| r.and_then(|rr| reg_from_bad64(rr).map(Expr::Reg)))
                .collect();
            Expr::Intrinsic {
                name: "multi_reg".to_string(),
                operands: reg_exprs,
            }
        }
        _ => Expr::Imm(0),
    }
}

fn mem_to_addr(op: &Operand) -> Expr {
    match op {
        Operand::MemReg(reg) => reg_from_bad64(*reg).map(Expr::Reg).unwrap_or(Expr::Imm(0)),
        Operand::MemOffset { reg, offset, .. } => {
            let base = reg_from_bad64(*reg).map(Expr::Reg).unwrap_or(Expr::Imm(0));
            let off_val = imm_to_u64(offset);
            if off_val == 0 {
                base
            } else {
                e_add(base, Expr::Imm(off_val))
            }
        }
        Operand::MemPreIdx { reg, imm } => {
            let base = reg_from_bad64(*reg).map(Expr::Reg).unwrap_or(Expr::Imm(0));
            let off_val = imm_to_u64(imm);
            if off_val == 0 {
                base
            } else {
                e_add(base, Expr::Imm(off_val))
            }
        }
        Operand::MemPostIdxImm { reg, .. } => {
            // Post-index: effective address is just the base register
            reg_from_bad64(*reg).map(Expr::Reg).unwrap_or(Expr::Imm(0))
        }
        Operand::MemPostIdxReg(regs) => reg_from_bad64(regs[0])
            .map(Expr::Reg)
            .unwrap_or(Expr::Imm(0)),
        Operand::MemExt { regs, shift, .. } => {
            let base = reg_from_bad64(regs[0])
                .map(Expr::Reg)
                .unwrap_or(Expr::Imm(0));
            let mut idx = reg_from_bad64(regs[1])
                .map(Expr::Reg)
                .unwrap_or(Expr::Imm(0));
            if let Some(s) = shift {
                idx = apply_shift(idx, *s);
            }
            e_add(base, idx)
        }
        _ => Expr::Imm(0),
    }
}

fn wrap_mem_writeback(mem: &Operand, stmt: Stmt) -> Stmt {
    match mem_writeback(mem) {
        Some((dst, src)) => Stmt::Pair(Box::new(stmt), Box::new(Stmt::Assign { dst, src })),
        None => stmt,
    }
}

fn mem_writeback(mem: &Operand) -> Option<(Reg, Expr)> {
    match mem {
        Operand::MemPreIdx { reg, imm } | Operand::MemPostIdxImm { reg, imm } => {
            let reg = reg_from_bad64(*reg)?;
            Some((
                reg.clone(),
                e_add(Expr::Reg(reg), Expr::Imm(imm_to_u64(imm))),
            ))
        }
        Operand::MemPostIdxReg(regs) => {
            let base = reg_from_bad64(regs[0])?;
            let offset = reg_from_bad64(regs[1])?;
            Some((base.clone(), e_add(Expr::Reg(base), Expr::Reg(offset))))
        }
        _ => None,
    }
}

fn apply_shift(expr: Expr, shift: Shift) -> Expr {
    match shift {
        Shift::LSL(0) => expr,
        Shift::LSL(n) => e_shl(expr, Expr::Imm(n as u64)),
        Shift::LSR(n) => e_lsr(expr, Expr::Imm(n as u64)),
        Shift::ASR(n) => e_asr(expr, Expr::Imm(n as u64)),
        Shift::ROR(n) => e_ror(expr, Expr::Imm(n as u64)),
        Shift::SXTW(n) => {
            let ext = e_sign_extend(expr, 32);
            if n == 0 {
                ext
            } else {
                e_shl(ext, Expr::Imm(n as u64))
            }
        }
        Shift::SXTX(n) => {
            if n == 0 {
                expr
            } else {
                e_shl(expr, Expr::Imm(n as u64))
            }
        }
        Shift::SXTB(n) => {
            let ext = e_sign_extend(expr, 8);
            if n == 0 {
                ext
            } else {
                e_shl(ext, Expr::Imm(n as u64))
            }
        }
        Shift::SXTH(n) => {
            let ext = e_sign_extend(expr, 16);
            if n == 0 {
                ext
            } else {
                e_shl(ext, Expr::Imm(n as u64))
            }
        }
        Shift::UXTW(n) => {
            let ext = e_zero_extend(expr, 32);
            if n == 0 {
                ext
            } else {
                e_shl(ext, Expr::Imm(n as u64))
            }
        }
        Shift::UXTX(n) => {
            if n == 0 {
                expr
            } else {
                e_shl(expr, Expr::Imm(n as u64))
            }
        }
        Shift::UXTB(n) => {
            let ext = e_zero_extend(expr, 8);
            if n == 0 {
                ext
            } else {
                e_shl(ext, Expr::Imm(n as u64))
            }
        }
        Shift::UXTH(n) => {
            let ext = e_zero_extend(expr, 16);
            if n == 0 {
                ext
            } else {
                e_shl(ext, Expr::Imm(n as u64))
            }
        }
        Shift::MSL(n) => e_intrinsic("msl", vec![expr, Expr::Imm(n as u64)]),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Register conversion
// ═══════════════════════════════════════════════════════════════════════

fn reg_from_bad64(r: bad64::Reg) -> Option<Reg> {
    use bad64::Reg as BR;
    match r {
        // General purpose — fast path
        BR::X0 => Some(Reg::X(0)),
        BR::X1 => Some(Reg::X(1)),
        BR::X2 => Some(Reg::X(2)),
        BR::X3 => Some(Reg::X(3)),
        BR::X4 => Some(Reg::X(4)),
        BR::X5 => Some(Reg::X(5)),
        BR::X6 => Some(Reg::X(6)),
        BR::X7 => Some(Reg::X(7)),
        BR::X8 => Some(Reg::X(8)),
        BR::X9 => Some(Reg::X(9)),
        BR::X10 => Some(Reg::X(10)),
        BR::X11 => Some(Reg::X(11)),
        BR::X12 => Some(Reg::X(12)),
        BR::X13 => Some(Reg::X(13)),
        BR::X14 => Some(Reg::X(14)),
        BR::X15 => Some(Reg::X(15)),
        BR::X16 => Some(Reg::X(16)),
        BR::X17 => Some(Reg::X(17)),
        BR::X18 => Some(Reg::X(18)),
        BR::X19 => Some(Reg::X(19)),
        BR::X20 => Some(Reg::X(20)),
        BR::X21 => Some(Reg::X(21)),
        BR::X22 => Some(Reg::X(22)),
        BR::X23 => Some(Reg::X(23)),
        BR::X24 => Some(Reg::X(24)),
        BR::X25 => Some(Reg::X(25)),
        BR::X26 => Some(Reg::X(26)),
        BR::X27 => Some(Reg::X(27)),
        BR::X28 => Some(Reg::X(28)),
        BR::X29 => Some(Reg::X(29)),
        BR::X30 => Some(Reg::X(30)),

        BR::W0 => Some(Reg::W(0)),
        BR::W1 => Some(Reg::W(1)),
        BR::W2 => Some(Reg::W(2)),
        BR::W3 => Some(Reg::W(3)),
        BR::W4 => Some(Reg::W(4)),
        BR::W5 => Some(Reg::W(5)),
        BR::W6 => Some(Reg::W(6)),
        BR::W7 => Some(Reg::W(7)),
        BR::W8 => Some(Reg::W(8)),
        BR::W9 => Some(Reg::W(9)),
        BR::W10 => Some(Reg::W(10)),
        BR::W11 => Some(Reg::W(11)),
        BR::W12 => Some(Reg::W(12)),
        BR::W13 => Some(Reg::W(13)),
        BR::W14 => Some(Reg::W(14)),
        BR::W15 => Some(Reg::W(15)),
        BR::W16 => Some(Reg::W(16)),
        BR::W17 => Some(Reg::W(17)),
        BR::W18 => Some(Reg::W(18)),
        BR::W19 => Some(Reg::W(19)),
        BR::W20 => Some(Reg::W(20)),
        BR::W21 => Some(Reg::W(21)),
        BR::W22 => Some(Reg::W(22)),
        BR::W23 => Some(Reg::W(23)),
        BR::W24 => Some(Reg::W(24)),
        BR::W25 => Some(Reg::W(25)),
        BR::W26 => Some(Reg::W(26)),
        BR::W27 => Some(Reg::W(27)),
        BR::W28 => Some(Reg::W(28)),
        BR::W29 => Some(Reg::W(29)),
        BR::W30 => Some(Reg::W(30)),

        BR::SP => Some(Reg::SP),
        BR::WSP => Some(Reg::SP),
        BR::XZR => Some(Reg::XZR),
        BR::WZR => Some(Reg::XZR),

        // FP/SIMD — use string fallback for compactness
        _ => reg_from_string(&format!("{}", r)),
    }
}

fn reg_from_string(s: &str) -> Option<Reg> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let (prefix, rest) = if bytes.len() > 1 {
        (bytes[0], &s[1..])
    } else {
        return None;
    };

    match prefix {
        b'v' => rest.parse().ok().filter(|&n: &u8| n < 32).map(Reg::V),
        b'q' => rest.parse().ok().filter(|&n: &u8| n < 32).map(Reg::Q),
        b'd' => rest.parse().ok().filter(|&n: &u8| n < 32).map(Reg::D),
        b's' => {
            // Avoid matching "sp"
            if rest == "p" {
                return Some(Reg::SP);
            }
            rest.parse().ok().filter(|&n: &u8| n < 32).map(Reg::S)
        }
        b'h' => rest.parse().ok().filter(|&n: &u8| n < 32).map(Reg::H),
        b'b' => rest
            .parse()
            .ok()
            .filter(|&n: &u8| n < 32)
            .map(|n| Reg::VByte(n)),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Condition code conversion
// ═══════════════════════════════════════════════════════════════════════

fn cond_from_bad64(c: bad64::Condition) -> Condition {
    match c {
        bad64::Condition::EQ => Condition::EQ,
        bad64::Condition::NE => Condition::NE,
        bad64::Condition::CS => Condition::CS,
        bad64::Condition::CC => Condition::CC,
        bad64::Condition::MI => Condition::MI,
        bad64::Condition::PL => Condition::PL,
        bad64::Condition::VS => Condition::VS,
        bad64::Condition::VC => Condition::VC,
        bad64::Condition::HI => Condition::HI,
        bad64::Condition::LS => Condition::LS,
        bad64::Condition::GE => Condition::GE,
        bad64::Condition::LT => Condition::LT,
        bad64::Condition::GT => Condition::GT,
        bad64::Condition::LE => Condition::LE,
        bad64::Condition::AL => Condition::AL,
        bad64::Condition::NV => Condition::NV,
    }
}

fn cond_from_branch_op(op: Op) -> Condition {
    match op {
        Op::B_EQ => Condition::EQ,
        Op::B_NE => Condition::NE,
        Op::B_CS => Condition::CS,
        Op::B_CC => Condition::CC,
        Op::B_MI => Condition::MI,
        Op::B_PL => Condition::PL,
        Op::B_VS => Condition::VS,
        Op::B_VC => Condition::VC,
        Op::B_HI => Condition::HI,
        Op::B_LS => Condition::LS,
        Op::B_GE => Condition::GE,
        Op::B_LT => Condition::LT,
        Op::B_GT => Condition::GT,
        Op::B_LE => Condition::LE,
        Op::B_AL => Condition::AL,
        Op::B_NV => Condition::NV,
        _ => Condition::AL,
    }
}

// Helper for formatting operands (used in MRS)
struct DisplayOperand<'a>(&'a Operand);
impl<'a> std::fmt::Display for DisplayOperand<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Operand::SysReg(sr) => write!(f, "{}", sr),
            _ => write!(f, "?"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lift_word(word: u32, pc: u64) -> LiftResult {
        let insn = bad64::decode(word, pc).expect("instruction should decode");
        lift(&insn, pc, Some(pc + 4))
    }

    #[test]
    fn lifts_char_respawn_cbnz() {
        let pc = 0x07a34a78;
        let result = lift_word(0x3500_02c8, pc);

        assert_eq!(
            result.stmt,
            Stmt::CondBranch {
                cond: BranchCond::NotZero(Expr::Reg(Reg::W(8))),
                target: Expr::Imm(0x07a34ad0),
                fallthrough: pc + 4,
            }
        );
        assert_eq!(result.edges, vec![0x07a34ad0, pc + 4]);
    }

    #[test]
    fn lifts_char_respawn_cmp_w8_imm1() {
        let pc = 0x07a34a80;
        let result = lift_word(0x7100_051f, pc);

        assert_eq!(
            result.stmt,
            Stmt::SetFlags {
                expr: e_sub(Expr::Reg(Reg::W(8)), Expr::Imm(1)),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_char_respawn_b_ne() {
        let pc = 0x07a34a84;
        let result = lift_word(0x5400_0201, pc);

        assert_eq!(
            result.stmt,
            Stmt::CondBranch {
                cond: BranchCond::Flag(Condition::NE),
                target: Expr::Imm(0x07a34ac4),
                fallthrough: pc + 4,
            }
        );
        assert_eq!(result.edges, vec![0x07a34ac4, pc + 4]);
    }

    #[test]
    fn lifts_ldr_literal_as_absolute_load() {
        let pc = 0x9b6117ac;
        let result = lift_word(0x5800_11c0, pc);

        assert_eq!(
            result.stmt,
            Stmt::Assign {
                dst: Reg::X(0),
                src: e_load(Expr::Imm(0x9b6119e4), 8),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_vector_movi_with_arrangement() {
        let pc = 0x4cbe0;
        let result = lift_word(0x6f07_e7e0, pc);

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "movi.2d".to_string(),
                operands: vec![Expr::Reg(Reg::V(0)), Expr::Imm(u64::MAX)],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_cmeq_with_arrangement() {
        let pc = 0x4cc14;
        let result = lift_word(0x2ea1_8c01, pc);

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "cmeq.2s".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(1)),
                    Expr::Reg(Reg::V(0)),
                    Expr::Reg(Reg::V(1)),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_bif_with_arrangement() {
        let pc = 0x4cc18;
        let result = lift_word(0x2ee1_1c02, pc);

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "bif.8b".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(2)),
                    Expr::Reg(Reg::V(0)),
                    Expr::Reg(Reg::V(1)),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_umov_lane_extract() {
        let pc = 0x73b69c;
        let result = lift_word(0x0e02_3c1a, pc);

        assert_eq!(
            result.stmt,
            Stmt::Assign {
                dst: Reg::W(26),
                src: e_extract(Expr::Reg(Reg::V(0)), 0, 16),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_vector_add_with_arrangement() {
        let pc = 0x73b4bc;
        let result = lift_word(0x4ee0_8420, pc);

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "add.2d".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(0)),
                    Expr::Reg(Reg::V(1)),
                    Expr::Reg(Reg::V(0)),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_ldxp_as_pair_load() {
        let pc = 0x297678;
        let result = lift_word(0xc87f_2120, pc);

        assert_eq!(
            result.stmt,
            Stmt::Pair(
                Box::new(Stmt::Assign {
                    dst: Reg::X(0),
                    src: e_load(Expr::Reg(Reg::X(9)), 8),
                }),
                Box::new(Stmt::Assign {
                    dst: Reg::X(8),
                    src: e_load(e_add(Expr::Reg(Reg::X(9)), Expr::Imm(8)), 8),
                }),
            )
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_stxp_as_pair_store_and_success_status() {
        let pc = 0x29767c;
        let result = lift_word(0xc82a_2120, pc);

        assert_eq!(
            result.stmt,
            Stmt::Pair(
                Box::new(Stmt::Pair(
                    Box::new(Stmt::Store {
                        addr: Expr::Reg(Reg::X(9)),
                        value: Expr::Reg(Reg::X(0)),
                        size: 8,
                    }),
                    Box::new(Stmt::Store {
                        addr: e_add(Expr::Reg(Reg::X(9)), Expr::Imm(8)),
                        value: Expr::Reg(Reg::X(8)),
                        size: 8,
                    }),
                )),
                Box::new(Stmt::Assign {
                    dst: Reg::W(10),
                    src: Expr::Imm(0),
                }),
            )
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_char_respawn_cmp_x8_x9() {
        let pc = 0x07a34a9c;
        let result = lift_word(0xeb09_011f, pc);

        assert_eq!(
            result.stmt,
            Stmt::SetFlags {
                expr: e_sub(Expr::Reg(Reg::X(8)), Expr::Reg(Reg::X(9))),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_char_respawn_cset_hs() {
        let pc = 0x07a34aa0;
        let result = lift_word(0x1a9f_37ea, pc);

        assert_eq!(
            result.stmt,
            Stmt::Assign {
                dst: Reg::W(10),
                src: e_cond_select(Condition::CS, Expr::Imm(1), Expr::Imm(0)),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_char_respawn_lsl_w10_2() {
        let pc = 0x07a34aa4;
        let result = lift_word(0x531e_754a, pc);

        assert_eq!(
            result.stmt,
            Stmt::Assign {
                dst: Reg::W(10),
                src: e_shl(Expr::Reg(Reg::W(10)), Expr::Imm(2)),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_char_respawn_b_hs() {
        let pc = 0x07a34aac;
        let result = lift_word(0x5400_0142, pc);

        assert_eq!(
            result.stmt,
            Stmt::CondBranch {
                cond: BranchCond::Flag(Condition::CS),
                target: Expr::Imm(0x07a34ad4),
                fallthrough: pc + 4,
            }
        );
        assert_eq!(result.edges, vec![0x07a34ad4, pc + 4]);
    }

    #[test]
    fn lifts_char_respawn_cmp_x10_x9() {
        let pc = 0x07a34ab4;
        let result = lift_word(0xeb09_015f, pc);

        assert_eq!(
            result.stmt,
            Stmt::SetFlags {
                expr: e_sub(Expr::Reg(Reg::X(10)), Expr::Reg(Reg::X(9))),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_char_respawn_b_ls() {
        let pc = 0x07a34ab8;
        let result = lift_word(0x5400_0129, pc);

        assert_eq!(
            result.stmt,
            Stmt::CondBranch {
                cond: BranchCond::Flag(Condition::LS),
                target: Expr::Imm(0x07a34adc),
                fallthrough: pc + 4,
            }
        );
        assert_eq!(result.edges, vec![0x07a34adc, pc + 4]);
    }

    #[test]
    fn lifts_char_respawn_b_to_store_site() {
        let pc = 0x07a34ac0;
        let result = lift_word(0x1400_0004, pc);

        assert_eq!(
            result.stmt,
            Stmt::Branch {
                target: Expr::Imm(0x07a34ad0),
            }
        );
        assert_eq!(result.edges, vec![0x07a34ad0]);
    }

    #[test]
    fn lifts_char_respawn_b_to_store_site_from_second_path() {
        let pc = 0x07a34ac8;
        let result = lift_word(0x1400_0002, pc);

        assert_eq!(
            result.stmt,
            Stmt::Branch {
                target: Expr::Imm(0x07a34ad0),
            }
        );
        assert_eq!(result.edges, vec![0x07a34ad0]);
    }

    #[test]
    fn lifts_char_respawn_store_wzr_as_32bit_store() {
        let pc = 0x07a34ad4;
        let result = lift_word(0xb900_081f, pc);

        assert_eq!(
            result.stmt,
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::X(0)), Expr::Imm(8)),
                value: Expr::Reg(Reg::XZR),
                size: 4,
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_ccmp_register_form_as_conditional_flag_update() {
        let pc = 0x1000;
        let result = lift_word(0x7a57_00c1, pc); // ccmp w6, w23, #0x1, eq

        assert_eq!(
            result.stmt,
            Stmt::SetFlags {
                expr: e_cond_select(
                    Condition::EQ,
                    e_sub(Expr::Reg(Reg::W(6)), Expr::Reg(Reg::W(23))),
                    Expr::Imm(0x1),
                ),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_ccmn_immediate_form_as_conditional_flag_update() {
        let pc = 0x2000;
        let result = lift_word(0xba4a_280d, pc); // ccmn x0, #0xa, #0xd, hs

        assert_eq!(
            result.stmt,
            Stmt::SetFlags {
                expr: e_cond_select(
                    Condition::CS,
                    e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0xa)),
                    Expr::Imm(0xd),
                ),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_ldrb_post_index_with_base_writeback() {
        let pc = 0x3000;
        let result = lift_word(0x3840_1441, pc); // ldrb w1, [x2], #1

        assert_eq!(
            result.stmt,
            Stmt::Pair(
                Box::new(Stmt::Assign {
                    dst: Reg::W(1),
                    src: e_load(Expr::Reg(Reg::X(2)), 1),
                }),
                Box::new(Stmt::Assign {
                    dst: Reg::X(2),
                    src: e_add(Expr::Reg(Reg::X(2)), Expr::Imm(1)),
                }),
            )
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_stp_pre_index_with_sp_writeback() {
        let pc = 0x4000;
        let sp_minus_32 = e_add(Expr::Reg(Reg::SP), Expr::Imm((-32i64) as u64));
        let result = lift_word(0xa9be_7bfd, pc); // stp x29, x30, [sp, #-32]!

        assert_eq!(
            result.stmt,
            Stmt::Pair(
                Box::new(Stmt::Pair(
                    Box::new(Stmt::Store {
                        addr: sp_minus_32.clone(),
                        value: Expr::Reg(Reg::X(29)),
                        size: 8,
                    }),
                    Box::new(Stmt::Store {
                        addr: e_add(sp_minus_32.clone(), Expr::Imm(8)),
                        value: Expr::Reg(Reg::X(30)),
                        size: 8,
                    }),
                )),
                Box::new(Stmt::Assign {
                    dst: Reg::SP,
                    src: sp_minus_32,
                }),
            )
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_ldp_post_index_with_sp_writeback() {
        let pc = 0x5000;
        let result = lift_word(0xa8c2_7bfd, pc); // ldp x29, x30, [sp], #32

        assert_eq!(
            result.stmt,
            Stmt::Pair(
                Box::new(Stmt::Pair(
                    Box::new(Stmt::Assign {
                        dst: Reg::X(29),
                        src: e_load(Expr::Reg(Reg::SP), 8),
                    }),
                    Box::new(Stmt::Assign {
                        dst: Reg::X(30),
                        src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
                    }),
                )),
                Box::new(Stmt::Assign {
                    dst: Reg::SP,
                    src: e_add(Expr::Reg(Reg::SP), Expr::Imm(32)),
                }),
            )
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_vector_fcvtzu_as_arranged_intrinsic() {
        let pc = 0x6000;
        let result = lift_word(0x6f4e_fd10, pc); // fcvtzu v16.2d, v8.2d, #0x32

        assert_eq!(
            result.stmt,
            Stmt::Assign {
                dst: Reg::V(16),
                src: e_intrinsic("fcvtzu.2d", vec![Expr::Reg(Reg::V(8))]),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_vector_ucvtf_as_arranged_intrinsic() {
        let pc = 0x7000;
        let result = lift_word(0x6f44_e460, pc); // ucvtf v0.2d, v3.2d, #0x3c

        assert_eq!(
            result.stmt,
            Stmt::Assign {
                dst: Reg::V(0),
                src: e_intrinsic("ucvtf.2d", vec![Expr::Reg(Reg::V(3))]),
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_sri_with_arrangement() {
        let pc = 0x7800;
        let result = lift_word(0x6f4b_46f8, pc); // sri v24.2d, v23.2d, #0x35

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "sri.2d".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(24)),
                    Expr::Reg(Reg::V(23)),
                    Expr::Imm(0x35)
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_sqshlu_with_arrangement() {
        let pc = 0x7900;
        let result = lift_word(0x6f51_67d8, pc); // sqshlu v24.2d, v30.2d, #0x11

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "sqshlu.2d".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(24)),
                    Expr::Reg(Reg::V(30)),
                    Expr::Imm(0x11)
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_ld1_with_arrangement_and_multireg_operand() {
        let pc = 0x7a00;
        let result = lift_word(0x0cdf_747f, pc); // ld1 {v31.8b}, [x3], #0x8

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "ld1.4h".to_string(),
                operands: vec![
                    Expr::Intrinsic {
                        name: "multi_reg".to_string(),
                        operands: vec![Expr::Reg(Reg::V(31))],
                    },
                    Expr::Reg(Reg::X(3)),
                    Expr::Imm(0x8),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_st1_with_arrangement_and_multireg_operand() {
        let pc = 0x7b00;
        let result = lift_word(0x4c9f_761f, pc); // st1 {v31.8h}, [x16], #0x10

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "st1.8h".to_string(),
                operands: vec![
                    Expr::Intrinsic {
                        name: "multi_reg".to_string(),
                        operands: vec![Expr::Reg(Reg::V(31))],
                    },
                    Expr::Reg(Reg::X(16)),
                    Expr::Imm(0x10),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_uqrshrn2_with_arrangement() {
        let pc = 0x7c00;
        let result = lift_word(0x6f3e_9f08, pc); // uqrshrn2 v8.4s, v24.2d, #0x2

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "uqrshrn2.4s".to_string(),
                operands: vec![Expr::Reg(Reg::V(8)), Expr::Reg(Reg::V(24)), Expr::Imm(0x2)],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_umull2_with_lane_extract_operand() {
        let pc = 0x8000;
        let result = lift_word(0x6f4b_a090, pc); // umull2 v16.4s, v4.8h, v11.h[0]

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "umull2.4s".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(16)),
                    Expr::Reg(Reg::V(4)),
                    e_extract(Expr::Reg(Reg::V(11)), 0, 16),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_mla_with_lane_extract_operand() {
        let pc = 0x9000;
        let result = lift_word(0x6f54_02a0, pc); // mla v0.8h, v21.8h, v4.h[1]

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "mla.8h".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(0)),
                    Expr::Reg(Reg::V(21)),
                    e_extract(Expr::Reg(Reg::V(4)), 16, 16),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_umlsl2_with_lane_extract_operand() {
        let pc = 0x9800;
        let result = lift_word(0x6f60_69f8, pc); // umlsl2 v24.4s, v15.8h, v0.h[6]

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "umlsl2.4s".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(24)),
                    Expr::Reg(Reg::V(15)),
                    e_extract(Expr::Reg(Reg::V(0)), 96, 16),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_fcmla_with_lane_extract_and_rotation_operand() {
        let pc = 0xa000;
        let result = lift_word(0x6f46_5b68, pc); // fcmla v8.8h, v27.8h, v6.h[2], #0xb4

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "fcmla.8h".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(8)),
                    Expr::Reg(Reg::V(27)),
                    e_extract(Expr::Reg(Reg::V(6)), 32, 16),
                    Expr::Imm(0xb4),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }

    #[test]
    fn lifts_fmulx_with_lane_extract_operand() {
        let pc = 0xa100;
        let result = lift_word(0x6fc4_9038, pc); // fmulx v24.2d, v1.2d, v4.d[0]

        assert_eq!(
            result.stmt,
            Stmt::Intrinsic {
                name: "fmulx.2d".to_string(),
                operands: vec![
                    Expr::Reg(Reg::V(24)),
                    Expr::Reg(Reg::V(1)),
                    e_extract(Expr::Reg(Reg::V(4)), 0, 64),
                ],
            }
        );
        assert_eq!(result.edges, vec![pc + 4]);
    }
}
