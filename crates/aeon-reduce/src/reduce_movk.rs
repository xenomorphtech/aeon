//! MOVZ/MOVK chain reduction -- collapses a sequence of MOVZ + MOVK inserts
//! that build a wide immediate into a single `Expr::Imm(u64)` when all
//! components are statically known.
//!
//! The lifter emits MOVK as:
//!   Stmt::Assign { dst: X(n), src: Intrinsic("movk", [Reg(X(n)), shifted]) }
//! where `shifted` is either:
//!   - `Shl(Imm(raw), Imm(shift))` when shift > 0  (from apply_shift)
//!   - `Imm(raw)` when shift == 0  (LSL #0 / no shift)
//!
//! MOVK semantics: replace the 16-bit chunk at the shift position, keeping all
//! other bits of the destination register unchanged.

use crate::env::RegisterEnv;
use aeonil::{Expr, Stmt};

/// Extract the (shifted_value, mask) pair from a MOVK shifted-immediate operand.
///
/// Returns `Some((value_to_OR, mask_of_chunk))` or `None` if the operand isn't
/// a recognized form.
fn extract_movk_imm(operand: &Expr) -> Option<(u64, u64)> {
    match operand {
        // Shl(Imm(raw), Imm(shift)) — produced by apply_shift for LSL #16/32/48
        Expr::Shl(raw, shift) => {
            if let (Expr::Imm(raw_val), Expr::Imm(shift_amt)) = (raw.as_ref(), shift.as_ref()) {
                let shifted_val = raw_val.wrapping_shl(*shift_amt as u32);
                let mask = 0xFFFF_u64.wrapping_shl(*shift_amt as u32);
                Some((shifted_val, mask))
            } else {
                None
            }
        }
        // Imm(val) — produced by apply_shift for LSL #0, or a pre-shifted constant.
        // If the immediate fits in 16 bits it's an unshifted MOVK (LSL #0).
        // If it doesn't, it's a pre-shifted value and we detect the chunk position.
        Expr::Imm(val) => {
            let mask = compute_movk_mask(*val);
            Some((*val, mask))
        }
        _ => None,
    }
}

/// Given a shifted immediate value, compute the 16-bit chunk mask.
///
/// For a value like `0x56780000`, the nonzero bits sit in bits [16..32),
/// so the mask is `0xFFFF0000`.  If the value is zero, we default to the
/// lowest chunk (mask = `0xFFFF`) since we can't determine the position.
fn compute_movk_mask(shifted_imm: u64) -> u64 {
    if shifted_imm == 0 {
        // Zero-insert at unknown position; default to chunk 0.
        return 0xFFFF;
    }

    // Find which 16-bit aligned chunk contains nonzero bits.
    // MOVK always targets exactly one 16-bit chunk, so we pick the lowest
    // chunk that has any nonzero bits.
    for chunk in 0..4u32 {
        let shift = chunk * 16;
        if (shifted_imm >> shift) & 0xFFFF != 0 {
            return 0xFFFF_u64 << shift;
        }
    }

    // Fallback (shouldn't happen for valid MOVK immediates)
    0xFFFF
}

/// Resolve MOVK intrinsic chains into folded immediates.
///
/// Walks the statement list forward, tracking known register values.  When a
/// MOVK intrinsic is encountered whose destination has a known `Imm` value
/// and whose shifted-immediate operand is a constant, the MOVK is folded into
/// a single `Imm` assignment.
pub fn resolve_movk_chains(stmts: Vec<Stmt>) -> Vec<Stmt> {
    resolve_movk_chains_with_stats(stmts).0
}

pub(crate) fn resolve_movk_chains_with_stats(stmts: Vec<Stmt>) -> (Vec<Stmt>, usize) {
    let mut env = RegisterEnv::new();
    let mut result = Vec::with_capacity(stmts.len());
    let mut resolutions = 0usize;

    for stmt in stmts {
        match &stmt {
            Stmt::Assign {
                dst,
                src: Expr::Intrinsic { name, operands },
            } if name == "movk" && operands.len() == 2 => {
                // operands[0] is Reg(dst) — the old value
                // operands[1] is the shifted immediate
                if let Some(Expr::Imm(old_val)) = env.lookup(dst).cloned() {
                    if let Some((shifted_val, mask)) = extract_movk_imm(&operands[1]) {
                        let new_val = (old_val & !mask) | shifted_val;
                        let folded = Expr::Imm(new_val);
                        env.assign(dst.clone(), folded.clone());
                        result.push(Stmt::Assign {
                            dst: dst.clone(),
                            src: folded,
                        });
                        resolutions += 1;
                        continue;
                    }
                }
                // Can't resolve — emit as-is and bind the intrinsic expression
                let src_clone = Expr::Intrinsic {
                    name: name.clone(),
                    operands: operands.clone(),
                };
                env.assign(dst.clone(), src_clone);
                result.push(stmt);
            }
            Stmt::Assign { dst, src } => {
                env.assign(dst.clone(), src.clone());
                result.push(stmt);
            }
            Stmt::Call { .. } => {
                result.push(stmt);
                env.invalidate_caller_saved();
            }
            _ => result.push(stmt),
        }
    }
    (result, resolutions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_intrinsic, e_shl, Expr, Reg, Stmt};

    /// Helper: make a MOVZ-style assignment (just an Imm assign).
    fn movz(reg: Reg, imm: u64) -> Stmt {
        Stmt::Assign {
            dst: reg,
            src: Expr::Imm(imm),
        }
    }

    /// Helper: make a MOVK intrinsic with Shl operand (shift > 0).
    fn movk_shl(reg: Reg, raw: u64, shift: u64) -> Stmt {
        Stmt::Assign {
            dst: reg.clone(),
            src: e_intrinsic(
                "movk",
                vec![Expr::Reg(reg), e_shl(Expr::Imm(raw), Expr::Imm(shift))],
            ),
        }
    }

    /// Helper: make a MOVK intrinsic with a plain Imm operand (shift == 0).
    fn movk_imm(reg: Reg, imm: u64) -> Stmt {
        Stmt::Assign {
            dst: reg.clone(),
            src: e_intrinsic("movk", vec![Expr::Reg(reg), Expr::Imm(imm)]),
        }
    }

    #[test]
    fn movz_movk_2step() {
        // MOVZ X0, #0x1234
        // MOVK X0, #0x5678, LSL #16
        // Expected: X0 = 0x56781234
        let stmts = vec![movz(Reg::X(0), 0x1234), movk_shl(Reg::X(0), 0x5678, 16)];
        let result = resolve_movk_chains(stmts);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0x56781234),
            }
        );
    }

    #[test]
    fn movz_movk_4step() {
        // Full 64-bit constant: 0xDEF09ABC56781234
        let stmts = vec![
            movz(Reg::X(0), 0x1234),
            movk_shl(Reg::X(0), 0x5678, 16),
            movk_shl(Reg::X(0), 0x9ABC, 32),
            movk_shl(Reg::X(0), 0xDEF0, 48),
        ];
        let result = resolve_movk_chains(stmts);
        assert_eq!(result.len(), 4);
        assert_eq!(
            result[3],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0xDEF0_9ABC_5678_1234),
            }
        );
        // Each intermediate step should also be folded
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0x5678_1234),
            }
        );
        assert_eq!(
            result[2],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0x9ABC_5678_1234),
            }
        );
    }

    #[test]
    fn movz_movk_partial() {
        // Only MOVZ + 1 MOVK (low 32 bits)
        let stmts = vec![movz(Reg::X(0), 0xAAAA), movk_shl(Reg::X(0), 0xBBBB, 16)];
        let result = resolve_movk_chains(stmts);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0xBBBBAAAA),
            }
        );
    }

    #[test]
    fn movz_movk_clobbered() {
        // MOVZ X0, #0x1234
        // X0 = X1  (clobber — breaks the chain)
        // MOVK X0, #0x5678, LSL #16
        // The MOVK can't resolve because X0 is no longer a known Imm.
        let stmts = vec![
            movz(Reg::X(0), 0x1234),
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Reg(Reg::X(1)),
            },
            movk_shl(Reg::X(0), 0x5678, 16),
        ];
        let result = resolve_movk_chains(stmts);
        assert_eq!(result.len(), 3);
        // The MOVK should remain as an intrinsic
        match &result[2] {
            Stmt::Assign {
                src: Expr::Intrinsic { name, .. },
                ..
            } => assert_eq!(name, "movk"),
            other => panic!("expected intrinsic movk, got {:?}", other),
        }
    }

    #[test]
    fn movk_shift_correctness() {
        // Verify each of the four 16-bit chunk positions
        let base = 0x0000_0000_0000_0000u64;

        // Chunk 0 (bits [0..16)) — uses plain Imm (LSL #0)
        let stmts = vec![movz(Reg::X(0), base), movk_imm(Reg::X(0), 0xAAAA)];
        let result = resolve_movk_chains(stmts);
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0xAAAA),
            }
        );

        // Chunk 1 (bits [16..32))
        let stmts = vec![movz(Reg::X(0), base), movk_shl(Reg::X(0), 0xBBBB, 16)];
        let result = resolve_movk_chains(stmts);
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0xBBBB_0000),
            }
        );

        // Chunk 2 (bits [32..48))
        let stmts = vec![movz(Reg::X(0), base), movk_shl(Reg::X(0), 0xCCCC, 32)];
        let result = resolve_movk_chains(stmts);
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0xCCCC_0000_0000),
            }
        );

        // Chunk 3 (bits [48..64))
        let stmts = vec![movz(Reg::X(0), base), movk_shl(Reg::X(0), 0xDDDD, 48)];
        let result = resolve_movk_chains(stmts);
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0xDDDD_0000_0000_0000),
            }
        );
    }

    #[test]
    fn movz_movk_w_register() {
        // W register variant (32-bit)
        // MOVZ W0, #0x1234
        // MOVK W0, #0xABCD, LSL #16
        let stmts = vec![movz(Reg::W(0), 0x1234), movk_shl(Reg::W(0), 0xABCD, 16)];
        let result = resolve_movk_chains(stmts);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::W(0),
                src: Expr::Imm(0xABCD_1234),
            }
        );
    }

    #[test]
    fn movk_with_pre_shifted_imm() {
        // If somehow the lifter produces a pre-shifted Imm (not Shl form)
        // e.g., Imm(0x56780000) for LSL #16
        let stmts = vec![
            movz(Reg::X(0), 0x1234),
            Stmt::Assign {
                dst: Reg::X(0),
                src: e_intrinsic("movk", vec![Expr::Reg(Reg::X(0)), Expr::Imm(0x5678_0000)]),
            },
        ];
        let result = resolve_movk_chains(stmts);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[1],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0x5678_1234),
            }
        );
    }

    #[test]
    fn movk_preserves_other_bits() {
        // Start with all bits set, then MOVK zeros into chunk 1
        // MOVZ X0, #0xFFFF
        // MOVK X0, #0xFFFF, LSL #16
        // MOVK X0, #0xFFFF, LSL #32
        // MOVK X0, #0xFFFF, LSL #48
        // Now X0 = 0xFFFF_FFFF_FFFF_FFFF
        // MOVK X0, #0x0000, LSL #16 → replace chunk 1 with zeros
        // This is the zero-insert edge case; with Shl form we know the position.
        let stmts = vec![
            movz(Reg::X(0), 0xFFFF),
            movk_shl(Reg::X(0), 0xFFFF, 16),
            movk_shl(Reg::X(0), 0xFFFF, 32),
            movk_shl(Reg::X(0), 0xFFFF, 48),
            // MOVK X0, #0x0000, LSL #16 — zero-insert using Shl form
            movk_shl(Reg::X(0), 0x0000, 16),
        ];
        let result = resolve_movk_chains(stmts);
        assert_eq!(result.len(), 5);
        // After zero-insert at chunk 1: 0xFFFF_FFFF_0000_FFFF
        assert_eq!(
            result[4],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0xFFFF_FFFF_0000_FFFF),
            }
        );
    }

    #[test]
    fn movk_call_invalidates_chain() {
        // MOVZ X0, #0x1234
        // CALL (clobbers caller-saved regs)
        // MOVK X0, #0x5678, LSL #16 — chain broken
        let stmts = vec![
            movz(Reg::X(0), 0x1234),
            Stmt::Call {
                target: Expr::Imm(0xDEAD),
            },
            movk_shl(Reg::X(0), 0x5678, 16),
        ];
        let result = resolve_movk_chains(stmts);
        assert_eq!(result.len(), 3);
        // MOVK should stay as intrinsic because the call invalidated X0
        match &result[2] {
            Stmt::Assign {
                src: Expr::Intrinsic { name, .. },
                ..
            } => assert_eq!(name, "movk"),
            other => panic!("expected intrinsic movk, got {:?}", other),
        }
    }

    #[test]
    fn movk_callee_saved_survives_call() {
        // X19 is callee-saved, so it survives a call
        let stmts = vec![
            movz(Reg::X(19), 0x1234),
            Stmt::Call {
                target: Expr::Imm(0xDEAD),
            },
            movk_shl(Reg::X(19), 0x5678, 16),
        ];
        let result = resolve_movk_chains(stmts);
        assert_eq!(result.len(), 3);
        assert_eq!(
            result[2],
            Stmt::Assign {
                dst: Reg::X(19),
                src: Expr::Imm(0x5678_1234),
            }
        );
    }

    #[test]
    fn compute_movk_mask_chunks() {
        assert_eq!(compute_movk_mask(0x1234), 0xFFFF);
        assert_eq!(compute_movk_mask(0x1234_0000), 0xFFFF_0000);
        assert_eq!(compute_movk_mask(0x1234_0000_0000), 0xFFFF_0000_0000);
        assert_eq!(
            compute_movk_mask(0x1234_0000_0000_0000),
            0xFFFF_0000_0000_0000
        );
        // Zero defaults to chunk 0
        assert_eq!(compute_movk_mask(0), 0xFFFF);
    }
}
