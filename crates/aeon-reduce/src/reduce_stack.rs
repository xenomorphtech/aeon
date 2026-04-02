//! Stack slot analysis -- identifies SP-relative loads and stores that form
//! local variable accesses, converts them into named stack slots, and
//! eliminates dead stores to slots that are never read.

use aeonil::{Expr, Reg, Stmt};

/// Information about the function prologue detected from flattened statements.
#[derive(Debug, Clone, PartialEq)]
pub struct PrologueInfo {
    /// Total frame size in bytes (the amount SP was decremented).
    pub frame_size: u64,
    /// Whether a frame pointer (X29) was set up via `MOV X29, SP`.
    pub has_frame_pointer: bool,
    /// Index of the first statement after the prologue.
    pub prologue_end: usize,
    /// Callee-saved registers stored in the prologue, with their SP-relative offsets.
    pub saved_regs: Vec<(Reg, i64)>,
}

/// Returns true if the register is a callee-saved general-purpose register (X19..X28).
fn is_callee_saved(reg: &Reg) -> bool {
    matches!(reg, Reg::X(n) if *n >= 19 && *n <= 28)
}

/// Interpret a u64 immediate as a signed i64 value.
/// The lifter converts signed offsets to unsigned via `imm_to_u64`,
/// so -16 becomes `0xFFFFFFFFFFFFFFF0`.
fn imm_as_signed(v: u64) -> i64 {
    v as i64
}

/// Check if an expression is `Reg(SP)`.
fn is_sp(expr: &Expr) -> bool {
    matches!(expr, Expr::Reg(Reg::SP))
}

/// Check if an expression is `Add(Reg(SP), Imm(v))` and return the immediate.
fn sp_plus_imm(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Add(a, b) => {
            if is_sp(a) {
                if let Expr::Imm(v) = b.as_ref() {
                    return Some(*v);
                }
            }
            None
        }
        _ => None,
    }
}

/// Check if an expression is `Add(Reg(X(29)), Imm(v))` and return the immediate.
fn fp_plus_imm(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Add(a, b) => {
            if matches!(a.as_ref(), Expr::Reg(Reg::X(29))) {
                if let Expr::Imm(v) = b.as_ref() {
                    return Some(*v);
                }
            }
            None
        }
        _ => None,
    }
}

/// Check if an expression is `Reg(X(29))`.
fn is_fp(expr: &Expr) -> bool {
    matches!(expr, Expr::Reg(Reg::X(29)))
}

/// Extract the stored register from a Store statement's value field.
fn store_value_reg(value: &Expr) -> Option<&Reg> {
    match value {
        Expr::Reg(r) => Some(r),
        _ => None,
    }
}

/// Detect ARM64 function prologue from a flattened statement list.
///
/// Recognizes two patterns:
/// 1. Standard frame-pointer prologue: Store X29/X30 at negative SP offset,
///    followed by `MOV X29, SP`.
/// 2. Leaf/no-FP prologue: `SUB SP, SP, #N` followed by stores.
pub fn detect_prologue(stmts: &[Stmt]) -> Option<PrologueInfo> {
    if stmts.is_empty() {
        return None;
    }

    // Pattern 1: First statement is Store to SP-relative negative offset (pre-indexed STP style)
    // e.g., Store { addr: Add(Reg(SP), Imm(0xFFFFFFFFFFFFFFF0)), value: Reg(X(29)), size: 8 }
    if let Some(info) = try_detect_preindexed(stmts) {
        return Some(info);
    }

    // Pattern 2: First statement is Assign(SP, Sub(Reg(SP), Imm(N))) -- explicit frame allocation
    if let Stmt::Assign { dst: Reg::SP, src } = &stmts[0] {
        if let Expr::Sub(a, b) = src {
            if is_sp(a) {
                if let Expr::Imm(n) = b.as_ref() {
                    let frame_size = *n;
                    let mut has_frame_pointer = false;
                    let mut saved_regs: Vec<(Reg, i64)> = Vec::new();
                    let mut prologue_end: usize = 1;

                    // Scan for register saves after the SUB
                    for (i, stmt) in stmts[1..].iter().enumerate() {
                        match stmt {
                            Stmt::Store { addr, value, size: 8 } => {
                                if let Some(reg) = store_value_reg(value) {
                                    let offset = if is_sp(addr) {
                                        Some(0i64)
                                    } else {
                                        sp_plus_imm(addr).map(imm_as_signed)
                                    };
                                    if let Some(off) = offset {
                                        if matches!(reg, Reg::X(29) | Reg::X(30)) || is_callee_saved(reg) {
                                            saved_regs.push((reg.clone(), off));
                                            prologue_end = i + 2; // +1 for the SUB, +1 for 0-based
                                            continue;
                                        }
                                    }
                                }
                                break;
                            }
                            Stmt::Assign { dst: Reg::X(29), src } if is_sp(src) => {
                                has_frame_pointer = true;
                                prologue_end = i + 2;
                                continue;
                            }
                            _ => break,
                        }
                    }

                    if frame_size > 0 {
                        return Some(PrologueInfo {
                            frame_size,
                            has_frame_pointer,
                            prologue_end,
                            saved_regs,
                        });
                    }
                }
            }
        }
    }

    None
}

/// Try to detect a pre-indexed STP-style prologue where the first store is at a
/// negative SP-relative offset (e.g., `STP X29, X30, [SP, #-16]!`).
fn try_detect_preindexed(stmts: &[Stmt]) -> Option<PrologueInfo> {
    // First statement must be a Store at a negative SP offset
    let (first_offset, first_reg) = match &stmts[0] {
        Stmt::Store { addr, value, size: 8 } => {
            let off = if is_sp(addr) {
                Some(0u64)
            } else {
                sp_plus_imm(addr)
            };
            let reg = store_value_reg(value)?;
            let off_val = off?;
            let signed = imm_as_signed(off_val);
            // For pre-indexed, the offset should be negative (or zero for base SP store)
            // Typically we expect X(29) first
            (signed, reg.clone())
        }
        _ => return None,
    };

    // The offset of the first store must be negative (pre-indexed decrement)
    if first_offset >= 0 {
        return None;
    }

    // Must be storing X29 or X30 (or a callee-saved reg) at a negative offset
    if !matches!(&first_reg, Reg::X(29) | Reg::X(30)) && !is_callee_saved(&first_reg) {
        return None;
    }

    let frame_size = (-first_offset) as u64;
    // Compute the saved offset relative to the new SP (bottom of frame).
    // The store is at [old_SP + first_offset] = [new_SP + 0] because SP was decremented by frame_size.
    // But we store the offset relative to frame base, i.e., offset from the pre-index address.
    // saved_regs offset = distance from the store address: 0 for first reg.
    let base = first_offset; // negative, e.g., -16
    let mut saved_regs = vec![(first_reg.clone(), 0i64)]; // offset 0 relative to frame base
    let mut prologue_end = 1;
    let mut has_frame_pointer = false;

    // Scan subsequent statements
    for stmt in &stmts[1..] {
        match stmt {
            Stmt::Store { addr, value, size: 8 } => {
                if let Some(reg) = store_value_reg(value) {
                    let offset = if is_sp(addr) {
                        Some(0u64)
                    } else {
                        sp_plus_imm(addr)
                    };
                    if let Some(off_val) = offset {
                        let signed = imm_as_signed(off_val);
                        // This store should be at an offset within the frame
                        // For the standard STP X29,X30,[SP,#-16]! pattern (after flattening):
                        // Store(Add(SP, -16), X29, 8)  => offset -16, base = -16, rel = 0
                        // Store(Add(SP, -8), X30, 8)   => offset -8,  base = -16, rel = 8
                        let rel = signed - base;
                        if rel >= 0 && (matches!(reg, Reg::X(29) | Reg::X(30)) || is_callee_saved(reg)) {
                            saved_regs.push((reg.clone(), rel));
                            prologue_end += 1;
                            continue;
                        }
                    }
                }
                break;
            }
            Stmt::Assign { dst: Reg::X(29), src } if is_sp(src) => {
                has_frame_pointer = true;
                prologue_end += 1;
                continue;
            }
            _ => break,
        }
    }

    Some(PrologueInfo {
        frame_size,
        has_frame_pointer,
        prologue_end,
        saved_regs,
    })
}

/// Recursively rewrite an expression, replacing SP-relative and (optionally)
/// FP-relative memory address patterns with `StackSlot` expressions.
fn rewrite_expr(expr: &Expr, has_fp: bool) -> Expr {
    // First, check if THIS expression is a stack-access pattern.
    // We look for Load nodes whose address is SP/FP-relative.
    match expr {
        Expr::Load { addr, size } => {
            // Check if addr is SP-relative
            if is_sp(addr) {
                return Expr::Load {
                    addr: Box::new(Expr::StackSlot { offset: 0, size: *size }),
                    size: *size,
                };
            }
            if let Some(v) = sp_plus_imm(addr) {
                let offset = imm_as_signed(v);
                return Expr::Load {
                    addr: Box::new(Expr::StackSlot { offset, size: *size }),
                    size: *size,
                };
            }
            // Check if addr is FP-relative (only when FP is set up)
            if has_fp {
                if is_fp(addr) {
                    return Expr::Load {
                        addr: Box::new(Expr::StackSlot { offset: 0, size: *size }),
                        size: *size,
                    };
                }
                if let Some(v) = fp_plus_imm(addr) {
                    let offset = imm_as_signed(v);
                    return Expr::Load {
                        addr: Box::new(Expr::StackSlot { offset, size: *size }),
                        size: *size,
                    };
                }
            }
            // Otherwise, recursively rewrite subexpressions of addr
            Expr::Load {
                addr: Box::new(rewrite_expr(addr, has_fp)),
                size: *size,
            }
        }
        // For all other expressions, recurse into subexpressions
        other => other.map_subexprs(|sub| rewrite_expr(sub, has_fp)),
    }
}

/// Rewrite a statement, replacing SP-relative and FP-relative memory accesses
/// with `StackSlot` expressions.
fn rewrite_stmt(stmt: Stmt, has_fp: bool) -> Stmt {
    match stmt {
        Stmt::Store { addr, value, size } => {
            // Check if addr is SP-relative
            if is_sp(&addr) {
                return Stmt::Store {
                    addr: Expr::StackSlot { offset: 0, size },
                    value: rewrite_expr(&value, has_fp),
                    size,
                };
            }
            if let Some(v) = sp_plus_imm(&addr) {
                let offset = imm_as_signed(v);
                return Stmt::Store {
                    addr: Expr::StackSlot { offset, size },
                    value: rewrite_expr(&value, has_fp),
                    size,
                };
            }
            // Check FP-relative
            if has_fp {
                if is_fp(&addr) {
                    return Stmt::Store {
                        addr: Expr::StackSlot { offset: 0, size },
                        value: rewrite_expr(&value, has_fp),
                        size,
                    };
                }
                if let Some(v) = fp_plus_imm(&addr) {
                    let offset = imm_as_signed(v);
                    return Stmt::Store {
                        addr: Expr::StackSlot { offset, size },
                        value: rewrite_expr(&value, has_fp),
                        size,
                    };
                }
            }
            // Not a stack access, but still rewrite subexpressions
            Stmt::Store {
                addr: rewrite_expr(&addr, has_fp),
                value: rewrite_expr(&value, has_fp),
                size,
            }
        }
        Stmt::Assign { dst, src } => Stmt::Assign {
            dst,
            src: rewrite_expr(&src, has_fp),
        },
        Stmt::Branch { target } => Stmt::Branch {
            target: rewrite_expr(&target, has_fp),
        },
        Stmt::Call { target } => Stmt::Call {
            target: rewrite_expr(&target, has_fp),
        },
        Stmt::SetFlags { expr } => Stmt::SetFlags {
            expr: rewrite_expr(&expr, has_fp),
        },
        Stmt::CondBranch { cond, target, fallthrough } => {
            let new_cond = match cond {
                aeonil::BranchCond::Flag(c) => aeonil::BranchCond::Flag(c),
                aeonil::BranchCond::Zero(e) => aeonil::BranchCond::Zero(rewrite_expr(&e, has_fp)),
                aeonil::BranchCond::NotZero(e) => aeonil::BranchCond::NotZero(rewrite_expr(&e, has_fp)),
                aeonil::BranchCond::BitZero(e, b) => aeonil::BranchCond::BitZero(rewrite_expr(&e, has_fp), b),
                aeonil::BranchCond::BitNotZero(e, b) => aeonil::BranchCond::BitNotZero(rewrite_expr(&e, has_fp), b),
                aeonil::BranchCond::Compare { cond: c, lhs, rhs } => aeonil::BranchCond::Compare {
                    cond: c,
                    lhs: Box::new(rewrite_expr(&lhs, has_fp)),
                    rhs: Box::new(rewrite_expr(&rhs, has_fp)),
                },
            };
            Stmt::CondBranch {
                cond: new_cond,
                target: rewrite_expr(&target, has_fp),
                fallthrough,
            }
        }
        Stmt::Pair(a, b) => Stmt::Pair(
            Box::new(rewrite_stmt(*a, has_fp)),
            Box::new(rewrite_stmt(*b, has_fp)),
        ),
        Stmt::Intrinsic { name, operands } => Stmt::Intrinsic {
            name,
            operands: operands.iter().map(|e| rewrite_expr(e, has_fp)).collect(),
        },
        // Statements with no expressions to rewrite
        other @ (Stmt::Ret | Stmt::Nop | Stmt::Barrier(_) | Stmt::Trap) => other,
    }
}

/// Rewrite SP-relative and FP-relative memory accesses to use StackSlot expressions.
pub fn rewrite_stack_accesses(stmts: Vec<Stmt>, prologue: &PrologueInfo) -> Vec<Stmt> {
    stmts
        .into_iter()
        .map(|stmt| rewrite_stmt(stmt, prologue.has_frame_pointer))
        .collect()
}

/// Detect prologue and rewrite stack accesses. Returns original stmts if no prologue found.
pub fn recognize_stack_frame(stmts: Vec<Stmt>) -> Vec<Stmt> {
    if let Some(prologue) = detect_prologue(&stmts) {
        rewrite_stack_accesses(stmts, &prologue)
    } else {
        stmts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, e_load, e_sub, e_stack_slot, Expr, Reg, Stmt};

    // ---- Prologue detection tests ----

    #[test]
    fn prologue_standard_fp() {
        // STP X29, X30, [SP, #-16]! (flattened to two stores) + MOV X29, SP
        let stmts = vec![
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm(0xFFFFFFFFFFFFFFF0)), // -16
                value: Expr::Reg(Reg::X(29)),
                size: 8,
            },
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm(0xFFFFFFFFFFFFFFF8)), // -8
                value: Expr::Reg(Reg::X(30)),
                size: 8,
            },
            Stmt::Assign {
                dst: Reg::X(29),
                src: Expr::Reg(Reg::SP),
            },
        ];
        let info = detect_prologue(&stmts).expect("should detect prologue");
        assert_eq!(info.frame_size, 16);
        assert!(info.has_frame_pointer);
        assert_eq!(
            info.saved_regs,
            vec![(Reg::X(29), 0), (Reg::X(30), 8)]
        );
        assert_eq!(info.prologue_end, 3);
    }

    #[test]
    fn prologue_no_fp() {
        // SUB SP, SP, #32 followed by some stores (but no MOV X29, SP)
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::SP,
                src: e_sub(Expr::Reg(Reg::SP), Expr::Imm(32)),
            },
            Stmt::Store {
                addr: Expr::Reg(Reg::SP),
                value: Expr::Reg(Reg::X(29)),
                size: 8,
            },
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm(8)),
                value: Expr::Reg(Reg::X(30)),
                size: 8,
            },
            // Body instruction
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(42),
            },
        ];
        let info = detect_prologue(&stmts).expect("should detect prologue");
        assert_eq!(info.frame_size, 32);
        assert!(!info.has_frame_pointer);
        assert_eq!(
            info.saved_regs,
            vec![(Reg::X(29), 0), (Reg::X(30), 8)]
        );
    }

    #[test]
    fn prologue_not_detected() {
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(42),
        }];
        assert!(detect_prologue(&stmts).is_none());
    }

    #[test]
    fn prologue_extra_callee_saved() {
        // STP X29,X30,[SP,#-32]! + Store X19 + Store X20
        let stmts = vec![
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-32i64) as u64)),
                value: Expr::Reg(Reg::X(29)),
                size: 8,
            },
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-24i64) as u64)),
                value: Expr::Reg(Reg::X(30)),
                size: 8,
            },
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-16i64) as u64)),
                value: Expr::Reg(Reg::X(19)),
                size: 8,
            },
            Stmt::Store {
                addr: e_add(Expr::Reg(Reg::SP), Expr::Imm((-8i64) as u64)),
                value: Expr::Reg(Reg::X(20)),
                size: 8,
            },
            Stmt::Assign {
                dst: Reg::X(29),
                src: Expr::Reg(Reg::SP),
            },
        ];
        let info = detect_prologue(&stmts).expect("should detect prologue");
        assert_eq!(info.frame_size, 32);
        assert!(info.has_frame_pointer);
        assert_eq!(
            info.saved_regs,
            vec![
                (Reg::X(29), 0),
                (Reg::X(30), 8),
                (Reg::X(19), 16),
                (Reg::X(20), 24),
            ]
        );
    }

    // ---- Stack rewriting tests ----

    #[test]
    fn sp_load_becomes_slot() {
        // Assign(X0, Load(Add(SP, Imm(8)), 8)) => Assign(X0, Load(StackSlot(8, 8)))
        let prologue = PrologueInfo {
            frame_size: 32,
            has_frame_pointer: false,
            prologue_end: 1,
            saved_regs: vec![],
        };
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(0),
            src: e_load(e_add(Expr::Reg(Reg::SP), Expr::Imm(8)), 8),
        }];
        let result = rewrite_stack_accesses(stmts, &prologue);
        assert_eq!(
            result[0],
            Stmt::Assign {
                dst: Reg::X(0),
                src: e_load(e_stack_slot(8, 8), 8),
            }
        );
    }

    #[test]
    fn sp_store_becomes_slot() {
        // Store(Add(SP, Imm(16)), W0, 4) => Store(StackSlot(16, 4), W0, 4)
        let prologue = PrologueInfo {
            frame_size: 32,
            has_frame_pointer: false,
            prologue_end: 1,
            saved_regs: vec![],
        };
        let stmts = vec![Stmt::Store {
            addr: e_add(Expr::Reg(Reg::SP), Expr::Imm(16)),
            value: Expr::Reg(Reg::W(0)),
            size: 4,
        }];
        let result = rewrite_stack_accesses(stmts, &prologue);
        assert_eq!(
            result[0],
            Stmt::Store {
                addr: e_stack_slot(16, 4),
                value: Expr::Reg(Reg::W(0)),
                size: 4,
            }
        );
    }

    #[test]
    fn sp_zero_offset() {
        // Load(Reg(SP), 8) => Load(StackSlot(0, 8))
        let prologue = PrologueInfo {
            frame_size: 16,
            has_frame_pointer: false,
            prologue_end: 1,
            saved_regs: vec![],
        };
        let stmts = vec![Stmt::Assign {
            dst: Reg::X(0),
            src: e_load(Expr::Reg(Reg::SP), 8),
        }];
        let result = rewrite_stack_accesses(stmts, &prologue);
        assert_eq!(
            result[0],
            Stmt::Assign {
                dst: Reg::X(0),
                src: e_load(e_stack_slot(0, 8), 8),
            }
        );
    }

    #[test]
    fn non_sp_unchanged() {
        // Load(Add(X8, Imm(16)), 8) => unchanged
        let prologue = PrologueInfo {
            frame_size: 32,
            has_frame_pointer: false,
            prologue_end: 1,
            saved_regs: vec![],
        };
        let original = Stmt::Assign {
            dst: Reg::X(0),
            src: e_load(e_add(Expr::Reg(Reg::X(8)), Expr::Imm(16)), 8),
        };
        let stmts = vec![original.clone()];
        let result = rewrite_stack_accesses(stmts, &prologue);
        assert_eq!(result[0], original);
    }

    #[test]
    fn fp_negative_offset() {
        // With FP detected: Store(Add(X29, Imm(0xFFFFFFFFFFFFFFFC)), W1, 4) => Store(StackSlot(-4, 4), W1, 4)
        let prologue = PrologueInfo {
            frame_size: 16,
            has_frame_pointer: true,
            prologue_end: 3,
            saved_regs: vec![(Reg::X(29), 0), (Reg::X(30), 8)],
        };
        let stmts = vec![Stmt::Store {
            addr: e_add(Expr::Reg(Reg::X(29)), Expr::Imm(0xFFFFFFFFFFFFFFFC)),
            value: Expr::Reg(Reg::W(1)),
            size: 4,
        }];
        let result = rewrite_stack_accesses(stmts, &prologue);
        assert_eq!(
            result[0],
            Stmt::Store {
                addr: e_stack_slot(-4, 4),
                value: Expr::Reg(Reg::W(1)),
                size: 4,
            }
        );
    }

    #[test]
    fn no_fp_x29_not_rewritten() {
        // Without FP setup, X29 accesses should stay as-is
        let prologue = PrologueInfo {
            frame_size: 32,
            has_frame_pointer: false,
            prologue_end: 1,
            saved_regs: vec![],
        };
        let original = Stmt::Store {
            addr: e_add(Expr::Reg(Reg::X(29)), Expr::Imm(0xFFFFFFFFFFFFFFFC)),
            value: Expr::Reg(Reg::W(1)),
            size: 4,
        };
        let stmts = vec![original.clone()];
        let result = rewrite_stack_accesses(stmts, &prologue);
        assert_eq!(result[0], original);
    }

    #[test]
    fn recognize_stack_frame_noop() {
        // Function with no prologue pattern => stmts unchanged
        let original = vec![
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(42),
            },
            Stmt::Ret,
        ];
        let result = recognize_stack_frame(original.clone());
        assert_eq!(result, original);
    }
}
