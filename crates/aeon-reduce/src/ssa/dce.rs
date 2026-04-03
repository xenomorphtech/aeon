//! Dead code elimination -- removes SSA statements whose defined variables
//! have no uses and no observable side effects (stores, calls, barriers).
//! Uses a worklist to cascade: removing a dead def may reduce use counts
//! of its operands, making those defs dead too.

use super::construct::SsaFunction;
use super::types::*;
use super::use_def::UseDefMap;
use std::collections::VecDeque;

/// Run dead code elimination. Returns true if any changes were made.
pub fn run(func: &mut SsaFunction, use_def: &mut UseDefMap) -> bool {
    let mut changed = false;
    let mut worklist: VecDeque<SsaVar> = VecDeque::new();

    // Seed worklist with all vars that have zero uses and non-side-effecting defs
    for block in &func.blocks {
        for stmt in &block.stmts {
            if let SsaStmt::Assign { dst, .. } = stmt {
                if use_def.use_count(dst) == 0 {
                    worklist.push_back(*dst);
                }
            }
        }
    }

    while let Some(dead_var) = worklist.pop_front() {
        // Double-check it's still dead (use count may have changed)
        if use_def.use_count(&dead_var) > 0 {
            continue;
        }

        // Find the definition
        let Some(def_loc) = use_def.def_of(&dead_var) else {
            continue;
        };

        // Get the statement at def_loc
        let block = &func.blocks[def_loc.block as usize];
        if def_loc.stmt_idx >= block.stmts.len() {
            continue;
        }
        let stmt = &block.stmts[def_loc.stmt_idx];

        // Only remove Assign statements (not Store, Call, Branch, etc.)
        let SsaStmt::Assign { src, .. } = stmt else {
            continue;
        };

        // Collect all vars used by this statement's RHS
        let operand_vars = collect_expr_vars(src);

        // Replace statement with Nop
        func.blocks[def_loc.block as usize].stmts[def_loc.stmt_idx] = SsaStmt::Nop;
        use_def.remove_def(&dead_var);
        changed = true;

        // Decrement use counts of operands; if any drop to zero, add to worklist
        for op_var in operand_vars {
            use_def.remove_use(&op_var, def_loc);
            if use_def.use_count(&op_var) == 0 {
                worklist.push_back(op_var);
            }
        }
    }

    // Sweep: remove Nop statements
    if changed {
        for block in &mut func.blocks {
            block.stmts.retain(|s| !matches!(s, SsaStmt::Nop));
        }
    }

    changed
}

/// Collect all SsaVar references in an expression.
fn collect_expr_vars(expr: &SsaExpr) -> Vec<SsaVar> {
    let mut vars = Vec::new();
    collect_vars_recursive(expr, &mut vars);
    vars
}

fn collect_vars_recursive(expr: &SsaExpr, vars: &mut Vec<SsaVar>) {
    match expr {
        SsaExpr::Var(v) => vars.push(*v),
        SsaExpr::Phi(operands) => {
            for (_, v) in operands {
                vars.push(*v);
            }
        }

        // Binary ops
        SsaExpr::Add(a, b)
        | SsaExpr::Sub(a, b)
        | SsaExpr::Mul(a, b)
        | SsaExpr::Div(a, b)
        | SsaExpr::UDiv(a, b)
        | SsaExpr::And(a, b)
        | SsaExpr::Or(a, b)
        | SsaExpr::Xor(a, b)
        | SsaExpr::Shl(a, b)
        | SsaExpr::Lsr(a, b)
        | SsaExpr::Asr(a, b)
        | SsaExpr::Ror(a, b)
        | SsaExpr::FAdd(a, b)
        | SsaExpr::FSub(a, b)
        | SsaExpr::FMul(a, b)
        | SsaExpr::FDiv(a, b)
        | SsaExpr::FMax(a, b)
        | SsaExpr::FMin(a, b) => {
            collect_vars_recursive(a, vars);
            collect_vars_recursive(b, vars);
        }

        // Insert has two sub-expressions
        SsaExpr::Insert { dst, src, .. } => {
            collect_vars_recursive(dst, vars);
            collect_vars_recursive(src, vars);
        }

        // Compare and CondSelect
        SsaExpr::Compare { lhs, rhs, .. } => {
            collect_vars_recursive(lhs, vars);
            collect_vars_recursive(rhs, vars);
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => {
            collect_vars_recursive(if_true, vars);
            collect_vars_recursive(if_false, vars);
        }

        // Unary ops
        SsaExpr::Neg(a)
        | SsaExpr::Abs(a)
        | SsaExpr::Not(a)
        | SsaExpr::FNeg(a)
        | SsaExpr::FAbs(a)
        | SsaExpr::FSqrt(a)
        | SsaExpr::FCvt(a)
        | SsaExpr::IntToFloat(a)
        | SsaExpr::FloatToInt(a)
        | SsaExpr::Clz(a)
        | SsaExpr::Cls(a)
        | SsaExpr::Rev(a)
        | SsaExpr::Rbit(a) => {
            collect_vars_recursive(a, vars);
        }

        // Unary with extra fields
        SsaExpr::SignExtend { src, .. }
        | SsaExpr::ZeroExtend { src, .. }
        | SsaExpr::Extract { src, .. } => {
            collect_vars_recursive(src, vars);
        }

        // Load has an address sub-expression
        SsaExpr::Load { addr, .. } => {
            collect_vars_recursive(addr, vars);
        }

        // Intrinsic has a vec of operand expressions
        SsaExpr::Intrinsic { operands, .. } => {
            for op in operands {
                collect_vars_recursive(op, vars);
            }
        }

        // Leaves with no variable references
        SsaExpr::Imm(_)
        | SsaExpr::FImm(_)
        | SsaExpr::StackSlot { .. }
        | SsaExpr::MrsRead(_)
        | SsaExpr::AdrpImm(_)
        | SsaExpr::AdrImm(_) => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::construct::{SsaBlock, SsaFunction};
    use crate::ssa::use_def::UseDefMap;

    /// Helper to create a simple SsaVar for testing.
    fn var(n: u8, version: u32) -> SsaVar {
        SsaVar {
            loc: RegLocation::Gpr(n),
            version,
            width: RegWidth::W64,
        }
    }

    /// Build a single-block function from a list of statements.
    fn one_block(stmts: Vec<SsaStmt>) -> SsaFunction {
        SsaFunction {
            entry: 0,
            blocks: vec![SsaBlock {
                id: 0,
                addr: 0,
                stmts,
                successors: vec![],
                predecessors: vec![],
            }],
        }
    }

    /// Build a two-block function.
    fn two_blocks(stmts0: Vec<SsaStmt>, stmts1: Vec<SsaStmt>) -> SsaFunction {
        SsaFunction {
            entry: 0,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    addr: 0,
                    stmts: stmts0,
                    successors: vec![1],
                    predecessors: vec![],
                },
                SsaBlock {
                    id: 1,
                    addr: 4,
                    stmts: stmts1,
                    successors: vec![],
                    predecessors: vec![0],
                },
            ],
        }
    }

    #[test]
    fn dce_unused_assign() {
        // v1 = Imm(42) with no uses -> removed
        let v1 = var(0, 1);
        let mut func = one_block(vec![SsaStmt::Assign {
            dst: v1,
            src: SsaExpr::Imm(42),
        }]);
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);
        assert!(func.blocks[0].stmts.is_empty());
    }

    #[test]
    fn dce_preserves_used() {
        // v1 = Imm(42); Store(addr=Imm(0x1000), v1, 4) -> v1 survives
        let v1 = var(0, 1);
        let mut func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(42),
            },
            SsaStmt::Store {
                addr: SsaExpr::Imm(0x1000),
                value: SsaExpr::Var(v1),
                size: 4,
            },
        ]);
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(!changed);
        assert_eq!(func.blocks[0].stmts.len(), 2);
    }

    #[test]
    fn dce_preserves_store() {
        // Store(addr=Imm(0x1000), Imm(99), 8) -> survives (side-effecting)
        let mut func = one_block(vec![SsaStmt::Store {
            addr: SsaExpr::Imm(0x1000),
            value: SsaExpr::Imm(99),
            size: 8,
        }]);
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(!changed);
        assert_eq!(func.blocks[0].stmts.len(), 1);
    }

    #[test]
    fn dce_preserves_call() {
        // Call(target=Imm(0xDEAD)) -> survives
        let mut func = one_block(vec![SsaStmt::Call {
            target: SsaExpr::Imm(0xDEAD),
        }]);
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(!changed);
        assert_eq!(func.blocks[0].stmts.len(), 1);
    }

    #[test]
    fn dce_cascading() {
        // v1 = Imm(1); v2 = Add(v1, v1); v3 = Mul(v2, Imm(2)) all unused -> all removed
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let v3 = var(2, 1);
        let mut func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(1),
            },
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Add(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Var(v1))),
            },
            SsaStmt::Assign {
                dst: v3,
                src: SsaExpr::Mul(Box::new(SsaExpr::Var(v2)), Box::new(SsaExpr::Imm(2))),
            },
        ]);
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);
        assert!(func.blocks[0].stmts.is_empty());
    }

    #[test]
    fn dce_dead_phi() {
        // Block 0: v1 = Imm(10)
        // Block 1: v2 = Imm(20)
        // Block 1: v3 = Phi((0, v1), (1, v2)) -- unused -> removed, v1/v2 use counts decremented
        let v1 = var(0, 1);
        let v2 = var(0, 2);
        let v3 = var(0, 3);
        let mut func = two_blocks(
            vec![SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(10),
            }],
            vec![
                SsaStmt::Assign {
                    dst: v2,
                    src: SsaExpr::Imm(20),
                },
                SsaStmt::Assign {
                    dst: v3,
                    src: SsaExpr::Phi(vec![(0, v1), (1, v2)]),
                },
            ],
        );
        let mut ud = UseDefMap::build(&func);

        // Before DCE: v1 and v2 each have 1 use (the phi)
        assert_eq!(ud.use_count(&v1), 1);
        assert_eq!(ud.use_count(&v2), 1);

        let changed = run(&mut func, &mut ud);
        assert!(changed);

        // All three should be removed (v3 dead -> phi removed -> v1,v2 dead -> removed)
        assert!(func.blocks[0].stmts.is_empty());
        assert!(func.blocks[1].stmts.is_empty());
        assert_eq!(ud.use_count(&v1), 0);
        assert_eq!(ud.use_count(&v2), 0);
    }

    #[test]
    fn dce_partial_cascade() {
        // v1 = Imm(1); v2 = Add(v1, Imm(2)); Store(addr=Imm(0x1000), v1, 4)
        // v2 is unused -> v2 removed, v1 survives because Store uses it
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let mut func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(1),
            },
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Add(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Imm(2))),
            },
            SsaStmt::Store {
                addr: SsaExpr::Imm(0x1000),
                value: SsaExpr::Var(v1),
                size: 4,
            },
        ]);
        let mut ud = UseDefMap::build(&func);

        let changed = run(&mut func, &mut ud);
        assert!(changed);
        // v2's assignment removed, v1 and Store remain
        assert_eq!(func.blocks[0].stmts.len(), 2);
        assert!(matches!(
            &func.blocks[0].stmts[0],
            SsaStmt::Assign { dst, src: SsaExpr::Imm(1) } if *dst == v1
        ));
        assert!(matches!(&func.blocks[0].stmts[1], SsaStmt::Store { .. }));
    }
}
