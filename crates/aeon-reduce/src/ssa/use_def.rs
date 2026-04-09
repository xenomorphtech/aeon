//! Use-def / def-use chains -- builds maps from each SSA variable use to
//! its unique definition site, and from each definition to all its uses.
//! Foundation for most SSA optimization passes.

use super::construct::SsaFunction;
use super::types::*;
use std::collections::{HashMap, HashSet};

/// Location of a statement within the function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StmtLocation {
    pub block: BlockId,
    pub stmt_idx: usize,
}

/// Maps each `SsaVar` to where it is defined (unique) and where it is used
/// (zero or more sites).
pub struct UseDefMap {
    defs: HashMap<SsaVar, StmtLocation>,
    uses: HashMap<SsaVar, HashSet<StmtLocation>>,
}

// ---------------------------------------------------------------------------
// Expression / statement walkers
// ---------------------------------------------------------------------------

fn collect_uses_in_expr(
    expr: &SsaExpr,
    loc: StmtLocation,
    uses: &mut HashMap<SsaVar, HashSet<StmtLocation>>,
) {
    match expr {
        SsaExpr::Var(v) => {
            uses.entry(*v).or_default().insert(loc);
        }
        SsaExpr::Phi(operands) => {
            for (_, v) in operands {
                uses.entry(*v).or_default().insert(loc);
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
            collect_uses_in_expr(a, loc, uses);
            collect_uses_in_expr(b, loc, uses);
        }

        // Insert has two sub-expressions
        SsaExpr::Insert { dst, src, .. } => {
            collect_uses_in_expr(dst, loc, uses);
            collect_uses_in_expr(src, loc, uses);
        }

        // Compare and CondSelect have two/three sub-expressions
        SsaExpr::Compare { lhs, rhs, .. } => {
            collect_uses_in_expr(lhs, loc, uses);
            collect_uses_in_expr(rhs, loc, uses);
        }
        SsaExpr::CondSelect {
            if_true, if_false, ..
        } => {
            collect_uses_in_expr(if_true, loc, uses);
            collect_uses_in_expr(if_false, loc, uses);
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
            collect_uses_in_expr(a, loc, uses);
        }

        // Unary with extra fields
        SsaExpr::SignExtend { src, .. }
        | SsaExpr::ZeroExtend { src, .. }
        | SsaExpr::Extract { src, .. } => {
            collect_uses_in_expr(src, loc, uses);
        }

        // Load has an address sub-expression
        SsaExpr::Load { addr, .. } => {
            collect_uses_in_expr(addr, loc, uses);
        }

        // Intrinsic has a vec of operand expressions
        SsaExpr::Intrinsic { operands, .. } => {
            for op in operands {
                collect_uses_in_expr(op, loc, uses);
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

fn collect_uses_in_branch_cond(
    cond: &SsaBranchCond,
    loc: StmtLocation,
    uses: &mut HashMap<SsaVar, HashSet<StmtLocation>>,
) {
    match cond {
        SsaBranchCond::Flag(_, var) => {
            uses.entry(*var).or_default().insert(loc);
        }
        SsaBranchCond::Zero(expr) | SsaBranchCond::NotZero(expr) => {
            collect_uses_in_expr(expr, loc, uses);
        }
        SsaBranchCond::BitZero(expr, _) | SsaBranchCond::BitNotZero(expr, _) => {
            collect_uses_in_expr(expr, loc, uses);
        }
        SsaBranchCond::Compare { lhs, rhs, .. } => {
            collect_uses_in_expr(lhs, loc, uses);
            collect_uses_in_expr(rhs, loc, uses);
        }
    }
}

fn collect_uses_in_stmt(
    stmt: &SsaStmt,
    loc: StmtLocation,
    uses: &mut HashMap<SsaVar, HashSet<StmtLocation>>,
) {
    match stmt {
        SsaStmt::Assign { src, .. } => {
            collect_uses_in_expr(src, loc, uses);
        }
        SsaStmt::Store { addr, value, .. } => {
            collect_uses_in_expr(addr, loc, uses);
            collect_uses_in_expr(value, loc, uses);
        }
        SsaStmt::Branch { target } => {
            collect_uses_in_expr(target, loc, uses);
        }
        SsaStmt::CondBranch { cond, target, .. } => {
            collect_uses_in_branch_cond(cond, loc, uses);
            collect_uses_in_expr(target, loc, uses);
        }
        SsaStmt::Call { target } => {
            collect_uses_in_expr(target, loc, uses);
        }
        SsaStmt::SetFlags { src, expr } => {
            uses.entry(*src).or_default().insert(loc);
            collect_uses_in_expr(expr, loc, uses);
        }
        SsaStmt::Intrinsic { operands, .. } => {
            for op in operands {
                collect_uses_in_expr(op, loc, uses);
            }
        }
        SsaStmt::Pair(a, b) => {
            collect_uses_in_stmt(a, loc, uses);
            collect_uses_in_stmt(b, loc, uses);
        }
        SsaStmt::Ret | SsaStmt::Nop | SsaStmt::Barrier(_) | SsaStmt::Trap { .. } => {}
    }
}

// ---------------------------------------------------------------------------
// UseDefMap implementation
// ---------------------------------------------------------------------------

impl UseDefMap {
    /// Build the use-def map by scanning all statements in the function.
    pub fn build(func: &SsaFunction) -> Self {
        let mut defs: HashMap<SsaVar, StmtLocation> = HashMap::new();
        let mut uses: HashMap<SsaVar, HashSet<StmtLocation>> = HashMap::new();

        for block in &func.blocks {
            for (stmt_idx, stmt) in block.stmts.iter().enumerate() {
                let loc = StmtLocation {
                    block: block.id,
                    stmt_idx,
                };

                // Record definitions
                match stmt {
                    SsaStmt::Assign { dst, .. } => {
                        defs.insert(*dst, loc);
                    }
                    SsaStmt::SetFlags { src, .. } => {
                        // SetFlags defines the flags variable (src is the
                        // flags SsaVar being written, expr is the
                        // computation).  We treat src as defined here too.
                        defs.insert(*src, loc);
                    }
                    SsaStmt::Pair(a, b) => {
                        // Recurse into pair to pick up nested defs
                        Self::collect_defs_in_stmt(a, loc, &mut defs);
                        Self::collect_defs_in_stmt(b, loc, &mut defs);
                    }
                    _ => {}
                }

                // Record uses
                collect_uses_in_stmt(stmt, loc, &mut uses);
            }
        }

        UseDefMap { defs, uses }
    }

    /// Helper to collect defs inside nested statements (Pair).
    fn collect_defs_in_stmt(
        stmt: &SsaStmt,
        loc: StmtLocation,
        defs: &mut HashMap<SsaVar, StmtLocation>,
    ) {
        match stmt {
            SsaStmt::Assign { dst, .. } => {
                defs.insert(*dst, loc);
            }
            SsaStmt::SetFlags { src, .. } => {
                defs.insert(*src, loc);
            }
            SsaStmt::Pair(a, b) => {
                Self::collect_defs_in_stmt(a, loc, defs);
                Self::collect_defs_in_stmt(b, loc, defs);
            }
            _ => {}
        }
    }

    /// Iterator over all use sites of a variable.
    pub fn uses_of(&self, var: &SsaVar) -> impl Iterator<Item = &StmtLocation> {
        self.uses.get(var).into_iter().flat_map(|s| s.iter())
    }

    /// Where a variable is defined.  Returns `None` for entry-version
    /// variables (version 0) which have no explicit definition.
    pub fn def_of(&self, var: &SsaVar) -> Option<StmtLocation> {
        self.defs.get(var).copied()
    }

    /// Number of sites that use the variable.
    pub fn use_count(&self, var: &SsaVar) -> usize {
        self.uses.get(var).map(|s| s.len()).unwrap_or(0)
    }

    /// Remove a use from the map.
    pub fn remove_use(&mut self, var: &SsaVar, loc: StmtLocation) {
        if let Some(set) = self.uses.get_mut(var) {
            set.remove(&loc);
        }
    }

    /// Add a use to the map.
    pub fn add_use(&mut self, var: &SsaVar, loc: StmtLocation) {
        self.uses.entry(*var).or_default().insert(loc);
    }

    /// Remove the definition record for a variable.
    pub fn remove_def(&mut self, var: &SsaVar) {
        self.defs.remove(var);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::construct::{SsaBlock, SsaFunction};

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
    fn use_def_single_assign() {
        // v1 = Imm(42)
        let v1 = var(0, 1);
        let func = one_block(vec![SsaStmt::Assign {
            dst: v1,
            src: SsaExpr::Imm(42),
        }]);

        let ud = UseDefMap::build(&func);
        assert_eq!(
            ud.def_of(&v1),
            Some(StmtLocation {
                block: 0,
                stmt_idx: 0
            })
        );
        assert_eq!(ud.use_count(&v1), 0);
    }

    #[test]
    fn use_def_chain() {
        // v1 = Imm(42)
        // v2 = Add(v1, Imm(1))
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(42),
            },
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Add(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Imm(1))),
            },
        ]);

        let ud = UseDefMap::build(&func);
        assert_eq!(ud.use_count(&v1), 1);
        let use_locs: Vec<_> = ud.uses_of(&v1).collect();
        assert_eq!(use_locs.len(), 1);
        assert_eq!(
            *use_locs[0],
            StmtLocation {
                block: 0,
                stmt_idx: 1
            }
        );
    }

    #[test]
    fn use_def_phi_uses() {
        // v3 = Phi((0, v1), (1, v2))
        let v1 = var(0, 1);
        let v2 = var(0, 2);
        let v3 = var(0, 3);
        let func = one_block(vec![SsaStmt::Assign {
            dst: v3,
            src: SsaExpr::Phi(vec![(0, v1), (1, v2)]),
        }]);

        let ud = UseDefMap::build(&func);
        assert_eq!(ud.use_count(&v1), 1);
        assert_eq!(ud.use_count(&v2), 1);
        assert_eq!(ud.use_count(&v3), 0);
    }

    #[test]
    fn use_def_store_uses() {
        // Store(v1, v2, 8)
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let func = one_block(vec![SsaStmt::Store {
            addr: SsaExpr::Var(v1),
            value: SsaExpr::Var(v2),
            size: 8,
        }]);

        let ud = UseDefMap::build(&func);
        assert_eq!(ud.use_count(&v1), 1);
        assert_eq!(ud.use_count(&v2), 1);
    }

    #[test]
    fn use_def_count() {
        // v1 = Imm(10)
        // v2 = Add(v1, v1)
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(10),
            },
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Add(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Var(v1))),
            },
        ]);

        let ud = UseDefMap::build(&func);
        // v1 is used twice in the same statement, but StmtLocation
        // is a set so it counts as 1 use site.
        assert_eq!(ud.use_count(&v1), 1);
        assert_eq!(ud.use_count(&v2), 0);
    }

    #[test]
    fn use_def_remove_use() {
        // v1 = Imm(42)
        // v2 = Add(v1, Imm(1))
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let func = one_block(vec![
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Imm(42),
            },
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Add(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Imm(1))),
            },
        ]);

        let mut ud = UseDefMap::build(&func);
        assert_eq!(ud.use_count(&v1), 1);

        ud.remove_use(
            &v1,
            StmtLocation {
                block: 0,
                stmt_idx: 1,
            },
        );
        assert_eq!(ud.use_count(&v1), 0);
    }

    #[test]
    fn use_def_multiple_uses() {
        // Block 0: v1 = Imm(42); v2 = Add(v1, Imm(1))
        // Block 1: v3 = Sub(v1, Imm(2))
        let v1 = var(0, 1);
        let v2 = var(1, 1);
        let v3 = var(2, 1);
        let func = two_blocks(
            vec![
                SsaStmt::Assign {
                    dst: v1,
                    src: SsaExpr::Imm(42),
                },
                SsaStmt::Assign {
                    dst: v2,
                    src: SsaExpr::Add(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Imm(1))),
                },
            ],
            vec![SsaStmt::Assign {
                dst: v3,
                src: SsaExpr::Sub(Box::new(SsaExpr::Var(v1)), Box::new(SsaExpr::Imm(2))),
            }],
        );

        let ud = UseDefMap::build(&func);
        // v1 is used in block 0 stmt 1 and block 1 stmt 0
        assert_eq!(ud.use_count(&v1), 2);
    }
}
