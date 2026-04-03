//! Common Subexpression Elimination -- dominator-tree walk CSE with a scoped
//! hash table.  Only CSEs pure arithmetic/logic expressions (not loads,
//! intrinsics, phis, or anything with side effects).

use super::construct::SsaFunction;
use super::domtree::DomTree;
use super::types::*;
use super::use_def::UseDefMap;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Canonical expression form
// ---------------------------------------------------------------------------

/// Hashable canonical expression for CSE lookup.
/// Commutative ops sort operands by SsaVar for canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CanonExpr {
    Add(SsaVar, SsaVar),
    Sub(SsaVar, SsaVar),
    Mul(SsaVar, SsaVar),
    And(SsaVar, SsaVar),
    Or(SsaVar, SsaVar),
    Xor(SsaVar, SsaVar),
    Shl(SsaVar, SsaVar),
    Lsr(SsaVar, SsaVar),
    Asr(SsaVar, SsaVar),
    Ror(SsaVar, SsaVar),
    Neg(SsaVar),
    Not(SsaVar),
    ZeroExtend { src: SsaVar, from_bits: u8 },
    SignExtend { src: SsaVar, from_bits: u8 },
    Extract { src: SsaVar, lsb: u8, width: u8 },
}

/// Ordering key for SsaVar used to canonicalize commutative operands.
/// Compares by (loc discriminant, loc index, version, width).
fn var_sort_key(v: &SsaVar) -> (u8, u8, u32, RegWidth) {
    let (disc, idx) = match v.loc {
        RegLocation::Gpr(n) => (0, n),
        RegLocation::Fpr(n) => (1, n),
        RegLocation::Sp => (2, 0),
        RegLocation::Flags => (3, 0),
    };
    (disc, idx, v.version, v.width)
}

/// Sort two SsaVars for commutative canonicalization.
fn sorted_pair(a: SsaVar, b: SsaVar) -> (SsaVar, SsaVar) {
    if var_sort_key(&a) <= var_sort_key(&b) {
        (a, b)
    } else {
        (b, a)
    }
}

/// Extract an SsaVar from an SsaExpr, returning None if the expression is
/// not a bare Var reference.
fn as_var(expr: &SsaExpr) -> Option<SsaVar> {
    if let SsaExpr::Var(v) = expr {
        Some(*v)
    } else {
        None
    }
}

/// Try to canonicalize an SsaExpr into a hashable CanonExpr.
/// Returns None for expressions that cannot be CSE'd (loads, phis, immediates,
/// intrinsics, etc.) or where operands are not bare Var references.
fn try_canonicalize(expr: &SsaExpr) -> Option<CanonExpr> {
    match expr {
        // Commutative binary ops -- sort operands
        SsaExpr::Add(a, b) => {
            let (l, r) = sorted_pair(as_var(a)?, as_var(b)?);
            Some(CanonExpr::Add(l, r))
        }
        SsaExpr::Mul(a, b) => {
            let (l, r) = sorted_pair(as_var(a)?, as_var(b)?);
            Some(CanonExpr::Mul(l, r))
        }
        SsaExpr::And(a, b) => {
            let (l, r) = sorted_pair(as_var(a)?, as_var(b)?);
            Some(CanonExpr::And(l, r))
        }
        SsaExpr::Or(a, b) => {
            let (l, r) = sorted_pair(as_var(a)?, as_var(b)?);
            Some(CanonExpr::Or(l, r))
        }
        SsaExpr::Xor(a, b) => {
            let (l, r) = sorted_pair(as_var(a)?, as_var(b)?);
            Some(CanonExpr::Xor(l, r))
        }

        // Non-commutative binary ops -- preserve order
        SsaExpr::Sub(a, b) => Some(CanonExpr::Sub(as_var(a)?, as_var(b)?)),
        SsaExpr::Shl(a, b) => Some(CanonExpr::Shl(as_var(a)?, as_var(b)?)),
        SsaExpr::Lsr(a, b) => Some(CanonExpr::Lsr(as_var(a)?, as_var(b)?)),
        SsaExpr::Asr(a, b) => Some(CanonExpr::Asr(as_var(a)?, as_var(b)?)),
        SsaExpr::Ror(a, b) => Some(CanonExpr::Ror(as_var(a)?, as_var(b)?)),

        // Unary ops
        SsaExpr::Neg(a) => Some(CanonExpr::Neg(as_var(a)?)),
        SsaExpr::Not(a) => Some(CanonExpr::Not(as_var(a)?)),

        // Unary with extra fields
        SsaExpr::ZeroExtend { src, from_bits } => Some(CanonExpr::ZeroExtend {
            src: as_var(src)?,
            from_bits: *from_bits,
        }),
        SsaExpr::SignExtend { src, from_bits } => Some(CanonExpr::SignExtend {
            src: as_var(src)?,
            from_bits: *from_bits,
        }),
        SsaExpr::Extract { src, lsb, width } => Some(CanonExpr::Extract {
            src: as_var(src)?,
            lsb: *lsb,
            width: *width,
        }),

        // Everything else: not eligible for CSE
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Scoped hash table
// ---------------------------------------------------------------------------

struct ScopedMap {
    map: HashMap<CanonExpr, SsaVar>,
    scopes: Vec<Vec<CanonExpr>>,
}

impl ScopedMap {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            scopes: Vec::new(),
        }
    }

    fn push_scope(&mut self) {
        self.scopes.push(Vec::new());
    }

    fn pop_scope(&mut self) {
        if let Some(keys) = self.scopes.pop() {
            for k in keys {
                self.map.remove(&k);
            }
        }
    }

    fn insert(&mut self, key: CanonExpr, value: SsaVar) {
        self.map.insert(key.clone(), value);
        if let Some(scope) = self.scopes.last_mut() {
            scope.push(key);
        }
    }

    fn get(&self, key: &CanonExpr) -> Option<SsaVar> {
        self.map.get(key).copied()
    }
}

// ---------------------------------------------------------------------------
// Main CSE pass
// ---------------------------------------------------------------------------

/// Run dominator-tree walk CSE. Returns true if any changes were made.
pub fn run(func: &mut SsaFunction, dom_tree: &DomTree, _use_def: &mut UseDefMap) -> bool {
    let mut table = ScopedMap::new();
    let mut changed = false;

    cse_block(func, dom_tree, func.entry, &mut table, &mut changed);

    changed
}

fn cse_block(
    func: &mut SsaFunction,
    dom_tree: &DomTree,
    block_id: BlockId,
    table: &mut ScopedMap,
    changed: &mut bool,
) {
    table.push_scope();

    let block_idx = func.blocks.iter().position(|b| b.id == block_id);
    if let Some(block_idx) = block_idx {
        for stmt_idx in 0..func.blocks[block_idx].stmts.len() {
            if let SsaStmt::Assign { dst, src } = &func.blocks[block_idx].stmts[stmt_idx] {
                let dst = *dst;
                if let Some(canon) = try_canonicalize(src) {
                    if let Some(existing) = table.get(&canon) {
                        // CSE hit: replace this assignment with a copy
                        func.blocks[block_idx].stmts[stmt_idx] = SsaStmt::Assign {
                            dst,
                            src: SsaExpr::Var(existing),
                        };
                        *changed = true;
                    } else {
                        // First occurrence: register in table
                        table.insert(canon, dst);
                    }
                }
            }
        }
    }

    // Recurse into dominated children
    let children: Vec<BlockId> = dom_tree.dom_children(block_id).to_vec();
    for child in children {
        cse_block(func, dom_tree, child, table, changed);
    }

    table.pop_scope();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::construct::{SsaBlock, SsaFunction};
    use crate::ssa::domtree::DomTree;
    use crate::ssa::use_def::UseDefMap;

    /// Helper: create an SsaVar for Gpr(n) with given version.
    fn var(n: u8, version: u32) -> SsaVar {
        SsaVar {
            loc: RegLocation::Gpr(n),
            version,
            width: RegWidth::W64,
        }
    }

    /// Helper: build an SsaFunction from a list of (id, stmts, successors).
    /// Predecessors are computed automatically.
    fn make_func(blocks: &[(BlockId, Vec<SsaStmt>, Vec<BlockId>)]) -> SsaFunction {
        let mut pred_map: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for &(id, _, _) in blocks {
            pred_map.entry(id).or_default();
        }
        for &(id, _, ref succs) in blocks {
            for &s in succs {
                pred_map.entry(s).or_default().push(id);
            }
        }
        let ssa_blocks: Vec<SsaBlock> = blocks
            .iter()
            .map(|(id, stmts, succs)| SsaBlock {
                id: *id,
                addr: *id as u64 * 4,
                stmts: stmts.clone(),
                successors: succs.clone(),
                predecessors: pred_map.get(id).cloned().unwrap_or_default(),
            })
            .collect();
        SsaFunction {
            entry: blocks[0].0,
            blocks: ssa_blocks,
        }
    }

    // -----------------------------------------------------------------------
    // 1. cse_same_block
    // -----------------------------------------------------------------------
    #[test]
    fn cse_same_block() {
        // v1 = Add(va, vb)
        // v2 = Add(va, vb)
        // --> v2 should be replaced with Var(v1)
        let va = var(0, 0);
        let vb = var(1, 0);
        let v1 = var(2, 1);
        let v2 = var(3, 1);

        let mut func = make_func(&[(
            0,
            vec![
                SsaStmt::Assign {
                    dst: v1,
                    src: SsaExpr::Add(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
                },
                SsaStmt::Assign {
                    dst: v2,
                    src: SsaExpr::Add(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
                },
            ],
            vec![],
        )]);

        let dom = DomTree::build(&func);
        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &dom, &mut ud);

        assert!(changed);
        // v2's source should now be Var(v1)
        assert_eq!(
            func.blocks[0].stmts[1],
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Var(v1),
            }
        );
        // v1 should be unchanged
        assert_eq!(
            func.blocks[0].stmts[0],
            SsaStmt::Assign {
                dst: v1,
                src: SsaExpr::Add(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb)),),
            }
        );
    }

    // -----------------------------------------------------------------------
    // 2. cse_dominated
    // -----------------------------------------------------------------------
    #[test]
    fn cse_dominated() {
        // Block A (0, entry): v1 = Mul(va, vb)
        // Block B (1, dominated by A): v2 = Mul(va, vb)
        // --> v2 should be replaced with Var(v1)
        let va = var(0, 0);
        let vb = var(1, 0);
        let v1 = var(2, 1);
        let v2 = var(3, 1);

        let mut func = make_func(&[
            (
                0,
                vec![SsaStmt::Assign {
                    dst: v1,
                    src: SsaExpr::Mul(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
                }],
                vec![1],
            ),
            (
                1,
                vec![SsaStmt::Assign {
                    dst: v2,
                    src: SsaExpr::Mul(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
                }],
                vec![],
            ),
        ]);

        let dom = DomTree::build(&func);
        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &dom, &mut ud);

        assert!(changed);
        assert_eq!(
            func.blocks[1].stmts[0],
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Var(v1),
            }
        );
    }

    // -----------------------------------------------------------------------
    // 3. cse_not_dominated
    // -----------------------------------------------------------------------
    #[test]
    fn cse_not_dominated() {
        // Diamond: A(0) -> B(1), C(2) -> D(3)
        // B and C are siblings (neither dominates the other)
        // B: v1 = Add(va, vb)
        // C: v2 = Add(va, vb)
        // --> both should survive (no CSE across non-dominating siblings)
        let va = var(0, 0);
        let vb = var(1, 0);
        let v1 = var(2, 1);
        let v2 = var(3, 1);

        let orig_b_stmt = SsaStmt::Assign {
            dst: v1,
            src: SsaExpr::Add(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
        };
        let orig_c_stmt = SsaStmt::Assign {
            dst: v2,
            src: SsaExpr::Add(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
        };

        let mut func = make_func(&[
            (0, vec![], vec![1, 2]),
            (1, vec![orig_b_stmt.clone()], vec![3]),
            (2, vec![orig_c_stmt.clone()], vec![3]),
            (3, vec![], vec![]),
        ]);

        let dom = DomTree::build(&func);
        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &dom, &mut ud);

        assert!(!changed);
        // Both statements should be untouched
        assert_eq!(func.blocks[1].stmts[0], orig_b_stmt);
        assert_eq!(func.blocks[2].stmts[0], orig_c_stmt);
    }

    // -----------------------------------------------------------------------
    // 4. cse_commutative
    // -----------------------------------------------------------------------
    #[test]
    fn cse_commutative() {
        // v1 = Add(va, vb)
        // v2 = Add(vb, va)  -- operands reversed
        // --> v2 should be replaced (operands canonicalized)
        let va = var(0, 0);
        let vb = var(1, 0);
        let v1 = var(2, 1);
        let v2 = var(3, 1);

        let mut func = make_func(&[(
            0,
            vec![
                SsaStmt::Assign {
                    dst: v1,
                    src: SsaExpr::Add(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
                },
                SsaStmt::Assign {
                    dst: v2,
                    src: SsaExpr::Add(Box::new(SsaExpr::Var(vb)), Box::new(SsaExpr::Var(va))),
                },
            ],
            vec![],
        )]);

        let dom = DomTree::build(&func);
        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &dom, &mut ud);

        assert!(changed);
        assert_eq!(
            func.blocks[0].stmts[1],
            SsaStmt::Assign {
                dst: v2,
                src: SsaExpr::Var(v1),
            }
        );
    }

    // -----------------------------------------------------------------------
    // 5. cse_sub_not_commutative
    // -----------------------------------------------------------------------
    #[test]
    fn cse_sub_not_commutative() {
        // v1 = Sub(va, vb)
        // v2 = Sub(vb, va)  -- reversed operands
        // --> both should survive (Sub is NOT commutative)
        let va = var(0, 0);
        let vb = var(1, 0);
        let v1 = var(2, 1);
        let v2 = var(3, 1);

        let orig_s1 = SsaStmt::Assign {
            dst: v1,
            src: SsaExpr::Sub(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
        };
        let orig_s2 = SsaStmt::Assign {
            dst: v2,
            src: SsaExpr::Sub(Box::new(SsaExpr::Var(vb)), Box::new(SsaExpr::Var(va))),
        };

        let mut func = make_func(&[(0, vec![orig_s1.clone(), orig_s2.clone()], vec![])]);

        let dom = DomTree::build(&func);
        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &dom, &mut ud);

        assert!(!changed);
        assert_eq!(func.blocks[0].stmts[0], orig_s1);
        assert_eq!(func.blocks[0].stmts[1], orig_s2);
    }

    // -----------------------------------------------------------------------
    // 6. cse_no_load_dedup
    // -----------------------------------------------------------------------
    #[test]
    fn cse_no_load_dedup() {
        // v1 = Load(va, 4)
        // v2 = Load(va, 4)
        // --> both should survive (loads are excluded from CSE)
        let va = var(0, 0);
        let v1 = var(2, 1);
        let v2 = var(3, 1);

        let orig_s1 = SsaStmt::Assign {
            dst: v1,
            src: SsaExpr::Load {
                addr: Box::new(SsaExpr::Var(va)),
                size: 4,
            },
        };
        let orig_s2 = SsaStmt::Assign {
            dst: v2,
            src: SsaExpr::Load {
                addr: Box::new(SsaExpr::Var(va)),
                size: 4,
            },
        };

        let mut func = make_func(&[(0, vec![orig_s1.clone(), orig_s2.clone()], vec![])]);

        let dom = DomTree::build(&func);
        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &dom, &mut ud);

        assert!(!changed);
        assert_eq!(func.blocks[0].stmts[0], orig_s1);
        assert_eq!(func.blocks[0].stmts[1], orig_s2);
    }

    // -----------------------------------------------------------------------
    // 7. cse_different_ops
    // -----------------------------------------------------------------------
    #[test]
    fn cse_different_ops() {
        // v1 = Add(va, vb)
        // v2 = Sub(va, vb)
        // --> both should survive (different operations)
        let va = var(0, 0);
        let vb = var(1, 0);
        let v1 = var(2, 1);
        let v2 = var(3, 1);

        let orig_s1 = SsaStmt::Assign {
            dst: v1,
            src: SsaExpr::Add(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
        };
        let orig_s2 = SsaStmt::Assign {
            dst: v2,
            src: SsaExpr::Sub(Box::new(SsaExpr::Var(va)), Box::new(SsaExpr::Var(vb))),
        };

        let mut func = make_func(&[(0, vec![orig_s1.clone(), orig_s2.clone()], vec![])]);

        let dom = DomTree::build(&func);
        let mut ud = UseDefMap::build(&func);
        let changed = run(&mut func, &dom, &mut ud);

        assert!(!changed);
        assert_eq!(func.blocks[0].stmts[0], orig_s1);
        assert_eq!(func.blocks[0].stmts[1], orig_s2);
    }
}
