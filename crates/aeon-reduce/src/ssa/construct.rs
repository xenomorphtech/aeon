//! SSA construction -- implements the Braun et al. "Simple and Efficient
//! Construction of SSA Form" (2013) algorithm.  Since all predecessors are
//! known from the CFG upfront, all blocks are sealed immediately.
//!
//! The key idea: instead of computing dominance frontiers and placing phi
//! functions explicitly, variable lookups lazily recurse through predecessors,
//! inserting phi nodes on demand and removing trivial ones.

use super::cfg::Cfg;
use super::types::*;
use aeonil::{BranchCond, Expr, Reg, Stmt};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// SSA basic block with versioned statements.
#[derive(Debug, Clone)]
pub struct SsaBlock {
    pub id: BlockId,
    pub addr: u64,
    pub stmts: Vec<SsaStmt>,
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
}

/// Complete SSA function.
#[derive(Debug, Clone)]
pub struct SsaFunction {
    pub entry: BlockId,
    pub blocks: Vec<SsaBlock>,
}

// ---------------------------------------------------------------------------
// Builder (internal)
// ---------------------------------------------------------------------------

/// SSA construction state.
struct SsaBuilder {
    /// Current variable definitions per block: block -> location -> SsaVar
    current_def: HashMap<BlockId, HashMap<RegLocation, SsaVar>>,
    /// Version counter per location
    version_counter: HashMap<RegLocation, u32>,
    /// The blocks being built (SsaBlock with stmts)
    blocks: Vec<SsaBlock>,
    /// Predecessor info from the Cfg
    predecessors: HashMap<BlockId, Vec<BlockId>>,
}

impl SsaBuilder {
    fn new(cfg: &Cfg) -> Self {
        let mut predecessors = HashMap::new();
        let mut blocks = Vec::new();
        for bb in &cfg.blocks {
            predecessors.insert(bb.id, bb.predecessors.clone());
            blocks.push(SsaBlock {
                id: bb.id,
                addr: bb.addr,
                stmts: Vec::new(),
                successors: bb.successors.clone(),
                predecessors: bb.predecessors.clone(),
            });
        }
        SsaBuilder {
            current_def: HashMap::new(),
            version_counter: HashMap::new(),
            blocks,
            predecessors,
        }
    }

    fn new_version(&mut self, loc: RegLocation) -> u32 {
        let counter = self.version_counter.entry(loc).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Record that `var` is the current definition of `loc` in `block`.
    fn write_variable(&mut self, block: BlockId, loc: RegLocation, var: SsaVar) {
        self.current_def.entry(block).or_default().insert(loc, var);
    }

    /// Read the current definition of `loc` in `block`.
    fn read_variable(&mut self, block: BlockId, loc: RegLocation) -> SsaVar {
        // If block has a local definition, return it
        if let Some(var) = self.current_def.get(&block).and_then(|m| m.get(&loc)) {
            return *var;
        }
        // Otherwise recurse to predecessors
        self.read_variable_recursive(block, loc)
    }

    fn read_variable_recursive(&mut self, block: BlockId, loc: RegLocation) -> SsaVar {
        let preds = self.predecessors.get(&block).cloned().unwrap_or_default();

        let var = if preds.is_empty() {
            // Entry block, no predecessors: create entry version (version 0)
            SsaVar {
                loc,
                version: 0,
                width: loc.full_width(),
            }
        } else if preds.len() == 1 {
            // Single predecessor: no phi needed
            self.read_variable(preds[0], loc)
        } else {
            // Multiple predecessors: insert phi
            let version = self.new_version(loc);
            let phi_var = SsaVar {
                loc,
                version,
                width: loc.full_width(),
            };
            // Write the phi result BEFORE recursing to break cycles
            self.write_variable(block, loc, phi_var);

            let mut operands = Vec::new();
            for &pred in &preds {
                let pred_var = self.read_variable(pred, loc);
                operands.push((pred, pred_var));
            }

            // Try to remove trivial phi
            // During initial construction, do NOT remove self-referencing
            // trivial phis -- the back-edge value isn't final yet.
            let simplified = Self::try_remove_trivial_phi(phi_var, &operands, false);
            if simplified != phi_var {
                self.write_variable(block, loc, simplified);
                return simplified;
            }

            // Insert phi at the beginning of the block
            let phi_stmt = SsaStmt::Assign {
                dst: phi_var,
                src: SsaExpr::Phi(operands),
            };
            self.blocks[block as usize].stmts.insert(0, phi_stmt);

            phi_var
        };

        self.write_variable(block, loc, var);
        var
    }

    /// Try to simplify a trivial phi. A phi is trivial if all operands
    /// (excluding self-references) are the same value.
    ///
    /// If `allow_self_trivial` is false, phis with self-references are
    /// never removed (used during initial construction when back-edge
    /// values are not yet final). If true, self-referencing phis where
    /// all non-self operands agree are removed (used in the fixup pass).
    fn try_remove_trivial_phi(
        phi_var: SsaVar,
        operands: &[(BlockId, SsaVar)],
        allow_self_trivial: bool,
    ) -> SsaVar {
        let mut same: Option<SsaVar> = None;
        let mut has_self_ref = false;
        for &(_, op) in operands {
            if op == phi_var {
                has_self_ref = true;
                continue; // self-reference
            }
            if let Some(s) = same {
                if s != op {
                    return phi_var; // non-trivial: different operands
                }
            } else {
                same = Some(op);
            }
        }
        // If there's a self-reference and we're not allowed to remove
        // self-trivial phis, keep it.
        if has_self_ref && !allow_self_trivial {
            return phi_var;
        }
        // All operands are the same (or self): trivial
        same.unwrap_or(phi_var)
    }

    // -----------------------------------------------------------------------
    // Statement processing: convert each original Stmt, applying SSA
    // versioning (reads via read_variable, writes via write_variable).
    // -----------------------------------------------------------------------

    /// Convert an aeonil `Expr` to `SsaExpr`, handling XZR reads as Imm(0)
    /// and W register reads as Extract of the full GPR.
    fn convert_read_expr(&mut self, block: BlockId, expr: &Expr) -> SsaExpr {
        match expr {
            Expr::Reg(Reg::XZR) => SsaExpr::Imm(0),
            Expr::Reg(Reg::PC) => panic!("PC should not appear in reduced IL"),
            Expr::Reg(r) => {
                let (loc, width) = reg_to_location(r);
                let var = self.read_variable(block, loc);
                if width < loc.full_width() {
                    // Sub-register read (e.g. W(n) from Gpr(n)):
                    // Extract the low bits
                    SsaExpr::Extract {
                        src: Box::new(SsaExpr::Var(var)),
                        lsb: 0,
                        width: width.bits(),
                    }
                } else {
                    SsaExpr::Var(var)
                }
            }
            Expr::Imm(v) => SsaExpr::Imm(*v),
            Expr::FImm(v) => SsaExpr::FImm(*v),
            Expr::Load { addr, size } => SsaExpr::Load {
                addr: Box::new(self.convert_read_expr(block, addr)),
                size: *size,
            },
            Expr::Add(a, b) => SsaExpr::Add(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Sub(a, b) => SsaExpr::Sub(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Mul(a, b) => SsaExpr::Mul(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Div(a, b) => SsaExpr::Div(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::UDiv(a, b) => SsaExpr::UDiv(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Neg(a) => SsaExpr::Neg(Box::new(self.convert_read_expr(block, a))),
            Expr::Abs(a) => SsaExpr::Abs(Box::new(self.convert_read_expr(block, a))),
            Expr::And(a, b) => SsaExpr::And(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Or(a, b) => SsaExpr::Or(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Xor(a, b) => SsaExpr::Xor(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Not(a) => SsaExpr::Not(Box::new(self.convert_read_expr(block, a))),
            Expr::Shl(a, b) => SsaExpr::Shl(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Lsr(a, b) => SsaExpr::Lsr(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Asr(a, b) => SsaExpr::Asr(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::Ror(a, b) => SsaExpr::Ror(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::SignExtend { src, from_bits } => SsaExpr::SignExtend {
                src: Box::new(self.convert_read_expr(block, src)),
                from_bits: *from_bits,
            },
            Expr::ZeroExtend { src, from_bits } => SsaExpr::ZeroExtend {
                src: Box::new(self.convert_read_expr(block, src)),
                from_bits: *from_bits,
            },
            Expr::Extract { src, lsb, width } => SsaExpr::Extract {
                src: Box::new(self.convert_read_expr(block, src)),
                lsb: *lsb,
                width: *width,
            },
            Expr::Insert {
                dst,
                src,
                lsb,
                width,
            } => SsaExpr::Insert {
                dst: Box::new(self.convert_read_expr(block, dst)),
                src: Box::new(self.convert_read_expr(block, src)),
                lsb: *lsb,
                width: *width,
            },
            Expr::FAdd(a, b) => SsaExpr::FAdd(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::FSub(a, b) => SsaExpr::FSub(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::FMul(a, b) => SsaExpr::FMul(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::FDiv(a, b) => SsaExpr::FDiv(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::FNeg(a) => SsaExpr::FNeg(Box::new(self.convert_read_expr(block, a))),
            Expr::FAbs(a) => SsaExpr::FAbs(Box::new(self.convert_read_expr(block, a))),
            Expr::FSqrt(a) => SsaExpr::FSqrt(Box::new(self.convert_read_expr(block, a))),
            Expr::FMax(a, b) => SsaExpr::FMax(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::FMin(a, b) => SsaExpr::FMin(
                Box::new(self.convert_read_expr(block, a)),
                Box::new(self.convert_read_expr(block, b)),
            ),
            Expr::FCvt(a) => SsaExpr::FCvt(Box::new(self.convert_read_expr(block, a))),
            Expr::IntToFloat(a) => SsaExpr::IntToFloat(Box::new(self.convert_read_expr(block, a))),
            Expr::FloatToInt(a) => SsaExpr::FloatToInt(Box::new(self.convert_read_expr(block, a))),
            Expr::Clz(a) => SsaExpr::Clz(Box::new(self.convert_read_expr(block, a))),
            Expr::Cls(a) => SsaExpr::Cls(Box::new(self.convert_read_expr(block, a))),
            Expr::Rev(a) => SsaExpr::Rev(Box::new(self.convert_read_expr(block, a))),
            Expr::Rbit(a) => SsaExpr::Rbit(Box::new(self.convert_read_expr(block, a))),
            Expr::CondSelect {
                cond,
                if_true,
                if_false,
            } => SsaExpr::CondSelect {
                cond: *cond,
                if_true: Box::new(self.convert_read_expr(block, if_true)),
                if_false: Box::new(self.convert_read_expr(block, if_false)),
            },
            Expr::Compare { cond, lhs, rhs } => SsaExpr::Compare {
                cond: *cond,
                lhs: Box::new(self.convert_read_expr(block, lhs)),
                rhs: Box::new(self.convert_read_expr(block, rhs)),
            },
            Expr::StackSlot { offset, size } => SsaExpr::StackSlot {
                offset: *offset,
                size: *size,
            },
            Expr::MrsRead(s) => SsaExpr::MrsRead(s.clone()),
            Expr::Intrinsic { name, operands } => SsaExpr::Intrinsic {
                name: name.clone(),
                operands: operands
                    .iter()
                    .map(|op| self.convert_read_expr(block, op))
                    .collect(),
            },
            Expr::AdrpImm(v) => SsaExpr::AdrpImm(*v),
            Expr::AdrImm(v) => SsaExpr::AdrImm(*v),
        }
    }

    /// Convert an aeonil `BranchCond` with SSA versioning.
    fn convert_read_branch_cond(&mut self, block: BlockId, cond: &BranchCond) -> SsaBranchCond {
        match cond {
            BranchCond::Flag(c) => {
                let flags = self.read_variable(block, RegLocation::Flags);
                SsaBranchCond::Flag(*c, flags)
            }
            BranchCond::Zero(expr) => SsaBranchCond::Zero(self.convert_read_expr(block, expr)),
            BranchCond::NotZero(expr) => {
                SsaBranchCond::NotZero(self.convert_read_expr(block, expr))
            }
            BranchCond::BitZero(expr, bit) => {
                SsaBranchCond::BitZero(self.convert_read_expr(block, expr), *bit)
            }
            BranchCond::BitNotZero(expr, bit) => {
                SsaBranchCond::BitNotZero(self.convert_read_expr(block, expr), *bit)
            }
            BranchCond::Compare { cond: c, lhs, rhs } => SsaBranchCond::Compare {
                cond: *c,
                lhs: Box::new(self.convert_read_expr(block, lhs)),
                rhs: Box::new(self.convert_read_expr(block, rhs)),
            },
        }
    }

    /// Process a single original statement, producing zero or more SsaStmts
    /// appended to the block.
    fn process_stmt(&mut self, block: BlockId, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { dst, src } => {
                if matches!(dst, Reg::XZR | Reg::PC) {
                    // Writes to XZR are discarded
                    self.blocks[block as usize].stmts.push(SsaStmt::Nop);
                    return;
                }

                let (loc, width) = reg_to_location(dst);
                let ssa_src = self.convert_read_expr(block, src);

                // Handle sub-register writes: wrap in ZeroExtend
                let final_src = if width < loc.full_width() {
                    SsaExpr::ZeroExtend {
                        src: Box::new(ssa_src),
                        from_bits: width.bits(),
                    }
                } else {
                    ssa_src
                };

                let version = self.new_version(loc);
                let ssa_dst = SsaVar {
                    loc,
                    version,
                    width: loc.full_width(),
                };
                self.write_variable(block, loc, ssa_dst);

                self.blocks[block as usize].stmts.push(SsaStmt::Assign {
                    dst: ssa_dst,
                    src: final_src,
                });
            }

            Stmt::Store { addr, value, size } => {
                let ssa_addr = self.convert_read_expr(block, addr);
                let ssa_value = self.convert_read_expr(block, value);
                self.blocks[block as usize].stmts.push(SsaStmt::Store {
                    addr: ssa_addr,
                    value: ssa_value,
                    size: *size,
                });
            }

            Stmt::Branch { target } => {
                let ssa_target = self.convert_read_expr(block, target);
                self.blocks[block as usize]
                    .stmts
                    .push(SsaStmt::Branch { target: ssa_target });
            }

            Stmt::CondBranch {
                cond,
                target,
                fallthrough: _,
            } => {
                let ssa_cond = self.convert_read_branch_cond(block, cond);
                let ssa_target = self.convert_read_expr(block, target);
                // Fallthrough block id: determined from the CFG successors.
                // The second successor (if any) is the fallthrough.
                let succs = &self.blocks[block as usize].successors.clone();
                let fallthrough_id = if succs.len() >= 2 { succs[1] } else { 0 };
                self.blocks[block as usize].stmts.push(SsaStmt::CondBranch {
                    cond: ssa_cond,
                    target: ssa_target,
                    fallthrough: fallthrough_id,
                });
            }

            Stmt::Call { target } => {
                let ssa_target = self.convert_read_expr(block, target);
                self.blocks[block as usize]
                    .stmts
                    .push(SsaStmt::Call { target: ssa_target });

                // After a call, clobber all caller-saved registers:
                // Gpr(0)..Gpr(18) and Flags
                for i in 0..=18u8 {
                    let loc = RegLocation::Gpr(i);
                    let version = self.new_version(loc);
                    let var = SsaVar {
                        loc,
                        version,
                        width: RegWidth::W64,
                    };
                    self.write_variable(block, loc, var);
                }
                {
                    let loc = RegLocation::Flags;
                    let version = self.new_version(loc);
                    let var = SsaVar {
                        loc,
                        version,
                        width: RegWidth::Full,
                    };
                    self.write_variable(block, loc, var);
                }
            }

            Stmt::Ret => {
                self.blocks[block as usize].stmts.push(SsaStmt::Ret);
            }

            Stmt::Nop => {
                self.blocks[block as usize].stmts.push(SsaStmt::Nop);
            }

            Stmt::SetFlags { expr } => {
                let ssa_expr = self.convert_read_expr(block, expr);
                let loc = RegLocation::Flags;
                let version = self.new_version(loc);
                let flags_var = SsaVar {
                    loc,
                    version,
                    width: RegWidth::Full,
                };
                self.write_variable(block, loc, flags_var);
                self.blocks[block as usize].stmts.push(SsaStmt::SetFlags {
                    src: flags_var,
                    expr: ssa_expr,
                });
            }

            Stmt::Barrier(s) => {
                self.blocks[block as usize]
                    .stmts
                    .push(SsaStmt::Barrier(s.clone()));
            }

            Stmt::Trap { kind, imm } => {
                self.blocks[block as usize].stmts.push(SsaStmt::Trap {
                    kind: *kind,
                    imm: *imm,
                });
            }

            Stmt::Intrinsic { name, operands } => {
                let ssa_ops: Vec<SsaExpr> = operands
                    .iter()
                    .map(|op| self.convert_read_expr(block, op))
                    .collect();
                self.blocks[block as usize].stmts.push(SsaStmt::Intrinsic {
                    name: name.clone(),
                    operands: ssa_ops,
                });
            }

            Stmt::Pair(a, b) => {
                self.process_stmt(block, a);
                self.process_stmt(block, b);
            }
        }
    }

    /// Process all blocks in order (Braun algorithm handles any order).
    fn process_all_blocks(&mut self, cfg: &Cfg) {
        for bb in &cfg.blocks {
            let block_id = bb.id;
            let stmts: Vec<Stmt> = bb.stmts.clone();
            for stmt in &stmts {
                self.process_stmt(block_id, stmt);
            }
        }
        // Fixup pass: update phi operands to use final current_def values
        // (handles back-edges where the predecessor hadn't been fully processed
        // when the phi was created).
        self.fixup_phis();
    }

    /// After all blocks are processed, update phi operands to reflect the
    /// final `current_def` for each predecessor block, then remove any
    /// newly-trivial phis.
    fn fixup_phis(&mut self) {
        let mut changed = true;
        while changed {
            changed = false;
            for bi in 0..self.blocks.len() {
                let mut si = 0;
                while si < self.blocks[bi].stmts.len() {
                    let needs_update = matches!(
                        &self.blocks[bi].stmts[si],
                        SsaStmt::Assign {
                            src: SsaExpr::Phi(_),
                            ..
                        }
                    );
                    if !needs_update {
                        si += 1;
                        continue;
                    }

                    // Extract phi info
                    let (phi_var, operands) = match &self.blocks[bi].stmts[si] {
                        SsaStmt::Assign {
                            dst,
                            src: SsaExpr::Phi(ops),
                        } => (*dst, ops.clone()),
                        _ => unreachable!(),
                    };

                    // Re-read operands from current_def (final values)
                    let updated_ops: Vec<(BlockId, SsaVar)> = operands
                        .iter()
                        .map(|&(pred, _)| {
                            let var = self
                                .current_def
                                .get(&pred)
                                .and_then(|m| m.get(&phi_var.loc))
                                .copied()
                                .unwrap_or(SsaVar {
                                    loc: phi_var.loc,
                                    version: 0,
                                    width: phi_var.loc.full_width(),
                                });
                            (pred, var)
                        })
                        .collect();

                    // Check if this phi is now trivial
                    // In the fixup pass, self-trivial removal IS allowed
                    // because all blocks have been fully processed.
                    let simplified = Self::try_remove_trivial_phi(phi_var, &updated_ops, true);
                    if simplified != phi_var {
                        // Remove the phi statement
                        self.blocks[bi].stmts.remove(si);
                        // Update current_def: anything referencing phi_var should use simplified
                        self.write_variable(bi as BlockId, phi_var.loc, simplified);
                        changed = true;
                        // Don't increment si since we removed the element
                    } else if updated_ops != operands {
                        // Update the phi operands
                        self.blocks[bi].stmts[si] = SsaStmt::Assign {
                            dst: phi_var,
                            src: SsaExpr::Phi(updated_ops),
                        };
                        changed = true;
                        si += 1;
                    } else {
                        si += 1;
                    }
                }
            }
        }
    }

    /// Finalize: produce the SsaFunction.
    fn finish(self, entry: BlockId) -> SsaFunction {
        SsaFunction {
            entry,
            blocks: self.blocks,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build SSA form from a CFG with pre-reduced statements.
pub fn build_ssa(cfg: &Cfg) -> SsaFunction {
    let mut builder = SsaBuilder::new(cfg);
    builder.process_all_blocks(cfg);
    builder.finish(cfg.entry)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::cfg::build_cfg;
    use super::*;
    use aeonil::{BranchCond, Condition, Expr, Reg, Stmt};

    /// Helper: build a single-block CFG from statements, then construct SSA.
    fn single_block_ssa(stmts: Vec<Stmt>) -> SsaFunction {
        let len = stmts.len();
        let instrs: Vec<(u64, Stmt, Vec<u64>)> = stmts
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                let addr = 0x1000 + (i as u64) * 4;
                let next = addr + 4;
                if i + 1 < len {
                    // Sequential: flows to the next instruction
                    (addr, s, vec![next])
                } else {
                    // Last statement: terminal (no edges)
                    (addr, s, vec![])
                }
            })
            .collect();
        let cfg = build_cfg(&instrs);
        build_ssa(&cfg)
    }

    /// Helper: build a multi-block CFG from instruction triples, then SSA.
    fn multi_block_ssa(instrs: Vec<(u64, Stmt, Vec<u64>)>) -> SsaFunction {
        let cfg = build_cfg(&instrs);
        build_ssa(&cfg)
    }

    // -- helpers to find statements in an SsaFunction --

    fn find_assigns(func: &SsaFunction, loc: RegLocation) -> Vec<&SsaStmt> {
        func.blocks
            .iter()
            .flat_map(|b| b.stmts.iter())
            .filter(|s| matches!(s, SsaStmt::Assign { dst, .. } if dst.loc == loc))
            .collect()
    }

    fn find_assigns_in_block(
        func: &SsaFunction,
        block: BlockId,
        loc: RegLocation,
    ) -> Vec<&SsaStmt> {
        func.blocks[block as usize]
            .stmts
            .iter()
            .filter(|s| matches!(s, SsaStmt::Assign { dst, .. } if dst.loc == loc))
            .collect()
    }

    fn get_assign_dst(s: &SsaStmt) -> &SsaVar {
        match s {
            SsaStmt::Assign { dst, .. } => dst,
            _ => panic!("not an assign"),
        }
    }

    fn get_assign_src(s: &SsaStmt) -> &SsaExpr {
        match s {
            SsaStmt::Assign { src, .. } => src,
            _ => panic!("not an assign"),
        }
    }

    // -----------------------------------------------------------------------
    // 1. ssa_single_def -- X0 = Imm(42) in one block
    // -----------------------------------------------------------------------
    #[test]
    fn ssa_single_def() {
        let func = single_block_ssa(vec![Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Imm(42),
        }]);

        assert_eq!(func.blocks.len(), 1);
        let assigns = find_assigns(&func, RegLocation::Gpr(0));
        assert_eq!(assigns.len(), 1);
        let dst = get_assign_dst(assigns[0]);
        assert_eq!(dst.loc, RegLocation::Gpr(0));
        assert_eq!(dst.version, 1); // first version
        assert_eq!(dst.width, RegWidth::W64);
        assert_eq!(*get_assign_src(assigns[0]), SsaExpr::Imm(42));
    }

    // -----------------------------------------------------------------------
    // 2. ssa_two_defs -- X0 = 1; X0 = 2
    // -----------------------------------------------------------------------
    #[test]
    fn ssa_two_defs() {
        let func = single_block_ssa(vec![
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(1),
            },
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(2),
            },
        ]);

        let assigns = find_assigns(&func, RegLocation::Gpr(0));
        assert_eq!(assigns.len(), 2);

        let d1 = get_assign_dst(assigns[0]);
        let d2 = get_assign_dst(assigns[1]);
        assert_eq!(d1.version, 1);
        assert_eq!(d2.version, 2);
        assert_ne!(d1, d2);

        assert_eq!(*get_assign_src(assigns[0]), SsaExpr::Imm(1));
        assert_eq!(*get_assign_src(assigns[1]), SsaExpr::Imm(2));
    }

    // -----------------------------------------------------------------------
    // 3. ssa_use_before_def -- X1 = Add(X0, 1) where X0 never defined
    // -----------------------------------------------------------------------
    #[test]
    fn ssa_use_before_def() {
        let func = single_block_ssa(vec![Stmt::Assign {
            dst: Reg::X(1),
            src: Expr::Add(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(1))),
        }]);

        let assigns = find_assigns(&func, RegLocation::Gpr(1));
        assert_eq!(assigns.len(), 1);

        // The source should reference gpr0_v0 (entry version)
        match get_assign_src(assigns[0]) {
            SsaExpr::Add(lhs, rhs) => {
                match lhs.as_ref() {
                    SsaExpr::Var(v) => {
                        assert_eq!(v.loc, RegLocation::Gpr(0));
                        assert_eq!(v.version, 0); // entry version
                    }
                    other => panic!("expected Var, got {:?}", other),
                }
                assert_eq!(**rhs, SsaExpr::Imm(1));
            }
            other => panic!("expected Add, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 4. ssa_def_use_chain -- X0=1; X1=Add(X0,2); X0=3; X2=Add(X0,4)
    // -----------------------------------------------------------------------
    #[test]
    fn ssa_def_use_chain() {
        let func = single_block_ssa(vec![
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(1),
            },
            Stmt::Assign {
                dst: Reg::X(1),
                src: Expr::Add(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(2))),
            },
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(3),
            },
            Stmt::Assign {
                dst: Reg::X(2),
                src: Expr::Add(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(4))),
            },
        ]);

        // X1 = Add(gpr0_v1, 2)  -- uses first X0 def
        let x1_assigns = find_assigns(&func, RegLocation::Gpr(1));
        assert_eq!(x1_assigns.len(), 1);
        match get_assign_src(x1_assigns[0]) {
            SsaExpr::Add(lhs, _) => {
                match lhs.as_ref() {
                    SsaExpr::Var(v) => {
                        assert_eq!(v.loc, RegLocation::Gpr(0));
                        assert_eq!(v.version, 1); // first def of X0
                    }
                    other => panic!("expected Var, got {:?}", other),
                }
            }
            other => panic!("expected Add, got {:?}", other),
        }

        // X2 = Add(gpr0_v2, 4)  -- uses second X0 def
        let x2_assigns = find_assigns(&func, RegLocation::Gpr(2));
        assert_eq!(x2_assigns.len(), 1);
        match get_assign_src(x2_assigns[0]) {
            SsaExpr::Add(lhs, _) => {
                match lhs.as_ref() {
                    SsaExpr::Var(v) => {
                        assert_eq!(v.loc, RegLocation::Gpr(0));
                        assert_eq!(v.version, 2); // second def of X0
                    }
                    other => panic!("expected Var, got {:?}", other),
                }
            }
            other => panic!("expected Add, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 5. phi_diamond -- A: X0=1, B: X0=2, C (merge): use X0 -> phi at C
    // -----------------------------------------------------------------------
    #[test]
    fn phi_diamond() {
        // Block A (0x100): X0=1, cond branch to B (0x108) or C (0x10c)
        // Block B (0x108): X0=2, branch to D (0x110)
        // Block C (0x10c): X0=3, branch to D (0x110)
        // Block D (0x110): X1 = X0 (should get phi)
        let instrs = vec![
            (
                0x100u64,
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Imm(1),
                },
                vec![0x104],
            ),
            (
                0x104,
                Stmt::CondBranch {
                    cond: BranchCond::Flag(Condition::EQ),
                    target: Expr::Imm(0x108),
                    fallthrough: 0x10c,
                },
                vec![0x108, 0x10c],
            ),
            (
                0x108,
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Imm(2),
                },
                vec![0x110],
            ),
            (
                0x10c,
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Imm(3),
                },
                vec![0x110],
            ),
            (
                0x110,
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: Expr::Reg(Reg::X(0)),
                },
                vec![],
            ),
        ];

        let func = multi_block_ssa(instrs);

        // Block D (last block) should have a phi for gpr0 and an assign for gpr1
        let d = func.blocks.last().unwrap();
        let gpr0_assigns: Vec<_> = d
            .stmts
            .iter()
            .filter(|s| matches!(s, SsaStmt::Assign { dst, .. } if dst.loc == RegLocation::Gpr(0)))
            .collect();

        // Should have a phi
        assert!(
            !gpr0_assigns.is_empty(),
            "expected phi for gpr0 in merge block"
        );
        let phi_stmt = gpr0_assigns[0];
        match get_assign_src(phi_stmt) {
            SsaExpr::Phi(operands) => {
                assert_eq!(operands.len(), 2);
                // Each operand should have a different version
                assert_ne!(operands[0].1.version, operands[1].1.version);
            }
            other => panic!("expected Phi, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 6. phi_trivial_removed -- both branches assign same value -> no phi
    // -----------------------------------------------------------------------
    #[test]
    fn phi_trivial_removed() {
        // Block A (0x100): cond branch to B (0x108) or C (0x10c)
        // Block B (0x108): branch to D (0x110)  (no X0 redefinition)
        // Block C (0x10c): branch to D (0x110)  (no X0 redefinition)
        // Block D (0x110): X1 = X0
        //
        // Since neither B nor C redefine X0, both read A's definition.
        // The phi is trivial and should be removed.
        let instrs = vec![
            (
                0x100u64,
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Imm(42),
                },
                vec![0x104],
            ),
            (
                0x104,
                Stmt::CondBranch {
                    cond: BranchCond::Flag(Condition::EQ),
                    target: Expr::Imm(0x108),
                    fallthrough: 0x10c,
                },
                vec![0x108, 0x10c],
            ),
            (
                0x108,
                Stmt::Branch {
                    target: Expr::Imm(0x110),
                },
                vec![0x110],
            ),
            (
                0x10c,
                Stmt::Branch {
                    target: Expr::Imm(0x110),
                },
                vec![0x110],
            ),
            (
                0x110,
                Stmt::Assign {
                    dst: Reg::X(1),
                    src: Expr::Reg(Reg::X(0)),
                },
                vec![],
            ),
        ];

        let func = multi_block_ssa(instrs);
        let d = func.blocks.last().unwrap();

        // No phi for gpr0 in the merge block (trivially removed)
        let gpr0_phis: Vec<_> = d
            .stmts
            .iter()
            .filter(|s| match s {
                SsaStmt::Assign { dst, src } => {
                    dst.loc == RegLocation::Gpr(0) && matches!(src, SsaExpr::Phi(_))
                }
                _ => false,
            })
            .collect();
        assert!(gpr0_phis.is_empty(), "trivial phi should have been removed");

        // X1's source should be Var(gpr0_v1) directly (the version from block A)
        let x1_assigns = find_assigns_in_block(&func, d.id, RegLocation::Gpr(1));
        assert_eq!(x1_assigns.len(), 1);
        match get_assign_src(x1_assigns[0]) {
            SsaExpr::Var(v) => {
                assert_eq!(v.loc, RegLocation::Gpr(0));
                assert_eq!(v.version, 1); // A's definition
            }
            other => panic!("expected Var (trivial phi removed), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 7. phi_loop_header -- X0 defined before loop, modified in loop body
    // -----------------------------------------------------------------------
    #[test]
    fn phi_loop_header() {
        // Block A (0x100): X0 = 0, branch to B (loop header)
        // Block B (0x104): X1 = X0 (reads phi), X0 = Add(X0, 1),
        //                  cond branch back to B or exit to C
        // Block C (0x110): ret
        //
        // We want a phi at block B for X0.
        let instrs = vec![
            (
                0x100u64,
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Imm(0),
                },
                vec![0x104],
            ),
            // loop header
            (
                0x104,
                Stmt::Assign {
                    dst: Reg::X(0),
                    src: Expr::Add(Box::new(Expr::Reg(Reg::X(0))), Box::new(Expr::Imm(1))),
                },
                vec![0x108],
            ),
            (
                0x108,
                Stmt::CondBranch {
                    cond: BranchCond::Flag(Condition::NE),
                    target: Expr::Imm(0x104),
                    fallthrough: 0x10c,
                },
                vec![0x104, 0x10c],
            ),
            (0x10c, Stmt::Ret, vec![]),
        ];

        let func = multi_block_ssa(instrs);

        // The loop header block (block containing 0x104) should have a phi for gpr0
        // because it has two predecessors: A and itself (back-edge).
        let loop_header = &func.blocks[1]; // block 1 = {0x104, 0x108}
        assert!(
            loop_header.predecessors.len() >= 2,
            "loop header should have >=2 preds"
        );

        let gpr0_phis: Vec<_> = loop_header
            .stmts
            .iter()
            .filter(|s| match s {
                SsaStmt::Assign { dst, src } => {
                    dst.loc == RegLocation::Gpr(0) && matches!(src, SsaExpr::Phi(_))
                }
                _ => false,
            })
            .collect();
        assert!(
            !gpr0_phis.is_empty(),
            "expected phi for gpr0 at loop header"
        );

        // The phi should have 2 operands
        match get_assign_src(gpr0_phis[0]) {
            SsaExpr::Phi(ops) => {
                assert_eq!(ops.len(), 2);
            }
            _ => unreachable!(),
        }
    }

    // -----------------------------------------------------------------------
    // 8. xzr_becomes_imm0 -- Add(XZR, Imm(1)) -> Add(Imm(0), Imm(1))
    // -----------------------------------------------------------------------
    #[test]
    fn xzr_becomes_imm0() {
        let func = single_block_ssa(vec![Stmt::Assign {
            dst: Reg::X(0),
            src: Expr::Add(Box::new(Expr::Reg(Reg::XZR)), Box::new(Expr::Imm(1))),
        }]);

        let assigns = find_assigns(&func, RegLocation::Gpr(0));
        assert_eq!(assigns.len(), 1);
        match get_assign_src(assigns[0]) {
            SsaExpr::Add(lhs, rhs) => {
                assert_eq!(**lhs, SsaExpr::Imm(0), "XZR should become Imm(0)");
                assert_eq!(**rhs, SsaExpr::Imm(1));
            }
            other => panic!("expected Add, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 9. call_clobbers_caller_saved -- after Call, X0 gets new version
    // -----------------------------------------------------------------------
    #[test]
    fn call_clobbers_caller_saved() {
        let func = single_block_ssa(vec![
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(10),
            },
            Stmt::Call {
                target: Expr::Imm(0xdead),
            },
            Stmt::Assign {
                dst: Reg::X(1),
                src: Expr::Reg(Reg::X(0)),
            },
        ]);

        // X0 is defined with v1 before call. After call, X0 is clobbered to v2.
        // X1's source should be gpr0_v2 (the clobbered version), NOT v1.
        let x1_assigns = find_assigns(&func, RegLocation::Gpr(1));
        assert_eq!(x1_assigns.len(), 1);
        match get_assign_src(x1_assigns[0]) {
            SsaExpr::Var(v) => {
                assert_eq!(v.loc, RegLocation::Gpr(0));
                assert!(
                    v.version > 1,
                    "X0 after call should have version > 1 (was clobbered), got {}",
                    v.version
                );
            }
            other => panic!("expected Var, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 10. wx_write_w_produces_zext -- W(0) = Imm(42) -> ZeroExtend(Imm(42), 32)
    // -----------------------------------------------------------------------
    #[test]
    fn wx_write_w_produces_zext() {
        let func = single_block_ssa(vec![Stmt::Assign {
            dst: Reg::W(0),
            src: Expr::Imm(42),
        }]);

        let assigns = find_assigns(&func, RegLocation::Gpr(0));
        assert_eq!(assigns.len(), 1);
        let dst = get_assign_dst(assigns[0]);
        assert_eq!(dst.loc, RegLocation::Gpr(0));
        assert_eq!(dst.width, RegWidth::W64); // canonical width

        match get_assign_src(assigns[0]) {
            SsaExpr::ZeroExtend { src, from_bits } => {
                assert_eq!(**src, SsaExpr::Imm(42));
                assert_eq!(*from_bits, 32);
            }
            other => panic!("expected ZeroExtend, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 11. wx_read_w_produces_extract -- reading W(0) when last def was X(0)
    // -----------------------------------------------------------------------
    #[test]
    fn wx_read_w_produces_extract() {
        let func = single_block_ssa(vec![
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0xFFFF_FFFF_FFFF_FFFF),
            },
            Stmt::Assign {
                dst: Reg::X(1),
                src: Expr::Reg(Reg::W(0)),
            },
        ]);

        let x1_assigns = find_assigns(&func, RegLocation::Gpr(1));
        assert_eq!(x1_assigns.len(), 1);
        match get_assign_src(x1_assigns[0]) {
            SsaExpr::Extract { src, lsb, width } => {
                match src.as_ref() {
                    SsaExpr::Var(v) => {
                        assert_eq!(v.loc, RegLocation::Gpr(0));
                        assert_eq!(v.version, 1); // the X(0) def
                    }
                    other => panic!("expected Var inside Extract, got {:?}", other),
                }
                assert_eq!(*lsb, 0);
                assert_eq!(*width, 32);
            }
            other => panic!("expected Extract, got {:?}", other),
        }
    }
}
