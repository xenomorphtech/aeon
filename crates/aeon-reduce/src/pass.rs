//! Pass tables and the runners that drive them.
//!
//! Every reduction stage is a list of named passes. The order of a list is
//! the order the passes run in, and it is written down once, here and in
//! `ssa::pipeline`. A runner applies a list, records how many rewrites each
//! pass reported, and calls an observer after every pass so that a caller
//! can validate the intermediate IL and name the pass that broke it.

use aeonil::Stmt;

use crate::reduce_adrp::resolve_adrp_add_with_stats;
use crate::reduce_const::fold_constants;
use crate::reduce_ext::fold_extensions;
use crate::reduce_flags::{eliminate_dead_flags, eliminate_dead_flags_cfg, fuse_flags_with_stats};
use crate::reduce_pair::flatten_pairs;
use crate::reduce_stack::{detect_prologue, rewrite_stack_accesses};
use crate::ssa::cfg::Cfg;

/// How many rewrites each pass reported, by pass name, in the order the
/// passes first ran. A pass that does not count its rewrites reports zero.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassCounts(Vec<(&'static str, usize)>);

impl PassCounts {
    pub fn add(&mut self, name: &'static str, rewrites: usize) {
        match self.0.iter_mut().find(|(known, _)| *known == name) {
            Some((_, total)) => *total += rewrites,
            None => self.0.push((name, rewrites)),
        }
    }

    /// The total for `name`, or zero if no such pass ran.
    pub fn get(&self, name: &str) -> usize {
        self.0
            .iter()
            .find(|(known, _)| *known == name)
            .map_or(0, |(_, total)| *total)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&'static str, usize)> + '_ {
        self.0.iter().copied()
    }
}

/// A rewrite of one basic block's statements that needs nothing but the
/// block.
pub struct BlockPass {
    pub name: &'static str,
    run: fn(Vec<Stmt>) -> (Vec<Stmt>, usize),
}

impl BlockPass {
    /// Applies the pass, returning the new statements and the number of
    /// rewrites it reported.
    pub fn run(&self, stmts: Vec<Stmt>) -> (Vec<Stmt>, usize) {
        (self.run)(stmts)
    }
}

pub const FLATTEN_PAIRS: &str = "flatten-pairs";
pub const FOLD_CONSTANTS: &str = "fold-constants";
pub const FORWARD_CONSTANTS: &str = "forward-constants";
pub const REFOLD_CONSTANTS: &str = "refold-constants";
pub const FUSE_FLAGS: &str = "fuse-flags";
pub const DEAD_FLAGS: &str = "dead-flags";
pub const FOLD_EXTENSIONS: &str = "fold-extensions";

/// The block-local pipeline, in order.
pub const BLOCK_PASSES: &[BlockPass] = &[
    // Structural: later passes look at one statement at a time.
    BlockPass {
        name: FLATTEN_PAIRS,
        run: |stmts| (flatten_pairs(stmts), 0),
    },
    BlockPass {
        name: FOLD_CONSTANTS,
        run: |stmts| (fold_constants(stmts), 0),
    },
    // Substitutes known constants for register reads and resolves
    // ADRP+ADD.
    BlockPass {
        name: FORWARD_CONSTANTS,
        run: resolve_adrp_add_with_stats,
    },
    // Forwarding leaves expressions over constants behind.
    BlockPass {
        name: REFOLD_CONSTANTS,
        run: |stmts| (fold_constants(stmts), 0),
    },
    BlockPass {
        name: FUSE_FLAGS,
        run: fuse_flags_with_stats,
    },
    BlockPass {
        name: DEAD_FLAGS,
        run: |stmts| {
            let before = stmts.len();
            let stmts = eliminate_dead_flags(stmts);
            let removed = before - stmts.len();
            (stmts, removed)
        },
    },
    BlockPass {
        name: FOLD_EXTENSIONS,
        run: |stmts| (fold_extensions(stmts), 0),
    },
];

/// Applies `passes` in order. `observe` is called with each pass's name and
/// its output.
pub fn run_block_passes(
    passes: &[BlockPass],
    mut stmts: Vec<Stmt>,
    counts: &mut PassCounts,
    observe: &mut dyn FnMut(&'static str, &[Stmt]),
) -> Vec<Stmt> {
    for pass in passes {
        let (next, rewrites) = pass.run(stmts);
        counts.add(pass.name, rewrites);
        observe(pass.name, &next);
        stmts = next;
    }
    stmts
}

/// A rewrite that needs the whole function.
pub struct CfgPass {
    pub name: &'static str,
    run: fn(&mut Cfg, &mut PassCounts) -> usize,
}

impl CfgPass {
    /// Applies the pass, returning the number of rewrites it reported.
    /// Counts of any passes it runs in turn go to `counts`.
    pub fn run(&self, cfg: &mut Cfg, counts: &mut PassCounts) -> usize {
        (self.run)(cfg, counts)
    }
}

pub const BLOCK_LOCAL: &str = "block-local";
pub const DEAD_FLAGS_CFG: &str = "dead-flags-cfg";
pub const STACK_SLOTS: &str = "stack-slots";

/// The function-level pipeline, in order.
pub const CFG_PASSES: &[CfgPass] = &[
    EACH_BLOCK,
    // A block cannot tell whether its flags are read later; the function
    // can.
    CfgPass {
        name: DEAD_FLAGS_CFG,
        run: |cfg, _| {
            let count = |cfg: &Cfg| cfg.blocks.iter().map(|block| block.stmts.len()).sum::<usize>();
            let before = count(cfg);
            eliminate_dead_flags_cfg(cfg);
            before - count(cfg)
        },
    },
    // One prologue, from the entry block, names the slots of every block.
    CfgPass {
        name: STACK_SLOTS,
        run: |cfg, _| {
            let Some(prologue) = cfg
                .blocks
                .get(cfg.entry as usize)
                .and_then(|entry| detect_prologue(&entry.stmts))
            else {
                return 0;
            };
            for block in &mut cfg.blocks {
                block.stmts = rewrite_stack_accesses(std::mem::take(&mut block.stmts), &prologue);
            }
            1
        },
    },
];

/// `BLOCK_PASSES` applied to every block of the function.
const EACH_BLOCK: CfgPass = CfgPass {
    name: BLOCK_LOCAL,
    run: |cfg, counts| {
        for block in &mut cfg.blocks {
            block.stmts = run_block_passes(
                BLOCK_PASSES,
                std::mem::take(&mut block.stmts),
                counts,
                &mut |_, _| {},
            );
        }
        0
    },
};

/// Applies `passes` in order. `observe` is called with each pass's name
/// before it runs (`false`) and after (`true`).
pub fn run_cfg_passes(
    passes: &[CfgPass],
    cfg: &mut Cfg,
    counts: &mut PassCounts,
    observe: &mut dyn FnMut(&'static str, bool, &Cfg),
) {
    for pass in passes {
        observe(pass.name, false, cfg);
        let rewrites = pass.run(cfg, counts);
        counts.add(pass.name, rewrites);
        observe(pass.name, true, cfg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{e_add, Expr, Reg};

    #[test]
    fn pass_names_are_unique() {
        let mut names: Vec<_> = BLOCK_PASSES.iter().map(|pass| pass.name).collect();
        names.extend(CFG_PASSES.iter().map(|pass| pass.name));
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total);
    }

    #[test]
    fn observer_sees_every_pass_in_order_and_counts_add_up() {
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::AdrpImm(0x1000),
            },
            Stmt::Assign {
                dst: Reg::X(0),
                src: e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10)),
            },
        ];
        let mut counts = PassCounts::default();
        let mut seen = Vec::new();
        let out = run_block_passes(BLOCK_PASSES, stmts, &mut counts, &mut |name, stmts| {
            seen.push((name, stmts.to_vec()))
        });

        let names: Vec<_> = seen.iter().map(|(name, _)| *name).collect();
        let expected: Vec<_> = BLOCK_PASSES.iter().map(|pass| pass.name).collect();
        assert_eq!(names, expected);
        // The last observation is the result.
        assert_eq!(seen.last().unwrap().1, out);
        assert_eq!(
            out[1],
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::Imm(0x1010)
            }
        );
        assert_eq!(counts.get(FORWARD_CONSTANTS), 1);
        assert_eq!(counts.get("no-such-pass"), 0);
    }

    #[test]
    fn a_prefix_of_the_table_stops_early() {
        let stmts = vec![
            Stmt::Assign {
                dst: Reg::X(0),
                src: Expr::AdrpImm(0x1000),
            },
            Stmt::Assign {
                dst: Reg::X(1),
                src: e_add(Expr::Reg(Reg::X(0)), Expr::Imm(0x10)),
            },
        ];
        let before_forwarding = BLOCK_PASSES
            .iter()
            .position(|pass| pass.name == FORWARD_CONSTANTS)
            .unwrap();
        let out = run_block_passes(
            &BLOCK_PASSES[..before_forwarding],
            stmts.clone(),
            &mut PassCounts::default(),
            &mut |_, _| {},
        );
        assert_eq!(out, stmts);
    }
}
