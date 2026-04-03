/// aeon-reduce -- IL reduction and SSA-based optimization passes for AeonIL.
///
/// Top-level modules implement peephole/local reductions on AeonIL statements,
/// while the `ssa` submodule provides SSA construction, analysis, and transforms.
pub mod env;
pub mod pipeline;
pub mod reduce_adrp;
pub mod reduce_const;
pub mod reduce_ext;
pub mod reduce_flags;
pub mod reduce_movk;
pub mod reduce_pair;
pub mod reduce_stack;
pub mod ssa;
