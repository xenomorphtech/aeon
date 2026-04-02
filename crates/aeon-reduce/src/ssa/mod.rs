/// SSA (Static Single Assignment) subsystem for AeonIL.
///
/// Provides CFG construction, dominance computation, SSA form conversion,
/// and classic SSA-based optimization passes (DCE, copy propagation, SCCP,
/// CSE, dead branch elimination).

pub mod types;
pub mod cfg;
pub mod construct;
pub mod convert;
pub mod domtree;
pub mod use_def;
pub mod dce;
pub mod copy_prop;
pub mod sccp;
pub mod cse;
pub mod dead_branch;
pub mod pipeline;
