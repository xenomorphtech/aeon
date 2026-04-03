pub mod cfg;
pub mod construct;
pub mod convert;
pub mod copy_prop;
pub mod cse;
pub mod dce;
pub mod dead_branch;
pub mod domtree;
pub mod pipeline;
pub mod sccp;
/// SSA (Static Single Assignment) subsystem for AeonIL.
///
/// Provides CFG construction, dominance computation, SSA form conversion,
/// and classic SSA-based optimization passes (DCE, copy propagation, SCCP,
/// CSE, dead branch elimination).
pub mod types;
pub mod use_def;
