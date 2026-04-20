// aeon-instrument: dynamic instrumentation via aeon-jit
//
// Architecture:
//   LiveContext (registers + memory accessor)
//     → DynCfg (lazy CFG expansion using the lifter)
//       → JIT compile discovered blocks with trace hooks
//         → TraceLog (execution trace + dataflow records)
//           → SymbolicFolder (fold invariants from concrete traces)
//
// Unlike Frida, this does NOT inject into a live process.
// It receives a snapshot (context + memory reader), then:
//   1. Lifts ARM64 blocks on demand as execution reaches them
//   2. JIT-compiles each block to x86_64 with instrumentation
//   3. Executes on the host, expanding the CFG dynamically
//   4. Records full execution + dataflow traces
//   5. Applies symbolic analysis to identify invariants

pub mod callbacks;
pub mod context;
pub mod dyncfg;
pub mod dynffi;
pub mod dynruntime;
pub mod engine;
pub mod parallel_cfg;
pub mod snapshot;
pub mod symbolic;
pub mod symbolic_cache;
pub mod trace;
pub mod translate;
