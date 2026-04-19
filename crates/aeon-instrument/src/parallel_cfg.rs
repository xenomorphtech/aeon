// Parallel CFG discovery infrastructure (Phase 2 optimization)
//
// Future parallel block compilation with rayon work-stealing.
// Current blocker: JitEntry function pointers cannot safely cross thread boundaries.
//
// Alternative optimization: Batch process discovered blocks in larger chunks
// to amortize JIT compilation overhead and improve cache locality.
//
// This module provides the infrastructure and will be activated once either:
// 1. aeon-jit exposes thread-safe compilation API
// 2. We implement custom block memoization without cross-thread JitEntry transfer

/// Configuration for parallel CFG optimization.
#[derive(Debug, Clone)]
pub struct ParallelCfgConfig {
    /// Enable batch processing of discovered blocks
    pub enable_batching: bool,
    /// Batch size for block discovery (blocks to discover before compiling)
    pub batch_size: usize,
    /// Maximum number of pending uncompiled blocks before blocking discovery
    pub max_pending: usize,
}

impl Default for ParallelCfgConfig {
    fn default() -> Self {
        Self {
            enable_batching: true,
            batch_size: 128,
            max_pending: 512,
        }
    }
}

/// Statistics for parallel CFG processing.
#[derive(Debug, Clone, Default)]
pub struct ParallelCfgStats {
    /// Total addresses discovered
    pub total_discovered: usize,
    /// Addresses compiled successfully
    pub compiled: usize,
    /// Addresses that failed to compile
    pub failed: usize,
    /// Batches processed
    pub batches: usize,
    /// Total wall time in milliseconds
    pub elapsed_ms: u128,
}