// Execution and dataflow tracing
//
// Records every block entry, register state transition, and memory
// read/write during instrumented execution. The trace is the raw
// material for symbolic folding.

use aeon_jit::JitContext;
use serde::{Deserialize, Serialize};

/// A single memory access observed during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccess {
    pub addr: u64,
    pub size: u8,
    pub value: u64,
    pub is_write: bool,
    /// Block address where this access occurred.
    pub block_addr: u64,
    /// Sequential index within the trace.
    pub seq: u64,
}

/// Register state snapshot at a block boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegSnapshot {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub flags: u64,
}

impl From<&JitContext> for RegSnapshot {
    fn from(ctx: &JitContext) -> Self {
        Self {
            x: ctx.x,
            sp: ctx.sp,
            pc: ctx.pc,
            flags: ctx.flags,
        }
    }
}

/// A traced block execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTrace {
    pub addr: u64,
    pub entry_regs: RegSnapshot,
    pub exit_regs: RegSnapshot,
    pub memory_accesses: Vec<MemoryAccess>,
    pub next_pc: u64,
    /// How many times this block has been visited.
    pub visit_count: u64,
    pub seq: u64,
}

/// Full execution trace — append-only log.
#[derive(Debug, Default)]
pub struct TraceLog {
    pub blocks: Vec<BlockTrace>,
    pub total_memory_reads: u64,
    pub total_memory_writes: u64,
    next_seq: u64,
}

impl TraceLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_block(&mut self, trace: BlockTrace) {
        self.total_memory_reads += trace
            .memory_accesses
            .iter()
            .filter(|a| !a.is_write)
            .count() as u64;
        self.total_memory_writes += trace
            .memory_accesses
            .iter()
            .filter(|a| a.is_write)
            .count() as u64;
        self.blocks.push(trace);
        self.next_seq += 1;
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// All unique block addresses visited.
    pub fn unique_blocks(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.blocks.iter().map(|b| b.addr).collect();
        addrs.sort();
        addrs.dedup();
        addrs
    }

    /// Visit count per block address.
    pub fn visit_counts(&self) -> std::collections::BTreeMap<u64, u64> {
        let mut counts = std::collections::BTreeMap::new();
        for b in &self.blocks {
            *counts.entry(b.addr).or_insert(0) += 1;
        }
        counts
    }

    /// Extract the trace for a specific block address.
    pub fn traces_for_block(&self, addr: u64) -> Vec<&BlockTrace> {
        self.blocks.iter().filter(|b| b.addr == addr).collect()
    }
}
