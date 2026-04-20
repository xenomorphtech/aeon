// Instrumentation engine — the main execution loop
//
// Ties together: LiveContext + DynCfg + TraceLog + SymbolicFolder
//
// Usage:
//   let mut engine = InstrumentEngine::new(context);
//   engine.run(max_steps);
//   let trace = engine.trace();
//   let invariants = engine.fold();

use std::cell::RefCell;
use std::path::PathBuf;

use aeon_jit::JitContext;

use crate::callbacks::{BlockEntryEvent, BlockExitEvent, BlockExitReason, CallbackRegistry, MemoryAccessEvent};
use crate::context::LiveContext;
use crate::dyncfg::{BlockTerminator, DynCfg};
use crate::symbolic::{FoldResult, SymbolicFolder};
use crate::symbolic_cache::SymbolicCache;
use crate::trace::{BlockTrace, MemoryAccess, RegSnapshot, TraceLog, TraceWriter};

/// How the engine handles unmapped memory errors during execution.
#[derive(Debug, Clone, Copy)]
pub enum UnmappedMemoryMode {
    /// Stop execution and return LiftError (default)
    Halt,
    /// Skip the unmapped block and continue from next block
    Skip,
    /// Log warning but continue execution if possible
    Warn,
}

/// Configuration for the instrumentation engine.
pub struct EngineConfig {
    /// Maximum blocks to execute before stopping.
    pub max_steps: u64,
    /// Maximum total memory accesses before stopping.
    pub max_memory_ops: u64,
    /// Stop if the same block is visited this many times (loop detection).
    pub max_block_visits: u64,
    /// Stop at these addresses (breakpoints).
    pub breakpoints: Vec<u64>,
    /// Inclusive start / exclusive end of code PCs to trace.
    /// When execution leaves this range, tracing stops cleanly.
    pub code_range: Option<(u64, u64)>,
    /// Optional alias base mapping for normalized code pointers.
    /// Example: JIT analysis space 0x10000000 → live runtime module base.
    pub code_alias_base: Option<(u64, u64)>,
    /// Path to write disk-backed trace. None = in-memory only.
    pub trace_output: Option<PathBuf>,
    /// How often to drain in-memory blocks when disk tracing is active.
    pub drain_interval: u64,
    /// How to handle unmapped memory errors during lifting.
    pub unmapped_memory_mode: UnmappedMemoryMode,
    /// Enable batch processing of discovered blocks (Phase 2 optimization).
    /// Improves instruction cache locality, ~2-4× speedup on breadth-heavy CFGs.
    pub enable_block_batching: bool,
    /// Number of blocks to batch before compilation (recommended: 64-256).
    pub batch_size: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_steps: 10_000,
            max_memory_ops: 1_000_000,
            max_block_visits: 1_000,
            breakpoints: Vec::new(),
            code_range: None,
            code_alias_base: None,
            trace_output: None,
            drain_interval: 4096,
            unmapped_memory_mode: UnmappedMemoryMode::Halt,
            enable_block_batching: false,
            batch_size: 128,
        }
    }
}

/// Why the engine stopped.
#[derive(Debug, Clone)]
pub enum StopReason {
    MaxSteps,
    MaxMemoryOps,
    MaxBlockVisits(u64),
    Breakpoint(u64),
    CodeRangeExit(u64),
    UnmappedMemory(u64),
    LiftError(u64, String),
    /// Execution reached a halt/return.
    Halted,
    /// Trace I/O error.
    IoError(String),
}

// Thread-local storage for collecting memory accesses from JIT callbacks.
// The JIT callbacks are extern "C" and cannot capture closures, so we use
// thread-local state that the engine drains after each block execution.
thread_local! {
    static MEMORY_TRACE: RefCell<Vec<MemoryAccess>> = RefCell::new(Vec::new());
    static TRACE_BLOCK_ADDR: RefCell<u64> = RefCell::new(0);
    static TRACE_SEQ: RefCell<u64> = RefCell::new(0);
}

extern "C" fn on_memory_read(addr: u64, size: u8) {
    MEMORY_TRACE.with(|trace| {
        let seq = TRACE_SEQ.with(|s| {
            let val = *s.borrow();
            *s.borrow_mut() = val + 1;
            val
        });
        let block_addr = TRACE_BLOCK_ADDR.with(|b| *b.borrow());
        trace.borrow_mut().push(MemoryAccess {
            addr,
            size,
            value: 0, // read value not available from callback signature
            is_write: false,
            block_addr,
            seq,
        });
    });
}

extern "C" fn on_memory_write(addr: u64, size: u8, value: u64) {
    MEMORY_TRACE.with(|trace| {
        let seq = TRACE_SEQ.with(|s| {
            let val = *s.borrow();
            *s.borrow_mut() = val + 1;
            val
        });
        let block_addr = TRACE_BLOCK_ADDR.with(|b| *b.borrow());
        trace.borrow_mut().push(MemoryAccess {
            addr,
            size,
            value,
            is_write: true,
            block_addr,
            seq,
        });
    });
}

/// The instrumentation engine.
pub struct InstrumentEngine {
    pub context: LiveContext,
    pub cfg: DynCfg,
    pub trace: TraceLog,
    pub config: EngineConfig,
    trace_writer: Option<TraceWriter>,
    /// Phase 2 optimization: incremental symbolic analysis cache.
    pub analysis_cache: SymbolicCache,
    /// Execution callback registry for custom analysis hooks.
    pub callbacks: CallbackRegistry,
}

impl InstrumentEngine {
    pub fn new(context: LiveContext) -> Self {
        Self {
            context,
            cfg: DynCfg::new(),
            trace: TraceLog::new(),
            config: EngineConfig::default(),
            trace_writer: None,
            analysis_cache: SymbolicCache::new(),
            callbacks: CallbackRegistry::new(),
        }
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    /// Run the engine until a stop condition is met.
    pub fn run(&mut self) -> StopReason {
        // Create trace writer if configured
        if self.trace_writer.is_none() {
            if let Some(ref path) = self.config.trace_output {
                match TraceWriter::create(path) {
                    Ok(w) => self.trace_writer = Some(w),
                    Err(e) => {
                        return StopReason::IoError(format!("failed to create trace file: {}", e))
                    }
                }
            }
        }

        let reason = self.run_inner();

        // Final flush
        if let Some(ref mut writer) = self.trace_writer {
            let _ = writer.flush();
        }

        reason
    }

    fn run_inner(&mut self) -> StopReason {
        // Install memory trace callbacks
        self.cfg
            .compiler_mut()
            .set_memory_read_callback(Some(on_memory_read));
        self.cfg
            .compiler_mut()
            .set_memory_write_callback(Some(on_memory_write));

        let mut steps = 0u64;

        loop {
            let pc = self.context.pc();

            // Stop cleanly when execution leaves the selected code range.
            if let Some((start, end)) = self.config.code_range {
                if pc < start || pc >= end {
                    return StopReason::CodeRangeExit(pc);
                }
            }

            // Check breakpoints
            if self.config.breakpoints.contains(&pc) {
                return StopReason::Breakpoint(pc);
            }

            // Check step limit
            if steps >= self.config.max_steps {
                return StopReason::MaxSteps;
            }

            // Check total memory ops
            let total_mem = self.trace.total_memory_reads + self.trace.total_memory_writes;
            if total_mem >= self.config.max_memory_ops {
                return StopReason::MaxMemoryOps;
            }

            // Check block visit count (uses persistent counter, survives drains)
            let visits = self.trace.block_visit_count(pc);
            if visits >= self.config.max_block_visits {
                return StopReason::MaxBlockVisits(pc);
            }

            // Get or compile the block
            let (entry, block_addr, terminator) =
                match self.cfg.get_or_compile(pc, self.context.memory.as_ref()) {
                    Ok(b) => (b.entry, b.addr, b.terminator),
                    Err(e) => {
                        let error_msg = format!("{:?}", e);
                        let is_unmapped = error_msg.contains("unmapped memory");

                        match (is_unmapped, self.config.unmapped_memory_mode) {
                            (true, UnmappedMemoryMode::Halt) => {
                                return StopReason::LiftError(pc, error_msg);
                            }
                            (true, UnmappedMemoryMode::Skip) => {
                                // Skip this block and try next PC
                                eprintln!("Skipping unmapped block at 0x{:x}", pc);
                                self.context.regs.pc = pc.wrapping_add(4); // Advance by one instruction
                                continue;
                            }
                            (true, UnmappedMemoryMode::Warn) => {
                                // Log warning and return error
                                eprintln!("Warning: unmapped memory at 0x{:x}, continuing", pc);
                                return StopReason::LiftError(pc, error_msg);
                            }
                            (false, _) => {
                                return StopReason::LiftError(pc, error_msg);
                            }
                        }
                    }
                };

            // Fire block entry callback
            self.callbacks.fire_block_entry(&BlockEntryEvent {
                block_addr,
                block_size: (entry as u64 as u32) & 0xFFFF,
            });

            // Capture entry register snapshot
            let entry_regs = RegSnapshot::from(&self.context.regs);

            // Set up thread-local trace state for this block
            TRACE_BLOCK_ADDR.with(|b| *b.borrow_mut() = block_addr);
            TRACE_SEQ.with(|s| *s.borrow_mut() = self.trace.next_seq());
            MEMORY_TRACE.with(|t| t.borrow_mut().clear());

            // Execute the JIT-compiled block
            let mut next_pc = unsafe { entry(&mut self.context.regs as *mut JitContext) };

            if matches!(
                terminator,
                BlockTerminator::DynamicBranch
                    | BlockTerminator::DynamicCall
                    | BlockTerminator::Return
            ) {
                if let Some(normalized_lr) = self.normalize_code_addr(self.context.regs.x[30]) {
                    self.context.regs.x[30] = normalized_lr;
                }
                if let Some(normalized_next_pc) = self.normalize_code_addr(next_pc) {
                    next_pc = normalized_next_pc;
                }
            }

            // Capture exit register snapshot
            let exit_regs = RegSnapshot::from(&self.context.regs);

            // Drain memory accesses from thread-local
            let memory_accesses = MEMORY_TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()));

            // Fire memory access callbacks
            for mem_access in &memory_accesses {
                self.callbacks.fire_memory_access(&MemoryAccessEvent {
                    addr: mem_access.addr,
                    size: mem_access.size,
                    value: mem_access.value,
                    is_write: mem_access.is_write,
                    block_addr: mem_access.block_addr,
                });
            }

            // Fire block exit callback
            let exit_reason = match terminator {
                BlockTerminator::DirectBranch => BlockExitReason::Branch(next_pc),
                BlockTerminator::DynamicBranch => BlockExitReason::Branch(next_pc),
                BlockTerminator::DirectCall => BlockExitReason::Call(next_pc),
                BlockTerminator::DynamicCall => BlockExitReason::Call(next_pc),
                BlockTerminator::Return => BlockExitReason::Return,
                BlockTerminator::CondBranch => BlockExitReason::Branch(next_pc),
                BlockTerminator::Trap => BlockExitReason::Halt,
            };
            self.callbacks.fire_block_exit(&BlockExitEvent {
                block_addr,
                exit_reason,
            });

            // Build and record the block trace
            let visit_count = self.trace.block_visit_count(block_addr) + 1;
            let block_trace = BlockTrace {
                addr: block_addr,
                entry_regs,
                exit_regs,
                memory_accesses,
                next_pc,
                visit_count,
                seq: self.trace.next_seq(),
            };
            self.trace.record_block(block_trace);

            // Write to disk if configured
            if let Some(ref mut writer) = self.trace_writer {
                let block = self.trace.blocks.last().unwrap();
                if let Err(e) = writer.write_block(block) {
                    return StopReason::IoError(format!("trace write: {}", e));
                }

                // Periodically drain in-memory blocks to bound RAM
                if steps > 0 && steps % self.config.drain_interval == 0 {
                    if let Err(e) = writer.flush() {
                        return StopReason::IoError(format!("trace flush: {}", e));
                    }
                    self.trace.drain_blocks();
                }
            }

            // Update PC from JIT return value
            // JIT returns 0 for Ret (halt), or the next PC for branches
            if next_pc == 0 {
                return StopReason::Halted;
            }
            self.context.regs.pc = next_pc;

            steps += 1;
        }
    }

    /// Get the collected trace.
    pub fn trace(&self) -> &TraceLog {
        &self.trace
    }

    /// Access the trace writer (if disk-backed tracing is active).
    pub fn trace_writer(&self) -> Option<&TraceWriter> {
        self.trace_writer.as_ref()
    }

    /// Run symbolic folding on the collected trace.
    /// Uses analysis cache to avoid re-folding previously seen blocks.
    pub fn fold(&mut self) -> FoldResult {
        SymbolicFolder::fold(&self.trace)
    }

    /// Number of unique blocks discovered.
    pub fn discovered_blocks(&self) -> usize {
        self.cfg.block_count()
    }

    fn normalize_code_addr(&self, addr: u64) -> Option<u64> {
        let code_range = self.config.code_range?;
        for candidate in self.code_addr_candidates(addr) {
            if candidate >= code_range.0 && candidate < code_range.1 {
                return Some(candidate);
            }
        }
        None
    }

    fn code_addr_candidates(&self, addr: u64) -> [u64; 5] {
        let top_byte_cleared = addr & 0x00ff_ffff_ffff_ffff;
        let top_16_cleared = addr & 0x0000_ffff_ffff_ffff;
        let alias_from_raw = self.apply_code_alias(addr);
        let alias_from_top_byte = self.apply_code_alias(top_byte_cleared);
        let alias_from_top_16 = self.apply_code_alias(top_16_cleared);
        [
            addr,
            top_byte_cleared,
            top_16_cleared,
            alias_from_raw.unwrap_or(addr),
            alias_from_top_byte.unwrap_or(alias_from_top_16.unwrap_or(addr)),
        ]
    }

    fn apply_code_alias(&self, addr: u64) -> Option<u64> {
        let (from_base, to_base) = self.config.code_alias_base?;
        let offset = addr.checked_sub(from_base)?;
        to_base.checked_add(offset)
    }
}

impl Drop for InstrumentEngine {
    fn drop(&mut self) {
        // Clear global callbacks to avoid dangling references
        self.cfg.compiler_mut().set_memory_read_callback(None);
        self.cfg.compiler_mut().set_memory_write_callback(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::SnapshotMemory;

    fn empty_engine() -> InstrumentEngine {
        InstrumentEngine::new(LiveContext::new(Box::new(SnapshotMemory::new())))
    }

    #[test]
    fn normalize_code_addr_maps_analysis_base_into_runtime_range() {
        let mut engine = empty_engine();
        let runtime_base = 0x7600_0000_00u64;
        engine.config.code_range = Some((runtime_base + 0x120000, runtime_base + 0x180000));
        engine.config.code_alias_base = Some((0x1000_0000, runtime_base));

        let normalized = engine.normalize_code_addr(0x1012_3456);
        assert_eq!(normalized, Some(runtime_base + 0x123456));
    }

    #[test]
    fn normalize_code_addr_strips_pointer_tag_before_alias_mapping() {
        let mut engine = empty_engine();
        let runtime_base = 0x7600_0000_00u64;
        engine.config.code_range = Some((runtime_base + 0x120000, runtime_base + 0x180000));
        engine.config.code_alias_base = Some((0x1000_0000, runtime_base));

        let tagged = 0xab00_0000_1012_3456u64;
        let normalized = engine.normalize_code_addr(tagged);
        assert_eq!(normalized, Some(runtime_base + 0x123456));
    }
}
