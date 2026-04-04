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

use aeon_jit::JitContext;

use crate::context::LiveContext;
use crate::dyncfg::DynCfg;
use crate::symbolic::{FoldResult, SymbolicFolder};
use crate::trace::{BlockTrace, MemoryAccess, RegSnapshot, TraceLog};

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
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_steps: 10_000,
            max_memory_ops: 1_000_000,
            max_block_visits: 1_000,
            breakpoints: Vec::new(),
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
    UnmappedMemory(u64),
    LiftError(u64, String),
    /// Execution reached a halt/return.
    Halted,
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
}

impl InstrumentEngine {
    pub fn new(context: LiveContext) -> Self {
        Self {
            context,
            cfg: DynCfg::new(),
            trace: TraceLog::new(),
            config: EngineConfig::default(),
        }
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    /// Run the engine until a stop condition is met.
    pub fn run(&mut self) -> StopReason {
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

            // Check block visit count
            let visits = self.trace.traces_for_block(pc).len() as u64;
            if visits >= self.config.max_block_visits {
                return StopReason::MaxBlockVisits(pc);
            }

            // Get or compile the block
            let (entry, block_addr) = match self.cfg.get_or_compile(pc, self.context.memory.as_ref())
            {
                Ok(b) => (b.entry, b.addr),
                Err(e) => return StopReason::LiftError(pc, format!("{:?}", e)),
            };

            // Capture entry register snapshot
            let entry_regs = RegSnapshot::from(&self.context.regs);

            // Set up thread-local trace state for this block
            TRACE_BLOCK_ADDR.with(|b| *b.borrow_mut() = block_addr);
            TRACE_SEQ.with(|s| *s.borrow_mut() = self.trace.next_seq());
            MEMORY_TRACE.with(|t| t.borrow_mut().clear());

            // Execute the JIT-compiled block
            let next_pc = unsafe { entry(&mut self.context.regs as *mut JitContext) };

            // Capture exit register snapshot
            let exit_regs = RegSnapshot::from(&self.context.regs);

            // Drain memory accesses from thread-local
            let memory_accesses = MEMORY_TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()));

            // Build and record the block trace
            let visit_count = self.trace.traces_for_block(block_addr).len() as u64 + 1;
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

    /// Run symbolic folding on the collected trace.
    pub fn fold(&self) -> FoldResult {
        SymbolicFolder::fold(&self.trace)
    }

    /// Number of unique blocks discovered.
    pub fn discovered_blocks(&self) -> usize {
        self.cfg.block_count()
    }
}

impl Drop for InstrumentEngine {
    fn drop(&mut self) {
        // Clear global callbacks to avoid dangling references
        self.cfg
            .compiler_mut()
            .set_memory_read_callback(None);
        self.cfg
            .compiler_mut()
            .set_memory_write_callback(None);
    }
}
