// Dynamic CFG expansion
//
// Instead of discovering the full CFG statically, DynCfg lifts blocks
// lazily as execution reaches them. This handles:
//   - Indirect branches (resolved from concrete register values)
//   - Packed/obfuscated code (only visited paths need lifting)
//   - Self-modifying code (re-lift if memory changes)
//
// Flow:
//   1. Engine asks DynCfg for the JIT entry at a given PC
//   2. If not cached, DynCfg reads bytes from MemoryProvider
//   3. Lifts the instruction stream to AeonIL basic block
//   4. Compiles via aeon-jit with trace instrumentation
//   5. Caches the entry and returns it
//   6. After execution, the JIT returns the next PC
//   7. Repeat from (1)

use std::collections::BTreeMap;

use aeon_jit::{JitCompiler, JitConfig, JitEntry, JitError};
use aeonil::{Expr, Reg, Stmt};

use crate::context::MemoryProvider;

/// A compiled block entry with metadata.
pub struct CompiledBlock {
    pub addr: u64,
    pub entry: JitEntry,
    pub stmts: Vec<Stmt>,
    pub size_bytes: usize,
    pub terminator: BlockTerminator,
    /// Statically known successors (direct branches).
    pub static_successors: Vec<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockTerminator {
    DirectBranch,
    DynamicBranch,
    DirectCall,
    DynamicCall,
    Return,
    CondBranch,
    Trap,
}

/// Lazily-expanding CFG backed by aeon lifter + JIT.
pub struct DynCfg {
    compiler: JitCompiler,
    blocks: BTreeMap<u64, CompiledBlock>,
    /// Addresses that failed to lift (unmapped, invalid encoding).
    failed: BTreeMap<u64, String>,
}

/// Check if a statement is a block terminator.
fn is_terminator(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Branch { .. }
        | Stmt::CondBranch { .. }
        | Stmt::Call { .. }
        | Stmt::Ret
        | Stmt::Trap => true,
        Stmt::Pair(a, b) => is_terminator(a) || is_terminator(b),
        _ => false,
    }
}

fn classify_terminator(stmt: &Stmt) -> Option<BlockTerminator> {
    match stmt {
        Stmt::Branch { target } => match target {
            Expr::Imm(_) => Some(BlockTerminator::DirectBranch),
            _ => Some(BlockTerminator::DynamicBranch),
        },
        Stmt::CondBranch { .. } => Some(BlockTerminator::CondBranch),
        Stmt::Call { target } => match target {
            Expr::Imm(_) => Some(BlockTerminator::DirectCall),
            _ => Some(BlockTerminator::DynamicCall),
        },
        Stmt::Ret => Some(BlockTerminator::Return),
        Stmt::Trap => Some(BlockTerminator::Trap),
        Stmt::Pair(a, b) => classify_terminator(b).or_else(|| classify_terminator(a)),
        _ => None,
    }
}

/// Transform Call and Ret statements so the JIT returns control to the engine
/// rather than trying to execute ARM64 addresses as x86_64 code.
///
/// - `Call { target }` → `Assign { X30 = return_addr }` + `Branch { target }`
///   This mimics what BL does (sets LR, then jumps). The engine will naturally
///   follow the call chain by compiling the callee's blocks.
///
/// - `Ret` → `Branch { target: Reg(X30) }`
///   Instead of halting (returning 0), returns the LR value so the engine
///   continues at the caller's return address. When LR=0 (top-level), this
///   returns 0 which signals halt.
fn transform_calls_and_rets(stmts: Vec<Stmt>, return_addr: u64) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(stmts.len() + 1);
    for stmt in stmts {
        match stmt {
            Stmt::Call { target } => {
                // Set LR = return address (instruction after the BL)
                out.push(Stmt::Assign {
                    dst: Reg::X(30),
                    src: Expr::Imm(return_addr),
                });
                // Branch to callee — JIT returns target addr to engine
                out.push(Stmt::Branch { target });
            }
            Stmt::Ret => {
                // Return via LR — JIT returns X30 value to engine
                out.push(Stmt::Branch {
                    target: Expr::Reg(Reg::X(30)),
                });
            }
            Stmt::Pair(a, b) => {
                // Recursively transform pairs
                let transformed = transform_calls_and_rets(vec![*a, *b], return_addr);
                for s in transformed {
                    out.push(s);
                }
            }
            other => out.push(other),
        }
    }
    out
}

impl DynCfg {
    pub fn new() -> Self {
        let config = JitConfig {
            instrument_memory: true,
            instrument_blocks: true,
        };
        Self {
            compiler: JitCompiler::new(config),
            blocks: BTreeMap::new(),
            failed: BTreeMap::new(),
        }
    }

    /// Get or compile the block at `addr`.
    /// Reads instruction bytes from `memory`, lifts, and JIT-compiles.
    pub fn get_or_compile(
        &mut self,
        addr: u64,
        memory: &dyn MemoryProvider,
    ) -> Result<&CompiledBlock, JitError> {
        if self.blocks.contains_key(&addr) {
            return Ok(&self.blocks[&addr]);
        }

        if let Some(_err) = self.failed.get(&addr) {
            return Err(JitError::UnsupportedStmt("previously failed address"));
        }

        let mut stmts = Vec::new();
        let mut pc = addr;
        let mut edges = Vec::new();
        let mut total_bytes = 0usize;
        let mut terminator = None;

        // Max instructions per block to prevent runaway lifting
        const MAX_BLOCK_INSNS: usize = 256;

        for _ in 0..MAX_BLOCK_INSNS {
            // Read 4 bytes (one ARM64 instruction, fixed-width)
            let bytes = match memory.read(pc, 4) {
                Some(b) => b,
                None => {
                    let msg = format!("unmapped memory at 0x{:x}", pc);
                    self.failed.insert(addr, msg);
                    return Err(JitError::UnsupportedStmt("unmapped memory"));
                }
            };

            let word = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            let next_pc = Some(pc + 4);

            // Decode ARM64 instruction
            let insn = match bad64::decode(word, pc) {
                Ok(i) => i,
                Err(_) => {
                    let msg = format!("invalid encoding 0x{:08x} at 0x{:x}", word, pc);
                    self.failed.insert(addr, msg);
                    return Err(JitError::UnsupportedStmt("invalid ARM64 encoding"));
                }
            };

            // Lift to AeonIL
            let result = aeon::lifter::lift(&insn, pc, next_pc);

            let is_term = is_terminator(&result.stmt);
            if is_term {
                terminator = classify_terminator(&result.stmt);
            }
            stmts.push(result.stmt);
            total_bytes += 4;

            if is_term {
                edges = result.edges;
                break;
            }

            pc += 4;
        }

        // If we hit MAX_BLOCK_INSNS without a terminator, add a branch to the
        // next instruction so execution can continue
        if !stmts.is_empty() && !is_terminator(stmts.last().unwrap()) {
            let next = addr + total_bytes as u64;
            stmts.push(Stmt::Branch {
                target: Expr::Imm(next),
            });
            edges = vec![next];
            terminator = Some(BlockTerminator::DirectBranch);
        }

        // Transform Call and Ret so the JIT returns control to the engine
        // instead of trying to call ARM64 addresses as x86_64 code.
        let return_addr = addr + total_bytes as u64;
        let stmts = transform_calls_and_rets(stmts, return_addr);

        // Compile the block via aeon-jit
        let code_ptr = self.compiler.compile_block(addr, &stmts)?;
        let entry: JitEntry = unsafe { std::mem::transmute(code_ptr) };

        let block = CompiledBlock {
            addr,
            entry,
            stmts,
            size_bytes: total_bytes,
            terminator: terminator.unwrap_or(BlockTerminator::Trap),
            static_successors: edges,
        };

        self.blocks.insert(addr, block);
        Ok(&self.blocks[&addr])
    }

    /// Access the underlying JIT compiler (for setting callbacks).
    pub fn compiler_mut(&mut self) -> &mut JitCompiler {
        &mut self.compiler
    }

    /// Number of compiled blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// All compiled block addresses.
    pub fn addresses(&self) -> Vec<u64> {
        self.blocks.keys().copied().collect()
    }

    /// Check if a block has been compiled.
    pub fn has_block(&self, addr: u64) -> bool {
        self.blocks.contains_key(&addr)
    }

    /// Invalidate a block (e.g., if memory changed).
    pub fn invalidate(&mut self, addr: u64) {
        self.blocks.remove(&addr);
        self.failed.remove(&addr);
    }
}
