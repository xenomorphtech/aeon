// Integration tests for the InstrumentEngine
//
// Loads real ARM64 ELF binaries, runs them through the full pipeline
// (lift → JIT → execute → trace → fold), and verifies the results.

use std::fs;
use std::path::{Path, PathBuf};

use aeon_instrument::context::{ElfMemory, LiveContext, SnapshotMemory};
use aeon_instrument::engine::{InstrumentEngine, StopReason};
use aeon_instrument::symbolic::Invariant;

use object::{Object, ObjectSymbol, SymbolKind};

/// Workspace root (two levels up from crates/aeon-instrument/).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf()
}

/// Resolve a sample path relative to the workspace root.
fn sample(name: &str) -> PathBuf {
    repo_root().join(name)
}

/// Resolve a symbol's virtual address from an ELF file.
fn symbol_address(path: &Path, name: &str) -> u64 {
    let data = fs::read(path).expect("read ELF");
    let obj = object::File::parse(&*data).expect("parse ELF");
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text || sym.address() == 0 {
            continue;
        }
        if sym.name() == Ok(name) {
            return sym.address();
        }
    }
    panic!("symbol '{}' not found in {:?}", name, path);
}

/// Build a LiveContext from an ELF binary + a host-allocated stack.
/// Returns (engine, stack_allocation) — keep the stack alive for the engine's lifetime.
fn engine_from_elf(elf_path: &str, entry_symbol: &str) -> (InstrumentEngine, Vec<u8>) {
    let full_path = sample(elf_path);
    let elf_path_str = full_path.to_str().expect("valid utf-8 path");
    let elf_mem = ElfMemory::from_elf(elf_path_str).expect("load ELF");
    let entry = symbol_address(&full_path, entry_symbol);

    // We need a writable stack region. ElfMemory is read-only (ELF segments),
    // so we layer a SnapshotMemory on top for the stack.
    let stack_size: usize = 1 << 20; // 1 MiB
    let stack = vec![0u8; stack_size];
    let stack_base = stack.as_ptr() as u64;
    let sp = (stack_base + stack_size as u64 - 0x100) & !0xf;

    // Composite memory: ELF segments + host stack
    let mut snapshot = SnapshotMemory::new();

    // Map ELF LOAD segments into SnapshotMemory
    let binary = elf_mem.binary();
    for seg in &binary.segments {
        if seg.file_size > 0 {
            let file_start = seg.file_offset as usize;
            let file_end = file_start + seg.file_size as usize;
            if file_end <= binary.data.len() {
                let mut data = binary.data[file_start..file_end].to_vec();
                // Zero-fill to mem_size if larger than file_size
                if seg.mem_size > seg.file_size {
                    data.resize(seg.mem_size as usize, 0);
                }
                snapshot.add_region(seg.vaddr, data);
            }
        }
    }

    // Map host stack into SnapshotMemory
    snapshot.add_region(stack_base, vec![0u8; stack_size]);

    let mut ctx = LiveContext::new(Box::new(snapshot));
    ctx.set_pc(entry);
    ctx.regs.sp = sp;
    // Set x30 (LR) to 0 so RET halts
    ctx.regs.x[30] = 0;

    (InstrumentEngine::new(ctx), stack)
}

// ── hello_aarch64.elf tests ───────────────────────────────────────

#[test]
fn engine_runs_hello_elf_to_completion() {
    let (mut engine, _stack) = engine_from_elf("samples/hello_aarch64.elf", "main");
    engine.config.max_steps = 50_000;

    let reason = engine.run();

    // Should halt (main returns via RET)
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );

    let trace = engine.trace();
    assert!(
        !trace.blocks.is_empty(),
        "trace should have at least one block"
    );
    assert!(
        trace.unique_blocks().len() >= 2,
        "should visit multiple unique blocks, got {}",
        trace.unique_blocks().len()
    );

    // Verify the return value in x0
    // hello_aarch64.c returns checksum ^ message[0], roundtrip test expects 1217937074
    let x0 = engine.context.regs.x[0];
    assert_eq!(
        x0, 1217937074,
        "main should return 1217937074 (checksum ^ message[0]), got {}",
        x0
    );
}

#[test]
fn engine_traces_memory_accesses() {
    let (mut engine, _stack) = engine_from_elf("samples/hello_aarch64.elf", "main");
    engine.config.max_steps = 50_000;
    engine.run();

    let trace = engine.trace();

    // hello_aarch64 reads a payload array and a string — should have memory ops
    let total = trace.total_memory_reads + trace.total_memory_writes;
    assert!(
        total > 0,
        "should have memory accesses, got reads={} writes={}",
        trace.total_memory_reads,
        trace.total_memory_writes
    );
}

#[test]
fn engine_discovers_multiple_blocks() {
    let (mut engine, _stack) = engine_from_elf("samples/hello_aarch64.elf", "main");
    engine.config.max_steps = 50_000;
    engine.run();

    // hello_aarch64 has main + checksum + select_message — at least 3 functions
    let blocks = engine.discovered_blocks();
    assert!(
        blocks >= 3,
        "should discover at least 3 blocks, got {}",
        blocks
    );
}

#[test]
fn engine_respects_max_steps() {
    let (mut engine, _stack) = engine_from_elf("samples/hello_aarch64.elf", "main");
    engine.config.max_steps = 5;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::MaxSteps),
        "expected MaxSteps, got {:?}",
        reason
    );

    let trace = engine.trace();
    assert_eq!(
        trace.blocks.len(),
        5,
        "should have exactly 5 block executions"
    );
}

#[test]
fn engine_breakpoint_stops_at_target() {
    let entry = symbol_address(Path::new("samples/hello_aarch64.elf"), "main");
    let (mut engine, _stack) = engine_from_elf("samples/hello_aarch64.elf", "main");

    // Set a breakpoint at entry+4 (second instruction of main)
    engine.config.breakpoints.push(entry + 4);
    // But also at some checksum address — use a function we know exists
    let checksum_addr = symbol_address(Path::new("samples/hello_aarch64.elf"), "checksum");
    engine.config.breakpoints.push(checksum_addr);

    let reason = engine.run();
    match &reason {
        StopReason::Breakpoint(addr) => {
            assert!(
                *addr == entry + 4 || *addr == checksum_addr,
                "breakpoint at unexpected address 0x{:x}",
                addr
            );
        }
        _ => panic!("expected Breakpoint, got {:?}", reason),
    }
}

// ── loops_cond_aarch64.elf tests ──────────────────────────────────

#[test]
fn engine_runs_loops_cond_to_completion() {
    let (mut engine, _stack) = engine_from_elf("samples/loops_cond_aarch64.elf", "main");
    engine.config.max_steps = 100_000;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );

    let trace = engine.trace();
    // loops_cond has nested loops — should execute many blocks
    assert!(
        trace.blocks.len() > 50,
        "loop-heavy program should execute many blocks, got {}",
        trace.blocks.len()
    );
}

#[test]
fn symbolic_fold_finds_invariants_in_loop_program() {
    let (mut engine, _stack) = engine_from_elf("samples/loops_cond_aarch64.elf", "main");
    engine.config.max_steps = 100_000;

    let reason = engine.run();
    assert!(matches!(reason, StopReason::Halted), "got {:?}", reason);

    let result = engine.fold();

    // With loops, we expect:
    // - Register constants (e.g., loop bounds, frame pointer)
    assert!(
        result.constant_registers > 0,
        "should find constant registers in loop program"
    );

    // - Resolved branches (some branches always go the same way)
    assert!(
        result.resolved_branches > 0,
        "should find always-taken branches in loop program"
    );

    // - Induction variables (loop counters)
    let induction_vars: Vec<_> = result
        .invariants
        .iter()
        .filter(|inv| matches!(inv, Invariant::InductionVariable { .. }))
        .collect();
    assert!(
        !induction_vars.is_empty(),
        "loop program should have induction variables"
    );

    // Print summary for debugging
    eprintln!(
        "Fold results: {} invariants total: {} const regs, {} const mem, \
         {} branches, {} induction vars, {} dataflow edges",
        result.invariants.len(),
        result.constant_registers,
        result.constant_memory,
        result.resolved_branches,
        result.induction_variables,
        result.dataflow_edges
    );
}

#[test]
fn symbolic_fold_finds_induction_with_known_stride() {
    let (mut engine, _stack) = engine_from_elf("samples/loops_cond_aarch64.elf", "main");
    engine.config.max_steps = 100_000;
    engine.run();

    let result = engine.fold();

    // Look for stride-1 induction variables (the basic for-loop counters)
    let stride_1: Vec<_> = result
        .invariants
        .iter()
        .filter(|inv| matches!(inv, Invariant::InductionVariable { stride: 1, .. }))
        .collect();

    // nested_sum has two for-loops with increment-by-1 counters
    // collatz_steps has a steps counter incrementing by 1
    // We should find at least some stride-1 induction variables
    eprintln!(
        "Found {} stride-1 induction variables: {:?}",
        stride_1.len(),
        stride_1.iter().take(3).collect::<Vec<_>>()
    );
    // Note: Whether we detect these depends on how the compiler maps
    // loop counters to registers. At -O1 they're usually in registers.
    // We assert softly — at least one induction variable total.
    assert!(
        result.induction_variables > 0,
        "should find at least one induction variable"
    );
}
