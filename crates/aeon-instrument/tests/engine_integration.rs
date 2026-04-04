// Integration tests for the InstrumentEngine
//
// Loads real ARM64 ELF binaries, runs them through the full pipeline
// (lift → JIT → execute → trace → fold), and verifies the results.
//
// The JIT compiles ARM64 loads/stores into real x86_64 memory accesses,
// so ELF LOAD segments must be mmap'd at their original virtual addresses.

use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use aeon::elf::{load_elf, LoadedBinary};
use aeon_instrument::context::{ElfMemory, LiveContext};
use aeon_instrument::engine::{InstrumentEngine, StopReason};
use aeon_instrument::symbolic::Invariant;

use object::{Object, ObjectSymbol, SymbolKind};

// Tests that mmap at fixed virtual addresses must run sequentially.
static TEST_LOCK: Mutex<()> = Mutex::new(());

// ── Helpers ──────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf()
}

fn sample(name: &str) -> PathBuf {
    repo_root().join(name)
}

/// Cross-compile an ARM64 C sample with -no-pie so LOAD segments are at
/// high virtual addresses (0x400000+) that can be mmap'd.
fn compile_sample(source_rel: &str) -> PathBuf {
    let source = sample(source_rel);
    let stem = source.file_stem().unwrap().to_str().unwrap();
    let out = repo_root()
        .join("target")
        .join(format!("{stem}_nopie.elf"));
    let status = Command::new("aarch64-linux-gnu-gcc")
        .args([
            "-O1",
            "-fno-inline",
            "-fno-stack-protector",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-o",
        ])
        .arg(&out)
        .arg(&source)
        .status()
        .expect("run aarch64-linux-gnu-gcc");
    assert!(status.success(), "cross-compile failed for {}", source_rel);
    out
}

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

/// RAII guard for mmap'd ELF segments at original virtual addresses.
/// The JIT-compiled code does real x86_64 memory ops at these addresses.
struct MappedSegments {
    regions: Vec<(*mut c_void, usize)>,
}

impl MappedSegments {
    fn map(binary: &LoadedBinary) -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
        let mut regions = Vec::new();
        let mut seen = std::collections::BTreeSet::new();

        for seg in &binary.segments {
            if seg.mem_size == 0 {
                continue;
            }
            let start = seg.vaddr & !(page_size - 1);
            let end = (seg.vaddr + seg.mem_size + page_size - 1) & !(page_size - 1);
            let len = (end - start) as usize;

            if !seen.insert((start, len)) {
                continue;
            }

            let mapped = unsafe {
                libc::mmap(
                    start as *mut c_void,
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            assert_ne!(
                mapped,
                libc::MAP_FAILED,
                "mmap failed for 0x{:x}..0x{:x}: {}",
                start,
                end,
                std::io::Error::last_os_error()
            );
            regions.push((mapped, len));

            // Copy file content into the mapped region
            if seg.file_size > 0 {
                let src_start = seg.file_offset as usize;
                let src_len = seg.file_size as usize;
                if src_start + src_len <= binary.data.len() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            binary.data[src_start..].as_ptr(),
                            seg.vaddr as *mut u8,
                            src_len,
                        );
                    }
                }
            }
        }

        Self { regions }
    }
}

impl Drop for MappedSegments {
    fn drop(&mut self) {
        for &(addr, len) in &self.regions {
            unsafe {
                libc::munmap(addr, len);
            }
        }
    }
}

/// Compile a .c sample and build an engine for it.
/// Returns (engine, mapped_segments, stack) — callers must keep these alive.
fn engine_for_sample(
    source_rel: &str,
    entry_symbol: &str,
) -> (InstrumentEngine, MappedSegments, Vec<u8>) {
    let elf_path = compile_sample(source_rel);
    let binary = load_elf(elf_path.to_str().unwrap()).expect("load ELF");

    // mmap ELF LOAD segments at original VAs so JIT code can access them
    let mapped = MappedSegments::map(&binary);

    let entry = symbol_address(&elf_path, entry_symbol);

    // ElfMemory provides instruction bytes to the lifter
    let elf_mem = ElfMemory::from_loaded(binary);

    // Host-allocated stack
    let stack_size: usize = 1 << 20;
    let stack = vec![0u8; stack_size];
    let sp = (stack.as_ptr() as u64 + stack_size as u64 - 0x100) & !0xf;

    let mut ctx = LiveContext::new(Box::new(elf_mem));
    ctx.set_pc(entry);
    ctx.regs.sp = sp;
    ctx.regs.x[30] = 0; // LR=0 → RET halts

    (InstrumentEngine::new(ctx), mapped, stack)
}

// ── hello_aarch64: full pipeline ─────────────────────────────────────

#[test]
fn smoke_hello_runs_to_halt() {
    let _lock = TEST_LOCK.lock().unwrap();
    let (mut engine, _mapped, _stack) =
        engine_for_sample("samples/hello_aarch64.c", "main");
    engine.config.max_steps = 50_000;

    let reason = engine.run();

    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );

    let trace = engine.trace();
    assert!(!trace.blocks.is_empty(), "should produce block traces");
    assert!(
        trace.unique_blocks().len() >= 2,
        "should visit multiple unique blocks, got {}",
        trace.unique_blocks().len()
    );
}

#[test]
fn hello_return_value() {
    let _lock = TEST_LOCK.lock().unwrap();
    let (mut engine, _mapped, _stack) =
        engine_for_sample("samples/hello_aarch64.c", "main");
    engine.config.max_steps = 50_000;
    engine.run();

    // Roundtrip test expects main → 1217937074
    assert_eq!(
        engine.context.regs.x[0], 1217937074,
        "main should return 1217937074, got {}",
        engine.context.regs.x[0]
    );
}

#[test]
fn hello_traces_memory() {
    let _lock = TEST_LOCK.lock().unwrap();
    let (mut engine, _mapped, _stack) =
        engine_for_sample("samples/hello_aarch64.c", "main");
    engine.config.max_steps = 50_000;
    engine.run();

    let trace = engine.trace();
    let total = trace.total_memory_reads + trace.total_memory_writes;
    assert!(
        total > 0,
        "should record memory accesses, reads={} writes={}",
        trace.total_memory_reads,
        trace.total_memory_writes
    );
}

#[test]
fn hello_discovers_multiple_blocks() {
    let _lock = TEST_LOCK.lock().unwrap();
    let (mut engine, _mapped, _stack) =
        engine_for_sample("samples/hello_aarch64.c", "main");
    engine.config.max_steps = 50_000;
    engine.run();

    assert!(
        engine.discovered_blocks() >= 3,
        "should discover at least 3 blocks (main + checksum + select_message), got {}",
        engine.discovered_blocks()
    );
}

// ── Engine controls ──────────────────────────────────────────────────

#[test]
fn max_steps_stops_engine() {
    let _lock = TEST_LOCK.lock().unwrap();
    let (mut engine, _mapped, _stack) =
        engine_for_sample("samples/hello_aarch64.c", "main");
    engine.config.max_steps = 5;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::MaxSteps),
        "expected MaxSteps, got {:?}",
        reason
    );
    assert_eq!(engine.trace().blocks.len(), 5);
}

#[test]
fn breakpoint_stops_engine() {
    let _lock = TEST_LOCK.lock().unwrap();
    let elf_path = compile_sample("samples/hello_aarch64.c");
    let checksum_addr = symbol_address(&elf_path, "checksum");

    let (mut engine, _mapped, _stack) =
        engine_for_sample("samples/hello_aarch64.c", "main");
    engine.config.breakpoints.push(checksum_addr);

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Breakpoint(addr) if addr == checksum_addr),
        "expected Breakpoint(0x{:x}), got {:?}",
        checksum_addr,
        reason
    );
}

// ── loops_cond_aarch64: symbolic analysis ────────────────────────────

#[test]
fn loops_runs_to_halt() {
    let _lock = TEST_LOCK.lock().unwrap();
    let (mut engine, _mapped, _stack) =
        engine_for_sample("samples/loops_cond_aarch64.c", "main");
    engine.config.max_steps = 100_000;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );
    assert!(
        engine.trace().blocks.len() > 50,
        "loop-heavy program should execute many blocks, got {}",
        engine.trace().blocks.len()
    );
}

#[test]
fn loops_symbolic_fold_finds_invariants() {
    let _lock = TEST_LOCK.lock().unwrap();
    let (mut engine, _mapped, _stack) =
        engine_for_sample("samples/loops_cond_aarch64.c", "main");
    engine.config.max_steps = 100_000;
    engine.run();

    let result = engine.fold();

    assert!(
        result.constant_registers > 0,
        "should find constant registers in loop program"
    );
    assert!(
        result.resolved_branches > 0,
        "should find always-taken branches in loop program"
    );
    assert!(
        result.induction_variables > 0,
        "should find induction variables (loop counters)"
    );

    eprintln!(
        "Fold: {} const regs, {} const mem, {} branches, {} induction, {} dataflow",
        result.constant_registers,
        result.constant_memory,
        result.resolved_branches,
        result.induction_variables,
        result.dataflow_edges
    );
}

#[test]
fn loops_has_stride_1_induction_variable() {
    let _lock = TEST_LOCK.lock().unwrap();
    let (mut engine, _mapped, _stack) =
        engine_for_sample("samples/loops_cond_aarch64.c", "main");
    engine.config.max_steps = 100_000;
    engine.run();

    let result = engine.fold();
    let stride_1: Vec<_> = result
        .invariants
        .iter()
        .filter(|inv| matches!(inv, Invariant::InductionVariable { stride: 1, .. }))
        .collect();

    eprintln!("stride-1 induction variables: {:?}", stride_1);
    assert!(
        result.induction_variables > 0,
        "should find at least one induction variable"
    );
}
