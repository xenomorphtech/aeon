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
use aeon_instrument::context::{ElfMemory, LiveContext, SnapshotMemory};
use aeon_instrument::engine::{EngineConfig, InstrumentEngine, StopReason, UnmappedMemoryMode};
use aeon_instrument::symbolic::Invariant;
use aeon_instrument::trace::read_trace_file;

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
    let out = repo_root().join("target").join(format!("{stem}_nopie.elf"));
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

fn symbol_range(path: &Path, name: &str) -> (u64, u64) {
    let data = fs::read(path).expect("read ELF");
    let obj = object::File::parse(&*data).expect("parse ELF");
    let mut text_symbols = Vec::new();
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text || sym.address() == 0 {
            continue;
        }
        let sym_name = match sym.name() {
            Ok(v) => v.to_string(),
            Err(_) => continue,
        };
        text_symbols.push((sym_name, sym.address(), sym.size()));
    }
    text_symbols.sort_by_key(|(_, addr, _)| *addr);

    for (idx, (sym_name, addr, size)) in text_symbols.iter().enumerate() {
        if sym_name != name {
            continue;
        }
        if *size > 0 {
            return (*addr, *addr + *size);
        }
        if let Some((_, next_addr, _)) = text_symbols.get(idx + 1) {
            return (*addr, *next_addr);
        }
        panic!(
            "symbol '{}' has zero size and no successor in {:?}",
            name, path
        );
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
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
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
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
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
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
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
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
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
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
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
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let elf_path = compile_sample("samples/hello_aarch64.c");
    let checksum_addr = symbol_address(&elf_path, "checksum");

    let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
    engine.config.breakpoints.push(checksum_addr);

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Breakpoint(addr) if addr == checksum_addr),
        "expected Breakpoint(0x{:x}), got {:?}",
        checksum_addr,
        reason
    );
}

#[test]
fn code_range_stops_when_execution_leaves_function() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let elf_path = compile_sample("samples/hello_aarch64.c");
    let (main_start, main_end) = symbol_range(&elf_path, "main");

    let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
    engine.config.max_steps = 50_000;
    engine.config.code_range = Some((main_start, main_end));

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::CodeRangeExit(addr) if addr < main_start || addr >= main_end),
        "expected CodeRangeExit outside 0x{:x}..0x{:x}, got {:?}",
        main_start,
        main_end,
        reason
    );
    assert!(
        !engine.trace().blocks.is_empty(),
        "should trace at least one block before leaving the code range"
    );
}

// ── loops_cond_aarch64: symbolic analysis ────────────────────────────

#[test]
fn loops_runs_to_halt() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/loops_cond_aarch64.c", "main");
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
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/loops_cond_aarch64.c", "main");
    engine.config.max_steps = 100_000;
    engine.run();

    let result = engine.fold();

    eprintln!(
        "Fold: {} const regs, {} const mem, {} branches, {} induction, {} dataflow, {} vtables",
        result.constant_registers,
        result.constant_memory,
        result.resolved_branches,
        result.induction_variables,
        result.dataflow_edges,
        result.vtables_detected
    );

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
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/loops_cond_aarch64.c", "main");
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

// ── bitops_aarch64: bitwise operations ──────────────────────────────

#[test]
fn bitops_runs_to_halt() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/bitops_aarch64.c", "main");
    engine.config.max_steps = 50_000;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );
}

#[test]
fn bitops_traces_operations() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/bitops_aarch64.c", "main");
    engine.config.max_steps = 50_000;
    engine.run();

    let trace = engine.trace();
    assert!(!trace.blocks.is_empty(), "should produce block traces");
}

// ── conditionals_aarch64: branch behavior ────────────────────────────

#[test]
fn conditionals_runs_to_halt() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/conditionals_aarch64.c", "main");
    engine.config.max_steps = 50_000;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );
}

#[test]
fn conditionals_discovers_multiple_paths() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/conditionals_aarch64.c", "main");
    engine.config.max_steps = 50_000;
    engine.run();

    assert!(
        engine.discovered_blocks() >= 3,
        "branch conditionals should discover multiple blocks, got {}",
        engine.discovered_blocks()
    );
}

// ── mem_access_aarch64: memory patterns ─────────────────────────────

#[test]
fn mem_access_runs_to_halt() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/mem_access_aarch64.c", "main");
    engine.config.max_steps = 50_000;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );
}

#[test]
fn mem_access_traces_memory_accesses() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/mem_access_aarch64.c", "main");
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

// ── Disk-backed trace writing ───────────────────────────────────────

#[test]
fn disk_trace_roundtrip() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let trace_path = std::env::temp_dir().join("aeon_disk_trace_test.bin");

    let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
    engine.config.max_steps = 50_000;
    engine.config.trace_output = Some(trace_path.clone());
    engine.config.drain_interval = 4; // drain frequently to test the path

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );

    // Verify trace file was written
    let writer = engine.trace_writer().unwrap();
    assert!(writer.entries_written() > 0, "should write entries to disk");
    assert!(
        writer.bytes_written() > 8,
        "should write more than just the header"
    );

    // Read it back and verify
    let entries = read_trace_file(&trace_path).expect("read trace file");
    assert_eq!(
        entries.len(),
        writer.entries_written() as usize,
        "entry count should match"
    );

    // Verify entry contents are plausible
    for entry in &entries {
        assert!(entry.addr != 0, "block addr should be non-zero");
        assert!(
            entry.seq < writer.entries_written(),
            "seq should be in range"
        );
    }

    // In-memory blocks should be small due to frequent drains
    assert!(
        engine.trace().blocks.len() < entries.len(),
        "in-memory blocks ({}) should be less than total ({}) due to drains",
        engine.trace().blocks.len(),
        entries.len()
    );

    // Visit counts should be accurate despite drains
    let total_visits: u64 = engine.trace().visit_counts().values().sum();
    assert_eq!(
        total_visits,
        entries.len() as u64,
        "persistent visit counts should match total entries"
    );

    let _ = std::fs::remove_file(&trace_path);
}

// ── NMSS obfuscated function tracing ────────────────────────────────

const NMSS_PATH: &str = "/home/sdancer/games/nmss/output/decrypted/nmsscr.dec";
/// Base address for rebasing the shared object (VA 0 segments can't be mmap'd).
const NMSS_BASE: u64 = 0x1000_0000;

/// Build an engine for a DYN (shared object) ELF by rebasing segments.
/// Returns (engine, mapped_segments, stack).
fn engine_for_dyn_elf(path: &str, func_offset: u64) -> (InstrumentEngine, MappedSegments, Vec<u8>) {
    let binary = load_elf(path).expect("load ELF");

    // Rebase segments: mmap at NMSS_BASE + segment.vaddr
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    let mut mmap_regions = Vec::new();
    let mut snapshot = SnapshotMemory::new();
    let mut seen = std::collections::BTreeSet::new();

    for seg in &binary.segments {
        if seg.mem_size == 0 {
            continue;
        }
        let rebased_vaddr = NMSS_BASE + seg.vaddr;
        let start = rebased_vaddr & !(page_size - 1);
        let end = (rebased_vaddr + seg.mem_size + page_size - 1) & !(page_size - 1);
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
        mmap_regions.push((mapped, len));

        // Copy file content into mmap'd region and SnapshotMemory
        let file_bytes = if seg.file_size > 0 {
            let src_start = seg.file_offset as usize;
            let src_len = seg.file_size as usize;
            if src_start + src_len <= binary.data.len() {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        binary.data[src_start..].as_ptr(),
                        rebased_vaddr as *mut u8,
                        src_len,
                    );
                }
                binary.data[src_start..src_start + src_len].to_vec()
            } else {
                vec![0u8; seg.mem_size as usize]
            }
        } else {
            vec![0u8; seg.mem_size as usize]
        };

        // Build SnapshotMemory region (full mem_size, zero-padded for BSS)
        let mut region_data = file_bytes;
        region_data.resize(seg.mem_size as usize, 0);
        snapshot.add_region(rebased_vaddr, region_data);
    }

    let mapped = MappedSegments {
        regions: mmap_regions,
    };

    let entry_pc = NMSS_BASE + func_offset;

    // Host-allocated stack
    let stack_size: usize = 1 << 20;
    let stack = vec![0u8; stack_size];
    let sp = (stack.as_ptr() as u64 + stack_size as u64 - 0x100) & !0xf;

    let mut ctx = LiveContext::new(Box::new(snapshot));
    ctx.set_pc(entry_pc);
    ctx.regs.sp = sp;
    ctx.regs.x[30] = 0; // LR=0 → RET halts

    // Point argument registers at writable scratch areas within the stack
    // so the function doesn't SIGSEGV dereferencing null pointers.
    let scratch_base = stack.as_ptr() as u64;
    for i in 0..8 {
        ctx.regs.x[i] = scratch_base + (i as u64) * 0x1000;
    }

    // Set tpidr_el0 to a valid TLS block (stack canary reads [tpidr_el0+0x28])
    ctx.regs.tpidr_el0 = scratch_base + 0x8000;

    (InstrumentEngine::new(ctx), mapped, stack)
}

#[test]
fn nmss_crypto_sub_20bb48_traces_to_disk() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    if !Path::new(NMSS_PATH).exists() {
        eprintln!("NMSS binary not found at {}, skipping", NMSS_PATH);
        return;
    }

    let trace_path = std::env::temp_dir().join("aeon_nmss_20bb48.trace");
    let (mut engine, _mapped, _stack) = engine_for_dyn_elf(NMSS_PATH, 0x20bb48);

    engine.config = EngineConfig {
        max_steps: 50_000,
        max_memory_ops: 500_000,
        max_block_visits: 500,
        breakpoints: Vec::new(),
        code_range: None,
        code_alias_base: None,
        trace_output: Some(trace_path.clone()),
        drain_interval: 2048,
        unmapped_memory_mode: UnmappedMemoryMode::Halt,
        enable_block_batching: false,
        batch_size: 128,
    };

    let reason = engine.run();
    eprintln!(
        "NMSS sub_20bb48: stopped with {:?}, {} blocks executed, {} unique blocks",
        reason,
        engine.trace_writer().map_or(0, |w| w.entries_written()),
        engine.trace().unique_blocks().len()
    );

    // Should have executed at least some blocks before hitting a limit
    let entries_written = engine.trace_writer().unwrap().entries_written();
    assert!(
        entries_written > 0,
        "should execute and trace at least one block"
    );

    // Verify the trace file can be read back
    let entries = read_trace_file(&trace_path).expect("read NMSS trace");
    assert_eq!(entries.len(), entries_written as usize);

    // All block addresses should be in the rebased range
    for entry in &entries {
        assert!(
            entry.addr >= NMSS_BASE,
            "block addr 0x{:x} should be >= base 0x{:x}",
            entry.addr,
            NMSS_BASE
        );
    }

    // Should have some memory accesses (crypto functions touch data)
    let total_mem_accesses: usize = entries.iter().map(|e| e.memory_accesses.len()).sum();
    eprintln!(
        "NMSS sub_20bb48: {} total memory accesses across {} blocks",
        total_mem_accesses, entries_written
    );

    let file_size = std::fs::metadata(&trace_path).unwrap().len();
    eprintln!(
        "NMSS trace file: {} bytes ({:.1} KB)",
        file_size,
        file_size as f64 / 1024.0
    );

    let _ = std::fs::remove_file(&trace_path);
}

#[test]
fn nmss_crypto_sub_2070a8_traces_to_disk() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    if !Path::new(NMSS_PATH).exists() {
        eprintln!("NMSS binary not found at {}, skipping", NMSS_PATH);
        return;
    }

    let trace_path = std::env::temp_dir().join("aeon_nmss_2070a8.trace");
    let (mut engine, _mapped, _stack) = engine_for_dyn_elf(NMSS_PATH, 0x2070a8);

    engine.config = EngineConfig {
        max_steps: 50_000,
        max_memory_ops: 500_000,
        max_block_visits: 500,
        breakpoints: Vec::new(),
        code_range: None,
        code_alias_base: None,
        trace_output: Some(trace_path.clone()),
        drain_interval: 2048,
        unmapped_memory_mode: UnmappedMemoryMode::Halt,
        enable_block_batching: false,
        batch_size: 128,
    };

    let reason = engine.run();
    eprintln!(
        "NMSS sub_2070a8: stopped with {:?}, {} blocks executed, {} unique blocks",
        reason,
        engine.trace_writer().map_or(0, |w| w.entries_written()),
        engine.trace().unique_blocks().len()
    );

    let entries_written = engine.trace_writer().unwrap().entries_written();
    assert!(
        entries_written > 0,
        "should execute and trace at least one block"
    );

    let entries = read_trace_file(&trace_path).expect("read NMSS trace");
    assert_eq!(entries.len(), entries_written as usize);

    for entry in &entries {
        assert!(
            entry.addr >= NMSS_BASE,
            "block addr 0x{:x} should be >= base 0x{:x}",
            entry.addr,
            NMSS_BASE
        );
    }

    let total_mem_accesses: usize = entries.iter().map(|e| e.memory_accesses.len()).sum();
    eprintln!(
        "NMSS sub_2070a8: {} total memory accesses across {} blocks",
        total_mem_accesses, entries_written
    );

    let _ = std::fs::remove_file(&trace_path);
}

// ── recursive_calls_aarch64: recursion handling ──────────────────────

#[test]
fn recursive_calls_runs_to_halt() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/recursive_calls_aarch64.c", "main");
    engine.config.max_steps = 100_000;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );

    let trace = engine.trace();
    assert!(!trace.blocks.is_empty(), "should produce block traces");
    let unique = trace.unique_blocks().len();
    eprintln!("recursive_calls: {} unique blocks visited", unique);
}

#[test]
fn recursive_calls_handles_call_stack() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/recursive_calls_aarch64.c", "main");
    engine.config.max_steps = 100_000;
    engine.run();

    assert!(
        engine.discovered_blocks() >= 3,
        "recursive function should have multiple basic blocks, got {}",
        engine.discovered_blocks()
    );
}

// ── deep_stack_aarch64: stack usage ──────────────────────────────────

#[test]
fn deep_stack_runs_to_halt() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/deep_stack_aarch64.c", "main");
    engine.config.max_steps = 100_000;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );
}

#[test]
fn deep_stack_traces_stack_operations() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/deep_stack_aarch64.c", "main");
    engine.config.max_steps = 100_000;
    engine.run();

    let trace = engine.trace();
    assert!(
        trace.total_memory_reads > 0 || trace.total_memory_writes > 0,
        "deep stack usage should involve memory accesses"
    );
}

// ── advanced_loops_aarch64: complex loop patterns ─────────────────────

#[test]
fn advanced_loops_runs_to_halt() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/advanced_loops_aarch64.c", "main");
    engine.config.max_steps = 200_000;

    let reason = engine.run();
    assert!(
        matches!(reason, StopReason::Halted),
        "expected Halted, got {:?}",
        reason
    );
}

#[test]
fn advanced_loops_discovers_blocks() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut engine, _mapped, _stack) = engine_for_sample("samples/advanced_loops_aarch64.c", "main");
    engine.config.max_steps = 200_000;
    engine.run();

    assert!(
        engine.discovered_blocks() >= 2,
        "advanced loop pattern should discover multiple blocks, got {}",
        engine.discovered_blocks()
    );
    eprintln!(
        "advanced_loops: {} blocks, {} unique blocks",
        engine.trace().blocks.len(),
        engine.trace().unique_blocks().len()
    );
}
