// Performance benchmarks for aeon_instrument engine
//
// Measures:
// - Block compilation time
// - JIT execution throughput
// - Memory overhead
// - Symbolic analysis performance
// - Trace I/O throughput

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use aeon::elf::{load_elf, LoadedBinary};
use aeon_instrument::context::{ElfMemory, LiveContext};
use aeon_instrument::engine::InstrumentEngine;
use object::{Object, ObjectSymbol};

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

fn compile_sample(source_rel: &str) -> PathBuf {
    let source = sample(source_rel);
    let stem = source.file_stem().unwrap().to_str().unwrap();
    let out = repo_root().join("target").join(format!("{stem}_bench.elf"));

    // Skip compilation if already exists
    if out.exists() {
        return out;
    }

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
        .expect("cross-compile");
    assert!(status.success(), "cross-compile failed for {}", source_rel);
    out
}

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
            if mapped == libc::MAP_FAILED {
                panic!("mmap failed");
            }
            regions.push((mapped, len));

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

fn engine_for_sample(source_rel: &str, entry_symbol: &str) -> (InstrumentEngine, MappedSegments, Vec<u8>) {
    let elf_path = compile_sample(source_rel);
    let binary = load_elf(elf_path.to_str().unwrap()).expect("load ELF");
    let mapped = MappedSegments::map(&binary);

    let entry = {
        let data = fs::read(&elf_path).expect("read ELF");
        let obj = object::File::parse(&*data).expect("parse ELF");
        let mut result = 0u64;
        for sym in obj.symbols() {
            if sym.kind() == object::SymbolKind::Text && sym.address() != 0 {
                if let Ok(name) = sym.name() {
                    if name == entry_symbol {
                        result = sym.address();
                        break;
                    }
                }
            }
        }
        assert_ne!(result, 0, "symbol not found");
        result
    };

    let elf_mem = ElfMemory::from_loaded(binary);
    let stack_size: usize = 1 << 20;
    let stack = vec![0u8; stack_size];
    let sp = (stack.as_ptr() as u64 + stack_size as u64 - 0x100) & !0xf;

    let mut ctx = LiveContext::new(Box::new(elf_mem));
    ctx.set_pc(entry);
    ctx.regs.sp = sp;
    ctx.regs.x[30] = 0;

    (InstrumentEngine::new(ctx), mapped, stack)
}

fn benchmark_block_compilation(c: &mut Criterion) {
    let _lock = std::sync::Mutex::new(());

    c.bench_function("compile_hello_full_run", |b| {
        b.iter(|| {
            let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
            engine.config.max_steps = 50_000;
            engine.run();
            black_box(engine.discovered_blocks())
        })
    });
}

fn benchmark_jit_execution(c: &mut Criterion) {
    let _lock = std::sync::Mutex::new(());

    c.bench_function("execute_hello_traced", |b| {
        b.iter(|| {
            let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
            engine.config.max_steps = 50_000;
            engine.run();
            let trace = engine.trace();
            black_box((trace.blocks.len(), trace.total_memory_reads + trace.total_memory_writes))
        })
    });
}

fn benchmark_symbolic_analysis(c: &mut Criterion) {
    let _lock = std::sync::Mutex::new(());

    c.bench_function("symbolic_fold_loops", |b| {
        b.iter(|| {
            let (mut engine, _mapped, _stack) = engine_for_sample("samples/loops_cond_aarch64.c", "main");
            engine.config.max_steps = 100_000;
            engine.run();
            let result = engine.fold();
            black_box((
                result.constant_registers,
                result.resolved_branches,
                result.induction_variables,
            ))
        })
    });
}

fn benchmark_trace_io(c: &mut Criterion) {
    let _lock = std::sync::Mutex::new(());

    c.bench_function("disk_trace_write", |b| {
        b.iter(|| {
            let trace_path = std::env::temp_dir().join("bench_trace.bin");
            let (mut engine, _mapped, _stack) = engine_for_sample("samples/hello_aarch64.c", "main");
            engine.config.max_steps = 50_000;
            engine.config.trace_output = Some(trace_path.clone());
            engine.config.drain_interval = 4;
            engine.run();
            let writer = engine.trace_writer().unwrap();
            black_box(writer.bytes_written());
            let _ = std::fs::remove_file(&trace_path);
        })
    });
}

fn benchmark_scaling(c: &mut Criterion) {
    let _lock = std::sync::Mutex::new(());
    let mut group = c.benchmark_group("step_scaling");

    for step_limit in [100, 500, 1000, 5000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(step_limit), step_limit, |b, &steps| {
            b.iter(|| {
                let (mut engine, _mapped, _stack) = engine_for_sample("samples/loops_cond_aarch64.c", "main");
                engine.config.max_steps = steps;
                engine.run();
                black_box(engine.trace().blocks.len())
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_block_compilation,
    benchmark_jit_execution,
    benchmark_symbolic_analysis,
    benchmark_trace_io,
    benchmark_scaling
);

criterion_main!(benches);
