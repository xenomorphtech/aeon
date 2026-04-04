#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

//! End-to-end round-trip coverage for `aeon-jit`.
//!
//! Pipeline:
//! 1. Compile a sample C file to both an AArch64 ELF and a native x86-64 ELF.
//! 2. Load the AArch64 ELF through `aeon::elf`, decode functions to AeonIL,
//!    and build basic blocks from the lifted instruction stream.
//! 3. Split lifted blocks at direct calls so the harness can drive whole
//!    multi-block functions while still compiling each executable unit through
//!    `JitCompiler::compile_block`.
//! 4. Map the ELF LOAD segments into host memory at their original virtual
//!    addresses so absolute addresses produced by lifting remain valid.
//! 5. Execute the JIT-compiled entry function and compare its `main` return
//!    value against a native x86-64 wrapper that prints the same integer.
//!
//! To add a new case:
//! - place a self-contained `*.c` sample in `samples/`;
//! - add a `sample_test!(test_sample_<name>, SampleCase { ... });` entry;
//! - prefer programs whose observable result is the `main` return value;
//! - set `min_lifted_functions` and `min_direct_call_sites` so the test
//!   asserts it is exercising more than a single straight-line block;
//! - keep external calls out of the sample for now, because the harness only
//!   virtualizes direct calls to lifted intra-binary functions.

use aeon::elf::{load_elf, FunctionInfo, LoadedBinary};
use aeon::function_ir::decode_function;
use aeon_jit::{JitCompiler, JitConfig, JitContext, JitEntry};
use aeon_reduce::ssa::cfg::{build_cfg, BasicBlock, Cfg};
use aeonil::{Expr, Stmt};
use object::{Object, ObjectSymbol, SymbolKind};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::c_void;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CALL_SITE_TAG: u64 = 1 << 62;
const STACK_SIZE: usize = 1 << 20;
const NATIVE_ENTRY_ALIAS: &str = "aeon_sample_main";
static FIXED_ADDRESS_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
struct SampleCase {
    source: &'static str,
    entry_symbol: &'static str,
    expected_return: Option<i32>,
    min_lifted_functions: usize,
    min_direct_call_sites: usize,
}

#[derive(Debug)]
struct LiftedFunction {
    addr: u64,
    cfg: Cfg,
}

#[derive(Debug, Clone)]
struct ExecutableBlock {
    addr: u64,
    stmts: Vec<Stmt>,
}

#[derive(Debug, Clone, Copy)]
struct CallSite {
    callee: u64,
    continuation: u64,
}

struct JittedProgram {
    _compiler: JitCompiler,
    block_entries: BTreeMap<u64, JitEntry>,
    function_entries: BTreeMap<u64, u64>,
    call_sites: Vec<CallSite>,
    _mapped_binary: FixedAddressMemory,
    stack: Vec<u8>,
}

struct FixedAddressMemory {
    mappings: Vec<MmapRegion>,
}

struct MmapRegion {
    addr: *mut c_void,
    len: usize,
}

impl Drop for FixedAddressMemory {
    fn drop(&mut self) {
        for region in &self.mappings {
            unsafe {
                libc::munmap(region.addr, region.len);
            }
        }
    }
}

impl FixedAddressMemory {
    fn map(binary: &LoadedBinary) -> TestResult<Self> {
        let page_size = page_size()?;
        let mut mappings = Vec::new();
        let mut mapped_ranges = BTreeSet::new();

        for segment in &binary.segments {
            if segment.mem_size == 0 {
                continue;
            }

            let start = align_down(segment.vaddr, page_size);
            let end = align_up(segment.vaddr + segment.mem_size, page_size);
            let len = usize::try_from(end - start)?;

            if mapped_ranges.insert((start, len)) {
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
                    return Err(io::Error::other(format!(
                        "mmap failed for ELF range 0x{start:x}..0x{end:x}: {}",
                        io::Error::last_os_error()
                    ))
                    .into());
                }
                mappings.push(MmapRegion { addr: mapped, len });
            }

            if segment.file_size == 0 {
                continue;
            }

            let file_start = usize::try_from(segment.file_offset)?;
            let file_len = usize::try_from(segment.file_size)?;
            let file_end = file_start + file_len;
            if file_end > binary.data.len() {
                return Err(io::Error::other(format!(
                    "segment file range 0x{:x}..0x{:x} exceeds ELF size",
                    segment.file_offset,
                    segment.file_offset + segment.file_size
                ))
                .into());
            }

            let src = binary.data[file_start..file_end].as_ptr();
            let dst = segment.vaddr as *mut u8;
            unsafe {
                std::ptr::copy_nonoverlapping(src, dst, file_len);
            }
        }

        Ok(Self { mappings })
    }
}

impl JittedProgram {
    fn new(binary: &LoadedBinary, functions: &BTreeMap<u64, LiftedFunction>) -> TestResult<Self> {
        let _mapped_binary = FixedAddressMemory::map(binary)?;

        let mut function_entries = BTreeMap::new();
        let mut blocks = BTreeMap::new();
        let mut call_sites = Vec::new();
        let mut next_synth_addr = max_block_addr(functions)
            .and_then(|addr| addr.checked_add(4))
            .ok_or_else(|| io::Error::other("no lifted blocks found"))?;

        for function in functions.values() {
            let entry_block = function
                .cfg
                .blocks
                .get(function.cfg.entry as usize)
                .ok_or_else(|| {
                    io::Error::other(format!("function 0x{:x} has no entry block", function.addr))
                })?;
            function_entries.insert(function.addr, entry_block.addr);

            for block in &function.cfg.blocks {
                for split in
                    split_block(&function.cfg, block, &mut next_synth_addr, &mut call_sites)?
                {
                    if blocks.insert(split.addr, split).is_some() {
                        return Err(io::Error::other(format!(
                            "duplicate executable block address 0x{:x}",
                            block.addr
                        ))
                        .into());
                    }
                }
            }
        }

        let mut compiler = JitCompiler::new(JitConfig::default());
        let mut block_entries = BTreeMap::new();
        for block in blocks.values() {
            let code = compiler
                .compile_block(block.addr, &block.stmts)
                .map_err(|error| {
                    io::Error::other(format!(
                        "failed to compile block 0x{:x}: {error}",
                        block.addr
                    ))
                })?;
            let entry = unsafe { std::mem::transmute::<*const u8, JitEntry>(code) };
            block_entries.insert(block.addr, entry);
        }

        Ok(Self {
            _compiler: compiler,
            block_entries,
            function_entries,
            call_sites,
            _mapped_binary,
            stack: vec![0u8; STACK_SIZE],
        })
    }

    fn execute_main(&self, entry_addr: u64) -> TestResult<i32> {
        let start_pc = *self
            .function_entries
            .get(&entry_addr)
            .ok_or_else(|| io::Error::other(format!("no lifted entry for 0x{entry_addr:x}")))?;

        let mut ctx = JitContext::default();
        ctx.sp = self.initial_sp();

        self.execute_from_pc(start_pc, &mut ctx)?;
        Ok(ctx.x[0] as u32 as i32)
    }

    fn execute_from_pc(&self, start_pc: u64, ctx: &mut JitContext) -> TestResult<()> {
        let mut pc = start_pc;
        loop {
            let entry = *self
                .block_entries
                .get(&pc)
                .ok_or_else(|| io::Error::other(format!("no compiled block for pc 0x{pc:x}")))?;

            debug_roundtrip(|| {
                eprintln!(
                    "enter pc=0x{pc:x} x0={} x1={} x2={} x3={} x19={} sp=0x{:x} flags=0x{:x}",
                    ctx.x[0], ctx.x[1], ctx.x[2], ctx.x[3], ctx.x[19], ctx.sp, ctx.flags
                );
            });
            let next = unsafe { entry(ctx) };
            debug_roundtrip(|| {
                eprintln!(
                    "leave pc=0x{pc:x} next=0x{next:x} x0={} x1={} x2={} x3={} x19={} sp=0x{:x} flags=0x{:x}",
                    ctx.x[0], ctx.x[1], ctx.x[2], ctx.x[3], ctx.x[19], ctx.sp, ctx.flags
                );
            });
            if next == 0 {
                return Ok(());
            }

            if let Some(call_site_id) = decode_call_site(next) {
                let call_site = self.call_sites.get(call_site_id).ok_or_else(|| {
                    io::Error::other(format!("invalid call-site id {call_site_id}"))
                })?;
                let callee_entry =
                    *self
                        .function_entries
                        .get(&call_site.callee)
                        .ok_or_else(|| {
                            io::Error::other(format!(
                                "no lifted callee entry for 0x{:x}",
                                call_site.callee
                            ))
                        })?;
                self.execute_from_pc(callee_entry, ctx)?;
                pc = call_site.continuation;
                continue;
            }

            pc = next;
        }
    }

    fn initial_sp(&self) -> u64 {
        let base = self.stack.as_ptr() as u64;
        (base + self.stack.len() as u64 - 0x100) & !0xf
    }
}

fn split_block(
    cfg: &Cfg,
    block: &BasicBlock,
    next_synth_addr: &mut u64,
    call_sites: &mut Vec<CallSite>,
) -> TestResult<Vec<ExecutableBlock>> {
    let mut result = Vec::new();
    let mut current_addr = block.addr;
    let mut current_stmts = Vec::new();

    for (index, stmt) in block.stmts.iter().enumerate() {
        match stmt {
            Stmt::Call {
                target: Expr::Imm(callee),
            } => {
                let continuation = if index + 1 < block.stmts.len() {
                    allocate_synth_addr(next_synth_addr)?
                } else {
                    single_successor_addr(cfg, block)?
                };
                let call_site_id = call_sites.len();
                call_sites.push(CallSite {
                    callee: *callee,
                    continuation,
                });
                current_stmts.push(Stmt::Branch {
                    target: Expr::Imm(encode_call_site(call_site_id)?),
                });
                result.push(ExecutableBlock {
                    addr: current_addr,
                    stmts: std::mem::take(&mut current_stmts),
                });
                current_addr = continuation;
            }
            Stmt::Call { .. } => {
                return Err(io::Error::other(format!(
                    "block 0x{:x} contains an indirect call",
                    block.addr
                ))
                .into());
            }
            _ => current_stmts.push(stmt.clone()),
        }
    }

    if !current_stmts.is_empty() {
        append_fallthrough_if_needed(cfg, block, &mut current_stmts)?;
        result.push(ExecutableBlock {
            addr: current_addr,
            stmts: current_stmts,
        });
    }

    Ok(result)
}

fn allocate_synth_addr(next_synth_addr: &mut u64) -> TestResult<u64> {
    let addr = *next_synth_addr;
    if addr >= CALL_SITE_TAG {
        return Err(
            io::Error::other("synthetic block address overflowed call-site tag space").into(),
        );
    }
    *next_synth_addr = next_synth_addr
        .checked_add(4)
        .ok_or_else(|| io::Error::other("synthetic block address overflow"))?;
    Ok(addr)
}

fn single_successor_addr(cfg: &Cfg, block: &BasicBlock) -> TestResult<u64> {
    let successor = block.successors.as_slice();
    let [successor] = successor else {
        return Err(io::Error::other(format!(
            "call-ending block 0x{:x} does not have exactly one fallthrough successor",
            block.addr
        ))
        .into());
    };
    cfg.blocks
        .get(*successor as usize)
        .map(|block| block.addr)
        .ok_or_else(|| {
            io::Error::other(format!(
                "successor block id {} for 0x{:x} is out of range",
                successor, block.addr
            ))
            .into()
        })
}

fn append_fallthrough_if_needed(
    cfg: &Cfg,
    block: &BasicBlock,
    stmts: &mut Vec<Stmt>,
) -> TestResult {
    if stmts.last().is_some_and(is_terminator) {
        return Ok(());
    }

    let fallthrough = single_successor_addr(cfg, block)?;
    stmts.push(Stmt::Branch {
        target: Expr::Imm(fallthrough),
    });
    Ok(())
}

fn lift_reachable_functions(
    binary: &LoadedBinary,
    entry_addr: u64,
) -> TestResult<BTreeMap<u64, LiftedFunction>> {
    let entry_addr = exact_function(binary, entry_addr)?.addr;
    let mut queue = VecDeque::from([entry_addr]);
    let mut seen = BTreeSet::new();
    let mut functions = BTreeMap::new();

    while let Some(func_addr) = queue.pop_front() {
        if !seen.insert(func_addr) {
            continue;
        }

        let func = exact_function(binary, func_addr)?;
        let decoded = decode_function(binary, func).map_err(io::Error::other)?;
        let cfg = build_cfg(&decoded.instruction_tuples());

        for callee in collect_direct_callees(&cfg)? {
            let callee_addr = exact_function(binary, callee)?.addr;
            queue.push_back(callee_addr);
        }

        functions.insert(
            func.addr,
            LiftedFunction {
                addr: func.addr,
                cfg,
            },
        );
    }

    Ok(functions)
}

fn collect_direct_callees(cfg: &Cfg) -> TestResult<BTreeSet<u64>> {
    let mut callees = BTreeSet::new();

    for block in &cfg.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Call {
                    target: Expr::Imm(target),
                } => {
                    callees.insert(*target);
                }
                Stmt::Call { .. } => {
                    return Err(io::Error::other(format!(
                        "block 0x{:x} contains an indirect call",
                        block.addr
                    ))
                    .into());
                }
                _ => {}
            }
        }
    }

    Ok(callees)
}

fn exact_function(binary: &LoadedBinary, addr: u64) -> TestResult<&FunctionInfo> {
    let func = binary
        .function_containing(addr)
        .ok_or_else(|| io::Error::other(format!("no function contains 0x{addr:x}")))?;
    if func.addr != addr {
        return Err(io::Error::other(format!(
            "expected an exact function entry at 0x{addr:x}, found 0x{:x}",
            func.addr
        ))
        .into());
    }
    Ok(func)
}

fn max_block_addr(functions: &BTreeMap<u64, LiftedFunction>) -> Option<u64> {
    functions
        .values()
        .flat_map(|function| function.cfg.blocks.iter().map(|block| block.addr))
        .max()
}

fn encode_call_site(call_site_id: usize) -> TestResult<u64> {
    let call_site_id = u64::try_from(call_site_id)?;
    Ok(CALL_SITE_TAG | call_site_id)
}

fn decode_call_site(value: u64) -> Option<usize> {
    if value & CALL_SITE_TAG == 0 {
        return None;
    }
    usize::try_from(value & !CALL_SITE_TAG).ok()
}

fn is_terminator(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Branch { .. } | Stmt::CondBranch { .. } | Stmt::Ret | Stmt::Trap => true,
        Stmt::Pair(left, right) => is_terminator(left) || is_terminator(right),
        _ => false,
    }
}

fn compile_aarch64_sample(source: &Path, output: &Path) -> TestResult<()> {
    // `-fno-inline` keeps the sample helper functions materialized so the
    // harness exercises cross-function lifting and call virtualization.
    // `-fno-stack-protector` avoids libc/PLT calls such as
    // `__stack_chk_fail`, which are outside the harness model.
    run_command(
        "aarch64-linux-gnu-gcc",
        &[
            "-O1",
            "-fno-inline",
            "-fno-stack-protector",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-o",
            output
                .to_str()
                .ok_or_else(|| io::Error::other("invalid arm64 output path"))?,
            source
                .to_str()
                .ok_or_else(|| io::Error::other("invalid sample path"))?,
        ],
    )?;
    Ok(())
}

fn compile_native_sample(source: &Path, output: &Path) -> TestResult<()> {
    let object_path = output.with_extension("sample.o");
    let wrapper_path = output.with_extension("wrapper.c");

    run_command(
        "gcc",
        &[
            "-O1",
            "-fno-inline",
            "-fno-stack-protector",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-Dmain=aeon_sample_main",
            "-c",
            "-o",
            object_path
                .to_str()
                .ok_or_else(|| io::Error::other("invalid native object path"))?,
            source
                .to_str()
                .ok_or_else(|| io::Error::other("invalid sample path"))?,
        ],
    )?;

    fs::write(
        &wrapper_path,
        format!(
            "#include <stdio.h>\nint {alias}(void);\nint main(void) {{\n    printf(\"%d\\n\", {alias}());\n    return 0;\n}}\n",
            alias = NATIVE_ENTRY_ALIAS,
        ),
    )?;

    run_command(
        "gcc",
        &[
            "-fno-pie",
            "-no-pie",
            "-o",
            output
                .to_str()
                .ok_or_else(|| io::Error::other("invalid native output path"))?,
            wrapper_path
                .to_str()
                .ok_or_else(|| io::Error::other("invalid native wrapper path"))?,
            object_path
                .to_str()
                .ok_or_else(|| io::Error::other("invalid native object path"))?,
        ],
    )?;
    Ok(())
}

fn run_command(program: &str, args: &[&str]) -> TestResult<Output> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        return Ok(output);
    }

    Err(io::Error::other(format!(
        "{program} failed with status {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ))
    .into())
}

fn native_main_return_value(binary: &Path) -> TestResult<i32> {
    let output = run_command(
        binary
            .to_str()
            .ok_or_else(|| io::Error::other("invalid native binary path"))?,
        &[],
    )?;
    let stdout = String::from_utf8(output.stdout)?;
    let value = stdout.trim();
    value.parse::<i32>().map_err(|error| {
        io::Error::other(format!(
            "failed to parse native wrapper output `{value}` as i32: {error}"
        ))
        .into()
    })
}

fn symbol_address(path: &Path, symbol_name: &str) -> TestResult<u64> {
    let data = fs::read(path)?;
    let object = object::File::parse(&*data)?;

    for symbol in object.symbols() {
        if symbol.kind() != SymbolKind::Text || symbol.address() == 0 {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name == symbol_name {
            return Ok(symbol.address());
        }
    }

    Err(io::Error::other(format!(
        "failed to resolve symbol `{symbol_name}` in {}",
        path.display()
    ))
    .into())
}

fn run_sample(case: SampleCase) -> TestResult {
    let _guard = FIXED_ADDRESS_TEST_LOCK
        .lock()
        .map_err(|_| io::Error::other("fixed-address roundtrip test lock is poisoned"))?;
    let tempdir = TempDir::new()?;
    let source = repo_root().join(case.source);
    let stem = source
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| io::Error::other(format!("invalid sample name: {}", source.display())))?;

    let arm64_binary = tempdir.path().join(format!("{stem}_arm64.elf"));
    let native_binary = tempdir.path().join(format!("{stem}_x64.elf"));

    compile_aarch64_sample(&source, &arm64_binary)?;
    compile_native_sample(&source, &native_binary)?;

    let native_return = native_main_return_value(&native_binary)?;
    if let Some(expected_return) = case.expected_return {
        assert_eq!(native_return, expected_return, "native return mismatch");
    }

    let arm64_binary_str = arm64_binary
        .to_str()
        .ok_or_else(|| io::Error::other("invalid arm64 binary path"))?;
    let binary = load_elf(arm64_binary_str)?;
    let entry_addr = symbol_address(&arm64_binary, case.entry_symbol)?;
    let functions = lift_reachable_functions(&binary, entry_addr)?;
    assert!(
        functions.len() >= case.min_lifted_functions,
        "expected at least {} lifted functions for {}, found {}",
        case.min_lifted_functions,
        case.source,
        functions.len()
    );
    let direct_call_sites = count_direct_call_sites(&functions)?;
    assert!(
        direct_call_sites >= case.min_direct_call_sites,
        "expected at least {} direct call sites for {}, found {}",
        case.min_direct_call_sites,
        case.source,
        direct_call_sites
    );
    debug_roundtrip(|| {
        for function in functions.values() {
            eprintln!("function 0x{:x}", function.addr);
            for block in &function.cfg.blocks {
                eprintln!("  block 0x{:x}", block.addr);
                for stmt in &block.stmts {
                    eprintln!("    {:?}", stmt);
                }
            }
        }
    });
    let program = JittedProgram::new(&binary, &functions)?;
    let jit_return = program.execute_main(entry_addr)?;

    if let Some(expected_return) = case.expected_return {
        assert_eq!(jit_return, expected_return, "JIT return mismatch");
    }
    assert_eq!(jit_return, native_return, "native and JIT returns diverged");

    Ok(())
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn page_size() -> TestResult<u64> {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 {
        return Err(io::Error::other("sysconf(_SC_PAGESIZE) failed").into());
    }
    Ok(u64::try_from(value)?)
}

fn debug_roundtrip(f: impl FnOnce()) {
    if std::env::var_os("AEON_DEBUG_ROUNDTRIP").is_some() {
        f();
    }
}

fn count_direct_call_sites(functions: &BTreeMap<u64, LiftedFunction>) -> TestResult<usize> {
    let mut total = 0usize;
    for function in functions.values() {
        for block in &function.cfg.blocks {
            for stmt in &block.stmts {
                match stmt {
                    Stmt::Call {
                        target: Expr::Imm(_),
                    } => total += 1,
                    Stmt::Call { .. } => {
                        return Err(io::Error::other(format!(
                            "block 0x{:x} contains an indirect call",
                            block.addr
                        ))
                        .into());
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(total)
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

macro_rules! sample_test {
    ($name:ident, $case:expr) => {
        #[test]
        fn $name() -> TestResult {
            run_sample($case)
        }
    };
}

sample_test!(
    test_sample_hello_aarch64,
    SampleCase {
        source: "samples/hello_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(1217937074),
        min_lifted_functions: 3,
        min_direct_call_sites: 2,
    }
);

sample_test!(
    test_sample_stack_calls_aarch64,
    SampleCase {
        source: "samples/stack_calls_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(6310),
        min_lifted_functions: 3,
        min_direct_call_sites: 3,
    }
);

sample_test!(
    test_sample_recursive_calls_aarch64,
    SampleCase {
        source: "samples/recursive_calls_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(89),
        min_lifted_functions: 3,
        min_direct_call_sites: 4,
    }
);

sample_test!(
    test_sample_bitops_aarch64,
    SampleCase {
        source: "samples/bitops_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(1404584957),
        min_lifted_functions: 6,
        min_direct_call_sites: 5,
    }
);

sample_test!(
    test_sample_loops_cond_aarch64,
    SampleCase {
        source: "samples/loops_cond_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(504),
        min_lifted_functions: 5,
        min_direct_call_sites: 7,
    }
);

sample_test!(
    test_sample_struct_array_aarch64,
    SampleCase {
        source: "samples/struct_array_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(13966),
        min_lifted_functions: 6,
        min_direct_call_sites: 6,
    }
);

sample_test!(
    test_sample_deep_stack_aarch64,
    SampleCase {
        source: "samples/deep_stack_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(2127423099),
        min_lifted_functions: 5,
        min_direct_call_sites: 7,
    }
);

sample_test!(
    test_sample_mem_access_aarch64,
    SampleCase {
        source: "samples/mem_access_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(336532132),
        min_lifted_functions: 8,
        min_direct_call_sites: 8,
    }
);

// ── Hash algorithm samples ────────────────────────────────────────────

sample_test!(
    test_sample_hash_crc32_aarch64,
    SampleCase {
        source: "samples/hash_crc32_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(1397587366),
        min_lifted_functions: 3,
        min_direct_call_sites: 4,
    }
);

sample_test!(
    test_sample_hash_fnv1a_aarch64,
    SampleCase {
        source: "samples/hash_fnv1a_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(1176015575),
        min_lifted_functions: 4,
        min_direct_call_sites: 7,
    }
);

sample_test!(
    test_sample_hash_sha256_aarch64,
    SampleCase {
        source: "samples/hash_sha256_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(1267851199),
        min_lifted_functions: 10,
        min_direct_call_sites: 20,
    }
);

sample_test!(
    test_sample_hash_md5_aarch64,
    SampleCase {
        source: "samples/hash_md5_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(1984371815),
        min_lifted_functions: 8,
        min_direct_call_sites: 10,
    }
);

sample_test!(
    test_sample_hash_siphash_aarch64,
    SampleCase {
        source: "samples/hash_siphash_aarch64.c",
        entry_symbol: "main",
        expected_return: Some(873003949),
        min_lifted_functions: 4,
        min_direct_call_sites: 16,
    }
);
