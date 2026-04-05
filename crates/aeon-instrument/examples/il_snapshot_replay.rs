use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::Arc;

use aeon::emulation::{
    execute_block, BackingStore, BlockExecutionResult, BlockStop, MemoryCellId, MemoryLocation,
    MemoryReadObservation, MemoryValueSource, MemoryWriteObservation, MissingMemoryPolicy, Value,
};
use aeon::lifter;
use aeon_instrument::context::{ElfMemory, MemoryProvider, SnapshotMemory};
use aeonil::{Expr, Reg, Stmt};
use object::{Object, ObjectSymbol, SymbolKind};
use serde::{Deserialize, Serialize};

const BLOCK_STEP_BUDGET: usize = 4096;
const MAX_BLOCK_INSNS: usize = 256;

fn main() {
    let cli = match Cli::parse() {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("{err}");
            usage();
            process::exit(1);
        }
    };

    let setup = match cli.mode {
        Mode::Synthetic => build_synthetic_setup(
            cli.report_out.clone(),
            cli.code_range,
            cli.pc_override,
            &cli.reg_overrides,
        ),
        Mode::ProcessSnapshot(ref dir) => build_process_snapshot_setup(
            dir,
            cli.report_out.clone(),
            cli.code_range,
            cli.pc_override,
            &cli.reg_overrides,
        ),
    };

    let setup = match setup {
        Ok(setup) => setup,
        Err(err) => {
            eprintln!("setup error: {err}");
            process::exit(1);
        }
    };

    let report = match run_replay(
        setup,
        cli.max_blocks,
        cli.max_block_visits,
        cli.missing_memory_policy,
    ) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("replay error: {err}");
            process::exit(1);
        }
    };

    if let Some(parent) = report.report_path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            eprintln!("failed to create {}: {}", parent.display(), err);
            process::exit(1);
        }
    }

    let json = match serde_json::to_string_pretty(&report) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("failed to serialize report: {err}");
            process::exit(1);
        }
    };

    if let Err(err) = fs::write(&report.report_path, json) {
        eprintln!("failed to write {}: {}", report.report_path.display(), err);
        process::exit(1);
    }

    println!("mode:          {}", report.mode);
    println!("start pc:      {}", report.start_pc);
    if let Some(range) = &report.code_range {
        println!("code range:    {}..{}", range[0], range[1]);
    }
    println!("blocks:        {}", report.blocks.len());
    println!("stop:          {}", report.stop_reason);
    println!(
        "summary:       concrete={} symbolic={}",
        report.summary.concrete_blocks, report.summary.symbolic_blocks
    );
    if let Some(first) = &report.summary.first_symbolic_block {
        println!("first symbolic: {}", first);
    }
    println!("report:        {}", report.report_path.display());

    if let Some(last) = report.blocks.last() {
        println!(
            "last block:    {}  reads={} writes={}",
            last.addr,
            last.reads.len(),
            last.writes.len()
        );
        if let Some(read) = last.reads.last() {
            println!(
                "last read:     {} size={} source={} value={}",
                read.location, read.size, read.source, read.value
            );
        }
    }
}

fn usage() {
    eprintln!("usage:");
    eprintln!(
        "  cargo run -p aeon-instrument --example il_snapshot_replay -- synthetic [--pc addr] [--reg name value] [--missing-memory stop|symbolic] [--max-blocks N] [--max-block-visits N] [--code-range start end] [--report-out path]"
    );
    eprintln!(
        "  cargo run -p aeon-instrument --example il_snapshot_replay -- snapshot <dir> [--pc addr] [--reg name value] [--missing-memory stop|symbolic] [--max-blocks N] [--max-block-visits N] [--code-range start end] [--report-out path]"
    );
}

#[derive(Debug, Clone)]
struct Cli {
    mode: Mode,
    pc_override: Option<u64>,
    reg_overrides: Vec<(Reg, u64)>,
    missing_memory_policy: MissingMemoryPolicy,
    max_blocks: u64,
    max_block_visits: u64,
    code_range: Option<(u64, u64)>,
    report_out: PathBuf,
}

#[derive(Debug, Clone)]
enum Mode {
    Synthetic,
    ProcessSnapshot(PathBuf),
}

impl Cli {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            return Err("missing mode".to_string());
        }

        let mut idx = 0usize;
        let mode = match args[idx].as_str() {
            "synthetic" => {
                idx += 1;
                Mode::Synthetic
            }
            "snapshot" => {
                idx += 1;
                let dir = args
                    .get(idx)
                    .ok_or_else(|| "snapshot mode requires a directory".to_string())?;
                idx += 1;
                Mode::ProcessSnapshot(PathBuf::from(dir))
            }
            other => return Err(format!("unknown mode '{other}'")),
        };

        let mut max_blocks = 32u64;
        let mut max_block_visits = 8u64;
        let mut pc_override = None;
        let mut reg_overrides = Vec::new();
        let mut missing_memory_policy = MissingMemoryPolicy::Stop;
        let mut code_range = None;
        let mut report_out = match &mode {
            Mode::Synthetic => std::env::temp_dir().join("aeon_il_synthetic_report.json"),
            Mode::ProcessSnapshot(dir) => dir.join("il_replay_report.json"),
        };

        while idx < args.len() {
            match args[idx].as_str() {
                "--max-blocks" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or_else(|| "--max-blocks requires a value".to_string())?;
                    max_blocks = parse_u64(value)?;
                    idx += 2;
                }
                "--max-block-visits" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or_else(|| "--max-block-visits requires a value".to_string())?;
                    max_block_visits = parse_u64(value)?;
                    idx += 2;
                }
                "--pc" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or_else(|| "--pc requires an address".to_string())?;
                    pc_override = Some(parse_u64(value)?);
                    idx += 2;
                }
                "--reg" => {
                    let name = args
                        .get(idx + 1)
                        .ok_or_else(|| "--reg requires a register name and value".to_string())?;
                    let value = args
                        .get(idx + 2)
                        .ok_or_else(|| "--reg requires a register name and value".to_string())?;
                    reg_overrides.push((parse_reg(name)?, parse_u64(value)?));
                    idx += 3;
                }
                "--missing-memory" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or_else(|| "--missing-memory requires stop or symbolic".to_string())?;
                    missing_memory_policy = parse_missing_memory_policy(value)?;
                    idx += 2;
                }
                "--code-range" => {
                    let start = args
                        .get(idx + 1)
                        .ok_or_else(|| "--code-range requires start and end".to_string())?;
                    let end = args
                        .get(idx + 2)
                        .ok_or_else(|| "--code-range requires start and end".to_string())?;
                    let start = parse_u64(start)?;
                    let end = parse_u64(end)?;
                    if start >= end {
                        return Err(format!(
                            "invalid code range 0x{start:x}..0x{end:x}: start must be below end"
                        ));
                    }
                    code_range = Some((start, end));
                    idx += 3;
                }
                "--report-out" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or_else(|| "--report-out requires a path".to_string())?;
                    report_out = PathBuf::from(value);
                    idx += 2;
                }
                other => return Err(format!("unknown option '{other}'")),
            }
        }

        Ok(Self {
            mode,
            pc_override,
            reg_overrides,
            missing_memory_policy,
            max_blocks,
            max_block_visits,
            code_range,
            report_out,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ProcessSnapshotManifest {
    faulting_pc: String,
    registers: BTreeMap<String, String>,
    regions: Vec<ProcessRegion>,
}

#[derive(Debug, Deserialize, Clone)]
struct ProcessRegion {
    base: String,
    end: String,
    perms: String,
    file_path: String,
    dumped: bool,
    dump_file: Option<String>,
    skip_reason: Option<String>,
}

#[derive(Debug, Clone)]
enum RegionSource {
    File(PathBuf),
    Inline(Arc<Vec<u8>>),
}

#[derive(Debug, Clone)]
struct ReplayRegion {
    base: u64,
    end: u64,
    perms: String,
    file_path: String,
    dumped: bool,
    skip_reason: Option<String>,
    source: Option<RegionSource>,
}

#[derive(Debug)]
struct SnapshotBackingStore {
    regions: Vec<ReplayRegion>,
    cache: RefCell<BTreeMap<u64, Arc<Vec<u8>>>>,
}

impl SnapshotBackingStore {
    fn new(mut regions: Vec<ReplayRegion>) -> Self {
        regions.sort_by_key(|region| region.base);
        Self {
            regions,
            cache: RefCell::new(BTreeMap::new()),
        }
    }

    fn find_region_exact(&self, addr: u64) -> Option<&ReplayRegion> {
        let idx = self.regions.partition_point(|region| region.base <= addr);
        let region = self.regions.get(idx.checked_sub(1)?)?;
        if addr < region.end {
            Some(region)
        } else {
            None
        }
    }

    fn find_region(&self, addr: u64) -> Option<(u64, &ReplayRegion)> {
        for candidate in canonical_address_candidates(addr) {
            if let Some(region) = self.find_region_exact(candidate) {
                return Some((candidate, region));
            }
        }
        None
    }

    fn region_summary(&self, location: &MemoryLocation) -> Option<String> {
        let addr = match location {
            MemoryLocation::Unknown => return None,
            MemoryLocation::Absolute(addr) => *addr,
            MemoryLocation::StackSlot(_) => return None,
        };
        let (_, region) = self.find_region(addr)?;
        Some(format!(
            "{} [{}] dumped={}{}",
            region.file_path,
            region.perms,
            region.dumped,
            region
                .skip_reason
                .as_ref()
                .map(|reason| format!(" skip_reason={reason}"))
                .unwrap_or_default()
        ))
    }

    fn region_bytes(&self, region: &ReplayRegion) -> Option<Arc<Vec<u8>>> {
        if let Some(cached) = self.cache.borrow().get(&region.base).cloned() {
            return Some(cached);
        }

        let bytes = match region.source.as_ref()? {
            RegionSource::File(path) => fs::read(path).ok()?,
            RegionSource::Inline(bytes) => bytes.as_ref().clone(),
        };
        let bytes = Arc::new(bytes);
        self.cache.borrow_mut().insert(region.base, bytes.clone());
        Some(bytes)
    }
}

impl BackingStore for SnapshotBackingStore {
    fn load(&self, addr: u64, size: u8) -> Option<Vec<u8>> {
        let (resolved_addr, region) = self.find_region(addr)?;
        if !region.dumped {
            return None;
        }
        let end = resolved_addr.checked_add(size as u64)?;
        if end > region.end {
            return None;
        }
        let bytes = self.region_bytes(region)?;
        let start = (resolved_addr - region.base) as usize;
        let end = start + size as usize;
        if end > bytes.len() {
            return None;
        }
        Some(bytes[start..end].to_vec())
    }
}

struct ReplaySetup {
    mode_name: String,
    report_out: PathBuf,
    start_pc: u64,
    code_range: Option<(u64, u64)>,
    registers: BTreeMap<Reg, Value>,
    code_memory: Box<dyn MemoryProvider>,
    backing_store: SnapshotBackingStore,
}

#[derive(Debug, Clone)]
struct LiftedBlock {
    addr: u64,
    stmts: Vec<Stmt>,
    terminator: BlockTerminator,
}

#[derive(Debug, Clone, Copy)]
enum BlockTerminator {
    DirectBranch,
    DynamicBranch,
    DirectCall,
    DynamicCall,
    Return,
    CondBranch,
    Trap,
}

#[derive(Debug, Clone)]
enum ReplayStop {
    Halted,
    MaxBlocks,
    MaxBlockVisits(u64),
    CodeRangeExit(u64),
    LiftError(u64, String),
    MissingMemory {
        block_addr: u64,
        location: MemoryLocation,
        size: u8,
    },
    SymbolicBranch(u64),
    UnsupportedControlFlow(u64),
    StepBudget(u64),
}

#[derive(Debug, Serialize)]
struct ReplayReport {
    mode: String,
    report_path: PathBuf,
    start_pc: String,
    code_range: Option<[String; 2]>,
    stop_reason: String,
    summary: ReplaySummary,
    blocks: Vec<BlockReport>,
    final_registers: Vec<RegisterReport>,
    final_memory: Vec<MemoryReport>,
}

#[derive(Debug, Serialize)]
struct ReplaySummary {
    concrete_blocks: usize,
    symbolic_blocks: usize,
    first_symbolic_block: Option<String>,
}

#[derive(Debug, Serialize)]
struct BlockReport {
    addr: String,
    stop: String,
    next_pc: Option<String>,
    symbolic: bool,
    first_symbolic_source: Option<String>,
    downstream_concrete_blocks: usize,
    downstream_symbolic_blocks: usize,
    reads: Vec<ReadReport>,
    writes: Vec<WriteReport>,
    changed_registers: Vec<RegisterReport>,
}

#[derive(Debug, Serialize)]
struct ReadReport {
    location: String,
    size: u8,
    value: String,
    concrete: bool,
    source: String,
    region: Option<String>,
}

#[derive(Debug, Serialize)]
struct WriteReport {
    location: String,
    size: u8,
    value: String,
    concrete: bool,
}

#[derive(Debug, Serialize)]
struct RegisterReport {
    reg: String,
    value: String,
    concrete: bool,
}

#[derive(Debug, Serialize)]
struct MemoryReport {
    location: String,
    size: u8,
    value: String,
    concrete: bool,
}

fn run_replay(
    setup: ReplaySetup,
    max_blocks: u64,
    max_block_visits: u64,
    missing_memory_policy: MissingMemoryPolicy,
) -> Result<ReplayReport, String> {
    let mut registers = setup.registers;
    let mut memory_overlay = BTreeMap::<MemoryCellId, Value>::new();
    let mut lifted_blocks = BTreeMap::<u64, LiftedBlock>::new();
    let mut visits = BTreeMap::<u64, u64>::new();
    let mut pc = setup.start_pc;
    let mut blocks = Vec::new();
    let stop_reason;

    loop {
        if let Some((start, end)) = setup.code_range {
            if pc < start || pc >= end {
                stop_reason = ReplayStop::CodeRangeExit(pc);
                break;
            }
        }

        if blocks.len() as u64 >= max_blocks {
            stop_reason = ReplayStop::MaxBlocks;
            break;
        }

        let visit_count = visits.entry(pc).or_insert(0);
        if *visit_count >= max_block_visits {
            stop_reason = ReplayStop::MaxBlockVisits(pc);
            break;
        }
        *visit_count += 1;

        if !lifted_blocks.contains_key(&pc) {
            let block = match lift_block(pc, setup.code_memory.as_ref()) {
                Ok(block) => block,
                Err(err) => {
                    stop_reason = ReplayStop::LiftError(pc, err);
                    break;
                }
            };
            lifted_blocks.insert(pc, block);
        }
        let block = lifted_blocks
            .get(&pc)
            .cloned()
            .ok_or_else(|| format!("missing cached block for 0x{pc:x}"))?;

        let previous_registers = registers.clone();
        let initial_registers = std::mem::take(&mut registers);
        let initial_memory = std::mem::take(&mut memory_overlay);
        let incoming_symbolic_source =
            first_symbolic_input_source(&initial_registers, &initial_memory);
        let result = execute_block(
            &block.stmts,
            initial_registers,
            initial_memory,
            &setup.backing_store,
            missing_memory_policy,
            BLOCK_STEP_BUDGET,
        );

        let mut next_pc = result.next_pc;
        if matches!(
            block.terminator,
            BlockTerminator::DynamicBranch | BlockTerminator::DynamicCall | BlockTerminator::Return
        ) {
            if let Some(candidate) = next_pc {
                if let Some(normalized) = normalize_code_addr(candidate, setup.code_range) {
                    next_pc = Some(normalized);
                }
            }
        }

        let changed_registers = diff_registers(&previous_registers, &result.final_registers);
        let block_report = block_report(
            &block,
            &result,
            &setup.backing_store,
            changed_registers,
            incoming_symbolic_source,
        );

        registers = result.final_registers;
        memory_overlay = result.final_memory;
        blocks.push(block_report);

        match result.stop {
            BlockStop::Completed => match next_pc {
                Some(0) => {
                    stop_reason = ReplayStop::Halted;
                    break;
                }
                Some(next_pc) => {
                    registers.insert(Reg::PC, Value::U64(next_pc));
                    pc = next_pc;
                }
                None => {
                    stop_reason = ReplayStop::UnsupportedControlFlow(block.addr);
                    break;
                }
            },
            BlockStop::StepBudget => {
                stop_reason = ReplayStop::StepBudget(block.addr);
                break;
            }
            BlockStop::MissingMemory { location, size } => {
                stop_reason = ReplayStop::MissingMemory {
                    block_addr: block.addr,
                    location,
                    size,
                };
                break;
            }
            BlockStop::SymbolicBranch => {
                stop_reason = ReplayStop::SymbolicBranch(block.addr);
                break;
            }
            BlockStop::UnsupportedControlFlow => {
                stop_reason = ReplayStop::UnsupportedControlFlow(block.addr);
                break;
            }
        }
    }

    let final_registers = register_reports(&registers);
    annotate_block_symbolic_summary(&mut blocks);
    let mut final_memory: Vec<_> = memory_overlay
        .iter()
        .map(|(id, value)| MemoryReport {
            location: format_location(&id.location),
            size: id.size,
            value: format_value(value),
            concrete: is_concrete(value),
        })
        .collect();
    final_memory.sort_by(|lhs, rhs| lhs.location.cmp(&rhs.location));

    Ok(ReplayReport {
        mode: setup.mode_name,
        report_path: setup.report_out,
        start_pc: format_hex(setup.start_pc),
        code_range: setup
            .code_range
            .map(|(start, end)| [format_hex(start), format_hex(end)]),
        stop_reason: format_stop_reason(&stop_reason),
        summary: replay_summary(&blocks),
        blocks,
        final_registers,
        final_memory,
    })
}

fn build_synthetic_setup(
    report_out: PathBuf,
    code_range_override: Option<(u64, u64)>,
    pc_override: Option<u64>,
    reg_overrides: &[(Reg, u64)],
) -> Result<ReplaySetup, String> {
    let elf_path = compile_sample("samples/probe_reads_aarch64.c")?;
    let (entry_pc, symbol_range) = symbol_range(&elf_path, "probe_reads")?;
    let start_pc = pc_override.unwrap_or(entry_pc);
    let code_range = code_range_override.or(Some(symbol_range));
    let code_memory = Box::new(
        ElfMemory::from_elf(
            elf_path
                .to_str()
                .ok_or_else(|| format!("non-utf8 path {}", elf_path.display()))?,
        )
        .map_err(|err| format!("load ELF {}: {err}", elf_path.display()))?,
    ) as Box<dyn MemoryProvider>;

    let known_base = 0x5000_0000u64;
    let stack_base = 0x6000_0000u64;
    let unknown_base = 0x5000_1000u64;
    let known_bytes = Arc::new(vec![0x11, 0x22, 0x33, 0x44]);
    let stack_bytes = Arc::new(vec![0u8; 0x4000]);
    let backing_store = SnapshotBackingStore::new(vec![
        ReplayRegion {
            base: known_base,
            end: known_base + known_bytes.len() as u64,
            perms: "rw-p".to_string(),
            file_path: "[synthetic-known]".to_string(),
            dumped: true,
            skip_reason: None,
            source: Some(RegionSource::Inline(known_bytes)),
        },
        ReplayRegion {
            base: stack_base,
            end: stack_base + stack_bytes.len() as u64,
            perms: "rw-p".to_string(),
            file_path: "[synthetic-stack]".to_string(),
            dumped: true,
            skip_reason: None,
            source: Some(RegionSource::Inline(stack_bytes)),
        },
    ]);

    let mut registers = BTreeMap::new();
    registers.insert(Reg::PC, Value::U64(start_pc));
    registers.insert(Reg::SP, Value::U64(stack_base + 0x3000));
    registers.insert(Reg::X(0), Value::U64(known_base));
    registers.insert(Reg::X(1), Value::U64(unknown_base));
    registers.insert(Reg::X(30), Value::U64(0));
    apply_reg_overrides(&mut registers, reg_overrides);

    Ok(ReplaySetup {
        mode_name: "synthetic".to_string(),
        report_out,
        start_pc,
        code_range,
        registers,
        code_memory,
        backing_store,
    })
}

fn build_process_snapshot_setup(
    dir: &Path,
    report_out: PathBuf,
    code_range_override: Option<(u64, u64)>,
    pc_override: Option<u64>,
    reg_overrides: &[(Reg, u64)],
) -> Result<ReplaySetup, String> {
    let manifest_path = dir.join("before_manifest.json");
    let manifest_str = fs::read_to_string(&manifest_path)
        .map_err(|err| format!("read {}: {err}", manifest_path.display()))?;
    let manifest: ProcessSnapshotManifest =
        serde_json::from_str(&manifest_str).map_err(|err| format!("parse manifest: {err}"))?;

    let manifest_pc = parse_u64(&manifest.faulting_pc)?;
    let start_pc = pc_override.unwrap_or(manifest_pc);
    let code_range = code_range_override.or_else(|| derive_code_range(&manifest.regions, start_pc));
    let memdump_dir = dir.join("memdump");

    let mut code_memory = SnapshotMemory::new();
    let mut backing_regions = Vec::with_capacity(manifest.regions.len());

    for region in &manifest.regions {
        let base = parse_u64(&region.base)?;
        let end = parse_u64(&region.end)?;
        let source = region
            .dump_file
            .as_ref()
            .map(|name| RegionSource::File(memdump_dir.join(name)));

        if region.dumped && overlaps(code_range, base, end) {
            let path = match source.as_ref() {
                Some(RegionSource::File(path)) => path,
                _ => {
                    return Err(format!(
                        "executable dumped region {} is missing dump_file",
                        region.file_path
                    ))
                }
            };
            let bytes = fs::read(path)
                .map_err(|err| format!("read code region {}: {err}", path.display()))?;
            code_memory.add_region(base, bytes);
        }

        backing_regions.push(ReplayRegion {
            base,
            end,
            perms: region.perms.clone(),
            file_path: region.file_path.clone(),
            dumped: region.dumped,
            skip_reason: region.skip_reason.clone(),
            source,
        });
    }

    if let Some((jit_base, jit_bytes)) = find_manual_jit_exec_alias(dir)? {
        code_memory.add_region(jit_base, jit_bytes);
    }

    let mut registers = BTreeMap::new();
    registers.insert(Reg::PC, Value::U64(start_pc));
    if let Some(sp) = manifest.registers.get("sp") {
        registers.insert(Reg::SP, Value::U64(parse_u64(sp)?));
    }
    for index in 0..31u8 {
        let name = format!("x{index}");
        if let Some(value) = manifest.registers.get(&name) {
            registers.insert(Reg::X(index), Value::U64(parse_u64(value)?));
        }
    }
    apply_reg_overrides(&mut registers, reg_overrides);

    Ok(ReplaySetup {
        mode_name: "process_snapshot".to_string(),
        report_out,
        start_pc,
        code_range,
        registers,
        code_memory: Box::new(code_memory),
        backing_store: SnapshotBackingStore::new(backing_regions),
    })
}

fn compile_sample(source_rel: &str) -> Result<PathBuf, String> {
    let repo_root = repo_root();
    let source = repo_root.join(source_rel);
    let stem = source
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| format!("invalid sample path {}", source.display()))?;
    let out = repo_root
        .join("target")
        .join(format!("{stem}_il_replay.elf"));

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
        .map_err(|err| format!("spawn aarch64-linux-gnu-gcc: {err}"))?;
    if !status.success() {
        return Err(format!("cross-compile failed for {}", source.display()));
    }

    Ok(out)
}

fn apply_reg_overrides(registers: &mut BTreeMap<Reg, Value>, overrides: &[(Reg, u64)]) {
    for (reg, value) in overrides {
        registers.insert(reg.clone(), Value::U64(*value));
    }
}

fn symbol_range(path: &Path, name: &str) -> Result<(u64, (u64, u64)), String> {
    let data = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let obj =
        object::File::parse(&*data).map_err(|err| format!("parse {}: {err}", path.display()))?;

    let mut text_symbols = Vec::new();
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text || sym.address() == 0 {
            continue;
        }
        let sym_name = match sym.name() {
            Ok(value) => value.to_string(),
            Err(_) => continue,
        };
        text_symbols.push((sym_name, sym.address(), sym.size()));
    }
    text_symbols.sort_by_key(|(_, addr, _)| *addr);

    for (idx, (sym_name, addr, size)) in text_symbols.iter().enumerate() {
        if sym_name != name {
            continue;
        }
        let end = if *size > 0 {
            *addr + *size
        } else {
            text_symbols
                .get(idx + 1)
                .map(|(_, next, _)| *next)
                .ok_or_else(|| format!("symbol {name} has zero size and no successor"))?
        };
        return Ok((*addr, (*addr, end)));
    }

    Err(format!("symbol {name} not found in {}", path.display()))
}

fn derive_code_range(regions: &[ProcessRegion], pc: u64) -> Option<(u64, u64)> {
    let mut parsed = Vec::with_capacity(regions.len());
    for region in regions {
        let base = parse_u64(&region.base).ok()?;
        let end = parse_u64(&region.end).ok()?;
        parsed.push((base, end, region.file_path.clone()));
    }
    parsed.sort_by_key(|(base, _, _)| *base);

    let idx = parsed
        .iter()
        .position(|(base, end, _)| *base <= pc && pc < *end)?;
    let (_, _, path) = &parsed[idx];

    let mut start = parsed[idx].0;
    let mut end = parsed[idx].1;

    let mut left = idx;
    while left > 0 && parsed[left - 1].2 == *path && parsed[left - 1].1 == start {
        left -= 1;
        start = parsed[left].0;
    }

    let mut right = idx;
    while right + 1 < parsed.len() && parsed[right + 1].2 == *path && parsed[right + 1].0 == end {
        right += 1;
        end = parsed[right].1;
    }

    Some((start, end))
}

fn find_manual_jit_exec_alias(snapshot_dir: &Path) -> Result<Option<(u64, Vec<u8>)>, String> {
    let Some(manual_dir) = snapshot_dir.parent() else {
        return Ok(None);
    };

    let mut matches = Vec::new();
    for entry in
        fs::read_dir(manual_dir).map_err(|err| format!("read {}: {err}", manual_dir.display()))?
    {
        let entry = entry.map_err(|err| format!("iterate {}: {err}", manual_dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(base_hex) = name
            .strip_prefix("jit_exec_alias_0x")
            .and_then(|rest| rest.strip_suffix(".bin"))
        else {
            continue;
        };
        matches.push((parse_u64(&format!("0x{base_hex}"))?, entry.path()));
    }

    matches.sort_by_key(|(base, _)| *base);
    if let Some((base, path)) = matches.first() {
        let bytes = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
        return Ok(Some((*base, bytes)));
    }

    Ok(None)
}

fn overlaps(range: Option<(u64, u64)>, base: u64, end: u64) -> bool {
    match range {
        Some((range_start, range_end)) => base < range_end && range_start < end,
        None => true,
    }
}

fn canonical_address_candidates(addr: u64) -> [u64; 3] {
    [
        addr,
        addr & 0x00ff_ffff_ffff_ffff,
        addr & 0x0000_ffff_ffff_ffff,
    ]
}

fn lift_block(addr: u64, memory: &dyn MemoryProvider) -> Result<LiftedBlock, String> {
    let mut stmts = Vec::new();
    let mut pc = addr;
    let mut total_bytes = 0usize;
    let mut terminator = None;

    for _ in 0..MAX_BLOCK_INSNS {
        let bytes = memory
            .read(pc, 4)
            .ok_or_else(|| format!("unmapped code at 0x{pc:x}"))?;
        let word = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let next_pc = Some(pc + 4);

        let insn = bad64::decode(word, pc)
            .map_err(|_| format!("invalid ARM64 encoding 0x{word:08x} at 0x{pc:x}"))?;
        let result = lifter::lift(&insn, pc, next_pc);
        let is_term = is_terminator(&result.stmt);
        if is_term {
            terminator = classify_terminator(&result.stmt);
        }
        stmts.push(result.stmt);
        total_bytes += 4;

        if is_term {
            break;
        }
        pc += 4;
    }

    if !stmts.is_empty() && !is_terminator(stmts.last().unwrap()) {
        let next = addr + total_bytes as u64;
        stmts.push(Stmt::Branch {
            target: Expr::Imm(next),
        });
        terminator = Some(BlockTerminator::DirectBranch);
    }

    let return_addr = addr + total_bytes as u64;
    let stmts = transform_calls_and_rets(stmts, return_addr);

    Ok(LiftedBlock {
        addr,
        stmts,
        terminator: terminator.unwrap_or(BlockTerminator::Trap),
    })
}

fn transform_calls_and_rets(stmts: Vec<Stmt>, return_addr: u64) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(stmts.len() + 1);
    for stmt in stmts {
        match stmt {
            Stmt::Call { target } => {
                out.push(Stmt::Assign {
                    dst: Reg::X(30),
                    src: Expr::Imm(return_addr),
                });
                out.push(Stmt::Branch { target });
            }
            Stmt::Ret => {
                out.push(Stmt::Branch {
                    target: Expr::Reg(Reg::X(30)),
                });
            }
            Stmt::Pair(lhs, rhs) => {
                let flattened = transform_calls_and_rets(vec![*lhs, *rhs], return_addr);
                out.extend(flattened);
            }
            other => out.push(other),
        }
    }
    out
}

fn is_terminator(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Branch { .. }
        | Stmt::CondBranch { .. }
        | Stmt::Call { .. }
        | Stmt::Ret
        | Stmt::Trap => true,
        Stmt::Pair(lhs, rhs) => is_terminator(lhs) || is_terminator(rhs),
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
        Stmt::Pair(lhs, rhs) => classify_terminator(rhs).or_else(|| classify_terminator(lhs)),
        _ => None,
    }
}

fn block_report(
    block: &LiftedBlock,
    result: &BlockExecutionResult,
    backing_store: &SnapshotBackingStore,
    changed_registers: Vec<RegisterReport>,
    incoming_symbolic_source: Option<String>,
) -> BlockReport {
    let (symbolic, first_symbolic_source) =
        block_symbolic_summary(result, &changed_registers, incoming_symbolic_source);
    BlockReport {
        addr: format_hex(block.addr),
        stop: format_block_stop(&result.stop),
        next_pc: result.next_pc.map(format_hex),
        symbolic,
        first_symbolic_source,
        downstream_concrete_blocks: 0,
        downstream_symbolic_blocks: 0,
        reads: result
            .reads
            .iter()
            .map(|read| read_report(read, backing_store))
            .collect(),
        writes: result.writes.iter().map(write_report).collect(),
        changed_registers,
    }
}

fn block_symbolic_summary(
    result: &BlockExecutionResult,
    changed_registers: &[RegisterReport],
    incoming_symbolic_source: Option<String>,
) -> (bool, Option<String>) {
    let has_symbolic_effect = result.reads.iter().any(|read| !is_concrete(&read.value))
        || result.writes.iter().any(|write| !is_concrete(&write.value))
        || changed_registers.iter().any(|reg| !reg.concrete)
        || matches!(
            result.stop,
            BlockStop::SymbolicBranch | BlockStop::MissingMemory { .. }
        );

    if !has_symbolic_effect {
        return (false, None);
    }

    let first_symbolic_source = incoming_symbolic_source
        .or_else(|| {
            result
                .reads
                .iter()
                .find(|read| !is_concrete(&read.value))
                .map(first_symbolic_read_source)
        })
        .or_else(|| {
            result
                .writes
                .iter()
                .find(|write| !is_concrete(&write.value))
                .map(first_symbolic_write_source)
        })
        .or_else(|| {
            changed_registers
                .iter()
                .find(|reg| !reg.concrete)
                .map(|reg| format!("register {} became symbolic", reg.reg))
        })
        .or_else(|| match &result.stop {
            BlockStop::SymbolicBranch => Some("symbolic branch condition".to_string()),
            BlockStop::MissingMemory { location, .. } => {
                Some(format!("missing read {}", format_location(location)))
            }
            _ => None,
        });

    (true, first_symbolic_source)
}

fn first_symbolic_input_source(
    registers: &BTreeMap<Reg, Value>,
    memory: &BTreeMap<MemoryCellId, Value>,
) -> Option<String> {
    for reg in tracked_registers() {
        if let Some(value) = registers.get(&reg) {
            if !is_concrete(value) {
                return Some(format!(
                    "incoming register {} was symbolic",
                    format_reg(&reg)
                ));
            }
        }
    }

    for (id, value) in memory {
        if !is_concrete(value) {
            return Some(format!(
                "incoming memory {} was symbolic",
                format_location(&id.location)
            ));
        }
    }

    None
}

fn first_symbolic_read_source(read: &MemoryReadObservation) -> String {
    if read.source.is_none() {
        format!("missing read {}", format_location(&read.id.location))
    } else {
        format!("symbolic read {}", format_location(&read.id.location))
    }
}

fn first_symbolic_write_source(write: &MemoryWriteObservation) -> String {
    format!("symbolic write {}", format_location(&write.id.location))
}

fn annotate_block_symbolic_summary(blocks: &mut [BlockReport]) {
    let mut downstream_concrete_blocks = 0usize;
    let mut downstream_symbolic_blocks = 0usize;

    for block in blocks.iter_mut().rev() {
        block.downstream_concrete_blocks = downstream_concrete_blocks;
        block.downstream_symbolic_blocks = downstream_symbolic_blocks;
        if block.symbolic {
            downstream_symbolic_blocks += 1;
        } else {
            downstream_concrete_blocks += 1;
        }
    }
}

fn replay_summary(blocks: &[BlockReport]) -> ReplaySummary {
    ReplaySummary {
        concrete_blocks: blocks.iter().filter(|block| !block.symbolic).count(),
        symbolic_blocks: blocks.iter().filter(|block| block.symbolic).count(),
        first_symbolic_block: blocks
            .iter()
            .find(|block| block.symbolic)
            .map(|block| block.addr.clone()),
    }
}

fn read_report(read: &MemoryReadObservation, backing_store: &SnapshotBackingStore) -> ReadReport {
    let source = match read.source {
        Some(MemoryValueSource::Overlay) => "overlay".to_string(),
        Some(MemoryValueSource::BackingStore) => "backing_store".to_string(),
        None => "missing_backing_store".to_string(),
    };

    ReadReport {
        location: format_location(&read.id.location),
        size: read.id.size,
        value: format_value(&read.value),
        concrete: is_concrete(&read.value),
        source,
        region: backing_store.region_summary(&read.id.location),
    }
}

fn write_report(write: &MemoryWriteObservation) -> WriteReport {
    WriteReport {
        location: format_location(&write.id.location),
        size: write.id.size,
        value: format_value(&write.value),
        concrete: is_concrete(&write.value),
    }
}

fn diff_registers(
    previous: &BTreeMap<Reg, Value>,
    current: &BTreeMap<Reg, Value>,
) -> Vec<RegisterReport> {
    let mut reports = Vec::new();
    for reg in tracked_registers() {
        let prev = previous.get(&reg);
        let next = current.get(&reg);
        if prev != next {
            reports.push(RegisterReport {
                reg: format_reg(&reg),
                value: next
                    .map(format_value)
                    .unwrap_or_else(|| "<unset>".to_string()),
                concrete: next.map(is_concrete).unwrap_or(false),
            });
        }
    }
    reports
}

fn register_reports(registers: &BTreeMap<Reg, Value>) -> Vec<RegisterReport> {
    let mut reports = Vec::new();
    for reg in tracked_registers() {
        if let Some(value) = registers.get(&reg) {
            reports.push(RegisterReport {
                reg: format_reg(&reg),
                value: format_value(value),
                concrete: is_concrete(value),
            });
        }
    }
    reports
}

fn tracked_registers() -> Vec<Reg> {
    let mut regs = Vec::new();
    for index in 0..31u8 {
        regs.push(Reg::X(index));
    }
    regs.push(Reg::SP);
    regs.push(Reg::PC);
    regs.push(Reg::Flags);
    regs
}

fn normalize_code_addr(addr: u64, code_range: Option<(u64, u64)>) -> Option<u64> {
    let (start, end) = code_range?;
    let candidates = [
        addr,
        addr & 0x00ff_ffff_ffff_ffff,
        addr & 0x0000_ffff_ffff_ffff,
    ];
    candidates
        .into_iter()
        .find(|candidate| *candidate >= start && *candidate < end)
}

fn format_stop_reason(stop: &ReplayStop) -> String {
    match stop {
        ReplayStop::Halted => "halted".to_string(),
        ReplayStop::MaxBlocks => "max_blocks".to_string(),
        ReplayStop::MaxBlockVisits(addr) => format!("max_block_visits at {}", format_hex(*addr)),
        ReplayStop::CodeRangeExit(addr) => format!("code_range_exit at {}", format_hex(*addr)),
        ReplayStop::LiftError(addr, err) => format!("lift_error at {}: {err}", format_hex(*addr)),
        ReplayStop::MissingMemory {
            block_addr,
            location,
            size,
        } => format!(
            "missing_memory in block {} at {} size={}",
            format_hex(*block_addr),
            format_location(location),
            size
        ),
        ReplayStop::SymbolicBranch(addr) => format!("symbolic_branch in {}", format_hex(*addr)),
        ReplayStop::UnsupportedControlFlow(addr) => {
            format!("unsupported_control_flow in {}", format_hex(*addr))
        }
        ReplayStop::StepBudget(addr) => format!("step_budget in {}", format_hex(*addr)),
    }
}

fn format_block_stop(stop: &BlockStop) -> String {
    match stop {
        BlockStop::Completed => "completed".to_string(),
        BlockStop::StepBudget => "step_budget".to_string(),
        BlockStop::MissingMemory { location, size } => {
            format!("missing_memory {} size={}", format_location(location), size)
        }
        BlockStop::SymbolicBranch => "symbolic_branch".to_string(),
        BlockStop::UnsupportedControlFlow => "unsupported_control_flow".to_string(),
    }
}

fn format_location(location: &MemoryLocation) -> String {
    match location {
        MemoryLocation::Unknown => "unknown".to_string(),
        MemoryLocation::Absolute(addr) => format_hex(*addr),
        MemoryLocation::StackSlot(offset) => format!("stack({offset:+#x})"),
    }
}

fn format_reg(reg: &Reg) -> String {
    match reg {
        Reg::X(index) => format!("x{index}"),
        Reg::W(index) => format!("w{index}"),
        Reg::SP => "sp".to_string(),
        Reg::PC => "pc".to_string(),
        Reg::XZR => "xzr".to_string(),
        Reg::Flags => "flags".to_string(),
        Reg::V(index) => format!("v{index}"),
        Reg::Q(index) => format!("q{index}"),
        Reg::D(index) => format!("d{index}"),
        Reg::S(index) => format!("s{index}"),
        Reg::H(index) => format!("h{index}"),
        Reg::VByte(index) => format!("vbyte{index}"),
    }
}

fn format_value(value: &Value) -> String {
    match value {
        Value::U64(bits) => format_hex(*bits),
        Value::U128(bits) => format!("0x{bits:032x}"),
        Value::F64(value) => value.to_string(),
        Value::Unknown => "unknown".to_string(),
    }
}

fn format_hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn is_concrete(value: &Value) -> bool {
    !matches!(value, Value::Unknown)
}

fn parse_u64(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|err| format!("invalid hex value '{value}': {err}"))
    } else {
        value
            .parse::<u64>()
            .map_err(|err| format!("invalid integer value '{value}': {err}"))
    }
}

fn parse_missing_memory_policy(value: &str) -> Result<MissingMemoryPolicy, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "stop" => Ok(MissingMemoryPolicy::Stop),
        "symbolic" => Ok(MissingMemoryPolicy::ContinueAsUnknown),
        other => Err(format!(
            "unsupported --missing-memory value '{other}'; expected stop or symbolic"
        )),
    }
}

fn parse_reg(value: &str) -> Result<Reg, String> {
    let value = value.trim().to_ascii_lowercase();
    if value == "sp" {
        return Ok(Reg::SP);
    }
    if value == "pc" {
        return Ok(Reg::PC);
    }
    if value == "flags" {
        return Ok(Reg::Flags);
    }
    if value == "xzr" {
        return Ok(Reg::XZR);
    }
    if let Some(index) = value.strip_prefix('x') {
        let index = index
            .parse::<u8>()
            .map_err(|err| format!("invalid register '{value}': {err}"))?;
        if index <= 30 {
            return Ok(Reg::X(index));
        }
    }
    if let Some(index) = value.strip_prefix('w') {
        let index = index
            .parse::<u8>()
            .map_err(|err| format!("invalid register '{value}': {err}"))?;
        if index <= 30 {
            return Ok(Reg::W(index));
        }
    }
    Err(format!("unsupported register '{value}'"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf()
}
