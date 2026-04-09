use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process;
use std::process::Command;

use aeon::emulation::{
    execute_block, BackingStore, BlockExecutionResult, BlockStop, MemoryCellId, MemoryLocation,
    MemoryReadObservation, MemoryValueSource, MemoryWriteObservation, MissingMemoryPolicy, Value,
};
use aeon::lifter;
use aeon_instrument::context::MemoryProvider;
use aeonil::{Expr, Reg, Stmt};
use serde::Serialize;

const BLOCK_STEP_BUDGET: usize = 4096;
const MAX_BLOCK_INSNS: usize = 256;
const DEFAULT_START_PC: u64 = 0x9b612670;
const DEFAULT_MAX_BLOCKS: u64 = 512;
const DEFAULT_MAX_BLOCK_VISITS: u64 = 32;
const NT_PRSTATUS: libc::c_ulong = 1;
const LIBC_MEMCPY_OFFSET: u64 = 0x4bb20;
const LIBC_MEMCPY_INTERNAL_OFFSET: u64 = 0x4b9b0;
const LIBC_MEMSET_OFFSET: u64 = 0x4bbe0;
const LIBC_STRCHR_MTE_OFFSET: u64 = 0x49100;
const LIBC_STRCHR_OFFSET: u64 = 0x491c0;
const LIBC_STRCMP_MTE_OFFSET: u64 = 0x492c0;
const LIBC_STRCMP_OFFSET: u64 = 0x49400;
const LIBC_STRLEN_MTE_OFFSET: u64 = 0x49800;
const LIBC_STRLEN_OFFSET: u64 = 0x49880;
const LIBC_STRNCMP_MTE_OFFSET: u64 = 0x499c0;
const LIBC_STRNCMP_OFFSET: u64 = 0x49b80;
const LIBC_CLOCK_GETTIME_OFFSET: u64 = 0x4b420;
const LIBC_GETTIMEOFDAY_OFFSET: u64 = 0x4b4b8;
const LIBC_CLOCK_NANOSLEEP_OFFSET: u64 = 0x5123c;
const LIBC_VSNPRINTF_CHK_OFFSET: u64 = 0x791b0;
const LIBC_SNPRINTF_CHK_OFFSET: u64 = 0x79238;
const LIBC_VSPRINTF_CHK_OFFSET: u64 = 0x7930c;
const LIBC_SPRINTF_CHK_OFFSET: u64 = 0x793a4;
const LIBC_SLEEP_OFFSET: u64 = 0x5e8a8;
const LIBC_USLEEP_OFFSET: u64 = 0x624b0;
const LIBC_NANOSLEEP_OFFSET: u64 = 0x9dc70;
const LIBC_ASPRINTF_OFFSET: u64 = 0xaa750;
const LIBC_SNPRINTF_OFFSET: u64 = 0xabed0;
const LIBC_VSNPRINTF_OFFSET: u64 = 0xac02c;
const LIBC_SPRINTF_OFFSET: u64 = 0xac13c;
const LIBC_VSPRINTF_OFFSET: u64 = 0xac24c;
const LIBC_VASPRINTF_OFFSET: u64 = 0x9b27c;
const LIBC_ACCESS_OFFSET: u64 = 0x4fb58;
const LIBC_OPEN_OFFSET: u64 = 0x5ac5c;
const LIBC_OPENAT_OFFSET: u64 = 0x5af14;
const LIBC_CLOSE_OFFSET: u64 = 0x53f18;
const LIBC_READ_OFFSET: u64 = 0x9d230;
const LIBC_LSEEK_OFFSET: u64 = 0x9d8f0;
const LIBC_FOPEN_OFFSET: u64 = 0xa93a4;
const LIBC_FCLOSE_OFFSET: u64 = 0xa9b08;
const LIBC_FSEEK_OFFSET: u64 = 0xaa324;
const LIBC_FTELL_OFFSET: u64 = 0xaa3dc;
const LIBC_FREAD_OFFSET: u64 = 0xacd40;
const LIBC_FREAD_UNLOCKED_OFFSET: u64 = 0xacdcc;
const LIBC_SCUDO_HYBRID_MUTEX_LOCK_SLOW_START: u64 = 0x404ec;
const LIBC_SCUDO_HYBRID_MUTEX_LOCK_SLOW_END: u64 = 0x4057c;
const LIBC_SCUDO_HYBRID_MUTEX_UNLOCK_START: u64 = 0x4057c;
const LIBC_SCUDO_HYBRID_MUTEX_UNLOCK_END: u64 = 0x405b8;
const LIBANDROID_AASSET_MANAGER_OPEN_OFFSET: u64 = 0x180e0;
const LIBANDROID_AASSET_READ_OFFSET: u64 = 0x18480;
const LIBANDROID_AASSET_CLOSE_OFFSET: u64 = 0x184b0;
const LIBANDROID_AASSET_GET_LENGTH_OFFSET: u64 = 0x184f0;
const LIBANDROID_AASSET_GET_LENGTH64_OFFSET: u64 = 0x18500;
const VDSO_CLOCK_GETTIME_OFFSET: u64 = 0x2e0;
const VDSO_GETTIMEOFDAY_OFFSET: u64 = 0x618;
const VDSO_CLOCK_GETRES_OFFSET: u64 = 0x810;
const VDSO_RT_SIGRETURN_OFFSET: u64 = 0x888;
const MAX_STUB_BYTES: u64 = 1 << 20;
const REMOTE_PAGE_SIZE: u64 = 4096;
const MAX_TRACE_STRING_BYTES: u64 = 512;
const SYNTHETIC_FILE_STREAM_BASE: u64 = 0x7fff_0000_0000;
const SYNTHETIC_FILE_STREAM_STRIDE: u64 = 0x100;
const SYNTHETIC_ASSET_HANDLE_BASE: u64 = 0x7ffe_0000_0000;
const SYNTHETIC_ASSET_HANDLE_STRIDE: u64 = 0x100;

fn main() {
    let cli = match Cli::parse() {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("{err}");
            usage();
            process::exit(1);
        }
    };

    let state_json = match cli.state_json.as_deref().map(load_state_json).transpose() {
        Ok(state) => state,
        Err(err) => {
            eprintln!("invalid state json: {err}");
            process::exit(1);
        }
    };

    let pid = cli
        .pid
        .or_else(|| state_json.as_ref().and_then(|state| state.pid))
        .unwrap_or_else(|| {
            eprintln!("--pid is required unless provided by --state-json");
            usage();
            process::exit(1);
        });
    let tid = cli
        .tid
        .or_else(|| state_json.as_ref().and_then(|state| state.tid))
        .unwrap_or(pid);

    let challenge_input = cli
        .challenge
        .as_ref()
        .or_else(|| {
            state_json
                .as_ref()
                .and_then(|state| state.challenge.as_ref())
        })
        .unwrap_or_else(|| {
            eprintln!("--challenge is required unless provided by --state-json");
            usage();
            process::exit(1);
        });
    let challenge = match normalize_hex(challenge_input) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("invalid challenge: {err}");
            process::exit(1);
        }
    };

    if (cli.adb_serial.is_some() || cli.maps_file.is_some()) && state_json.is_none() {
        eprintln!(
            "--adb-serial/--maps-file currently require --state-json for trap-time registers"
        );
        usage();
        process::exit(1);
    }
    if (cli.maps_file.is_some() || cli.offline_cache) && cli.adb_serial.is_none() {
        eprintln!("--maps-file/--offline-cache require --adb-serial for cache namespace selection");
        usage();
        process::exit(1);
    }
    if cli.offline_cache && cli.maps_file.is_none() {
        eprintln!("--offline-cache requires --maps-file");
        usage();
        process::exit(1);
    }

    let page_cache_dir = if cli.adb_serial.is_some() || cli.maps_file.is_some() {
        Some(
            cli.page_cache_dir
                .clone()
                .unwrap_or_else(default_remote_page_cache_dir),
        )
    } else {
        None
    };

    let proc_memory = match (cli.adb_serial.as_deref(), cli.maps_file.as_deref()) {
        (Some(serial), Some(maps_file)) => ProcMemory::open_cached(
            serial,
            pid,
            maps_file,
            page_cache_dir.clone(),
            cli.offline_cache,
        ),
        (Some(serial), None) => ProcMemory::open_adb(serial, pid, page_cache_dir.clone()),
        (None, Some(_)) => unreachable!("validated above"),
        (None, None) => ProcMemory::open(pid),
    };
    let proc_memory = match proc_memory {
        Ok(memory) => memory,
        Err(err) => {
            eprintln!("failed to open process memory: {err}");
            process::exit(1);
        }
    };

    let live_regs = if cli.adb_serial.is_some() || cli.maps_file.is_some() {
        None
    } else {
        Some(match read_live_regs(tid) {
            Ok(regs) => regs,
            Err(err) => {
                eprintln!("failed to read live registers: {err}");
                process::exit(1);
            }
        })
    };

    let start_pc = cli
        .pc_override
        .or_else(|| state_json.as_ref().and_then(|state| state.pc))
        .or_else(|| {
            live_regs.as_ref().map(|regs| {
                if regs.pc == 0 {
                    DEFAULT_START_PC
                } else {
                    regs.pc
                }
            })
        })
        .unwrap_or(DEFAULT_START_PC);
    let trace_range = cli
        .trace_range
        .or_else(|| derive_code_range(&proc_memory.regions, start_pc));

    let mut registers = live_regs
        .as_ref()
        .map(|regs| registers_from_live_regs(regs, start_pc))
        .unwrap_or_else(BTreeMap::new);
    registers.insert(Reg::PC, Value::U64(start_pc));
    if let Some(state) = &state_json {
        apply_reg_overrides(&mut registers, &state.reg_overrides);
    }
    apply_reg_overrides(&mut registers, &cli.reg_overrides);
    let sysreg_overrides = infer_sysreg_overrides(&proc_memory, &registers, state_json.as_ref());
    let virtual_clock = match VirtualClock::seed_now() {
        Ok(clock) => clock,
        Err(err) => {
            eprintln!("failed to seed virtual clock: {err}");
            process::exit(1);
        }
    };
    let file_roots = if cli.file_roots.is_empty() {
        default_guest_file_roots()
    } else {
        cli.file_roots.clone()
    };

    let setup = LiveReplaySetup {
        pid,
        tid,
        challenge,
        report_out: cli
            .report_out
            .unwrap_or_else(|| std::env::temp_dir().join("aeon_live_cert_eval.json")),
        page_cache_dir,
        sprintf_trace_out: cli.sprintf_trace_out,
        file_roots,
        path_maps: cli.path_maps,
        adb_serial: cli.adb_serial,
        start_pc,
        entry_lr: read_u64_reg(&registers, Reg::X(30))
            .or_else(|| state_json.as_ref().and_then(|state| state.lr)),
        trace_range,
        registers,
        sysreg_overrides,
        memory: proc_memory,
        virtual_clock,
        missing_memory_policy: cli.missing_memory_policy,
        summary_only: cli.summary_only,
        stop_on_token: cli.stop_on_token,
        stop_on_non_concrete: cli.stop_on_non_concrete,
        verbose_trace: cli.verbose_trace,
    };

    let report = match run_replay(setup, cli.max_blocks, cli.max_block_visits) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("replay failed: {err}");
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

    println!("pid:           {}", report.pid);
    println!("tid:           {}", report.tid);
    println!("challenge:     {}", report.challenge);
    println!("start pc:      {}", report.start_pc);
    if let Some(range) = &report.trace_range {
        println!("trace range:   {}..{}", range[0], range[1]);
    }
    println!("blocks:        {}", report.block_count);
    println!("stop:          {}", report.stop_reason);
    println!(
        "summary:       traced_concrete={} traced_symbolic={} untraced={}",
        report.summary.concrete_blocks,
        report.summary.symbolic_blocks,
        report.summary.untraced_blocks
    );
    println!(
        "dependencies:  concrete={} symbolic={}",
        report.summary.concrete_dependencies, report.summary.symbolic_dependencies
    );
    println!(
        "trace flips:   entries={} exits={}",
        report.summary.trace_entries, report.summary.trace_exits
    );
    if let Some(first) = &report.summary.first_symbolic_block {
        println!("first symbolic: {}", first);
    }
    if let Some(token) = &report.best_token {
        println!("token:         {}", token.value);
        println!("token addr:    {}", token.start_addr);
    } else {
        println!("token:         <none>");
    }
    if let Some(value) = &report.return_art_string {
        println!("return string: {}", value.value);
        println!("return addr:   {}", value.object_ptr);
    }
    if let Some(path) = &report.sprintf_trace_path {
        println!("sprintf trace: {}", path.display());
    }
    let fopen_calls = report
        .fopen_trace
        .iter()
        .filter(|record| record.phase == "entry")
        .count();
    println!("fopen calls:   {}", fopen_calls);
    if let Some(path) = &report.page_cache_dir {
        println!("page cache:    {}", path.display());
    }
    println!("report:        {}", report.report_path.display());
}

fn usage() {
    eprintln!("usage:");
    eprintln!(
        "  cargo run -p aeon-instrument --bin live_cert_eval -- [--state-json path] [--adb-serial SERIAL] [--maps-file path] [--offline-cache] [--page-cache-dir path] [--file-root path] [--path-map <guest-prefix> <host-path>] [--pid <pid>] [--challenge <hex>] [--tid <tid>] [--pc <addr>] [--reg <name> <value>] [--max-blocks N] [--max-block-visits N] [--trace-range start end] [--missing-memory stop|symbolic] [--summary-only] [--stop-on-token] [--stop-on-non-concrete] [--verbose-trace] [--report-out path] [--sprintf-trace-out path]"
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestPathMap {
    guest_prefix: String,
    host_prefix: PathBuf,
}

#[derive(Debug, Clone)]
struct Cli {
    state_json: Option<PathBuf>,
    adb_serial: Option<String>,
    maps_file: Option<PathBuf>,
    offline_cache: bool,
    page_cache_dir: Option<PathBuf>,
    file_roots: Vec<PathBuf>,
    path_maps: Vec<GuestPathMap>,
    pid: Option<i32>,
    tid: Option<i32>,
    challenge: Option<String>,
    pc_override: Option<u64>,
    reg_overrides: Vec<(Reg, Value)>,
    max_blocks: u64,
    max_block_visits: u64,
    trace_range: Option<(u64, u64)>,
    missing_memory_policy: MissingMemoryPolicy,
    summary_only: bool,
    stop_on_token: bool,
    stop_on_non_concrete: bool,
    verbose_trace: bool,
    report_out: Option<PathBuf>,
    sprintf_trace_out: Option<PathBuf>,
}

impl Cli {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            return Err("missing arguments".to_string());
        }

        let mut state_json = None;
        let mut adb_serial = None;
        let mut maps_file = None;
        let mut offline_cache = false;
        let mut page_cache_dir = None;
        let mut file_roots = Vec::new();
        let mut path_maps = Vec::new();
        let mut pid = None;
        let mut tid = None;
        let mut challenge = None;
        let mut pc_override = None;
        let mut reg_overrides = Vec::new();
        let mut max_blocks = DEFAULT_MAX_BLOCKS;
        let mut max_block_visits = DEFAULT_MAX_BLOCK_VISITS;
        let mut trace_range = None;
        let mut missing_memory_policy = MissingMemoryPolicy::Stop;
        let mut summary_only = false;
        let mut stop_on_token = false;
        let mut stop_on_non_concrete = false;
        let mut verbose_trace = false;
        let mut report_out = None;
        let mut sprintf_trace_out = None;

        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--state-json" => {
                    state_json = Some(PathBuf::from(
                        args.get(idx + 1)
                            .ok_or_else(|| "--state-json requires a path".to_string())?,
                    ));
                    idx += 2;
                }
                "--adb-serial" => {
                    adb_serial = Some(
                        args.get(idx + 1)
                            .ok_or_else(|| "--adb-serial requires a device serial".to_string())?
                            .clone(),
                    );
                    idx += 2;
                }
                "--maps-file" => {
                    maps_file = Some(PathBuf::from(
                        args.get(idx + 1)
                            .ok_or_else(|| "--maps-file requires a path".to_string())?,
                    ));
                    idx += 2;
                }
                "--offline-cache" => {
                    offline_cache = true;
                    idx += 1;
                }
                "--page-cache-dir" => {
                    page_cache_dir =
                        Some(PathBuf::from(args.get(idx + 1).ok_or_else(|| {
                            "--page-cache-dir requires a path".to_string()
                        })?));
                    idx += 2;
                }
                "--file-root" => {
                    file_roots.push(PathBuf::from(
                        args.get(idx + 1)
                            .ok_or_else(|| "--file-root requires a path".to_string())?,
                    ));
                    idx += 2;
                }
                "--path-map" => {
                    let guest_prefix = args
                        .get(idx + 1)
                        .ok_or_else(|| {
                            "--path-map requires a guest prefix and host path".to_string()
                        })?
                        .clone();
                    let host_prefix = PathBuf::from(args.get(idx + 2).ok_or_else(|| {
                        "--path-map requires a guest prefix and host path".to_string()
                    })?);
                    path_maps.push(GuestPathMap {
                        guest_prefix,
                        host_prefix,
                    });
                    idx += 3;
                }
                "--pid" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or_else(|| "--pid requires a value".to_string())?;
                    pid = Some(
                        value
                            .parse::<i32>()
                            .map_err(|err| format!("invalid --pid '{value}': {err}"))?,
                    );
                    idx += 2;
                }
                "--tid" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or_else(|| "--tid requires a value".to_string())?;
                    tid = Some(
                        value
                            .parse::<i32>()
                            .map_err(|err| format!("invalid --tid '{value}': {err}"))?,
                    );
                    idx += 2;
                }
                "--challenge" => {
                    challenge = Some(
                        args.get(idx + 1)
                            .ok_or_else(|| "--challenge requires a hex string".to_string())?
                            .clone(),
                    );
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
                    let reg = parse_reg(name)?;
                    let val = match &reg {
                        Reg::Q(_) | Reg::V(_) => Value::U128(parse_hex_u128(value)?),
                        Reg::D(_) => Value::U64(parse_u64(value)?),
                        _ => Value::U64(parse_u64(value)?),
                    };
                    reg_overrides.push((reg, val));
                    idx += 3;
                }
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
                "--trace-range" | "--code-range" => {
                    let start = args
                        .get(idx + 1)
                        .ok_or_else(|| "--trace-range requires start and end".to_string())?;
                    let end = args
                        .get(idx + 2)
                        .ok_or_else(|| "--trace-range requires start and end".to_string())?;
                    let start = parse_u64(start)?;
                    let end = parse_u64(end)?;
                    if start >= end {
                        return Err(format!(
                            "invalid trace range 0x{start:x}..0x{end:x}: start must be below end"
                        ));
                    }
                    trace_range = Some((start, end));
                    idx += 3;
                }
                "--missing-memory" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or_else(|| "--missing-memory requires stop or symbolic".to_string())?;
                    missing_memory_policy = parse_missing_memory_policy(value)?;
                    idx += 2;
                }
                "--summary-only" => {
                    summary_only = true;
                    idx += 1;
                }
                "--stop-on-token" => {
                    stop_on_token = true;
                    idx += 1;
                }
                "--stop-on-non-concrete" | "--stop-on-symbolic" => {
                    stop_on_non_concrete = true;
                    idx += 1;
                }
                "--verbose-trace" => {
                    verbose_trace = true;
                    idx += 1;
                }
                "--report-out" => {
                    report_out = Some(PathBuf::from(
                        args.get(idx + 1)
                            .ok_or_else(|| "--report-out requires a path".to_string())?,
                    ));
                    idx += 2;
                }
                "--sprintf-trace-out" => {
                    sprintf_trace_out =
                        Some(PathBuf::from(args.get(idx + 1).ok_or_else(|| {
                            "--sprintf-trace-out requires a path".to_string()
                        })?));
                    idx += 2;
                }
                other => return Err(format!("unknown option '{other}'")),
            }
        }

        Ok(Self {
            state_json,
            adb_serial,
            maps_file,
            offline_cache,
            page_cache_dir,
            file_roots,
            path_maps,
            pid,
            tid,
            challenge,
            pc_override,
            reg_overrides,
            max_blocks,
            max_block_visits,
            trace_range,
            missing_memory_policy,
            summary_only,
            stop_on_token,
            stop_on_non_concrete,
            verbose_trace,
            report_out,
            sprintf_trace_out,
        })
    }
}

#[derive(Debug, Clone)]
struct InputState {
    pid: Option<i32>,
    tid: Option<i32>,
    challenge: Option<String>,
    pc: Option<u64>,
    lr: Option<u64>,
    reg_overrides: Vec<(Reg, Value)>,
    sysreg_overrides: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
struct ProcRegion {
    base: u64,
    end: u64,
    perms: String,
    offset: u64,
    path: String,
}

#[derive(Debug)]
struct ProcMemory {
    source: ProcMemorySource,
    regions: Vec<ProcRegion>,
}

#[derive(Debug)]
enum ProcMemorySource {
    Local(File),
    Remote(RemoteProcMemory),
}

#[derive(Debug)]
struct RemoteProcMemory {
    serial: String,
    pid: i32,
    page_cache: RefCell<BTreeMap<u64, Vec<u8>>>,
    disk_cache_dir: Option<PathBuf>,
    allow_remote_fetch: bool,
}

impl ProcMemory {
    fn open(pid: i32) -> Result<Self, String> {
        let maps_path = format!("/proc/{pid}/maps");
        let mem_path = format!("/proc/{pid}/mem");
        let regions = parse_proc_maps(&maps_path)?;
        let mem = File::open(&mem_path).map_err(|err| format!("open {mem_path}: {err}"))?;
        Ok(Self {
            source: ProcMemorySource::Local(mem),
            regions,
        })
    }

    fn open_adb(
        serial: impl Into<String>,
        pid: i32,
        page_cache_dir: Option<PathBuf>,
    ) -> Result<Self, String> {
        let serial = serial.into();
        let maps = adb_shell_text(&serial, &format!("cat /proc/{pid}/maps"))?;
        let regions = parse_proc_maps_text(&maps, &format!("adb:{serial}:/proc/{pid}/maps"))?;
        Ok(Self {
            source: ProcMemorySource::Remote(RemoteProcMemory {
                serial,
                pid,
                page_cache: RefCell::new(BTreeMap::new()),
                disk_cache_dir: page_cache_dir,
                allow_remote_fetch: true,
            }),
            regions,
        })
    }

    fn open_cached(
        serial: impl Into<String>,
        pid: i32,
        maps_path: &Path,
        page_cache_dir: Option<PathBuf>,
        offline_cache: bool,
    ) -> Result<Self, String> {
        let serial = serial.into();
        let maps = fs::read_to_string(maps_path)
            .map_err(|err| format!("read {}: {err}", maps_path.display()))?;
        let regions =
            parse_proc_maps_text(&maps, &format!("cache:{}:{}", serial, maps_path.display()))?;
        Ok(Self {
            source: ProcMemorySource::Remote(RemoteProcMemory {
                serial,
                pid,
                page_cache: RefCell::new(BTreeMap::new()),
                disk_cache_dir: page_cache_dir,
                allow_remote_fetch: !offline_cache,
            }),
            regions,
        })
    }

    fn find_region_exact(&self, addr: u64) -> Option<&ProcRegion> {
        let idx = self.regions.partition_point(|region| region.base <= addr);
        let region = self.regions.get(idx.checked_sub(1)?)?;
        if addr < region.end {
            Some(region)
        } else {
            None
        }
    }

    fn find_region(&self, addr: u64) -> Option<(u64, &ProcRegion)> {
        for candidate in canonical_address_candidates(addr) {
            if let Some(region) = self.find_region_exact(candidate) {
                return Some((candidate, region));
            }
        }
        None
    }

    fn read_remote(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        let (resolved_addr, region) = self.find_region(addr)?;
        if !region.perms.starts_with('r') {
            if remote_debug_enabled() {
                eprintln!(
                    "[remote] rejecting unreadable region addr=0x{addr:x} resolved=0x{resolved_addr:x} perms={} path={}",
                    region.perms, region.path
                );
            }
            return None;
        }
        let end = resolved_addr.checked_add(size as u64)?;
        if end > region.end {
            if remote_debug_enabled() {
                eprintln!(
                    "[remote] rejecting cross-region read addr=0x{addr:x} resolved=0x{resolved_addr:x} size={size} region=0x{:x}-0x{:x} path={}",
                    region.base, region.end, region.path
                );
            }
            return None;
        }
        match &self.source {
            ProcMemorySource::Local(mem) => {
                let mut buf = vec![0u8; size];
                match mem.read_at(&mut buf, resolved_addr) {
                    Ok(nread) if nread == size => Some(buf),
                    _ => None,
                }
            }
            ProcMemorySource::Remote(remote) => {
                self.read_remote_cached(remote, resolved_addr, size, region)
            }
        }
    }

    fn read_remote_cached(
        &self,
        remote: &RemoteProcMemory,
        addr: u64,
        size: usize,
        region: &ProcRegion,
    ) -> Option<Vec<u8>> {
        if remote_debug_enabled() {
            eprintln!(
                "[remote] read addr=0x{addr:x} size={size} region_end=0x{:x}",
                region.end
            );
        }
        let mut out = Vec::with_capacity(size);
        let mut current = addr;
        while out.len() < size {
            let page_addr = current & !(REMOTE_PAGE_SIZE - 1);
            let page_offset = (current - page_addr) as usize;
            let page_len = (region.end.saturating_sub(page_addr)).min(REMOTE_PAGE_SIZE) as usize;
            if page_len == 0 || page_offset >= page_len {
                if remote_debug_enabled() {
                    eprintln!(
                        "[remote] invalid page slice addr=0x{addr:x} current=0x{current:x} page=0x{page_addr:x} offset={page_offset} len={page_len}"
                    );
                }
                return None;
            }
            let page = self.fetch_remote_page(remote, region, page_addr, page_len)?;
            let remaining = size - out.len();
            let take = remaining.min(page_len - page_offset);
            out.extend_from_slice(&page[page_offset..page_offset + take]);
            current = current.wrapping_add(take as u64);
        }
        Some(out)
    }

    fn fetch_remote_page(
        &self,
        remote: &RemoteProcMemory,
        region: &ProcRegion,
        page_addr: u64,
        page_len: usize,
    ) -> Option<Vec<u8>> {
        if let Some(cached) = remote.page_cache.borrow().get(&page_addr).cloned() {
            if remote_debug_enabled() {
                eprintln!(
                    "[remote] cache hit page=0x{page_addr:x} len={}",
                    cached.len()
                );
            }
            return Some(cached);
        }
        if let Some(cached) = read_disk_cached_page(remote, region, page_addr, page_len) {
            if remote_debug_enabled() {
                eprintln!(
                    "[remote] disk cache hit page=0x{page_addr:x} len={}",
                    cached.len()
                );
            }
            remote
                .page_cache
                .borrow_mut()
                .insert(page_addr, cached.clone());
            return Some(cached);
        }
        if !remote.allow_remote_fetch {
            if remote_debug_enabled() {
                eprintln!("[remote] offline cache miss for page=0x{page_addr:x}");
            }
            return None;
        }
        if remote_debug_enabled() {
            eprintln!(
                "[remote] fetch page=0x{page_addr:x} len={page_len} pid={}",
                remote.pid
            );
        }
        let fetched = adb_shell_binary(
            &remote.serial,
            &format!(
                "dd if=/proc/{pid}/mem bs=1 skip={page_addr} count={page_len} iflag=skip_bytes,count_bytes status=none",
                pid = remote.pid
            ),
        )
        .map_err(|err| {
            if remote_debug_enabled() {
                eprintln!("[remote] adb fetch failed for 0x{page_addr:x}: {err}");
            }
            err
        })
        .ok()?;
        if fetched.len() != page_len {
            if remote_debug_enabled() {
                eprintln!(
                    "[remote] short fetch for page=0x{page_addr:x}: got {} expected {page_len}",
                    fetched.len()
                );
            }
            return None;
        }
        remote
            .page_cache
            .borrow_mut()
            .insert(page_addr, fetched.clone());
        write_disk_cached_page(remote, region, page_addr, page_len, &fetched);
        Some(fetched)
    }

    fn region_summary(&self, location: &MemoryLocation) -> Option<String> {
        let addr = match location {
            MemoryLocation::Unknown => return None,
            MemoryLocation::Absolute(addr) => *addr,
            MemoryLocation::StackSlot(_) => return None,
        };
        let (_, region) = self.find_region(addr)?;
        Some(format!(
            "{} [{}] offset={:#x}",
            region.path, region.perms, region.offset
        ))
    }
}

fn read_disk_cached_page(
    remote: &RemoteProcMemory,
    region: &ProcRegion,
    page_addr: u64,
    page_len: usize,
) -> Option<Vec<u8>> {
    let path = remote_page_cache_path(
        remote.disk_cache_dir.as_deref()?,
        remote,
        region,
        page_addr,
        page_len,
    )?;
    let bytes = fs::read(&path).ok()?;
    if bytes.len() != page_len {
        return None;
    }
    Some(bytes)
}

fn write_disk_cached_page(
    remote: &RemoteProcMemory,
    region: &ProcRegion,
    page_addr: u64,
    page_len: usize,
    bytes: &[u8],
) {
    let Some(cache_root) = remote.disk_cache_dir.as_deref() else {
        return;
    };
    let Some(path) = remote_page_cache_path(cache_root, remote, region, page_addr, page_len) else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    let _ = fs::write(path, bytes);
}

fn remote_page_cache_path(
    cache_root: &Path,
    remote: &RemoteProcMemory,
    region: &ProcRegion,
    page_addr: u64,
    page_len: usize,
) -> Option<PathBuf> {
    let namespace = page_cache_namespace(remote, region)?;
    let page_offset = region
        .offset
        .checked_add(page_addr.checked_sub(region.base)?)?;
    let mut path = cache_root.to_path_buf();
    path.push(sanitize_cache_component(&remote.serial));
    path.push(format!(
        "{:016x}_{}",
        stable_string_hash(&namespace),
        sanitize_cache_component(cache_namespace_label(&namespace, region))
    ));
    path.push(format!("{page_offset:016x}_{page_len:04x}.bin"));
    Some(path)
}

fn page_cache_namespace(remote: &RemoteProcMemory, region: &ProcRegion) -> Option<String> {
    let path = region.path.trim();
    if is_stable_cache_region(path) {
        return Some(format!("stable:{path}"));
    }

    Some(format!(
        "volatile:{}:{}:{:x}:{:x}:{:x}:{}:{}",
        remote.pid, remote.serial, region.base, region.end, region.offset, region.perms, path
    ))
}

fn is_stable_cache_region(path: &str) -> bool {
    if path.is_empty()
        || path.starts_with("/memfd:")
        || path.starts_with("/dev/ashmem/")
        || path == "[heap]"
        || path.starts_with("[stack")
        || path.starts_with("[anon")
    {
        return false;
    }
    true
}

fn cache_namespace_label<'a>(namespace: &'a str, region: &'a ProcRegion) -> &'a str {
    Path::new(namespace)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|label| !label.is_empty())
        .or_else(|| {
            Path::new(region.path.trim())
                .file_name()
                .and_then(|name| name.to_str())
        })
        .unwrap_or(namespace)
}

fn sanitize_cache_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "_".to_string()
    } else {
        out
    }
}

fn stable_string_hash(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0001_0000_01b3);
    }
    hash
}

impl MemoryProvider for ProcMemory {
    fn read(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        self.read_remote(addr, size)
    }
}

impl BackingStore for ProcMemory {
    fn load(&self, addr: u64, size: u8) -> Option<Vec<u8>> {
        self.read_remote(addr, size as usize)
    }
}

#[derive(Debug, Clone, Copy)]
struct VirtualClock {
    realtime_ns: u64,
    monotonic_ns: u64,
    boottime_ns: u64,
}

impl VirtualClock {
    fn seed_now() -> Result<Self, String> {
        let realtime_ns = read_clock_ns(libc::CLOCK_REALTIME)?;
        let monotonic_ns = read_clock_ns(libc::CLOCK_MONOTONIC)?;
        let boottime_ns = read_clock_ns(libc::CLOCK_BOOTTIME).unwrap_or(monotonic_ns);
        Ok(Self {
            realtime_ns,
            monotonic_ns,
            boottime_ns,
        })
    }

    fn timespec_for_clock(&self, clock_id: i32) -> libc::timespec {
        ns_to_timespec(self.clock_ns(clock_id))
    }

    fn clock_ns(&self, clock_id: i32) -> u64 {
        match clock_id as libc::clockid_t {
            libc::CLOCK_REALTIME | libc::CLOCK_REALTIME_COARSE | libc::CLOCK_REALTIME_ALARM => {
                self.realtime_ns
            }
            libc::CLOCK_BOOTTIME | libc::CLOCK_BOOTTIME_ALARM => self.boottime_ns,
            libc::CLOCK_THREAD_CPUTIME_ID | libc::CLOCK_PROCESS_CPUTIME_ID => self.monotonic_ns,
            _ => self.monotonic_ns,
        }
    }

    fn advance_by(&mut self, delta_ns: u64) {
        self.realtime_ns = self.realtime_ns.saturating_add(delta_ns);
        self.monotonic_ns = self.monotonic_ns.saturating_add(delta_ns);
        self.boottime_ns = self.boottime_ns.saturating_add(delta_ns);
    }
}

fn read_clock_ns(clock_id: libc::clockid_t) -> Result<u64, String> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(clock_id, &mut ts) };
    if rc != 0 {
        return Err(format!(
            "clock_gettime({clock_id}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(timespec_to_ns(ts))
}

fn timespec_to_ns(ts: libc::timespec) -> u64 {
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

fn ns_to_timespec(ns: u64) -> libc::timespec {
    libc::timespec {
        tv_sec: (ns / 1_000_000_000) as libc::time_t,
        tv_nsec: (ns % 1_000_000_000) as libc::c_long,
    }
}

fn adb_shell_text(serial: &str, command: &str) -> Result<String, String> {
    let output = Command::new("adb")
        .args(["-s", serial, "exec-out", "su", "0", "sh", "-c", command])
        .output()
        .map_err(|err| format!("spawn adb exec-out: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "adb exec-out failed with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|err| format!("adb exec-out utf8 decode: {err}"))
}

fn remote_debug_enabled() -> bool {
    matches!(
        std::env::var("AEON_REMOTE_DEBUG").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn adb_shell_binary(serial: &str, command: &str) -> Result<Vec<u8>, String> {
    let output = Command::new("adb")
        .args(["-s", serial, "exec-out", "su", "0", "sh", "-c", command])
        .output()
        .map_err(|err| format!("spawn adb exec-out: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "adb exec-out failed with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    Ok(output.stdout)
}

#[derive(Debug, Clone, Copy)]
struct LiveRegs {
    x: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct UserPtRegs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

fn read_live_regs(tid: i32) -> Result<LiveRegs, String> {
    let tid = tid as libc::pid_t;
    let attach_result = unsafe {
        libc::ptrace(
            libc::PTRACE_ATTACH,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if attach_result == -1 {
        return Err(format!(
            "ptrace attach {tid}: {}",
            std::io::Error::last_os_error()
        ));
    }

    let result = (|| {
        let mut status = 0i32;
        let wait_result = unsafe { libc::waitpid(tid, &mut status, 0) };
        if wait_result == -1 {
            return Err(format!(
                "waitpid {tid}: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut regs = UserPtRegs::default();
        let mut iov = libc::iovec {
            iov_base: (&mut regs as *mut UserPtRegs).cast::<libc::c_void>(),
            iov_len: std::mem::size_of::<UserPtRegs>(),
        };
        let ptrace_result = unsafe {
            ptrace_getregset(
                tid,
                NT_PRSTATUS as usize as *mut libc::c_void,
                (&mut iov as *mut libc::iovec).cast::<libc::c_void>(),
            )
        };
        if ptrace_result == -1 {
            return Err(format!(
                "ptrace getregset {tid}: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(LiveRegs {
            x: regs.regs,
            sp: regs.sp,
            pc: regs.pc,
            pstate: regs.pstate,
        })
    })();

    let detach_result = unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            libc::SIGSTOP as usize as *mut libc::c_void,
        )
    };
    if detach_result == -1 {
        eprintln!(
            "warning: ptrace detach {} failed: {}",
            tid,
            std::io::Error::last_os_error()
        );
    }

    result
}

#[cfg(target_os = "android")]
unsafe fn ptrace_getregset(
    tid: libc::pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> libc::c_long {
    libc::ptrace(0x4204 as libc::c_int, tid, addr, data)
}

#[cfg(not(target_os = "android"))]
unsafe fn ptrace_getregset(
    tid: libc::pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> libc::c_long {
    libc::ptrace(0x4204 as libc::c_uint, tid, addr, data)
}

fn registers_from_live_regs(live: &LiveRegs, start_pc: u64) -> BTreeMap<Reg, Value> {
    let mut registers = BTreeMap::new();
    for index in 0..31u8 {
        registers.insert(Reg::X(index), Value::U64(live.x[index as usize]));
    }
    registers.insert(Reg::SP, Value::U64(live.sp));
    registers.insert(Reg::PC, Value::U64(start_pc));
    registers.insert(Reg::Flags, Value::U64(live.pstate));
    registers
}

fn load_state_json(path: &Path) -> Result<InputState, String> {
    let root: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?,
    )
    .map_err(|err| format!("parse {}: {err}", path.display()))?;
    let object = root
        .as_object()
        .ok_or_else(|| format!("{}: top-level json must be an object", path.display()))?;

    let pid = object.get("pid").map(parse_json_i32).transpose()?;
    let tid = object
        .get("thread_id")
        .or_else(|| object.get("tid"))
        .map(parse_json_i32)
        .transpose()?;
    let challenge = object
        .get("challenge")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let pc = object
        .get("pc")
        .or_else(|| object.get("faulting_pc"))
        .map(parse_json_u64)
        .transpose()?;
    let lr = object.get("lr").map(parse_json_u64).transpose()?;

    let mut reg_overrides: Vec<(Reg, Value)> = Vec::new();
    if let Some(registers) = object.get("registers") {
        let registers = registers
            .as_object()
            .ok_or_else(|| format!("{}: 'registers' must be a json object", path.display()))?;
        for (name, value) in registers {
            let lower = name.trim().to_ascii_lowercase();
            if lower == "simd" {
                // handled below
                continue;
            }
            if lower == "nzcv" {
                if let Ok(v) = parse_json_u64(value) {
                    reg_overrides.push((Reg::Flags, Value::U64(v)));
                }
                continue;
            }
            let reg = match parse_json_reg(name) {
                Ok(r) => r,
                Err(_) => continue,
            };
            reg_overrides.push((reg, Value::U64(parse_json_u64(value)?)));
        }
        // Parse SIMD sub-object: {"q0": "hex128", ...}
        if let Some(simd) = registers.get("simd").and_then(|v| v.as_object()) {
            for (name, value) in simd {
                let reg = match parse_json_reg(name) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if let Some(hex) = value.as_str() {
                    if let Ok(v) = parse_simd_hex_u128_le(hex) {
                        reg_overrides.push((reg, Value::U128(v)));
                    }
                }
            }
        }
    }
    if !reg_overrides.iter().any(|(reg, _)| *reg == Reg::X(30)) {
        if let Some(lr) = lr {
            reg_overrides.push((Reg::X(30), Value::U64(lr)));
        }
    }

    let mut sysreg_overrides = BTreeMap::new();
    if let Some(system_registers) = object
        .get("system_registers")
        .or_else(|| object.get("sysregs"))
    {
        let system_registers = system_registers.as_object().ok_or_else(|| {
            format!(
                "{}: 'system_registers' must be a json object",
                path.display()
            )
        })?;
        for (name, value) in system_registers {
            sysreg_overrides.insert(name.trim().to_ascii_lowercase(), parse_json_u64(value)?);
        }
    }

    Ok(InputState {
        pid,
        tid,
        challenge,
        pc,
        lr,
        reg_overrides,
        sysreg_overrides,
    })
}

fn infer_sysreg_overrides(
    memory: &ProcMemory,
    registers: &BTreeMap<Reg, Value>,
    state_json: Option<&InputState>,
) -> BTreeMap<String, u64> {
    let mut overrides = state_json
        .map(|state| state.sysreg_overrides.clone())
        .unwrap_or_default();

    if overrides.contains_key("tpidr_el0") {
        return overrides;
    }

    let mut counts = BTreeMap::<u64, usize>::new();
    for reg in [Reg::X(22), Reg::X(25), Reg::X(28)] {
        if let Some(value) = registers.get(&reg).and_then(value_as_u64) {
            *counts.entry(value).or_insert(0) += 1;
        }
    }

    if let Some((candidate, _)) = counts.into_iter().find(|(_, count)| *count >= 2) {
        if let Some((resolved, region)) = memory.find_region(candidate) {
            if region.perms.starts_with('r') {
                overrides.insert("tpidr_el0".to_string(), resolved);
                return overrides;
            }
        }
    }

    if let Some(candidate) = infer_tpidr_el0_from_tls_region(memory, registers) {
        overrides.insert("tpidr_el0".to_string(), candidate);
    }

    overrides
}

fn infer_tpidr_el0_from_tls_region(
    memory: &ProcMemory,
    registers: &BTreeMap<Reg, Value>,
) -> Option<u64> {
    let sp = read_u64_reg(registers, Reg::SP)?;
    let (_, tls_region) = memory.find_region(sp)?;
    if !tls_region.perms.starts_with('r') || !tls_region.path.contains("[anon:stack_and_tls:") {
        return None;
    }

    let mut candidates = Vec::new();
    for index in 0..=30 {
        let reg = Reg::X(index);
        let Some(value) = read_u64_reg(registers, reg) else {
            continue;
        };
        if value < tls_region.base || value >= tls_region.end {
            continue;
        }
        if value & 0xfff != 0 {
            continue;
        }
        candidates.push(value);
    }
    candidates.sort_unstable();
    candidates.dedup();

    candidates
        .into_iter()
        .filter_map(|candidate| score_tpidr_el0_candidate(memory, tls_region, sp, candidate))
        .max()
        .map(|(_, candidate)| candidate)
}

fn score_tpidr_el0_candidate(
    memory: &ProcMemory,
    tls_region: &ProcRegion,
    sp: u64,
    candidate: u64,
) -> Option<(u64, u64)> {
    let canary = read_backing_u64(memory, candidate.checked_add(0x28)?);
    let has_canary = canary.filter(|value| *value != 0).is_some();
    let next_ptr = read_backing_u64(memory, candidate.checked_add(0x30)?);
    let has_ptr = next_ptr
        .and_then(|value| memory.find_region(value))
        .is_some();

    if !has_canary {
        return None;
    }

    let mut score = 0u64;
    if candidate >= sp {
        score += 1 << 20;
    }
    if has_ptr {
        score += 1 << 16;
    }
    score += tls_region.end.saturating_sub(candidate).min(0xffff);
    Some((score, candidate))
}

fn read_backing_u64(memory: &ProcMemory, addr: u64) -> Option<u64> {
    let bytes = memory.load(addr, 8)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes);
    Some(u64::from_le_bytes(buf))
}

fn parse_proc_maps(path: &str) -> Result<Vec<ProcRegion>, String> {
    let content = fs::read_to_string(path).map_err(|err| format!("read {path}: {err}"))?;
    parse_proc_maps_text(&content, path)
}

fn parse_proc_maps_text(content: &str, source_name: &str) -> Result<Vec<ProcRegion>, String> {
    let mut regions = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        regions.push(
            parse_proc_maps_line(line)
                .map_err(|err| format!("parse {source_name}:{}: {err}: {line}", lineno + 1))?,
        );
    }
    regions.sort_by_key(|region| region.base);
    Ok(regions)
}

fn parse_proc_maps_line(line: &str) -> Result<ProcRegion, String> {
    let mut rest = line.trim();
    let range = take_field(&mut rest).ok_or_else(|| "missing address range".to_string())?;
    let perms = take_field(&mut rest).ok_or_else(|| "missing perms".to_string())?;
    let offset = take_field(&mut rest).ok_or_else(|| "missing offset".to_string())?;
    let _dev = take_field(&mut rest).ok_or_else(|| "missing dev".to_string())?;
    let _inode = take_field(&mut rest).ok_or_else(|| "missing inode".to_string())?;
    let path = rest.trim().to_string();

    let (base, end) = parse_hex_range(range)?;
    Ok(ProcRegion {
        base,
        end,
        perms: perms.to_string(),
        offset: parse_hex_field(offset)?,
        path,
    })
}

fn take_field<'a>(input: &mut &'a str) -> Option<&'a str> {
    *input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    let end = input.find(char::is_whitespace).unwrap_or(input.len());
    let field = &input[..end];
    *input = &input[end..];
    Some(field)
}

fn parse_hex_range(value: &str) -> Result<(u64, u64), String> {
    let mut parts = value.splitn(2, '-');
    let start = parts
        .next()
        .ok_or_else(|| "missing range start".to_string())?;
    let end = parts
        .next()
        .ok_or_else(|| "missing range end".to_string())?;
    Ok((parse_hex_field(start)?, parse_hex_field(end)?))
}

fn parse_hex_field(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.trim(), 16)
        .map_err(|err| format!("invalid hex field '{value}': {err}"))
}

fn default_remote_page_cache_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../capture/manual/page_cache")
}

fn default_guest_file_roots() -> Vec<PathBuf> {
    let bins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bins");
    if bins.is_dir() {
        vec![bins]
    } else {
        Vec::new()
    }
}

#[derive(Debug)]
struct LiveReplaySetup {
    pid: i32,
    tid: i32,
    challenge: String,
    report_out: PathBuf,
    page_cache_dir: Option<PathBuf>,
    sprintf_trace_out: Option<PathBuf>,
    file_roots: Vec<PathBuf>,
    path_maps: Vec<GuestPathMap>,
    adb_serial: Option<String>,
    start_pc: u64,
    entry_lr: Option<u64>,
    trace_range: Option<(u64, u64)>,
    registers: BTreeMap<Reg, Value>,
    sysreg_overrides: BTreeMap<String, u64>,
    memory: ProcMemory,
    virtual_clock: VirtualClock,
    missing_memory_policy: MissingMemoryPolicy,
    summary_only: bool,
    stop_on_token: bool,
    stop_on_non_concrete: bool,
    verbose_trace: bool,
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
    ReturnedToEntryLr(u64),
    MaxBlocks,
    MaxBlockVisits(u64),
    TokenFound(String),
    NonConcrete {
        pc: u64,
        reason: String,
    },
    LiftError(u64, String),
    ExecutionPanic(u64, String),
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
    pid: i32,
    tid: i32,
    challenge: String,
    report_path: PathBuf,
    page_cache_dir: Option<PathBuf>,
    sprintf_trace_path: Option<PathBuf>,
    fopen_trace: Vec<FopenTraceRecord>,
    return_art_string: Option<ArtStringReport>,
    start_pc: String,
    trace_range: Option<[String; 2]>,
    block_count: usize,
    stop_reason: String,
    summary: ReplaySummary,
    dependencies: Vec<DependencyReport>,
    best_token: Option<TokenCandidate>,
    token_candidates: Vec<TokenCandidate>,
    blocks: Vec<BlockReport>,
    final_registers: Vec<RegisterReport>,
}

#[derive(Debug, Serialize)]
struct ReplaySummary {
    concrete_blocks: usize,
    symbolic_blocks: usize,
    untraced_blocks: usize,
    trace_entries: usize,
    trace_exits: usize,
    first_symbolic_block: Option<String>,
    concrete_dependencies: usize,
    symbolic_dependencies: usize,
}

#[derive(Debug)]
struct SprintfTraceSink {
    path: PathBuf,
    file: BufWriter<File>,
    pending: Vec<PendingSprintfTrace>,
    next_id: u64,
}

#[derive(Debug, Clone)]
struct PendingSprintfTrace {
    id: u64,
    function: &'static str,
    entry_pc: u64,
    return_pc: u64,
    dest_ptr: Option<u64>,
    dest_limit: Option<u64>,
    format_ptr: Option<u64>,
    format_preview: Option<String>,
}

#[derive(Debug, Serialize)]
struct SprintfTraceRecord {
    phase: &'static str,
    id: u64,
    function: &'static str,
    entry_pc: String,
    return_pc: String,
    current_pc: Option<String>,
    dest_ptr: Option<String>,
    dest_limit: Option<u64>,
    format_ptr: Option<String>,
    format_preview: Option<String>,
    output_preview: Option<String>,
}

#[derive(Debug, Default)]
struct FopenTraceState {
    records: Vec<FopenTraceRecord>,
    pending: Vec<PendingFopenTrace>,
    next_id: u64,
}

#[derive(Debug, Clone)]
struct PendingFopenTrace {
    id: u64,
    function: &'static str,
    entry_pc: u64,
    return_pc: u64,
    path_ptr: Option<u64>,
    mode_ptr: Option<u64>,
    path_preview: Option<String>,
    mode_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FopenTraceRecord {
    phase: &'static str,
    id: u64,
    function: &'static str,
    entry_pc: String,
    return_pc: String,
    current_pc: Option<String>,
    path_ptr: Option<String>,
    mode_ptr: Option<String>,
    path_preview: Option<String>,
    mode_preview: Option<String>,
    result_ptr: Option<String>,
}

#[derive(Debug)]
struct HostFileBridge {
    roots: Vec<PathBuf>,
    path_maps: Vec<GuestPathMap>,
    adb_serial: Option<String>,
    next_fd: i32,
    next_stream_slot: u64,
    next_asset_slot: u64,
    files: BTreeMap<i32, HostFileEntry>,
    streams: BTreeMap<u64, i32>,
    assets: BTreeMap<u64, i32>,
}

#[derive(Debug)]
struct HostFileEntry {
    host_path: PathBuf,
    source: HostFileSource,
}

#[derive(Debug)]
enum HostFileSource {
    Host(File),
    Buffer(Cursor<Vec<u8>>),
}

impl SprintfTraceSink {
    fn create(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("create sprintf trace dir {}: {err}", parent.display()))?;
        }
        let file = File::create(&path)
            .map_err(|err| format!("create sprintf trace {}: {err}", path.display()))?;
        Ok(Self {
            path,
            file: BufWriter::new(file),
            pending: Vec::new(),
            next_id: 1,
        })
    }

    fn log_entry(&mut self, mut pending: PendingSprintfTrace) -> Result<(), String> {
        if pending.id == 0 {
            pending.id = self.next_id;
            self.next_id += 1;
        }
        self.write_record(&SprintfTraceRecord {
            phase: "entry",
            id: pending.id,
            function: pending.function,
            entry_pc: format_hex(pending.entry_pc),
            return_pc: format_hex(pending.return_pc),
            current_pc: Some(format_hex(pending.entry_pc)),
            dest_ptr: pending.dest_ptr.map(format_hex),
            dest_limit: pending.dest_limit,
            format_ptr: pending.format_ptr.map(format_hex),
            format_preview: pending.format_preview.clone(),
            output_preview: None,
        })?;
        self.pending.push(pending);
        Ok(())
    }

    fn finish_ready(
        &mut self,
        pc: u64,
        memory_overlay: &BTreeMap<MemoryCellId, Value>,
        memory: &ProcMemory,
    ) -> Result<(), String> {
        while self
            .pending
            .last()
            .map(|pending| pending.return_pc == pc)
            .unwrap_or(false)
        {
            let pending = self.pending.pop().expect("pending trace");
            let output_preview = pending
                .dest_ptr
                .map(|dest| {
                    read_c_string_best_effort(
                        memory_overlay,
                        memory,
                        dest,
                        pending
                            .dest_limit
                            .unwrap_or(MAX_TRACE_STRING_BYTES)
                            .min(MAX_TRACE_STRING_BYTES),
                    )
                })
                .transpose()?;
            self.write_record(&SprintfTraceRecord {
                phase: "return",
                id: pending.id,
                function: pending.function,
                entry_pc: format_hex(pending.entry_pc),
                return_pc: format_hex(pending.return_pc),
                current_pc: Some(format_hex(pc)),
                dest_ptr: pending.dest_ptr.map(format_hex),
                dest_limit: pending.dest_limit,
                format_ptr: pending.format_ptr.map(format_hex),
                format_preview: pending.format_preview,
                output_preview,
            })?;
        }
        Ok(())
    }

    fn flush_pending(&mut self) -> Result<(), String> {
        while let Some(pending) = self.pending.pop() {
            self.write_record(&SprintfTraceRecord {
                phase: "unterminated",
                id: pending.id,
                function: pending.function,
                entry_pc: format_hex(pending.entry_pc),
                return_pc: format_hex(pending.return_pc),
                current_pc: None,
                dest_ptr: pending.dest_ptr.map(format_hex),
                dest_limit: pending.dest_limit,
                format_ptr: pending.format_ptr.map(format_hex),
                format_preview: pending.format_preview,
                output_preview: None,
            })?;
        }
        Ok(())
    }

    fn write_record(&mut self, record: &SprintfTraceRecord) -> Result<(), String> {
        serde_json::to_writer(&mut self.file, record)
            .map_err(|err| format!("serialize sprintf trace {}: {err}", self.path.display()))?;
        self.file
            .write_all(b"\n")
            .map_err(|err| format!("write sprintf trace {}: {err}", self.path.display()))?;
        self.file
            .flush()
            .map_err(|err| format!("flush sprintf trace {}: {err}", self.path.display()))
    }
}

impl FopenTraceState {
    fn log_entry(&mut self, mut pending: PendingFopenTrace) {
        if pending.id == 0 {
            pending.id = self.next_id.max(1);
            self.next_id = pending.id + 1;
        }
        self.records.push(FopenTraceRecord {
            phase: "entry",
            id: pending.id,
            function: pending.function,
            entry_pc: format_hex(pending.entry_pc),
            return_pc: format_hex(pending.return_pc),
            current_pc: Some(format_hex(pending.entry_pc)),
            path_ptr: pending.path_ptr.map(format_hex),
            mode_ptr: pending.mode_ptr.map(format_hex),
            path_preview: pending.path_preview.clone(),
            mode_preview: pending.mode_preview.clone(),
            result_ptr: None,
        });
        self.pending.push(pending);
    }

    fn finish_ready(&mut self, pc: u64, registers: &BTreeMap<Reg, Value>) {
        while self
            .pending
            .last()
            .map(|pending| pending.return_pc == pc)
            .unwrap_or(false)
        {
            let pending = self.pending.pop().expect("pending fopen trace");
            self.records.push(FopenTraceRecord {
                phase: "return",
                id: pending.id,
                function: pending.function,
                entry_pc: format_hex(pending.entry_pc),
                return_pc: format_hex(pending.return_pc),
                current_pc: Some(format_hex(pc)),
                path_ptr: pending.path_ptr.map(format_hex),
                mode_ptr: pending.mode_ptr.map(format_hex),
                path_preview: pending.path_preview,
                mode_preview: pending.mode_preview,
                result_ptr: read_u64_reg(registers, Reg::X(0)).map(format_hex),
            });
        }
    }

    fn flush_pending(&mut self) {
        while let Some(pending) = self.pending.pop() {
            self.records.push(FopenTraceRecord {
                phase: "unterminated",
                id: pending.id,
                function: pending.function,
                entry_pc: format_hex(pending.entry_pc),
                return_pc: format_hex(pending.return_pc),
                current_pc: None,
                path_ptr: pending.path_ptr.map(format_hex),
                mode_ptr: pending.mode_ptr.map(format_hex),
                path_preview: pending.path_preview,
                mode_preview: pending.mode_preview,
                result_ptr: None,
            });
        }
    }
}

impl Default for HostFileBridge {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            path_maps: Vec::new(),
            adb_serial: None,
            next_fd: 3,
            next_stream_slot: 1,
            next_asset_slot: 1,
            files: BTreeMap::new(),
            streams: BTreeMap::new(),
            assets: BTreeMap::new(),
        }
    }
}

impl HostFileBridge {
    fn new(roots: Vec<PathBuf>, path_maps: Vec<GuestPathMap>, adb_serial: Option<String>) -> Self {
        Self {
            roots,
            path_maps,
            adb_serial,
            ..Self::default()
        }
    }

    fn fopen(
        &mut self,
        guest_path: &str,
        mode: &str,
        memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    ) -> u64 {
        if !fopen_mode_supported(mode) {
            return 0;
        }
        let Some(fd) = self.open_fd(guest_path, None) else {
            return 0;
        };
        self.alloc_stream(fd, memory_overlay)
    }

    fn fread(
        &mut self,
        stream: u64,
        dest: u64,
        elem_size: u64,
        count: u64,
        memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    ) -> Result<u64, String> {
        if elem_size == 0 || count == 0 {
            return Ok(0);
        }
        let total = elem_size
            .checked_mul(count)
            .ok_or_else(|| "fread size overflow".to_string())?;
        if total > MAX_STUB_BYTES {
            return Err(format!("fread refused oversized length {}", total));
        }
        let Some(fd) = self.streams.get(&stream).copied() else {
            return Ok(0);
        };
        let read_len = self.read_fd_inner(fd, total as usize, dest, memory_overlay)?;
        Ok((read_len as u64) / elem_size)
    }

    fn fclose(&mut self, stream: u64) -> u64 {
        let Some(fd) = self.streams.remove(&stream) else {
            return u64::MAX;
        };
        self.files.remove(&fd);
        0
    }

    fn fseek(&mut self, stream: u64, offset: i64, whence: u32) -> u64 {
        let Some(fd) = self.streams.get(&stream).copied() else {
            return u64::MAX;
        };
        self.seek_fd_result(fd, offset, whence)
            .map_or(u64::MAX, |_| 0)
    }

    fn ftell(&mut self, stream: u64) -> u64 {
        let Some(fd) = self.streams.get(&stream).copied() else {
            return u64::MAX;
        };
        self.tell_fd(fd).unwrap_or(u64::MAX)
    }

    fn access(&self, guest_path: &str, mode: u32) -> u64 {
        let Some(host_path) = self.resolve_host_path(guest_path, None) else {
            return u64::MAX;
        };
        if access_mode_supported(mode) && file_readable(&host_path) {
            0
        } else {
            u64::MAX
        }
    }

    fn open(&mut self, guest_path: &str, flags: u32, dirfd: Option<i32>) -> u64 {
        if !open_flags_supported(flags) {
            return u64::MAX;
        }
        self.open_fd(guest_path, dirfd)
            .map(|fd| fd as u64)
            .unwrap_or(u64::MAX)
    }

    fn asset_open(
        &mut self,
        asset_name: &str,
        memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    ) -> u64 {
        let Some(fd) = self.open_named_asset_fd(asset_name) else {
            return 0;
        };
        let handle = SYNTHETIC_ASSET_HANDLE_BASE.wrapping_add(
            self.next_asset_slot
                .saturating_mul(SYNTHETIC_ASSET_HANDLE_STRIDE),
        );
        self.next_asset_slot += 1;
        self.assets.insert(handle, fd);
        stub_write_bytes(memory_overlay, handle, &[0u8; 0x20]);
        stub_write_bytes(memory_overlay, handle, &(fd as u64).to_le_bytes());
        handle
    }

    fn asset_length(&mut self, handle: u64) -> u64 {
        let Some(fd) = self.assets.get(&handle).copied() else {
            return 0;
        };
        self.file_len(fd).unwrap_or(0)
    }

    fn asset_read(
        &mut self,
        handle: u64,
        dest: u64,
        count: u64,
        memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    ) -> Result<u64, String> {
        if count > MAX_STUB_BYTES {
            return Err(format!("AAsset_read refused oversized length {}", count));
        }
        let Some(fd) = self.assets.get(&handle).copied() else {
            return Ok(0);
        };
        let read_len = self.read_fd_inner(fd, count as usize, dest, memory_overlay)?;
        Ok(read_len as u64)
    }

    fn asset_close(&mut self, handle: u64) -> u64 {
        let Some(fd) = self.assets.remove(&handle) else {
            return 0;
        };
        self.files.remove(&fd);
        0
    }

    fn read(
        &mut self,
        fd: i32,
        dest: u64,
        count: u64,
        memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    ) -> Result<u64, String> {
        if count > MAX_STUB_BYTES {
            return Err(format!("read refused oversized length {}", count));
        }
        let Some(_) = self.files.get(&fd) else {
            return Ok(u64::MAX);
        };
        let read_len = self.read_fd_inner(fd, count as usize, dest, memory_overlay)?;
        Ok(read_len as u64)
    }

    fn close(&mut self, fd: i32) -> u64 {
        if self.files.remove(&fd).is_some() {
            self.streams.retain(|_, mapped_fd| *mapped_fd != fd);
            0
        } else {
            u64::MAX
        }
    }

    fn lseek(&mut self, fd: i32, offset: i64, whence: u32) -> u64 {
        self.seek_fd_result(fd, offset, whence).unwrap_or(u64::MAX)
    }

    fn alloc_virtual_fd(&mut self, label: impl Into<PathBuf>, data: Vec<u8>) -> i32 {
        self.alloc_fd_with_source(label.into(), HostFileSource::Buffer(Cursor::new(data)))
    }

    fn alloc_fd_with_source(&mut self, host_path: PathBuf, source: HostFileSource) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.files.insert(fd, HostFileEntry { host_path, source });
        fd
    }

    fn alloc_stream(&mut self, fd: i32, memory_overlay: &mut BTreeMap<MemoryCellId, Value>) -> u64 {
        let stream = SYNTHETIC_FILE_STREAM_BASE.wrapping_add(
            self.next_stream_slot
                .saturating_mul(SYNTHETIC_FILE_STREAM_STRIDE),
        );
        self.next_stream_slot += 1;
        self.streams.insert(stream, fd);
        stub_write_bytes(memory_overlay, stream, &[0u8; 0x20]);
        stub_write_bytes(memory_overlay, stream, &(fd as u64).to_le_bytes());
        stream
    }

    fn read_fd_inner(
        &mut self,
        fd: i32,
        count: usize,
        dest: u64,
        memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    ) -> Result<usize, String> {
        let Some(entry) = self.files.get_mut(&fd) else {
            return Ok(usize::MAX);
        };
        let mut buf = vec![0u8; count];
        let read_len = match &mut entry.source {
            HostFileSource::Host(file) => file
                .read(&mut buf)
                .map_err(|err| format!("read {}: {err}", entry.host_path.display()))?,
            HostFileSource::Buffer(cursor) => cursor
                .read(&mut buf)
                .map_err(|err| format!("read {}: {err}", entry.host_path.display()))?,
        };
        stub_write_bytes(memory_overlay, dest, &buf[..read_len]);
        Ok(read_len)
    }

    fn seek_fd_result(&mut self, fd: i32, offset: i64, whence: u32) -> Option<u64> {
        let entry = self.files.get_mut(&fd)?;
        let seek_from = match whence as i32 {
            libc::SEEK_SET => SeekFrom::Start(offset.max(0) as u64),
            libc::SEEK_CUR => SeekFrom::Current(offset),
            libc::SEEK_END => SeekFrom::End(offset),
            _ => return None,
        };
        match &mut entry.source {
            HostFileSource::Host(file) => file.seek(seek_from).ok(),
            HostFileSource::Buffer(cursor) => cursor.seek(seek_from).ok(),
        }
    }

    fn tell_fd(&mut self, fd: i32) -> Option<u64> {
        let entry = self.files.get_mut(&fd)?;
        match &mut entry.source {
            HostFileSource::Host(file) => file.stream_position().ok(),
            HostFileSource::Buffer(cursor) => cursor.stream_position().ok(),
        }
    }

    fn file_len(&mut self, fd: i32) -> Option<u64> {
        let entry = self.files.get_mut(&fd)?;
        match &mut entry.source {
            HostFileSource::Host(file) => file.metadata().ok().map(|meta| meta.len()),
            HostFileSource::Buffer(cursor) => Some(cursor.get_ref().len() as u64),
        }
    }

    fn resolve_host_path(&self, guest_path: &str, dirfd: Option<i32>) -> Option<PathBuf> {
        if guest_path.is_empty() {
            return None;
        }

        let mut candidates = Vec::new();
        let guest = Path::new(guest_path);
        if guest.is_absolute() {
            candidates.push(guest.to_path_buf());
        } else if let Some(dirfd) = dirfd {
            if dirfd != libc::AT_FDCWD {
                if let Some(entry) = self.files.get(&dirfd) {
                    if let Some(parent) = entry.host_path.parent() {
                        candidates.push(parent.join(guest));
                    }
                }
            }
            candidates.push(guest.to_path_buf());
        } else {
            candidates.push(guest.to_path_buf());
        }

        for map in &self.path_maps {
            if let Some(suffix) = strip_guest_prefix(guest_path, &map.guest_prefix) {
                candidates.push(join_guest_suffix(&map.host_prefix, suffix));
            }
        }

        for root in &self.roots {
            candidates.push(join_guest_suffix(root, guest_path));
        }

        candidates
            .into_iter()
            .find(|candidate| file_readable(candidate))
    }

    fn resolve_named_asset_path(&self, asset_name: &str) -> Option<PathBuf> {
        if let Some(path) = self.resolve_host_path(asset_name, None) {
            return Some(path);
        }
        let base = Path::new(asset_name).file_name()?.to_str()?;
        for root in &self.roots {
            let exact = root.join(base);
            if file_readable(&exact) {
                return Some(exact);
            }
            let suffix = format!("_{base}");
            let Ok(entries) = fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if name == base || name.ends_with(&suffix) {
                    return Some(path);
                }
            }
        }
        None
    }

    fn open_named_asset_fd(&mut self, asset_name: &str) -> Option<i32> {
        let host_path = self.resolve_named_asset_path(asset_name)?;
        let file = File::open(&host_path).ok()?;
        Some(self.alloc_fd_with_source(host_path, HostFileSource::Host(file)))
    }

    fn open_fd(&mut self, guest_path: &str, dirfd: Option<i32>) -> Option<i32> {
        if let Some(host_path) = self.resolve_host_path(guest_path, dirfd) {
            let file = File::open(&host_path).ok()?;
            return Some(self.alloc_fd_with_source(host_path, HostFileSource::Host(file)));
        }
        if Path::new(guest_path).is_absolute() {
            if let Some(serial) = &self.adb_serial {
                let bytes =
                    adb_shell_binary(serial, &format!("cat {}", shell_single_quote(guest_path)))
                        .ok()?;
                return Some(self.alloc_virtual_fd(PathBuf::from(guest_path), bytes));
            }
        }
        None
    }
}

impl SymbolResolver {
    fn describe_addr(&mut self, memory: &ProcMemory, addr: u64) -> String {
        let Some((resolved, region)) = memory.find_region(addr) else {
            return format!("{} <unmapped>", format_hex(addr));
        };
        let file_offset = resolved
            .checked_sub(region.base)
            .and_then(|delta| region.offset.checked_add(delta))
            .unwrap_or(0);
        let mut description = format!(
            "{} {}+0x{:x}",
            format_hex(resolved),
            region.path,
            file_offset
        );
        if let Some(symbol) = self.resolve_symbol(&region.path, file_offset) {
            description.push(' ');
            description.push_str(&symbol);
        }
        description
    }

    fn resolve_symbol(&mut self, region_path: &str, file_offset: u64) -> Option<String> {
        let key = (region_path.to_string(), file_offset);
        if let Some(cached) = self.symbol_cache.get(&key) {
            return cached.clone();
        }

        let local_file = self.local_symbol_file(region_path);
        let resolved = local_file
            .as_ref()
            .and_then(|path| symbolize_file_offset(path, file_offset));
        self.symbol_cache.insert(key, resolved.clone());
        resolved
    }

    fn local_symbol_file(&mut self, region_path: &str) -> Option<PathBuf> {
        if let Some(cached) = self.local_file_cache.get(region_path) {
            return cached.clone();
        }

        let resolved = resolve_local_symbol_file(region_path);
        self.local_file_cache
            .insert(region_path.to_string(), resolved.clone());
        resolved
    }
}

#[derive(Debug, Clone, Copy)]
struct StubOutcome {
    next_pc: u64,
}

#[derive(Debug, Clone, Serialize)]
struct TokenCandidate {
    start_addr: String,
    end_addr: String,
    value: String,
    len: usize,
}

#[derive(Debug, Serialize)]
struct DependencyReport {
    location: String,
    size: u8,
    first_block: String,
    region: Option<String>,
    use_count: usize,
    concrete_reads: usize,
    symbolic_reads: usize,
    sources: Vec<String>,
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

#[derive(Debug, Default)]
struct IgnoredNonConcreteEffects {
    reads: BTreeSet<MemoryCellId>,
    writes: BTreeSet<MemoryCellId>,
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

#[derive(Debug, Clone, Serialize)]
struct ArtStringReport {
    object_ptr: String,
    value_ptr: String,
    length: usize,
    compressed: bool,
    value: String,
}

#[derive(Debug, Default)]
struct SymbolResolver {
    symbol_cache: BTreeMap<(String, u64), Option<String>>,
    local_file_cache: BTreeMap<String, Option<PathBuf>>,
}

fn run_replay(
    setup: LiveReplaySetup,
    max_blocks: u64,
    max_block_visits: u64,
) -> Result<ReplayReport, String> {
    let LiveReplaySetup {
        pid,
        tid,
        challenge,
        report_out,
        page_cache_dir,
        sprintf_trace_out,
        file_roots,
        path_maps,
        adb_serial,
        start_pc,
        entry_lr,
        trace_range,
        registers: initial_registers,
        sysreg_overrides,
        memory,
        virtual_clock,
        missing_memory_policy,
        summary_only,
        stop_on_token,
        stop_on_non_concrete,
        verbose_trace,
    } = setup;
    let mut sprintf_trace = sprintf_trace_out
        .map(SprintfTraceSink::create)
        .transpose()?;
    let mut fopen_trace = FopenTraceState::default();
    let mut file_bridge = HostFileBridge::new(file_roots, path_maps, adb_serial);
    let mut symbol_resolver = verbose_trace.then(SymbolResolver::default);
    let mut registers = initial_registers;
    let mut memory_overlay = BTreeMap::<MemoryCellId, Value>::new();
    let mut lifted_blocks = BTreeMap::<u64, LiftedBlock>::new();
    let mut visits = BTreeMap::<u64, u64>::new();
    let mut pc = start_pc;
    let mut virtual_clock = virtual_clock;
    let mut blocks = Vec::new();
    let mut dependency_by_key = BTreeMap::<(String, u8), DependencyReport>::new();
    let mut dependency_sources = BTreeMap::<(String, u8), BTreeMap<String, ()>>::new();
    let mut block_count = 0usize;
    let mut concrete_blocks = 0usize;
    let mut symbolic_blocks = 0usize;
    let mut untraced_blocks = 0usize;
    let mut trace_entries = 0usize;
    let mut trace_exits = 0usize;
    let mut first_symbolic_block = None::<String>;
    let mut tracing_was_active = false;
    let mut ignored_symbolic_memory = BTreeSet::<MemoryCellId>::new();
    let stop_reason;

    loop {
        if let Some(trace) = sprintf_trace.as_mut() {
            trace.finish_ready(pc, &memory_overlay, &memory)?;
        }
        fopen_trace.finish_ready(pc, &registers);

        if stop_on_non_concrete {
            if let Some(reason) = first_symbolic_input_source_filtered(
                &registers,
                &memory_overlay,
                &ignored_symbolic_memory,
            ) {
                stop_reason = ReplayStop::NonConcrete { pc, reason };
                break;
            }
        }

        if block_count > 0 && entry_lr == Some(pc) {
            stop_reason = ReplayStop::ReturnedToEntryLr(pc);
            break;
        }

        let tracing_active = is_in_range(pc, trace_range);
        if tracing_active && !tracing_was_active {
            trace_entries += 1;
            if verbose_trace {
                verbose_trace_line(&format!("[trace-entry] {}", format_hex(pc)))?;
            }
        } else if !tracing_active && tracing_was_active {
            trace_exits += 1;
        }
        tracing_was_active = tracing_active;

        if block_count as u64 >= max_blocks {
            stop_reason = ReplayStop::MaxBlocks;
            break;
        }

        let visit_count = visits.entry(pc).or_insert(0);
        if *visit_count >= max_block_visits {
            stop_reason = ReplayStop::MaxBlockVisits(pc);
            break;
        }
        *visit_count += 1;

        let stub = match maybe_execute_known_stub_with_io(
            pc,
            &mut registers,
            &mut memory_overlay,
            &memory,
            &mut virtual_clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        ) {
            Ok(stub) => stub,
            Err(err) if stop_on_non_concrete && is_non_concrete_stub_error(&err) => {
                stop_reason = ReplayStop::NonConcrete { pc, reason: err };
                break;
            }
            Err(err) => return Err(err),
        };
        if let Some(stub) = stub {
            let next_pc = normalize_control_flow_addr(stub.next_pc, &memory, trace_range)
                .unwrap_or(stub.next_pc);
            block_count += 1;
            if tracing_active {
                concrete_blocks += 1;
                if verbose_trace {
                    verbose_trace_line(&format!(
                        "[trace-stub] pc={} next={}",
                        format_hex(pc),
                        format_hex(next_pc)
                    ))?;
                }
            } else {
                untraced_blocks += 1;
            }
            if tracing_active && !is_in_range(next_pc, trace_range) {
                trace_exits += usize::from(tracing_was_active);
                tracing_was_active = false;
                if let Some(resolver) = symbol_resolver.as_mut() {
                    verbose_trace_line(&format!(
                        "[trace-exit] {} -> {}",
                        format_hex(pc),
                        resolver.describe_addr(&memory, next_pc)
                    ))?;
                } else {
                    verbose_trace_line(&format!(
                        "[trace-exit] {} -> {}",
                        format_hex(pc),
                        format_hex(next_pc)
                    ))?;
                }
            }
            registers.insert(Reg::PC, Value::U64(next_pc));
            pc = next_pc;
            continue;
        }

        if !lifted_blocks.contains_key(&pc) {
            let block = match lift_block(pc, &memory, &sysreg_overrides) {
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
        let filter_context =
            stop_on_non_concrete.then(|| (initial_registers.clone(), initial_memory.clone()));
        let incoming_symbolic_source = if stop_on_non_concrete {
            first_symbolic_input_source_filtered(
                &initial_registers,
                &initial_memory,
                &ignored_symbolic_memory,
            )
        } else {
            first_symbolic_input_source(&initial_registers, &initial_memory)
        };
        let result = match catch_unwind(AssertUnwindSafe(|| {
            execute_block(
                &block.stmts,
                initial_registers,
                initial_memory,
                &memory,
                missing_memory_policy,
                BLOCK_STEP_BUDGET,
            )
        })) {
            Ok(result) => result,
            Err(payload) => {
                stop_reason = ReplayStop::ExecutionPanic(block.addr, panic_payload_string(payload));
                break;
            }
        };

        let mut next_pc = result.next_pc;
        if matches!(
            block.terminator,
            BlockTerminator::DynamicBranch | BlockTerminator::DynamicCall | BlockTerminator::Return
        ) {
            if let Some(candidate) = next_pc {
                if let Some(normalized) =
                    normalize_control_flow_addr(candidate, &memory, trace_range)
                {
                    next_pc = Some(normalized);
                }
            }
        }

        let changed_registers = diff_registers(&previous_registers, &result.final_registers);
        let ignored_effects = filter_context
            .as_ref()
            .map(|(registers, memory_overlay)| {
                collect_nonsemantic_simd_preserve_effects(
                    &block,
                    registers,
                    memory_overlay,
                    &memory,
                )
            })
            .transpose()?
            .unwrap_or_default();
        let filtered_non_concrete_reason = if stop_on_non_concrete {
            first_non_concrete_block_reason_filtered(
                &result,
                &changed_registers,
                incoming_symbolic_source.clone(),
                &ignored_symbolic_memory,
                &ignored_effects,
            )
        } else {
            None
        };
        block_count += 1;

        if tracing_active && verbose_trace {
            let summary = trace_register_summary(&changed_registers, &result.final_registers);
            verbose_trace_line(&format!(
                "[trace-block] pc={} stop={} next={} {}",
                format_hex(block.addr),
                format_block_stop(&result.stop),
                next_pc
                    .map(format_hex)
                    .unwrap_or_else(|| "<none>".to_string()),
                summary
            ))?;
        }

        if tracing_active {
            let block_report = block_report(
                &block,
                &result,
                &memory,
                changed_registers,
                incoming_symbolic_source,
            );

            if block_report.symbolic {
                symbolic_blocks += 1;
                if first_symbolic_block.is_none() {
                    first_symbolic_block = Some(block_report.addr.clone());
                }
            } else {
                concrete_blocks += 1;
            }

            accumulate_dependency_reports_for_block(
                &block_report,
                &mut dependency_by_key,
                &mut dependency_sources,
            );
            if !summary_only {
                blocks.push(block_report);
            }
        } else {
            untraced_blocks += 1;
        }

        if stop_on_non_concrete {
            for write in &result.writes {
                if !ignored_effects.writes.contains(&write.id) {
                    ignored_symbolic_memory.remove(&write.id);
                }
            }
            ignored_symbolic_memory.extend(ignored_effects.writes.iter().cloned());
        }
        registers = result.final_registers;
        memory_overlay = result.final_memory;

        if stop_on_non_concrete {
            if let Some(reason) = filtered_non_concrete_reason {
                stop_reason = ReplayStop::NonConcrete {
                    pc: block.addr,
                    reason,
                };
                break;
            }
        }

        if stop_on_token {
            if let Some(token) = pick_stop_token_candidate(&memory_overlay) {
                stop_reason = ReplayStop::TokenFound(token.value);
                break;
            }
        }

        match result.stop {
            BlockStop::Completed => match next_pc {
                Some(0) => {
                    stop_reason = ReplayStop::Halted;
                    break;
                }
                Some(next_pc) => {
                    if tracing_active && !is_in_range(next_pc, trace_range) {
                        trace_exits += usize::from(tracing_was_active);
                        tracing_was_active = false;
                        if verbose_trace {
                            if let Some(resolver) = symbol_resolver.as_mut() {
                                verbose_trace_line(&format!(
                                    "[trace-exit] {} -> {}",
                                    format_hex(block.addr),
                                    resolver.describe_addr(&memory, next_pc)
                                ))?;
                            } else {
                                verbose_trace_line(&format!(
                                    "[trace-exit] {} -> {}",
                                    format_hex(block.addr),
                                    format_hex(next_pc)
                                ))?;
                            }
                        }
                    }
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

    if !summary_only {
        annotate_block_symbolic_summary(&mut blocks);
    }
    if let Some(trace) = sprintf_trace.as_mut() {
        trace.flush_pending()?;
    }
    fopen_trace.flush_pending();
    let final_registers = register_reports(&registers);
    let return_art_string = read_u64_reg(&registers, Reg::X(0)).and_then(|ptr| {
        decode_art_string_report(&memory_overlay, &memory, ptr)
            .ok()
            .flatten()
    });
    let dependencies = finalize_dependency_reports(dependency_by_key, dependency_sources);
    let mut token_candidates = extract_token_candidates(&memory_overlay);
    if let Some(candidate) = art_string_token_candidate(return_art_string.as_ref()) {
        token_candidates.push(candidate);
    }
    let best_token = pick_best_token(&token_candidates);

    Ok(ReplayReport {
        pid,
        tid,
        challenge,
        report_path: report_out,
        page_cache_dir,
        sprintf_trace_path: sprintf_trace.as_ref().map(|trace| trace.path.clone()),
        fopen_trace: fopen_trace.records,
        return_art_string,
        start_pc: format_hex(start_pc),
        trace_range: trace_range.map(|(start, end)| [format_hex(start), format_hex(end)]),
        block_count,
        stop_reason: format_stop_reason(&stop_reason),
        summary: ReplaySummary {
            concrete_blocks,
            symbolic_blocks,
            untraced_blocks,
            trace_entries,
            trace_exits,
            first_symbolic_block,
            concrete_dependencies: dependencies
                .iter()
                .filter(|dependency| dependency.symbolic_reads == 0)
                .count(),
            symbolic_dependencies: dependencies
                .iter()
                .filter(|dependency| dependency.symbolic_reads > 0)
                .count(),
        },
        dependencies,
        best_token,
        token_candidates,
        blocks,
        final_registers,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn maybe_execute_known_stub(
    pc: u64,
    registers: &mut BTreeMap<Reg, Value>,
    memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    virtual_clock: &mut VirtualClock,
    sprintf_trace: &mut Option<SprintfTraceSink>,
) -> Result<Option<StubOutcome>, String> {
    let mut fopen_trace = FopenTraceState::default();
    let mut file_bridge = HostFileBridge::default();
    maybe_execute_known_stub_with_io(
        pc,
        registers,
        memory_overlay,
        memory,
        virtual_clock,
        sprintf_trace,
        &mut fopen_trace,
        &mut file_bridge,
    )
}

fn maybe_execute_known_stub_with_io(
    pc: u64,
    registers: &mut BTreeMap<Reg, Value>,
    memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    virtual_clock: &mut VirtualClock,
    sprintf_trace: &mut Option<SprintfTraceSink>,
    fopen_trace: &mut FopenTraceState,
    file_bridge: &mut HostFileBridge,
) -> Result<Option<StubOutcome>, String> {
    let Some((resolved_pc, region)) = memory.find_region(pc) else {
        return Ok(None);
    };
    let file_offset = resolved_pc
        .checked_sub(region.base)
        .and_then(|delta| region.offset.checked_add(delta))
        .ok_or_else(|| format!("failed to compute file offset for {}", format_hex(pc)))?;

    if region.path.ends_with("/libc.so") {
        if let Some(trace) = sprintf_trace.as_mut() {
            if let Some(call) =
                capture_sprintf_trace(file_offset, pc, registers, memory_overlay, memory)?
            {
                trace.log_entry(call)?;
            }
        }
        if let Some(call) = capture_fopen_trace(file_offset, pc, registers, memory_overlay, memory)?
        {
            fopen_trace.log_entry(call);
        }

        if file_offset == LIBC_ACCESS_OFFSET {
            let path_ptr = require_u64_reg(registers, Reg::X(0), "access", pc, "x0")?;
            let mode = require_u64_reg(registers, Reg::X(1), "access", pc, "x1")? as u32;
            let next_pc = require_u64_reg(registers, Reg::X(30), "access", pc, "x30")?;
            let path = read_c_string_best_effort(
                memory_overlay,
                memory,
                path_ptr,
                MAX_TRACE_STRING_BYTES,
            )?;
            write_u64_reg(registers, 0, file_bridge.access(&path, mode));
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_OPEN_OFFSET {
            let path_ptr = require_u64_reg(registers, Reg::X(0), "open", pc, "x0")?;
            let flags = require_u64_reg(registers, Reg::X(1), "open", pc, "x1")? as u32;
            let next_pc = require_u64_reg(registers, Reg::X(30), "open", pc, "x30")?;
            let path = read_c_string_best_effort(
                memory_overlay,
                memory,
                path_ptr,
                MAX_TRACE_STRING_BYTES,
            )?;
            write_u64_reg(registers, 0, file_bridge.open(&path, flags, None));
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_OPENAT_OFFSET {
            let dirfd = require_u64_reg(registers, Reg::X(0), "openat", pc, "x0")? as i32;
            let path_ptr = require_u64_reg(registers, Reg::X(1), "openat", pc, "x1")?;
            let flags = require_u64_reg(registers, Reg::X(2), "openat", pc, "x2")? as u32;
            let next_pc = require_u64_reg(registers, Reg::X(30), "openat", pc, "x30")?;
            let path = read_c_string_best_effort(
                memory_overlay,
                memory,
                path_ptr,
                MAX_TRACE_STRING_BYTES,
            )?;
            write_u64_reg(registers, 0, file_bridge.open(&path, flags, Some(dirfd)));
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_READ_OFFSET {
            let fd = require_u64_reg(registers, Reg::X(0), "read", pc, "x0")? as i32;
            let dest = require_u64_reg(registers, Reg::X(1), "read", pc, "x1")?;
            let count = require_u64_reg(registers, Reg::X(2), "read", pc, "x2")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "read", pc, "x30")?;
            let result = file_bridge.read(fd, dest, count, memory_overlay)?;
            write_u64_reg(registers, 0, result);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_CLOSE_OFFSET {
            let fd = require_u64_reg(registers, Reg::X(0), "close", pc, "x0")? as i32;
            let next_pc = require_u64_reg(registers, Reg::X(30), "close", pc, "x30")?;
            write_u64_reg(registers, 0, file_bridge.close(fd));
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_LSEEK_OFFSET {
            let fd = require_u64_reg(registers, Reg::X(0), "lseek", pc, "x0")? as i32;
            let offset = signed_u64(require_u64_reg(registers, Reg::X(1), "lseek", pc, "x1")?);
            let whence = require_u64_reg(registers, Reg::X(2), "lseek", pc, "x2")? as u32;
            let next_pc = require_u64_reg(registers, Reg::X(30), "lseek", pc, "x30")?;
            write_u64_reg(registers, 0, file_bridge.lseek(fd, offset, whence));
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_FOPEN_OFFSET {
            let path_ptr = require_u64_reg(registers, Reg::X(0), "fopen", pc, "x0")?;
            let mode_ptr = require_u64_reg(registers, Reg::X(1), "fopen", pc, "x1")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "fopen", pc, "x30")?;
            let path = read_c_string_best_effort(
                memory_overlay,
                memory,
                path_ptr,
                MAX_TRACE_STRING_BYTES,
            )?;
            let mode = read_c_string_best_effort(
                memory_overlay,
                memory,
                mode_ptr,
                MAX_TRACE_STRING_BYTES,
            )?;
            write_u64_reg(
                registers,
                0,
                file_bridge.fopen(&path, &mode, memory_overlay),
            );
            return Ok(Some(StubOutcome { next_pc }));
        }

        if matches!(file_offset, LIBC_FREAD_OFFSET | LIBC_FREAD_UNLOCKED_OFFSET) {
            let dest = require_u64_reg(registers, Reg::X(0), "fread", pc, "x0")?;
            let elem_size = require_u64_reg(registers, Reg::X(1), "fread", pc, "x1")?;
            let count = require_u64_reg(registers, Reg::X(2), "fread", pc, "x2")?;
            let stream = require_u64_reg(registers, Reg::X(3), "fread", pc, "x3")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "fread", pc, "x30")?;
            let result = file_bridge.fread(stream, dest, elem_size, count, memory_overlay)?;
            write_u64_reg(registers, 0, result);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_FCLOSE_OFFSET {
            let stream = require_u64_reg(registers, Reg::X(0), "fclose", pc, "x0")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "fclose", pc, "x30")?;
            write_u64_reg(registers, 0, file_bridge.fclose(stream));
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_FSEEK_OFFSET {
            let stream = require_u64_reg(registers, Reg::X(0), "fseek", pc, "x0")?;
            let offset = signed_u64(require_u64_reg(registers, Reg::X(1), "fseek", pc, "x1")?);
            let whence = require_u64_reg(registers, Reg::X(2), "fseek", pc, "x2")? as u32;
            let next_pc = require_u64_reg(registers, Reg::X(30), "fseek", pc, "x30")?;
            write_u64_reg(registers, 0, file_bridge.fseek(stream, offset, whence));
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_FTELL_OFFSET {
            let stream = require_u64_reg(registers, Reg::X(0), "ftell", pc, "x0")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "ftell", pc, "x30")?;
            write_u64_reg(registers, 0, file_bridge.ftell(stream));
            return Ok(Some(StubOutcome { next_pc }));
        }

        if (LIBC_SCUDO_HYBRID_MUTEX_LOCK_SLOW_START..LIBC_SCUDO_HYBRID_MUTEX_LOCK_SLOW_END)
            .contains(&file_offset)
        {
            let next_pc = require_u64_reg(
                registers,
                Reg::X(30),
                "scudo::HybridMutex::lockSlow",
                pc,
                "x30",
            )?;
            return Ok(Some(StubOutcome { next_pc }));
        }

        if (LIBC_SCUDO_HYBRID_MUTEX_UNLOCK_START..LIBC_SCUDO_HYBRID_MUTEX_UNLOCK_END)
            .contains(&file_offset)
        {
            let next_pc = require_u64_reg(
                registers,
                Reg::X(30),
                "scudo::HybridMutex::unlock",
                pc,
                "x30",
            )?;
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_CLOCK_GETTIME_OFFSET {
            let clock_id = require_u64_reg(registers, Reg::X(0), "clock_gettime", pc, "x0")?;
            let timespec_ptr = require_u64_reg(registers, Reg::X(1), "clock_gettime", pc, "x1")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "clock_gettime", pc, "x30")?;
            stub_clock_gettime(memory_overlay, virtual_clock, clock_id as i32, timespec_ptr);
            write_u64_reg(registers, 0, 0);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_GETTIMEOFDAY_OFFSET {
            let timeval_ptr = require_u64_reg(registers, Reg::X(0), "gettimeofday", pc, "x0")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "gettimeofday", pc, "x30")?;
            stub_gettimeofday(memory_overlay, virtual_clock, timeval_ptr);
            write_u64_reg(registers, 0, 0);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_CLOCK_NANOSLEEP_OFFSET {
            let clock_id =
                require_u64_reg(registers, Reg::X(0), "clock_nanosleep", pc, "x0")? as i32;
            let flags = require_u64_reg(registers, Reg::X(1), "clock_nanosleep", pc, "x1")?;
            let req_ptr = require_u64_reg(registers, Reg::X(2), "clock_nanosleep", pc, "x2")?;
            let rem_ptr = require_u64_reg(registers, Reg::X(3), "clock_nanosleep", pc, "x3")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "clock_nanosleep", pc, "x30")?;
            stub_clock_nanosleep(
                memory_overlay,
                memory,
                virtual_clock,
                clock_id,
                flags as i32,
                req_ptr,
                rem_ptr,
                pc,
            )?;
            write_u64_reg(registers, 0, 0);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_NANOSLEEP_OFFSET {
            let req_ptr = require_u64_reg(registers, Reg::X(0), "nanosleep", pc, "x0")?;
            let rem_ptr = require_u64_reg(registers, Reg::X(1), "nanosleep", pc, "x1")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "nanosleep", pc, "x30")?;
            stub_clock_nanosleep(
                memory_overlay,
                memory,
                virtual_clock,
                libc::CLOCK_REALTIME,
                0,
                req_ptr,
                rem_ptr,
                pc,
            )?;
            write_u64_reg(registers, 0, 0);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_SLEEP_OFFSET {
            let seconds = require_u64_reg(registers, Reg::X(0), "sleep", pc, "x0")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "sleep", pc, "x30")?;
            virtual_clock.advance_by(seconds.saturating_mul(1_000_000_000));
            write_u64_reg(registers, 0, 0);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_USLEEP_OFFSET {
            let micros = require_u64_reg(registers, Reg::X(0), "usleep", pc, "x0")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "usleep", pc, "x30")?;
            virtual_clock.advance_by(micros.saturating_mul(1_000));
            write_u64_reg(registers, 0, 0);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if matches!(
            file_offset,
            LIBC_MEMCPY_OFFSET | LIBC_MEMCPY_INTERNAL_OFFSET
        ) {
            let dest = require_u64_reg(registers, Reg::X(0), "memcpy", pc, "x0")?;
            let src = require_u64_reg(registers, Reg::X(1), "memcpy", pc, "x1")?;
            let len = require_u64_reg(registers, Reg::X(2), "memcpy", pc, "x2")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "memcpy", pc, "x30")?;
            let bytes = stub_read_bytes(memory_overlay, memory, src, len, "memcpy", pc)?;
            stub_write_bytes(memory_overlay, dest, &bytes);
            write_u64_reg(registers, 0, dest);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBC_MEMSET_OFFSET {
            let dest = require_u64_reg(registers, Reg::X(0), "memset", pc, "x0")?;
            let fill = require_u64_reg(registers, Reg::X(1), "memset", pc, "x1")?;
            let len = require_u64_reg(registers, Reg::X(2), "memset", pc, "x2")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "memset", pc, "x30")?;
            if len > MAX_STUB_BYTES {
                return Err(format!(
                    "memset stub at {} refused oversized length {}",
                    format_hex(pc),
                    len
                ));
            }
            let bytes = vec![(fill & 0xff) as u8; len as usize];
            stub_write_bytes(memory_overlay, dest, &bytes);
            write_u64_reg(registers, 0, dest);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if matches!(file_offset, LIBC_STRLEN_MTE_OFFSET | LIBC_STRLEN_OFFSET) {
            let ptr = require_u64_reg(registers, Reg::X(0), "strlen", pc, "x0")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "strlen", pc, "x30")?;
            let len = stub_strlen(memory_overlay, memory, ptr, "strlen", pc)?;
            write_u64_reg(registers, 0, len);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if matches!(file_offset, LIBC_STRCHR_MTE_OFFSET | LIBC_STRCHR_OFFSET) {
            let ptr = require_u64_reg(registers, Reg::X(0), "strchr", pc, "x0")?;
            let needle = require_u64_reg(registers, Reg::X(1), "strchr", pc, "x1")? as u8;
            let next_pc = require_u64_reg(registers, Reg::X(30), "strchr", pc, "x30")?;
            let result = stub_strchr(memory_overlay, memory, ptr, needle, "strchr", pc)?;
            write_u64_reg(registers, 0, result);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if matches!(file_offset, LIBC_STRCMP_MTE_OFFSET | LIBC_STRCMP_OFFSET) {
            let lhs = require_u64_reg(registers, Reg::X(0), "strcmp", pc, "x0")?;
            let rhs = require_u64_reg(registers, Reg::X(1), "strcmp", pc, "x1")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "strcmp", pc, "x30")?;
            let result = stub_strcmp(memory_overlay, memory, lhs, rhs, "strcmp", pc)?;
            write_u64_reg(registers, 0, (result as u32) as u64);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if matches!(file_offset, LIBC_STRNCMP_MTE_OFFSET | LIBC_STRNCMP_OFFSET) {
            let lhs = require_u64_reg(registers, Reg::X(0), "strncmp", pc, "x0")?;
            let rhs = require_u64_reg(registers, Reg::X(1), "strncmp", pc, "x1")?;
            let len = require_u64_reg(registers, Reg::X(2), "strncmp", pc, "x2")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "strncmp", pc, "x30")?;
            let result = stub_strncmp(memory_overlay, memory, lhs, rhs, len, "strncmp", pc)?;
            write_u64_reg(registers, 0, (result as u32) as u64);
            return Ok(Some(StubOutcome { next_pc }));
        }
    }

    if region.path.ends_with("/libandroid.so") {
        if file_offset == LIBANDROID_AASSET_MANAGER_OPEN_OFFSET {
            let name_ptr = require_u64_reg(registers, Reg::X(1), "AAssetManager_open", pc, "x1")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "AAssetManager_open", pc, "x30")?;
            let asset_name = read_c_string_best_effort(
                memory_overlay,
                memory,
                name_ptr,
                MAX_TRACE_STRING_BYTES,
            )?;
            let handle = file_bridge.asset_open(&asset_name, memory_overlay);
            write_u64_reg(registers, 0, handle);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBANDROID_AASSET_READ_OFFSET {
            let handle = require_u64_reg(registers, Reg::X(0), "AAsset_read", pc, "x0")?;
            let dest = require_u64_reg(registers, Reg::X(1), "AAsset_read", pc, "x1")?;
            let count = require_u64_reg(registers, Reg::X(2), "AAsset_read", pc, "x2")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "AAsset_read", pc, "x30")?;
            let result = file_bridge.asset_read(handle, dest, count, memory_overlay)?;
            write_u64_reg(registers, 0, result);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if file_offset == LIBANDROID_AASSET_CLOSE_OFFSET {
            let handle = require_u64_reg(registers, Reg::X(0), "AAsset_close", pc, "x0")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "AAsset_close", pc, "x30")?;
            write_u64_reg(registers, 0, file_bridge.asset_close(handle));
            return Ok(Some(StubOutcome { next_pc }));
        }

        if matches!(
            file_offset,
            LIBANDROID_AASSET_GET_LENGTH_OFFSET | LIBANDROID_AASSET_GET_LENGTH64_OFFSET
        ) {
            let handle = require_u64_reg(registers, Reg::X(0), "AAsset_getLength", pc, "x0")?;
            let next_pc = require_u64_reg(registers, Reg::X(30), "AAsset_getLength", pc, "x30")?;
            write_u64_reg(registers, 0, file_bridge.asset_length(handle));
            return Ok(Some(StubOutcome { next_pc }));
        }
    }

    if region.path == "[vdso]" {
        if (VDSO_CLOCK_GETTIME_OFFSET..VDSO_GETTIMEOFDAY_OFFSET).contains(&file_offset) {
            let clock_id =
                require_u64_reg(registers, Reg::X(0), "__kernel_clock_gettime", pc, "x0")?;
            let timespec_ptr =
                require_u64_reg(registers, Reg::X(1), "__kernel_clock_gettime", pc, "x1")?;
            let next_pc =
                require_u64_reg(registers, Reg::X(30), "__kernel_clock_gettime", pc, "x30")?;
            stub_clock_gettime(memory_overlay, virtual_clock, clock_id as i32, timespec_ptr);
            write_u64_reg(registers, 0, 0);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if (VDSO_GETTIMEOFDAY_OFFSET..VDSO_CLOCK_GETRES_OFFSET).contains(&file_offset) {
            let timeval_ptr =
                require_u64_reg(registers, Reg::X(0), "__kernel_gettimeofday", pc, "x0")?;
            let next_pc =
                require_u64_reg(registers, Reg::X(30), "__kernel_gettimeofday", pc, "x30")?;
            stub_gettimeofday(memory_overlay, virtual_clock, timeval_ptr);
            write_u64_reg(registers, 0, 0);
            return Ok(Some(StubOutcome { next_pc }));
        }

        if (VDSO_CLOCK_GETRES_OFFSET..VDSO_RT_SIGRETURN_OFFSET).contains(&file_offset) {
            let timespec_ptr =
                require_u64_reg(registers, Reg::X(1), "__kernel_clock_getres", pc, "x1")?;
            let next_pc =
                require_u64_reg(registers, Reg::X(30), "__kernel_clock_getres", pc, "x30")?;
            if timespec_ptr != 0 {
                stub_write_timespec(memory_overlay, timespec_ptr, ns_to_timespec(1));
            }
            write_u64_reg(registers, 0, 0);
            return Ok(Some(StubOutcome { next_pc }));
        }
    }

    Ok(None)
}

fn capture_sprintf_trace(
    file_offset: u64,
    pc: u64,
    registers: &BTreeMap<Reg, Value>,
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
) -> Result<Option<PendingSprintfTrace>, String> {
    let Some((function, dest_ptr, dest_limit, format_ptr)) =
        sprintf_trace_args(file_offset, registers)
    else {
        return Ok(None);
    };
    let Some(return_pc) = read_u64_reg(registers, Reg::X(30)) else {
        return Ok(None);
    };
    let format_preview = format_ptr
        .map(|ptr| read_c_string_best_effort(memory_overlay, memory, ptr, MAX_TRACE_STRING_BYTES))
        .transpose()?;

    Ok(Some(PendingSprintfTrace {
        id: 0,
        function,
        entry_pc: pc,
        return_pc,
        dest_ptr,
        dest_limit,
        format_ptr,
        format_preview,
    }))
}

fn capture_fopen_trace(
    file_offset: u64,
    pc: u64,
    registers: &BTreeMap<Reg, Value>,
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
) -> Result<Option<PendingFopenTrace>, String> {
    if file_offset != LIBC_FOPEN_OFFSET {
        return Ok(None);
    }
    let Some(return_pc) = read_u64_reg(registers, Reg::X(30)) else {
        return Ok(None);
    };
    let path_ptr = read_u64_reg(registers, Reg::X(0));
    let mode_ptr = read_u64_reg(registers, Reg::X(1));
    let path_preview = path_ptr
        .map(|ptr| read_c_string_best_effort(memory_overlay, memory, ptr, MAX_TRACE_STRING_BYTES))
        .transpose()?;
    let mode_preview = mode_ptr
        .map(|ptr| read_c_string_best_effort(memory_overlay, memory, ptr, MAX_TRACE_STRING_BYTES))
        .transpose()?;

    Ok(Some(PendingFopenTrace {
        id: 0,
        function: "fopen",
        entry_pc: pc,
        return_pc,
        path_ptr,
        mode_ptr,
        path_preview,
        mode_preview,
    }))
}

fn sprintf_trace_args(
    file_offset: u64,
    registers: &BTreeMap<Reg, Value>,
) -> Option<(&'static str, Option<u64>, Option<u64>, Option<u64>)> {
    match file_offset {
        LIBC_SPRINTF_OFFSET | LIBC_VSPRINTF_OFFSET => Some((
            if file_offset == LIBC_SPRINTF_OFFSET {
                "sprintf"
            } else {
                "vsprintf"
            },
            read_u64_reg(registers, Reg::X(0)),
            Some(MAX_TRACE_STRING_BYTES),
            read_u64_reg(registers, Reg::X(1)),
        )),
        LIBC_SNPRINTF_OFFSET | LIBC_VSNPRINTF_OFFSET => Some((
            if file_offset == LIBC_SNPRINTF_OFFSET {
                "snprintf"
            } else {
                "vsnprintf"
            },
            read_u64_reg(registers, Reg::X(0)),
            read_u64_reg(registers, Reg::X(1)),
            read_u64_reg(registers, Reg::X(2)),
        )),
        LIBC_SPRINTF_CHK_OFFSET | LIBC_VSPRINTF_CHK_OFFSET => Some((
            if file_offset == LIBC_SPRINTF_CHK_OFFSET {
                "__sprintf_chk"
            } else {
                "__vsprintf_chk"
            },
            read_u64_reg(registers, Reg::X(0)),
            read_u64_reg(registers, Reg::X(2)),
            read_u64_reg(registers, Reg::X(3)),
        )),
        LIBC_SNPRINTF_CHK_OFFSET | LIBC_VSNPRINTF_CHK_OFFSET => Some((
            if file_offset == LIBC_SNPRINTF_CHK_OFFSET {
                "__snprintf_chk"
            } else {
                "__vsnprintf_chk"
            },
            read_u64_reg(registers, Reg::X(0)),
            read_u64_reg(registers, Reg::X(1)),
            read_u64_reg(registers, Reg::X(4)),
        )),
        LIBC_ASPRINTF_OFFSET | LIBC_VASPRINTF_OFFSET => Some((
            if file_offset == LIBC_ASPRINTF_OFFSET {
                "asprintf"
            } else {
                "vasprintf"
            },
            None,
            None,
            read_u64_reg(registers, Reg::X(1)),
        )),
        _ => None,
    }
}

fn read_c_string_best_effort(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    ptr: u64,
    max_len: u64,
) -> Result<String, String> {
    let mut bytes = Vec::new();
    for offset in 0..max_len {
        let byte = stub_read_u8(memory_overlay, memory, ptr.wrapping_add(offset), "trace", 0)?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn shell_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn strip_guest_prefix<'a>(guest_path: &'a str, guest_prefix: &str) -> Option<&'a str> {
    let suffix = guest_path.strip_prefix(guest_prefix)?;
    if suffix.is_empty() || suffix.starts_with('/') {
        Some(suffix)
    } else {
        None
    }
}

fn join_guest_suffix(root: &Path, guest_suffix: &str) -> PathBuf {
    let suffix = guest_suffix.trim_start_matches('/');
    if suffix.is_empty() {
        root.to_path_buf()
    } else {
        root.join(suffix)
    }
}

fn file_readable(path: &Path) -> bool {
    path.is_file() && File::open(path).is_ok()
}

fn access_mode_supported(mode: u32) -> bool {
    let supported = libc::F_OK as u32 | libc::R_OK as u32;
    mode & !supported == 0
}

fn open_flags_supported(flags: u32) -> bool {
    let write_bits =
        libc::O_WRONLY as u32 | libc::O_RDWR as u32 | libc::O_CREAT as u32 | libc::O_TRUNC as u32;
    flags & write_bits == 0
}

fn fopen_mode_supported(mode: &str) -> bool {
    let mode = mode.trim();
    if mode.is_empty() {
        return false;
    }
    let first = mode.as_bytes()[0];
    first == b'r' && !mode.contains('w') && !mode.contains('a')
}

fn signed_u64(bits: u64) -> i64 {
    i64::from_ne_bytes(bits.to_ne_bytes())
}

fn stub_clock_gettime(
    memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    virtual_clock: &VirtualClock,
    clock_id: i32,
    timespec_ptr: u64,
) {
    if timespec_ptr == 0 {
        return;
    }
    let ts = virtual_clock.timespec_for_clock(clock_id);
    stub_write_timespec(memory_overlay, timespec_ptr, ts);
}

fn stub_gettimeofday(
    memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    virtual_clock: &VirtualClock,
    timeval_ptr: u64,
) {
    if timeval_ptr == 0 {
        return;
    }
    let ts = ns_to_timespec(virtual_clock.realtime_ns);
    stub_write_timeval(memory_overlay, timeval_ptr, ts.tv_sec, ts.tv_nsec / 1_000);
}

fn stub_clock_nanosleep(
    memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    virtual_clock: &mut VirtualClock,
    clock_id: i32,
    flags: i32,
    req_ptr: u64,
    rem_ptr: u64,
    pc: u64,
) -> Result<(), String> {
    let req = stub_read_timespec(memory_overlay, memory, req_ptr, "nanosleep", pc)?;
    let requested_ns = timespec_to_ns(req);
    let delta_ns = if flags & libc::TIMER_ABSTIME != 0 {
        requested_ns.saturating_sub(virtual_clock.clock_ns(clock_id))
    } else {
        requested_ns
    };
    virtual_clock.advance_by(delta_ns);
    if rem_ptr != 0 {
        stub_write_timespec(
            memory_overlay,
            rem_ptr,
            libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        );
    }
    Ok(())
}

fn stub_read_timespec(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    ptr: u64,
    stub_name: &str,
    pc: u64,
) -> Result<libc::timespec, String> {
    if ptr == 0 {
        return Err(format!(
            "{} stub at {} received null timespec pointer",
            stub_name,
            format_hex(pc)
        ));
    }
    let bytes = stub_read_bytes(memory_overlay, memory, ptr, 16, stub_name, pc)?;
    let sec = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    Ok(libc::timespec {
        tv_sec: sec as libc::time_t,
        tv_nsec: nsec as libc::c_long,
    })
}

fn stub_write_timespec(
    memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    ptr: u64,
    ts: libc::timespec,
) {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&(ts.tv_sec as i64).to_le_bytes());
    bytes[8..16].copy_from_slice(&(ts.tv_nsec as i64).to_le_bytes());
    stub_write_bytes(memory_overlay, ptr, &bytes);
}

fn stub_write_timeval(
    memory_overlay: &mut BTreeMap<MemoryCellId, Value>,
    ptr: u64,
    sec: libc::time_t,
    usec: libc::suseconds_t,
) {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&(sec as i64).to_le_bytes());
    bytes[8..16].copy_from_slice(&(usec as i64).to_le_bytes());
    stub_write_bytes(memory_overlay, ptr, &bytes);
}

fn require_u64_reg(
    registers: &BTreeMap<Reg, Value>,
    reg: Reg,
    stub_name: &str,
    pc: u64,
    reg_name: &str,
) -> Result<u64, String> {
    read_u64_reg(registers, reg).ok_or_else(|| {
        format!(
            "{} stub at {} missing concrete {}",
            stub_name,
            format_hex(pc),
            reg_name
        )
    })
}

fn stub_read_bytes(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    addr: u64,
    len: u64,
    stub_name: &str,
    pc: u64,
) -> Result<Vec<u8>, String> {
    if len > MAX_STUB_BYTES {
        return Err(format!(
            "{} stub at {} refused oversized length {}",
            stub_name,
            format_hex(pc),
            len
        ));
    }
    (0..len)
        .map(|offset| {
            stub_read_u8(
                memory_overlay,
                memory,
                addr.wrapping_add(offset),
                stub_name,
                pc,
            )
        })
        .collect()
}

fn stub_write_bytes(memory_overlay: &mut BTreeMap<MemoryCellId, Value>, addr: u64, bytes: &[u8]) {
    for (offset, byte) in bytes.iter().enumerate() {
        memory_overlay.insert(
            MemoryCellId {
                location: MemoryLocation::Absolute(addr.wrapping_add(offset as u64)),
                size: 1,
            },
            Value::U64(*byte as u64),
        );
    }
}

fn stub_read_u8(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    addr: u64,
    stub_name: &str,
    pc: u64,
) -> Result<u8, String> {
    for candidate in canonical_address_candidates(addr) {
        if let Some(Value::U64(bits)) = memory_overlay.get(&MemoryCellId {
            location: MemoryLocation::Absolute(candidate),
            size: 1,
        }) {
            return Ok(*bits as u8);
        }
    }
    match memory.load(addr, 1) {
        Some(bytes) if !bytes.is_empty() => Ok(bytes[0]),
        _ => Err(format!(
            "{} stub at {} could not read byte from {}",
            stub_name,
            format_hex(pc),
            format_hex(addr)
        )),
    }
}

fn stub_strlen(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    ptr: u64,
    stub_name: &str,
    pc: u64,
) -> Result<u64, String> {
    for offset in 0..MAX_STUB_BYTES {
        if stub_read_u8(
            memory_overlay,
            memory,
            ptr.wrapping_add(offset),
            stub_name,
            pc,
        )? == 0
        {
            return Ok(offset);
        }
    }
    Err(format!(
        "{} stub at {} exceeded max scan {} bytes",
        stub_name,
        format_hex(pc),
        MAX_STUB_BYTES
    ))
}

fn stub_strchr(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    ptr: u64,
    needle: u8,
    stub_name: &str,
    pc: u64,
) -> Result<u64, String> {
    for offset in 0..MAX_STUB_BYTES {
        let byte = stub_read_u8(
            memory_overlay,
            memory,
            ptr.wrapping_add(offset),
            stub_name,
            pc,
        )?;
        if byte == needle {
            return Ok(ptr.wrapping_add(offset));
        }
        if byte == 0 {
            return Ok(if needle == 0 {
                ptr.wrapping_add(offset)
            } else {
                0
            });
        }
    }
    Err(format!(
        "{} stub at {} exceeded max scan {} bytes",
        stub_name,
        format_hex(pc),
        MAX_STUB_BYTES
    ))
}

fn stub_strcmp(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    lhs: u64,
    rhs: u64,
    stub_name: &str,
    pc: u64,
) -> Result<i32, String> {
    stub_strcmp_impl(memory_overlay, memory, lhs, rhs, None, stub_name, pc)
}

fn stub_strncmp(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    lhs: u64,
    rhs: u64,
    len: u64,
    stub_name: &str,
    pc: u64,
) -> Result<i32, String> {
    if len > MAX_STUB_BYTES {
        return Err(format!(
            "{} stub at {} refused oversized length {}",
            stub_name,
            format_hex(pc),
            len
        ));
    }
    stub_strcmp_impl(memory_overlay, memory, lhs, rhs, Some(len), stub_name, pc)
}

fn stub_strcmp_impl(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    lhs: u64,
    rhs: u64,
    len_limit: Option<u64>,
    stub_name: &str,
    pc: u64,
) -> Result<i32, String> {
    let limit = len_limit.unwrap_or(MAX_STUB_BYTES);
    for offset in 0..limit {
        let lhs_byte = stub_read_u8(
            memory_overlay,
            memory,
            lhs.wrapping_add(offset),
            stub_name,
            pc,
        )?;
        let rhs_byte = stub_read_u8(
            memory_overlay,
            memory,
            rhs.wrapping_add(offset),
            stub_name,
            pc,
        )?;
        if lhs_byte != rhs_byte || lhs_byte == 0 || rhs_byte == 0 {
            return Ok(lhs_byte as i32 - rhs_byte as i32);
        }
    }
    Ok(0)
}

fn pick_stop_token_candidate(memory: &BTreeMap<MemoryCellId, Value>) -> Option<TokenCandidate> {
    let candidate = pick_best_token(&extract_token_candidates(memory))?;
    if candidate.value.len() == 48 && candidate.value.bytes().all(is_hex_ascii) {
        Some(candidate)
    } else {
        None
    }
}

fn canonical_address_candidates(addr: u64) -> [u64; 3] {
    [
        addr,
        addr & 0x00ff_ffff_ffff_ffff,
        addr & 0x0000_ffff_ffff_ffff,
    ]
}

fn derive_code_range(regions: &[ProcRegion], pc: u64) -> Option<(u64, u64)> {
    let idx = regions
        .iter()
        .position(|region| region.base <= pc && pc < region.end)?;
    let path = &regions[idx].path;

    let mut start = regions[idx].base;
    let mut end = regions[idx].end;

    let mut left = idx;
    while left > 0 && regions[left - 1].path == *path && regions[left - 1].end == start {
        left -= 1;
        start = regions[left].base;
    }

    let mut right = idx;
    while right + 1 < regions.len()
        && regions[right + 1].path == *path
        && regions[right + 1].base == end
    {
        right += 1;
        end = regions[right].end;
    }

    Some((start, end))
}

fn lift_block(
    addr: u64,
    memory: &dyn MemoryProvider,
    sysreg_overrides: &BTreeMap<String, u64>,
) -> Result<LiftedBlock, String> {
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
        stmts.push(rewrite_stmt_sysregs(result.stmt, sysreg_overrides));
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

fn rewrite_stmt_sysregs(stmt: Stmt, sysreg_overrides: &BTreeMap<String, u64>) -> Stmt {
    match stmt {
        Stmt::Assign { dst, src } => Stmt::Assign {
            dst,
            src: rewrite_expr_sysregs(src, sysreg_overrides),
        },
        Stmt::Store { addr, value, size } => Stmt::Store {
            addr: rewrite_expr_sysregs(addr, sysreg_overrides),
            value: rewrite_expr_sysregs(value, sysreg_overrides),
            size,
        },
        Stmt::Branch { target } => Stmt::Branch {
            target: rewrite_expr_sysregs(target, sysreg_overrides),
        },
        Stmt::CondBranch {
            cond,
            target,
            fallthrough,
        } => Stmt::CondBranch {
            cond: rewrite_branch_cond_sysregs(cond, sysreg_overrides),
            target: rewrite_expr_sysregs(target, sysreg_overrides),
            fallthrough,
        },
        Stmt::Call { target } => Stmt::Call {
            target: rewrite_expr_sysregs(target, sysreg_overrides),
        },
        Stmt::Pair(lhs, rhs) => Stmt::Pair(
            Box::new(rewrite_stmt_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_stmt_sysregs(*rhs, sysreg_overrides)),
        ),
        Stmt::SetFlags { expr } => Stmt::SetFlags {
            expr: rewrite_expr_sysregs(expr, sysreg_overrides),
        },
        Stmt::Intrinsic { name, operands } => Stmt::Intrinsic {
            name,
            operands: operands
                .into_iter()
                .map(|operand| rewrite_expr_sysregs(operand, sysreg_overrides))
                .collect(),
        },
        other => other,
    }
}

fn rewrite_branch_cond_sysregs(
    cond: aeonil::BranchCond,
    sysreg_overrides: &BTreeMap<String, u64>,
) -> aeonil::BranchCond {
    use aeonil::BranchCond;
    match cond {
        BranchCond::Flag(_) => cond,
        BranchCond::Zero(expr) => BranchCond::Zero(rewrite_expr_sysregs(expr, sysreg_overrides)),
        BranchCond::NotZero(expr) => {
            BranchCond::NotZero(rewrite_expr_sysregs(expr, sysreg_overrides))
        }
        BranchCond::BitZero(expr, bit) => {
            BranchCond::BitZero(rewrite_expr_sysregs(expr, sysreg_overrides), bit)
        }
        BranchCond::BitNotZero(expr, bit) => {
            BranchCond::BitNotZero(rewrite_expr_sysregs(expr, sysreg_overrides), bit)
        }
        BranchCond::Compare { cond, lhs, rhs } => BranchCond::Compare {
            cond,
            lhs: Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            rhs: Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        },
    }
}

fn rewrite_expr_sysregs(expr: Expr, sysreg_overrides: &BTreeMap<String, u64>) -> Expr {
    match expr {
        Expr::MrsRead(name) => sysreg_overrides
            .get(&name.to_ascii_lowercase())
            .copied()
            .map(Expr::Imm)
            .unwrap_or(Expr::MrsRead(name)),
        Expr::Load { addr, size } => Expr::Load {
            addr: Box::new(rewrite_expr_sysregs(*addr, sysreg_overrides)),
            size,
        },
        Expr::Add(lhs, rhs) => Expr::Add(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Sub(lhs, rhs) => Expr::Sub(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Mul(lhs, rhs) => Expr::Mul(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Div(lhs, rhs) => Expr::Div(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::UDiv(lhs, rhs) => Expr::UDiv(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Neg(inner) => Expr::Neg(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::Abs(inner) => Expr::Abs(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::And(lhs, rhs) => Expr::And(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Or(lhs, rhs) => Expr::Or(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Xor(lhs, rhs) => Expr::Xor(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Not(inner) => Expr::Not(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::Shl(lhs, rhs) => Expr::Shl(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Lsr(lhs, rhs) => Expr::Lsr(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Asr(lhs, rhs) => Expr::Asr(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::Ror(lhs, rhs) => Expr::Ror(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::SignExtend { src, from_bits } => Expr::SignExtend {
            src: Box::new(rewrite_expr_sysregs(*src, sysreg_overrides)),
            from_bits,
        },
        Expr::ZeroExtend { src, from_bits } => Expr::ZeroExtend {
            src: Box::new(rewrite_expr_sysregs(*src, sysreg_overrides)),
            from_bits,
        },
        Expr::Extract { src, lsb, width } => Expr::Extract {
            src: Box::new(rewrite_expr_sysregs(*src, sysreg_overrides)),
            lsb,
            width,
        },
        Expr::Insert {
            dst,
            src,
            lsb,
            width,
        } => Expr::Insert {
            dst: Box::new(rewrite_expr_sysregs(*dst, sysreg_overrides)),
            src: Box::new(rewrite_expr_sysregs(*src, sysreg_overrides)),
            lsb,
            width,
        },
        Expr::FAdd(lhs, rhs) => Expr::FAdd(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::FSub(lhs, rhs) => Expr::FSub(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::FMul(lhs, rhs) => Expr::FMul(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::FDiv(lhs, rhs) => Expr::FDiv(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::FNeg(inner) => Expr::FNeg(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::FAbs(inner) => Expr::FAbs(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::FSqrt(inner) => Expr::FSqrt(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::FMax(lhs, rhs) => Expr::FMax(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::FMin(lhs, rhs) => Expr::FMin(
            Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        ),
        Expr::FCvt(inner) => Expr::FCvt(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::IntToFloat(inner) => {
            Expr::IntToFloat(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides)))
        }
        Expr::FloatToInt(inner) => {
            Expr::FloatToInt(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides)))
        }
        Expr::CondSelect {
            cond,
            if_true,
            if_false,
        } => Expr::CondSelect {
            cond,
            if_true: Box::new(rewrite_expr_sysregs(*if_true, sysreg_overrides)),
            if_false: Box::new(rewrite_expr_sysregs(*if_false, sysreg_overrides)),
        },
        Expr::Compare { cond, lhs, rhs } => Expr::Compare {
            cond,
            lhs: Box::new(rewrite_expr_sysregs(*lhs, sysreg_overrides)),
            rhs: Box::new(rewrite_expr_sysregs(*rhs, sysreg_overrides)),
        },
        Expr::Clz(inner) => Expr::Clz(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::Cls(inner) => Expr::Cls(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::Rev(inner) => Expr::Rev(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::Rbit(inner) => Expr::Rbit(Box::new(rewrite_expr_sysregs(*inner, sysreg_overrides))),
        Expr::Intrinsic { name, operands } => Expr::Intrinsic {
            name,
            operands: operands
                .into_iter()
                .map(|operand| rewrite_expr_sysregs(operand, sysreg_overrides))
                .collect(),
        },
        other => other,
    }
}

fn transform_calls_and_rets(stmts: Vec<Stmt>, return_addr: u64) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(stmts.len() + 1);
    for stmt in stmts {
        match stmt {
            Stmt::Call { target } => {
                let target = match target {
                    Expr::Reg(Reg::X(30)) => {
                        out.push(Stmt::Assign {
                            dst: Reg::X(17),
                            src: Expr::Reg(Reg::X(30)),
                        });
                        Expr::Reg(Reg::X(17))
                    }
                    other => other,
                };
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
                out.extend(transform_calls_and_rets(vec![*lhs, *rhs], return_addr));
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn transform_call_via_x30_preserves_old_target() {
        let stmts = transform_calls_and_rets(
            vec![Stmt::Call {
                target: Expr::Reg(Reg::X(30)),
            }],
            0x1234,
        );
        assert_eq!(
            stmts,
            vec![
                Stmt::Assign {
                    dst: Reg::X(17),
                    src: Expr::Reg(Reg::X(30)),
                },
                Stmt::Assign {
                    dst: Reg::X(30),
                    src: Expr::Imm(0x1234),
                },
                Stmt::Branch {
                    target: Expr::Reg(Reg::X(17)),
                },
            ]
        );
    }
}

fn is_terminator(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Branch { .. }
        | Stmt::CondBranch { .. }
        | Stmt::Call { .. }
        | Stmt::Ret
        | Stmt::Trap { .. } => true,
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
        Stmt::Trap { .. } => Some(BlockTerminator::Trap),
        Stmt::Pair(lhs, rhs) => classify_terminator(rhs).or_else(|| classify_terminator(lhs)),
        _ => None,
    }
}

fn block_report(
    block: &LiftedBlock,
    result: &BlockExecutionResult,
    proc_memory: &ProcMemory,
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
            .map(|read| read_report(read, proc_memory))
            .collect(),
        writes: result.writes.iter().map(write_report).collect(),
        changed_registers,
    }
}

fn first_non_concrete_block_reason_filtered(
    result: &BlockExecutionResult,
    changed_registers: &[RegisterReport],
    incoming_symbolic_source: Option<String>,
    ignored_input_memory: &BTreeSet<MemoryCellId>,
    ignored_effects: &IgnoredNonConcreteEffects,
) -> Option<String> {
    if incoming_symbolic_source.is_some() {
        return incoming_symbolic_source;
    }

    if let Some(read) = result.reads.iter().find(|read| {
        !is_concrete(&read.value)
            && !ignored_input_memory.contains(&read.id)
            && !ignored_effects.reads.contains(&read.id)
    }) {
        return Some(first_symbolic_read_source(read));
    }

    if let Some(write) = result
        .writes
        .iter()
        .find(|write| !is_concrete(&write.value) && !ignored_effects.writes.contains(&write.id))
    {
        return Some(first_symbolic_write_source(write));
    }

    if let Some(reg) = changed_registers.iter().find(|reg| !reg.concrete) {
        return Some(format!("register {} became symbolic", reg.reg));
    }

    match &result.stop {
        BlockStop::SymbolicBranch => Some("symbolic branch condition".to_string()),
        BlockStop::MissingMemory { location, .. } => {
            let ignored_missing = result.reads.iter().any(|read| {
                !is_concrete(&read.value)
                    && ignored_effects.reads.contains(&read.id)
                    && read.id.location == *location
            });
            if ignored_missing {
                None
            } else {
                Some(format!("missing read {}", format_location(location)))
            }
        }
        _ => None,
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

fn first_symbolic_input_source_filtered(
    registers: &BTreeMap<Reg, Value>,
    memory: &BTreeMap<MemoryCellId, Value>,
    ignored_memory: &BTreeSet<MemoryCellId>,
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
        if !is_concrete(value) && !ignored_memory.contains(id) {
            return Some(format!(
                "incoming memory {} was symbolic",
                format_location(&id.location)
            ));
        }
    }

    None
}

fn collect_nonsemantic_simd_preserve_effects(
    block: &LiftedBlock,
    initial_registers: &BTreeMap<Reg, Value>,
    initial_memory: &BTreeMap<MemoryCellId, Value>,
    backing: &dyn BackingStore,
) -> Result<IgnoredNonConcreteEffects, String> {
    let mut registers = initial_registers.clone();
    let mut memory = initial_memory.clone();
    let mut flat = Vec::new();
    flatten_stmts(&block.stmts, &mut flat);
    let mut effects = IgnoredNonConcreteEffects::default();

    for stmt in flat {
        let ignore_stmt = is_nonsemantic_simd_preserve_stmt(&stmt);
        let result = execute_block(
            std::slice::from_ref(&stmt),
            registers,
            memory,
            backing,
            MissingMemoryPolicy::ContinueAsUnknown,
            16,
        );
        if !matches!(result.stop, BlockStop::Completed) {
            return Err(format!(
                "failed to inspect preserve stmt in {}: {}",
                format_hex(block.addr),
                format_block_stop(&result.stop)
            ));
        }
        if ignore_stmt {
            effects.reads.extend(
                result
                    .reads
                    .iter()
                    .filter(|read| !is_concrete(&read.value))
                    .map(|read| read.id.clone()),
            );
            effects.writes.extend(
                result
                    .writes
                    .iter()
                    .filter(|write| !is_concrete(&write.value))
                    .map(|write| write.id.clone()),
            );
        }
        registers = result.final_registers;
        memory = result.final_memory;
    }

    Ok(effects)
}

fn flatten_stmts(stmts: &[Stmt], out: &mut Vec<Stmt>) {
    for stmt in stmts {
        match stmt {
            Stmt::Pair(lhs, rhs) => {
                flatten_stmts(std::slice::from_ref(lhs), out);
                flatten_stmts(std::slice::from_ref(rhs), out);
            }
            other => out.push(other.clone()),
        }
    }
}

fn is_nonsemantic_simd_preserve_stmt(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Store { addr, value, size } => {
            *size == 8
                && expr_references_stack_pointer(addr)
                && matches!(value, Expr::Reg(Reg::D(index)) if (8..=15).contains(index))
        }
        Stmt::Assign { dst, src } => {
            matches!(dst, Reg::D(index) if (8..=15).contains(index))
                && matches!(src, Expr::Load { addr, size } if *size == 8 && expr_references_stack_pointer(addr))
        }
        _ => false,
    }
}

fn expr_references_stack_pointer(expr: &Expr) -> bool {
    match expr {
        Expr::Reg(Reg::SP) | Expr::StackSlot { .. } => true,
        Expr::Add(lhs, rhs)
        | Expr::Sub(lhs, rhs)
        | Expr::And(lhs, rhs)
        | Expr::Or(lhs, rhs)
        | Expr::Xor(lhs, rhs)
        | Expr::Shl(lhs, rhs)
        | Expr::Lsr(lhs, rhs)
        | Expr::Asr(lhs, rhs)
        | Expr::Ror(lhs, rhs)
        | Expr::Mul(lhs, rhs)
        | Expr::Div(lhs, rhs)
        | Expr::UDiv(lhs, rhs)
        | Expr::FAdd(lhs, rhs)
        | Expr::FSub(lhs, rhs)
        | Expr::FMul(lhs, rhs)
        | Expr::FDiv(lhs, rhs)
        | Expr::FMax(lhs, rhs)
        | Expr::FMin(lhs, rhs)
        | Expr::Compare { lhs, rhs, .. } => {
            expr_references_stack_pointer(lhs) || expr_references_stack_pointer(rhs)
        }
        Expr::Load { addr, .. }
        | Expr::Neg(addr)
        | Expr::Abs(addr)
        | Expr::Not(addr)
        | Expr::FNeg(addr)
        | Expr::FAbs(addr)
        | Expr::FSqrt(addr)
        | Expr::FCvt(addr)
        | Expr::IntToFloat(addr)
        | Expr::FloatToInt(addr)
        | Expr::Clz(addr)
        | Expr::Cls(addr)
        | Expr::Rev(addr)
        | Expr::Rbit(addr)
        | Expr::SignExtend { src: addr, .. }
        | Expr::ZeroExtend { src: addr, .. }
        | Expr::Extract { src: addr, .. } => expr_references_stack_pointer(addr),
        Expr::Insert { dst, src, .. } => {
            expr_references_stack_pointer(dst) || expr_references_stack_pointer(src)
        }
        Expr::CondSelect {
            if_true, if_false, ..
        } => expr_references_stack_pointer(if_true) || expr_references_stack_pointer(if_false),
        Expr::Intrinsic { operands, .. } => operands.iter().any(expr_references_stack_pointer),
        _ => false,
    }
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

fn accumulate_dependency_reports_for_block(
    block: &BlockReport,
    by_key: &mut BTreeMap<(String, u8), DependencyReport>,
    source_sets: &mut BTreeMap<(String, u8), BTreeMap<String, ()>>,
) {
    for read in &block.reads {
        if read.source == "overlay" {
            continue;
        }
        let key = (read.location.clone(), read.size);
        let entry = by_key
            .entry(key.clone())
            .or_insert_with(|| DependencyReport {
                location: read.location.clone(),
                size: read.size,
                first_block: block.addr.clone(),
                region: read.region.clone(),
                use_count: 0,
                concrete_reads: 0,
                symbolic_reads: 0,
                sources: Vec::new(),
            });
        entry.use_count += 1;
        if read.concrete {
            entry.concrete_reads += 1;
        } else {
            entry.symbolic_reads += 1;
        }
        source_sets
            .entry(key)
            .or_default()
            .insert(read.source.clone(), ());
    }
}

fn finalize_dependency_reports(
    by_key: BTreeMap<(String, u8), DependencyReport>,
    mut source_sets: BTreeMap<(String, u8), BTreeMap<String, ()>>,
) -> Vec<DependencyReport> {
    let mut reports: Vec<_> = by_key
        .into_iter()
        .map(|(key, mut report)| {
            if let Some(sources) = source_sets.remove(&key) {
                report.sources = sources.into_keys().collect();
            }
            report
        })
        .collect();
    reports.sort_by(|lhs, rhs| {
        lhs.first_block
            .cmp(&rhs.first_block)
            .then(lhs.location.cmp(&rhs.location))
    });
    reports
}

fn read_report(read: &MemoryReadObservation, proc_memory: &ProcMemory) -> ReadReport {
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
        region: proc_memory.region_summary(&read.id.location),
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

fn is_in_range(addr: u64, range: Option<(u64, u64)>) -> bool {
    let Some((start, end)) = range else {
        return true;
    };
    canonical_address_candidates(addr)
        .into_iter()
        .any(|candidate| candidate >= start && candidate < end)
}

fn normalize_control_flow_addr(
    addr: u64,
    proc_memory: &ProcMemory,
    trace_range: Option<(u64, u64)>,
) -> Option<u64> {
    for candidate in canonical_address_candidates(addr) {
        if is_in_range(candidate, trace_range) {
            return Some(candidate);
        }
        if let Some((resolved, region)) = proc_memory.find_region(candidate) {
            if region.perms.contains('x') {
                return Some(resolved);
            }
        }
    }
    None
}

fn resolve_local_symbol_file(region_path: &str) -> Option<PathBuf> {
    if region_path.starts_with('[') || region_path.is_empty() {
        return None;
    }

    let direct = Path::new(region_path);
    if direct.exists() {
        return Some(direct.to_path_buf());
    }

    let basename = Path::new(region_path).file_name()?;
    let fallback = Path::new("/tmp/aeon_live").join(basename);
    fallback.exists().then_some(fallback)
}

fn symbolize_file_offset(path: &Path, file_offset: u64) -> Option<String> {
    let output = Command::new("llvm-symbolizer")
        .arg(format!("--obj={}", path.display()))
        .arg(format!("0x{file_offset:x}"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let first = stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)?;
    if first == "??" {
        None
    } else {
        Some(first.to_string())
    }
}

fn verbose_trace_line(message: &str) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{message}").map_err(|err| format!("write verbose trace: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush verbose trace: {err}"))
}

fn trace_register_summary(
    changed_registers: &[RegisterReport],
    final_registers: &BTreeMap<Reg, Value>,
) -> String {
    format!(
        "x0={} x1={} x30={} changed={}",
        read_u64_reg(final_registers, Reg::X(0))
            .map(format_hex)
            .unwrap_or_else(|| "unknown".to_string()),
        read_u64_reg(final_registers, Reg::X(1))
            .map(format_hex)
            .unwrap_or_else(|| "unknown".to_string()),
        read_u64_reg(final_registers, Reg::X(30))
            .map(format_hex)
            .unwrap_or_else(|| "unknown".to_string()),
        changed_registers.len()
    )
}

fn decode_art_string_report(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    object_ptr: u64,
) -> Result<Option<ArtStringReport>, String> {
    if object_ptr == 0 {
        return Ok(None);
    }

    let count_bytes = stub_read_bytes(
        memory_overlay,
        memory,
        object_ptr.wrapping_add(8),
        4,
        "art_string",
        0,
    )?;
    let count = u32::from_le_bytes(count_bytes[0..4].try_into().unwrap());
    let mut attempts = Vec::new();
    if (count & 1) != 0 {
        attempts.push((true, (count >> 1) as usize, object_ptr.wrapping_add(12)));
    }
    if count != 0 && (count & 1) == 0 {
        attempts.push((true, (count >> 1) as usize, object_ptr.wrapping_add(16)));
        attempts.push((false, (count >> 1) as usize, object_ptr.wrapping_add(16)));
    }

    for (compressed, length, value_ptr) in attempts {
        if length == 0 || length > 4096 {
            continue;
        }
        if let Some(value) =
            try_decode_art_string_value(memory_overlay, memory, value_ptr, length, compressed)?
        {
            return Ok(Some(ArtStringReport {
                object_ptr: format_hex(object_ptr),
                value_ptr: format_hex(value_ptr),
                length,
                compressed,
                value,
            }));
        }
    }

    Ok(None)
}

fn try_decode_art_string_value(
    memory_overlay: &BTreeMap<MemoryCellId, Value>,
    memory: &ProcMemory,
    value_ptr: u64,
    length: usize,
    compressed: bool,
) -> Result<Option<String>, String> {
    let value = if compressed {
        let bytes = stub_read_bytes(
            memory_overlay,
            memory,
            value_ptr,
            length as u64,
            "art_string",
            0,
        )?;
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        let bytes = stub_read_bytes(
            memory_overlay,
            memory,
            value_ptr,
            (length * 2) as u64,
            "art_string",
            0,
        )?;
        let utf16 = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&utf16)
    };
    if is_plausible_art_string_value(&value) {
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

fn is_plausible_art_string_value(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| !ch.is_control() || ch == ' ')
}

fn art_string_token_candidate(report: Option<&ArtStringReport>) -> Option<TokenCandidate> {
    let report = report?;
    let value = report.value.trim().to_ascii_uppercase();
    if value.len() == 48 && value.bytes().all(is_hex_ascii) {
        let start_addr = parse_u64(&report.value_ptr).ok()?;
        Some(TokenCandidate {
            start_addr: report.value_ptr.clone(),
            end_addr: format_hex(start_addr.wrapping_add(value.len() as u64)),
            len: value.len(),
            value,
        })
    } else {
        None
    }
}

fn extract_token_candidates(memory: &BTreeMap<MemoryCellId, Value>) -> Vec<TokenCandidate> {
    let mut bytes = BTreeMap::<u64, u8>::new();
    for (id, value) in memory {
        let MemoryLocation::Absolute(addr) = id.location else {
            continue;
        };
        let Some(concrete_bytes) = value_to_le_bytes(value, id.size) else {
            continue;
        };
        for (offset, byte) in concrete_bytes.into_iter().enumerate() {
            bytes.insert(addr + offset as u64, byte);
        }
    }

    let mut runs = Vec::<(u64, Vec<u8>)>::new();
    let mut current_start = None;
    let mut current_bytes = Vec::new();
    let mut previous_addr = 0u64;

    for (addr, byte) in bytes {
        let printable = byte.is_ascii_graphic();
        if !printable {
            flush_run(&mut runs, &mut current_start, &mut current_bytes);
            previous_addr = addr;
            continue;
        }
        if let Some(start) = current_start {
            if addr == previous_addr + 1 {
                current_bytes.push(byte);
            } else {
                runs.push((start, std::mem::take(&mut current_bytes)));
                current_start = Some(addr);
                current_bytes.push(byte);
            }
        } else {
            current_start = Some(addr);
            current_bytes.push(byte);
        }
        previous_addr = addr;
    }
    flush_run(&mut runs, &mut current_start, &mut current_bytes);

    let mut candidates = Vec::new();
    for (start, bytes) in runs {
        let mut idx = 0usize;
        while idx < bytes.len() {
            while idx < bytes.len() && !is_hex_ascii(bytes[idx]) {
                idx += 1;
            }
            let run_start = idx;
            while idx < bytes.len() && is_hex_ascii(bytes[idx]) {
                idx += 1;
            }
            if idx - run_start >= 16 {
                let value = String::from_utf8_lossy(&bytes[run_start..idx]).into_owned();
                let start_addr = start + run_start as u64;
                let end_addr = start + idx as u64;
                candidates.push(TokenCandidate {
                    start_addr: format_hex(start_addr),
                    end_addr: format_hex(end_addr),
                    len: value.len(),
                    value,
                });
            }
        }
    }

    candidates.sort_by(|lhs, rhs| {
        rhs.value
            .len()
            .cmp(&lhs.value.len())
            .then_with(|| lhs.start_addr.cmp(&rhs.start_addr))
    });
    candidates
}

fn flush_run(
    runs: &mut Vec<(u64, Vec<u8>)>,
    current_start: &mut Option<u64>,
    current_bytes: &mut Vec<u8>,
) {
    if let Some(start) = current_start.take() {
        if !current_bytes.is_empty() {
            runs.push((start, std::mem::take(current_bytes)));
        }
    }
}

fn pick_best_token(candidates: &[TokenCandidate]) -> Option<TokenCandidate> {
    candidates
        .iter()
        .max_by(|lhs, rhs| {
            score_token_candidate(lhs)
                .cmp(&score_token_candidate(rhs))
                .then_with(|| lhs.value.len().cmp(&rhs.value.len()))
        })
        .cloned()
}

fn score_token_candidate(candidate: &TokenCandidate) -> (usize, usize) {
    let exact = usize::from(candidate.value.len() == 48);
    let uppercase_hex = usize::from(candidate.value.bytes().all(is_hex_ascii));
    (exact, uppercase_hex)
}

fn value_to_le_bytes(value: &Value, size: u8) -> Option<Vec<u8>> {
    match value {
        Value::U64(bits) => {
            let mut out = bits.to_le_bytes().to_vec();
            out.truncate(size as usize);
            Some(out)
        }
        Value::U128(bits) if size == 16 => Some(bits.to_le_bytes().to_vec()),
        _ => None,
    }
}

fn is_hex_ascii(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

fn format_stop_reason(stop: &ReplayStop) -> String {
    match stop {
        ReplayStop::Halted => "halted".to_string(),
        ReplayStop::ReturnedToEntryLr(addr) => {
            format!("returned_to_entry_lr {}", format_hex(*addr))
        }
        ReplayStop::MaxBlocks => "max_blocks".to_string(),
        ReplayStop::MaxBlockVisits(addr) => format!("max_block_visits at {}", format_hex(*addr)),
        ReplayStop::TokenFound(token) => format!("token_found {}", token),
        ReplayStop::NonConcrete { pc, reason } => {
            format!("non_concrete in {}: {reason}", format_hex(*pc))
        }
        ReplayStop::LiftError(addr, err) => format!("lift_error at {}: {err}", format_hex(*addr)),
        ReplayStop::ExecutionPanic(addr, err) => {
            format!("execution_panic in {}: {err}", format_hex(*addr))
        }
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

fn panic_payload_string(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_string(),
            Err(_) => "non-string panic payload".to_string(),
        },
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

fn read_u64_reg(registers: &BTreeMap<Reg, Value>, reg: Reg) -> Option<u64> {
    registers
        .get(&reg)
        .and_then(value_as_u64)
        .or_else(|| match reg {
            Reg::X(index) => registers
                .get(&Reg::W(index))
                .and_then(value_as_u64)
                .map(|value| value & 0xffff_ffff),
            Reg::W(index) => registers
                .get(&Reg::X(index))
                .and_then(value_as_u64)
                .map(|value| value & 0xffff_ffff),
            _ => None,
        })
}

fn write_u64_reg(registers: &mut BTreeMap<Reg, Value>, index: u8, value: u64) {
    registers.insert(Reg::X(index), Value::U64(value));
    registers.insert(Reg::W(index), Value::U64(value & 0xffff_ffff));
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

fn is_non_concrete_stub_error(err: &str) -> bool {
    err.contains("missing concrete")
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

fn value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::U64(bits) => Some(*bits),
        Value::U128(bits) => Some(*bits as u64),
        Value::F64(_) | Value::Unknown => None,
    }
}

fn parse_json_u64(value: &serde_json::Value) -> Result<u64, String> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    if let Some(value) = value.as_i64() {
        return u64::try_from(value)
            .map_err(|_| format!("negative integer is not a valid u64: {value}"));
    }
    if let Some(value) = value.as_str() {
        return parse_u64(value);
    }
    Err(format!("unsupported numeric json value: {value}"))
}

fn parse_hex_u128(value: &str) -> Result<u128, String> {
    let value = value.trim();
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if hex.is_empty() {
        return Err("empty hex string for u128".to_string());
    }
    u128::from_str_radix(hex, 16).map_err(|e| format!("invalid u128 hex '{value}': {e}"))
}

fn parse_simd_hex_u128_le(value: &str) -> Result<u128, String> {
    let value = value.trim();
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if hex.len() != 32 {
        return Err(format!(
            "invalid SIMD hex '{value}': expected exactly 16 bytes / 32 hex chars"
        ));
    }
    let mut bytes = [0u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        let chunk = &hex[start..start + 2];
        *slot = u8::from_str_radix(chunk, 16)
            .map_err(|e| format!("invalid SIMD byte hex '{value}': {e}"))?;
    }
    Ok(u128::from_le_bytes(bytes))
}

fn parse_json_i32(value: &serde_json::Value) -> Result<i32, String> {
    let value = parse_json_u64(value)?;
    i32::try_from(value).map_err(|_| format!("json integer out of range for i32: {value}"))
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
    if let Some(index) = value.strip_prefix('q') {
        let index = index
            .parse::<u8>()
            .map_err(|err| format!("invalid register '{value}': {err}"))?;
        if index <= 31 {
            return Ok(Reg::Q(index));
        }
    }
    if let Some(index) = value.strip_prefix('v') {
        let index = index
            .parse::<u8>()
            .map_err(|err| format!("invalid register '{value}': {err}"))?;
        if index <= 31 {
            return Ok(Reg::V(index));
        }
    }
    if let Some(index) = value.strip_prefix('d') {
        let index = index
            .parse::<u8>()
            .map_err(|err| format!("invalid register '{value}': {err}"))?;
        if index <= 31 {
            return Ok(Reg::D(index));
        }
    }
    if let Some(index) = value.strip_prefix('s') {
        let index = index
            .parse::<u8>()
            .map_err(|err| format!("invalid register '{value}': {err}"))?;
        if index <= 31 {
            return Ok(Reg::S(index));
        }
    }
    Err(format!("unsupported register '{value}'"))
}

fn parse_json_reg(value: &str) -> Result<Reg, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pstate" | "nzcv" => Ok(Reg::Flags),
        other => parse_reg(other),
    }
}

fn apply_reg_overrides(registers: &mut BTreeMap<Reg, Value>, overrides: &[(Reg, Value)]) {
    for (reg, value) in overrides {
        registers.insert(reg.clone(), value.clone());
    }
}

fn normalize_hex(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty string".to_string());
    }
    let stripped = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if stripped.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    if !stripped.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("hex string contains non-hex characters".to_string());
    }
    Ok(stripped.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_proc_memory_with_path(path: &str) -> ProcMemory {
        ProcMemory {
            source: ProcMemorySource::Local(File::open("/dev/null").expect("open /dev/null")),
            regions: vec![ProcRegion {
                base: 0,
                end: 0x1_0000_0000,
                perms: "r-xp".to_string(),
                offset: 0,
                path: path.to_string(),
            }],
        }
    }

    fn test_proc_memory() -> ProcMemory {
        test_proc_memory_with_path("/system/lib64/libc.so")
    }

    fn test_proc_memory_with_regions_and_bytes(
        regions: Vec<ProcRegion>,
        writes: &[(u64, &[u8])],
    ) -> ProcMemory {
        let dir = test_temp_dir("proc_memory");
        let mem_path = dir.join("mem.bin");
        let end = regions.iter().map(|region| region.end).max().unwrap_or(0);
        let mut bytes = vec![0u8; end as usize];
        for (addr, chunk) in writes {
            let start = *addr as usize;
            let stop = start + chunk.len();
            bytes[start..stop].copy_from_slice(chunk);
        }
        fs::write(&mem_path, bytes).expect("write proc memory image");
        ProcMemory {
            source: ProcMemorySource::Local(File::open(&mem_path).expect("open proc memory image")),
            regions,
        }
    }

    fn overlay_bytes(addr: u64, bytes: &[u8]) -> BTreeMap<MemoryCellId, Value> {
        let mut overlay = BTreeMap::new();
        stub_write_bytes(&mut overlay, addr, bytes);
        overlay
    }

    fn regs(pairs: &[(Reg, u64)]) -> BTreeMap<Reg, Value> {
        let mut registers = BTreeMap::new();
        for (reg, value) in pairs {
            registers.insert(reg.clone(), Value::U64(*value));
        }
        registers
    }

    fn test_clock() -> VirtualClock {
        VirtualClock {
            realtime_ns: 1_700_000_000_123_456_789,
            monotonic_ns: 900_000_000,
            boottime_ns: 900_000_000,
        }
    }

    fn test_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        path.push(format!(
            "aeon_live_cert_eval_{label}_{}_{}",
            process::id(),
            nonce
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn memset_stub_writes_bytes_and_returns_dest() {
        let memory = test_proc_memory();
        let mut clock = test_clock();
        let mut trace = None;
        let mut registers = regs(&[
            (Reg::X(0), 0x1000),
            (Reg::X(1), 0xaa),
            (Reg::X(2), 4),
            (Reg::X(30), 0x2000),
        ]);
        let mut overlay = BTreeMap::new();

        let outcome = maybe_execute_known_stub(
            LIBC_MEMSET_OFFSET,
            &mut registers,
            &mut overlay,
            &memory,
            &mut clock,
            &mut trace,
        )
        .expect("memset stub result")
        .expect("memset stub hit");

        assert_eq!(outcome.next_pc, 0x2000);
        assert_eq!(read_u64_reg(&registers, Reg::X(0)), Some(0x1000));
        assert_eq!(
            stub_read_bytes(&overlay, &memory, 0x1000, 4, "test", 0).unwrap(),
            vec![0xaa; 4]
        );
    }

    #[test]
    fn memcpy_stub_copies_overlay_bytes() {
        let memory = test_proc_memory();
        let mut clock = test_clock();
        let mut trace = None;
        let mut registers = regs(&[
            (Reg::X(0), 0x2000),
            (Reg::X(1), 0x3000),
            (Reg::X(2), 4),
            (Reg::X(30), 0x4000),
        ]);
        let mut overlay = overlay_bytes(0x3000, b"ABCD");

        let outcome = maybe_execute_known_stub(
            LIBC_MEMCPY_OFFSET,
            &mut registers,
            &mut overlay,
            &memory,
            &mut clock,
            &mut trace,
        )
        .expect("memcpy stub result")
        .expect("memcpy stub hit");

        assert_eq!(outcome.next_pc, 0x4000);
        assert_eq!(
            stub_read_bytes(&overlay, &memory, 0x2000, 4, "test", 0).unwrap(),
            b"ABCD"
        );
    }

    #[test]
    fn strchr_stub_finds_matching_byte() {
        let memory = test_proc_memory();
        let mut clock = test_clock();
        let mut trace = None;
        let mut registers = regs(&[
            (Reg::X(0), 0x5000),
            (Reg::X(1), b'B' as u64),
            (Reg::X(30), 0x6000),
        ]);
        let mut overlay = overlay_bytes(0x5000, b"ABC\0");

        let outcome = maybe_execute_known_stub(
            LIBC_STRCHR_OFFSET,
            &mut registers,
            &mut overlay,
            &memory,
            &mut clock,
            &mut trace,
        )
        .expect("strchr stub result")
        .expect("strchr stub hit");

        assert_eq!(outcome.next_pc, 0x6000);
        assert_eq!(read_u64_reg(&registers, Reg::X(0)), Some(0x5001));
    }

    #[test]
    fn strcmp_and_strlen_stubs_return_expected_values() {
        let memory = test_proc_memory();
        let mut clock = test_clock();
        let mut trace = None;

        let mut strlen_regs = regs(&[(Reg::X(0), 0x7000), (Reg::X(30), 0x7100)]);
        let mut strlen_overlay = overlay_bytes(0x7000, b"token\0");
        let strlen_outcome = maybe_execute_known_stub(
            LIBC_STRLEN_OFFSET,
            &mut strlen_regs,
            &mut strlen_overlay,
            &memory,
            &mut clock,
            &mut trace,
        )
        .expect("strlen stub result")
        .expect("strlen stub hit");
        assert_eq!(strlen_outcome.next_pc, 0x7100);
        assert_eq!(read_u64_reg(&strlen_regs, Reg::X(0)), Some(5));

        let mut strcmp_regs = regs(&[
            (Reg::X(0), 0x7200),
            (Reg::X(1), 0x7300),
            (Reg::X(30), 0x7400),
        ]);
        let mut strcmp_overlay = overlay_bytes(0x7200, b"abc\0");
        strcmp_overlay.extend(overlay_bytes(0x7300, b"abd\0"));
        let strcmp_outcome = maybe_execute_known_stub(
            LIBC_STRCMP_OFFSET,
            &mut strcmp_regs,
            &mut strcmp_overlay,
            &memory,
            &mut clock,
            &mut trace,
        )
        .expect("strcmp stub result")
        .expect("strcmp stub hit");
        assert_eq!(strcmp_outcome.next_pc, 0x7400);
        assert_eq!(read_u64_reg(&strcmp_regs, Reg::W(0)), Some(u32::MAX as u64));
    }

    #[test]
    fn time_and_sleep_stubs_write_virtual_time_and_advance_it() {
        let memory = test_proc_memory_with_path("/system/lib64/libc.so");
        let mut clock = test_clock();
        let mut trace = None;

        let mut clock_gettime_regs = regs(&[
            (Reg::X(0), libc::CLOCK_MONOTONIC as u64),
            (Reg::X(1), 0x8000),
            (Reg::X(30), 0x8100),
        ]);
        let mut overlay = BTreeMap::new();
        let outcome = maybe_execute_known_stub(
            LIBC_CLOCK_GETTIME_OFFSET,
            &mut clock_gettime_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut trace,
        )
        .expect("clock_gettime stub result")
        .expect("clock_gettime stub hit");
        assert_eq!(outcome.next_pc, 0x8100);
        assert_eq!(read_u64_reg(&clock_gettime_regs, Reg::X(0)), Some(0));
        let ts = stub_read_timespec(&overlay, &memory, 0x8000, "test", 0).unwrap();
        assert_eq!(timespec_to_ns(ts), 900_000_000);

        let mut nanosleep_overlay = overlay_bytes(
            0x9000,
            &[
                1, 0, 0, 0, 0, 0, 0, 0, // tv_sec = 1
                0x88, 0x13, 0, 0, 0, 0, 0, 0, // tv_nsec = 5000
            ],
        );
        let mut nanosleep_regs = regs(&[(Reg::X(0), 0x9000), (Reg::X(1), 0), (Reg::X(30), 0x9100)]);
        let sleep_outcome = maybe_execute_known_stub(
            LIBC_NANOSLEEP_OFFSET,
            &mut nanosleep_regs,
            &mut nanosleep_overlay,
            &memory,
            &mut clock,
            &mut trace,
        )
        .expect("nanosleep stub result")
        .expect("nanosleep stub hit");
        assert_eq!(sleep_outcome.next_pc, 0x9100);
        assert_eq!(clock.monotonic_ns, 1_900_005_000);

        let vdso_memory = test_proc_memory_with_path("[vdso]");
        let mut vdso_regs = regs(&[
            (Reg::X(0), libc::CLOCK_MONOTONIC as u64),
            (Reg::X(1), 0xa000),
            (Reg::X(30), 0xa100),
        ]);
        let mut vdso_overlay = BTreeMap::new();
        let vdso_outcome = maybe_execute_known_stub(
            VDSO_CLOCK_GETTIME_OFFSET + 0x2c,
            &mut vdso_regs,
            &mut vdso_overlay,
            &vdso_memory,
            &mut clock,
            &mut trace,
        )
        .expect("vdso clock_gettime stub result")
        .expect("vdso clock_gettime stub hit");
        assert_eq!(vdso_outcome.next_pc, 0xa100);
        let vdso_ts = stub_read_timespec(&vdso_overlay, &vdso_memory, 0xa000, "test", 0).unwrap();
        assert_eq!(timespec_to_ns(vdso_ts), 1_900_005_000);
    }

    #[test]
    fn scudo_mutex_stubs_return_immediately() {
        let memory = test_proc_memory_with_path("/apex/com.android.runtime/lib64/bionic/libc.so");
        let mut clock = test_clock();
        let mut trace = None;
        let mut overlay = BTreeMap::new();
        let mut lock_registers = regs(&[(Reg::X(30), 0x2222)]);
        let mut unlock_registers = regs(&[(Reg::X(30), 0x3333)]);

        let lock_pc = LIBC_SCUDO_HYBRID_MUTEX_LOCK_SLOW_START;
        let unlock_pc = LIBC_SCUDO_HYBRID_MUTEX_UNLOCK_START;

        let lock = maybe_execute_known_stub(
            lock_pc,
            &mut lock_registers,
            &mut overlay,
            &memory,
            &mut clock,
            &mut trace,
        )
        .expect("lockSlow stub result");
        let unlock = maybe_execute_known_stub(
            unlock_pc,
            &mut unlock_registers,
            &mut overlay,
            &memory,
            &mut clock,
            &mut trace,
        )
        .expect("unlock stub result");

        assert_eq!(lock.map(|stub| stub.next_pc), Some(0x2222));
        assert_eq!(unlock.map(|stub| stub.next_pc), Some(0x3333));
    }

    #[test]
    fn replay_stops_when_execution_reaches_entry_lr() {
        let setup = LiveReplaySetup {
            pid: 1,
            tid: 1,
            challenge: "AABB".to_string(),
            report_out: std::env::temp_dir().join("aeon_test_entry_lr.json"),
            page_cache_dir: None,
            sprintf_trace_out: None,
            file_roots: Vec::new(),
            path_maps: Vec::new(),
            adb_serial: None,
            start_pc: LIBC_MEMSET_OFFSET,
            entry_lr: Some(0x2000),
            trace_range: None,
            registers: regs(&[
                (Reg::X(0), 0x1000),
                (Reg::X(1), 0x41),
                (Reg::X(2), 4),
                (Reg::X(30), 0x2000),
            ]),
            sysreg_overrides: BTreeMap::new(),
            memory: test_proc_memory(),
            virtual_clock: test_clock(),
            missing_memory_policy: MissingMemoryPolicy::Stop,
            summary_only: true,
            stop_on_token: false,
            stop_on_non_concrete: false,
            verbose_trace: false,
        };

        let report = run_replay(setup, 16, 16).expect("run replay");

        assert_eq!(report.block_count, 1);
        assert_eq!(report.stop_reason, "returned_to_entry_lr 0x2000");
        assert!(report
            .final_registers
            .iter()
            .any(|reg| reg.reg == "pc" && reg.value == "0x2000"));
    }

    #[test]
    fn replay_stops_when_block_becomes_non_concrete() {
        let code = [
            0x20u8, 0x00, 0x40, 0xf9, // ldr x0, [x1]
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ];
        let memory = test_proc_memory_with_regions_and_bytes(
            vec![ProcRegion {
                base: 0x1000,
                end: 0x2000,
                perms: "r-xp".to_string(),
                offset: 0,
                path: "/jit/test.bin".to_string(),
            }],
            &[(0x1000, &code)],
        );
        let setup = LiveReplaySetup {
            pid: 1,
            tid: 1,
            challenge: "AABB".to_string(),
            report_out: std::env::temp_dir().join("aeon_test_stop_non_concrete_block.json"),
            page_cache_dir: None,
            sprintf_trace_out: None,
            file_roots: Vec::new(),
            path_maps: Vec::new(),
            adb_serial: None,
            start_pc: 0x1000,
            entry_lr: None,
            trace_range: Some((0x1000, 0x2000)),
            registers: regs(&[(Reg::X(1), 0x3000), (Reg::X(30), 0x2000)]),
            sysreg_overrides: BTreeMap::new(),
            memory,
            virtual_clock: test_clock(),
            missing_memory_policy: MissingMemoryPolicy::ContinueAsUnknown,
            summary_only: true,
            stop_on_token: false,
            stop_on_non_concrete: true,
            verbose_trace: false,
        };

        let report = run_replay(setup, 16, 16).expect("run replay");

        assert_eq!(report.block_count, 1);
        assert_eq!(
            report.stop_reason,
            "non_concrete in 0x1000: missing read 0x3000"
        );
    }

    #[test]
    fn replay_stops_when_stub_argument_is_not_concrete() {
        let setup = LiveReplaySetup {
            pid: 1,
            tid: 1,
            challenge: "AABB".to_string(),
            report_out: std::env::temp_dir().join("aeon_test_stop_non_concrete_stub.json"),
            page_cache_dir: None,
            sprintf_trace_out: None,
            file_roots: Vec::new(),
            path_maps: Vec::new(),
            adb_serial: None,
            start_pc: LIBC_MEMSET_OFFSET,
            entry_lr: None,
            trace_range: None,
            registers: regs(&[(Reg::X(1), 0x41), (Reg::X(2), 4), (Reg::X(30), 0x2000)]),
            sysreg_overrides: BTreeMap::new(),
            memory: test_proc_memory(),
            virtual_clock: test_clock(),
            missing_memory_policy: MissingMemoryPolicy::Stop,
            summary_only: true,
            stop_on_token: false,
            stop_on_non_concrete: true,
            verbose_trace: false,
        };

        let report = run_replay(setup, 16, 16).expect("run replay");

        assert_eq!(report.block_count, 0);
        assert_eq!(
            report.stop_reason,
            format!(
                "non_concrete in {}: memset stub at {} missing concrete x0",
                format_hex(LIBC_MEMSET_OFFSET),
                format_hex(LIBC_MEMSET_OFFSET)
            )
        );
    }

    #[test]
    fn non_concrete_filter_ignores_d8_d15_stack_spills() {
        let memory = test_proc_memory();
        let block = LiftedBlock {
            addr: 0x1000,
            stmts: vec![
                Stmt::Assign {
                    dst: Reg::SP,
                    src: Expr::Sub(Box::new(Expr::Reg(Reg::SP)), Box::new(Expr::Imm(0xb0))),
                },
                Stmt::Store {
                    addr: Expr::Add(Box::new(Expr::Reg(Reg::SP)), Box::new(Expr::Imm(16))),
                    value: Expr::Reg(Reg::D(8)),
                    size: 8,
                },
                Stmt::Store {
                    addr: Expr::Add(Box::new(Expr::Reg(Reg::SP)), Box::new(Expr::Imm(24))),
                    value: Expr::Reg(Reg::D(9)),
                    size: 8,
                },
                Stmt::Branch {
                    target: Expr::Imm(0x2000),
                },
            ],
            terminator: BlockTerminator::DirectBranch,
        };
        let initial_registers = BTreeMap::from([
            (Reg::SP, Value::U64(0x4000)),
            (Reg::D(8), Value::Unknown),
            (Reg::D(9), Value::Unknown),
        ]);
        let initial_memory = BTreeMap::new();
        let result = execute_block(
            &block.stmts,
            initial_registers.clone(),
            initial_memory.clone(),
            &memory,
            MissingMemoryPolicy::ContinueAsUnknown,
            BLOCK_STEP_BUDGET,
        );
        let changed_registers = diff_registers(&initial_registers, &result.final_registers);
        let ignored = collect_nonsemantic_simd_preserve_effects(
            &block,
            &initial_registers,
            &initial_memory,
            &memory,
        )
        .expect("collect ignored spill effects");

        assert!(!ignored.writes.is_empty());
        assert_eq!(
            first_non_concrete_block_reason_filtered(
                &result,
                &changed_registers,
                None,
                &BTreeSet::new(),
                &ignored,
            ),
            None
        );
    }

    #[test]
    fn decode_art_string_report_handles_compressed_layout() {
        let memory = test_proc_memory();
        let mut overlay = BTreeMap::new();
        let object = 0x4000u64;
        let count = ((48u32) << 1) | 1;
        stub_write_bytes(&mut overlay, object + 8, &count.to_le_bytes());
        stub_write_bytes(
            &mut overlay,
            object + 12,
            b"3DBAB9F744F6B601E62D42B80212A8DFCD8E42847FE6C6D2",
        );

        let decoded = decode_art_string_report(&overlay, &memory, object)
            .expect("decode compressed art string")
            .expect("compressed art string");

        assert!(decoded.compressed);
        assert_eq!(decoded.length, 48);
        assert_eq!(decoded.object_ptr, "0x4000");
        assert_eq!(decoded.value_ptr, "0x400c");
        assert_eq!(
            decoded.value,
            "3DBAB9F744F6B601E62D42B80212A8DFCD8E42847FE6C6D2"
        );
        assert_eq!(
            art_string_token_candidate(Some(&decoded))
                .expect("token candidate from compressed art string")
                .value,
            "3DBAB9F744F6B601E62D42B80212A8DFCD8E42847FE6C6D2"
        );
    }

    #[test]
    fn decode_art_string_report_handles_utf16_layout() {
        let memory = test_proc_memory();
        let mut overlay = BTreeMap::new();
        let object = 0x5000u64;
        let value = "TOKEN";
        let count = (value.len() as u32) << 1;
        stub_write_bytes(&mut overlay, object + 8, &count.to_le_bytes());
        stub_write_bytes(&mut overlay, object + 12, &0u32.to_le_bytes());
        let utf16 = value
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        stub_write_bytes(&mut overlay, object + 16, &utf16);

        let decoded = decode_art_string_report(&overlay, &memory, object)
            .expect("decode utf16 art string")
            .expect("utf16 art string");

        assert!(!decoded.compressed);
        assert_eq!(decoded.length, 5);
        assert_eq!(decoded.value_ptr, "0x5010");
        assert_eq!(decoded.value, "TOKEN");
    }

    #[test]
    fn decode_art_string_report_handles_observed_compressed_plus_16_layout() {
        let memory = test_proc_memory();
        let mut overlay = BTreeMap::new();
        let object = 0x5800u64;
        let value = "com.netmarble.thered";
        let count = (value.len() as u32) << 1;
        stub_write_bytes(&mut overlay, object + 8, &count.to_le_bytes());
        stub_write_bytes(&mut overlay, object + 16, value.as_bytes());

        let decoded = decode_art_string_report(&overlay, &memory, object)
            .expect("decode observed compressed art string")
            .expect("observed compressed art string");

        assert!(decoded.compressed);
        assert_eq!(decoded.length, value.len());
        assert_eq!(decoded.value_ptr, "0x5810");
        assert_eq!(decoded.value, value);
    }

    #[test]
    fn infer_sysreg_overrides_recovers_tpidr_el0_from_stack_tls_region() {
        let tls_base = 0x1000u64;
        let tls_end = 0x4000u64;
        let tpidr = 0x3000u64;
        let canary = 0x2273_323d_4275_b9bbu64;
        let memory = test_proc_memory_with_regions_and_bytes(
            vec![ProcRegion {
                base: tls_base,
                end: tls_end,
                perms: "rw-p".to_string(),
                offset: 0,
                path: "[anon:stack_and_tls:42]".to_string(),
            }],
            &[(tpidr + 0x28, &canary.to_le_bytes())],
        );
        let registers = regs(&[(Reg::SP, 0x2fe0), (Reg::X(26), tpidr), (Reg::X(29), 0x2080)]);

        let overrides = infer_sysreg_overrides(&memory, &registers, None);

        assert_eq!(overrides.get("tpidr_el0").copied(), Some(tpidr));
    }

    #[test]
    fn infer_sysreg_overrides_prefers_explicit_sysreg_json_value() {
        let tls_base = 0x1000u64;
        let tls_end = 0x4000u64;
        let memory = test_proc_memory_with_regions_and_bytes(
            vec![ProcRegion {
                base: tls_base,
                end: tls_end,
                perms: "rw-p".to_string(),
                offset: 0,
                path: "[anon:stack_and_tls:42]".to_string(),
            }],
            &[],
        );
        let registers = regs(&[(Reg::SP, 0x2fe0), (Reg::X(26), 0x3000)]);
        let state = InputState {
            pid: Some(1),
            tid: Some(42),
            challenge: None,
            pc: None,
            lr: None,
            reg_overrides: Vec::new(),
            sysreg_overrides: BTreeMap::from([("tpidr_el0".to_string(), 0xdead_beef)]),
        };

        let overrides = infer_sysreg_overrides(&memory, &registers, Some(&state));

        assert_eq!(overrides.get("tpidr_el0").copied(), Some(0xdead_beef));
    }

    #[test]
    fn load_state_json_parses_nested_simd_registers() {
        let dir = test_temp_dir("state_json_simd");
        let path = dir.join("freeze.json");
        let json = serde_json::json!({
            "pid": 13660,
            "thread_id": 13746,
            "pc": "0x9bea10a0",
            "lr": "0x9be848b4",
            "challenge": "AABBCCDDEEFF0011",
            "registers": {
                "pc": "0x9bea10a0",
                "sp": "0x7bde2e46b0",
                "x0": "0x70ab9b58",
                "x30": "0x9be848b4",
                "nzcv": "0",
                "simd": {
                    "q0": "01000000000000000000000000000000",
                    "q1": "404b2ede7b000000d04a2ede7b000000"
                }
            }
        });
        fs::write(
            &path,
            serde_json::to_vec_pretty(&json).expect("serialize state json"),
        )
        .expect("write state json");

        let state = load_state_json(&path).expect("load state json with simd");

        assert_eq!(state.pid, Some(13660));
        assert_eq!(state.tid, Some(13746));
        assert_eq!(state.pc, Some(0x9bea10a0));
        assert_eq!(state.lr, Some(0x9be848b4));
        assert_eq!(state.challenge.as_deref(), Some("AABBCCDDEEFF0011"));
        assert!(state
            .reg_overrides
            .contains(&(Reg::SP, Value::U64(0x7bde2e46b0))));
        assert!(state
            .reg_overrides
            .contains(&(Reg::X(0), Value::U64(0x70ab9b58))));
        assert!(state.reg_overrides.contains(&(Reg::Flags, Value::U64(0))));
        assert!(state
            .reg_overrides
            .contains(&(Reg::Q(0), Value::U128(0x00000000000000000000000000000001))));
        assert!(state
            .reg_overrides
            .contains(&(Reg::Q(1), Value::U128(0x0000007bde2e4ad00000007bde2e4b40))));
    }

    #[test]
    fn decode_art_string_report_rejects_invalid_lengths() {
        let memory = test_proc_memory();
        let mut overlay = BTreeMap::new();
        let object = 0x6000u64;
        let oversized_count = ((4097u32) << 1) | 1;
        stub_write_bytes(&mut overlay, object + 8, &oversized_count.to_le_bytes());

        assert!(decode_art_string_report(&overlay, &memory, 0)
            .expect("decode null art string")
            .is_none());
        assert!(decode_art_string_report(&overlay, &memory, object)
            .expect("decode oversized art string")
            .is_none());
    }

    #[test]
    fn art_string_token_candidate_trims_and_uppercases_hex() {
        let report = ArtStringReport {
            object_ptr: "0x4000".to_string(),
            value_ptr: "0x400c".to_string(),
            length: 50,
            compressed: true,
            value: " f6ee2878618d9eb4649be8d98b45dff30caf9104b2ea8239\n".to_string(),
        };

        let token =
            art_string_token_candidate(Some(&report)).expect("candidate from lowercase art string");

        assert_eq!(token.start_addr, "0x400c");
        assert_eq!(token.len, 48);
        assert_eq!(
            token.value,
            "F6EE2878618D9EB4649BE8D98B45DFF30CAF9104B2EA8239"
        );
    }

    #[test]
    fn remote_page_cache_path_rebases_using_file_offset() {
        let cache_root = Path::new("/tmp/aeon-cache");
        let remote = RemoteProcMemory {
            serial: "emulator-5554".to_string(),
            pid: 42,
            page_cache: RefCell::new(BTreeMap::new()),
            disk_cache_dir: None,
            allow_remote_fetch: true,
        };
        let region_a = ProcRegion {
            base: 0x7000_0000,
            end: 0x7000_3000,
            perms: "r-xp".to_string(),
            offset: 0x1000,
            path: "/system/lib64/libc.so".to_string(),
        };
        let region_b = ProcRegion {
            base: 0x7100_0000,
            end: 0x7100_3000,
            perms: "r-xp".to_string(),
            offset: 0x1000,
            path: "/system/lib64/libc.so".to_string(),
        };

        let path_a = remote_page_cache_path(cache_root, &remote, &region_a, 0x7000_1000, 4096)
            .expect("cache path for first mapping");
        let path_b = remote_page_cache_path(cache_root, &remote, &region_b, 0x7100_1000, 4096)
            .expect("cache path for rebased mapping");

        assert_eq!(path_a, path_b);
    }

    #[test]
    fn remote_page_cache_namespaces_volatile_regions_by_process_identity() {
        let cache_root = Path::new("/tmp/aeon-cache");
        let remote_a = RemoteProcMemory {
            serial: "emulator-5554".to_string(),
            pid: 42,
            page_cache: RefCell::new(BTreeMap::new()),
            disk_cache_dir: None,
            allow_remote_fetch: true,
        };
        let remote_b = RemoteProcMemory {
            serial: "emulator-5554".to_string(),
            pid: 43,
            page_cache: RefCell::new(BTreeMap::new()),
            disk_cache_dir: None,
            allow_remote_fetch: true,
        };
        let memfd = ProcRegion {
            base: 0x7000_0000,
            end: 0x7000_1000,
            perms: "r-xp".to_string(),
            offset: 0,
            path: "/memfd:jit-cache (deleted)".to_string(),
        };
        let anon = ProcRegion {
            base: 0x7100_0000,
            end: 0x7100_1000,
            perms: "rw-p".to_string(),
            offset: 0,
            path: "[anon:scudo:primary]".to_string(),
        };

        let memfd_a = remote_page_cache_path(cache_root, &remote_a, &memfd, memfd.base, 4096)
            .expect("memfd cache path for first process");
        let memfd_b = remote_page_cache_path(cache_root, &remote_b, &memfd, memfd.base, 4096)
            .expect("memfd cache path for second process");
        let anon_a = remote_page_cache_path(cache_root, &remote_a, &anon, anon.base, 4096)
            .expect("anon cache path");

        assert_ne!(memfd_a, memfd_b);
        assert_ne!(memfd_a, anon_a);
    }

    #[test]
    fn disk_cached_page_round_trips_for_stable_regions() {
        let dir = test_temp_dir("page_cache");
        let remote = RemoteProcMemory {
            serial: "emulator-5554".to_string(),
            pid: 42,
            page_cache: RefCell::new(BTreeMap::new()),
            disk_cache_dir: Some(dir.clone()),
            allow_remote_fetch: true,
        };
        let region = ProcRegion {
            base: 0x7200_0000,
            end: 0x7200_2000,
            perms: "r--p".to_string(),
            offset: 0x4000,
            path: "/system/lib64/libart.so".to_string(),
        };
        let bytes = vec![0xaa, 0xbb, 0xcc, 0xdd];

        write_disk_cached_page(&remote, &region, 0x7200_1000, bytes.len(), &bytes);
        let cached = read_disk_cached_page(&remote, &region, 0x7200_1000, bytes.len())
            .expect("read cached page");

        assert_eq!(cached, bytes);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn open_cached_uses_saved_maps_and_disk_cache_without_remote_fetch() {
        let dir = test_temp_dir("offline_page_cache");
        let maps_path = dir.join("proc.maps");
        fs::write(
            &maps_path,
            "70000000-70001000 r--p 00004000 00:00 0 /system/lib64/libart.so\n",
        )
        .expect("write maps file");
        let cache_root = dir.join("cache");
        let memory = ProcMemory::open_cached(
            "emulator-5554",
            42,
            &maps_path,
            Some(cache_root.clone()),
            true,
        )
        .expect("open cached proc memory");
        let region = memory
            .find_region_exact(0x7000_0000)
            .expect("cached region");
        let remote = match &memory.source {
            ProcMemorySource::Remote(remote) => remote,
            ProcMemorySource::Local(_) => panic!("expected cached remote source"),
        };
        let mut page = vec![0u8; REMOTE_PAGE_SIZE as usize];
        page[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        write_disk_cached_page(remote, region, 0x7000_0000, page.len(), &page);
        let bytes = memory
            .read_remote(0x7000_0000, 4)
            .expect("read cached bytes");

        assert_eq!(bytes, vec![0x11, 0x22, 0x33, 0x44]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn capture_sprintf_trace_reads_format_preview() {
        let memory = test_proc_memory_with_path("/apex/com.android.runtime/lib64/bionic/libc.so");
        let registers = regs(&[
            (Reg::X(0), 0x5000),
            (Reg::X(1), 0x6000),
            (Reg::X(30), 0x7000),
        ]);
        let overlay = overlay_bytes(0x6000, b"token=%s\0");

        let trace =
            capture_sprintf_trace(LIBC_SPRINTF_OFFSET, 0x1234, &registers, &overlay, &memory)
                .expect("capture trace")
                .expect("sprintf trace");

        assert_eq!(trace.function, "sprintf");
        assert_eq!(trace.dest_ptr, Some(0x5000));
        assert_eq!(trace.format_ptr, Some(0x6000));
        assert_eq!(trace.return_pc, 0x7000);
        assert_eq!(trace.format_preview.as_deref(), Some("token=%s"));
    }

    #[test]
    fn capture_fopen_trace_reads_path_and_mode_preview() {
        let memory = test_proc_memory_with_path("/apex/com.android.runtime/lib64/bionic/libc.so");
        let registers = regs(&[
            (Reg::X(0), 0x5100),
            (Reg::X(1), 0x5200),
            (Reg::X(30), 0x5300),
        ]);
        let mut overlay = overlay_bytes(0x5100, b"/data/app/test/assets.bin\0");
        overlay.extend(overlay_bytes(0x5200, b"rb\0"));

        let trace = capture_fopen_trace(LIBC_FOPEN_OFFSET, 0x1234, &registers, &overlay, &memory)
            .expect("capture fopen trace")
            .expect("fopen trace");

        assert_eq!(trace.function, "fopen");
        assert_eq!(trace.path_ptr, Some(0x5100));
        assert_eq!(trace.mode_ptr, Some(0x5200));
        assert_eq!(trace.return_pc, 0x5300);
        assert_eq!(
            trace.path_preview.as_deref(),
            Some("/data/app/test/assets.bin")
        );
        assert_eq!(trace.mode_preview.as_deref(), Some("rb"));
    }

    #[test]
    fn fopen_fread_fseek_ftell_and_fclose_stubs_bridge_host_files() {
        let dir = test_temp_dir("fopen_bridge");
        let asset_root = dir.join("mirrored");
        fs::create_dir_all(&asset_root).expect("create asset root");
        let host_file = asset_root.join("payload.bin");
        fs::write(&host_file, b"ABCDEFGH").expect("write host file");

        let memory = test_proc_memory_with_path("/apex/com.android.runtime/lib64/bionic/libc.so");
        let mut clock = test_clock();
        let mut sprintf_trace = None;
        let mut fopen_trace = FopenTraceState::default();
        let mut file_bridge = HostFileBridge::new(
            Vec::new(),
            vec![GuestPathMap {
                guest_prefix: "/data/app/com.netmarble.thered".to_string(),
                host_prefix: asset_root.clone(),
            }],
            None,
        );
        let mut overlay = overlay_bytes(0x5000, b"/data/app/com.netmarble.thered/payload.bin\0");
        overlay.extend(overlay_bytes(0x5100, b"rb\0"));
        let mut fopen_regs = regs(&[
            (Reg::X(0), 0x5000),
            (Reg::X(1), 0x5100),
            (Reg::X(30), 0x5200),
        ]);

        let open = maybe_execute_known_stub_with_io(
            LIBC_FOPEN_OFFSET,
            &mut fopen_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("fopen stub")
        .expect("fopen outcome");
        assert_eq!(open.next_pc, 0x5200);
        let stream = read_u64_reg(&fopen_regs, Reg::X(0)).expect("stream result");
        assert_ne!(stream, 0);
        fopen_trace.finish_ready(0x5200, &fopen_regs);
        assert_eq!(fopen_trace.records.len(), 2);
        assert_eq!(fopen_trace.records[0].phase, "entry");
        assert_eq!(fopen_trace.records[1].phase, "return");

        let mut fread_regs = regs(&[
            (Reg::X(0), 0x5300),
            (Reg::X(1), 2),
            (Reg::X(2), 2),
            (Reg::X(3), stream),
            (Reg::X(30), 0x5400),
        ]);
        let fread = maybe_execute_known_stub_with_io(
            LIBC_FREAD_OFFSET,
            &mut fread_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("fread stub")
        .expect("fread outcome");
        assert_eq!(fread.next_pc, 0x5400);
        assert_eq!(read_u64_reg(&fread_regs, Reg::X(0)), Some(2));
        assert_eq!(
            stub_read_bytes(&overlay, &memory, 0x5300, 4, "test", 0).unwrap(),
            b"ABCD"
        );

        let mut ftell_regs = regs(&[(Reg::X(0), stream), (Reg::X(30), 0x5500)]);
        let ftell = maybe_execute_known_stub_with_io(
            LIBC_FTELL_OFFSET,
            &mut ftell_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("ftell stub")
        .expect("ftell outcome");
        assert_eq!(ftell.next_pc, 0x5500);
        assert_eq!(read_u64_reg(&ftell_regs, Reg::X(0)), Some(4));

        let mut fseek_regs = regs(&[
            (Reg::X(0), stream),
            (Reg::X(1), 1),
            (Reg::X(2), libc::SEEK_SET as u64),
            (Reg::X(30), 0x5600),
        ]);
        let fseek = maybe_execute_known_stub_with_io(
            LIBC_FSEEK_OFFSET,
            &mut fseek_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("fseek stub")
        .expect("fseek outcome");
        assert_eq!(fseek.next_pc, 0x5600);
        assert_eq!(read_u64_reg(&fseek_regs, Reg::X(0)), Some(0));

        let mut fclose_regs = regs(&[(Reg::X(0), stream), (Reg::X(30), 0x5700)]);
        let fclose = maybe_execute_known_stub_with_io(
            LIBC_FCLOSE_OFFSET,
            &mut fclose_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("fclose stub")
        .expect("fclose outcome");
        assert_eq!(fclose.next_pc, 0x5700);
        assert_eq!(read_u64_reg(&fclose_regs, Reg::X(0)), Some(0));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn open_read_lseek_and_close_stubs_bridge_host_files() {
        let dir = test_temp_dir("open_bridge");
        let root = dir.join("root");
        let guest_rel = Path::new("system/etc/hash-seed.bin");
        let host_file = root.join(guest_rel);
        fs::create_dir_all(host_file.parent().expect("host file parent"))
            .expect("create file root");
        fs::write(&host_file, b"0123456789").expect("write bridge file");

        let memory = test_proc_memory_with_path("/system/lib64/libc.so");
        let mut clock = test_clock();
        let mut sprintf_trace = None;
        let mut fopen_trace = FopenTraceState::default();
        let mut file_bridge = HostFileBridge::new(vec![root.clone()], Vec::new(), None);
        let mut overlay = overlay_bytes(0x6000, b"/system/etc/hash-seed.bin\0");
        let mut open_regs = regs(&[
            (Reg::X(0), 0x6000),
            (Reg::X(1), libc::O_RDONLY as u64),
            (Reg::X(30), 0x6100),
        ]);

        let open = maybe_execute_known_stub_with_io(
            LIBC_OPEN_OFFSET,
            &mut open_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("open stub")
        .expect("open outcome");
        assert_eq!(open.next_pc, 0x6100);
        let fd = read_u64_reg(&open_regs, Reg::X(0)).expect("open fd") as i32;
        assert!(fd >= 3);

        let mut read_regs = regs(&[
            (Reg::X(0), fd as u64),
            (Reg::X(1), 0x6200),
            (Reg::X(2), 5),
            (Reg::X(30), 0x6300),
        ]);
        let read = maybe_execute_known_stub_with_io(
            LIBC_READ_OFFSET,
            &mut read_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("read stub")
        .expect("read outcome");
        assert_eq!(read.next_pc, 0x6300);
        assert_eq!(read_u64_reg(&read_regs, Reg::X(0)), Some(5));
        assert_eq!(
            stub_read_bytes(&overlay, &memory, 0x6200, 5, "test", 0).unwrap(),
            b"01234"
        );

        let mut lseek_regs = regs(&[
            (Reg::X(0), fd as u64),
            (Reg::X(1), 2),
            (Reg::X(2), libc::SEEK_SET as u64),
            (Reg::X(30), 0x6400),
        ]);
        let lseek = maybe_execute_known_stub_with_io(
            LIBC_LSEEK_OFFSET,
            &mut lseek_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("lseek stub")
        .expect("lseek outcome");
        assert_eq!(lseek.next_pc, 0x6400);
        assert_eq!(read_u64_reg(&lseek_regs, Reg::X(0)), Some(2));

        let mut close_regs = regs(&[(Reg::X(0), fd as u64), (Reg::X(30), 0x6500)]);
        let close = maybe_execute_known_stub_with_io(
            LIBC_CLOSE_OFFSET,
            &mut close_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("close stub")
        .expect("close outcome");
        assert_eq!(close.next_pc, 0x6500);
        assert_eq!(read_u64_reg(&close_regs, Reg::X(0)), Some(0));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn aasset_stubs_resolve_suffix_named_nmss_assets() {
        let dir = test_temp_dir("aasset_bridge");
        let bins = dir.join("bins");
        fs::create_dir_all(&bins).expect("create bins dir");
        let host_file = bins.join("0a8a78ae_nmsscr.nmss");
        fs::write(&host_file, b"NMSSDATA").expect("write nmss asset");

        let memory = test_proc_memory_with_path("/system/lib64/libandroid.so");
        let mut clock = test_clock();
        let mut sprintf_trace = None;
        let mut fopen_trace = FopenTraceState::default();
        let mut file_bridge = HostFileBridge::new(vec![bins.clone()], Vec::new(), None);
        let mut overlay = overlay_bytes(0x7000, b"nmsscr.nmss\0");

        let mut open_regs = regs(&[
            (Reg::X(0), 0),
            (Reg::X(1), 0x7000),
            (Reg::X(2), 0),
            (Reg::X(30), 0x7100),
        ]);
        let open = maybe_execute_known_stub_with_io(
            LIBANDROID_AASSET_MANAGER_OPEN_OFFSET,
            &mut open_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("AAssetManager_open stub")
        .expect("AAssetManager_open outcome");
        assert_eq!(open.next_pc, 0x7100);
        let handle = read_u64_reg(&open_regs, Reg::X(0)).expect("asset handle");
        assert_ne!(handle, 0);

        let mut len_regs = regs(&[(Reg::X(0), handle), (Reg::X(30), 0x7200)]);
        let get_len = maybe_execute_known_stub_with_io(
            LIBANDROID_AASSET_GET_LENGTH_OFFSET,
            &mut len_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("AAsset_getLength stub")
        .expect("AAsset_getLength outcome");
        assert_eq!(get_len.next_pc, 0x7200);
        assert_eq!(read_u64_reg(&len_regs, Reg::X(0)), Some(8));

        let mut read_regs = regs(&[
            (Reg::X(0), handle),
            (Reg::X(1), 0x7300),
            (Reg::X(2), 4),
            (Reg::X(30), 0x7400),
        ]);
        let read = maybe_execute_known_stub_with_io(
            LIBANDROID_AASSET_READ_OFFSET,
            &mut read_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("AAsset_read stub")
        .expect("AAsset_read outcome");
        assert_eq!(read.next_pc, 0x7400);
        assert_eq!(read_u64_reg(&read_regs, Reg::X(0)), Some(4));
        assert_eq!(
            stub_read_bytes(&overlay, &memory, 0x7300, 4, "test", 0).unwrap(),
            b"NMSS"
        );

        let mut close_regs = regs(&[(Reg::X(0), handle), (Reg::X(30), 0x7500)]);
        let close = maybe_execute_known_stub_with_io(
            LIBANDROID_AASSET_CLOSE_OFFSET,
            &mut close_regs,
            &mut overlay,
            &memory,
            &mut clock,
            &mut sprintf_trace,
            &mut fopen_trace,
            &mut file_bridge,
        )
        .expect("AAsset_close stub")
        .expect("AAsset_close outcome");
        assert_eq!(close.next_pc, 0x7500);
        assert_eq!(read_u64_reg(&close_regs, Reg::X(0)), Some(0));
        let _ = fs::remove_dir_all(dir);
    }
}
