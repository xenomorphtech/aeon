// frida_trace — load a Frida capture and run the instrumented engine
//
// Workflow:
//   1. On device: python3 frida/nmss_capture.py
//   2. Trace:     cargo run --example frida_trace -- ./capture/sub_20bb48/
//
// The Frida capture contains real runtime memory (relocated GOT, initialized
// globals, actual register state), so the engine can trace far deeper than
// with a static binary load.
//
// Memory regions are mmap'd at their original runtime addresses so the
// JIT-compiled code (which does real x86_64 memory ops) hits valid memory.

use std::env;
use std::path::PathBuf;
use std::process;

use aeon_instrument::engine::{EngineConfig, InstrumentEngine, StopReason};
use aeon_instrument::snapshot::{load_capture, MappedCapture};
use aeon_instrument::trace::read_trace_file;

const READBACK_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

fn parse_u64_arg(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| format!("invalid hex value '{}': {}", s, e))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("invalid integer value '{}': {}", s, e))
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: frida_trace <capture_dir> [--binary <decrypted.elf>] [--code-range <start> <end>] [trace_output]"
        );
        eprintln!();
        eprintln!("  capture_dir   Directory with snapshot.json + region .bin files");
        eprintln!("  --binary      Decrypted binary for code (replaces packed module code)");
        eprintln!("  --code-range  Inclusive start / exclusive end PC range to trace");
        eprintln!("  trace_output  Path for output trace file (default: <capture_dir>/trace.bin)");
        process::exit(1);
    }

    let capture_dir = PathBuf::from(&args[1]);
    let mut decrypted_binary: Option<String> = None;
    let mut manual_code_range: Option<(u64, u64)> = None;
    let mut trace_output = capture_dir.join("trace.bin");
    let mut trace_output_explicit = false;

    let mut i = 2;
    while i < args.len() {
        if args[i] == "--binary" && i + 1 < args.len() {
            decrypted_binary = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--code-range" && i + 2 < args.len() {
            let start = match parse_u64_arg(&args[i + 1]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}", e);
                    process::exit(1);
                }
            };
            let end = match parse_u64_arg(&args[i + 2]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}", e);
                    process::exit(1);
                }
            };
            if start >= end {
                eprintln!(
                    "invalid --code-range: start 0x{:x} must be below end 0x{:x}",
                    start, end
                );
                process::exit(1);
            }
            manual_code_range = Some((start, end));
            i += 3;
        } else if args[i].starts_with("--") {
            eprintln!("unknown option: {}", args[i]);
            process::exit(1);
        } else {
            if trace_output_explicit {
                eprintln!("unexpected extra positional argument: {}", args[i]);
                process::exit(1);
            }
            trace_output = PathBuf::from(&args[i]);
            trace_output_explicit = true;
            i += 1;
        }
    }

    // Load the capture
    let (mut ctx, meta) = match load_capture(&capture_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error loading capture: {}", e);
            process::exit(1);
        }
    };

    eprintln!(
        "function: {}  pc: {}  sp: {}",
        meta.function_name, meta.registers.pc, meta.registers.sp
    );
    if let Some(ref name) = meta.module_name {
        eprintln!(
            "module: {} base: {}",
            name,
            meta.module_base.as_deref().unwrap_or("?")
        );
    }
    let code_alias_base = match (
        meta.analysis_base.as_deref(),
        meta.jit_base.as_deref().or(meta.module_base.as_deref()),
    ) {
        (Some(from_base), Some(to_base)) => {
            let from_base = match parse_u64_arg(from_base) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("invalid analysis_base in snapshot.json: {}", e);
                    process::exit(1);
                }
            };
            let to_base = match parse_u64_arg(to_base) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("invalid jit/module base in snapshot.json: {}", e);
                    process::exit(1);
                }
            };
            Some((from_base, to_base))
        }
        _ => None,
    };
    let code_range = if let Some(range) = manual_code_range {
        Some(range)
    } else {
        match (
            meta.code_range_start.as_deref(),
            meta.code_range_end.as_deref(),
        ) {
            (Some(start), Some(end)) => {
                let start = match parse_u64_arg(start) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("invalid code_range_start in snapshot.json: {}", e);
                        process::exit(1);
                    }
                };
                let end = match parse_u64_arg(end) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("invalid code_range_end in snapshot.json: {}", e);
                        process::exit(1);
                    }
                };
                if start >= end {
                    eprintln!(
                        "invalid code range in snapshot.json: start 0x{:x} must be below end 0x{:x}",
                        start, end
                    );
                    process::exit(1);
                }
                Some((start, end))
            }
            _ => None,
        }
    };
    if let Some((start, end)) = code_range {
        eprintln!("code range: 0x{:x}..0x{:x}", start, end);
    }
    if let Some((from_base, to_base)) = code_alias_base {
        eprintln!("code alias: 0x{:x} -> 0x{:x}", from_base, to_base);
    }

    // mmap captured regions at their runtime addresses for JIT execution
    let _mapped = match MappedCapture::map(&mut ctx, &meta, &capture_dir) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error mapping regions: {}", e);
            process::exit(1);
        }
    };

    // If a decrypted binary is provided, overlay its segments at the module base.
    // This replaces the packed/trampolined code with the real decrypted instructions.
    // We mmap full segments and copy decrypted data into them.
    let mut _overlay_maps: Vec<(*mut std::ffi::c_void, usize)>;
    if let Some(ref bin_path) = decrypted_binary {
        let base = meta
            .module_base
            .as_ref()
            .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok())
            .expect("module_base required when using --binary");

        let binary = aeon::elf::load_elf(bin_path).expect("load decrypted binary");
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
        let mut overlay_regions = Vec::new();

        // mmap + overlay each segment from the decrypted binary
        for seg in &binary.segments {
            if seg.mem_size == 0 {
                continue;
            }
            let runtime_addr = base + seg.vaddr;
            let start = runtime_addr & !(page_size - 1);
            let end = (runtime_addr + seg.mem_size + page_size - 1) & !(page_size - 1);
            let len = (end - start) as usize;

            let mapped = unsafe {
                libc::mmap(
                    start as *mut std::ffi::c_void,
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                eprintln!("warning: overlay mmap failed at 0x{:x}", start);
                continue;
            }
            overlay_regions.push((mapped, len));

            // Copy file data
            if seg.file_size > 0 {
                let src_start = seg.file_offset as usize;
                let src_len = seg.file_size as usize;
                if src_start + src_len <= binary.data.len() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            binary.data[src_start..].as_ptr(),
                            runtime_addr as *mut u8,
                            src_len,
                        );
                    }
                }
            }
            eprintln!(
                "overlay segment at 0x{:x} ({} bytes)",
                runtime_addr, seg.mem_size
            );
        }
        _overlay_maps = overlay_regions;

        // Build merged memory: captured module data (has relocated GOT) with
        // decrypted code overlaid on top (replaces trampolines with real instructions).
        let mut new_mem = aeon_instrument::context::SnapshotMemory::new();

        // Add non-module regions (TLS, args, stack)
        for region in &meta.regions {
            if region.label.as_deref() == Some("module") {
                continue;
            }
            let addr =
                u64::from_str_radix(region.address.trim_start_matches("0x"), 16).unwrap_or(0);
            let file_path = capture_dir.join(&region.file);
            if let Ok(data) = std::fs::read(&file_path) {
                new_mem.add_region(addr, data);
            }
        }

        // Build the merged module region:
        // Start with captured module data (has runtime GOT values)
        let captured_module = meta
            .regions
            .iter()
            .find(|r| r.label.as_deref() == Some("module"));
        let mut module_data = if let Some(mod_region) = captured_module {
            std::fs::read(capture_dir.join(&mod_region.file)).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Only overlay CODE from the decrypted binary, preserving the captured
        // module's DATA section (which has runtime-relocated GOT entries).
        // The packed module has data sections starting around file offset 0x388000
        // (the r--p and rw-p segments). Don't overwrite those.
        if let Some(seg) = binary.segments.first() {
            if seg.file_size > 0 {
                let vaddr = seg.vaddr as usize;
                let src_start = seg.file_offset as usize;
                let src_len = seg.file_size as usize;
                if src_start + src_len <= binary.data.len() {
                    // Find where the captured module's data section starts
                    // by looking for the boundary in the captured module.
                    // The data section is typically at the last ~256KB of the module.
                    // Use the captured module size as a conservative upper bound for code.
                    let captured_len = module_data.len();
                    let data_section_offset = if captured_len > 0x40000 {
                        // Heuristic: data section starts around 0x388000 for this binary.
                        // More precisely: find where code ends and data begins.
                        // The last code segment ends before the data, with a small gap.
                        // Use 0x388000 as the cutoff for libnmsssa.so.
                        0x388000usize
                    } else {
                        captured_len
                    };

                    let overlay_len = src_len.min(data_section_offset);
                    let needed = vaddr + overlay_len;
                    if needed > module_data.len() {
                        module_data.resize(needed, 0);
                    }
                    module_data[vaddr..vaddr + overlay_len]
                        .copy_from_slice(&binary.data[src_start..src_start + overlay_len]);
                    eprintln!(
                        "overlaid code: {} bytes (truncated at data section 0x{:x})",
                        overlay_len, data_section_offset
                    );
                }
            }
        }

        // Also overlay the mmap'd region with the merged data
        let overlay_len = module_data
            .len()
            .min(_overlay_maps.iter().map(|&(_, len)| len).sum::<usize>());
        if overlay_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(module_data.as_ptr(), base as *mut u8, overlay_len);
            }
        }

        new_mem.add_region(base, module_data);

        // Also add the decrypted binary's data segment at its VA offset.
        // This provides initialized flags/constants that the code reads
        // (e.g., the initialization flag at 0x4e8d58 that gates the obfuscated path).
        // It doesn't overlap with the captured module data (which ends around 0x3c5000).
        if binary.segments.len() > 1 {
            let data_seg = &binary.segments[1];
            let data_addr = base + data_seg.vaddr;
            let src_start = data_seg.file_offset as usize;
            let src_len = data_seg.file_size as usize;
            if src_start + src_len <= binary.data.len() {
                let mut data = binary.data[src_start..src_start + src_len].to_vec();
                data.resize(data_seg.mem_size as usize, 0);

                // Also mmap this region for JIT memory access
                let ds_start = data_addr & !(page_size - 1);
                let ds_end = (data_addr + data.len() as u64 + page_size - 1) & !(page_size - 1);
                let ds_len = (ds_end - ds_start) as usize;
                let ds_mapped = unsafe {
                    libc::mmap(
                        ds_start as *mut std::ffi::c_void,
                        ds_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                if ds_mapped != libc::MAP_FAILED {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            data.as_ptr(),
                            data_addr as *mut u8,
                            data.len(),
                        );
                    }
                    _overlay_maps.push((ds_mapped, ds_len));
                }

                // Patch the initialization flag at 0x4e8d58 to 0xFF
                // (simulates post-initialization state so the obfuscated path is taken).
                let flag_offset = (0x4e8d58 - data_seg.vaddr) as usize;
                if flag_offset < data.len() {
                    data[flag_offset] = 0xFF;
                    // Also patch in the mmap'd region
                    unsafe {
                        *((data_addr + flag_offset as u64) as *mut u8) = 0xFF;
                    }
                    eprintln!("patched init flag at 0x4e8d58 → 0xFF");
                }

                new_mem.add_region(data_addr, data);
                eprintln!(
                    "added data segment at 0x{:x} ({} bytes)",
                    data_addr, data_seg.mem_size
                );
            }
        }

        ctx.memory = Box::new(new_mem);
        eprintln!("overlaid decrypted binary at base 0x{:x}", base);
    } else {
        _overlay_maps = Vec::new();
    }

    // Configure engine
    let config = EngineConfig {
        max_steps: 500_000,
        max_memory_ops: 5_000_000,
        max_block_visits: 2_000,
        breakpoints: Vec::new(),
        code_range,
        code_alias_base,
        trace_output: Some(trace_output.clone()),
        drain_interval: 8192,
    };

    let mut engine = InstrumentEngine::new(ctx).with_config(config);

    eprintln!("running engine (max {} steps)...", engine.config.max_steps);
    let reason = engine.run();

    // Summary
    let writer = engine.trace_writer().unwrap();
    let entries = writer.entries_written();
    let bytes = writer.bytes_written();
    let unique = engine.trace().unique_blocks().len();

    eprintln!();
    eprintln!("=== trace complete ===");
    eprintln!("stop reason:    {:?}", reason);
    eprintln!("blocks traced:  {}", entries);
    eprintln!("unique blocks:  {}", unique);
    eprintln!(
        "memory ops:     {} reads + {} writes",
        engine.trace().total_memory_reads,
        engine.trace().total_memory_writes
    );
    eprintln!(
        "trace file:     {} ({:.1} KB)",
        trace_output.display(),
        bytes as f64 / 1024.0
    );

    // Avoid deserializing the entire trace file back into RAM for large runs.
    if bytes <= READBACK_LIMIT_BYTES {
        match read_trace_file(&trace_output) {
            Ok(traces) => {
                eprintln!("verified:       {} entries readable", traces.len());
            }
            Err(e) => {
                eprintln!("warning: could not re-read trace file: {}", e);
            }
        }
    } else {
        eprintln!(
            "verified:       skipped full readback ({:.1} MB exceeds {:.1} MB limit)",
            bytes as f64 / 1024.0 / 1024.0,
            READBACK_LIMIT_BYTES as f64 / 1024.0 / 1024.0
        );
    }

    // Print block visit summary from the in-memory counters, which survive drains.
    let visits = engine.trace().visit_counts();
    let mut sorted: Vec<_> = visits.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    if !sorted.is_empty() {
        eprintln!();
        eprintln!("hottest blocks (top 20):");
        for (addr, count) in sorted.iter().take(20) {
            eprintln!("  0x{:x}  {} visits", addr, count);
        }
    }

    // Run symbolic analysis on whatever blocks are still in memory
    let fold = engine.fold();
    if fold.invariants.is_empty() {
        eprintln!("\nno invariants found (blocks may have been drained to disk)");
    } else {
        eprintln!();
        eprintln!("symbolic analysis (in-memory blocks):");
        eprintln!("  constant registers:    {}", fold.constant_registers);
        eprintln!("  constant memory:       {}", fold.constant_memory);
        eprintln!("  resolved branches:     {}", fold.resolved_branches);
        eprintln!("  induction variables:   {}", fold.induction_variables);
        eprintln!("  dataflow edges:        {}", fold.dataflow_edges);
    }

    // Exit with appropriate code
    match reason {
        StopReason::Halted => process::exit(0),
        StopReason::MaxSteps
        | StopReason::MaxBlockVisits(_)
        | StopReason::MaxMemoryOps
        | StopReason::CodeRangeExit(_) => process::exit(0),
        StopReason::Breakpoint(_) => process::exit(0),
        StopReason::IoError(ref e) => {
            eprintln!("I/O error: {}", e);
            process::exit(1)
        }
        StopReason::LiftError(addr, ref e) => {
            eprintln!("lift error at 0x{:x}: {}", addr, e);
            process::exit(2)
        }
        StopReason::UnmappedMemory(addr) => {
            eprintln!("unmapped memory at 0x{:x}", addr);
            process::exit(2)
        }
    }
}
