//! A hostile binary must not take down a persistent session.
//!
//! The sample ELF is corrupted in seeded, reproducible ways (headers, section
//! table, unwind tables, code, truncation) and every read-only tool is run
//! against each mutant. A tool may fail, but it has to fail with an error:
//! no panic may reach the service boundary.
//!
//! `AEON_HOSTILE_ITERS` overrides the number of mutants.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aeon_service::service::AeonFrontend;
use serde_json::{json, Value};

fn sample() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../samples/hello_aarch64.elf");
    std::fs::read(path).expect("sample ELF")
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// File ranges worth corrupting in the sample: ELF and program headers, the
/// dynamic symbol table, code, unwind tables, and the section header table
/// at the end of the file.
fn regions(len: usize) -> [(usize, usize); 6] {
    [
        (0, 0x200),
        (0x2b8, 0x2b8 + 0xd8),
        (0x600, 0x600 + 0x21c),
        (0x870, 0x9a4),
        (len - 0x1000, len),
        (0, len),
    ]
}

fn mutate(original: &[u8], seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut data = original.to_vec();
    let (start, end) = regions(data.len())[rng.below(6)];
    for _ in 0..1 + rng.below(8) {
        let at = start + rng.below(end - start);
        data[at] = match rng.below(4) {
            0 => 0x00,
            1 => 0xff,
            _ => rng.next() as u8,
        };
    }
    if rng.below(8) == 0 {
        let keep = 1 + rng.below(data.len());
        data.truncate(keep);
    }
    data
}

fn calls(addrs: &[String]) -> Vec<(&'static str, Value)> {
    let mut calls = vec![
        ("list_functions", json!({})),
        ("scan_pointers", json!({})),
        ("scan_vtables", json!({})),
        ("search_rc4", json!({})),
        ("get_coverage", json!({})),
        ("get_function_pointers", json!({})),
    ];
    for addr in addrs {
        for tool in [
            "get_il",
            "get_reduced_il",
            "get_stack_frame",
            "get_function_cfg",
            "get_function_skeleton",
            "get_xrefs",
            "get_blackboard_entry",
        ] {
            calls.push((tool, json!({ "addr": addr })));
        }
        calls.push(("get_ssa", json!({ "addr": addr, "optimize": true })));
        calls.push((
            "get_function_at",
            json!({ "addr": addr, "include_asm": true, "include_il": true }),
        ));
        calls.push(("get_function_pointers", json!({ "addr": addr })));
        calls.push((
            "get_data_flow_slice",
            json!({ "addr": addr, "register": "x0", "direction": "backward" }),
        ));
        calls.push(("get_bytes", json!({ "addr": addr, "size": 64 })));
        calls.push(("get_data", json!({ "addr": addr, "size": 64 })));
        calls.push(("get_string", json!({ "addr": addr, "max_len": 64 })));
        let start = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap();
        let end = format!("0x{:x}", start.saturating_add(0x40));
        calls.push((
            "emulate_snippet_il",
            json!({ "start_addr": addr, "end_addr": end, "step_limit": 200 }),
        ));
        calls.push((
            "emulate_snippet_native",
            json!({ "start_addr": addr, "end_addr": end, "step_limit": 200 }),
        ));
        calls.push(("get_asm", json!({ "start_addr": addr, "stop_addr": end })));
    }
    if let [first, .., last] = addrs {
        calls.push((
            "get_asm",
            json!({ "start_addr": first, "stop_addr": last }),
        ));
        calls.push((
            "find_call_paths",
            json!({ "start_addr": first, "goal_addr": last }),
        ));
    }
    calls
}

#[test]
fn corrupted_binaries_fail_with_errors_not_panics() {
    let iterations: u64 = std::env::var("AEON_HOSTILE_ITERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300);
    let original = sample();
    let dir = std::env::temp_dir().join(format!("aeon-hostile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("mutant.elf");

    // Record where panics happen instead of printing a backtrace for each.
    let seen: Arc<Mutex<BTreeSet<String>>> = Arc::default();
    let sink = seen.clone();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        sink.lock().unwrap().insert(at);
    }));

    let mut failures = Vec::new();
    let mut loaded = 0;
    // `AEON_HOSTILE_SEED` replays a single mutant.
    let only: Option<u64> = std::env::var("AEON_HOSTILE_SEED")
        .ok()
        .and_then(|value| value.parse().ok());
    let seeds = match only {
        Some(seed) => seed..seed + 1,
        None => 0..iterations,
    };
    let iterations = seeds.end - seeds.start;
    for seed in seeds {
        let trace = std::env::var_os("AEON_HOSTILE_TRACE").is_some();
        if trace {
            eprintln!("seed {seed}: mutate");
        }
        std::fs::write(&path, mutate(&original, seed)).unwrap();
        if trace {
            eprintln!("seed {seed}: load");
        }
        let mut service = AeonFrontend::new();
        let load = json!({ "path": path.to_str().unwrap() });
        let mut run = |service: &mut AeonFrontend, tool: &'static str, args: &Value| {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                service.call_tool_typed(tool, args)
            }));
            match outcome {
                Ok(Ok(value)) => Some(value),
                Ok(Err(error)) => {
                    if trace {
                        eprintln!("  {tool} failed: {}", error.message);
                    }
                    if error.message.contains("panicked") {
                        failures.push(format!("seed {seed}: {tool}: {}", error.message));
                    }
                    None
                }
                Err(_) => {
                    failures.push(format!("seed {seed}: {tool} panicked"));
                    None
                }
            }
        };
        if run(&mut service, "load_binary", &load).is_none() {
            continue;
        }
        loaded += 1;
        if trace {
            eprintln!("seed {seed}: loaded");
        }

        // Addresses the mutant itself advertises, plus ones that were
        // functions, data and nothing at all in the original.
        let mut addrs: Vec<String> = run(&mut service, "list_functions", &json!({ "limit": 4 }))
            .and_then(|value| value["functions"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|function| function["addr"].as_str().map(str::to_string))
            .collect();
        if trace {
            eprintln!("seed {seed}: addrs {addrs:?}");
        }
        addrs.extend(["0x600", "0x788", "0x830", "0x8c0", "0xfffffffffffffff8"].map(String::from));

        for (tool, args) in calls(&addrs) {
            if trace {
                eprintln!("seed {seed}: {tool} {args}");
            }
            run(&mut service, tool, &args);
        }
    }

    std::panic::set_hook(previous);
    let _ = std::fs::remove_dir_all(&dir);
    let seen = seen.lock().unwrap();
    assert!(
        failures.is_empty(),
        "{} panics at {:#?}\nfirst failures: {:#?}",
        failures.len(),
        *seen,
        &failures[..failures.len().min(10)]
    );
    // The mutations must not be so destructive that nothing gets past the
    // loader, or the tools are not being exercised.
    assert!(loaded * 4 >= iterations, "only {loaded} of {iterations} mutants loaded");
}
