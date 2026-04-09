use aeon_instrument::context::SnapshotMemory;
use aeon_instrument::dynruntime::{DynamicRuntime, DynamicRuntimeConfig, DynamicRuntimeStop};
use aeon_jit::JitContext;
use std::env;
use std::fs;
use std::process;

fn usage() -> ! {
    eprintln!(
        "usage: jit_dynamic_replay --input <blob.bin> --base <hex> --pc <hex> [--max-steps <n>]"
    );
    process::exit(2);
}

fn parse_hex(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(digits, 16).map_err(|err| format!("invalid hex '{value}': {err}"))
}

fn parse_usize(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|err| format!("invalid usize '{value}': {err}"))
}

fn stop_label(stop: &DynamicRuntimeStop) -> String {
    match stop {
        DynamicRuntimeStop::Halted => "halted".to_string(),
        DynamicRuntimeStop::MaxSteps => "max_steps".to_string(),
        DynamicRuntimeStop::CodeRangeExit(pc) => format!("code_range_exit@0x{pc:x}"),
        DynamicRuntimeStop::LiftError(pc, err) => format!("lift_error@0x{pc:x}:{err}"),
    }
}

fn main() {
    let mut input = None::<String>;
    let mut base = None::<u64>;
    let mut pc = None::<u64>;
    let mut max_steps = 4096usize;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => input = args.next(),
            "--base" => {
                let value = args.next().unwrap_or_else(|| usage());
                base = Some(parse_hex(&value).unwrap_or_else(|err| {
                    eprintln!("{err}");
                    process::exit(2);
                }));
            }
            "--pc" => {
                let value = args.next().unwrap_or_else(|| usage());
                pc = Some(parse_hex(&value).unwrap_or_else(|err| {
                    eprintln!("{err}");
                    process::exit(2);
                }));
            }
            "--max-steps" => {
                let value = args.next().unwrap_or_else(|| usage());
                max_steps = parse_usize(&value).unwrap_or_else(|err| {
                    eprintln!("{err}");
                    process::exit(2);
                });
            }
            "--help" | "-h" => usage(),
            other => {
                eprintln!("unexpected arg: {other}");
                usage();
            }
        }
    }

    let input = input.unwrap_or_else(|| usage());
    let base = base.unwrap_or_else(|| usage());
    let pc = pc.unwrap_or_else(|| usage());

    let blob = fs::read(&input).unwrap_or_else(|err| {
        eprintln!("failed to read {input}: {err}");
        process::exit(1);
    });

    let mut mem = SnapshotMemory::new();
    mem.add_region(base, blob.clone());

    let mut ctx = JitContext::default();
    ctx.pc = pc;

    let mut runtime = DynamicRuntime::new();
    let result = runtime.run(
        &mut ctx,
        &mem,
        DynamicRuntimeConfig {
            max_steps,
            code_range: Some((base, base + blob.len() as u64)),
        },
    );

    println!("start_pc=0x{:x}", result.start_pc);
    println!("final_pc=0x{:x}", result.final_pc);
    println!("steps={}", result.steps);
    println!("compiled_blocks={}", result.compiled_blocks);
    println!("stop={}", stop_label(&result.stop));
    for pc in result.path {
        println!("path=0x{pc:x}");
    }
}
