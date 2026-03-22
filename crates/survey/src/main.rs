use std::collections::HashMap;

use aeon::elf::load_elf;
use serde_json::json;

struct Args {
    binary_path: String,
    limit: Option<usize>,
    json_output: bool,
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{}", message);
            std::process::exit(1);
        }
    };

    let binary = match load_elf(&args.binary_path) {
        Ok(binary) => binary,
        Err(error) => {
            eprintln!("Failed to load ELF: {}", error);
            std::process::exit(1);
        }
    };

    let text = binary.text_bytes();
    let base_addr = binary.text_section_addr;

    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut decode_errors: u64 = 0;

    let words = text.len() / 4;
    for i in 0..words {
        let off = i * 4;
        let word = u32::from_le_bytes(text[off..off + 4].try_into().unwrap());
        let vaddr = base_addr + off as u64;
        match bad64::decode(word, vaddr) {
            Ok(insn) => {
                let name = format!("{:?}", insn.op());
                *counts.entry(name).or_insert(0) += 1;
            }
            Err(_) => decode_errors += 1,
        }
    }

    let mut sorted: Vec<(String, u64)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    if args.json_output {
        let counts = sorted
            .iter()
            .take(args.limit.unwrap_or(sorted.len()))
            .map(|(opcode, count)| {
                json!({
                    "opcode": opcode,
                    "count": count,
                })
            })
            .collect::<Vec<_>>();

        let output = json!({
            "path": args.binary_path,
            "text_section_addr": format!("0x{:x}", binary.text_section_addr),
            "text_section_size": format!("0x{:x}", binary.text_section_size),
            "total_words": words,
            "decode_errors": decode_errors,
            "unique_opcodes": sorted.len(),
            "counts": counts,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    println!("ARM64 opcode survey");
    println!("  Binary      : {}", args.binary_path);
    println!("  .text addr  : 0x{:x}", binary.text_section_addr);
    println!(
        "  .text size  : 0x{:x} ({} bytes)",
        binary.text_section_size, binary.text_section_size
    );
    println!("  Total words : {}", words);
    println!("  Decode errors (undefined/data): {}", decode_errors);
    println!("  Unique opcodes: {}", sorted.len());
    println!();
    println!("{:<40} {:>12}", "OPCODE", "COUNT");
    println!("{}", "-".repeat(54));

    let limit = args.limit.unwrap_or(sorted.len());
    for (opcode, count) in sorted.iter().take(limit) {
        println!("{:<40} {:>12}", opcode, count);
    }
}

fn parse_args() -> Result<Args, String> {
    let mut binary_path = None;
    let mut limit = None;
    let mut json_output = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" | "help" => return Err(usage()),
            "--json" => json_output = true,
            "--limit" => {
                let value = args.next().ok_or_else(usage)?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid value for --limit: {}", value))?;
                limit = Some(parsed);
            }
            _ if binary_path.is_none() => binary_path = Some(arg),
            _ => return Err(usage()),
        }
    }

    let binary_path = binary_path.ok_or_else(usage)?;
    Ok(Args {
        binary_path,
        limit,
        json_output,
    })
}

fn usage() -> String {
    [
        "Usage:",
        "  survey <binary> [--limit <count>] [--json]",
    ]
    .join("\n")
}
