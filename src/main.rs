use aeon::engine::AeonEngine;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("rc4");
    let binary_path = args.get(2).map(|s| s.as_str()).unwrap_or("libUnreal.so");

    let mut engine = AeonEngine::new();

    eprintln!("Loading {}...", binary_path);
    if let Err(e) = engine.load_binary(binary_path) {
        eprintln!("Failed to load binary: {}", e);
        std::process::exit(1);
    }

    match mode {
        "coverage" => {
            eprintln!("Scanning all instructions...");
            let report = engine.coverage_report();
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        "rc4" => {
            eprintln!("Searching for RC4 implementations...");
            let report = aeon::rc4_search::search(engine.binary.as_ref().unwrap());
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        "func" => {
            let addr_str = args.get(3).expect("usage: aeon func <binary> <addr>");
            let addr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
                .expect("invalid hex address");
            engine.ingest_function_by_addr(addr);
            let details = engine.get_function_details(addr);
            println!("{}", serde_json::to_string_pretty(&details).unwrap());
        }
        _ => {
            eprintln!("Usage: aeon <coverage|rc4|func> [binary] [addr]");
            std::process::exit(1);
        }
    }
}
