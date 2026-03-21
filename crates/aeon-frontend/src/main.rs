fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("rc4");
    let binary_path = args.get(2).map(|s| s.as_str()).unwrap_or("libUnreal.so");

    eprintln!("Loading {}...", binary_path);
    let session = match aeon::AeonSession::load(binary_path) {
        Ok(session) => session,
        Err(e) => {
            eprintln!("Failed to load binary: {}", e);
            std::process::exit(1);
        }
    };

    let output = match mode {
        "coverage" => {
            eprintln!("Scanning all instructions...");
            session.get_coverage()
        }
        "rc4" => {
            eprintln!("Searching for RC4 implementations...");
            session.search_rc4()
        }
        "func" => {
            let addr_str = args.get(3).expect("usage: aeon func <binary> <addr>");
            let addr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
                .expect("invalid hex address");
            match session.get_function_details(addr) {
                Ok(details) => details,
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("Usage: aeon <coverage|rc4|func> [binary] [addr]");
            std::process::exit(1);
        }
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
