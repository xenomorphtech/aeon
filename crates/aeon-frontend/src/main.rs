enum Command {
    Coverage { binary_path: String },
    Rc4 { binary_path: String },
    Func { binary_path: String, addr: u64 },
    Help,
}

fn main() {
    let command = match parse_args() {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{}", message);
            std::process::exit(1);
        }
    };

    if let Command::Help = command {
        println!("{}", usage());
        return;
    }

    let binary_path = match &command {
        Command::Coverage { binary_path }
        | Command::Rc4 { binary_path }
        | Command::Func { binary_path, .. } => binary_path,
        Command::Help => unreachable!(),
    };

    eprintln!("Loading {}...", binary_path);
    let session = match aeon::AeonSession::load(binary_path) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("Failed to load binary: {}", error);
            std::process::exit(1);
        }
    };

    let output = match command {
        Command::Coverage { .. } => {
            eprintln!("Scanning all instructions...");
            session.get_coverage()
        }
        Command::Rc4 { .. } => {
            eprintln!("Searching for RC4 implementations...");
            session.search_rc4()
        }
        Command::Func { addr, .. } => match session.get_function_details(addr) {
            Ok(details) => details,
            Err(error) => {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        },
        Command::Help => unreachable!(),
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn parse_args() -> Result<Command, String> {
    let mut args = std::env::args().skip(1);
    let Some(mode) = args.next() else {
        return Err(usage());
    };

    if matches!(mode.as_str(), "-h" | "--help" | "help") {
        return Ok(Command::Help);
    }

    match mode.as_str() {
        "coverage" => {
            let binary_path = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            Ok(Command::Coverage { binary_path })
        }
        "rc4" => {
            let binary_path = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            Ok(Command::Rc4 { binary_path })
        }
        "func" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let addr_str = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            let addr = parse_hex_addr(&addr_str)?;
            Ok(Command::Func { binary_path, addr })
        }
        _ => Err(usage()),
    }
}

fn parse_hex_addr(value: &str) -> Result<u64, String> {
    let trimmed = value.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(trimmed, 16).map_err(|_| format!("invalid hex address: {}", value))
}

fn usage() -> String {
    [
        "Usage:",
        "  aeon coverage <binary>",
        "  aeon rc4 <binary>",
        "  aeon func <binary> <addr>",
    ]
    .join("\n")
}
