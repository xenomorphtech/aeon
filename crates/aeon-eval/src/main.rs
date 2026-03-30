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

    let output = match command {
        Command::ConstructorLayout { binary_path, addr } => {
            match aeon_eval::evaluate_constructor_object_layout(&binary_path, addr) {
                Ok(run) => serde_json::to_value(run).unwrap(),
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::Help => unreachable!(),
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

enum Command {
    ConstructorLayout { binary_path: String, addr: u64 },
    Help,
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
        "constructor-layout" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let addr_str = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            let addr = parse_hex_addr(&addr_str)?;
            Ok(Command::ConstructorLayout { binary_path, addr })
        }
        _ => Err(usage()),
    }
}

fn parse_hex_addr(value: &str) -> Result<u64, String> {
    let trimmed = value.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(trimmed, 16).map_err(|_| format!("invalid hex address: {}", value))
}

fn usage() -> String {
    ["Usage:", "  aeon-eval constructor-layout <binary> <addr>"].join("\n")
}
