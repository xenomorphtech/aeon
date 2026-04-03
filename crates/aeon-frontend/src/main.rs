enum Command {
    Coverage {
        binary_path: String,
    },
    Rc4 {
        binary_path: String,
    },
    Func {
        binary_path: String,
        addr: u64,
    },
    ReducedIl {
        binary_path: String,
        addr: u64,
    },
    Ssa {
        binary_path: String,
        addr: u64,
        optimize: bool,
    },
    StackFrame {
        binary_path: String,
        addr: u64,
    },
    Pointers {
        binary_path: String,
    },
    VTables {
        binary_path: String,
    },
    FuncPointers {
        binary_path: String,
        addr: u64,
    },
    CallPath {
        binary_path: String,
        start_addr: u64,
        goal_addr: u64,
        max_depth: usize,
        include_all_paths: bool,
        max_paths: usize,
    },
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
        | Command::Func { binary_path, .. }
        | Command::ReducedIl { binary_path, .. }
        | Command::Ssa { binary_path, .. }
        | Command::StackFrame { binary_path, .. }
        | Command::Pointers { binary_path }
        | Command::VTables { binary_path }
        | Command::FuncPointers { binary_path, .. }
        | Command::CallPath { binary_path, .. } => binary_path,
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
        Command::ReducedIl { addr, .. } => {
            eprintln!("Reducing function at 0x{:x}...", addr);
            match session.get_reduced_il(addr) {
                Ok(details) => details,
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::Ssa { addr, optimize, .. } => {
            eprintln!(
                "Building {} SSA for 0x{:x}...",
                if optimize { "optimized" } else { "raw" },
                addr
            );
            match session.get_ssa(addr, optimize) {
                Ok(details) => details,
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::StackFrame { addr, .. } => {
            eprintln!("Summarizing stack frame for 0x{:x}...", addr);
            match session.get_stack_frame(addr) {
                Ok(details) => details,
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::Pointers { .. } => {
            eprintln!("Scanning mapped data pointers...");
            session.scan_pointers()
        }
        Command::VTables { .. } => {
            eprintln!("Detecting vtables...");
            session.scan_vtables()
        }
        Command::FuncPointers { addr, .. } => {
            eprintln!("Enumerating pointer references in 0x{:x}...", addr);
            match session.scan_function_pointers(Some(addr), 0, 1) {
                Ok(report) => report,
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::CallPath {
            start_addr,
            goal_addr,
            max_depth,
            include_all_paths,
            max_paths,
            ..
        } => {
            eprintln!(
                "Searching call paths from 0x{:x} to 0x{:x}...",
                start_addr, goal_addr
            );
            match session.find_call_paths(
                start_addr,
                goal_addr,
                max_depth,
                include_all_paths,
                max_paths,
            ) {
                Ok(report) => report,
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
        "reduced-il" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let addr_str = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            let addr = parse_hex_addr(&addr_str)?;
            Ok(Command::ReducedIl { binary_path, addr })
        }
        "ssa" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let addr_str = args.next().ok_or_else(usage)?;
            let mut optimize = true;

            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--raw" => optimize = false,
                    "--optimized" => optimize = true,
                    _ => return Err(usage()),
                }
            }

            let addr = parse_hex_addr(&addr_str)?;
            Ok(Command::Ssa {
                binary_path,
                addr,
                optimize,
            })
        }
        "stack-frame" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let addr_str = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            let addr = parse_hex_addr(&addr_str)?;
            Ok(Command::StackFrame { binary_path, addr })
        }
        "pointers" => {
            let binary_path = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            Ok(Command::Pointers { binary_path })
        }
        "vtables" => {
            let binary_path = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            Ok(Command::VTables { binary_path })
        }
        "func-pointers" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let addr_str = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            let addr = parse_hex_addr(&addr_str)?;
            Ok(Command::FuncPointers { binary_path, addr })
        }
        "call-path" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let start_addr = parse_hex_addr(&args.next().ok_or_else(usage)?)?;
            let goal_addr = parse_hex_addr(&args.next().ok_or_else(usage)?)?;
            let mut max_depth = 6usize;
            let mut include_all_paths = false;
            let mut max_paths = 32usize;
            let mut positional_depth_consumed = false;

            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--all" => include_all_paths = true,
                    "--max-depth" => {
                        let value = args.next().ok_or_else(usage)?;
                        max_depth = value
                            .parse()
                            .map_err(|_| format!("invalid max depth: {}", value))?;
                    }
                    "--max-paths" => {
                        let value = args.next().ok_or_else(usage)?;
                        max_paths = value
                            .parse()
                            .map_err(|_| format!("invalid max path count: {}", value))?;
                    }
                    value if !value.starts_with("--") && !positional_depth_consumed => {
                        max_depth = value
                            .parse()
                            .map_err(|_| format!("invalid max depth: {}", value))?;
                        positional_depth_consumed = true;
                    }
                    _ => return Err(usage()),
                }
            }

            Ok(Command::CallPath {
                binary_path,
                start_addr,
                goal_addr,
                max_depth,
                include_all_paths,
                max_paths,
            })
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
        "  aeon reduced-il <binary> <addr>",
        "  aeon ssa <binary> <addr> [--raw|--optimized]",
        "  aeon stack-frame <binary> <addr>",
        "  aeon pointers <binary>",
        "  aeon vtables <binary>",
        "  aeon func-pointers <binary> <addr>",
        "  aeon call-path <binary> <start_addr> <goal_addr> [max_depth] [--all] [--max-paths N]",
    ]
    .join("\n")
}
