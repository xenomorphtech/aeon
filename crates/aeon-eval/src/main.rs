fn main() {
    use std::fs;
    use std::path::Path;

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
        Command::ReducedIlGolden {
            binary_path,
            addr,
            golden_path,
        } => match aeon_eval::evaluate_reduced_il_golden(&binary_path, addr, &golden_path) {
            Ok(run) => serde_json::to_value(run).unwrap(),
            Err(error) => {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        },
        Command::ReductionMetrics { binary_path, addr } => {
            match aeon_eval::evaluate_reduction_metrics(&binary_path, addr) {
                Ok(run) => serde_json::to_value(run).unwrap(),
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::RunCorpus { manifest_path } => {
            match aeon_eval::load_corpus_manifest(&manifest_path) {
                Ok(manifest) => {
                    let base = Path::new(".");
                    let results = aeon_eval::run_corpus(&manifest, base);
                    let scores: Vec<_> = results.iter().zip(manifest.tasks.iter())
                        .filter_map(|((_, result), task)| result.as_ref().ok()
                            .map(|run| aeon_eval::score_run(run, task)))
                        .collect();
                    let report = aeon_eval::aggregate_benchmark(&manifest.id, scores);
                    serde_json::to_value(report).unwrap()
                }
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::ScoreRun { task_spec_path, run_path } => {
            match (fs::read(&task_spec_path), fs::read(&run_path)) {
                (Ok(task_data), Ok(run_data)) => {
                    match (serde_json::from_slice::<aeon_eval::TaskSpec>(&task_data),
                           serde_json::from_slice::<aeon_eval::EvaluationRun>(&run_data)) {
                        (Ok(task), Ok(run)) => {
                            let score = aeon_eval::score_run(&run, &task);
                            serde_json::to_value(score).unwrap()
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            eprintln!("JSON parse error: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    eprintln!("File read error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Command::Help => unreachable!(),
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

enum Command {
    ConstructorLayout {
        binary_path: String,
        addr: u64,
    },
    ReducedIlGolden {
        binary_path: String,
        addr: u64,
        golden_path: String,
    },
    ReductionMetrics {
        binary_path: String,
        addr: u64,
    },
    RunCorpus {
        manifest_path: String,
    },
    ScoreRun {
        task_spec_path: String,
        run_path: String,
    },
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
        "reduced-il-golden" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let addr_str = args.next().ok_or_else(usage)?;
            let golden_path = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            let addr = parse_hex_addr(&addr_str)?;
            Ok(Command::ReducedIlGolden {
                binary_path,
                addr,
                golden_path,
            })
        }
        "reduction-metrics" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let addr_str = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            let addr = parse_hex_addr(&addr_str)?;
            Ok(Command::ReductionMetrics { binary_path, addr })
        }
        "run-corpus" => {
            let manifest_path = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            Ok(Command::RunCorpus { manifest_path })
        }
        "score-run" => {
            let task_spec_path = args.next().ok_or_else(usage)?;
            let run_path = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            Ok(Command::ScoreRun { task_spec_path, run_path })
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
        "  aeon-eval constructor-layout <binary> <addr>",
        "  aeon-eval reduced-il-golden <binary> <addr> <golden>",
        "  aeon-eval reduction-metrics <binary> <addr>",
        "  aeon-eval run-corpus <manifest>",
        "  aeon-eval score-run <task-spec> <run>",
    ]
    .join("\n")
}
