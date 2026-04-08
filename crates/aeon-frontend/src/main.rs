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
        include_functions: bool,
        pretty: bool,
    },
    FuncPointers {
        binary_path: String,
        addr: u64,
    },
    XrefGraph {
        binary_path: String,
        threads: Option<usize>,
    },
    XrefGraphStats {
        binary_path: String,
        threads: Option<usize>,
    },
    XrefsPass {
        binary_path: String,
        threads: Option<usize>,
    },
    XrefPath {
        binary_path: String,
        start_addr: u64,
        goal_addr: u64,
        max_depth: usize,
        include_all_paths: bool,
        max_paths: usize,
        threads: Option<usize>,
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
    match aeon::resource_limits::install_process_memory_limit() {
        Ok(Some(limit_bytes)) => {
            eprintln!("Applied process memory cap: {} bytes", limit_bytes);
        }
        Ok(None) => {}
        Err(error) => eprintln!("Warning: failed to apply process memory cap: {}", error),
    }

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
        | Command::VTables { binary_path, .. }
        | Command::FuncPointers { binary_path, .. }
        | Command::XrefGraph { binary_path, .. }
        | Command::XrefGraphStats { binary_path, .. }
        | Command::XrefsPass { binary_path, .. }
        | Command::XrefPath { binary_path, .. }
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
        Command::VTables {
            include_functions,
            pretty,
            ..
        } => {
            eprintln!("Detecting vtables...");
            let report = aeon::pointer_analysis::scan_vtables_for_output(
                session.binary(),
                include_functions,
            );
            if pretty {
                serde_json::to_writer_pretty(std::io::stdout(), &report).unwrap();
            } else {
                serde_json::to_writer(std::io::stdout(), &report).unwrap();
            }
            println!();
            return;
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
        Command::XrefGraph { threads, .. } => {
            eprintln!("Building reusable xref graph...");
            match session.xref_graph_summary(threads) {
                Ok(report) => {
                    print_xref_graph_summary(&report);
                    return;
                }
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::XrefGraphStats { threads, .. } => {
            eprintln!("Counting reusable xref graph edges...");
            match session.xref_graph_build_stats(threads) {
                Ok(report) => {
                    print_xref_graph_build_stats(&report);
                    return;
                }
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::XrefsPass { threads, .. } => {
            eprintln!("Scanning xrefs across all functions...");
            match session.scan_xrefs_pass(threads) {
                Ok(report) => report,
                Err(error) => {
                    eprintln!("{}", error);
                    std::process::exit(1);
                }
            }
        }
        Command::XrefPath {
            start_addr,
            goal_addr,
            max_depth,
            include_all_paths,
            max_paths,
            threads,
            ..
        } => {
            eprintln!(
                "Searching xref paths from 0x{:x} to 0x{:x}...",
                start_addr, goal_addr
            );
            match session.find_xref_path_report(
                start_addr,
                goal_addr,
                max_depth,
                include_all_paths,
                max_paths,
                threads,
            ) {
                Ok(report) => {
                    print_xref_path_report(&report);
                    return;
                }
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

fn print_xref_graph_summary(report: &aeon::xref_graph::XrefGraphSummaryReport) {
    println!("Xref Graph");
    println!(
        "nodes: total={} functions={} vtables={} active={}",
        report.total_nodes, report.function_nodes, report.vtable_nodes, report.active_nodes
    );
    println!(
        "edges: total={} direct_calls={} tail_calls={} indirect_vtable_exact={} indirect_vtable_referenced={} indirect_vtable_slot_fallback={} vtable_slots={}",
        report.total_edges,
        report.direct_call_edges,
        report.tail_call_edges,
        report.indirect_vtable_exact_edges,
        report.indirect_vtable_referenced_edges,
        report.indirect_vtable_slot_fallback_edges,
        report.vtable_slot_edges
    );
    println!(
        "unresolved indirect sites: {}",
        report.unresolved_indirect_sites
    );
    println!("truncated functions: {}", report.truncated_functions);
    println!("threads used: {}", report.threads_used);
    println!(
        "build time: {:.3}s",
        report.build_elapsed_ms as f64 / 1000.0
    );
}

fn print_xref_graph_build_stats(report: &aeon::xref_graph::XrefGraphBuildStats) {
    println!("Xref Graph Stats");
    println!(
        "nodes: functions={} vtables={}",
        report.total_function_nodes, report.total_vtable_nodes
    );
    println!(
        "edges: function_edges={} vtable_slot_edges={} total={}",
        report.total_function_edges,
        report.total_vtable_slot_edges,
        report.total_function_edges + report.total_vtable_slot_edges
    );
    println!(
        "edge kinds: direct_calls={} tail_calls={} indirect_vtable_exact={} indirect_vtable_referenced={} indirect_vtable_slot_fallback={}",
        report.direct_call_edges,
        report.tail_call_edges,
        report.indirect_vtable_exact_edges,
        report.indirect_vtable_referenced_edges,
        report.indirect_vtable_slot_fallback_edges
    );
    println!("functions with edges: {}", report.functions_with_edges);
    println!(
        "max function edges: {} at 0x{:x}",
        report.max_edges_in_function, report.max_edge_function_addr
    );
    println!(
        "unresolved indirect sites: {}",
        report.unresolved_indirect_sites
    );
    println!("truncated functions: {}", report.truncated_functions);
    println!("threads used: {}", report.threads_used);
    println!("elapsed: {:.3}s", report.elapsed_ms as f64 / 1000.0);
}

fn print_xref_path_report(report: &aeon::xref_graph::XrefPathSearchReport) {
    println!("Xref Path");
    println!("start: {}", format_xref_node(&report.start));
    println!("goal: {}", format_xref_node(&report.goal));
    println!("max depth: {}", report.max_depth);
    println!(
        "graph: nodes={} edges={} direct_edges={} vtable_edges={} unresolved_indirect_sites={}",
        report.graph_node_count,
        report.graph_edge_count,
        report.direct_edge_count,
        report.vtable_edge_count,
        report.unresolved_indirect_sites
    );

    match &report.shortest_path {
        Some(path) => print_xref_path("shortest path", path),
        None => println!("shortest path: none"),
    }

    if let Some(paths) = &report.all_paths {
        println!("all paths: {}", paths.len());
        for (index, path) in paths.iter().enumerate() {
            print_xref_path(&format!("path {}", index + 1), path);
        }
    }
}

fn print_xref_path(label: &str, path: &aeon::xref_graph::XrefPath) {
    println!("{}: {} hops", label, path.edges.len());
    if let Some(first) = path.nodes.first() {
        println!("  0. {}", format_xref_node(first));
    }

    for (index, edge) in path.edges.iter().enumerate() {
        println!("     --{}-->", format_xref_edge(edge));
        println!(
            "  {}. {}",
            index + 1,
            format_xref_node(&path.nodes[index + 1])
        );
    }
}

fn format_xref_node(node: &aeon::xref_graph::XrefNodeView) -> String {
    match node.kind {
        aeon::xref_graph::XrefNodeKind::Function => {
            if let Some(name) = &node.name {
                format!("function 0x{:x} ({})", node.addr, name)
            } else {
                format!("function 0x{:x}", node.addr)
            }
        }
        aeon::xref_graph::XrefNodeKind::VTable => {
            let mut suffix = Vec::new();
            if let Some(section) = &node.section {
                suffix.push(section.clone());
            }
            if let Some(group_id) = node.group_id {
                suffix.push(format!("group {}", group_id));
            }
            if let Some(function_count) = node.function_count {
                suffix.push(format!("{} slots", function_count));
            }

            if suffix.is_empty() {
                format!("vtable 0x{:x}", node.addr)
            } else {
                format!("vtable 0x{:x} [{}]", node.addr, suffix.join(", "))
            }
        }
    }
}

fn format_xref_edge(edge: &aeon::xref_graph::XrefEdgeView) -> String {
    let mut parts = vec![match edge.kind {
        aeon::xref_graph::XrefEdgeKind::DirectCall => "direct_call".to_string(),
        aeon::xref_graph::XrefEdgeKind::TailCall => "tail_call".to_string(),
        aeon::xref_graph::XrefEdgeKind::IndirectVtableExact => "indirect_vtable_exact".to_string(),
        aeon::xref_graph::XrefEdgeKind::IndirectVtableReferenced => {
            "indirect_vtable_referenced".to_string()
        }
        aeon::xref_graph::XrefEdgeKind::IndirectVtableSlotFallback => {
            "indirect_vtable_slot_fallback".to_string()
        }
        aeon::xref_graph::XrefEdgeKind::VtableSlot => "vtable_slot".to_string(),
    }];

    if let Some(instruction_addr) = edge.instruction_addr {
        parts.push(format!("@ 0x{:x}", instruction_addr));
    }
    if let Some(slot_offset) = edge.slot_offset {
        parts.push(format!("slot +0x{:x}", slot_offset));
    }

    parts.join(", ")
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
            let mut include_functions = false;
            let mut pretty = false;

            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--full" => include_functions = true,
                    "--pretty" => pretty = true,
                    _ => return Err(usage()),
                }
            }
            Ok(Command::VTables {
                binary_path,
                include_functions,
                pretty,
            })
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
        "xref-graph" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let mut threads = None;

            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--threads" => {
                        let value = args.next().ok_or_else(usage)?;
                        let parsed = value
                            .parse()
                            .map_err(|_| format!("invalid thread count: {}", value))?;
                        threads = Some(parsed);
                    }
                    _ => return Err(usage()),
                }
            }

            Ok(Command::XrefGraph {
                binary_path,
                threads,
            })
        }
        "xref-graph-stats" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let mut threads = None;

            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--threads" => {
                        let value = args.next().ok_or_else(usage)?;
                        let parsed = value
                            .parse()
                            .map_err(|_| format!("invalid thread count: {}", value))?;
                        threads = Some(parsed);
                    }
                    _ => return Err(usage()),
                }
            }

            Ok(Command::XrefGraphStats {
                binary_path,
                threads,
            })
        }
        "xrefs-pass" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let mut threads = None;

            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--threads" => {
                        let value = args.next().ok_or_else(usage)?;
                        let parsed = value
                            .parse()
                            .map_err(|_| format!("invalid thread count: {}", value))?;
                        threads = Some(parsed);
                    }
                    _ => return Err(usage()),
                }
            }

            Ok(Command::XrefsPass {
                binary_path,
                threads,
            })
        }
        "xref-path" => {
            let binary_path = args.next().ok_or_else(usage)?;
            let start_addr = parse_hex_addr(&args.next().ok_or_else(usage)?)?;
            let goal_addr = parse_hex_addr(&args.next().ok_or_else(usage)?)?;
            let mut max_depth = 6usize;
            let mut include_all_paths = false;
            let mut max_paths = 32usize;
            let mut threads = None;
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
                    "--threads" => {
                        let value = args.next().ok_or_else(usage)?;
                        let parsed = value
                            .parse()
                            .map_err(|_| format!("invalid thread count: {}", value))?;
                        threads = Some(parsed);
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

            Ok(Command::XrefPath {
                binary_path,
                start_addr,
                goal_addr,
                max_depth,
                include_all_paths,
                max_paths,
                threads,
            })
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
        "  aeon vtables <binary> [--full] [--pretty]",
        "  aeon func-pointers <binary> <addr>",
        "  aeon xref-graph <binary> [--threads N]",
        "  aeon xref-graph-stats <binary> [--threads N]",
        "  aeon xrefs-pass <binary> [--threads N]",
        "  aeon xref-path <binary> <start_addr> <goal_addr> [max_depth] [--all] [--max-paths N] [--threads N]",
        "  aeon call-path <binary> <start_addr> <goal_addr> [max_depth] [--all] [--max-paths N]",
    ]
    .join("\n")
}
