use aeon_swarm::{
    claude::RealClaudeClient,
    coordinator::SwarmCoordinator,
    types::SwarmConfig,
};

fn main() {
    let mut args = std::env::args().skip(1);
    let binary_path = args
        .next()
        .unwrap_or_else(|| {
            eprintln!("Usage: aeon-swarm <binary-path> [--json]");
            std::process::exit(1);
        });
    let json_output = args.any(|a| a == "--json");

    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .unwrap_or_else(|_| {
            eprintln!("ANTHROPIC_API_KEY not set");
            std::process::exit(1);
        });

    let config = SwarmConfig::default_with_binary(binary_path);
    let api_key_clone = api_key.clone();

    let coordinator = SwarmCoordinator::new(config, move || {
        RealClaudeClient::new(api_key_clone.clone())
    })
    .unwrap_or_else(|e| {
        eprintln!("Failed to initialize: {}", e);
        std::process::exit(1);
    });

    let report = coordinator.run().unwrap_or_else(|e| {
        eprintln!("Swarm failed: {}", e);
        std::process::exit(1);
    });

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("=== Swarm Report ===");
        println!("Run ID: {}", report.run_id);
        println!("Binary: {}", report.binary_path);
        println!("Tool calls: {}", report.total_tool_calls);
        println!(
            "Tokens: {} in / {} out",
            report.total_prompt_tokens, report.total_completion_tokens
        );
        println!("Addresses with findings: {}", report.address_findings.len());
        if let Some(summary) = &report.reporter_summary {
            println!("\nReporter summary:\n{}", summary);
        }
    }
}
