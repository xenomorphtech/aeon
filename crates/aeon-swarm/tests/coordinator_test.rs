use aeon_swarm::{
    blackboard::BlackboardWrite,
    claude::MockClaudeClient,
    coordinator::SwarmCoordinator,
    types::SwarmConfig,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[test]
fn coordinator_full_pipeline_scout_no_tracer_targets() {
    let binary = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../samples/hello_aarch64.elf"
    );

    let config = SwarmConfig {
        binary_path: binary.to_string(),
        api_key: None,
        scout_model: "mock".to_string(),
        tracer_model: "mock".to_string(),
        reporter_model: "mock".to_string(),
        scout_parallelism: 1,
        tracer_parallelism: 1,
        scout_max_tool_calls: 10,
        tracer_max_tool_calls: 10,
        reporter_max_tool_calls: 10,
        scout_partition_size: 100,
        max_tracer_targets_per_scout: 5,
    };

    // Script: Scout adds hypothesis (no TRACER_TARGET), Reporter summarizes.
    let scout_resp = vec![
        MockClaudeClient::tool_use_response(
            "r1",
            "add_hypothesis",
            json!({ "addr": "0x650", "note": "Entry point to main" }),
        ),
        MockClaudeClient::end_turn_response("Scout done."),
    ];

    let reporter_resp = vec![MockClaudeClient::end_turn_response(
        r#"{"assessment":"simple hello-world binary"}"#,
    )];

    let responses = Arc::new(Mutex::new(vec![scout_resp, reporter_resp]));

    let coord = SwarmCoordinator::new(config, {
        let r = Arc::clone(&responses);
        move || MockClaudeClient::new(r.lock().unwrap().remove(0))
    })
    .unwrap();

    let report = coord.run().unwrap();

    assert!(report.address_findings.iter().any(|f| f.addr == 0x650));
    assert_eq!(report.tracer_targets.len(), 0);
    assert!(report.reporter_summary.is_some());
}

#[test]
fn coordinator_full_pipeline_with_tracer_target() {
    let binary = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../samples/hello_aarch64.elf"
    );

    let config = SwarmConfig {
        binary_path: binary.to_string(),
        api_key: None,
        scout_model: "mock".to_string(),
        tracer_model: "mock".to_string(),
        reporter_model: "mock".to_string(),
        scout_parallelism: 1,
        tracer_parallelism: 1,
        scout_max_tool_calls: 10,
        tracer_max_tool_calls: 10,
        reporter_max_tool_calls: 10,
        scout_partition_size: 100,
        max_tracer_targets_per_scout: 5,
    };

    // Script: Scout emits TRACER_TARGET, Tracer processes it, Reporter summarizes.
    let scout_resp = vec![
        MockClaudeClient::tool_use_response(
            "r1",
            "add_hypothesis",
            json!({ "addr": "0x650", "note": "TRACER_TARGET: suspicious loop" }),
        ),
        MockClaudeClient::end_turn_response("Scout done."),
    ];

    let tracer_resp = vec![
        MockClaudeClient::tool_use_response(
            "r2",
            "add_hypothesis",
            json!({ "addr": "0x650", "note": "Confirmed loop at 0x650" }),
        ),
        MockClaudeClient::end_turn_response("Tracer done."),
    ];

    let reporter_resp = vec![MockClaudeClient::end_turn_response(
        r#"{"assessment":"suspicious loop found"}"#,
    )];

    let responses = Arc::new(Mutex::new(vec![scout_resp, tracer_resp, reporter_resp]));

    let coord = SwarmCoordinator::new(config, {
        let r = Arc::clone(&responses);
        move || MockClaudeClient::new(r.lock().unwrap().remove(0))
    })
    .unwrap();

    let report = coord.run().unwrap();

    assert_eq!(report.tracer_targets, vec![0x650]);
    assert!(report
        .address_findings
        .iter()
        .any(|f| f.addr == 0x650 && f.hypotheses.len() >= 2));
    assert!(report.reporter_summary.is_some());
}

#[test]
fn coordinator_aggregates_writes_by_address() {
    let binary = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../samples/hello_aarch64.elf"
    );

    let config = SwarmConfig {
        binary_path: binary.to_string(),
        api_key: None,
        scout_model: "mock".to_string(),
        tracer_model: "mock".to_string(),
        reporter_model: "mock".to_string(),
        scout_parallelism: 1,
        tracer_parallelism: 1,
        scout_max_tool_calls: 10,
        tracer_max_tool_calls: 10,
        reporter_max_tool_calls: 10,
        scout_partition_size: 100,
        max_tracer_targets_per_scout: 5,
    };

    let scout_resp = vec![
        MockClaudeClient::tool_use_response(
            "r1",
            "rename_symbol",
            json!({ "addr": "0x650", "name": "main" }),
        ),
        MockClaudeClient::end_turn_response("Scout done."),
    ];

    let reporter_resp = vec![MockClaudeClient::end_turn_response("Done.")];

    let responses = Arc::new(Mutex::new(vec![scout_resp, reporter_resp]));

    let coord = SwarmCoordinator::new(config, {
        let r = Arc::clone(&responses);
        move || MockClaudeClient::new(r.lock().unwrap().remove(0))
    })
    .unwrap();

    let report = coord.run().unwrap();

    let finding = report.address_findings.iter().find(|f| f.addr == 0x650);
    assert!(finding.is_some());
    assert_eq!(finding.unwrap().symbol, Some("main".to_string()));
}
