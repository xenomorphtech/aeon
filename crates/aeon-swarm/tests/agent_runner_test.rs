use aeon_swarm::{
    agent::AgentRunner,
    blackboard::BlackboardWrite,
    bridge::DirectBridge,
    claude::{ClaudeContentBlock, MockClaudeClient},
    types::{AgentSpec, SwarmRole},
};
use aeon_frontend::service::AeonFrontend;
use std::sync::{Arc, Mutex};
use serde_json::json;

fn make_test_frontend(binary_path: &str) -> Arc<Mutex<AeonFrontend>> {
    let mut fe = AeonFrontend::new();
    fe.call_tool("load_binary", &json!({ "path": binary_path }))
        .unwrap();
    Arc::new(Mutex::new(fe))
}

#[test]
fn scout_agent_emits_hypothesis_write_and_tracer_target() {
    let frontend = make_test_frontend("../../samples/hello_aarch64.elf");

    let claude = MockClaudeClient::new(vec![
        MockClaudeClient::tool_use_response(
            "r1",
            "add_hypothesis",
            json!({ "addr": "0x650", "note": "TRACER_TARGET: suspicious loop" }),
        ),
        MockClaudeClient::end_turn_response("Flagged 0x650 for deep analysis."),
    ]);

    let spec = AgentSpec {
        id: "scout-test".to_string(),
        role: SwarmRole::Scout,
        model: "claude-haiku-4-5".to_string(),
        assigned_addrs: vec![0x650],
        max_tool_calls: 10,
        max_tokens: 2048,
    };

    let output = AgentRunner::new(spec, claude, DirectBridge::from_arc(frontend)).run();

    assert_eq!(output.tool_calls_made, 1);
    assert!(output.terminated_cleanly);
    assert_eq!(output.tracer_targets, vec![0x650]);
    assert_eq!(output.writes.len(), 1);
    assert!(matches!(
        &output.writes[0],
        BlackboardWrite::AddHypothesis {
            addr: 0x650,
            note,
            ..
        }
        if note.contains("TRACER_TARGET")
    ));
}

#[test]
fn agent_stops_at_max_tool_calls() {
    let frontend = make_test_frontend("../../samples/hello_aarch64.elf");

    let claude = MockClaudeClient::new(vec![
        MockClaudeClient::tool_use_response("r1", "list_functions", json!({})),
        MockClaudeClient::tool_use_response("r2", "list_functions", json!({})),
        MockClaudeClient::tool_use_response("r3", "list_functions", json!({})),
    ]);

    let spec = AgentSpec {
        id: "scout-limit".to_string(),
        role: SwarmRole::Scout,
        model: "claude-haiku-4-5".to_string(),
        assigned_addrs: vec![],
        max_tool_calls: 2,
        max_tokens: 2048,
    };

    let output = AgentRunner::new(spec, claude, DirectBridge::from_arc(frontend)).run();
    assert!(!output.terminated_cleanly);
    assert!(output.tool_calls_made <= 2);
}

#[test]
fn tracer_agent_rename_symbol_captured() {
    let frontend = make_test_frontend("../../samples/hello_aarch64.elf");

    let claude = MockClaudeClient::new(vec![
        MockClaudeClient::tool_use_response(
            "r1",
            "rename_symbol",
            json!({ "addr": "0x650", "name": "entry_point" }),
        ),
        MockClaudeClient::end_turn_response("Renamed symbol."),
    ]);

    let spec = AgentSpec {
        id: "tracer-test".to_string(),
        role: SwarmRole::Tracer,
        model: "claude-haiku-4-5".to_string(),
        assigned_addrs: vec![0x650],
        max_tool_calls: 10,
        max_tokens: 2048,
    };

    let output = AgentRunner::new(spec, claude, DirectBridge::from_arc(frontend)).run();

    assert_eq!(output.tool_calls_made, 1);
    assert!(output.terminated_cleanly);
    assert_eq!(output.writes.len(), 1);
    assert!(matches!(
        &output.writes[0],
        BlackboardWrite::RenameSymbol {
            addr: 0x650,
            name,
            ..
        }
        if name == "entry_point"
    ));
}

#[test]
fn disallowed_tool_returns_error_result() {
    let frontend = make_test_frontend("../../samples/hello_aarch64.elf");

    let claude = MockClaudeClient::new(vec![
        MockClaudeClient::tool_use_response(
            "r1",
            "get_ssa", // Tracer-only tool
            json!({ "addr": "0x650" }),
        ),
        MockClaudeClient::end_turn_response("Done."),
    ]);

    let spec = AgentSpec {
        id: "scout-invalid".to_string(),
        role: SwarmRole::Scout, // Scouts don't have access to get_ssa
        model: "claude-haiku-4-5".to_string(),
        assigned_addrs: vec![0x650],
        max_tool_calls: 10,
        max_tokens: 2048,
    };

    let output = AgentRunner::new(spec, claude, DirectBridge::from_arc(frontend)).run();

    assert_eq!(output.tool_calls_made, 1);
    assert!(output.terminated_cleanly);
    assert_eq!(output.writes.len(), 0); // No write captured
}
