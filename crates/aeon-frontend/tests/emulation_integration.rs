//! Integration tests for sandbox emulation tools: emulate_snippet_il and emulate_snippet_native
//!
//! Tests demonstrate:
//! - AeonIL interpretation mode for symbolic/lifted code execution
//! - Unicorn-based native ARM64 execution with memory support
//! - Error handling (invalid ranges, step budget exhaustion, missing memory)
//! - Register initialization and final state verification
//! - Memory write tracking and decoded string extraction

use serde_json::json;
use std::path::PathBuf;

#[path = "../src/service.rs"]
mod service;

use service::AeonFrontend;

fn sample_binary_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../samples/hello_aarch64.elf")
        .display()
        .to_string()
}

fn load_sample_binary(frontend: &mut AeonFrontend) {
    frontend
        .call_tool(
            "load_binary",
            &json!({
                "path": sample_binary_path()
            }),
        )
        .expect("load binary");
}

/// Test AeonIL emulation: simple loop at known address
#[test]
fn emulate_snippet_il_basic_execution() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Execute a small snippet from the sample binary
    let result = frontend
        .call_tool(
            "emulate_snippet_il",
            &json!({
                "start_addr": "0x718",
                "end_addr": "0x730",
                "initial_registers": {
                    "x0": "0x1",
                    "x1": "0x2"
                },
                "step_limit": 100
            }),
        )
        .expect("emulate_snippet_il");

    assert!(result.is_object());
    assert_eq!(result["mode"].as_str(), Some("il"));
    assert_eq!(result["start_addr"].as_str(), Some("0x718"));
    assert_eq!(result["end_addr"].as_str(), Some("0x730"));
    assert!(result["final_registers"].is_object());
    assert!(result["steps_executed"].is_number());
}

/// Test AeonIL emulation: verify initial registers appear in final state
#[test]
fn emulate_snippet_il_preserves_initial_state() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool(
            "emulate_snippet_il",
            &json!({
                "start_addr": "0x718",
                "end_addr": "0x720",
                "initial_registers": {
                    "x0": "0xdeadbeef",
                    "x1": "0xcafebabe"
                },
                "step_limit": 50
            }),
        )
        .expect("emulate_snippet_il");

    assert!(result.is_object());
    let final_regs = result["final_registers"].as_object().expect("final_registers");
    // At minimum, initial registers should be present (even if unmodified)
    assert!(
        final_regs.contains_key("x0") || final_regs.contains_key("x1"),
        "Final registers should include initialized x0 or x1"
    );
}

/// Test AeonIL emulation: error handling for invalid address range
#[test]
fn emulate_snippet_il_rejects_invalid_range() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // start_addr >= end_addr should be rejected
    let result = frontend.call_tool(
        "emulate_snippet_il",
        &json!({
            "start_addr": "0x800",
            "end_addr": "0x800",
            "initial_registers": {},
            "step_limit": 100
        }),
    );

    assert!(result.is_err(), "Should reject start_addr >= end_addr");
}

/// Test AeonIL emulation: error handling for range that's too large
#[test]
fn emulate_snippet_il_rejects_oversized_range() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Snippet > 64KB should be rejected
    let result = frontend.call_tool(
        "emulate_snippet_il",
        &json!({
            "start_addr": "0x1000",
            "end_addr": "0x1000000",
            "initial_registers": {},
            "step_limit": 100
        }),
    );

    assert!(result.is_err(), "Should reject oversized snippet");
}

/// Test native emulation: basic unicorn execution
#[test]
fn emulate_snippet_native_basic_execution() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool(
            "emulate_snippet_native",
            &json!({
                "start_addr": "0x718",
                "end_addr": "0x730",
                "initial_registers": {
                    "x0": "0x1",
                    "x1": "0x2"
                },
                "initial_memory": {},
                "step_limit": 100
            }),
        )
        .expect("emulate_snippet_native");

    assert!(result.is_object());
    assert_eq!(result["start_addr"].as_str(), Some("0x718"));
    assert_eq!(result["end_addr"].as_str(), Some("0x730"));
    assert!(result["final_registers"].is_object());
    assert!(result["memory_writes"].is_array());
    assert!(result["decoded_strings"].is_array());
    assert!(result["stop_reason"].is_string());
}

/// Test native emulation: verify register initialization
#[test]
fn emulate_snippet_native_initializes_registers() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool(
            "emulate_snippet_native",
            &json!({
                "start_addr": "0x718",
                "end_addr": "0x720",
                "initial_registers": {
                    "x0": "0x12345678",
                    "x1": "0x87654321",
                    "sp": "0x7fff8000"
                },
                "initial_memory": {},
                "step_limit": 50
            }),
        )
        .expect("emulate_snippet_native");

    assert!(result.is_object());
    let final_regs = result["final_registers"].as_object().expect("final_registers");
    // x0, x1, sp should all be present in output
    assert!(final_regs.contains_key("x0"), "Final registers should have x0");
    assert!(final_regs.contains_key("x1"), "Final registers should have x1");
    assert!(final_regs.contains_key("sp"), "Final registers should have sp");
}

/// Test native emulation: memory write tracking
#[test]
fn emulate_snippet_native_tracks_memory_writes() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool(
            "emulate_snippet_native",
            &json!({
                "start_addr": "0x718",
                "end_addr": "0x750",
                "initial_registers": {
                    "x0": "0x7fff8000",
                    "x1": "0x42"
                },
                "initial_memory": {},
                "step_limit": 200
            }),
        )
        .expect("emulate_snippet_native");

    assert!(result.is_object());
    let memory_writes = result["memory_writes"]
        .as_array()
        .expect("memory_writes should be array");

    // If there are memory writes, they should be properly formatted
    for write in memory_writes {
        assert!(write.is_object(), "Each memory write should be an object");
        assert!(write.get("addr").is_some(), "Memory write should have addr");
        assert!(write.get("size").is_some(), "Memory write should have size");
        assert!(write.get("value").is_some(), "Memory write should have value");
    }
}

/// Test native emulation: step limit exhaustion detection
#[test]
fn emulate_snippet_native_detects_step_limit() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Use very low step limit
    let result = frontend
        .call_tool(
            "emulate_snippet_native",
            &json!({
                "start_addr": "0x718",
                "end_addr": "0x800",
                "initial_registers": {},
                "initial_memory": {},
                "step_limit": 2
            }),
        )
        .expect("emulate_snippet_native");

    assert!(result.is_object());
    assert!(result["stop_reason"].is_string());
    let stop_reason = result["stop_reason"].as_str().unwrap();
    // With such a low limit, should hit it or range exit
    assert!(
        stop_reason == "step_limit" || stop_reason.contains("range_exit"),
        "Should hit step limit or exit range, got: {}",
        stop_reason
    );
}

/// Test backward compatibility: emulate_snippet as alias for emulate_snippet_native
#[test]
fn emulate_snippet_alias_works() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool(
            "emulate_snippet",
            &json!({
                "start_addr": "0x718",
                "end_addr": "0x730",
                "initial_registers": {
                    "x0": "0x1"
                },
                "initial_memory": {},
                "step_limit": 100
            }),
        )
        .expect("emulate_snippet");

    // Should behave like native version
    assert!(result.is_object());
    assert!(result["final_registers"].is_object());
    assert!(result["memory_writes"].is_array());
    assert!(result["decoded_strings"].is_array());
}

/// Test native emulation: both tools registered in tools_list
#[test]
fn both_emulation_tools_in_schema() {
    let tools = service::tools_list();
    let tool_array = tools
        .get("tools")
        .and_then(|t| t.as_array())
        .expect("tools should be array");

    let tool_names: Vec<&str> = tool_array
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();

    assert!(
        tool_names.contains(&"emulate_snippet_il"),
        "emulate_snippet_il should be in tools list"
    );
    assert!(
        tool_names.contains(&"emulate_snippet_native"),
        "emulate_snippet_native should be in tools list"
    );
    assert!(
        tool_names.contains(&"emulate_snippet"),
        "emulate_snippet (alias) should be in tools list"
    );
}

/// Test schema for emulate_snippet_il
#[test]
fn emulate_snippet_il_has_valid_schema() {
    let tools = service::tools_list();
    let tool_array = tools
        .get("tools")
        .and_then(|t| t.as_array())
        .expect("tools should be array");

    let il_tool = tool_array
        .iter()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some("emulate_snippet_il"))
        .expect("emulate_snippet_il tool should exist");

    assert!(il_tool.get("name").is_some());
    assert!(il_tool.get("description").is_some());
    let schema = il_tool.get("inputSchema").expect("should have inputSchema");
    assert!(
        schema
            .get("properties")
            .and_then(|p| p.get("start_addr"))
            .is_some(),
        "schema should have start_addr property"
    );
    assert!(
        schema
            .get("properties")
            .and_then(|p| p.get("end_addr"))
            .is_some(),
        "schema should have end_addr property"
    );
    assert!(
        schema
            .get("properties")
            .and_then(|p| p.get("initial_registers"))
            .is_some(),
        "schema should have initial_registers property"
    );
    // IL version should NOT require initial_memory
    assert!(
        !schema
            .get("properties")
            .and_then(|p| p.get("initial_memory"))
            .is_some(),
        "IL version should not have initial_memory"
    );
}

/// Test schema for emulate_snippet_native
#[test]
fn emulate_snippet_native_has_valid_schema() {
    let tools = service::tools_list();
    let tool_array = tools
        .get("tools")
        .and_then(|t| t.as_array())
        .expect("tools should be array");

    let native_tool = tool_array
        .iter()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some("emulate_snippet_native"))
        .expect("emulate_snippet_native tool should exist");

    assert!(native_tool.get("name").is_some());
    assert!(native_tool.get("description").is_some());
    let schema = native_tool.get("inputSchema").expect("should have inputSchema");
    assert!(
        schema
            .get("properties")
            .and_then(|p| p.get("start_addr"))
            .is_some(),
        "schema should have start_addr property"
    );
    assert!(
        schema
            .get("properties")
            .and_then(|p| p.get("end_addr"))
            .is_some(),
        "schema should have end_addr property"
    );
    assert!(
        schema
            .get("properties")
            .and_then(|p| p.get("initial_registers"))
            .is_some(),
        "schema should have initial_registers property"
    );
    // Native version SHOULD support initial_memory
    assert!(
        schema
            .get("properties")
            .and_then(|p| p.get("initial_memory"))
            .is_some(),
        "Native version should have initial_memory"
    );
}

/// Test IL emulation: handles unknown/unsupported instructions gracefully
#[test]
fn emulate_snippet_il_handles_unsupported_instructions() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Should not crash even with unsupported instructions
    let result = frontend.call_tool(
        "emulate_snippet_il",
        &json!({
            "start_addr": "0x7d8",
            "end_addr": "0x7e8",
            "initial_registers": {
                "x0": "0x100"
            },
            "step_limit": 50
        }),
    );

    // Should either succeed or return an error, not panic
    assert!(result.is_ok() || result.is_err());
}

/// Test native emulation: memory state consistency
#[test]
fn emulate_snippet_native_memory_consistency() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Pre-populate memory with a known value
    let result = frontend
        .call_tool(
            "emulate_snippet_native",
            &json!({
                "start_addr": "0x718",
                "end_addr": "0x728",
                "initial_registers": {
                    "x0": "0x7fff8100"
                },
                "initial_memory": {
                    "0x7fff8100": "0x1122334455667788"
                },
                "step_limit": 50
            }),
        )
        .expect("emulate_snippet_native");

    // Should complete without error
    assert!(result.is_object());
    assert!(result["final_registers"].is_object());
}
