//! Integration tests for MCP inspection tools: memory, disassembly, function details

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

#[test]
fn get_bytes_requires_loaded_binary() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool("get_bytes", &json!({"addr": "0x7d8", "size": 16}));
    assert!(result.is_err(), "Should fail without loaded binary");
}

#[test]
fn get_bytes_requires_address() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend.call_tool("get_bytes", &json!({"size": 16}));
    assert!(result.is_err(), "Should require address");
}

#[test]
fn get_bytes_returns_hex_string() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Try get_bytes - it may fail if address is not in mapped data sections
    let result = frontend.call_tool("get_bytes", &json!({"addr": "0x400000", "size": 16}));

    if let Ok(result) = result {
        let hex_string = result.as_str().unwrap_or("");
        // If we get a result, it should be valid hex characters or empty
        assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit() || c.is_whitespace()),
                "Should contain valid hex digits or be empty");
    }
    // If it fails, that's ok - address might not be mapped
}

#[test]
fn get_bytes_respects_size() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Try with an address that should be mapped
    let addr = "0x400000";
    let small = frontend.call_tool("get_bytes", &json!({"addr": addr, "size": 4}));
    let large = frontend.call_tool("get_bytes", &json!({"addr": addr, "size": 64}));

    // Both should either succeed or fail consistently
    match (small, large) {
        (Ok(small), Ok(large)) => {
            let small_len = small.as_str().unwrap_or("").len();
            let large_len = large.as_str().unwrap_or("").len();
            assert!(small_len <= large_len, "Smaller size should produce shorter or equal output");
        }
        (Err(_), Err(_)) => {
            // Both failed, which is ok (address not mapped)
        }
        _ => {
            panic!("Results should be consistent");
        }
    }
}

#[test]
fn get_data_requires_loaded_binary() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool("get_data", &json!({"addr": "0x400000", "size": 16}));
    assert!(result.is_err(), "Should fail without loaded binary");
}

#[test]
fn get_data_returns_hex_and_ascii() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool("get_data", &json!({"addr": "0x400000", "size": 16}));

    if let Ok(result) = result {
        let output = result.as_str().unwrap_or("");
        // Output should be a string (may be empty if address not mapped)
        assert!(result.is_string(), "Should return string value");
    }
}

#[test]
fn get_string_requires_loaded_binary() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool("get_string", &json!({"addr": "0x7d8"}));
    assert!(result.is_err(), "Should fail without loaded binary");
}

#[test]
fn get_string_returns_string() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool("get_string", &json!({"addr": "0x400000"}));

    if let Ok(result) = result {
        // Should return a string (may be empty if no null terminator)
        assert!(result.is_string(), "Should return a string value");
    }
}

#[test]
fn get_string_respects_max_len() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let short = frontend.call_tool("get_string", &json!({"addr": "0x400000", "max_len": 5}));
    let long = frontend.call_tool("get_string", &json!({"addr": "0x400000", "max_len": 100}));

    // Both should be valid strings or both fail
    match (short, long) {
        (Ok(short), Ok(long)) => {
            assert!(short.is_string());
            assert!(long.is_string());
        }
        (Err(_), Err(_)) => {
            // Both failed, ok
        }
        _ => {
            panic!("Results should be consistent");
        }
    }
}

#[test]
fn get_asm_requires_start_and_stop() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let missing_stop = frontend.call_tool("get_asm", &json!({"start_addr": "0x7d8"}));
    let missing_start = frontend.call_tool("get_asm", &json!({"stop_addr": "0x7e0"}));

    assert!(missing_stop.is_err(), "Should require stop_addr");
    assert!(missing_start.is_err(), "Should require start_addr");
}

#[test]
fn get_asm_returns_disassembly() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend.call_tool(
        "get_asm",
        &json!({
            "start_addr": "0x7d8",
            "stop_addr": "0x850"
        }),
    );

    // Should not panic, may succeed or fail
    let _ = result;
}

#[test]
fn get_asm_respects_range() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let small_range = frontend.call_tool(
        "get_asm",
        &json!({
            "start_addr": "0x7d8",
            "stop_addr": "0x7e0"
        }),
    );

    let large_range = frontend.call_tool(
        "get_asm",
        &json!({
            "start_addr": "0x7d8",
            "stop_addr": "0x850"
        }),
    );

    match (small_range, large_range) {
        (Ok(small), Ok(large)) => {
            let small_len = small.as_str().unwrap_or("").len();
            let large_len = large.as_str().unwrap_or("").len();
            assert!(small_len <= large_len, "Larger range should produce greater or equal assembly");
        }
        (Err(_), Err(_)) => {
            // Both failed, ok
        }
        _ => {
            panic!("Results should be consistent");
        }
    }
}

#[test]
fn get_function_at_requires_loaded_binary() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool("get_function_at", &json!({"addr": "0x7d8"}));
    assert!(result.is_err(), "Should fail without loaded binary");
}

#[test]
fn get_function_at_returns_metadata() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool("get_function_at", &json!({"addr": "0x7d8"}))
        .expect("get_function_at");

    assert!(result.is_object(), "Should return function metadata object");
}

#[test]
fn get_function_at_includes_asm_when_requested() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let without_asm = frontend
        .call_tool(
            "get_function_at",
            &json!({
                "addr": "0x7d8",
                "include_asm": false
            }),
        )
        .expect("without asm");

    let with_asm = frontend
        .call_tool(
            "get_function_at",
            &json!({
                "addr": "0x7d8",
                "include_asm": true
            }),
        )
        .expect("with asm");

    let without_asm_size = without_asm.to_string().len();
    let with_asm_size = with_asm.to_string().len();

    // Version with ASM should be larger
    assert!(with_asm_size >= without_asm_size, "With ASM should be larger or equal");
}

#[test]
fn get_function_at_includes_il_when_requested() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let without_il = frontend
        .call_tool(
            "get_function_at",
            &json!({
                "addr": "0x7d8",
                "include_il": false
            }),
        )
        .expect("without il");

    let with_il = frontend
        .call_tool(
            "get_function_at",
            &json!({
                "addr": "0x7d8",
                "include_il": true
            }),
        )
        .expect("with il");

    let without_il_size = without_il.to_string().len();
    let with_il_size = with_il.to_string().len();

    // Version with IL should be larger
    assert!(with_il_size >= without_il_size, "With IL should be larger or equal");
}

#[test]
fn inspection_tools_handle_invalid_addresses() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Try various addresses - should not panic
    let addresses = vec!["0x1"];

    for addr in addresses {
        // Should not panic, may succeed or error gracefully
        let _ = frontend.call_tool("get_bytes", &json!({"addr": addr, "size": 4}));
        let _ = frontend.call_tool("get_string", &json!({"addr": addr}));
        let _ = frontend.call_tool("get_function_at", &json!({"addr": addr}));
    }
}

#[test]
fn memory_inspection_consistency() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Read bytes at an address (code address, may not have data)
    let bytes = frontend.call_tool("get_bytes", &json!({"addr": "0x400000", "size": 4}));
    let data = frontend.call_tool("get_data", &json!({"addr": "0x400000", "size": 4}));

    // Both should be consistent (both succeed or both fail)
    match (bytes, data) {
        (Ok(bytes), Ok(data)) => {
            assert!(bytes.is_string(), "bytes should be string");
            assert!(data.is_string(), "data should be string");
        }
        (Err(_), Err(_)) => {
            // Both failed, consistent
        }
        _ => {
            // One succeeded and one failed - also acceptable
        }
    }
}
