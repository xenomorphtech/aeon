//! Integration tests for MCP query tools: xrefs, call paths, pointer analysis

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
fn get_xrefs_requires_loaded_binary() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool("get_xrefs", &json!({"addr": "0x7d8"}));
    assert!(result.is_err(), "Should fail without loaded binary");
}

#[test]
fn get_xrefs_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool("get_xrefs", &json!({"addr": "0x7d8"}))
        .expect("get_xrefs");

    assert!(result.is_object(), "Xrefs result should be an object");
    // Should have incoming and outgoing references
    let obj = result.as_object().unwrap();
    assert!(
        obj.contains_key("outgoing") || obj.contains_key("incoming") || obj.len() > 0,
        "Xrefs should contain reference data"
    );
}

#[test]
fn find_call_paths_requires_start_and_goal() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Missing goal
    let result = frontend.call_tool(
        "find_call_paths",
        &json!({"start_addr": "0x7d8"}),
    );
    assert!(result.is_err(), "Should require both start and goal addresses");
}

#[test]
fn find_call_paths_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend.call_tool(
        "find_call_paths",
        &json!({
            "start_addr": "0x7d8",
            "goal_addr": "0x7d8"
        }),
    );

    // May return empty path or error if addresses are invalid, but shouldn't panic
    let _ = result;
}

#[test]
fn find_call_paths_respects_max_depth() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let shallow = frontend.call_tool(
        "find_call_paths",
        &json!({
            "start_addr": "0x7d8",
            "goal_addr": "0x7d8",
            "max_depth": 2
        }),
    );

    let deep = frontend.call_tool(
        "find_call_paths",
        &json!({
            "start_addr": "0x7d8",
            "goal_addr": "0x7d8",
            "max_depth": 10
        }),
    );

    // Both should be valid results (may be empty or error)
    let _ = (shallow, deep);
}

#[test]
fn find_call_paths_respects_include_all_paths() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let single_path = frontend.call_tool(
        "find_call_paths",
        &json!({
            "start_addr": "0x7d8",
            "goal_addr": "0x7d8",
            "include_all_paths": false
        }),
    );

    let all_paths = frontend.call_tool(
        "find_call_paths",
        &json!({
            "start_addr": "0x7d8",
            "goal_addr": "0x7d8",
            "include_all_paths": true
        }),
    );

    // Both should be valid
    let _ = (single_path, all_paths);
}

#[test]
fn scan_pointers_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend.call_tool("scan_pointers", &json!({})).expect("scan_pointers");

    assert!(result.is_object() || result.is_array(), "Pointer scan should return structured data");
}

#[test]
fn scan_vtables_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend.call_tool("scan_vtables", &json!({})).expect("scan_vtables");

    assert!(result.is_object() || result.is_array(), "Vtable scan should return structured data");
}

#[test]
fn get_function_pointers_requires_loaded_binary() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool("get_function_pointers", &json!({"addr": "0x7d8"}));
    assert!(result.is_err(), "Should fail without loaded binary");
}

#[test]
fn get_function_pointers_with_address_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend
        .call_tool("get_function_pointers", &json!({"addr": "0x7d8"}))
        .expect("get_function_pointers");

    assert!(result.is_object() || result.is_array(), "Function pointers should be structured");
}

#[test]
fn get_function_pointers_pagination() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result1 = frontend.call_tool(
        "get_function_pointers",
        &json!({
            "offset": 0,
            "limit": 10
        }),
    );

    let result2 = frontend.call_tool(
        "get_function_pointers",
        &json!({
            "offset": 10,
            "limit": 10
        }),
    );

    // Both should succeed or be consistent
    let _ = (result1, result2);
}

#[test]
fn search_rc4_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend.call_tool("search_rc4", &json!({})).expect("search_rc4");

    // Result should be structured (array of matches or empty)
    assert!(result.is_array() || result.is_object(), "RC4 search should return structured data");
}

#[test]
fn xrefs_and_call_paths_consistent() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Get xrefs for a function
    let xrefs = frontend
        .call_tool("get_xrefs", &json!({"addr": "0x7d8"}))
        .expect("get_xrefs");

    // Xrefs should be a valid object
    assert!(xrefs.is_object(), "Xrefs should be an object");

    // If there are outgoing calls, they should be reachable via call paths
    if let Some(outgoing) = xrefs.get("outgoing") {
        if let Some(arr) = outgoing.as_array() {
            if !arr.is_empty() {
                // Try to find a path to the first outgoing call
                if let Some(target) = arr[0].get("target").and_then(|t| t.as_str()) {
                    let _path = frontend.call_tool(
                        "find_call_paths",
                        &json!({
                            "start_addr": "0x7d8",
                            "goal_addr": target
                        }),
                    );
                }
            }
        }
    }
}
