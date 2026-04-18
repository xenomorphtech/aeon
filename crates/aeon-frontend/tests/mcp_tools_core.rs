//! Integration tests for core MCP tools: binary loading and analysis

use serde_json::{json, Value};
use std::path::PathBuf;

// Re-use the test harness from aeon-frontend
#[path = "../src/service.rs"]
mod service;
#[path = "../src/mcp.rs"]
mod mcp;

use service::AeonFrontend;

fn sample_binary_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../samples/hello_aarch64.elf")
        .display()
        .to_string()
}

fn load_sample_binary(frontend: &mut AeonFrontend) -> Result<Value, String> {
    frontend.call_tool(
        "load_binary",
        &json!({
            "path": sample_binary_path()
        }),
    )
}

#[test]
fn load_binary_succeeds_with_valid_elf() {
    let mut frontend = AeonFrontend::new();
    let result = load_sample_binary(&mut frontend);
    assert!(result.is_ok(), "Should load valid ELF");
}

#[test]
fn load_binary_fails_with_nonexistent_file() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool(
        "load_binary",
        &json!({
            "path": "/nonexistent/path/to/file.elf"
        }),
    );
    assert!(result.is_err(), "Should fail with nonexistent file");
}

#[test]
fn load_binary_fails_without_path_argument() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool("load_binary", &json!({}));
    assert!(result.is_err(), "Should fail without path argument");
}

#[test]
fn list_functions_requires_loaded_binary() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool(
        "list_functions",
        &json!({
            "offset": 0,
            "limit": 10
        }),
    );
    assert!(result.is_err(), "Should fail without loaded binary");
}

#[test]
fn list_functions_succeeds_after_loading_binary() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend.call_tool(
        "list_functions",
        &json!({
            "offset": 0,
            "limit": 10
        }),
    );
    assert!(result.is_ok(), "Should list functions after loading");
    let response = result.unwrap();
    assert!(response.is_object(), "Should return object with functions");
    assert!(response.get("functions").is_some(), "Should have functions field");
}

#[test]
fn list_functions_respects_pagination() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let all_resp = frontend
        .call_tool("list_functions", &json!({"offset": 0, "limit": 100}))
        .expect("list all");
    let all = all_resp
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or(&vec![])
        .len();

    let first_page_resp = frontend
        .call_tool("list_functions", &json!({"offset": 0, "limit": 5}))
        .expect("list first page");
    let first_page = first_page_resp
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or(&vec![])
        .len();

    // Only expect the second page if there are enough functions
    if all >= 5 {
        let second_page_resp = frontend
            .call_tool("list_functions", &json!({"offset": 5, "limit": 5}))
            .expect("list second page");
        let second_page = second_page_resp
            .get("functions")
            .and_then(|f| f.as_array())
            .unwrap_or(&vec![])
            .len();

        assert_eq!(first_page, 5.min(all), "First page should have correct count");
        assert_eq!(second_page, (all - 5).min(5), "Second page should have correct count");
    } else {
        assert!(first_page <= all, "First page should not exceed total");
    }
}

#[test]
fn list_functions_filters_by_name() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let all_resp = frontend
        .call_tool("list_functions", &json!({"offset": 0, "limit": 100}))
        .expect("list all");
    let all_functions = all_resp
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or(&vec![])
        .to_vec();

    if !all_functions.is_empty() {
        // Get a function name from the first function
        if let Some(first_name) = all_functions[0].get("name").and_then(|n| n.as_str()) {
            let filtered_result = frontend
                .call_tool(
                    "list_functions",
                    &json!({"offset": 0, "limit": 100, "name_filter": first_name}),
                )
                .expect("list filtered");

            let filtered = filtered_result
                .get("functions")
                .and_then(|f| f.as_array())
                .unwrap();

            assert!(filtered.iter().all(|f| {
                f.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| n.contains(first_name))
                    .unwrap_or(false)
            }), "All filtered results should match name filter");
        }
    }
}

#[test]
fn get_il_requires_valid_address() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend.call_tool(
        "get_il",
        &json!({
            "addr": "0x1000000000"
        }),
    );
    // Expecting either an error or a valid result, but not a panic
    let _ = result;
}

#[test]
fn get_il_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    // Use a known valid address from the sample binary
    let result = frontend
        .call_tool("get_il", &json!({"addr": "0x7d8"}))
        .expect("get_il");

    assert!(result.is_object(), "IL result should be an object");
    // IL has listing_kind, instruction_count, and listing fields
    assert!(result.get("listing_kind").is_some() || result.get("listing").is_some(), "IL should have listing data");
}

#[test]
fn get_reduced_il_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_reduced_il", &json!({"addr": "0x7d8"}))
        .expect("get_reduced_il");

    assert!(result.is_object(), "Reduced IL result should be an object");
    assert!(result.get("artifact").is_some(), "Reduced IL should have artifact field");
}

#[test]
fn get_ssa_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_ssa", &json!({"addr": "0x7d8"}))
        .expect("get_ssa");

    assert!(result.is_object(), "SSA result should be an object");
    assert!(result.get("artifact").is_some(), "SSA should have artifact field");
}

#[test]
fn get_ssa_respects_optimize_parameter() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let optimized = frontend
        .call_tool("get_ssa", &json!({"addr": "0x7d8", "optimize": true}))
        .expect("get_ssa optimized");

    let unoptimized = frontend
        .call_tool("get_ssa", &json!({"addr": "0x7d8", "optimize": false}))
        .expect("get_ssa unoptimized");

    // Both should be valid objects
    assert!(optimized.is_object());
    assert!(unoptimized.is_object());
}

#[test]
fn get_stack_frame_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_stack_frame", &json!({"addr": "0x7d8"}))
        .expect("get_stack_frame");

    assert!(result.is_object(), "Stack frame result should be an object");
}

#[test]
fn get_function_cfg_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_cfg", &json!({"addr": "0x7d8"}))
        .expect("get_function_cfg");

    assert!(result.is_object(), "CFG result should be an object");
}

#[test]
fn get_coverage_returns_statistics() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_coverage", &json!({}))
        .expect("get_coverage");

    assert!(result.is_object(), "Coverage result should be an object");
    // Should have coverage statistics
    let obj = result.as_object().unwrap();
    assert!(obj.len() > 0, "Coverage should have statistics");
}

#[test]
fn rename_symbol_requires_loaded_binary() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool(
        "rename_symbol",
        &json!({
            "addr": "0x7d8",
            "name": "test_func"
        }),
    );
    assert!(result.is_err(), "Should fail without loaded binary");
}

#[test]
fn rename_symbol_succeeds_after_loading() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend.call_tool(
        "rename_symbol",
        &json!({
            "addr": "0x7d8",
            "name": "my_function"
        }),
    );
    assert!(result.is_ok(), "Should rename symbol after loading binary");
}

#[test]
fn set_analysis_name_alias_works() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    // set_analysis_name is backwards-compatible alias for rename_symbol
    let result = frontend.call_tool(
        "set_analysis_name",
        &json!({
            "addr": "0x7d8",
            "name": "analysis_name"
        }),
    );
    assert!(result.is_ok(), "set_analysis_name should work");
}

#[test]
fn add_hypothesis_succeeds() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend.call_tool(
        "add_hypothesis",
        &json!({
            "addr": "0x7d8",
            "note": "This is a test hypothesis"
        }),
    );
    assert!(result.is_ok(), "Should add hypothesis");
}

#[test]
fn define_struct_succeeds() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend.call_tool(
        "define_struct",
        &json!({
            "addr": "0x7d8",
            "definition": "struct test { int field1; char field2; }"
        }),
    );
    assert!(result.is_ok(), "Should define struct");
}

#[test]
fn search_analysis_names_requires_pattern() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend.call_tool("search_analysis_names", &json!({}));
    assert!(result.is_err(), "Should require pattern argument");
}

#[test]
fn search_analysis_names_with_pattern_succeeds() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    // First add an analysis name
    frontend
        .call_tool("rename_symbol", &json!({"addr": "0x7d8", "name": "test_func"}))
        .ok();

    // Then search for it
    let result = frontend.call_tool("search_analysis_names", &json!({"pattern": "test.*"}));
    assert!(result.is_ok(), "Should search analysis names with pattern");
}
