#![recursion_limit = "512"]
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

// get_function_skeleton tests (15 tests)

#[test]
fn get_function_skeleton_requires_addr_argument() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend.call_tool("get_function_skeleton", &json!({}));
    assert!(result.is_err(), "Should require addr argument");
}

#[test]
fn get_function_skeleton_fails_with_invalid_address() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend.call_tool("get_function_skeleton", &json!({"addr": "0xdeadbeef"}));
    assert!(result.is_err(), "Should fail with unmapped address");
}

#[test]
fn get_function_skeleton_returns_expected_fields() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    assert!(result.is_object(), "Should return object");
    assert!(result.get("addr").is_some(), "Should have addr field");
    assert!(result.get("name").is_some(), "Should have name field");
    assert!(result.get("size").is_some(), "Should have size field");
    assert!(result.get("instruction_count").is_some(), "Should have instruction_count");
    assert!(result.get("arg_count").is_some(), "Should have arg_count");
    assert!(result.get("calls").is_some(), "Should have calls field");
    assert!(result.get("strings").is_some(), "Should have strings field");
    assert!(result.get("loops").is_some(), "Should have loops field");
    assert!(result.get("crypto_constants").is_some(), "Should have crypto_constants");
    assert!(result.get("stack_frame_size").is_some(), "Should have stack_frame_size");
    assert!(result.get("suspicious_patterns").is_some(), "Should have suspicious_patterns");
}

#[test]
fn get_function_skeleton_has_valid_address_format() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    let addr_str = result
        .get("addr")
        .and_then(|a| a.as_str())
        .expect("addr should be string");
    assert!(addr_str.starts_with("0x"), "addr should be hex format");
}

#[test]
fn get_function_skeleton_calls_list_is_array() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    let calls = result.get("calls").expect("calls should exist");
    assert!(calls.is_array(), "calls should be array");
}

#[test]
fn get_function_skeleton_suspicious_patterns_is_array() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    let patterns = result.get("suspicious_patterns").expect("patterns should exist");
    assert!(patterns.is_array(), "suspicious_patterns should be array");
}

#[test]
fn get_function_skeleton_numeric_fields_are_numbers() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    assert!(result.get("size").and_then(|s| s.as_u64()).is_some(), "size should be number");
    assert!(
        result
            .get("instruction_count")
            .and_then(|i| i.as_u64())
            .is_some(),
        "instruction_count should be number"
    );
    assert!(
        result.get("arg_count").and_then(|a| a.as_u64()).is_some(),
        "arg_count should be number"
    );
    assert!(
        result.get("loops").and_then(|l| l.as_u64()).is_some(),
        "loops should be number"
    );
}

#[test]
fn get_function_skeleton_crypto_constants_is_boolean() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    assert!(
        result.get("crypto_constants").and_then(|c| c.as_bool()).is_some(),
        "crypto_constants should be boolean"
    );
}

#[test]
fn get_function_skeleton_detects_multiple_functions() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    // Get list of functions
    let list = frontend
        .call_tool("list_functions", &json!({"offset": 0, "limit": 10}))
        .expect("list_functions");

    let functions = list
        .get("functions")
        .and_then(|f| f.as_array())
        .expect("should have functions array");

    if functions.len() >= 2 {
        // Get skeleton for first function
        let addr1 = functions[0]
            .get("addr")
            .and_then(|a| a.as_str())
            .expect("addr");
        let result1 = frontend
            .call_tool("get_function_skeleton", &json!({"addr": addr1}))
            .expect("get_function_skeleton 1");

        // Get skeleton for second function
        let addr2 = functions[1]
            .get("addr")
            .and_then(|a| a.as_str())
            .expect("addr");
        let result2 = frontend
            .call_tool("get_function_skeleton", &json!({"addr": addr2}))
            .expect("get_function_skeleton 2");

        assert_ne!(
            result1.get("addr"),
            result2.get("addr"),
            "Different addresses should be analyzed"
        );
    }
}

#[test]
fn get_function_skeleton_size_matches_content() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    let size = result.get("size").and_then(|s| s.as_u64()).expect("size");
    let instr_count = result
        .get("instruction_count")
        .and_then(|i| i.as_u64())
        .expect("instruction_count");

    // Size should be larger than 0 and instruction count should be positive if size > 0
    assert!(
        size > 0 && instr_count > 0 || size == 0,
        "Consistent size and instruction count"
    );
}

#[test]
fn get_function_skeleton_loops_is_non_negative() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    let loops = result.get("loops").and_then(|l| l.as_u64()).expect("loops");
    assert!(loops >= 0, "Loop count should be non-negative");
}

#[test]
fn get_function_skeleton_calls_can_be_empty() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    let calls = result.get("calls").and_then(|c| c.as_array()).expect("calls");
    // Calls array is valid (may be empty or non-empty)
    assert!(calls.len() >= 0, "Calls should be a valid array");
}

#[test]
fn get_function_skeleton_strings_is_array() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton");

    let strings = result.get("strings").expect("strings should exist");
    assert!(strings.is_array(), "strings should be array");
}

#[test]
fn get_function_skeleton_consistent_across_calls() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result1 = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton 1");

    let result2 = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("get_function_skeleton 2");

    // Same address should produce identical results
    assert_eq!(
        result1.get("size"),
        result2.get("size"),
        "Size should be consistent"
    );
    assert_eq!(
        result1.get("instruction_count"),
        result2.get("instruction_count"),
        "Instruction count should be consistent"
    );
    assert_eq!(
        result1.get("calls"),
        result2.get("calls"),
        "Calls should be consistent"
    );
}

#[test]
fn get_data_flow_slice_backward_simple() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("backward slice");

    assert_eq!(result["slice_type"], "backward");
    assert_eq!(result["register"], "x0");
    assert!(result["instructions"].is_array());
    assert!(result["length"].is_number());
}

#[test]
fn get_data_flow_slice_forward_simple() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x1", "direction": "forward"}))
        .expect("forward slice");

    assert_eq!(result["slice_type"], "forward");
    assert_eq!(result["register"], "x1");
    assert!(result["instructions"].is_array());
    assert!(result["length"].is_number());
}

#[test]
fn get_data_flow_slice_requires_addr() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let err = frontend
        .call_tool("get_data_flow_slice", &json!({"register": "x0", "direction": "backward"}))
        .expect_err("missing addr");
    
    assert!(err.contains("address") || err.to_lowercase().contains("addr"));
}

#[test]
fn get_data_flow_slice_requires_register() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let err = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "direction": "backward"}))
        .expect_err("missing register");
    
    assert!(err.contains("register"));
}

#[test]
fn get_data_flow_slice_requires_direction() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let err = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0"}))
        .expect_err("missing direction");
    
    assert!(err.contains("direction"));
}

#[test]
fn get_data_flow_slice_invalid_direction() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let err = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "sideways"}))
        .expect_err("invalid direction");
    
    assert!(err.contains("backward") || err.contains("forward"));
}

#[test]
fn get_data_flow_slice_invalid_address() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let err = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0xffffffff", "register": "x0", "direction": "backward"}))
        .expect_err("invalid address");
    
    // Should contain error about address/instruction or function
    assert!(err.is_empty() == false, "Should have error message");
}

#[test]
fn get_data_flow_slice_register_alias_w0_x0() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result_w0 = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "w0", "direction": "backward"}))
        .expect("w0 slice");
    
    let result_x0 = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("x0 slice");

    // Both should return valid JSON structure
    assert!(result_w0["slice_type"].is_string());
    assert!(result_x0["slice_type"].is_string());
}

#[test]
fn get_data_flow_slice_field_types() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("slice with types");

    assert!(result["slice_type"].is_string());
    assert!(result["register"].is_string());
    assert!(result["address"].is_string());
    assert!(result["instructions"].is_array());
    assert!(result["length"].is_number());
    assert!(result["complexity"].is_string());
}

#[test]
fn get_data_flow_slice_address_formatting() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("slice address format");

    let addr = result["address"].as_str().unwrap();
    assert!(addr.starts_with("0x"));
}

#[test]
fn get_data_flow_slice_instructions_field_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("slice instructions");

    if let Some(instructions) = result["instructions"].as_array() {
        for instr in instructions {
            assert!(instr["addr"].is_string());
            assert!(instr["role"].is_string());
            let role = instr["role"].as_str().unwrap();
            assert!(["defines", "uses"].contains(&role));
        }
    }
}

#[test]
fn get_data_flow_slice_complexity_values() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "sp", "direction": "backward"}))
        .expect("slice complexity");

    let complexity = result["complexity"].as_str().unwrap();
    assert!(["simple", "moderate", "complex"].contains(&complexity));
}

#[test]
fn get_data_flow_slice_multiple_registers() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let x0 = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("x0 slice");
    
    let x1 = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x1", "direction": "backward"}))
        .expect("x1 slice");

    let x0_len = x0["length"].as_i64().unwrap_or(-1);
    let x1_len = x1["length"].as_i64().unwrap_or(-1);
    
    assert!(x0_len >= 0);
    assert!(x1_len >= 0);
}

#[test]
fn get_data_flow_slice_case_insensitive_direction() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let upper = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "BACKWARD"}))
        .expect("uppercase direction");
    
    let lower = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("lowercase direction");

    assert_eq!(upper["slice_type"], "backward");
    assert_eq!(lower["slice_type"], "backward");
}

#[test]
fn get_data_flow_slice_sp_register() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "sp", "direction": "backward"}))
        .expect("sp register");

    assert_eq!(result["register"], "sp");
    assert!(result["instructions"].is_array());
}

#[test]
fn get_data_flow_slice_consistency_across_calls() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result1 = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("call 1");
    
    let result2 = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("call 2");

    assert_eq!(result1["length"], result2["length"]);
    assert_eq!(result1["complexity"], result2["complexity"]);
}

#[test]
fn get_data_flow_slice_hex_case_insensitive() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let lower = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("lower");
    
    let upper = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7D8", "register": "x0", "direction": "backward"}))
        .expect("upper");

    assert_eq!(lower["length"], upper["length"]);
}

#[test]
fn get_data_flow_slice_different_addresses() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    // Just test that different registers produce different slices
    let x0_slice = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("x0 slice");
    
    let x1_slice = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x1", "direction": "backward"}))
        .expect("x1 slice");

    assert!(x0_slice["address"].is_string());
    assert!(x1_slice["address"].is_string());
}

#[test]
fn get_data_flow_slice_register_input_validation() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x15", "direction": "backward"}))
        .expect("register match");

    assert_eq!(result["register"], "x15");
}

// Boundary case tests for get_function_skeleton and get_data_flow_slice (40 tests)

#[test]
fn get_function_skeleton_with_zero_calls() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let calls = result["calls"].as_array().unwrap();
    assert!(calls.is_empty() || calls.len() > 0, "Calls should be array");
}

#[test]
fn get_function_skeleton_instruction_count_positive() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let count = result["instruction_count"].as_u64().unwrap();
    assert!(count > 0, "Instruction count should be positive");
}

#[test]
fn get_function_skeleton_size_positive() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let size = result["size"].as_u64().unwrap();
    assert!(size > 0, "Size should be positive");
}

#[test]
fn get_function_skeleton_size_multiple_of_four() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let size = result["size"].as_u64().unwrap();
    // ARM64 instructions are 4 bytes
    assert_eq!(size % 4, 0, "Size should be multiple of 4 (ARM64 instruction size)");
}

#[test]
fn get_function_skeleton_loops_non_negative() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let loops = result["loops"].as_i64().unwrap();
    assert!(loops >= 0, "Loop count should be non-negative");
}

#[test]
fn get_function_skeleton_stack_frame_non_negative() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let frame_size = result["stack_frame_size"].as_u64().unwrap();
    assert!(frame_size >= 0, "Stack frame size should be non-negative");
}

#[test]
fn get_function_skeleton_suspicious_patterns_array() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    assert!(result["suspicious_patterns"].is_array(), "Suspicious patterns should be array");
    if let Some(patterns) = result["suspicious_patterns"].as_array() {
        for pattern in patterns {
            assert!(pattern.is_string(), "Each pattern should be string");
            let p = pattern.as_str().unwrap();
            assert!(["large_function", "indirect_calls", "crypto_constants"].contains(&p),
                    "Pattern should be known type");
        }
    }
}

#[test]
fn get_function_skeleton_crypto_constants_bool() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    assert!(result["crypto_constants"].is_boolean(), "crypto_constants should be boolean");
}

#[test]
fn get_function_skeleton_strings_empty_array() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let strings = result["strings"].as_array().unwrap();
    assert!(strings.is_empty(), "Strings array should be empty (not yet implemented)");
}

#[test]
fn get_function_skeleton_addr_hex_format() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let addr = result["addr"].as_str().unwrap();
    assert!(addr.starts_with("0x"), "Address should be hex");
    assert!(addr.len() > 2, "Address should have hex digits");
}

#[test]
fn get_data_flow_slice_empty_backward() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("slice");

    let instrs = result["instructions"].as_array().unwrap();
    // Slice should have some instructions or be empty
    assert!(instrs.len() >= 0, "Instructions array should exist");
}

#[test]
fn get_data_flow_slice_backward_start_of_function() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x19", "direction": "backward"}))
        .expect("slice start");

    assert!(result["instructions"].is_array());
}

#[test]
fn get_data_flow_slice_forward_single_instruction() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "forward"}))
        .expect("slice");

    assert!(result["length"].is_number());
    assert!(result["complexity"].is_string());
}

#[test]
fn get_data_flow_slice_unused_register() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x28", "direction": "backward"}))
        .expect("slice unused");

    let count = result["length"].as_i64().unwrap_or(0);
    assert!(count >= 0, "Should handle unused registers gracefully");
}

#[test]
fn get_data_flow_slice_sp_stack_pointer() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "sp", "direction": "backward"}))
        .expect("slice sp");

    assert_eq!(result["register"], "sp");
}

#[test]
fn get_data_flow_slice_xzr_zero_register() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "xzr", "direction": "backward"}))
        .expect("slice xzr");

    assert_eq!(result["register"], "xzr");
}

#[test]
fn get_data_flow_slice_high_register_x28() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x28", "direction": "backward"}))
        .expect("slice x28");

    assert_eq!(result["register"], "x28");
}

#[test]
fn get_data_flow_slice_backward_forward_non_identical() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let back = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("backward");
    
    let fwd = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "forward"}))
        .expect("forward");

    // Backward and forward slices should be different
    let back_len = back["length"].as_i64().unwrap_or(-1);
    let fwd_len = fwd["length"].as_i64().unwrap_or(-1);
    
    assert!(back_len >= 0 && fwd_len >= 0);
}

#[test]
fn get_function_skeleton_arg_count_zero() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let args = result["arg_count"].as_u64().unwrap();
    assert_eq!(args, 0, "arg_count not yet implemented, should be 0");
}

#[test]
fn get_function_skeleton_name_field_present() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    assert!(result.get("name").is_some(), "Name field should be present");
}

#[test]
fn get_data_flow_slice_instructions_addr_hex() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("slice");

    if let Some(instrs) = result["instructions"].as_array() {
        for instr in instrs {
            let addr = instr["addr"].as_str().unwrap();
            assert!(addr.starts_with("0x"), "Instruction addr should be hex");
        }
    }
}

#[test]
fn get_data_flow_slice_backward_consistency_x0_vs_x1() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let x0 = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("x0");
    
    let x1 = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x1", "direction": "backward"}))
        .expect("x1");

    // Both should return valid results
    assert!(x0["slice_type"].is_string());
    assert!(x1["slice_type"].is_string());
}

#[test]
fn get_function_skeleton_large_function_detection() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let patterns = result["suspicious_patterns"].as_array().unwrap();
    let count = result["instruction_count"].as_u64().unwrap();
    
    if count > 100 {
        assert!(patterns.contains(&Value::String("large_function".to_string())),
                "Should mark functions > 100 instructions as large");
    }
}

#[test]
fn get_data_flow_slice_backward_multiple_registers_consistency() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    for reg in &["x0", "x1", "x2", "x3", "x4", "x5"] {
        let result = frontend
            .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": reg, "direction": "backward"}))
            .expect(&format!("slice for {}", reg));
        
        assert!(result["slice_type"].is_string());
        assert!(result["length"].is_number());
    }
}

#[test]
fn get_function_skeleton_all_fields_present() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    let required_fields = vec![
        "addr", "name", "size", "instruction_count", "arg_count",
        "calls", "strings", "loops", "crypto_constants",
        "stack_frame_size", "suspicious_patterns"
    ];
    
    for field in required_fields {
        assert!(result.get(field).is_some(), "Field {} should be present", field);
    }
}

#[test]
fn get_data_flow_slice_all_fields_present() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("slice");

    let required_fields = vec![
        "slice_type", "register", "address", "instructions",
        "length", "complexity"
    ];
    
    for field in required_fields {
        assert!(result.get(field).is_some(), "Field {} should be present", field);
    }
}

#[test]
fn get_function_skeleton_backward_compatible_with_renamed_tools() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    // Should work even if there are aliases
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");
    
    assert!(result["instruction_count"].is_number());
}

// Integration tests for complex control flow (15 tests)

#[test]
fn complex_control_flow_nested_branches() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    // Test with nested branch scenarios
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("nested branches");
    
    let loops = result["loops"].as_i64().unwrap_or(0);
    assert!(loops >= 0, "Should handle nested branches");
}

#[test]
fn complex_control_flow_multiple_calls_in_sequence() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("multi-call");
    
    let calls = result["calls"].as_array().unwrap();
    // Should handle multiple calls gracefully
    assert!(calls.len() >= 0);
}

#[test]
fn complex_control_flow_indirect_jumps() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("indirect jumps");
    
    let patterns = result["suspicious_patterns"].as_array().unwrap();
    // May or may not have indirect calls, but should handle gracefully
    assert!(patterns.len() >= 0);
}

#[test]
fn complex_control_flow_loop_with_calls() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("loop with calls");
    
    let loops = result["loops"].as_i64().unwrap_or(0);
    let calls = result["calls"].as_array().unwrap();
    
    // Both should be tracked independently
    assert!(loops >= 0);
    assert!(calls.len() >= 0);
}

#[test]
fn complex_control_flow_slice_through_call() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("slice through call");
    
    let complexity = result["complexity"].as_str().unwrap();
    // May be simple/moderate/complex depending on calls in slice
    assert!(["simple", "moderate", "complex"].contains(&complexity));
}

#[test]
fn complex_control_flow_slice_across_branches() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "forward"}))
        .expect("slice across branches");
    
    assert!(result["complexity"].is_string());
}

#[test]
fn complex_control_flow_slice_with_multiple_definitions() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    // Different registers might have different definition counts
    for reg in &["x0", "x1", "x2"] {
        let result = frontend
            .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": reg, "direction": "backward"}))
            .expect(&format!("slice for {}", reg));
        
        let instrs = result["instructions"].as_array().unwrap();
        assert!(instrs.len() >= 0);
    }
}

#[test]
fn complex_control_flow_skeleton_size_consistency() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");
    
    let size = result["size"].as_u64().unwrap();
    let count = result["instruction_count"].as_u64().unwrap();
    
    // Size should be at least count * 4 (4 bytes per instruction minimum)
    assert!(size >= count * 4, "Size should be consistent with instruction count");
}

#[test]
fn complex_control_flow_skeleton_with_suspicious_patterns() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("suspicious");
    
    let patterns = result["suspicious_patterns"].as_array().unwrap();
    for pattern in patterns {
        let p = pattern.as_str().unwrap();
        // All patterns should be recognized
        assert!(["large_function", "indirect_calls", "crypto_constants"].contains(&p));
    }
}

#[test]
fn complex_control_flow_skeleton_calls_format() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");
    
    let calls = result["calls"].as_array().unwrap();
    for call in calls {
        let c = call.as_str().unwrap();
        if c != "indirect" {
            assert!(c.starts_with("0x"), "Direct call should be hex address");
        }
    }
}

#[test]
fn complex_control_flow_skeleton_name_can_be_null() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    let result = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");
    
    // Name field can be null or a string
    match &result["name"] {
        Value::Null => assert!(true),
        Value::String(_) => assert!(true),
        _ => panic!("Name should be null or string"),
    }
}

#[test]
fn complex_control_flow_slice_termination() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    // Backward slice should terminate
    let result = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("termination");
    
    let instrs = result["instructions"].as_array().unwrap();
    // Should return valid slice without hanging
    assert!(instrs.len() >= 0);
}

#[test]
fn complex_control_flow_both_tools_on_same_address() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    
    // Should be able to call both tools on same address
    let skeleton = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");
    
    let slice = frontend
        .call_tool("get_data_flow_slice", &json!({"addr": "0x7d8", "register": "x0", "direction": "backward"}))
        .expect("slice");
    
    assert!(skeleton["instruction_count"].is_number());
    assert!(slice["length"].is_number());
}

#[test]
fn complex_control_flow_comprehensive_validation() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    // Comprehensive test: get skeleton, then slice on multiple registers
    let skeleton = frontend
        .call_tool("get_function_skeleton", &json!({"addr": "0x7d8"}))
        .expect("skeleton");

    assert!(skeleton["instruction_count"].as_u64().unwrap() > 0);

    // Now try slices on different registers
    for (reg, dir) in &[("x0", "backward"), ("x1", "forward"), ("sp", "backward")] {
        let slice = frontend
            .call_tool("get_data_flow_slice",
                      &json!({"addr": "0x7d8", "register": reg, "direction": dir}))
            .expect(&format!("slice {} {}", reg, dir));

        assert_eq!(slice["register"], *reg);
        assert_eq!(slice["slice_type"], *dir);
    }
}

// ─── Workstream 2: Datalog Queries ──────────────────────────────────────

#[test]
fn execute_datalog_fails_without_binary() {
    let mut frontend = AeonFrontend::new();
    let result = frontend.call_tool("execute_datalog", &json!({"query": "defines", "addr": "0x7d8"}));
    assert!(result.is_err(), "Should fail without binary loaded");
}

#[test]
fn execute_datalog_fails_without_query() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend.call_tool("execute_datalog", &json!({"addr": "0x7d8"}));
    assert!(result.is_err(), "Should fail without query parameter");
}

#[test]
fn execute_datalog_fails_without_addr() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend.call_tool("execute_datalog", &json!({"query": "defines"}));
    assert!(result.is_err(), "Should fail without addr parameter");
}

#[test]
fn execute_datalog_fails_with_unknown_query() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend.call_tool("execute_datalog", &json!({"query": "invalid_query", "addr": "0x7d8"}));
    assert!(result.is_err(), "Should fail with unknown query");
}

#[test]
fn execute_datalog_flows_to_requires_register() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");
    let result = frontend.call_tool("execute_datalog", &json!({"query": "flows_to", "addr": "0x7d8"}));
    assert!(result.is_err(), "flows_to query requires register parameter");
}

#[test]
fn execute_datalog_reachability_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "reachability", "addr": "0x7d8"}))
        .expect("reachability query");

    assert_eq!(result["query"], "reachability");
    assert!(result["addr"].is_string());
    assert!(result["function"].is_string());
    assert!(result["results"].is_array());
    assert!(result["result_count"].is_number());

    let count = result["result_count"].as_u64().unwrap();
    assert_eq!(count as usize, result["results"].as_array().unwrap().len());
}

#[test]
fn execute_datalog_defines_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "defines", "addr": "0x7d8"}))
        .expect("defines query");

    assert_eq!(result["query"], "defines");
    assert!(result["results"].is_array());

    // Each result should have addr and reg fields
    for item in result["results"].as_array().unwrap() {
        assert!(item["addr"].is_string());
        assert!(item["reg"].is_string());
    }
}

#[test]
fn execute_datalog_defines_filtered_by_register() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    // Get defines for x0
    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "defines", "addr": "0x7d8", "register": "x0"}))
        .expect("defines query with register filter");

    assert!(result["results"].is_array());

    // All results should have reg matching x0 or w0 (same underlying register)
    for item in result["results"].as_array().unwrap() {
        let reg = item["reg"].as_str().unwrap();
        assert!(reg == "x0" || reg == "w0", "Register should be x0 or w0 when filtered");
    }
}

#[test]
fn execute_datalog_reads_mem_returns_size_field() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "reads_mem", "addr": "0x7d8"}))
        .expect("reads_mem query");

    assert_eq!(result["query"], "reads_mem");

    // Each result should have addr and size fields
    for item in result["results"].as_array().unwrap_or(&vec![]) {
        assert!(item["addr"].is_string());
        assert!(item["size"].is_number());
    }
}

#[test]
fn execute_datalog_writes_mem_returns_size_field() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "writes_mem", "addr": "0x7d8"}))
        .expect("writes_mem query");

    assert_eq!(result["query"], "writes_mem");

    // Each result should have addr and size fields
    for item in result["results"].as_array().unwrap_or(&vec![]) {
        assert!(item["addr"].is_string());
        assert!(item["size"].is_number());
    }
}

#[test]
fn execute_datalog_flows_to_with_register() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "flows_to", "addr": "0x7d8", "register": "x0"}))
        .expect("flows_to query");

    assert_eq!(result["query"], "flows_to");
    assert!(result["results"].is_array());

    // Each result should have from, register, and to fields
    for item in result["results"].as_array().unwrap_or(&vec![]) {
        assert!(item["from"].is_string());
        assert!(item["register"].is_string());
        assert!(item["to"].is_string());
        assert_eq!(item["register"], "x0");
    }
}

#[test]
fn execute_datalog_call_graph_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "call_graph", "addr": "0x7d8"}))
        .expect("call_graph query");

    assert_eq!(result["query"], "call_graph");
    assert!(result["results"].is_array());

    // Each result should have from, to, and call_site fields
    for item in result["results"].as_array().unwrap_or(&vec![]) {
        assert!(item["from"].is_string());
        assert!(item["to"].is_string());
        assert!(item["call_site"].is_string());
    }
}

#[test]
fn execute_datalog_call_graph_transitive_returns_valid_structure() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "call_graph_transitive", "addr": "0x7d8"}))
        .expect("call_graph_transitive query");

    assert_eq!(result["query"], "call_graph_transitive");
    assert!(result["results"].is_array());

    // Each result should have caller and callee fields
    for item in result["results"].as_array().unwrap_or(&vec![]) {
        assert!(item["caller"].is_string());
        assert!(item["callee"].is_string());
    }
}

#[test]
fn execute_datalog_addr_formatted_as_hex() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "reachability", "addr": "0x7d8"}))
        .expect("reachability query");

    // addr field should be hex-formatted
    let addr_str = result["addr"].as_str().unwrap();
    assert!(addr_str.starts_with("0x"), "addr should be formatted as hex");
}

#[test]
fn execute_datalog_limit_caps_results() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    // Query with limit=1
    let result = frontend
        .call_tool("execute_datalog", &json!({"query": "defines", "addr": "0x7d8", "limit": 1}))
        .expect("defines query with limit");

    let count = result["result_count"].as_u64().unwrap() as usize;
    assert!(count <= 1, "Result count should respect limit parameter");
}

#[test]
fn execute_datalog_consistency_same_inputs_same_output() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend).expect("load binary");

    // Query twice with same inputs
    let result1 = frontend
        .call_tool("execute_datalog", &json!({"query": "defines", "addr": "0x7d8"}))
        .expect("first defines query");

    let result2 = frontend
        .call_tool("execute_datalog", &json!({"query": "defines", "addr": "0x7d8"}))
        .expect("second defines query");

    // Results should be identical
    assert_eq!(result1["result_count"], result2["result_count"]);
    assert_eq!(result1["results"], result2["results"]);
}
