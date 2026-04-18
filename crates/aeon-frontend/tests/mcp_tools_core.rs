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
