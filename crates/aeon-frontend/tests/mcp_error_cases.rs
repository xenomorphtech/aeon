//! Integration tests for MCP error handling and edge cases

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
fn tool_calls_without_loaded_binary_fail_gracefully() {
    let mut frontend = AeonFrontend::new();

    let tools = vec![
        ("list_functions", json!({})),
        ("get_il", json!({"addr": "0x7d8"})),
        ("get_reduced_il", json!({"addr": "0x7d8"})),
        ("get_ssa", json!({"addr": "0x7d8"})),
        ("get_stack_frame", json!({"addr": "0x7d8"})),
        ("get_function_cfg", json!({"addr": "0x7d8"})),
        ("get_xrefs", json!({"addr": "0x7d8"})),
        ("get_function_pointers", json!({"addr": "0x7d8"})),
        ("get_bytes", json!({"addr": "0x7d8", "size": 16})),
        ("get_data", json!({"addr": "0x7d8", "size": 16})),
        ("get_string", json!({"addr": "0x7d8"})),
        ("get_function_at", json!({"addr": "0x7d8"})),
    ];

    for (tool_name, args) in tools {
        let result = frontend.call_tool(tool_name, &args);
        assert!(
            result.is_err(),
            "Tool {} should fail without loaded binary",
            tool_name
        );
    }
}

#[test]
fn invalid_address_format_handled() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let invalid_addrs = vec!["not_hex", "0x", "0xGGG", "0x7d8x", ""];

    for addr in invalid_addrs {
        // These tools require an address parameter
        let _ = frontend.call_tool("get_il", &json!({"addr": addr}));
        let _ = frontend.call_tool("get_bytes", &json!({"addr": addr, "size": 16}));
        let _ = frontend.call_tool("get_function_at", &json!({"addr": addr}));
    }
}

#[test]
fn out_of_range_addresses_handled() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let huge_addresses = vec!["0x10000000000000"];

    for addr in huge_addresses {
        // Should not panic, may return empty or error
        let _ = frontend.call_tool("get_bytes", &json!({"addr": addr, "size": 16}));
        let _ = frontend.call_tool("get_function_at", &json!({"addr": addr}));
    }
}

#[test]
fn negative_size_parameters_handled() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // JSON doesn't really have negative numbers in the same way, but we can test 0 and large values
    let _ = frontend.call_tool("get_bytes", &json!({"addr": "0x7d8", "size": 0}));
    let _ = frontend.call_tool("get_bytes", &json!({"addr": "0x7d8", "size": 1000000}));
}

#[test]
fn list_functions_boundary_pagination() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Offset beyond available functions
    let result = frontend.call_tool(
        "list_functions",
        &json!({"offset": 999999, "limit": 10}),
    );
    assert!(result.is_ok(), "Should handle offset beyond range gracefully");
}

#[test]
fn call_paths_with_identical_addresses() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend.call_tool(
        "find_call_paths",
        &json!({
            "start_addr": "0x7d8",
            "goal_addr": "0x7d8"
        }),
    );
    // Should not panic, may be empty path or direct match
    let _ = result;
}

#[test]
fn call_paths_unreachable_target() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let result = frontend.call_tool(
        "find_call_paths",
        &json!({
            "start_addr": "0x7d8",
            "goal_addr": "0x1"  // Likely unreachable
        }),
    );
    // Should handle gracefully, may be empty result
    let _ = result;
}

#[test]
fn analysis_name_operations_with_invalid_addresses() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let _ = frontend.call_tool(
        "rename_symbol",
        &json!({
            "addr": "0xffffffffffffffff",
            "name": "test"
        }),
    );

    let _ = frontend.call_tool(
        "add_hypothesis",
        &json!({
            "addr": "0xffffffffffffffff",
            "note": "test"
        }),
    );

    let _ = frontend.call_tool(
        "define_struct",
        &json!({
            "addr": "0xffffffffffffffff",
            "definition": "struct test {}"
        }),
    );
}

#[test]
fn search_with_invalid_regex_pattern() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Try an invalid regex pattern
    let result = frontend.call_tool("search_analysis_names", &json!({"pattern": "[invalid regex"}));
    // Should handle gracefully
    let _ = result;
}

#[test]
fn empty_string_parameters() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Empty name
    let _ = frontend.call_tool("rename_symbol", &json!({"addr": "0x7d8", "name": ""}));

    // Empty note
    let _ = frontend.call_tool("add_hypothesis", &json!({"addr": "0x7d8", "note": ""}));

    // Empty struct definition
    let _ = frontend.call_tool(
        "define_struct",
        &json!({"addr": "0x7d8", "definition": ""}),
    );

    // Empty regex pattern
    let _ = frontend.call_tool("search_analysis_names", &json!({"pattern": ""}));
}

#[test]
fn very_long_string_parameters() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let long_string = "a".repeat(10000);

    let _ = frontend.call_tool(
        "rename_symbol",
        &json!({"addr": "0x7d8", "name": long_string}),
    );

    let _ = frontend.call_tool(
        "add_hypothesis",
        &json!({"addr": "0x7d8", "note": long_string}),
    );

    let _ = frontend.call_tool(
        "define_struct",
        &json!({"addr": "0x7d8", "definition": long_string}),
    );
}

#[test]
fn special_characters_in_names() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let special_names = vec![
        "test<>function",
        "func::with::namespace",
        "func with spaces",
        "func\nwith\nnewlines",
        "func\twith\ttabs",
        "func\\with\\backslashes",
        "func'with'quotes",
        "func\"with\"doublequotes",
    ];

    for name in special_names {
        let _ = frontend.call_tool(
            "rename_symbol",
            &json!({"addr": "0x7d8", "name": name}),
        );
    }
}

#[test]
fn unicode_in_string_parameters() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let unicode_strings = vec![
        "function_名前",  // Japanese
        "fonction_名前",  // Mixed
        "🔥test🔥",     // Emoji
        "функция",       // Cyrillic
        "ل",            // Arabic
    ];

    for s in unicode_strings {
        let _ = frontend.call_tool("rename_symbol", &json!({"addr": "0x7d8", "name": s}));
        let _ = frontend.call_tool("add_hypothesis", &json!({"addr": "0x7d8", "note": s}));
    }
}

#[test]
fn get_asm_with_invalid_range() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // stop_addr before start_addr
    let _ = frontend.call_tool(
        "get_asm",
        &json!({
            "start_addr": "0x800",
            "stop_addr": "0x7d8"
        }),
    );

    // Identical addresses
    let _ = frontend.call_tool(
        "get_asm",
        &json!({
            "start_addr": "0x7d8",
            "stop_addr": "0x7d8"
        }),
    );

    // Very large range
    let _ = frontend.call_tool(
        "get_asm",
        &json!({
            "start_addr": "0x0",
            "stop_addr": "0xffffffff"
        }),
    );
}

#[test]
fn load_binary_with_unsupported_format() {
    let mut frontend = AeonFrontend::new();

    // Try loading with unsupported format
    let result = frontend.call_tool(
        "load_binary",
        &json!({
            "path": sample_binary_path(),
            "format": "unsupported_format"
        }),
    );
    // Should either work (if format is ignored) or fail gracefully
    let _ = result;
}

#[test]
fn multiple_sequential_loads() {
    let mut frontend = AeonFrontend::new();

    // Load same binary multiple times
    let path = sample_binary_path();
    for _ in 0..3 {
        let result = frontend.call_tool("load_binary", &json!({"path": path}));
        assert!(result.is_ok(), "Should allow reloading binary");
    }

    // Should still work after multiple loads
    let list = frontend.call_tool("list_functions", &json!({"offset": 0, "limit": 10}));
    assert!(list.is_ok(), "Should work after multiple loads");
}

#[test]
fn tool_state_isolation() {
    let mut frontend1 = AeonFrontend::new();
    let mut frontend2 = AeonFrontend::new();

    // Load in frontend1
    load_sample_binary(&mut frontend1);

    // frontend2 should not have binary loaded
    let result = frontend2.call_tool("list_functions", &json!({"offset": 0, "limit": 10}));
    assert!(result.is_err(), "Frontend instances should be isolated");

    // Load in frontend2
    load_sample_binary(&mut frontend2);

    // Both should now work independently
    let list1 = frontend1.call_tool("list_functions", &json!({"offset": 0, "limit": 10}));
    let list2 = frontend2.call_tool("list_functions", &json!({"offset": 0, "limit": 10}));
    assert!(list1.is_ok());
    assert!(list2.is_ok());
}
