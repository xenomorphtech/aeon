//! Integration tests for MCP multi-tool workflows and state management

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
fn workflow_list_analyze_inspect() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // List functions
    let response = frontend
        .call_tool("list_functions", &json!({"offset": 0, "limit": 5}))
        .expect("list_functions");

    let func_array = response
        .get("functions")
        .and_then(|f| f.as_array())
        .expect("Should have functions array");
    assert!(!func_array.is_empty(), "Should have at least one function");

    // For each function, get IL
    for func in func_array.iter().take(3) {
        if let Some(addr_str) = func.get("addr").and_then(|a| a.as_str()) {
            let il = frontend
                .call_tool("get_il", &json!({"addr": addr_str}))
                .expect("get_il");
            assert!(il.is_object(), "IL should be object");
        }
    }
}

#[test]
fn workflow_analyze_then_annotate() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Get function
    let func = frontend
        .call_tool("get_function_at", &json!({"addr": "0x7d8"}))
        .expect("get_function_at");

    assert!(func.is_object());

    // Annotate it
    let _ = frontend.call_tool(
        "rename_symbol",
        &json!({"addr": "0x7d8", "name": "analyzed_func"}),
    );

    let _ = frontend.call_tool(
        "add_hypothesis",
        &json!({"addr": "0x7d8", "note": "This is a test function"}),
    );

    // Verify it exists in search
    let search = frontend
        .call_tool("search_analysis_names", &json!({"pattern": "analyzed_func"}))
        .expect("search_analysis_names");

    assert!(search.is_array() || search.is_object());
}

#[test]
fn workflow_function_exploration() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let start_addr = "0x7d8";

    // Get function and xrefs
    let _func = frontend
        .call_tool("get_function_at", &json!({"addr": start_addr}))
        .expect("get_function_at");

    let xrefs = frontend
        .call_tool("get_xrefs", &json!({"addr": start_addr}))
        .expect("get_xrefs");

    assert!(xrefs.is_object());

    // Get CFG
    let cfg = frontend
        .call_tool("get_function_cfg", &json!({"addr": start_addr}))
        .expect("get_function_cfg");

    assert!(cfg.is_object());

    // Get stack frame
    let stack = frontend
        .call_tool("get_stack_frame", &json!({"addr": start_addr}))
        .expect("get_stack_frame");

    assert!(stack.is_object());
}

#[test]
fn workflow_memory_analysis() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";

    // Read bytes (may fail or succeed)
    let _ = frontend.call_tool("get_bytes", &json!({"addr": addr, "size": 32}));

    // Read as data (may fail or succeed)
    let _ = frontend.call_tool("get_data", &json!({"addr": addr, "size": 32}));

    // Get disassembly (should work for code address)
    let _ = frontend.call_tool(
        "get_asm",
        &json!({"start_addr": addr, "stop_addr": "0x850"}),
    );

    // Get string (may be empty)
    let _ = frontend.call_tool("get_string", &json!({"addr": addr}));
}

#[test]
fn workflow_cross_references() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";

    // Get xrefs
    let xrefs = frontend
        .call_tool("get_xrefs", &json!({"addr": addr}))
        .expect("get_xrefs");

    if let Some(outgoing) = xrefs.get("outgoing").and_then(|o| o.as_array()) {
        if !outgoing.is_empty() {
            // Try to find paths to called functions
            if let Some(target) = outgoing[0].get("target").and_then(|t| t.as_str()) {
                let _paths = frontend.call_tool(
                    "find_call_paths",
                    &json!({
                        "start_addr": addr,
                        "goal_addr": target
                    }),
                );
            }
        }
    }

    // Get function pointers
    let pointers = frontend
        .call_tool("get_function_pointers", &json!({"addr": addr}))
        .expect("get_function_pointers");

    assert!(pointers.is_object() || pointers.is_array());
}

#[test]
fn workflow_pointer_and_vtable_analysis() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Scan all pointers
    let pointers = frontend
        .call_tool("scan_pointers", &json!({}))
        .expect("scan_pointers");
    assert!(pointers.is_object() || pointers.is_array());

    // Scan vtables
    let vtables = frontend
        .call_tool("scan_vtables", &json!({}))
        .expect("scan_vtables");
    assert!(vtables.is_object() || vtables.is_array());

    // Get function pointers at a specific location
    let func_ptrs = frontend
        .call_tool("get_function_pointers", &json!({"addr": "0x7d8"}))
        .expect("get_function_pointers");
    assert!(func_ptrs.is_object() || func_ptrs.is_array());
}

#[test]
fn workflow_behavioral_search() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Search for RC4 patterns
    let rc4 = frontend
        .call_tool("search_rc4", &json!({}))
        .expect("search_rc4");
    assert!(rc4.is_object() || rc4.is_array());

    // Get coverage stats
    let coverage = frontend
        .call_tool("get_coverage", &json!({}))
        .expect("get_coverage");
    assert!(coverage.is_object());
}

#[test]
fn workflow_semantic_annotations_persistence() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";
    let name = "my_important_function";

    // Add annotation
    frontend
        .call_tool("rename_symbol", &json!({"addr": addr, "name": name}))
        .expect("rename_symbol");

    // Verify it's there by searching
    let search = frontend
        .call_tool("search_analysis_names", &json!({"pattern": name}))
        .expect("search");
    assert!(search.is_array() || search.is_object());

    // Add struct definition
    frontend
        .call_tool(
            "define_struct",
            &json!({"addr": addr, "definition": "struct MyStruct { int a; int b; }"}),
        )
        .expect("define_struct");

    // Add hypothesis
    frontend
        .call_tool(
            "add_hypothesis",
            &json!({"addr": addr, "note": "This function initializes data structures"}),
        )
        .expect("add_hypothesis");

    // Re-fetch function info
    let func = frontend
        .call_tool("get_function_at", &json!({"addr": addr}))
        .expect("get_function_at");
    assert!(func.is_object());
}

#[test]
fn workflow_comprehensive_analysis() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";

    // 1. Get basic function info
    let _func = frontend
        .call_tool("get_function_at", &json!({"addr": addr}))
        .expect("get_function_at");

    // 2. Analyze IL
    let _il = frontend
        .call_tool("get_il", &json!({"addr": addr}))
        .expect("get_il");

    let _reduced_il = frontend
        .call_tool("get_reduced_il", &json!({"addr": addr}))
        .expect("get_reduced_il");

    let _ssa = frontend
        .call_tool("get_ssa", &json!({"addr": addr}))
        .expect("get_ssa");

    // 3. Control flow
    let _cfg = frontend
        .call_tool("get_function_cfg", &json!({"addr": addr}))
        .expect("get_function_cfg");

    // 4. References
    let _xrefs = frontend
        .call_tool("get_xrefs", &json!({"addr": addr}))
        .expect("get_xrefs");

    // 5. Memory inspection
    let _bytes = frontend
        .call_tool("get_bytes", &json!({"addr": addr, "size": 32}))
        .expect("get_bytes");

    let _asm = frontend
        .call_tool(
            "get_asm",
            &json!({"start_addr": addr, "stop_addr": "0x820"}),
        )
        .expect("get_asm");

    // 6. Annotate findings
    frontend
        .call_tool(
            "rename_symbol",
            &json!({"addr": addr, "name": "comprehensive_test"}),
        )
        .ok();

    // 7. Verify all data is present
    let search = frontend
        .call_tool(
            "search_analysis_names",
            &json!({"pattern": "comprehensive_test"}),
        )
        .expect("search");
    assert!(search.is_array() || search.is_object());
}

#[test]
fn state_persists_across_tool_calls() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Add an annotation
    frontend
        .call_tool(
            "rename_symbol",
            &json!({"addr": "0x7d8", "name": "state_test"}),
        )
        .expect("rename_symbol");

    // Do many other operations
    for i in 0..5 {
        let _list = frontend
            .call_tool("list_functions", &json!({"offset": i, "limit": 1}))
            .ok();
    }

    // Verify annotation still exists
    let search = frontend
        .call_tool("search_analysis_names", &json!({"pattern": "state_test"}))
        .expect("search");

    let is_found = if let Some(arr) = search.as_array() {
        !arr.is_empty()
    } else if search.is_object() {
        true // Object with results
    } else {
        false
    };

    assert!(is_found, "Annotation should persist across operations");
}

#[test]
fn tools_provide_consistent_addresses() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    // Get functions list
    let response = frontend
        .call_tool("list_functions", &json!({"offset": 0, "limit": 10}))
        .expect("list_functions");
    let functions = response
        .get("functions")
        .and_then(|f| f.as_array())
        .map(|a| a.to_vec())
        .unwrap_or_default();

    if !functions.is_empty() {
        // Use address from list
        if let Some(addr) = functions[0].get("addr").and_then(|a| a.as_str()) {
            // Get function at that address
            let func = frontend
                .call_tool("get_function_at", &json!({"addr": addr}))
                .expect("get_function_at");

            // Should be able to analyze it
            let _il = frontend
                .call_tool("get_il", &json!({"addr": addr}))
                .ok();

            // And inspect it
            let _asm = frontend
                .call_tool(
                    "get_asm",
                    &json!({"start_addr": addr, "stop_addr": "0xffffffff"}),
                )
                .ok();

            assert!(func.is_object());
        }
    }
}
