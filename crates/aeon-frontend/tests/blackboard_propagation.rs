//! Integration tests for blackboard mutations and semantic propagation
//!
//! Demonstrates end-to-end workflows showing how rename_symbol, define_struct,
//! and add_hypothesis mutations propagate through downstream analysis tools
//! (get_il, get_ssa, get_reduced_il, get_function_cfg, get_blackboard_entry).

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

/// Test that rename_symbol mutations appear in downstream IL output
#[test]
fn blackboard_rename_symbol_propagates_to_il() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";

    // Rename a function
    let rename_response = frontend
        .call_tool("rename_symbol", &json!({"addr": addr, "name": "main_loop"}))
        .expect("rename_symbol");

    assert!(rename_response.is_object());
    assert_eq!(
        rename_response["status"].as_str(),
        Some("renamed"),
        "rename_symbol should report status=renamed"
    );

    // Get IL and verify resolved_name is present
    let il_response = frontend
        .call_tool("get_il", &json!({"addr": addr}))
        .expect("get_il");

    assert!(il_response.is_object());
    let resolved_name = il_response.get("resolved_name").and_then(|v| v.as_str());
    assert_eq!(
        resolved_name, Some("main_loop"),
        "IL should contain resolved_name from blackboard rename"
    );
}

/// Test that rename_symbol mutations appear in SSA output
#[test]
fn blackboard_rename_symbol_propagates_to_ssa() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";

    // Rename function
    frontend
        .call_tool("rename_symbol", &json!({"addr": addr, "name": "ssa_test_func"}))
        .expect("rename_symbol");

    // Get SSA and verify resolved_name
    let ssa_response = frontend
        .call_tool("get_ssa", &json!({"addr": addr}))
        .expect("get_ssa");

    assert!(ssa_response.is_object());
    let resolved_name = ssa_response.get("resolved_name").and_then(|v| v.as_str());
    assert_eq!(
        resolved_name, Some("ssa_test_func"),
        "SSA should contain resolved_name from blackboard"
    );
}

/// Test that rename_symbol mutations appear in reduced IL output
#[test]
fn blackboard_rename_symbol_propagates_to_reduced_il() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";

    frontend
        .call_tool("rename_symbol", &json!({"addr": addr, "name": "reduced_il_func"}))
        .expect("rename_symbol");

    let reduced_il = frontend
        .call_tool("get_reduced_il", &json!({"addr": addr}))
        .expect("get_reduced_il");

    assert!(reduced_il.is_object());
    let resolved_name = reduced_il.get("resolved_name").and_then(|v| v.as_str());
    assert_eq!(
        resolved_name, Some("reduced_il_func"),
        "Reduced IL should contain resolved_name"
    );
}

/// Test that rename_symbol mutations appear in CFG output
#[test]
fn blackboard_rename_symbol_propagates_to_cfg() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";

    frontend
        .call_tool("rename_symbol", &json!({"addr": addr, "name": "cfg_function"}))
        .expect("rename_symbol");

    let cfg = frontend
        .call_tool("get_function_cfg", &json!({"addr": addr}))
        .expect("get_function_cfg");

    assert!(cfg.is_object());
    let resolved_name = cfg.get("resolved_name").and_then(|v| v.as_str());
    assert_eq!(resolved_name, Some("cfg_function"), "CFG should contain resolved_name");

    // CFG edges should be annotated with src_name/dst_name
    if let Some(edges) = cfg.get("edges").and_then(|e| e.as_array()) {
        for edge in edges {
            // Each edge should have src and dst fields at minimum
            assert!(edge.get("src").is_some(), "Edge should have src");
            assert!(edge.get("dst").is_some(), "Edge should have dst");
        }
    }
}

/// Test that define_struct mutations appear in blackboard entry
#[test]
fn blackboard_define_struct_propagates_to_entry() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";
    let struct_def = "struct Context { u32 state; u64 ptr; }";

    let struct_response = frontend
        .call_tool("define_struct", &json!({"addr": addr, "definition": struct_def}))
        .expect("define_struct");

    assert_eq!(
        struct_response["status"].as_str(),
        Some("defined"),
        "define_struct should report status=defined"
    );

    // Get blackboard entry and verify struct_definition
    let entry = frontend
        .call_tool("get_blackboard_entry", &json!({"addr": addr}))
        .expect("get_blackboard_entry");

    assert!(entry.is_object());
    let semantic = entry.get("semantic").and_then(|s| s.as_object());
    assert!(semantic.is_some(), "Blackboard entry should have semantic");

    if let Some(sem) = semantic {
        let struct_definition = sem.get("struct_definition").and_then(|s| s.as_str());
        assert_eq!(
            struct_definition, Some(struct_def),
            "Struct definition should be stored in blackboard"
        );
    }
}

/// Test that add_hypothesis mutations appear in blackboard entry and search
#[test]
fn blackboard_add_hypothesis_appears_in_entry_and_search() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";
    let hypothesis = "This function implements event dispatch logic";

    let hyp_response = frontend
        .call_tool("add_hypothesis", &json!({"addr": addr, "note": hypothesis}))
        .expect("add_hypothesis");

    assert_eq!(
        hyp_response["status"].as_str(),
        Some("recorded"),
        "add_hypothesis should report status=recorded"
    );

    // Get blackboard entry and verify hypothesis
    let entry = frontend
        .call_tool("get_blackboard_entry", &json!({"addr": addr}))
        .expect("get_blackboard_entry");

    let semantic = entry.get("semantic").and_then(|s| s.as_object());
    assert!(semantic.is_some());

    if let Some(sem) = semantic {
        let hypotheses = sem.get("hypotheses").and_then(|h| h.as_array());
        assert!(hypotheses.is_some(), "Should have hypotheses array");
        assert!(
            hypotheses
                .unwrap()
                .iter()
                .any(|h| h.as_str() == Some(hypothesis)),
            "Hypothesis should be in semantic entry"
        );
    }

    // Search for hypothesis
    let search = frontend
        .call_tool("search_analysis_names", &json!({"pattern": "event dispatch"}))
        .expect("search_analysis_names");

    let matches = search.get("matches").and_then(|m| m.as_array());
    assert!(
        matches.is_some() && !matches.unwrap().is_empty(),
        "Search should find hypothesis by text"
    );
}

/// Test comprehensive workflow: multiple mutations on same address
#[test]
fn blackboard_multiple_mutations_on_same_address() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";

    // Apply multiple mutations
    frontend
        .call_tool("rename_symbol", &json!({"addr": addr, "name": "process_events"}))
        .expect("rename_symbol");

    frontend
        .call_tool("define_struct", &json!({"addr": addr, "definition": "struct EventQueue { u32 head; u32 tail; }"}))
        .expect("define_struct");

    frontend
        .call_tool("add_hypothesis", &json!({"addr": addr, "note": "Queue-based event processing"}))
        .expect("add_hypothesis");

    frontend
        .call_tool("add_hypothesis", &json!({"addr": addr, "note": "Called from main loop"}))
        .expect("add_hypothesis");

    // Verify all mutations in blackboard entry
    let entry = frontend
        .call_tool("get_blackboard_entry", &json!({"addr": addr}))
        .expect("get_blackboard_entry");

    assert_eq!(
        entry.get("resolved_name").and_then(|v| v.as_str()),
        Some("process_events"),
        "Should have symbol"
    );

    if let Some(sem) = entry.get("semantic").and_then(|s| s.as_object()) {
        assert!(
            sem.get("struct_definition")
                .and_then(|s| s.as_str())
                .is_some(),
            "Should have struct definition"
        );

        let hyps = sem.get("hypotheses").and_then(|h| h.as_array());
        assert_eq!(
            hyps.map(|h| h.len()),
            Some(2),
            "Should have 2 hypotheses (no duplicates)"
        );
    }

    // Verify propagation to IL
    let il = frontend
        .call_tool("get_il", &json!({"addr": addr}))
        .expect("get_il");

    assert_eq!(
        il.get("resolved_name").and_then(|v| v.as_str()),
        Some("process_events"),
        "IL should have resolved name"
    );

    assert!(il.get("semantic").is_some(), "IL should have semantic");
}

/// Test that duplicate hypotheses are rejected
#[test]
fn blackboard_duplicate_hypothesis_rejected() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";
    let hypothesis = "Duplicate test hypothesis";

    // Add same hypothesis twice
    let resp1 = frontend
        .call_tool("add_hypothesis", &json!({"addr": addr, "note": hypothesis}))
        .expect("add_hypothesis");

    let resp2 = frontend
        .call_tool("add_hypothesis", &json!({"addr": addr, "note": hypothesis}))
        .expect("add_hypothesis");

    // Both should succeed (add_hypothesis doesn't fail on duplicates)
    assert_eq!(resp1["status"].as_str(), Some("recorded"));
    assert_eq!(resp2["status"].as_str(), Some("recorded"));

    // But blackboard entry should only have one
    let entry = frontend
        .call_tool("get_blackboard_entry", &json!({"addr": addr}))
        .expect("get_blackboard_entry");

    if let Some(sem) = entry.get("semantic").and_then(|s| s.as_object()) {
        if let Some(hyps) = sem.get("hypotheses").and_then(|h| h.as_array()) {
            let matching_hyps: Vec<_> = hyps
                .iter()
                .filter(|h| h.as_str() == Some(hypothesis))
                .collect();
            assert_eq!(
                matching_hyps.len(),
                1,
                "Duplicate hypothesis should not be stored"
            );
        }
    }
}

/// Test search_analysis_names with symbol, struct, and hypothesis patterns
#[test]
fn blackboard_search_across_all_mutation_types() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr1 = "0x7d8";
    let addr2 = "0x800";

    // Create diverse mutations
    frontend
        .call_tool("rename_symbol", &json!({"addr": addr1, "name": "crypto_hasher"}))
        .expect("rename");

    frontend
        .call_tool("define_struct", &json!({"addr": addr2, "definition": "struct CryptoState { u64 nonce; }"}))
        .expect("define_struct");

    // Search by symbol name
    let search1 = frontend
        .call_tool("search_analysis_names", &json!({"pattern": "crypto_hasher"}))
        .expect("search");

    let empty_vec = vec![];
    let matches1 = search1.get("matches").and_then(|m| m.as_array()).unwrap_or(&empty_vec);
    assert!(
        matches1.len() > 0,
        "Should find symbol by name pattern"
    );

    // Search by struct pattern
    let search2 = frontend
        .call_tool("search_analysis_names", &json!({"pattern": "CryptoState"}))
        .expect("search");

    let matches2 = search2.get("matches").and_then(|m| m.as_array()).unwrap_or(&empty_vec);
    assert!(
        matches2.len() > 0,
        "Should find struct by definition pattern"
    );

    // Search by regex pattern
    let search3 = frontend
        .call_tool("search_analysis_names", &json!({"pattern": "^crypto.*"}))
        .expect("search");

    let matches3 = search3.get("matches").and_then(|m| m.as_array()).unwrap_or(&empty_vec);
    assert!(
        matches3.len() > 0,
        "Should find symbol by regex pattern"
    );
}

/// Test semantic context propagation across multiple tool calls
#[test]
fn blackboard_semantic_context_persists_across_tools() {
    let mut frontend = AeonFrontend::new();
    load_sample_binary(&mut frontend);

    let addr = "0x7d8";

    // Add semantic info
    frontend
        .call_tool("rename_symbol", &json!({"addr": addr, "name": "persistent_func"}))
        .expect("rename");

    // Call multiple tools and verify same resolved_name appears
    let il = frontend
        .call_tool("get_il", &json!({"addr": addr}))
        .expect("get_il");

    let ssa = frontend
        .call_tool("get_ssa", &json!({"addr": addr}))
        .expect("get_ssa");

    let reduced_il = frontend
        .call_tool("get_reduced_il", &json!({"addr": addr}))
        .expect("get_reduced_il");

    let cfg = frontend
        .call_tool("get_function_cfg", &json!({"addr": addr}))
        .expect("get_cfg");

    let entry = frontend
        .call_tool("get_blackboard_entry", &json!({"addr": addr}))
        .expect("get_entry");

    // All should have consistent resolved_name
    let expected = "persistent_func";
    assert_eq!(il.get("resolved_name").and_then(|v| v.as_str()), Some(expected));
    assert_eq!(ssa.get("resolved_name").and_then(|v| v.as_str()), Some(expected));
    assert_eq!(
        reduced_il.get("resolved_name").and_then(|v| v.as_str()),
        Some(expected)
    );
    assert_eq!(cfg.get("resolved_name").and_then(|v| v.as_str()), Some(expected));
    assert_eq!(
        entry.get("resolved_name").and_then(|v| v.as_str()),
        Some(expected)
    );
}
