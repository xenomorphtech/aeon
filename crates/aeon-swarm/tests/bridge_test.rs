use aeon_swarm::bridge::{DirectBridge, ToolBridge};
use aeon_frontend::service::AeonFrontend;
use serde_json::json;

#[test]
fn direct_bridge_routes_add_hypothesis_to_frontend() {
    let binary = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../samples/hello_aarch64.elf"
    );
    let mut fe = AeonFrontend::new();
    fe.call_tool("load_binary", &json!({ "path": binary }))
        .unwrap();
    let bridge = DirectBridge::new(fe);

    let result = bridge.execute(
        "add_hypothesis",
        &json!({ "addr": "0x650", "note": "test note" }),
    );
    assert!(result.is_ok(), "add_hypothesis should succeed: {:?}", result);
    let val = result.unwrap();
    assert_eq!(val["status"], "recorded");
}

#[test]
fn direct_bridge_rejects_unknown_tool() {
    let binary = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../samples/hello_aarch64.elf"
    );
    let mut fe = AeonFrontend::new();
    fe.call_tool("load_binary", &json!({ "path": binary }))
        .unwrap();
    let bridge = DirectBridge::new(fe);

    let result = bridge.execute("nonexistent_tool", &json!({}));
    assert!(result.is_err());
}

#[test]
fn direct_bridge_clone_shares_state() {
    let binary = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../samples/hello_aarch64.elf"
    );
    let mut fe = AeonFrontend::new();
    fe.call_tool("load_binary", &json!({ "path": binary }))
        .unwrap();
    let bridge1 = DirectBridge::new(fe);
    let bridge2 = bridge1.clone();

    // Both bridges should share the same mutex and frontend.
    let r1 = bridge1.execute("list_functions", &json!({ "offset": 0, "limit": 5 }));
    assert!(r1.is_ok());

    let r2 = bridge2.execute("list_functions", &json!({ "offset": 0, "limit": 5 }));
    assert!(r2.is_ok());
}
