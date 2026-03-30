//! MCP (Model Context Protocol) server — JSON-RPC 2.0 over stdio.
//!
//! Exposes Aeon's reverse engineering capabilities as discrete, single-action
//! tools with strict JSON input/output for agent consumption.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::service::{tools_list, AeonFrontend};

pub fn run() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut frontend = AeonFrontend::new();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => break,
        };
        if line.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(err) => {
                write_error(
                    &mut stdout,
                    Value::Null,
                    -32700,
                    &format!("Parse error: {}", err),
                );
                continue;
            }
        };

        let id = request.get("id").cloned().unwrap_or(Value::Null);
        if id.is_null() {
            continue;
        }

        let method = request
            .get("method")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

        match dispatch(method, &params, &mut frontend) {
            Ok(result) => write_result(&mut stdout, &id, result),
            Err((code, message)) => write_error(&mut stdout, id, code, &message),
        }
    }
}

fn dispatch(
    method: &str,
    params: &Value,
    frontend: &mut AeonFrontend,
) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => Ok(handle_initialize()),
        "tools/list" => Ok(tools_list()),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            let result = match frontend.call_tool(name, &args) {
                Ok(value) => json!({
                    "content": [{"type": "text", "text": serde_json::to_string(&value).unwrap()}],
                    "isError": false
                }),
                Err(message) => json!({
                    "content": [{"type": "text", "text": message}],
                    "isError": true
                }),
            };

            Ok(result)
        }
        _ => Err((-32601, format!("Method not found: {}", method))),
    }
}

fn handle_initialize() -> Value {
    json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "aeon",
            "version": "0.1.0"
        }
    })
}

fn write_result(out: &mut impl Write, id: &Value, result: Value) {
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    });
    let _ = writeln!(out, "{}", serde_json::to_string(&response).unwrap());
    let _ = out.flush();
}

fn write_error(out: &mut impl Write, id: Value, code: i64, message: &str) {
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    });
    let _ = writeln!(out, "{}", serde_json::to_string(&response).unwrap());
    let _ = out.flush();
}
