use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::service::{tools_list, AeonFrontend};

pub fn run() {
    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8787".to_string());

    let server = Server::http(&bind_addr)
        .unwrap_or_else(|err| panic!("failed to bind {}: {}", bind_addr, err));

    eprintln!("aeon-http listening on http://{}", bind_addr);

    let mut frontend = AeonFrontend::new();
    for request in server.incoming_requests() {
        handle_request(request, &mut frontend);
    }
}

fn handle_request(mut request: Request, frontend: &mut AeonFrontend) {
    let method = request.method().clone();
    let url = request.url().to_string();

    let (status, body) = match (method.clone(), url.as_str()) {
        (Method::Get, "/health") => (
            200,
            json!({
                "ok": true,
                "state": frontend.status(),
            }),
        ),
        (Method::Get, "/tools") => (200, tools_list()),
        (Method::Post, "/call") => match read_json_body(&mut request) {
            Ok(body) => handle_call(body, frontend),
            Err(error) => (400, json!({ "ok": false, "error": error })),
        },
        _ => (
            404,
            json!({
                "ok": false,
                "error": "Not found",
                "method": format!("{:?}", method),
                "path": url,
            }),
        ),
    };

    respond_json(request, status, body);
}

fn handle_call(body: Value, frontend: &mut AeonFrontend) -> (u16, Value) {
    let name = body
        .get("name")
        .or_else(|| body.get("tool"))
        .and_then(|value| value.as_str());
    let Some(name) = name else {
        return (
            400,
            json!({
                "ok": false,
                "error": "Missing required field: name",
                "state": frontend.status(),
            }),
        );
    };

    let args = body
        .get("arguments")
        .or_else(|| body.get("args"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    match frontend.call_tool(name, &args) {
        Ok(result) => (
            200,
            json!({
                "ok": true,
                "result": result,
                "state": frontend.status(),
            }),
        ),
        Err(error) => (
            400,
            json!({
                "ok": false,
                "error": error,
                "state": frontend.status(),
            }),
        ),
    }
}

fn read_json_body(request: &mut Request) -> Result<Value, String> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|err| format!("Failed to read request body: {}", err))?;

    serde_json::from_str(&body).map_err(|err| format!("Invalid JSON body: {}", err))
}

fn respond_json(request: Request, status: u16, body: Value) {
    let response_body = serde_json::to_string_pretty(&body).unwrap();
    let response = Response::from_string(response_body)
        .with_status_code(StatusCode(status))
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());

    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::handle_call;
    use crate::service::AeonFrontend;

    fn sample_binary_path() -> String {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .join("../../samples/hello_aarch64.elf")
            .display()
            .to_string()
    }

    #[test]
    fn http_call_smoke_for_stack_frame_tool() {
        let mut frontend = AeonFrontend::new();

        let (status, load) = handle_call(
            json!({
                "name": "load_binary",
                "arguments": { "path": sample_binary_path() }
            }),
            &mut frontend,
        );
        assert_eq!(status, 200);
        assert_eq!(load["ok"], true);

        let (status, response) = handle_call(
            json!({
                "name": "get_stack_frame",
                "arguments": { "addr": "0x718" }
            }),
            &mut frontend,
        );
        assert_eq!(status, 200);
        assert_eq!(response["ok"], true);
        assert_eq!(response["result"]["artifact"], "stack_frame");
    }

    #[test]
    fn http_call_supports_raw_binary_loading_for_disassembly() {
        let mut frontend = AeonFrontend::new();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let raw_path = std::env::temp_dir().join(format!("aeon_raw_{unique}.bin"));
        let raw = [
            0x20u8, 0x00, 0x80, 0x52, // mov w0, #1
            0xc0, 0x03, 0x5f, 0xd6,   // ret
        ];
        fs::write(&raw_path, raw).expect("write raw sample");

        let (status, load) = handle_call(
            json!({
                "name": "load_binary",
                "arguments": {
                    "path": raw_path.display().to_string(),
                    "format": "raw",
                    "base_addr": "0x1000"
                }
            }),
            &mut frontend,
        );
        assert_eq!(status, 200);
        assert_eq!(load["ok"], true);
        assert_eq!(load["result"]["total_functions"], 1);
        assert_eq!(load["result"]["text_section_addr"], "0x1000");

        let (status, asm) = handle_call(
            json!({
                "name": "get_asm",
                "arguments": {
                    "start_addr": "0x1000",
                    "stop_addr": "0x1008"
                }
            }),
            &mut frontend,
        );
        assert_eq!(status, 200);
        assert_eq!(asm["ok"], true);
        assert_eq!(asm["result"]["instruction_count"], 2);
        assert_eq!(asm["result"]["listing"][0]["asm"], "mov w0, #0x1");
        assert_eq!(asm["result"]["listing"][1]["asm"], "ret");

        let (status, func) = handle_call(
            json!({
                "name": "get_function_at",
                "arguments": { "addr": "0x1004" }
            }),
            &mut frontend,
        );
        assert_eq!(status, 200);
        assert_eq!(func["ok"], true);
        assert_eq!(func["result"]["name"], "raw_text");

        let _ = fs::remove_file(raw_path);
    }
}
