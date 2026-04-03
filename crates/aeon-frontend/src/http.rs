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
    use std::path::PathBuf;

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
}
