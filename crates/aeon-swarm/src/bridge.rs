use std::sync::{Arc, Mutex};
use serde_json::Value;
use aeon_frontend::service::AeonFrontend;

pub trait ToolBridge: Send + Sync {
    fn execute(&self, name: &str, args: &Value) -> Result<Value, String>;
}

pub struct DirectBridge(Arc<Mutex<AeonFrontend>>);

impl DirectBridge {
    pub fn new(fe: AeonFrontend) -> Self {
        Self(Arc::new(Mutex::new(fe)))
    }

    pub fn from_arc(arc: Arc<Mutex<AeonFrontend>>) -> Self {
        Self(arc)
    }
}

impl ToolBridge for DirectBridge {
    fn execute(&self, name: &str, args: &Value) -> Result<Value, String> {
        let mut guard = self
            .0
            .lock()
            .map_err(|e| format!("mutex poisoned: {}", e))?;
        guard.call_tool(name, args)
    }
}

impl Clone for DirectBridge {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

unsafe impl Send for DirectBridge {}
unsafe impl Sync for DirectBridge {}

pub struct HttpBridge {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpBridge {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::blocking::Client::new(),
        }
    }
}

impl ToolBridge for HttpBridge {
    fn execute(&self, name: &str, args: &Value) -> Result<Value, String> {
        let url = format!("{}/call", self.base_url);
        let payload = serde_json::json!({ "name": name, "arguments": args });

        let resp = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .map_err(|e| format!("HTTP error: {}", e))?;

        let body: Value = resp
            .json()
            .map_err(|e| format!("JSON decode error: {}", e))?;

        if body.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            Ok(body["result"].clone())
        } else {
            Err(body
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_string())
        }
    }
}
