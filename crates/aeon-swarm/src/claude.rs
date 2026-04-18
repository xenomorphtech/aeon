use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeMessage {
    pub role: String,
    pub content: Vec<ClaudeContentBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClaudeContentBlock {
    Text { text: String },
    ToolUse { id: String, name: String, input: Value },
    ToolResult { tool_use_id: String, content: Value },
}

impl ClaudeContentBlock {
    pub fn text(s: impl Into<String>) -> Self {
        ClaudeContentBlock::Text { text: s.into() }
    }

    pub fn tool_result(id: impl Into<String>, content: Value) -> Self {
        ClaudeContentBlock::ToolResult {
            tool_use_id: id.into(),
            content,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaudeRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<ClaudeMessage>,
    pub tools: Vec<ClaudeToolDef>,
    pub max_tokens: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClaudeResponse {
    pub id: String,
    pub content: Vec<ClaudeContentBlock>,
    pub stop_reason: String,
    pub usage: ClaudeUsage,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClaudeUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

pub trait ClaudeClient: Send + Sync {
    fn call(&self, request: ClaudeRequest) -> Result<ClaudeResponse, String>;
}

pub struct RealClaudeClient {
    api_key: String,
    http: reqwest::blocking::Client,
}

impl RealClaudeClient {
    const MESSAGES_URL: &'static str = "https://api.anthropic.com/v1/messages";
    const ANTHROPIC_VERSION: &'static str = "2023-06-01";

    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("failed to build reqwest client"),
        }
    }
}

impl ClaudeClient for RealClaudeClient {
    fn call(&self, request: ClaudeRequest) -> Result<ClaudeResponse, String> {
        let body = json!({
            "model": request.model,
            "system": request.system,
            "messages": request.messages,
            "tools": request.tools.iter().map(|t| json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            })).collect::<Vec<_>>(),
            "max_tokens": request.max_tokens,
        });

        let resp = self
            .http
            .post(Self::MESSAGES_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", Self::ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| format!("HTTP send error: {}", e))?;

        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| format!("failed to read response: {}", e))?;

        if !status.is_success() {
            return Err(format!("Claude API error {}: {}", status, text));
        }

        serde_json::from_str(&text)
            .map_err(|e| format!("JSON decode error: {}: {}", e, &text[..text.len().min(200)]))
    }
}

pub struct MockClaudeClient {
    responses: Mutex<VecDeque<ClaudeResponse>>,
}

impl MockClaudeClient {
    pub fn new(responses: Vec<ClaudeResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
        }
    }

    pub fn tool_use_response(
        id: impl Into<String>,
        tool_name: impl Into<String>,
        input: Value,
    ) -> ClaudeResponse {
        ClaudeResponse {
            id: id.into(),
            content: vec![ClaudeContentBlock::ToolUse {
                id: "tu_001".to_string(),
                name: tool_name.into(),
                input,
            }],
            stop_reason: "tool_use".to_string(),
            usage: ClaudeUsage {
                input_tokens: 50,
                output_tokens: 20,
            },
        }
    }

    pub fn end_turn_response(text: impl Into<String>) -> ClaudeResponse {
        ClaudeResponse {
            id: "resp_end".to_string(),
            content: vec![ClaudeContentBlock::Text {
                text: text.into(),
            }],
            stop_reason: "end_turn".to_string(),
            usage: ClaudeUsage {
                input_tokens: 100,
                output_tokens: 40,
            },
        }
    }
}

impl ClaudeClient for MockClaudeClient {
    fn call(&self, _request: ClaudeRequest) -> Result<ClaudeResponse, String> {
        let mut queue = self.responses.lock().unwrap();
        queue
            .pop_front()
            .ok_or_else(|| "MockClaudeClient: scripted response queue exhausted".to_string())
    }
}
