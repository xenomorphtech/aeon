//! Transports for the tool service in `aeon-service`: MCP over stdio and a
//! stateful HTTP API. The `aeon` CLI is this crate's main binary.

pub mod http;
pub mod mcp;
