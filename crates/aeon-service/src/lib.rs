//! The stateful tool service: one loaded binary, a typed request per tool,
//! and JSON in and out.
//!
//! This crate knows nothing about transports. The CLI, MCP and HTTP
//! frontends in `aeon-frontend` and the orchestrator in `aeon-swarm` all
//! sit on top of it.

#![recursion_limit = "512"]

pub mod requests;
pub mod service;

pub use service::{tools_list, AeonFrontend};
