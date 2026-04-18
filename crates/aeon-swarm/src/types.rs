use serde::{Deserialize, Serialize};
use crate::blackboard::BlackboardWrite;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwarmRole {
    #[serde(rename = "scout")]
    Scout,
    #[serde(rename = "tracer")]
    Tracer,
    #[serde(rename = "reporter")]
    Reporter,
}

impl SwarmRole {
    pub fn allowed_tools(&self) -> &'static [&'static str] {
        match self {
            SwarmRole::Scout => &[
                "list_functions",
                "get_function_skeleton",
                "search_rc4",
                "scan_vtables",
                "add_hypothesis",
                "rename_symbol",
                "get_function_at",
            ],
            SwarmRole::Tracer => &[
                "get_il",
                "get_ssa",
                "get_data_flow_slice",
                "execute_datalog",
                "get_xrefs",
                "add_hypothesis",
                "rename_symbol",
                "define_struct",
                "get_function_at",
                "get_asm",
                "get_bytes",
            ],
            SwarmRole::Reporter => &[
                "get_blackboard_entry",
                "search_analysis_names",
                "list_functions",
                "get_function_at",
                "get_function_skeleton",
            ],
        }
    }

    pub fn system_prompt(&self) -> &'static str {
        match self {
            SwarmRole::Scout => crate::roles::SCOUT_SYSTEM_PROMPT,
            SwarmRole::Tracer => crate::roles::TRACER_SYSTEM_PROMPT,
            SwarmRole::Reporter => crate::roles::REPORTER_SYSTEM_PROMPT,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSpec {
    pub id: String,
    pub role: SwarmRole,
    pub model: String,
    pub assigned_addrs: Vec<u64>,
    pub max_tool_calls: usize,
    pub max_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmConfig {
    pub binary_path: String,
    pub api_key: Option<String>,
    pub scout_model: String,
    pub tracer_model: String,
    pub reporter_model: String,
    pub scout_parallelism: usize,
    pub tracer_parallelism: usize,
    pub scout_max_tool_calls: usize,
    pub tracer_max_tool_calls: usize,
    pub reporter_max_tool_calls: usize,
    pub scout_partition_size: usize,
    pub max_tracer_targets_per_scout: usize,
}

impl SwarmConfig {
    pub fn default_with_binary(binary_path: String) -> Self {
        Self {
            binary_path,
            api_key: None,
            scout_model: "claude-opus-4-7".to_string(),
            tracer_model: "claude-opus-4-7".to_string(),
            reporter_model: "claude-opus-4-7".to_string(),
            scout_parallelism: 4,
            tracer_parallelism: 2,
            scout_max_tool_calls: 30,
            tracer_max_tool_calls: 60,
            reporter_max_tool_calls: 20,
            scout_partition_size: 50,
            max_tracer_targets_per_scout: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentOutput {
    pub agent_id: String,
    pub role: SwarmRole,
    pub writes: Vec<BlackboardWrite>,
    pub tracer_targets: Vec<u64>,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub tool_calls_made: usize,
    pub terminated_cleanly: bool,
    pub final_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressFinding {
    pub addr: u64,
    pub symbol: Option<String>,
    pub hypotheses: Vec<String>,
    pub struct_definition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmReport {
    pub run_id: String,
    pub binary_path: String,
    pub all_writes: Vec<BlackboardWrite>,
    pub address_findings: Vec<AddressFinding>,
    pub reporter_summary: Option<String>,
    pub total_prompt_tokens: u64,
    pub total_completion_tokens: u64,
    pub total_tool_calls: usize,
    pub tracer_targets: Vec<u64>,
}
