use serde::{Deserialize, Serialize};
use serde_json::json;
use aeon_frontend::service::AeonFrontend;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum BlackboardWrite {
    #[serde(rename = "add_hypothesis")]
    AddHypothesis {
        addr: u64,
        note: String,
        agent_id: String,
    },
    #[serde(rename = "rename_symbol")]
    RenameSymbol {
        addr: u64,
        name: String,
        agent_id: String,
    },
    #[serde(rename = "define_struct")]
    DefineStruct {
        addr: u64,
        definition: String,
        agent_id: String,
    },
    #[serde(rename = "set_analysis_name")]
    SetAnalysisName {
        addr: u64,
        name: String,
        agent_id: String,
    },
}

impl BlackboardWrite {
    pub fn addr(&self) -> u64 {
        match self {
            BlackboardWrite::AddHypothesis { addr, .. } => *addr,
            BlackboardWrite::RenameSymbol { addr, .. } => *addr,
            BlackboardWrite::DefineStruct { addr, .. } => *addr,
            BlackboardWrite::SetAnalysisName { addr, .. } => *addr,
        }
    }

    pub fn agent_id(&self) -> &str {
        match self {
            BlackboardWrite::AddHypothesis { agent_id, .. } => agent_id,
            BlackboardWrite::RenameSymbol { agent_id, .. } => agent_id,
            BlackboardWrite::DefineStruct { agent_id, .. } => agent_id,
            BlackboardWrite::SetAnalysisName { agent_id, .. } => agent_id,
        }
    }
}

pub fn merge_writes(writes: &[BlackboardWrite], fe: &mut AeonFrontend) {
    for write in writes {
        let _ = match write {
            BlackboardWrite::AddHypothesis { addr, note, .. } => {
                fe.call_tool(
                    "add_hypothesis",
                    &json!({ "addr": format!("0x{:x}", addr), "note": note }),
                )
            }
            BlackboardWrite::RenameSymbol { addr, name, .. } => {
                fe.call_tool(
                    "rename_symbol",
                    &json!({ "addr": format!("0x{:x}", addr), "name": name }),
                )
            }
            BlackboardWrite::DefineStruct { addr, definition, .. } => {
                fe.call_tool(
                    "define_struct",
                    &json!({ "addr": format!("0x{:x}", addr), "definition": definition }),
                )
            }
            BlackboardWrite::SetAnalysisName { addr, name, .. } => {
                fe.call_tool(
                    "set_analysis_name",
                    &json!({ "addr": format!("0x{:x}", addr), "name": name }),
                )
            }
        };
    }
}

pub fn filter_writes_by_addr(writes: &[BlackboardWrite], addr: u64) -> Vec<BlackboardWrite> {
    writes.iter().filter(|w| w.addr() == addr).cloned().collect()
}
