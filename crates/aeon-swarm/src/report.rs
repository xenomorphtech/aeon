use std::collections::HashMap;

use crate::blackboard::BlackboardWrite;
use crate::types::{AddressFinding, AgentOutput, SwarmReport};

pub fn build_report(
    run_id: String,
    binary_path: String,
    all_writes: Vec<BlackboardWrite>,
    tracer_targets: Vec<u64>,
    all_outputs: Vec<AgentOutput>,
) -> SwarmReport {
    // Aggregate findings per address.
    let mut by_addr: HashMap<u64, AddressFinding> = HashMap::new();

    for write in &all_writes {
        let entry = by_addr.entry(write.addr()).or_insert_with(|| AddressFinding {
            addr: write.addr(),
            symbol: None,
            hypotheses: Vec::new(),
            struct_definition: None,
        });

        match write {
            BlackboardWrite::AddHypothesis { note, .. } => {
                if !entry.hypotheses.iter().any(|h| h == note) {
                    entry.hypotheses.push(note.clone());
                }
            }
            BlackboardWrite::RenameSymbol { name, .. }
            | BlackboardWrite::SetAnalysisName { name, .. } => {
                entry.symbol = Some(name.clone());
            }
            BlackboardWrite::DefineStruct { definition, .. } => {
                entry.struct_definition = Some(definition.clone());
            }
        }
    }

    let mut address_findings: Vec<AddressFinding> = by_addr.into_values().collect();
    address_findings.sort_by_key(|f| f.addr);

    let reporter_summary = all_outputs
        .iter()
        .find(|o| matches!(o.role, crate::types::SwarmRole::Reporter))
        .and_then(|o| o.final_text.clone());

    let total_prompt_tokens: u64 = all_outputs.iter().map(|o| o.prompt_tokens).sum();
    let total_completion_tokens: u64 = all_outputs.iter().map(|o| o.completion_tokens).sum();
    let total_tool_calls: usize = all_outputs.iter().map(|o| o.tool_calls_made).sum();

    SwarmReport {
        run_id,
        binary_path,
        all_writes,
        address_findings,
        reporter_summary,
        total_prompt_tokens,
        total_completion_tokens,
        total_tool_calls,
        tracer_targets,
    }
}
