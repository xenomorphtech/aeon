use serde_json::{json, Value};

use crate::blackboard::BlackboardWrite;
use crate::bridge::ToolBridge;
use crate::claude::{ClaudeClient, ClaudeContentBlock, ClaudeMessage, ClaudeRequest, ClaudeToolDef};
use crate::roles::tool_defs_for_role;
use crate::types::{AgentOutput, AgentSpec, SwarmRole};

pub struct AgentRunner<C: ClaudeClient, B: ToolBridge> {
    spec: AgentSpec,
    claude: C,
    bridge: B,
}

impl<C: ClaudeClient, B: ToolBridge> AgentRunner<C, B> {
    pub fn new(spec: AgentSpec, claude: C, bridge: B) -> Self {
        Self { spec, claude, bridge }
    }

    pub fn run(self) -> AgentOutput {
        let AgentRunner { spec, claude, bridge } = self;

        let tools: Vec<ClaudeToolDef> = tool_defs_for_role(&spec.role);
        let system = spec.role.system_prompt().to_string();

        let initial_user_msg = build_initial_user_message(&spec);

        let mut messages: Vec<ClaudeMessage> = vec![ClaudeMessage {
            role: "user".to_string(),
            content: vec![ClaudeContentBlock::text(initial_user_msg)],
        }];

        let mut writes: Vec<BlackboardWrite> = Vec::new();
        let mut tracer_targets: Vec<u64> = Vec::new();
        let mut prompt_tokens: u64 = 0;
        let mut completion_tokens: u64 = 0;
        let mut tool_calls_made: usize = 0;
        let mut terminated_cleanly = false;
        let mut final_text: Option<String> = None;

        'outer: loop {
            let request = ClaudeRequest {
                model: spec.model.clone(),
                system: system.clone(),
                messages: messages.clone(),
                tools: tools.clone(),
                max_tokens: spec.max_tokens,
            };

            let response = match claude.call(request) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[{}] Claude error: {}", spec.id, e);
                    break;
                }
            };

            prompt_tokens += response.usage.input_tokens;
            completion_tokens += response.usage.output_tokens;

            messages.push(ClaudeMessage {
                role: "assistant".to_string(),
                content: response.content.clone(),
            });

            if response.stop_reason == "end_turn" || response.stop_reason == "max_tokens" {
                terminated_cleanly = response.stop_reason == "end_turn";
                for block in &response.content {
                    if let ClaudeContentBlock::Text { text } = block {
                        final_text = Some(text.clone());
                    }
                }
                break;
            }

            let mut tool_results: Vec<ClaudeContentBlock> = Vec::new();

            for block in &response.content {
                let ClaudeContentBlock::ToolUse { id, name, input } = block else {
                    continue;
                };

                if tool_calls_made >= spec.max_tool_calls {
                    tool_results.push(ClaudeContentBlock::tool_result(
                        id.clone(),
                        json!({ "error": "Tool call limit reached. Wrap up your analysis." }),
                    ));
                    terminated_cleanly = false;
                    break 'outer;
                }

                if !spec.role.allowed_tools().contains(&name.as_str()) {
                    tool_results.push(ClaudeContentBlock::tool_result(
                        id.clone(),
                        json!({ "error": format!("Tool '{}' is not available for this role.", name) }),
                    ));
                    tool_calls_made += 1;
                    continue;
                }

                let result = bridge.execute(name, input);

                if let Ok(ref _v) = result {
                    if let Some(write) = try_capture_as_write(&spec.id, name, input) {
                        if let BlackboardWrite::AddHypothesis { addr, note, .. } = &write {
                            if note.contains("TRACER_TARGET") {
                                tracer_targets.push(*addr);
                            }
                        }
                        writes.push(write);
                    }
                }

                let result_val = match result {
                    Ok(v) => v,
                    Err(e) => json!({ "error": e }),
                };

                tool_results.push(ClaudeContentBlock::tool_result(id.clone(), result_val));
                tool_calls_made += 1;
            }

            if !tool_results.is_empty() {
                messages.push(ClaudeMessage {
                    role: "user".to_string(),
                    content: tool_results,
                });
            }
        }

        AgentOutput {
            agent_id: spec.id,
            role: spec.role,
            writes,
            tracer_targets,
            prompt_tokens,
            completion_tokens,
            tool_calls_made,
            terminated_cleanly,
            final_text,
        }
    }
}

fn build_initial_user_message(spec: &AgentSpec) -> String {
    let addrs: Vec<String> = spec
        .assigned_addrs
        .iter()
        .map(|a| format!("0x{:x}", a))
        .collect();

    match spec.role {
        SwarmRole::Scout => format!(
            "You are analyzing an ARM64 binary. Your assigned function addresses for initial triage are: [{}]. \
             Use list_functions and get_function_skeleton to quickly identify interesting patterns. \
             For any function that looks interesting (crypto, deobfuscation, suspicious loops), \
             call add_hypothesis with a note that includes the text TRACER_TARGET to flag it for deep analysis. \
             Complete your analysis efficiently.",
            addrs.join(", ")
        ),
        SwarmRole::Tracer => format!(
            "You are performing deep analysis on ARM64 binary functions. \
             Your assigned targets for deep analysis are: [{}]. \
             For each target, use get_il, get_ssa, get_data_flow_slice, execute_datalog, and get_xrefs \
             to fully characterize the function's behavior. Record your findings with add_hypothesis. \
             Be thorough and systematic.",
            addrs.join(", ")
        ),
        SwarmRole::Reporter => {
            "You are the final-stage reporter. Use get_blackboard_entry, search_analysis_names, \
             list_functions, and get_function_at to survey everything recorded by the Scout and Tracer agents. \
             Produce a structured summary: crypto routines found, suspicious patterns, renamed symbols, \
             and your overall assessment of the binary's purpose.".to_string()
        }
    }
}

fn try_capture_as_write(
    agent_id: &str,
    tool_name: &str,
    input: &Value,
) -> Option<BlackboardWrite> {
    let parse_addr = |v: &Value| -> Option<u64> {
        v.get("addr")
            .and_then(Value::as_str)
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    };

    match tool_name {
        "add_hypothesis" => Some(BlackboardWrite::AddHypothesis {
            addr: parse_addr(input)?,
            note: input.get("note")?.as_str()?.to_string(),
            agent_id: agent_id.to_string(),
        }),
        "rename_symbol" => Some(BlackboardWrite::RenameSymbol {
            addr: parse_addr(input)?,
            name: input.get("name")?.as_str()?.to_string(),
            agent_id: agent_id.to_string(),
        }),
        "define_struct" => Some(BlackboardWrite::DefineStruct {
            addr: parse_addr(input)?,
            definition: input.get("definition")?.as_str()?.to_string(),
            agent_id: agent_id.to_string(),
        }),
        "set_analysis_name" => Some(BlackboardWrite::SetAnalysisName {
            addr: parse_addr(input)?,
            name: input.get("name")?.as_str()?.to_string(),
            agent_id: agent_id.to_string(),
        }),
        _ => None,
    }
}
