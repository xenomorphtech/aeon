use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorpusEntry {
    pub id: String,
    pub path: String,
    pub architecture: Architecture,
    pub operating_system: Option<String>,
    pub format: BinaryFormat,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    Aarch64,
    X86_64,
    X86,
    Arm,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    Elf,
    MachO,
    Pe,
    Raw,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskSpec {
    pub id: String,
    pub corpus_entry_id: String,
    pub kind: TaskKind,
    pub prompt: String,
    pub expected_outcome: ExpectedOutcome,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    FindConfigLoader,
    RecoverPacketShape,
    RecoverConstructorObjectLayout,
    ProveReachability,
    ExtractDecryptedStrings,
    IdentifyCustomCryptoLoop,
    ClassifyBehavior,
    ProduceEvidenceBundle,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    ExactJson(Value),
    ContainsStrings(Vec<String>),
    AddressSet(Vec<String>),
    StructuredClaim {
        statement: String,
        required_evidence_kinds: Vec<EvidenceKind>,
    },
    Custom(Value),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationRun {
    pub run_id: String,
    pub task_id: String,
    pub agent: AgentDescriptor,
    pub outcome: RunOutcome,
    pub claims: Vec<Claim>,
    pub evidence: Vec<EvidenceItem>,
    pub metrics: RunMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDescriptor {
    pub name: String,
    pub model: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    Passed,
    Failed,
    Partial,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Claim {
    pub id: String,
    pub statement: String,
    pub confidence: Option<f32>,
    pub evidence_ids: Vec<String>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceItem {
    pub id: String,
    pub kind: EvidenceKind,
    pub label: String,
    pub value: Value,
    pub provenance: Vec<ProvenanceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Address,
    Function,
    String,
    ObjectPointerLayout,
    StructDefinition,
    DataFlowSlice,
    DatalogQuery,
    DatalogResult,
    EmulationTrace,
    BlackboardEntry,
    JsonArtifact,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceRef {
    pub tool: String,
    pub locator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunMetrics {
    pub duration_ms: Option<u64>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub tool_calls: u64,
    pub metadata: Value,
}

impl EvaluationRun {
    pub fn evidence_map(&self) -> std::collections::HashMap<&str, &EvidenceItem> {
        self.evidence
            .iter()
            .map(|item| (item.id.as_str(), item))
            .collect()
    }

    pub fn claims_with_missing_evidence(&self) -> Vec<&Claim> {
        let evidence = self.evidence_map();
        self.claims
            .iter()
            .filter(|claim| {
                claim
                    .evidence_ids
                    .iter()
                    .any(|id| !evidence.contains_key(id.as_str()))
            })
            .collect()
    }
}

pub fn evaluate_constructor_object_layout(
    binary_path: &str,
    addr: u64,
) -> Result<EvaluationRun, Box<dyn std::error::Error>> {
    let session = aeon::AeonSession::load(binary_path)?;
    let layout = session
        .analyze_constructor_object_layout(addr)
        .map_err(std::io::Error::other)?;
    let layout_value = serde_json::to_value(&layout)?;

    let outcome = if layout.final_pointer_fields.is_empty() {
        RunOutcome::Failed
    } else {
        RunOutcome::Passed
    };

    let claim_statement = if layout.final_pointer_fields.is_empty() {
        format!(
            "No object-rooted pointer fields were recovered from constructor 0x{:x}.",
            layout.function_addr
        )
    } else {
        format!(
            "Constructor 0x{:x} lays out {} pointer fields on its object.",
            layout.function_addr,
            layout.final_pointer_fields.len()
        )
    };

    Ok(EvaluationRun {
        run_id: format!("constructor-layout:{}:0x{:x}", binary_path, addr),
        task_id: format!("recover-constructor-object-layout:0x{:x}", addr),
        agent: AgentDescriptor {
            name: "aeon-eval".to_string(),
            model: None,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        },
        outcome,
        claims: vec![Claim {
            id: "claim-constructor-layout".to_string(),
            statement: claim_statement,
            confidence: Some(if layout.final_pointer_fields.is_empty() {
                0.2
            } else {
                0.95
            }),
            evidence_ids: vec!["ev-constructor-layout".to_string()],
            metadata: serde_json::json!({
                "query_addr": format!("0x{:x}", layout.query_addr),
                "function_addr": format!("0x{:x}", layout.function_addr),
                "field_offsets": layout.final_pointer_fields.iter().map(|field| format!("0x{:x}", field.field_offset)).collect::<Vec<_>>(),
            }),
        }],
        evidence: vec![EvidenceItem {
            id: "ev-constructor-layout".to_string(),
            kind: EvidenceKind::ObjectPointerLayout,
            label: format!("constructor_layout@0x{:x}", layout.function_addr),
            value: layout_value,
            provenance: vec![ProvenanceRef {
                tool: "analyze_constructor_object_layout".to_string(),
                locator: format!("{}:0x{:x}", binary_path, addr),
            }],
        }],
        metrics: RunMetrics {
            duration_ms: None,
            prompt_tokens: None,
            completion_tokens: None,
            tool_calls: 1,
            metadata: Value::Null,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn claims_with_missing_evidence_reports_dangling_references() {
        let run = EvaluationRun {
            run_id: "run-1".to_string(),
            task_id: "task-1".to_string(),
            agent: AgentDescriptor {
                name: "aeon-agent".to_string(),
                model: Some("gpt-5.4".to_string()),
                version: Some("2026-03-22".to_string()),
            },
            outcome: RunOutcome::Partial,
            claims: vec![
                Claim {
                    id: "claim-ok".to_string(),
                    statement: "The config loader is reachable.".to_string(),
                    confidence: Some(0.9),
                    evidence_ids: vec!["ev-1".to_string()],
                    metadata: Value::Null,
                },
                Claim {
                    id: "claim-missing".to_string(),
                    statement: "The packet struct has a length-prefixed payload.".to_string(),
                    confidence: Some(0.6),
                    evidence_ids: vec!["ev-missing".to_string()],
                    metadata: json!({"note": "needs validation"}),
                },
            ],
            evidence: vec![EvidenceItem {
                id: "ev-1".to_string(),
                kind: EvidenceKind::Function,
                label: "config_loader".to_string(),
                value: json!({"addr": "0x401000"}),
                provenance: vec![ProvenanceRef {
                    tool: "get_function_skeleton".to_string(),
                    locator: "0x401000".to_string(),
                }],
            }],
            metrics: RunMetrics {
                duration_ms: Some(1200),
                prompt_tokens: Some(100),
                completion_tokens: Some(200),
                tool_calls: 3,
                metadata: Value::Null,
            },
        };

        let missing = run.claims_with_missing_evidence();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].id, "claim-missing");
    }

    #[test]
    fn task_spec_round_trips_through_json() {
        let task = TaskSpec {
            id: "task-config-loader".to_string(),
            corpus_entry_id: "fixture-hello".to_string(),
            kind: TaskKind::FindConfigLoader,
            prompt: "Find the configuration loading routine.".to_string(),
            expected_outcome: ExpectedOutcome::ContainsStrings(vec![
                "config.json".to_string(),
            ]),
            metadata: json!({"difficulty": "smoke"}),
        };

        let encoded = serde_json::to_string(&task).unwrap();
        let decoded: TaskSpec = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, task);
    }

    #[test]
    fn constructor_layout_eval_produces_object_layout_evidence() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let binary_path = manifest_dir.join("../../libUnreal.so");
        if !binary_path.exists() {
            return;
        }

        let run = evaluate_constructor_object_layout(binary_path.to_str().unwrap(), 0x05e66990)
            .expect("constructor layout evaluation should succeed");

        assert_eq!(run.outcome, RunOutcome::Passed);
        assert_eq!(run.evidence.len(), 1);
        assert_eq!(run.evidence[0].kind, EvidenceKind::ObjectPointerLayout);

        let offsets = run.evidence[0]
            .value
            .get("final_pointer_fields")
            .and_then(Value::as_array)
            .expect("layout should include final_pointer_fields")
            .iter()
            .filter_map(|field| field.get("field_offset").and_then(Value::as_u64))
            .collect::<Vec<_>>();

        assert_eq!(offsets, vec![0, 32, 280, 296]);
    }
}
