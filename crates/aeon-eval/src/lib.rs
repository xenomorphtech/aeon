use aeon::il::{BranchCond, Condition, Expr, Reg, Stmt};
use aeon::AeonSession;
use aeon_reduce::pipeline::{reduce_function_cfg_with_metrics, ReductionMetrics};
use aeon_reduce::ssa::cfg::{build_cfg, Cfg};
use aeon_reduce::ssa::construct::build_ssa;
use aeon_reduce::ssa::pipeline::optimize_ssa;
use aeon_reduce::ssa::validate::{validate_ssa, SsaValidationReport};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusManifest {
    pub id: String,
    pub description: Option<String>,
    pub binaries: Vec<CorpusEntry>,
    pub tasks: Vec<TaskSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskScore {
    pub task_id: String,
    pub run_id: String,
    pub passed: bool,
    pub score: f64,
    pub outcome_kind: String,
    pub details: Value,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub manifest_id: String,
    pub total_tasks: usize,
    pub passed: usize,
    pub failed: usize,
    pub pass_rate: f64,
    pub total_duration_ms: u64,
    pub scores: Vec<TaskScore>,
    pub timestamp: String,
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

pub fn load_corpus_manifest(path: &str) -> Result<CorpusManifest, Box<dyn std::error::Error>> {
    let raw = fs::read(path)?;
    Ok(serde_json::from_slice(&raw)?)
}

pub fn verify_expected_outcome(expected: &ExpectedOutcome, run: &EvaluationRun) -> bool {
    match expected {
        ExpectedOutcome::ExactJson(v) => {
            run.evidence.iter().any(|e| &e.value == v)
        }
        ExpectedOutcome::ContainsStrings(strings) => {
            let serialized = serde_json::to_string(&serde_json::to_value(run).unwrap_or_default())
                .unwrap_or_default();
            strings.iter().all(|s| serialized.contains(s.as_str()))
        }
        ExpectedOutcome::AddressSet(addrs) => {
            let serialized = serde_json::to_string(&serde_json::to_value(run).unwrap_or_default())
                .unwrap_or_default();
            addrs.iter().all(|a| serialized.contains(a.as_str()))
        }
        ExpectedOutcome::StructuredClaim { required_evidence_kinds, .. } => {
            let present_kinds: Vec<&EvidenceKind> = run.evidence.iter()
                .map(|e| &e.kind).collect();
            required_evidence_kinds.iter()
                .all(|required| present_kinds.contains(&required))
        }
        ExpectedOutcome::Custom(_) => run.outcome == RunOutcome::Passed,
    }
}

pub fn score_run(run: &EvaluationRun, task: &TaskSpec) -> TaskScore {
    let passed = verify_expected_outcome(&task.expected_outcome, run);
    let outcome_kind = match &task.expected_outcome {
        ExpectedOutcome::ExactJson(_) => "exact_json",
        ExpectedOutcome::ContainsStrings(_) => "contains_strings",
        ExpectedOutcome::AddressSet(_) => "address_set",
        ExpectedOutcome::StructuredClaim { .. } => "structured_claim",
        ExpectedOutcome::Custom(_) => "custom",
    };
    TaskScore {
        task_id: task.id.clone(),
        run_id: run.run_id.clone(),
        passed,
        score: if passed { 1.0 } else { 0.0 },
        outcome_kind: outcome_kind.to_string(),
        details: json!({
            "run_outcome": run.outcome,
            "claims_count": run.claims.len(),
            "evidence_count": run.evidence.len(),
            "missing_evidence": run.claims_with_missing_evidence().len(),
        }),
        duration_ms: run.metrics.duration_ms,
    }
}

pub fn aggregate_benchmark(manifest_id: &str, scores: Vec<TaskScore>) -> BenchmarkReport {
    let passed = scores.iter().filter(|s| s.passed).count();
    let total = scores.len();
    let total_duration_ms = scores.iter().filter_map(|s| s.duration_ms).sum();
    BenchmarkReport {
        manifest_id: manifest_id.to_string(),
        total_tasks: total,
        passed,
        failed: total - passed,
        pass_rate: if total == 0 { 0.0 } else { passed as f64 / total as f64 },
        total_duration_ms,
        scores,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

pub fn evaluate_constructor_object_layout(
    binary_path: &str,
    addr: u64,
) -> Result<EvaluationRun, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
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

    let mut run = EvaluationRun {
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
    };
    run.metrics.duration_ms = Some(start.elapsed().as_millis() as u64);
    Ok(run)
}

struct FunctionArtifacts {
    function_addr: u64,
    binary_sha256: String,
    function_sha256: String,
    raw_cfg: Cfg,
    reduced_cfg: Cfg,
    metrics: ReductionMetrics,
    validation: SsaValidationReport,
}

pub fn evaluate_reduced_il_golden(
    binary_path: &str,
    addr: u64,
    golden_path: &str,
) -> Result<EvaluationRun, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let artifacts = load_function_artifacts(binary_path, addr)?;
    let reduced_value = normalize_cfg_artifact(
        artifacts.function_addr,
        &artifacts.reduced_cfg,
        Some(&artifacts.binary_sha256),
        Some(&artifacts.function_sha256),
    );
    let raw_value = normalize_cfg_artifact(
        artifacts.function_addr,
        &artifacts.raw_cfg,
        Some(&artifacts.binary_sha256),
        Some(&artifacts.function_sha256),
    );
    let expected: Value = serde_json::from_slice(&fs::read(golden_path)?)?;
    let expected = materialize_optional_golden_fields(expected, &reduced_value);
    let matches = reduced_value == expected;
    let outcome = if matches {
        RunOutcome::Passed
    } else {
        RunOutcome::Failed
    };

    let mut evidence = vec![
        EvidenceItem {
            id: "ev-raw-il".to_string(),
            kind: EvidenceKind::JsonArtifact,
            label: format!("raw_il@0x{:x}", artifacts.function_addr),
            value: raw_value,
            provenance: vec![ProvenanceRef {
                tool: "lift_function_instructions".to_string(),
                locator: format!("{}:0x{:x}", binary_path, artifacts.function_addr),
            }],
        },
        EvidenceItem {
            id: "ev-reduced-il".to_string(),
            kind: EvidenceKind::JsonArtifact,
            label: format!("reduced_il@0x{:x}", artifacts.function_addr),
            value: reduced_value.clone(),
            provenance: vec![ProvenanceRef {
                tool: "evaluate_reduced_il_golden".to_string(),
                locator: format!("{}:0x{:x}", binary_path, artifacts.function_addr),
            }],
        },
    ];

    let mut evidence_ids = vec!["ev-reduced-il".to_string(), "ev-raw-il".to_string()];
    if !matches {
        evidence.push(EvidenceItem {
            id: "ev-golden-diff".to_string(),
            kind: EvidenceKind::JsonArtifact,
            label: format!("golden_diff@0x{:x}", artifacts.function_addr),
            value: json!({
                "golden_path": golden_path,
                "actual": reduced_value,
                "expected": expected,
                "differences": diff_json_values(&expected, &reduced_value, "$", 32),
            }),
            provenance: vec![ProvenanceRef {
                tool: "evaluate_reduced_il_golden".to_string(),
                locator: golden_path.to_string(),
            }],
        });
        evidence_ids.push("ev-golden-diff".to_string());
    }

    let mut run = EvaluationRun {
        run_id: format!(
            "reduced-il-golden:{}:0x{:x}",
            binary_path, artifacts.function_addr
        ),
        task_id: format!("reduced-il-golden:0x{:x}", artifacts.function_addr),
        agent: agent_descriptor(),
        outcome,
        claims: vec![Claim {
            id: "claim-reduced-il-golden".to_string(),
            statement: if matches {
                format!(
                    "Reduced IL for function 0x{:x} matches the checked-in golden.",
                    artifacts.function_addr
                )
            } else {
                format!(
                    "Reduced IL for function 0x{:x} diverged from the checked-in golden.",
                    artifacts.function_addr
                )
            },
            confidence: Some(if matches { 0.99 } else { 0.1}),
            evidence_ids,
            metadata: json!({
                "binary_sha256": artifacts.binary_sha256,
                "function_sha256": artifacts.function_sha256,
                "golden_path": golden_path,
            }),
        }],
        evidence,
        metrics: RunMetrics {
            duration_ms: None,
            prompt_tokens: None,
            completion_tokens: None,
            tool_calls: 1,
            metadata: json!({
                "binary_sha256": artifacts.binary_sha256,
                "function_sha256": artifacts.function_sha256,
                "golden_path": golden_path,
            }),
        },
    };
    run.metrics.duration_ms = Some(start.elapsed().as_millis() as u64);
    Ok(run)
}

pub fn evaluate_reduction_metrics(
    binary_path: &str,
    addr: u64,
) -> Result<EvaluationRun, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let artifacts = load_function_artifacts(binary_path, addr)?;
    let metrics_value = reduction_metrics_value(&artifacts.metrics);
    let validation_value = validation_report_value(&artifacts.validation);
    let outcome = if artifacts.validation.is_valid {
        RunOutcome::Passed
    } else {
        RunOutcome::Failed
    };

    let mut run = EvaluationRun {
        run_id: format!(
            "reduction-metrics:{}:0x{:x}",
            binary_path, artifacts.function_addr
        ),
        task_id: format!("reduction-metrics:0x{:x}", artifacts.function_addr),
        agent: agent_descriptor(),
        outcome,
        claims: vec![Claim {
            id: "claim-reduction-metrics".to_string(),
            statement: if artifacts.validation.is_valid {
                format!(
                    "Reduction metrics and SSA validation completed successfully for function 0x{:x}.",
                    artifacts.function_addr
                )
            } else {
                format!(
                    "SSA validation failed for function 0x{:x}.",
                    artifacts.function_addr
                )
            },
            confidence: Some(if artifacts.validation.is_valid {
                0.95
            } else {
                0.05
            }),
            evidence_ids: vec![
                "ev-metric-snapshot".to_string(),
                "ev-ssa-validation".to_string(),
            ],
            metadata: json!({
                "binary_sha256": artifacts.binary_sha256,
                "function_sha256": artifacts.function_sha256,
            }),
        }],
        evidence: vec![
            EvidenceItem {
                id: "ev-metric-snapshot".to_string(),
                kind: EvidenceKind::JsonArtifact,
                label: format!("metric_snapshot@0x{:x}", artifacts.function_addr),
                value: metrics_value.clone(),
                provenance: vec![ProvenanceRef {
                    tool: "evaluate_reduction_metrics".to_string(),
                    locator: format!("{}:0x{:x}", binary_path, artifacts.function_addr),
                }],
            },
            EvidenceItem {
                id: "ev-ssa-validation".to_string(),
                kind: EvidenceKind::JsonArtifact,
                label: format!("ssa_validation@0x{:x}", artifacts.function_addr),
                value: validation_value.clone(),
                provenance: vec![ProvenanceRef {
                    tool: "validate_ssa".to_string(),
                    locator: format!("{}:0x{:x}", binary_path, artifacts.function_addr),
                }],
            },
        ],
        metrics: RunMetrics {
            duration_ms: None,
            prompt_tokens: None,
            completion_tokens: None,
            tool_calls: 1,
            metadata: json!({
                "metric_snapshot": metrics_value,
                "ssa_validation": validation_value,
            }),
        },
    };
    run.metrics.duration_ms = Some(start.elapsed().as_millis() as u64);
    Ok(run)
}

pub fn evaluate_function_skeleton(
    binary_path: &str,
    addr: u64,
) -> Result<EvaluationRun, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let session = AeonSession::load(binary_path)?;
    let skeleton = session
        .get_function_skeleton(addr)
        .map_err(std::io::Error::other)?;
    let skeleton_value = serde_json::to_value(&skeleton)?;

    let mut run = EvaluationRun {
        run_id: format!("function-skeleton:{}:0x{:x}", binary_path, addr),
        task_id: format!("classify-behavior:0x{:x}", addr),
        agent: agent_descriptor(),
        outcome: RunOutcome::Passed,
        claims: vec![Claim {
            id: "claim-function-skeleton".to_string(),
            statement: format!("Function skeleton recovered for 0x{:x}", addr),
            confidence: Some(0.95),
            evidence_ids: vec!["ev-function-skeleton".to_string()],
            metadata: json!({}),
        }],
        evidence: vec![EvidenceItem {
            id: "ev-function-skeleton".to_string(),
            kind: EvidenceKind::JsonArtifact,
            label: format!("function_skeleton@0x{:x}", addr),
            value: skeleton_value,
            provenance: vec![ProvenanceRef {
                tool: "get_function_skeleton".to_string(),
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
    };
    run.metrics.duration_ms = Some(start.elapsed().as_millis() as u64);
    Ok(run)
}

pub fn evaluate_datalog_query(
    binary_path: &str,
    addr: u64,
    query_name: &str,
) -> Result<EvaluationRun, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let session = AeonSession::load(binary_path)?;
    let result = session
        .execute_datalog(query_name, addr, None, None)
        .map_err(std::io::Error::other)?;
    let result_value = serde_json::to_value(&result)?;

    let mut run = EvaluationRun {
        run_id: format!("datalog-query:{}:0x{:x}:{}", binary_path, addr, query_name),
        task_id: format!("datalog-query:0x{:x}:{}", addr, query_name),
        agent: agent_descriptor(),
        outcome: RunOutcome::Passed,
        claims: vec![Claim {
            id: "claim-datalog-query".to_string(),
            statement: format!("Datalog query '{}' executed for 0x{:x}", query_name, addr),
            confidence: Some(0.95),
            evidence_ids: vec!["ev-datalog-result".to_string()],
            metadata: json!({"query": query_name}),
        }],
        evidence: vec![EvidenceItem {
            id: "ev-datalog-result".to_string(),
            kind: EvidenceKind::DatalogResult,
            label: format!("datalog_{}@0x{:x}", query_name, addr),
            value: result_value,
            provenance: vec![ProvenanceRef {
                tool: "execute_datalog".to_string(),
                locator: format!("{}:0x{:x}:{}", binary_path, addr, query_name),
            }],
        }],
        metrics: RunMetrics {
            duration_ms: None,
            prompt_tokens: None,
            completion_tokens: None,
            tool_calls: 1,
            metadata: Value::Null,
        },
    };
    run.metrics.duration_ms = Some(start.elapsed().as_millis() as u64);
    Ok(run)
}

pub fn evaluate_emulation_snippet(
    binary_path: &str,
    start_addr: u64,
    end_addr: u64,
    expected_regs: &HashMap<String, u64>,
) -> Result<EvaluationRun, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let session = AeonSession::load(binary_path)?;
    let result = session
        .emulate_snippet(start_addr, end_addr, HashMap::new(), HashMap::new(), 1000)
        .map_err(std::io::Error::other)?;
    let result_value = serde_json::to_value(&result)?;

    let passed = if let Some(final_regs) = result_value.get("final_registers").and_then(|v| v.as_object()) {
        expected_regs.iter().all(|(reg_name, expected_val)| {
            final_regs.get(reg_name)
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .map(|actual| actual == *expected_val)
                .unwrap_or(false)
        })
    } else {
        false
    };

    let mut run = EvaluationRun {
        run_id: format!("emulation-snippet:{}:0x{:x}-0x{:x}", binary_path, start_addr, end_addr),
        task_id: format!("emulation-snippet:0x{:x}-0x{:x}", start_addr, end_addr),
        agent: agent_descriptor(),
        outcome: if passed { RunOutcome::Passed } else { RunOutcome::Failed },
        claims: vec![Claim {
            id: "claim-emulation".to_string(),
            statement: format!("Emulation snippet 0x{:x}-0x{:x} produces expected registers", start_addr, end_addr),
            confidence: Some(if passed { 0.95 } else { 0.1 }),
            evidence_ids: vec!["ev-emulation-trace".to_string()],
            metadata: json!({"expected_registers": expected_regs}),
        }],
        evidence: vec![EvidenceItem {
            id: "ev-emulation-trace".to_string(),
            kind: EvidenceKind::EmulationTrace,
            label: format!("emulation_0x{:x}_0x{:x}", start_addr, end_addr),
            value: result_value,
            provenance: vec![ProvenanceRef {
                tool: "emulate_snippet_native".to_string(),
                locator: format!("{}:0x{:x}-0x{:x}", binary_path, start_addr, end_addr),
            }],
        }],
        metrics: RunMetrics {
            duration_ms: None,
            prompt_tokens: None,
            completion_tokens: None,
            tool_calls: 1,
            metadata: Value::Null,
        },
    };
    run.metrics.duration_ms = Some(start.elapsed().as_millis() as u64);
    Ok(run)
}

fn parse_hex_from_metadata(metadata: &Value, key: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = metadata[key].as_str()
        .ok_or_else(|| format!("missing '{}' in task metadata", key))?;
    parse_hex_u64(s).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

fn parse_hex_u64(s: &str) -> Result<u64, std::num::ParseIntError> {
    u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
}

fn agent_descriptor() -> AgentDescriptor {
    AgentDescriptor {
        name: "aeon-eval".to_string(),
        model: None,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

fn load_function_artifacts(
    binary_path: &str,
    addr: u64,
) -> Result<FunctionArtifacts, Box<dyn std::error::Error>> {
    let session = AeonSession::load(binary_path)?;
    let func = session
        .binary()
        .function_containing(addr)
        .ok_or_else(|| std::io::Error::other(format!("No function containing 0x{:x}", addr)))?;
    let function_addr = func.addr;
    let function_bytes = session
        .binary()
        .function_bytes(func)
        .ok_or_else(|| std::io::Error::other("Function bytes out of range"))?;
    let instructions = session
        .lift_function_instructions(addr)
        .map_err(std::io::Error::other)?;

    let raw_cfg = build_cfg(&instructions);
    let (reduced_cfg, metrics) = reduce_function_cfg_with_metrics(&instructions);
    let mut optimized_ssa = build_ssa(&reduced_cfg);
    optimize_ssa(&mut optimized_ssa);

    Ok(FunctionArtifacts {
        function_addr,
        binary_sha256: sha256_hex(&fs::read(binary_path)?),
        function_sha256: sha256_hex(function_bytes),
        raw_cfg,
        reduced_cfg,
        metrics,
        validation: validate_ssa(&optimized_ssa),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn reduction_metrics_value(metrics: &ReductionMetrics) -> Value {
    json!({
        "eligible_stack_accesses": metrics.eligible_stack_accesses,
        "stack_slots_recognized": metrics.stack_slots_recognized,
        "adrp_resolutions": metrics.adrp_resolutions,
        "flag_fusions": metrics.flag_fusions,
        "movk_chain_resolutions": metrics.movk_chain_resolutions,
        "ssa_vars_before_optimization": metrics.ssa_vars_before_optimization,
        "ssa_vars_after_optimization": metrics.ssa_vars_after_optimization,
        "intrinsic_instructions": metrics.intrinsic_instructions,
        "proper_il_instructions": metrics.proper_il_instructions,
        "intrinsic_to_proper_il_ratio": metrics.intrinsic_to_proper_il_ratio(),
    })
}

fn validation_report_value(report: &SsaValidationReport) -> Value {
    json!({
        "is_valid": report.is_valid,
        "issue_count": report.issues.len(),
        "issues": report.issues.iter().map(|issue| {
            json!({
                "code": issue.code,
                "block": issue.block.map(|block| hex_addr(block as u64)),
                "stmt_idx": issue.stmt_idx,
                "message": issue.message,
            })
        }).collect::<Vec<_>>(),
    })
}

fn normalize_cfg_artifact(
    function_addr: u64,
    cfg: &Cfg,
    binary_sha256: Option<&str>,
    function_sha256: Option<&str>,
) -> Value {
    let addr_map: HashMap<_, _> = cfg
        .blocks
        .iter()
        .map(|block| (block.id, block.addr))
        .collect();
    let mut blocks = cfg.blocks.iter().collect::<Vec<_>>();
    blocks.sort_by_key(|block| block.addr);

    json!({
        "function": hex_addr(function_addr),
        "binary_sha256": binary_sha256,
        "function_sha256": function_sha256,
        "blocks": blocks.into_iter().map(|block| {
            let mut predecessors = block
                .predecessors
                .iter()
                .filter_map(|pred| addr_map.get(pred).copied())
                .collect::<Vec<_>>();
            predecessors.sort_unstable();

            let mut successors = block
                .successors
                .iter()
                .filter_map(|succ| addr_map.get(succ).copied())
                .collect::<Vec<_>>();
            successors.sort_unstable();

            json!({
                "addr": hex_addr(block.addr),
                "predecessors": predecessors.into_iter().map(hex_addr).collect::<Vec<_>>(),
                "successors": successors.into_iter().map(hex_addr).collect::<Vec<_>>(),
                "stmts": block.stmts.iter().map(normalize_stmt).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    })
}

fn normalize_stmt(stmt: &Stmt) -> Value {
    match stmt {
        Stmt::Assign { dst, src } => json!(["assign", normalize_reg(dst), normalize_expr(src)]),
        Stmt::Store { addr, value, size } => {
            json!(["store", normalize_expr(addr), normalize_expr(value), size])
        }
        Stmt::Branch { target } => json!(["branch", normalize_expr(target)]),
        Stmt::CondBranch {
            cond,
            target,
            fallthrough,
        } => json!([
            "cond_branch",
            normalize_branch_cond(cond),
            normalize_expr(target),
            hex_addr(*fallthrough)
        ]),
        Stmt::Call { target } => json!(["call", normalize_expr(target)]),
        Stmt::Ret => json!(["ret"]),
        Stmt::Nop => json!(["nop"]),
        Stmt::Pair(a, b) => json!(["pair", normalize_stmt(a), normalize_stmt(b)]),
        Stmt::SetFlags { expr } => json!(["set_flags", normalize_expr(expr)]),
        Stmt::Barrier(name) => json!(["barrier", name]),
        Stmt::Trap { kind: _, imm: _ } => json!(["trap"]),
        Stmt::Intrinsic { name, operands } => {
            json!([
                "intrinsic",
                name,
                operands.iter().map(normalize_expr).collect::<Vec<_>>()
            ])
        }
    }
}

fn normalize_branch_cond(cond: &BranchCond) -> Value {
    match cond {
        BranchCond::Flag(condition) => json!(["flag", normalize_condition(*condition)]),
        BranchCond::Zero(expr) => json!(["zero", normalize_expr(expr)]),
        BranchCond::NotZero(expr) => json!(["not_zero", normalize_expr(expr)]),
        BranchCond::BitZero(expr, bit) => json!(["bit_zero", normalize_expr(expr), bit]),
        BranchCond::BitNotZero(expr, bit) => {
            json!(["bit_not_zero", normalize_expr(expr), bit])
        }
        BranchCond::Compare { cond, lhs, rhs } => json!([
            "compare",
            normalize_condition(*cond),
            normalize_expr(lhs),
            normalize_expr(rhs)
        ]),
    }
}

fn normalize_expr(expr: &Expr) -> Value {
    match expr {
        Expr::Reg(reg) => json!(["reg", normalize_reg(reg)]),
        Expr::Imm(value) => json!(["imm", hex_addr(*value)]),
        Expr::FImm(value) => json!(["fimm", value]),
        Expr::Load { addr, size } => json!(["load", normalize_expr(addr), size]),
        Expr::Add(lhs, rhs) => json!(["add", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Sub(lhs, rhs) => json!(["sub", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Mul(lhs, rhs) => json!(["mul", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Div(lhs, rhs) => json!(["div", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::UDiv(lhs, rhs) => json!(["udiv", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Neg(value) => json!(["neg", normalize_expr(value)]),
        Expr::Abs(value) => json!(["abs", normalize_expr(value)]),
        Expr::And(lhs, rhs) => json!(["and", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Or(lhs, rhs) => json!(["or", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Xor(lhs, rhs) => json!(["xor", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Not(value) => json!(["not", normalize_expr(value)]),
        Expr::Shl(lhs, rhs) => json!(["shl", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Lsr(lhs, rhs) => json!(["lsr", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Asr(lhs, rhs) => json!(["asr", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::Ror(lhs, rhs) => json!(["ror", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::SignExtend { src, from_bits } => {
            json!(["sign_extend", normalize_expr(src), from_bits])
        }
        Expr::ZeroExtend { src, from_bits } => {
            json!(["zero_extend", normalize_expr(src), from_bits])
        }
        Expr::Extract { src, lsb, width } => {
            json!(["extract", normalize_expr(src), lsb, width])
        }
        Expr::Insert {
            dst,
            src,
            lsb,
            width,
        } => json!([
            "insert",
            normalize_expr(dst),
            normalize_expr(src),
            lsb,
            width
        ]),
        Expr::FAdd(lhs, rhs) => json!(["fadd", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::FSub(lhs, rhs) => json!(["fsub", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::FMul(lhs, rhs) => json!(["fmul", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::FDiv(lhs, rhs) => json!(["fdiv", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::FNeg(value) => json!(["fneg", normalize_expr(value)]),
        Expr::FAbs(value) => json!(["fabs", normalize_expr(value)]),
        Expr::FSqrt(value) => json!(["fsqrt", normalize_expr(value)]),
        Expr::FMax(lhs, rhs) => json!(["fmax", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::FMin(lhs, rhs) => json!(["fmin", normalize_expr(lhs), normalize_expr(rhs)]),
        Expr::FCvt(value) => json!(["fcvt", normalize_expr(value)]),
        Expr::IntToFloat(value) => json!(["int_to_float", normalize_expr(value)]),
        Expr::FloatToInt(value) => json!(["float_to_int", normalize_expr(value)]),
        Expr::Clz(value) => json!(["clz", normalize_expr(value)]),
        Expr::Cls(value) => json!(["cls", normalize_expr(value)]),
        Expr::Rev(value) => json!(["rev", normalize_expr(value)]),
        Expr::Rbit(value) => json!(["rbit", normalize_expr(value)]),
        Expr::CondSelect {
            cond,
            if_true,
            if_false,
        } => json!([
            "cond_select",
            normalize_condition(*cond),
            normalize_expr(if_true),
            normalize_expr(if_false)
        ]),
        Expr::Compare { cond, lhs, rhs } => json!([
            "compare",
            normalize_condition(*cond),
            normalize_expr(lhs),
            normalize_expr(rhs)
        ]),
        Expr::StackSlot { offset, size } => json!(["stack_slot", offset, size]),
        Expr::MrsRead(name) => json!(["mrs_read", name]),
        Expr::Intrinsic { name, operands } => {
            json!([
                "intrinsic",
                name,
                operands.iter().map(normalize_expr).collect::<Vec<_>>()
            ])
        }
        Expr::AdrpImm(value) => json!(["adrp_imm", hex_addr(*value)]),
        Expr::AdrImm(value) => json!(["adr_imm", hex_addr(*value)]),
    }
}

fn normalize_reg(reg: &Reg) -> String {
    match reg {
        Reg::X(n) => format!("x{}", n),
        Reg::W(n) => format!("w{}", n),
        Reg::SP => "sp".to_string(),
        Reg::PC => "pc".to_string(),
        Reg::XZR => "xzr".to_string(),
        Reg::Flags => "flags".to_string(),
        Reg::V(n) => format!("v{}", n),
        Reg::Q(n) => format!("q{}", n),
        Reg::D(n) => format!("d{}", n),
        Reg::S(n) => format!("s{}", n),
        Reg::H(n) => format!("h{}", n),
        Reg::VByte(n) => format!("vbyte{}", n),
    }
}

fn normalize_condition(condition: Condition) -> &'static str {
    match condition {
        Condition::EQ => "eq",
        Condition::NE => "ne",
        Condition::CS => "cs",
        Condition::CC => "cc",
        Condition::MI => "mi",
        Condition::PL => "pl",
        Condition::VS => "vs",
        Condition::VC => "vc",
        Condition::HI => "hi",
        Condition::LS => "ls",
        Condition::GE => "ge",
        Condition::LT => "lt",
        Condition::GT => "gt",
        Condition::LE => "le",
        Condition::AL => "al",
        Condition::NV => "nv",
    }
}

fn hex_addr(value: u64) -> String {
    format!("0x{:x}", value)
}

fn diff_json_values(expected: &Value, actual: &Value, path: &str, remaining: usize) -> Vec<String> {
    if remaining == 0 {
        return Vec::new();
    }
    if expected == actual {
        return Vec::new();
    }

    match (expected, actual) {
        (Value::Object(expected_map), Value::Object(actual_map)) => {
            let mut diffs = Vec::new();
            let mut keys = BTreeMap::new();
            for key in expected_map.keys() {
                keys.insert(key.clone(), ());
            }
            for key in actual_map.keys() {
                keys.insert(key.clone(), ());
            }
            for key in keys.keys() {
                if diffs.len() >= remaining {
                    break;
                }
                match (expected_map.get(key), actual_map.get(key)) {
                    (Some(expected_child), Some(actual_child)) => {
                        diffs.extend(diff_json_values(
                            expected_child,
                            actual_child,
                            &format!("{}.{}", path, key),
                            remaining - diffs.len(),
                        ));
                    }
                    (None, Some(_)) => diffs.push(format!("{}.{} added", path, key)),
                    (Some(_), None) => diffs.push(format!("{}.{} removed", path, key)),
                    (None, None) => {}
                }
            }
            diffs
        }
        (Value::Array(expected_items), Value::Array(actual_items)) => {
            let max_len = expected_items.len().max(actual_items.len());
            let mut diffs = Vec::new();
            for index in 0..max_len {
                if diffs.len() >= remaining {
                    break;
                }
                match (expected_items.get(index), actual_items.get(index)) {
                    (Some(expected_child), Some(actual_child)) => {
                        diffs.extend(diff_json_values(
                            expected_child,
                            actual_child,
                            &format!("{}[{}]", path, index),
                            remaining - diffs.len(),
                        ));
                    }
                    (None, Some(_)) => diffs.push(format!("{}[{}] added", path, index)),
                    (Some(_), None) => diffs.push(format!("{}[{}] removed", path, index)),
                    (None, None) => {}
                }
            }
            diffs
        }
        _ => vec![format!("{} expected {} got {}", path, expected, actual)],
    }
}

#[cfg(test)]
fn normalize_reduced_instructions_artifact(
    function_addr: u64,
    instructions: &[(u64, Stmt, Vec<u64>)],
) -> Value {
    let cfg = aeon_reduce::pipeline::reduce_function_cfg(instructions);
    normalize_cfg_artifact(function_addr, &cfg, None, None)
}

fn materialize_optional_golden_fields(mut expected: Value, actual: &Value) -> Value {
    let Some(expected_obj) = expected.as_object_mut() else {
        return expected;
    };
    let Some(actual_obj) = actual.as_object() else {
        return expected;
    };

    for key in ["binary_sha256", "function_sha256"] {
        match expected_obj.get(key) {
            Some(Value::Null) | None => {
                if let Some(actual_value) = actual_obj.get(key) {
                    expected_obj.insert(key.to_string(), actual_value.clone());
                }
            }
            Some(_) => {}
        }
    }

    expected
}

pub fn run_corpus(
    manifest: &CorpusManifest,
    binary_base: &std::path::Path,
) -> Vec<(String, Result<EvaluationRun, String>)> {
    manifest.tasks.iter().map(|task| {
        let entry = manifest.binaries.iter()
            .find(|b| b.id == task.corpus_entry_id);
        let binary_path = entry
            .map(|e| binary_base.join(&e.path).to_string_lossy().into_owned())
            .unwrap_or_else(|| task.corpus_entry_id.clone());

        let result = run_task(task, &binary_path)
            .map_err(|e| e.to_string());
        (task.id.clone(), result)
    }).collect()
}

fn run_task(task: &TaskSpec, binary_path: &str)
    -> Result<EvaluationRun, Box<dyn std::error::Error>>
{
    let mut run = match &task.kind {
        TaskKind::RecoverConstructorObjectLayout => {
            let addr = parse_hex_from_metadata(&task.metadata, "addr")?;
            evaluate_constructor_object_layout(binary_path, addr)?
        }
        TaskKind::ProduceEvidenceBundle => {
            let addr = parse_hex_from_metadata(&task.metadata, "addr")?;
            let query = task.metadata["query"].as_str()
                .ok_or("missing query in metadata")?;
            evaluate_datalog_query(binary_path, addr, query)?
        }
        TaskKind::ClassifyBehavior => {
            let addr = parse_hex_from_metadata(&task.metadata, "addr")?;
            evaluate_function_skeleton(binary_path, addr)?
        }
        TaskKind::ExtractDecryptedStrings => {
            let start_addr = parse_hex_from_metadata(&task.metadata, "start_addr")?;
            let end_addr = parse_hex_from_metadata(&task.metadata, "end_addr")?;
            let expected_regs: HashMap<String, u64> = task.metadata["expected_registers"]
                .as_object()
                .map(|m| m.iter().filter_map(|(k, v)| {
                    v.as_str().and_then(|s| parse_hex_u64(s).ok())
                        .map(|n| (k.clone(), n))
                }).collect())
                .unwrap_or_default();
            evaluate_emulation_snippet(binary_path, start_addr, end_addr, &expected_regs)?
        }
        _ => {
            let addr = parse_hex_from_metadata(&task.metadata, "addr")?;
            evaluate_constructor_object_layout(binary_path, addr)?
        }
    };

    if run.metrics.duration_ms.is_none() {
        run.metrics.duration_ms = Some(0);
    }
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeon::il::{e_add, e_intrinsic, e_load, e_sub};
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
            expected_outcome: ExpectedOutcome::ContainsStrings(vec!["config.json".to_string()]),
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

    #[test]
    fn synthetic_reduction_goldens_match() {
        let cases = vec![
            (
                0x1000,
                vec![
                    (
                        0x1000,
                        Stmt::Assign {
                            dst: Reg::X(8),
                            src: Expr::AdrpImm(0x412000),
                        },
                        vec![0x1004],
                    ),
                    (
                        0x1004,
                        Stmt::Assign {
                            dst: Reg::X(8),
                            src: e_add(Expr::Reg(Reg::X(8)), Expr::Imm(0x340)),
                        },
                        vec![0x1008],
                    ),
                    (
                        0x1008,
                        Stmt::Assign {
                            dst: Reg::X(0),
                            src: e_load(Expr::Reg(Reg::X(8)), 8),
                        },
                        vec![],
                    ),
                ],
                "synthetic-adrp-add-ldr.json",
            ),
            (
                0x2000,
                vec![
                    (
                        0x2000,
                        Stmt::SetFlags {
                            expr: e_sub(Expr::Reg(Reg::W(8)), Expr::Imm(1)),
                        },
                        vec![0x2004],
                    ),
                    (
                        0x2004,
                        Stmt::CondBranch {
                            cond: BranchCond::Flag(Condition::NE),
                            target: Expr::Imm(0x3000),
                            fallthrough: 0x2008,
                        },
                        vec![0x3000, 0x2008],
                    ),
                    (0x2008, Stmt::Ret, vec![]),
                    (0x3000, Stmt::Ret, vec![]),
                ],
                "synthetic-cmp-bne.json",
            ),
            (
                0x4000,
                vec![
                    (
                        0x4000,
                        Stmt::Assign {
                            dst: Reg::X(0),
                            src: Expr::Imm(0xBABE),
                        },
                        vec![0x4004],
                    ),
                    (
                        0x4004,
                        Stmt::Assign {
                            dst: Reg::X(0),
                            src: e_intrinsic(
                                "movk",
                                vec![Expr::Reg(Reg::X(0)), Expr::Imm(0xCAFE0000)],
                            ),
                        },
                        vec![0x4008],
                    ),
                    (
                        0x4008,
                        Stmt::Assign {
                            dst: Reg::X(0),
                            src: e_intrinsic(
                                "movk",
                                vec![Expr::Reg(Reg::X(0)), Expr::Imm(0xBEEF00000000)],
                            ),
                        },
                        vec![0x400c],
                    ),
                    (
                        0x400c,
                        Stmt::Assign {
                            dst: Reg::X(0),
                            src: e_intrinsic(
                                "movk",
                                vec![Expr::Reg(Reg::X(0)), Expr::Imm(0xDEAD000000000000)],
                            ),
                        },
                        vec![],
                    ),
                ],
                "synthetic-movk-chain.json",
            ),
        ];

        for (function_addr, instructions, golden_name) in cases {
            let actual = normalize_reduced_instructions_artifact(function_addr, &instructions);
            let expected = read_json(golden_path(golden_name));
            assert_eq!(
                actual, expected,
                "synthetic golden mismatch for {}",
                golden_name
            );
        }
    }

    #[test]
    fn reduced_il_binary_goldens_match_sample_elf() {
        let binary_path = sample_binary_path();
        let cases = [
            (0x650_u64, "hello-aarch64-0x650-reduced.json"),
            (0x710_u64, "hello-aarch64-0x710-reduced.json"),
            (0x788_u64, "hello-aarch64-0x788-reduced.json"),
        ];

        for (addr, golden_name) in cases {
            let run = evaluate_reduced_il_golden(
                binary_path.to_str().unwrap(),
                addr,
                golden_path(golden_name).to_str().unwrap(),
            )
            .expect("binary golden evaluation should succeed");
            assert_eq!(
                run.outcome,
                RunOutcome::Passed,
                "golden mismatch at 0x{:x}",
                addr
            );
        }
    }

    #[test]
    fn reduction_metrics_report_expected_counts_for_sample_function() {
        let binary_path = sample_binary_path();
        let run = evaluate_reduction_metrics(binary_path.to_str().unwrap(), 0x788)
            .expect("reduction metrics evaluation should succeed");

        assert_eq!(run.outcome, RunOutcome::Passed);

        let metrics = run
            .evidence
            .iter()
            .find(|item| item.id == "ev-metric-snapshot")
            .expect("metric snapshot evidence should exist");
        assert_eq!(metrics.value["eligible_stack_accesses"], json!(1));
        assert_eq!(metrics.value["stack_slots_recognized"], json!(1));
        assert_eq!(metrics.value["adrp_resolutions"], json!(3));
        assert_eq!(metrics.value["flag_fusions"], json!(2));
        assert_eq!(metrics.value["movk_chain_resolutions"], json!(0));
        assert_eq!(metrics.value["intrinsic_to_proper_il_ratio"], json!(0.0));

        let before = metrics.value["ssa_vars_before_optimization"]
            .as_u64()
            .expect("ssa_vars_before_optimization should be numeric");
        let after = metrics.value["ssa_vars_after_optimization"]
            .as_u64()
            .expect("ssa_vars_after_optimization should be numeric");
        assert!(after <= before);

        let validation = run
            .evidence
            .iter()
            .find(|item| item.id == "ev-ssa-validation")
            .expect("ssa validation evidence should exist");
        assert_eq!(validation.value["is_valid"], json!(true));
        assert_eq!(validation.value["issue_count"], json!(0));
    }

    #[test]
    fn sample_corpus_manifest_lists_expected_cases() {
        let manifest = read_json(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../eval/corpus/hello-aarch64-reduced.json"),
        );

        assert_eq!(manifest["id"], json!("hello-aarch64-reduced"));
        assert_eq!(manifest["path"], json!("samples/hello_aarch64.elf"));
        assert_eq!(
            manifest["cases"].as_array().map(Vec::len),
            Some(3),
            "manifest should keep the three sample golden cases in sync"
        );
    }

    fn sample_binary_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../samples/hello_aarch64.elf")
    }

    fn golden_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../eval/goldens")
            .join(name)
    }

    fn read_json(path: PathBuf) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn score_run_address_set_passes() {
        let task = TaskSpec {
            id: "task-1".to_string(),
            corpus_entry_id: "bin-1".to_string(),
            kind: TaskKind::FindConfigLoader,
            prompt: "test".to_string(),
            expected_outcome: ExpectedOutcome::AddressSet(vec!["0x401000".to_string()]),
            metadata: Value::Null,
        };
        let run = EvaluationRun {
            run_id: "run-1".to_string(),
            task_id: "task-1".to_string(),
            agent: AgentDescriptor {
                name: "aeon".to_string(),
                model: None,
                version: None,
            },
            outcome: RunOutcome::Passed,
            claims: vec![Claim {
                id: "c1".to_string(),
                statement: "Found function at 0x401000".to_string(),
                confidence: Some(0.9),
                evidence_ids: vec!["e1".to_string()],
                metadata: Value::Null,
            }],
            evidence: vec![EvidenceItem {
                id: "e1".to_string(),
                kind: EvidenceKind::Address,
                label: "addr".to_string(),
                value: json!({"value": "0x401000"}),
                provenance: vec![],
            }],
            metrics: RunMetrics {
                duration_ms: Some(100),
                prompt_tokens: None,
                completion_tokens: None,
                tool_calls: 1,
                metadata: Value::Null,
            },
        };
        let score = score_run(&run, &task);
        assert!(score.passed);
        assert_eq!(score.score, 1.0);
    }

    #[test]
    fn score_run_address_set_fails() {
        let task = TaskSpec {
            id: "task-1".to_string(),
            corpus_entry_id: "bin-1".to_string(),
            kind: TaskKind::FindConfigLoader,
            prompt: "test".to_string(),
            expected_outcome: ExpectedOutcome::AddressSet(vec!["0x999999".to_string()]),
            metadata: Value::Null,
        };
        let run = EvaluationRun {
            run_id: "run-1".to_string(),
            task_id: "task-1".to_string(),
            agent: AgentDescriptor {
                name: "aeon".to_string(),
                model: None,
                version: None,
            },
            outcome: RunOutcome::Passed,
            claims: vec![],
            evidence: vec![],
            metrics: RunMetrics {
                duration_ms: Some(100),
                prompt_tokens: None,
                completion_tokens: None,
                tool_calls: 1,
                metadata: Value::Null,
            },
        };
        let score = score_run(&run, &task);
        assert!(!score.passed);
        assert_eq!(score.score, 0.0);
    }

    #[test]
    fn score_run_contains_strings_passes() {
        let task = TaskSpec {
            id: "task-1".to_string(),
            corpus_entry_id: "bin-1".to_string(),
            kind: TaskKind::ExtractDecryptedStrings,
            prompt: "test".to_string(),
            expected_outcome: ExpectedOutcome::ContainsStrings(vec!["secret_key".to_string()]),
            metadata: Value::Null,
        };
        let run = EvaluationRun {
            run_id: "run-1".to_string(),
            task_id: "task-1".to_string(),
            agent: AgentDescriptor {
                name: "aeon".to_string(),
                model: None,
                version: None,
            },
            outcome: RunOutcome::Passed,
            claims: vec![Claim {
                id: "c1".to_string(),
                statement: "Found secret_key in decrypted strings".to_string(),
                confidence: Some(0.9),
                evidence_ids: vec![],
                metadata: Value::Null,
            }],
            evidence: vec![],
            metrics: RunMetrics {
                duration_ms: Some(100),
                prompt_tokens: None,
                completion_tokens: None,
                tool_calls: 1,
                metadata: Value::Null,
            },
        };
        let score = score_run(&run, &task);
        assert!(score.passed);
    }

    #[test]
    fn score_run_structured_claim_passes() {
        let task = TaskSpec {
            id: "task-1".to_string(),
            corpus_entry_id: "bin-1".to_string(),
            kind: TaskKind::ClassifyBehavior,
            prompt: "test".to_string(),
            expected_outcome: ExpectedOutcome::StructuredClaim {
                statement: "function has crypto".to_string(),
                required_evidence_kinds: vec![EvidenceKind::JsonArtifact],
            },
            metadata: Value::Null,
        };
        let run = EvaluationRun {
            run_id: "run-1".to_string(),
            task_id: "task-1".to_string(),
            agent: AgentDescriptor {
                name: "aeon".to_string(),
                model: None,
                version: None,
            },
            outcome: RunOutcome::Passed,
            claims: vec![],
            evidence: vec![EvidenceItem {
                id: "e1".to_string(),
                kind: EvidenceKind::JsonArtifact,
                label: "artifact".to_string(),
                value: json!({}),
                provenance: vec![],
            }],
            metrics: RunMetrics {
                duration_ms: Some(100),
                prompt_tokens: None,
                completion_tokens: None,
                tool_calls: 1,
                metadata: Value::Null,
            },
        };
        let score = score_run(&run, &task);
        assert!(score.passed);
    }

    #[test]
    fn aggregate_benchmark_computes_pass_rate() {
        let scores = vec![
            TaskScore {
                task_id: "t1".to_string(),
                run_id: "r1".to_string(),
                passed: true,
                score: 1.0,
                outcome_kind: "address_set".to_string(),
                details: Value::Null,
                duration_ms: Some(100),
            },
            TaskScore {
                task_id: "t2".to_string(),
                run_id: "r2".to_string(),
                passed: true,
                score: 1.0,
                outcome_kind: "address_set".to_string(),
                details: Value::Null,
                duration_ms: Some(200),
            },
            TaskScore {
                task_id: "t3".to_string(),
                run_id: "r3".to_string(),
                passed: true,
                score: 1.0,
                outcome_kind: "address_set".to_string(),
                details: Value::Null,
                duration_ms: Some(150),
            },
            TaskScore {
                task_id: "t4".to_string(),
                run_id: "r4".to_string(),
                passed: false,
                score: 0.0,
                outcome_kind: "address_set".to_string(),
                details: Value::Null,
                duration_ms: Some(50),
            },
        ];
        let report = aggregate_benchmark("test-manifest", scores);
        assert_eq!(report.total_tasks, 4);
        assert_eq!(report.passed, 3);
        assert_eq!(report.failed, 1);
        assert!((report.pass_rate - 0.75).abs() < 0.01);
        assert_eq!(report.total_duration_ms, 500);
        assert_eq!(report.manifest_id, "test-manifest");
    }

    #[test]
    fn evaluate_function_skeleton_produces_evidence() {
        let binary_path = sample_binary_path();
        let run = evaluate_function_skeleton(binary_path.to_str().unwrap(), 0x650)
            .expect("skeleton evaluation should succeed");
        assert_eq!(run.outcome, RunOutcome::Passed);
        assert_eq!(run.evidence.len(), 1);
        assert_eq!(run.evidence[0].kind, EvidenceKind::JsonArtifact);
        assert!(run.metrics.duration_ms.is_some());
    }

    #[test]
    fn evaluate_datalog_query_produces_result() {
        let binary_path = sample_binary_path();
        let run = evaluate_datalog_query(binary_path.to_str().unwrap(), 0x788, "reachability")
            .expect("datalog evaluation should succeed");
        assert_eq!(run.outcome, RunOutcome::Passed);
        assert_eq!(run.evidence.len(), 1);
        assert_eq!(run.evidence[0].kind, EvidenceKind::DatalogResult);
        assert!(run.metrics.duration_ms.is_some());
    }

    #[test]
    fn evaluator_has_timing() {
        let binary_path = sample_binary_path();
        let run = evaluate_function_skeleton(binary_path.to_str().unwrap(), 0x650)
            .expect("skeleton evaluation should succeed");
        assert!(run.metrics.duration_ms.is_some());
        assert!(run.metrics.duration_ms.unwrap() >= 0);
    }
}
