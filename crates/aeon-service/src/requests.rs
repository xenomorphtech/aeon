//! The arguments of every tool, as types.
//!
//! Each tool's request struct is both what its arguments are parsed into
//! (`Deserialize`) and what its published schema is generated from
//! (`JsonSchema`), so the two cannot disagree. Field doc comments become the
//! schema's descriptions.

use std::collections::HashMap;

use schemars::generate::SchemaSettings;
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::service::ArgError;

/// Parses a tool call's arguments. Absent arguments are an empty object.
pub fn parse<R: DeserializeOwned>(args: &Value) -> Result<R, ArgError> {
    let args = match args {
        Value::Null => Value::Object(Default::default()),
        other => other.clone(),
    };
    serde_json::from_value(args).map_err(|error| {
        let message = error.to_string();
        // serde says "missing field `addr`"; say which parameter instead.
        match message
            .strip_prefix("missing field `")
            .and_then(|rest| rest.split('`').next())
        {
            Some(field) => ArgError::from(format!("Missing required parameter: {}", field)),
            None => ArgError::from(format!("Invalid arguments: {}", message)),
        }
    })
}

/// The JSON schema of a request type, self-contained (no `$ref`s).
pub fn schema_of<R: JsonSchema>() -> Value {
    let settings = SchemaSettings::draft2020_12().with(|settings| {
        settings.inline_subschemas = true;
        settings.meta_schema = None;
    });
    let mut schema = settings.into_generator().into_root_schema_for::<R>().to_value();
    if let Some(object) = schema.as_object_mut() {
        // The tool's name and description are published next to the schema.
        object.remove("title");
        object.remove("description");
        object
            .entry("properties")
            .or_insert_with(|| Value::Object(Default::default()));
    }
    unwrap_descriptions(&mut schema);
    schema
}

/// Doc comments are wrapped in the source; descriptions should not be.
fn unwrap_descriptions(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                match value {
                    Value::String(text) if key == "description" => {
                        *text = text.split_whitespace().collect::<Vec<_>>().join(" ");
                    }
                    other => unwrap_descriptions(other),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(unwrap_descriptions),
        _ => {}
    }
}

pub fn parse_hex(text: &str) -> Option<u64> {
    let digits = text.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(digits, 16).ok()
}

/// A virtual address, written in hex with or without `0x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexAddr(pub u64);

impl<'de> Deserialize<'de> for HexAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse_hex(&text)
            .map(HexAddr)
            .ok_or_else(|| serde::de::Error::custom(format!("Invalid hex address: {}", text)))
    }
}

impl JsonSchema for HexAddr {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "HexAddr".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string" })
    }
}

/// A number given as an integer or as a hex string.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RegisterValue {
    Int(u64),
    Hex(String),
}

impl RegisterValue {
    /// The value, or an error naming `what` it was for.
    pub fn value(&self, what: &str) -> Result<u64, ArgError> {
        match self {
            RegisterValue::Int(value) => Ok(*value),
            RegisterValue::Hex(text) => parse_hex(text)
                .ok_or_else(|| ArgError::from(format!("Invalid hex value for {}: {}", what, text))),
        }
    }
}

/// Bytes to place in memory: a hex number, stored as a little-endian
/// 64-bit value, or an array of bytes.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum MemoryValue {
    Hex(String),
    Bytes(Vec<u8>),
}

pub fn register_map(
    registers: HashMap<String, RegisterValue>,
) -> Result<HashMap<String, u64>, ArgError> {
    registers
        .into_iter()
        .map(|(name, value)| {
            let value = value.value(&format!("register {}", name))?;
            Ok((name, value))
        })
        .collect()
}

pub fn memory_map(memory: HashMap<String, MemoryValue>) -> Result<HashMap<u64, Vec<u8>>, ArgError> {
    memory
        .into_iter()
        .map(|(addr, value)| {
            let addr = parse_hex(&addr).ok_or_else(|| {
                ArgError::from(format!("Invalid hex address for memory: {}", addr))
            })?;
            let bytes = match value {
                MemoryValue::Bytes(bytes) => bytes,
                MemoryValue::Hex(text) => parse_hex(&text)
                    .ok_or_else(|| ArgError::from(format!("Invalid hex value: {}", text)))?
                    .to_le_bytes()
                    .to_vec(),
            };
            Ok((addr, bytes))
        })
        .collect()
}

fn default_true() -> bool {
    true
}
fn default_elf() -> String {
    "elf".to_string()
}
fn default_6() -> usize {
    6
}
fn default_32() -> usize {
    32
}
fn default_50() -> usize {
    50
}
fn default_64() -> usize {
    64
}
fn default_100() -> usize {
    100
}
fn default_256() -> usize {
    256
}
fn default_1000() -> usize {
    1000
}

/// A tool that takes no arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct NoArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoadBinary {
    /// Path to binary
    pub path: String,
    /// Binary format: 'elf' or 'raw'
    #[serde(default = "default_elf")]
    pub format: String,
    /// Required for raw binaries: virtual base address in hex
    pub base_addr: Option<HexAddr>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFunctions {
    /// Start index
    #[serde(default)]
    pub offset: usize,
    /// Max results
    #[serde(default = "default_100")]
    pub limit: usize,
    /// Substring filter on symbol name
    #[serde(default)]
    pub name_filter: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NameAddress {
    /// Virtual address in hex
    pub addr: HexAddr,
    /// Semantic symbol name to assign to the address
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DefineStruct {
    /// Virtual address in hex
    pub addr: HexAddr,
    /// Structure definition text
    pub definition: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddHypothesis {
    /// Virtual address in hex
    pub addr: HexAddr,
    /// Hypothesis or analyst note
    pub note: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchAnalysisNames {
    /// Regex pattern matched against analysis names
    pub pattern: String,
}

/// The one argument of the many tools that work on an address.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AtAddress {
    /// Any virtual address in hex, e.g. '0x5e611fc'
    pub addr: HexAddr,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetSsa {
    /// Any virtual address in hex, e.g. '0x5e611fc'
    pub addr: HexAddr,
    /// Run SSA optimization passes before returning JSON
    #[serde(default = "default_true")]
    pub optimize: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetDataFlowSlice {
    /// Instruction address in hex, e.g. '0x5e611fc'
    pub addr: HexAddr,
    /// Register name (e.g., 'x0', 'w1', 'sp')
    pub register: String,
    /// Direction of data flow to trace
    #[schemars(extend("enum" = ["backward", "forward"]))]
    pub direction: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteDatalog {
    /// Named Datalog query to execute
    #[schemars(extend("enum" = [
        "reachability", "defines", "reads_mem", "writes_mem", "flows_to",
        "call_graph", "call_graph_transitive"
    ]))]
    pub query: String,
    /// Virtual address in hex. For per-function queries, identifies the
    /// function. For cross-function queries, identifies the root function.
    pub addr: HexAddr,
    /// Register name (e.g. 'x0', 'w1', 'sp'). Required for 'defines' and
    /// 'flows_to' queries.
    pub register: Option<String>,
    /// Maximum number of result tuples to return (default 500)
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFunctionPointers {
    /// Optional function address in hex; when present, analyzes the
    /// containing function
    pub addr: Option<HexAddr>,
    /// Start index when scanning multiple functions
    #[serde(default)]
    pub offset: usize,
    /// Max functions to analyze when addr is omitted
    #[serde(default = "default_50")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindCallPaths {
    /// Start function address in hex
    pub start_addr: HexAddr,
    /// Goal function address in hex
    pub goal_addr: HexAddr,
    /// Maximum call depth to explore
    #[serde(default = "default_6")]
    pub max_depth: usize,
    /// Include all simple paths up to max_depth
    #[serde(default)]
    pub include_all_paths: bool,
    /// Maximum number of paths to return when include_all_paths is true
    #[serde(default = "default_32")]
    pub max_paths: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadBytes {
    /// Virtual address in hex
    pub addr: HexAddr,
    /// Number of bytes to read
    #[serde(default = "default_64")]
    pub size: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetAsm {
    /// Start virtual address in hex, e.g. '0x512025c'
    pub start_addr: HexAddr,
    /// Stop virtual address in hex (exclusive), e.g. '0x51202cc'
    pub stop_addr: HexAddr,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFunctionAt {
    /// Any virtual address in hex, e.g. '0x5e611fc'
    pub addr: HexAddr,
    /// Include asm in the returned listing
    #[serde(default)]
    pub include_asm: bool,
    /// Include AeonIL in the returned listing
    #[serde(default)]
    pub include_il: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetString {
    /// Virtual address in hex
    pub addr: HexAddr,
    /// Max bytes to scan for null terminator
    #[serde(default = "default_256")]
    pub max_len: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmulateIl {
    /// Hex address to begin execution, e.g. '0x1234'
    pub start_addr: HexAddr,
    /// Hex address to stop execution (exclusive)
    pub end_addr: HexAddr,
    /// Register values at entry. Keys: x0-x30, sp. Values: hex strings or
    /// integers.
    #[serde(default)]
    pub initial_registers: HashMap<String, RegisterValue>,
    /// Max IL statements to execute
    #[serde(default = "default_1000")]
    pub step_limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmulateNative {
    /// Hex address to begin execution, e.g. '0x1234'
    pub start_addr: HexAddr,
    /// Hex address to stop execution (exclusive)
    pub end_addr: HexAddr,
    /// Register values at entry. Keys: x0-x30, sp, pc, nzcv. Values: hex
    /// strings or integers.
    #[serde(default)]
    pub initial_registers: HashMap<String, RegisterValue>,
    /// Memory overlays. Keys: hex addresses. Values: hex string or array of
    /// bytes.
    #[serde(default)]
    pub initial_memory: HashMap<String, MemoryValue>,
    /// Max instructions to execute
    #[serde(default = "default_1000")]
    pub step_limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Watchpoint {
    /// Watchpoint address in hex
    pub addr: HexAddr,
    /// Range size in bytes: an integer or a hex string (default 8)
    pub size: Option<RegisterValue>,
    /// Trigger on reads
    #[serde(default)]
    pub on_read: bool,
    /// Trigger on writes
    #[serde(default = "default_true")]
    pub on_write: bool,
    /// Stop execution on hit
    #[serde(default)]
    pub stop_on_hit: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RegisterPatch {
    /// Register name (x0-x30, sp, pc, nzcv)
    pub name: String,
    /// Value in hex
    pub value: HexAddr,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddressHook {
    /// Hook address in hex
    pub addr: HexAddr,
    /// Stop execution on hit
    #[serde(default)]
    pub stop_on_hit: bool,
    /// Register patches to apply
    #[serde(default)]
    pub patches: Vec<RegisterPatch>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmulateNativeAdvanced {
    /// Hex address to begin execution, e.g. '0x1234'
    pub start_addr: HexAddr,
    /// Hex address to stop execution (exclusive)
    pub end_addr: HexAddr,
    /// Register values at entry. Keys: x0-x30, sp, pc, nzcv. Values: hex
    /// strings or integers.
    #[serde(default)]
    pub initial_registers: HashMap<String, RegisterValue>,
    /// Memory overlays. Keys: hex addresses. Values: hex string or array of
    /// bytes.
    #[serde(default)]
    pub initial_memory: HashMap<String, MemoryValue>,
    /// Max instructions to execute
    #[serde(default = "default_1000")]
    pub step_limit: usize,
    /// Memory watchpoints to track
    #[serde(default)]
    pub watchpoints: Vec<Watchpoint>,
    /// Instruction hooks with optional register patches
    #[serde(default)]
    pub address_hooks: Vec<AddressHook>,
    /// Record visited PC values
    #[serde(default)]
    pub record_pc_trace: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn addresses_parse_with_or_without_a_prefix() {
        let request: AtAddress = parse(&json!({ "addr": "0x7D8" })).unwrap();
        assert_eq!(request.addr, HexAddr(0x7d8));
        let request: AtAddress = parse(&json!({ "addr": "7d8" })).unwrap();
        assert_eq!(request.addr, HexAddr(0x7d8));
    }

    #[test]
    fn argument_errors_name_the_parameter() {
        let error = parse::<AtAddress>(&json!({})).unwrap_err();
        assert_eq!(error, ArgError::from("Missing required parameter: addr"));
        let error = parse::<AtAddress>(&json!({ "addr": "zzz" })).unwrap_err();
        assert!(format!("{error:?}").contains("Invalid hex address: zzz"));
        let error = parse::<GetSsa>(&json!({ "addr": "0x1", "optimize": "yes" })).unwrap_err();
        assert!(format!("{error:?}").contains("optimize") || format!("{error:?}").contains("boolean"));
    }

    #[test]
    fn omitted_arguments_take_their_defaults() {
        let request: ListFunctions = parse(&Value::Null).unwrap();
        assert_eq!((request.offset, request.limit), (0, 100));
        assert_eq!(request.name_filter, "");
        let request: GetSsa = parse(&json!({ "addr": "0x1" })).unwrap();
        assert!(request.optimize);
    }

    #[test]
    fn schema_matches_what_the_parser_requires() {
        let schema = schema_of::<FindCallPaths>();
        assert_eq!(schema["type"], "object");
        let mut required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        required.sort();
        assert_eq!(required, ["goal_addr", "start_addr"]);
        assert_eq!(schema["properties"]["max_depth"]["default"], 6);
        assert_eq!(schema["properties"]["start_addr"]["type"], "string");

        // Exactly the required fields are needed to parse.
        assert!(parse::<FindCallPaths>(&json!({ "start_addr": "1", "goal_addr": "2" })).is_ok());
        assert!(parse::<FindCallPaths>(&json!({ "start_addr": "1" })).is_err());
    }

    #[test]
    fn schemas_are_self_contained_and_unwrapped() {
        let schema = schema_of::<EmulateNativeAdvanced>();
        let text = schema.to_string();
        assert!(!text.contains("$ref"), "{text}");
        assert!(!text.contains("\\n"), "{text}");
        assert_eq!(schema_of::<NoArgs>()["properties"], json!({}));
    }

    #[test]
    fn register_and_memory_values_take_hex_or_numbers() {
        let request: EmulateNative = parse(&json!({
            "start_addr": "0x10",
            "end_addr": "0x20",
            "initial_registers": { "x0": "0xff", "x1": 7 },
            "initial_memory": { "0x100": "0x1122", "0x200": [1, 2, 3] },
        }))
        .unwrap();
        let registers = register_map(request.initial_registers).unwrap();
        assert_eq!((registers["x0"], registers["x1"]), (0xff, 7));
        let memory = memory_map(request.initial_memory).unwrap();
        assert_eq!(memory[&0x100], 0x1122u64.to_le_bytes());
        assert_eq!(memory[&0x200], [1, 2, 3]);
    }
}
