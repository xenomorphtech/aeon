# aeon

aeon is meant to be a sensory organ, reasoning sandbox, and execution environment for autonomous AI agents, without any bloat from human-aimed tooling.

In this repository, that idea is applied to ARM64 ELF analysis. The workspace provides a reusable Rust analysis core plus thin agent-facing frontends that load binaries, lift instructions into AeonIL, run Datalog analyses, and expose the results through strict JSON interfaces.

The repository includes a small sample ARM64 ELF at `samples/hello_aarch64.elf` for smoke tests and examples.

## Design Principles

- **Agent-native first** - interfaces are machine-oriented and JSON-based
- **Sensory surface over UX surface** - the system exposes bytes, strings, asm, IL, CFGs, xrefs, and behavioral search primitives directly
- **Reasoning sandbox** - a binary is loaded once into a persistent session, then queried repeatedly through narrow tool calls
- **Execution environment** - CLI, MCP, and HTTP frontends give autonomous agents a concrete place to run analysis actions
- **No human-tooling bloat** - no dashboards, no TUI layer, no analyst workflow scaffolding

## Current Capabilities

- **ARM64 ELF ingestion** - parses ELF images and discovers functions from `.eh_frame`
- **AeonIL lifting** - lifts ARM64 instructions into a BNIL-style intermediate representation
- **ECS-backed program model** - stores instruction facts and relationships in `bevy_ecs`
- **Datalog analysis** - computes CFG edges, reachability, terminal blocks, and cross-references with `ascent`
- **Behavioral crypto search** - detects RC4 KSA and PRGA patterns structurally rather than by signature
- **Pointer and vtable recovery** - scans mapped data for internal pointers, detects candidate C++ vtables, and groups related tables
- **Function reference recovery** - resolves direct and PC-relative pointer operands to map per-function code and data references
- **Call-path search** - builds a direct-plus-vtable call graph and finds shortest or bounded paths between functions
- **Raw memory inspection** - reads bytes, data regions, and null-terminated strings from virtual addresses
- **Agent-facing transport layers** - exposes the same session through CLI, MCP over stdio, and a stateful HTTP API

## Workspace Layout

- `crates/aeon-eval` - evaluation corpus, task, claim, and evidence models
- `crates/aeonil` - standalone AeonIL crate
- `crates/aeon` - reusable analysis library
- `crates/aeon-frontend` - CLI, MCP, and HTTP frontends
- `crates/survey` - standalone opcode survey utility

## Build

```bash
cargo build --release
```

This produces:

- `target/release/aeon`
- `target/release/aeon-eval`
- `target/release/aeon-mcp`
- `target/release/aeon-http`
- `target/release/survey`

## Interfaces

### CLI

The CLI is intentionally small and machine-friendly. It prints JSON and supports direct analysis modes for inspection, pointer recovery, and path search:

```bash
# Search for RC4 implementations
aeon rc4 samples/hello_aarch64.elf

# Report IL lift coverage
aeon coverage samples/hello_aarch64.elf

# Inspect the function containing a specific address
aeon func samples/hello_aarch64.elf 0x7d8

# Scan mapped data sections for internal pointers
aeon pointers libUnreal.so

# Detect candidate vtables
aeon vtables libUnreal.so

# Enumerate pointer references in a function
aeon func-pointers libUnreal.so 0x5e66990

# Search call-graph paths between two functions
aeon call-path libUnreal.so 0x5e66990 0x5e66990 --all
```

### MCP Server

`aeon-mcp` exposes the analysis session as JSON-RPC 2.0 over stdio for agent runtimes that speak MCP.

The project root includes `.mcp.json` for local auto-discovery in Claude Code. It runs the server through `cargo run --release`, so it does not depend on a machine-specific binary path.

### HTTP API

`aeon-http` exposes the same stateful session over HTTP:

```bash
aeon-http 127.0.0.1:8787
```

Example calls:

```bash
curl -s http://127.0.0.1:8787/call \
  -H 'content-type: application/json' \
  -d '{"name":"load_binary","arguments":{"path":"samples/hello_aarch64.elf"}}'

curl -s http://127.0.0.1:8787/call \
  -H 'content-type: application/json' \
  -d '{"name":"get_function_at","arguments":{"addr":"0x7d8"}}'

curl -s http://127.0.0.1:8787/call \
  -H 'content-type: application/json' \
  -d '{"name":"get_il","arguments":{"addr":"0x7d8"}}'
```

Useful endpoints:

- `GET /health` - loaded or unloaded state plus session summary
- `GET /tools` - tool schemas
- `POST /call` - execute `{ "name": "...", "arguments": { ... } }`

### Library

The core crate can also be embedded directly in Rust tooling:

```toml
[dependencies]
aeon = { path = "/path/to/aeon/crates/aeon" }
serde_json = "1.0"
```

```rust
use aeon::AeonSession;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = AeonSession::load("samples/hello_aarch64.elf")?;
    let functions = session.list_functions(0, 10, None);
    println!("{}", serde_json::to_string_pretty(&functions)?);
    Ok(())
}
```

Lower-level modules remain public for callers that want direct access to ELF parsing, lifting, IL types, engine internals, or RC4 search logic.

### Survey

`survey` is a generic opcode survey tool for any ELF that aeon can parse:

```bash
survey samples/hello_aarch64.elf --limit 20
survey samples/hello_aarch64.elf --json
```

### Eval

`aeon-eval` runs reproducible capability checks and emits evidence-bearing JSON:

```bash
aeon-eval constructor-layout libUnreal.so 0x05e66990
```

## Tool Surface

These tools are exposed by the MCP and HTTP frontends:

Generated from `crates/aeon-frontend/src/service.rs` via `cargo run -p aeon-frontend --bin aeon_docgen`.

<!-- BEGIN GENERATED TOOL SURFACE -->
| Tool | Description |
|------|-------------|
| `load_binary` | Load an ELF or raw AArch64 binary for analysis. Must be called before other tools. Typical workflow: load_binary → list_functions → get_function_skeleton (triage) → get_il/get_ssa (deep analysis). Returns binary metadata (entry point, section info). For raw binaries, base_addr sets virtual address offset. |
| `list_functions` | List functions discovered from .eh_frame unwind tables. Supports pagination and name filtering. |
| `set_analysis_name` | Attach or overwrite a semantic symbol name on an address (identical to rename_symbol). Assigns a custom analysis label for documentation and reference. |
| `rename_symbol` | Attach or overwrite a semantic symbol name on an address (identical to set_analysis_name). Assigns a custom analysis label for documentation and reference. |
| `define_struct` | Attach or overwrite a structure definition on an address. Use to document inferred struct layouts at data locations or function parameters. Definition is free-form text (e.g. `{field1: u64, field2: u32}` or C-like `struct { uint64_t a; uint32_t b; }`). Returns success/failure. Limitation: definition is stored as text; no validation or type checking applied. |
| `add_hypothesis` | Record a semantic hypothesis or analyst note on an address. Accumulates observations; duplicates ignored. Use to document reasoning, suspected vulnerabilities, or ambiguous behavior. Example notes: `possible_integer_overflow`, `looks_like_CRC32_loop`, `malloc_call_without_check`. All notes retrieved via get_blackboard_entry. |
| `search_analysis_names` | Search analysis names attached to addresses using a regex pattern. Finds all addresses where set_analysis_name/rename_symbol was used. Use to locate all references to a specific analysis (e.g., all hypothetical vulnerability sites). Limitations: only searches names already annotated; returns empty if no matches. Example: pattern `^crypto_` finds all crypto-related annotations. |
| `get_blackboard_entry` | Look up all semantic context at an address: symbol name, struct definition, hypotheses, containing function. Use to inspect accumulated annotations (e.g., what prior analysis named this location). Returns annotations added via set_analysis_name, define_struct, add_hypothesis. Limitation: empty if no annotations were added to this address. Use after analysis pass to review findings. |
| `get_il` | Get the lifted AeonIL intermediate language listing for the function containing a given address. Use when analyzing full IL details. For block-structure overview, use get_reduced_il instead. |
| `get_function_il` | Backwards-compatible alias for get_il. |
| `get_reduced_il` | Return block-structured reduced AeonIL for the function containing a given address. Use when you need control flow structure without full IL details. Faster than get_il for overview analysis. |
| `get_ssa` | Return reduced SSA form for the function containing a given address, optionally optimized. Use for data flow analysis and value tracking. Better than IL for understanding variable definitions and uses. |
| `get_stack_frame` | Summarize the detected stack frame and visible stack-slot accesses for the function containing a given address. Use to identify local variables, stack-based arguments, and saved register locations. |
| `get_function_cfg` | Get the Control Flow Graph for a function. Returns block adjacency (edges), terminal blocks, and reachability analysis. Use to identify loops, dominators, dead code, or understand control dependencies. Returns block addresses and successors (branch targets). Limitation: represents lifted IL structure, not obfuscated control flow flattening patterns. |
| `get_function_skeleton` | Get a dense summary of function properties for quick analysis: argument count, calls, string literals, loops, crypto constants, stack frame, suspicious patterns. Use for initial function triage before detailed analysis with get_il or get_cfg. |
| `get_data_flow_slice` | Trace value flow for a register backward or forward from an instruction. Backward: find where value originates. Forward: find where value is consumed. Returns instruction addresses and registers in the data dependency chain. Use to understand parameter flow or value dependencies. |
| `get_xrefs` | Get cross-references for an address: outgoing calls (direct BL/BLR) and incoming callers. Returns call sites with target functions. Use to map call graph edges, find data flow entry points, or identify vulnerability sinks. Limitation: does not resolve indirect VTable calls. Returns both function addresses and call site locations for tracing execution paths. |
| `execute_datalog` | Run a named Datalog query over a function or the whole binary. Returns structured facts derived by the ascent Datalog engine from lifted AeonIL. Query-specific parameters: 'defines' and 'flows_to' require 'register' parameter. Others only need 'addr'. |
| `scan_pointers` | Scan data sections (.rodata, .data) for embedded pointers. Classifies references as data-to-data or data-to-code. Returns map of pointer addresses and targets. Use to find hidden function pointers or global data references. |
| `scan_vtables` | Detect C++ virtual method tables (vtables) in data sections. Finds arrays of function pointers and groups related tables. Returns vtable addresses and methods. Use to understand class hierarchies and virtual dispatch. |
| `get_function_pointers` | Enumerate pointer-valued operands and resolved code/data references for one function or a paginated slice of functions. Use with addr to analyze one function, or omit addr to scan all functions. |
| `find_call_paths` | Find call-graph paths between two functions. Returns shortest path by default. Use to understand how execution reaches target functions. Enable include_all_paths for all reachable paths (useful for exploit chains or data flow tracking). |
| `get_bytes` | Read raw bytes from the binary at a virtual address. Returns hex-encoded string. Use for quick binary inspection at text section addresses. Prefer get_data for reading ELF data sections (.rodata, .data) which handles segment mapping automatically. |
| `search_rc4` | Search for RC4 cipher implementations using behavioral pattern matching (KSA: swap+mod256; PRGA: XOR+keystream). Use to identify crypto operations in obfuscated code. Returns candidate functions with confidence scores. Limitation: may match similar bit-manipulation patterns (not guaranteed RC4). No examples available (algorithm signatures); returns matching function addresses and matching IL subgraph patterns. |
| `get_coverage` | Get IL lift coverage: % successfully lifted vs intrinsics vs NOPs vs decode errors. Use to assess IL quality and identify unlifted patterns (e.g., SIMD/crypto). Returns counts and percentages for each category. Interpretation: >95% lifted = high confidence, <85% = significant gaps. Limitation: does not indicate semantic correctness, only syntactic liftability. |
| `get_asm` | Disassemble ARM64 instructions between two virtual addresses. Returns asm only, without AeonIL. Use for quick assembly inspection without full IL lifting. |
| `get_function_at` | Find the function containing a given address. Returns function metadata (bounds, name, etc.). Use include_asm=true for assembly listing or include_il=true for full IL analysis. Quick way to identify function context before deeper analysis. |
| `get_string` | Read a null-terminated string at any virtual address (works across all ELF segments, not just .text). Use to extract embedded strings, error messages, or constants for context in analysis. |
| `get_data` | Read raw bytes at any virtual address (works across all ELF segments). Returns hex + ASCII. Use for inspecting data sections, tables, or constants outside of code regions. |
| `emulate_snippet_il` | Execute an ARM64 code region using AeonIL interpretation without full binary emulation. Faster than native emulation. Use for symbolic execution, quick logic analysis, or stripped code. For accurate memory simulation, use emulate_snippet_native instead. |
| `emulate_snippet_native` | Execute an ARM64 code region in unicorn ARM64 sandbox. Full native emulation with memory support. Use for reversing obfuscated loops, string decryption, or format decoders. Returns final register state, memory writes, and decoded strings. For faster interpretation-only analysis, use emulate_snippet_il instead. |
| `emulate_snippet` | Execute an ARM64 code region in a bounded sandbox. Alias for emulate_snippet_native. Returns final register state, memory writes, and decoded strings. Use for reversing obfuscated loops, string decryption, or format decoders. |
| `emulate_snippet_native_advanced` | Execute an ARM64 code region with advanced features: memory watchpoints, instruction hooks with register patching, PC tracing, and extended register state (SIMD). |
<!-- END GENERATED TOOL SURFACE -->

## Architecture

```text
ELF binary
  -> bad64 decode
    -> AeonIL lifting
      -> bevy_ecs fact store
        -> ascent Datalog analysis
          -> CLI / MCP / HTTP agent interface
```

## Key Modules

| File | Purpose |
|------|---------|
| `crates/aeon-eval/src/lib.rs` | Evaluation corpus, task, and evidence models |
| `crates/aeonil/src/lib.rs` | AeonIL data types and expression helpers |
| `crates/aeon/src/api.rs` | High-level session API |
| `crates/aeon/src/elf.rs` | ELF parsing and function discovery |
| `crates/aeon/src/lifter.rs` | ARM64 to AeonIL lifting |
| `crates/aeon/src/il.rs` | Compatibility re-export of `aeonil` |
| `crates/aeon/src/object_layout.rs` | Constructor object-layout recovery for pointer fields |
| `crates/aeon/src/components.rs` | ECS components for lifted facts |
| `crates/aeon/src/analysis.rs` | Datalog rules for CFG and reachability |
| `crates/aeon/src/rc4_search.rs` | Behavioral RC4 detection |
| `crates/aeon/src/engine.rs` | Session orchestration and analysis internals |
| `crates/aeon-frontend/src/service.rs` | Shared stateful tool dispatch |
| `crates/aeon-frontend/src/mcp.rs` | MCP frontend |
| `crates/aeon-frontend/src/http.rs` | HTTP frontend |

## Dependencies

- [bad64](https://crates.io/crates/bad64) - ARM64 instruction decoding
- [bevy_ecs](https://crates.io/crates/bevy_ecs) - entity-component storage
- [ascent](https://crates.io/crates/ascent) - Datalog engine
- [object](https://crates.io/crates/object) - ELF parsing
- [gimli](https://crates.io/crates/gimli) - DWARF and `.eh_frame` reading
