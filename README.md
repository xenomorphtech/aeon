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
| `load_binary` | Load an ELF or raw AArch64 binary for analysis. Must be called before other tools. |
| `list_functions` | List functions discovered from .eh_frame unwind tables. Supports pagination and name filtering. |
| `set_analysis_name` | Backwards-compatible alias for rename_symbol. Attaches or overwrites a semantic symbol on an address. |
| `rename_symbol` | Attach or overwrite a semantic symbol name on an address. |
| `define_struct` | Attach or overwrite a structure definition on an address. |
| `add_hypothesis` | Record a semantic hypothesis on an address. Duplicate notes are ignored. |
| `search_analysis_names` | Search analysis names attached to addresses using a regex pattern. |
| `get_blackboard_entry` | Look up all semantic context recorded for an address: symbol name, struct definition, hypotheses, and containing function. Use to inspect what the blackboard knows about a specific address. |
| `get_il` | Get the lifted AeonIL intermediate language listing for the function containing a given address. |
| `get_function_il` | Backwards-compatible alias for get_il. |
| `get_reduced_il` | Return block-structured reduced AeonIL for the function containing a given address. |
| `get_ssa` | Return reduced SSA form for the function containing a given address, optionally optimized. |
| `get_stack_frame` | Summarize the detected stack frame and visible stack-slot accesses for the function containing a given address. |
| `get_function_cfg` | Get the Control Flow Graph for a function. Returns adjacency list, terminal blocks, and reachability from Datalog analysis. |
| `get_function_skeleton` | Get a dense summary of function properties for efficient triage: argument count, calls, strings, loops, crypto constants, stack frame size, and suspicious patterns. |
| `get_xrefs` | Get cross-references for an address: outgoing calls from the function, and incoming calls from other functions. |
| `scan_pointers` | Scan non-executable mapped sections for pointer-sized values that reference other locations in the binary, classifying data-to-data and data-to-code edges. |
| `scan_vtables` | Detect candidate C++ vtables in .rodata/.data-style sections by finding arrays of function pointers and grouping related tables. |
| `get_function_pointers` | Enumerate pointer-valued operands and resolved code/data references for one function or a paginated slice of functions. |
| `find_call_paths` | Find shortest and optionally all bounded call-graph paths between two functions using direct calls and vtable-resolved indirect calls. |
| `get_bytes` | Read raw bytes from the binary at a virtual address. Returns hex-encoded string. |
| `search_rc4` | Search for RC4 cipher implementations using Datalog behavioral subgraph isomorphism. Detects KSA (swap+256+mod256) and PRGA (swap+keystream XOR) patterns. |
| `get_coverage` | Get IL lift coverage statistics: proper IL vs intrinsic vs nop vs decode errors. |
| `get_asm` | Disassemble ARM64 instructions between two virtual addresses. Returns asm only, without AeonIL. |
| `get_function_at` | Find the function containing a given address. Returns function metadata by default, and can optionally attach asm and/or AeonIL listings. |
| `get_string` | Read a null-terminated string at any virtual address (works across all ELF segments, not just .text). |
| `get_data` | Read raw bytes at any virtual address (works across all ELF segments). Returns hex + ASCII. |
| `emulate_snippet` | Execute an ARM64 code region in a bounded sandbox. Returns final register state, memory writes, and any decoded strings. Use for reversing obfuscated loops, string decryption, or format decoders. |
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
