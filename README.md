# aeon

aeon is meant to be a sensory organ, reasoning sandbox, and execution environment for autonomous AI agents, without any bloat from human-aimed tooling.

In this repository, that idea is applied to ARM64 ELF analysis. The workspace provides a reusable Rust analysis core plus thin agent-facing frontends that load binaries, lift instructions into AeonIL, run Datalog analyses, and expose the results through strict JSON interfaces.

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
- **Raw memory inspection** - reads bytes, data regions, and null-terminated strings from virtual addresses
- **Agent-facing transport layers** - exposes the same session through CLI, MCP over stdio, and a stateful HTTP API

## Workspace Layout

- `crates/aeon` - reusable analysis library
- `crates/aeon-frontend` - CLI, MCP, and HTTP frontends
- `crates/survey` - standalone opcode survey utility

## Build

```bash
cargo build --release
```

This produces:

- `target/release/aeon`
- `target/release/aeon-mcp`
- `target/release/aeon-http`

## Interfaces

### CLI

The CLI is intentionally small and machine-friendly. It prints JSON and supports three direct modes:

```bash
# Search for RC4 implementations
aeon rc4 path/to/binary.so

# Report IL lift coverage
aeon coverage path/to/binary.so

# Inspect the function containing a specific address
aeon func path/to/binary.so 0x51203d0
```

### MCP Server

`aeon-mcp` exposes the analysis session as JSON-RPC 2.0 over stdio for agent runtimes that speak MCP.

The project root includes `.mcp.json` for local auto-discovery in Claude Code.

### HTTP API

`aeon-http` exposes the same stateful session over HTTP:

```bash
aeon-http 127.0.0.1:8787
```

Example calls:

```bash
curl -s http://127.0.0.1:8787/call \
  -H 'content-type: application/json' \
  -d '{"name":"load_binary","arguments":{"path":"libUnreal.so"}}'

curl -s http://127.0.0.1:8787/call \
  -H 'content-type: application/json' \
  -d '{"name":"get_function_at","arguments":{"addr":"0x51203d0"}}'
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
    let session = AeonSession::load("libUnreal.so")?;
    let functions = session.list_functions(0, 10, None);
    println!("{}", serde_json::to_string_pretty(&functions)?);
    Ok(())
}
```

Lower-level modules remain public for callers that want direct access to ELF parsing, lifting, IL types, engine internals, or RC4 search logic.

## Tool Surface

These tools are exposed by the MCP and HTTP frontends:

| Tool | Description |
|------|-------------|
| `load_binary` | Load an ELF binary for analysis |
| `list_functions` | Paginated function listing with optional name filter |
| `set_analysis_name` | Attach or overwrite an analysis name on an address |
| `search_analysis_names` | Regex search over assigned analysis names |
| `get_function_il` | Lift a function to AeonIL |
| `get_function_cfg` | Return CFG edges, terminal blocks, and reachability |
| `get_xrefs` | Return incoming and outgoing cross-references |
| `get_bytes` | Read raw bytes from a virtual address |
| `get_asm` | Disassemble an address range |
| `get_function_at` | Find the function containing a given address |
| `get_string` | Read a null-terminated string at an address |
| `get_data` | Read raw data across ELF segments |
| `get_coverage` | Report IL lift coverage statistics |
| `search_rc4` | Search for RC4 implementations via behavioral matching |

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
| `crates/aeon/src/api.rs` | High-level session API |
| `crates/aeon/src/elf.rs` | ELF parsing and function discovery |
| `crates/aeon/src/lifter.rs` | ARM64 to AeonIL lifting |
| `crates/aeon/src/il.rs` | AeonIL data types |
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
