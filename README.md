# aeon

Reverse engineering toolkit for ARM64 ELF binaries. The repository is split into a reusable library crate for analysis and a separate frontend crate for the CLI, MCP server, and a stateful HTTP testing API.

## Features

- **ARM64 lifter** — Decodes and lifts ARM64 instructions to AeonIL, a BNIL-style intermediate representation covering data movement, arithmetic, logic, branches, FP, SIMD, and memory operations
- **ECS architecture** — Instructions are entities with components (address, raw asm, lifted IL, CFG edges, function membership) managed by `bevy_ecs`
- **Datalog analysis** — Uses `ascent` to compute control flow graphs, reachability, terminal blocks, and cross-references via declarative rules
- **RC4 behavioral search** — Detects RC4 KSA and PRGA patterns through dataflow analysis and structural matching—no signatures, purely behavioral
- **MCP server** — JSON-RPC 2.0 over stdio, integrates directly with Claude Code for interactive binary analysis
- **Coverage metrics** — Reports what percentage of instructions lift to proper IL vs. intrinsic fallbacks vs. decode errors

## Workspace Layout

- `crates/aeon` — reusable analysis library
- `crates/aeon-frontend` — CLI, MCP, and HTTP frontends
- `crates/survey` — standalone opcode survey utility

## Building

```
cargo build --release
```

Produces three binaries:
- `target/release/aeon` — CLI tool
- `target/release/aeon-mcp` — MCP server
- `target/release/aeon-http` — stateful HTTP JSON API for testing

## Usage

### CLI

```bash
# Search for RC4 implementations (default mode)
aeon rc4 path/to/binary.so

# Report IL lift coverage
aeon coverage path/to/binary.so

# Analyze a specific function
aeon func path/to/binary.so 0x51203d0
```

### Library

Point a custom Rust tool at the library crate:

```toml
[dependencies]
aeon = { path = "/path/to/aeon/crates/aeon" }
serde_json = "1.0"
```

Then load a binary through the high-level session API:

```rust
use aeon::AeonSession;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = AeonSession::load("libUnreal.so")?;
    let functions = session.list_functions(0, 10, None);
    println!("{}", serde_json::to_string_pretty(&functions)?);
    Ok(())
}
```

The lower-level modules remain public under the library crate, including `elf`, `lifter`, `il`, `engine`, and `rc4_search`, so custom tools can bypass the JSON-style session helpers when they need more control.

### MCP server

The MCP server exposes these tools over JSON-RPC 2.0 on stdio:

| Tool | Description |
|------|-------------|
| `load_binary` | Load an ELF binary for analysis |
| `list_functions` | Paginated function listing with optional name filter |
| `set_analysis_name` | Attach an analysis name to an address |
| `search_analysis_names` | Regex search over assigned analysis names |
| `get_function_il` | Lift a function to AeonIL |
| `get_function_cfg` | CFG edges, terminal blocks, reachability |
| `get_xrefs` | Cross-references to/from a function |
| `get_asm` | Disassemble a virtual address range |
| `get_bytes` | Read raw bytes (hex + ASCII) |
| `get_coverage` | IL coverage statistics |
| `search_rc4` | Behavioral RC4 detection across all functions |

To use with Claude Code, the `.mcp.json` in the project root configures auto-discovery.

### HTTP testing API

Start the stateful HTTP frontend:

```bash
aeon-http 127.0.0.1:8787
```

Then send JSON tool calls directly over HTTP:

```bash
curl -s http://127.0.0.1:8787/call \
  -H 'content-type: application/json' \
  -d '{"name":"load_binary","arguments":{"path":"libUnreal.so"}}'

curl -s http://127.0.0.1:8787/call \
  -H 'content-type: application/json' \
  -d '{"name":"search_analysis_names","arguments":{"pattern":"^rc4"}}'
```

Useful endpoints:

- `GET /health` — current loaded/unloaded state
- `GET /tools` — available tool schemas
- `POST /call` — execute a stateful tool call with `{ "name": "...", "arguments": { ... } }`

## Architecture

```
ELF binary
  → bad64 (ARM64 decode)
    → lifter (AeonIL)
      → bevy_ecs (instruction store)
        → ascent (Datalog analysis)
          → MCP server / CLI output
```

### Key modules

| File | Purpose |
|------|---------|
| `crates/aeon/src/api.rs` | High-level library session API for custom tooling |
| `crates/aeon/src/elf.rs` | ELF parsing, .eh_frame function discovery |
| `crates/aeon/src/lifter.rs` | ARM64 → AeonIL instruction lifting |
| `crates/aeon/src/il.rs` | AeonIL type definitions (Expr, Stmt, Register) |
| `crates/aeon/src/components.rs` | ECS components (Address, LiftedIL, CfgEdges) |
| `crates/aeon/src/analysis.rs` | Datalog rules for CFG and reachability |
| `crates/aeon/src/rc4_search.rs` | Behavioral RC4 pattern detection |
| `crates/aeon/src/engine.rs` | Orchestrates loading, lifting, and analysis internals |
| `crates/aeon-frontend/src/service.rs` | Shared stateful tool/session dispatch for all frontends |
| `crates/aeon-frontend/src/mcp.rs` | MCP JSON-RPC frontend |
| `crates/aeon-frontend/src/http.rs` | Stateful HTTP JSON API for testing |

## Dependencies

- [bad64](https://crates.io/crates/bad64) — ARM64 instruction decoding
- [bevy_ecs](https://crates.io/crates/bevy_ecs) — Entity Component System
- [ascent](https://crates.io/crates/ascent) — Datalog engine
- [object](https://crates.io/crates/object) — ELF parsing
- [gimli](https://crates.io/crates/gimli) — DWARF / .eh_frame unwind tables
