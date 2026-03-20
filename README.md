# aeon

Reverse engineering toolkit for ARM64 ELF binaries. Lifts machine code to a typed intermediate language, runs Datalog-based semantic analysis, and exposes everything through an MCP server for AI-agent-driven workflows.

## Features

- **ARM64 lifter** — Decodes and lifts ARM64 instructions to AeonIL, a BNIL-style intermediate representation covering data movement, arithmetic, logic, branches, FP, SIMD, and memory operations
- **ECS architecture** — Instructions are entities with components (address, raw asm, lifted IL, CFG edges, function membership) managed by `bevy_ecs`
- **Datalog analysis** — Uses `ascent` to compute control flow graphs, reachability, terminal blocks, and cross-references via declarative rules
- **RC4 behavioral search** — Detects RC4 KSA and PRGA patterns through dataflow analysis and structural matching—no signatures, purely behavioral
- **MCP server** — JSON-RPC 2.0 over stdio, integrates directly with Claude Code for interactive binary analysis
- **Coverage metrics** — Reports what percentage of instructions lift to proper IL vs. intrinsic fallbacks vs. decode errors

## Building

```
cargo build --release
```

Produces two binaries:
- `target/release/aeon` — CLI tool
- `target/release/aeon-mcp` — MCP server

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

### MCP server

The MCP server exposes these tools over JSON-RPC 2.0 on stdio:

| Tool | Description |
|------|-------------|
| `load_binary` | Load an ELF binary for analysis |
| `list_functions` | Paginated function listing with optional name filter |
| `get_function_il` | Lift a function to AeonIL |
| `get_function_cfg` | CFG edges, terminal blocks, reachability |
| `get_xrefs` | Cross-references to/from a function |
| `get_asm` | Disassemble a virtual address range |
| `get_bytes` | Read raw bytes (hex + ASCII) |
| `get_coverage` | IL coverage statistics |
| `search_rc4` | Behavioral RC4 detection across all functions |

To use with Claude Code, the `.mcp.json` in the project root configures auto-discovery.

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
| `src/elf.rs` | ELF parsing, .eh_frame function discovery |
| `src/lifter.rs` | ARM64 → AeonIL instruction lifting |
| `src/il.rs` | AeonIL type definitions (Expr, Stmt, Register) |
| `src/components.rs` | ECS components (Address, LiftedIL, CfgEdges) |
| `src/analysis.rs` | Datalog rules for CFG and reachability |
| `src/rc4_search.rs` | Behavioral RC4 pattern detection |
| `src/engine.rs` | Orchestrates loading, lifting, and analysis |
| `src/mcp.rs` | MCP JSON-RPC server |

## Dependencies

- [bad64](https://crates.io/crates/bad64) — ARM64 instruction decoding
- [bevy_ecs](https://crates.io/crates/bevy_ecs) — Entity Component System
- [ascent](https://crates.io/crates/ascent) — Datalog engine
- [object](https://crates.io/crates/object) — ELF parsing
- [gimli](https://crates.io/crates/gimli) — DWARF / .eh_frame unwind tables
