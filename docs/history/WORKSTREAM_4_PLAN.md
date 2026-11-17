# Workstream 4: Active Experimentation — Implementation Plan

**Status**: Planning phase  
**Target**: Expose bounded code emulation to agents for reversing dynamic behavior  
**Date**: 2026-04-18

---

## Goal

Enable agents to execute small code regions in a controlled sandbox, eliminating the need to manually reverse obfuscated loops, string decryption, or format decoders. Instead of guessing, the agent specifies a memory snapshot and register state, executes the snippet, and inspects the results.

## Current State

### What Already Exists

1. **AeonIL Interpreter** (`crates/aeon/src/emulation.rs`)
   - `execute_block()`: Runs AeonIL statements with register/memory state, respects step budgets
   - `execute_snippet()`: Simpler variant for isolated code regions
   - Returns: final registers, touched memory, stop reason (budget, missing mem, etc.)
   - Supports: backing memory store, configurable memory policy (Stop vs ContinueAsUnknown)

2. **Binary Loading & Lifting** (`crates/aeon/src/`)
   - ELF ingestion, function discovery, AeonIL lifting
   - Address-to-IL translation ready

3. **Semantic Blackboard** (`crates/aeon/src/engine.rs`)
   - `rename_symbol()`, `define_struct()`, `add_hypothesis()`
   - Already exposed in MCP tools — agents can annotate as they discover

4. **JIT-Based Instrumentation** (`crates/aeon-instrument/`)
   - Dynamic CFG expansion, symbolic folding
   - Separate from static emulation; focus here is on static snippet execution

### What's Missing

1. **MCP Tool for Sandbox Execution**
   - No `emulate_snippet` exposed to agents
   - No memory initialization helpers
   - No register initialization from agent input
   - No standardized output format

2. **Integration Points**
   - AeonSession lacks emulation method
   - service.rs tool dispatch doesn't include emulation
   - mcp.rs has no corresponding MCP method

3. **Observable Outputs**
   - Current emulation returns raw Rust types; needs JSON-friendly format
   - Must surface: final registers, memory ranges touched, decoded strings/buffers, branch trace

---

## Architecture

### Execution Path

```
Agent (MCP) → emulate_snippet(start, end, init_regs, init_mem)
         ↓
AeonFrontend::tool_emulate_snippet(args)
         ↓
AeonSession::emulate_snippet(start, end, regs, mem) 
         ↓
Lifter (get IL for region) → emulation::execute_block()
         ↓
BlockExecutionResult (registers, memory, stop_reason, steps)
         ↓
Format as JSON → return to agent
```

### MCP Tool Signature

```json
{
  "name": "emulate_snippet",
  "description": "Execute a code snippet with bounded state in a sandbox. Useful for reversing obfuscated loops or dynamic decryption.",
  "arguments": {
    "type": "object",
    "properties": {
      "start_addr": {
        "type": "string",
        "description": "Hex address where execution begins, e.g. '0x1234'"
      },
      "end_addr": {
        "type": "string",
        "description": "Hex address where execution stops (exclusive), e.g. '0x1250'"
      },
      "initial_registers": {
        "type": "object",
        "description": "Register values at entry, e.g. {\"x0\": \"0x1000\", \"x1\": \"42\"}. Unspecified registers default to 0.",
        "additionalProperties": { "type": "string" }
      },
      "initial_memory": {
        "type": "object",
        "description": "Memory cells to pre-populate, e.g. {\"0x1000\": \"0x41424344\"} (8 bytes at 0x1000)",
        "additionalProperties": { "type": "string" }
      },
      "step_limit": {
        "type": "integer",
        "description": "Max IL statements to execute (default 1000). Prevents infinite loops.",
        "default": 1000
      },
      "missing_memory_policy": {
        "type": "string",
        "enum": ["stop", "continue_unknown"],
        "description": "Behavior when code reads uninitialized memory (default: 'stop')",
        "default": "stop"
      }
    },
    "required": ["start_addr", "end_addr"]
  }
}
```

### Response Format

```json
{
  "status": "completed",
  "start_addr": "0x1234",
  "end_addr": "0x1250",
  "steps_executed": 42,
  "stop_reason": "Completed",
  "final_registers": {
    "x0": "0x41424344",
    "x1": "0x1234",
    "pc": "0x1250"
  },
  "memory_writes": [
    {
      "addr": "0x2000",
      "size": 8,
      "value": "0x0102030405060708",
      "from_register": "x0"
    }
  ],
  "memory_reads": [
    {
      "addr": "0x1000",
      "size": 4,
      "value": "0x41424344",
      "missing": false
    }
  ],
  "decoded_strings": [
    {
      "addr": "0x2000",
      "bytes": "hello",
      "confidence": "nul_terminated"
    }
  ]
}
```

---

## Implementation Steps

### Phase 1: Core Emulation API (→ AeonSession)

**Files**: `crates/aeon/src/api.rs`

```rust
impl AeonSession {
    pub fn emulate_snippet(
        &self,
        start_addr: u64,
        end_addr: u64,
        initial_registers: HashMap<String, u64>,
        initial_memory: HashMap<u64, Vec<u8>>,
        step_limit: usize,
        missing_memory_policy: MissingMemoryPolicy,
    ) -> Result<Value, String> {
        // 1. Lift range [start_addr, end_addr) into AeonIL
        // 2. Build initial register map
        // 3. Build backing memory store from binary + overlays
        // 4. Call emulation::execute_block()
        // 5. Format and return JSON result
    }
}
```

**Subtasks**:
- [ ] Extend lifter to handle address ranges (not just whole functions)
- [ ] Implement `BinaryBackingStore` that wraps LoadedBinary
- [ ] Convert string hex args (x0, x1, etc.) to aeonil::Reg
- [ ] Build initial_registers BTreeMap<Reg, Value> from agent input
- [ ] Extract decoded strings from final memory state

### Phase 2: Service Layer Integration

**Files**: `crates/aeon-frontend/src/service.rs`

```rust
impl AeonFrontend {
    fn tool_emulate_snippet(&self, args: &Value) -> Result<Value, String> {
        let session = self.require_session()?;
        
        // Parse arguments
        let start_addr = parse_hex_arg(args, "start_addr")?;
        let end_addr = parse_hex_arg(args, "end_addr")?;
        let initial_registers = parse_register_map(args)?;
        let initial_memory = parse_memory_map(args)?;
        let step_limit = parse_usize_arg(args, "step_limit", 1000)?;
        let missing_policy = parse_missing_policy(args)?;
        
        session.emulate_snippet(
            start_addr, end_addr,
            initial_registers, initial_memory,
            step_limit, missing_policy,
        )
    }
}
```

**Subtasks**:
- [ ] Add tool to `call_tool()` dispatcher
- [ ] Write argument parsers for hex addresses, register maps, memory maps
- [ ] Error messages guide agent (e.g., "register x99 not found")
- [ ] Add to tools_list() description

### Phase 3: MCP Tool Binding

**Files**: `crates/aeon-frontend/src/service.rs` (tools_list function)

Add to the tools JSON list:

```rust
{
    "name": "emulate_snippet",
    "description": "Execute a code snippet with initial register/memory state in a bounded sandbox. Returns final state and memory accesses.",
    "inputSchema": { ... }  // as defined above
}
```

**Subtasks**:
- [ ] Add JSON schema for arguments
- [ ] Add to tools_list()
- [ ] Document in README

### Phase 4: Testing & Documentation

**Files**: 
- `crates/aeon/tests/emulation_integration.rs` (new)
- `crates/aeon-frontend/src/service.rs` (add test)

**Test Cases**:
- [ ] Simple arithmetic loop (init x0=100, decrement, check result)
- [ ] Memory read/write cycle (write to x0, read back, verify)
- [ ] String decryption mock (XOR loop, extract final buffer)
- [ ] Missing memory handling (agent initializes partial state, emulator extends)
- [ ] Step budget enforcement (infinite loop terminates cleanly)
- [ ] Register aliasing (x0 vs x0 lower bits)

**Subtasks**:
- [ ] Use `samples/hello_aarch64.elf` or create minimal test binary
- [ ] Golden outputs for reproducibility
- [ ] Document emulation limits and assumptions

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Lifting errors for invalid address range | Tool fails, agent blocked | Graceful error: "addr 0x1234–0x1250 not fully lifted: missing block at 0x1240" |
| Agent initializes contradictory state | Nonsensical results | Validate: no overlaps in memory_map, warn if initial_registers out of range |
| Unbounded allocation if agent copies huge binary | OOM | Cap initial_memory size (e.g., 10 MB), document in schema |
| Symbolic operations unhandled | Silent wrong result | Execute_block already handles (stops at SymbolicBranch); surface in stop_reason |
| Register name typos (x40 instead of x0) | Silent failure | Case-insensitive parsing, prefix with "q/x/w/b" for width, reject invalid names |

---

## Success Criteria

1. ✓ Agent can pass code address + register state to emulate_snippet
2. ✓ Sandbox executes deterministically; same input → same output
3. ✓ Agent receives: final register state, memory ranges touched, decoded strings
4. ✓ Handles obfuscated loop: agent initializes buffer, runs snippet, extracts decrypted result
5. ✓ Step limits prevent hangs; agent can probe with smaller budgets
6. ✓ MCP tool documented and in tools_list()

---

## Integration with Broader Roadmap

- **Workstream 1 (Token-Efficient Topology)**: Emulation results feed back as evidence; agent uses function skeleton to decide _whether_ to emulate
- **Workstream 2 (Datalog)**: Agent can run Datalog queries to find _where_ to emulate (e.g., "find all string decryption loops")
- **Workstream 3 (Blackboard)**: Agents annotate discovered functions as "string_decryption_loop"; emulation results update hypothesis state
- **Workstream 5 (Swarm)**: Specialized "Tracer" role can orchestrate emulation over high-value snippets in parallel

---

## Non-Goals

- Live process injection (that's aeon-instrument's role with Frida/JIT)
- Symbolic execution (out of scope; emulation is concrete)
- Scripting sandbox security (assume agent is trusted)
- Performance profiling (scope is correctness, not speed)

---

## Milestones

1. **Week 1**: Implement Phase 1 & 2 (AeonSession + service layer)
2. **Week 2**: Phase 3 & 4 (MCP binding, tests, docs)
3. **Week 3**: Agent integration test (CLI agent successfully uses emulate_snippet on real binary)
