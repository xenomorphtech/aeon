# ARM64 Hash Function Tracing Example

This document demonstrates using the ARM64 Code Rewriter instrumentation framework to trace execution of complex hashing functions (SHA256, MD5, SipHash, etc.).

## Framework Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   ARM64 Rewriter Framework                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Phase 1: Core Rewriter                                         │
│  └─ Shadow memory allocation + PC redirection                  │
│                                                                 │
│ Phase 2: IL Storage (LLIL/MLIL/HLIL)                          │
│  └─ Instruction-level IL at multiple abstraction levels        │
│                                                                 │
│ Phase 3: Hook Engine                                           │
│  └─ Sandboxed execution context (isolated registers/memory)    │
│                                                                 │
│ Phase 4: Rust Scripting API                                   │
│  └─ High-level hooks: InstructionTracer, MemoryTracer, etc    │
│                                                                 │
│ Phase 5: AeonSession Integration                              │
│  └─ create_instrumentation() method for fluent configuration   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Example: SHA256 Hash Function Tracing

### Step 1: Load ARM64 Binary

```rust
use aeon::AeonSession;

let session = AeonSession::load("./hash_sha256_test")?;
println!("Binary loaded: {:#?}", session.summary());
```

### Step 2: Locate Hash Function

```rust
let functions = session.list_functions(0, 100, None);
// Find sha256_block function in the binary
let skeleton = session.get_function_skeleton(0x400d00)?;
println!("Function bounds: {}", skeleton["bounds"]);
```

### Step 3: Create Instrumentation

```rust
let instrumentation = session.create_instrumentation(0x400d00, 0x401000)?
    .with_instruction_trace()          // Log every instruction
    .with_memory_trace()                // Log memory access
    .with_register_trace(vec![
        "x0".to_string(),  // state array pointer
        "x1".to_string(),  // message block pointer
        "x2".to_string(),  // loop counters
        "x3".to_string(),  // temporary values
        "x4".to_string(),
        "x5".to_string(),
    ])
    .with_branch_trace()                // Log branches/calls
    .build();

println!("Instrumentation ready with {} hooks", instrumentation.hook_count());
```

### Step 4: Initialize Execution Context

```rust
use std::collections::BTreeMap;

let mut registers = BTreeMap::new();
registers.insert("x0".to_string(), 0x402000);  // state buffer address
registers.insert("x1".to_string(), 0x402100);  // message block address
registers.insert("x2".to_string(), 0);         // loop index
registers.insert("sp".to_string(), 0x700000);  // stack pointer

let (state, control_flow) = instrumentation.execute(0x400d00, registers);
println!("Execution completed: {:?}", control_flow);
println!("Final state: {:#?}", state);
```

## Trace Analysis

The framework provides insights at multiple levels:

### 1. Instruction-Level Tracing

```
Instruction @ 0x400d00: 9100a3ff (add sp, sp, #41)
  Before:  x0=0x402000, sp=0x700000
  After:   x0=0x402000, sp=0x700029
  Trace:   memory_write at 0x6ffffc (size=8)

Instruction @ 0x400d04: 390003e0 (strh w0, [sp])
  Before:  x0=0x402000, sp=0x700029
  After:   x0=0x402000, sp=0x700029
  Trace:   memory_write at 0x700029 (size=2, data=0x0000)
```

### 2. Memory Access Patterns

```
Memory Load  @ 0x400e20: addr=0x402000 size=8  (state[0])
Memory Load  @ 0x400e28: addr=0x402008 size=8  (state[1])
...
Memory Store @ 0x400f00: addr=0x402000 size=8  (state[0] += T1+T2)
Memory Store @ 0x400f08: addr=0x402008 size=8  (state[1] += ...)
```

### 3. Register State Evolution

```
Register x0: 0x402000 → 0x402008 → 0x402010 (pointer increment)
Register x2: 0x00000000 → 0x00000001 → 0x00000002 (loop counter)
Register x3: 0x6a09e667 → 0xbb67ae85 → 0x3c6ef372 (state values)
```

### 4. Control Flow Analysis

```
Branch @ 0x400f50 (loop):
  Target: 0x400d10 (branch back to loop start)
  Iteration count: 64 (expected for SHA256)

Indirect Call @ 0x401000 (function exit):
  Target: 0x7fffffe0 (return address)
```

## Use Cases

### 1. Reverse-Engineering Unknown Hash Functions

- Trace execution to understand input/output relationships
- Identify constants and lookup tables
- Map out state transformations
- Detect obfuscation patterns

### 2. Cryptographic Analysis

- Monitor key material handling
- Detect timing variations (cache effects)
- Track state mixing quality
- Identify side-channel vulnerabilities

### 3. Obfuscation Evasion

- Understand control flow flattening
- Trace through MBA (Mixed Boolean-Arithmetic) expressions
- Monitor dispatcher logic
- Extract original algorithm semantics

### 4. Performance Analysis

- Count instruction types executed
- Identify memory access hotspots
- Measure register pressure
- Profile branch prediction failures

## Integration with Binary Analysis

Combine tracing with static analysis:

```rust
// Get IL representations of traced instructions
let llil = session.get_il(0x400d00)?;      // Low-level IL
let mlil = session.get_reduced_il(0x400d00)?;  // Mid-level IL
let ssa = session.get_ssa(0x400d00, true)?;    // SSA form

// Execute trace
let (trace_state, _) = instrumentation.execute(0x400d00, registers);

// Compare static analysis with dynamic trace
// This reveals:
// - Which IL statements actually execute
// - Dead code and unreachable paths
// - Aliasing and pointer relationships
```

## Implementation Status

✅ **Complete**: 
- Core Rewriter (shadow memory, PC redirection)
- IL Storage (LLIL/MLIL/HLIL queries)
- Hook Engine (sandboxed contexts)
- Rust Scripting API (high-level hooks)
- AeonSession Integration

🚀 **Next Steps**:
- MCP tool exposure (web/REST API)
- Full execution with emulation (unicorn integration)
- Memory protection (mprotect on original code)
- Advanced: Symbolic execution over traces

## Files

- `crates/aeon/src/rewriter.rs` - Core shadow memory management
- `crates/aeon/src/il_store.rs` - IL caching and queries
- `crates/aeon/src/hook_engine.rs` - Hook execution engine
- `crates/aeon/src/instrumentation.rs` - High-level API
- `crates/aeon/src/api.rs` - AeonSession integration

## Test Binaries

Compiled ARM64 test binaries:
```bash
# SHA256 hash function (from samples/)
crates/aeon-jit/samples/hash_sha256_test

# Other available hash functions (to be compiled)
crates/aeon-jit/samples/hash_sha256_aarch64.c
crates/aeon-jit/samples/hash_md5_aarch64.c
crates/aeon-jit/samples/hash_siphash_aarch64.c
crates/aeon-jit/samples/hash_fnv1a_aarch64.c
crates/aeon-jit/samples/hash_crc32_aarch64.c
```

## Summary

The ARM64 Code Rewriter provides a complete instrumentation framework for tracing complex hash functions and other cryptographic code. The sandboxed hook context prevents register contamination while providing full visibility into:

- Instruction execution
- Memory access patterns
- Register state evolution
- Control flow behavior
- State transformations

This enables reverse-engineering, analysis, and optimization of ARM64 binaries without requiring native code execution or kernel-level instrumentation.
