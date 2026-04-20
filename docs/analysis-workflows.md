# Aeon Analysis Workflows Guide

This guide demonstrates how to use aeon's MCP tools to solve common reverse engineering and binary analysis tasks. All examples leverage the improved tool descriptions from the BFCL+ToolACE quality optimization.

## Table of Contents

1. [Quick-Start: Basic Function Analysis](#quick-start-basic-function-analysis)
2. [Vulnerability Hunting Workflow](#vulnerability-hunting-workflow)
3. [Crypto Detection and Analysis](#crypto-detection-and-analysis)
4. [Data Structure Recovery](#data-structure-recovery)
5. [Call Graph and Control Flow Analysis](#call-graph-and-control-flow-analysis)
6. [Obfuscation Detection](#obfuscation-detection)
7. [Integration: Multi-Tool Workflows](#integration-multi-tool-workflows)

---

## Quick-Start: Basic Function Analysis

**Goal:** Understand what a function does.

**Tools Used:** `load_binary` → `list_functions` → `get_function_skeleton` → `get_il` / `get_ssa`

### Step-by-Step

```
1. load_binary("path/to/binary", format="elf")
   └─ Returns: binary metadata, entry point, section info

2. list_functions(limit=10)
   └─ Returns: First 10 function addresses and names
   └─ Use pagination (offset/limit) for large binaries

3. get_function_skeleton(addr="0x401234")
   └─ Returns: argument count, calls, loops, crypto patterns
   └─ Quick assessment: is this cryptography, networking, or business logic?

4a. get_il(addr="0x401234")
    └─ For detailed instruction-by-instruction analysis
    └─ When you need to understand semantics

4b. get_ssa(addr="0x401234", optimize=true)
    └─ For data flow analysis
    └─ Better for tracking variable definitions and uses
```

### Example Output Interpretation

```
get_function_skeleton output:
{
  "arg_count": 2,
  "calls": ["malloc", "memcpy"],
  "loops": 1,
  "crypto_patterns": ["AES", "SHA256"],
  "stack_usage": 256
}
→ Interpretation: 2-argument function, allocates memory, has loop,
  contains cryptographic operations, large stack usage.
```

---

## Vulnerability Hunting Workflow

**Goal:** Identify potential security issues in a binary.

**Tools Used:** `get_function_skeleton` → `get_xrefs` → `find_call_paths` → `get_il`

### Systematic Approach

```
Phase 1: Surface-Level Triage
  ├─ list_functions(limit=100) to enumerate all functions
  ├─ get_function_skeleton() for each to identify suspicious patterns
  │  └─ Look for: malloc, strcpy, sprintf, system, execve
  └─ Annotate suspicious functions with set_analysis_name("potentially_vulnerable")

Phase 2: Data Flow Analysis
  ├─ get_xrefs(addr="<suspicious_function>")
  │  └─ Who calls this function? What data reaches it?
  ├─ find_call_paths(start="entry_point", goal="<vulnerable_function>")
  │  └─ How can we reach this vulnerability?
  └─ Add hypotheses with add_hypothesis(addr="...", note="buffer_overflow_if_x > 256")

Phase 3: Deep Dive
  ├─ get_il(addr="<vulnerable_function>") for instruction analysis
  ├─ get_data_flow_slice(addr="<instruction>", register="x0", direction="backward")
  │  └─ Where does the vulnerable data come from?
  └─ Verify with emulate_snippet_native() if necessary
```

### Example: Finding strcpy Vulnerabilities

```
1. search_analysis_names(pattern=".*strcpy.*")
   └─ Returns: All strcpy calls annotated in prior analysis

2. For each result:
   get_xrefs(addr="<strcpy_location>")
   └─ Who calls strcpy? With what buffer?

3. find_call_paths(start="untrusted_input_handler", goal="<strcpy>")
   └─ Is strcpy reachable from user input?

4. get_il(addr="<strcpy>")
   └─ Check buffer size vs input validation
```

---

## Crypto Detection and Analysis

**Goal:** Identify cryptographic operations and understand their implementation.

**Tools Used:** `search_rc4` → `scan_pointers` → `get_function_pointers` → `get_il`

### Crypto Search Strategy

```
Phase 1: Algorithm Detection
  ├─ search_rc4()
  │  └─ Returns: function addresses with RC4 behavioral patterns
  │  └─ Limitation: May match similar XOR/shift patterns
  ├─ search_analysis_names(pattern="^crypto_.*")
  │  └─ Find all previously-annotated crypto functions
  └─ scan_pointers()
      └─ Locate constant tables (S-boxes, round constants, etc.)

Phase 2: Implementation Analysis
  ├─ For each detected crypto function:
  │  ├─ get_function_skeleton() to identify algorithm family
  │  ├─ get_coverage() to assess IL lift quality
  │  │  └─ >95%: Use IL analysis; <85%: May be obfuscated
  │  └─ get_il(addr="<crypto_func>")
  └─ Annotate with set_analysis_name("AES_encrypt_impl")

Phase 3: Key Management
  ├─ get_data_flow_slice() backward from crypto function entry
  │  └─ Where do keys/IVs come from?
  ├─ scan_pointers() to find embedded keys in data sections
  └─ define_struct(addr="<key_location>", definition="{u8 key[32]}")
```

### Example: Analyzing AES Implementation

```
1. search_rc4() → No matches
2. get_coverage() on suspected AES function → 94% lifted
3. get_il(addr="0x401000")
   └─ Look for characteristic patterns:
      - SubBytes operations
      - MixColumns matrix multiplications
      - Round constants (0x01020408...)

4. Define structure at S-box location:
   define_struct(addr="0x402000", definition="{u8 sbox[256]}")

5. add_hypothesis(addr="0x401000", note="AES_ECB_128_encrypt")
```

---

## Data Structure Recovery

**Goal:** Understand how data is organized and used.

**Tools Used:** `get_data` → `scan_pointers` → `define_struct` → `get_xrefs`

### Data Recovery Process

```
Phase 1: Locate Structures
  ├─ get_data(addr="<suspected_data_location>", size=256)
  │  └─ Inspect raw bytes and ASCII representation
  ├─ scan_pointers()
  │  └─ Find embedded code/data pointers (vtables, callbacks)
  └─ get_function_pointers(addr="<function>")
      └─ What pointers does this function use?

Phase 2: Define Layout
  ├─ Identify field boundaries from instruction patterns
  ├─ define_struct(addr="<struct_location>", definition="{
  │     uint32_t magic;
  │     uint16_t version;
  │     uint8_t reserved[6];
  │     void (*handler)(void);
  │   }")
  └─ Annotate fields with set_analysis_name() for each significant offset

Phase 3: Usage Analysis
  ├─ get_xrefs(addr="<struct_location>")
  │  └─ Who references this structure?
  ├─ get_data_flow_slice() backward to find initialization
  └─ emulate_snippet_native() to trace structure population
```

### Example: Recovering a Command Table

```
1. scan_pointers() finds array of function pointers at 0x403000
2. get_data(addr="0x403000", size=128) shows:
   0x403000: 0x401100 0x401200 0x401300 ...

3. define_struct(addr="0x403000", definition="{
     void (*handler[8])(void);
   }")

4. For each handler:
   get_function_at(addr="0x401100") → understand its purpose
   set_analysis_name(addr="0x403000", name="cmd_table")

5. find_call_paths(start="main", goal="0x403000")
   └─ How is this table used?
```

---

## Call Graph and Control Flow Analysis

**Goal:** Understand program structure and execution paths.

**Tools Used:** `get_xrefs` → `find_call_paths` → `get_function_cfg` → `execute_datalog`

### Call Graph Analysis

```
Phase 1: Direct Call Graph
  ├─ get_xrefs(addr="<function>")
  │  └─ Returns: callers and callees
  └─ Recursively for all discovered functions → full call graph

Phase 2: Control Flow
  ├─ get_function_cfg(addr="<function>")
  │  └─ Returns: basic blocks and edges
  │  └─ Use to identify loops and dominators
  └─ For obfuscated code, get_coverage() reveals lift quality
      └─ Low coverage (<85%) suggests control flow flattening

Phase 3: Reachability Analysis
  ├─ execute_datalog(query="call_graph_transitive", addr="<entry>")
  │  └─ All functions reachable from entry point
  ├─ find_call_paths(start="untrusted_input", goal="<critical_func>")
  │  └─ Can attacker reach sensitive functions?
  └─ find_call_paths() with include_all_paths=true
      └─ Find all exploitation paths
```

### Example: Attack Surface Analysis

```
1. find_call_paths(
     start="handle_network_request",
     goal="execute_command",
     include_all_paths=true
   )
   └─ Returns: All paths from network to command execution

2. For each path:
   get_il(addr="<branching_point>")
   └─ What conditions must be met?

3. Add hypotheses:
   add_hypothesis(addr="<path[0]>", note="authentication_bypass_if_x == 0")
```

---

## Obfuscation Detection

**Goal:** Identify and analyze obfuscated code.

**Tools Used:** `get_coverage` → `get_function_cfg` → `emulate_snippet_il`

### Obfuscation Indicators

```
Phase 1: Quality Assessment
  ├─ get_coverage()
  │  └─ <85% lifted: Heavy obfuscation or unsupported instructions
  ├─ get_function_skeleton()
  │  └─ High instruction count relative to functionality?
  └─ get_function_cfg()
      └─ Excessive branching? Complex dominance?

Phase 2: Analysis Strategy
  ├─ If IL lift quality is low:
  │  ├─ get_asm() for raw assembly inspection
  │  └─ emulate_snippet_native() to observe behavior
  ├─ If control flow is flattened:
  │  ├─ emulate_snippet_il() to trace execution
  │  └─ Look for dispatch table patterns
  └─ If constant arithmetic is obfuscated:
      ├─ emulate_snippet_native() with symbolic execution
      └─ Use execute_datalog(query="defines") to track constant origins

Phase 3: Deobfuscation
  ├─ Annotate patterns: set_analysis_name("MBA_obfuscation")
  ├─ Document transformations: add_hypothesis()
  └─ Create simplified pseudocode in comments
```

### Example: MBA (Mixed Boolean-Arithmetic) Analysis

```
1. Identify suspicious constant chains:
   get_il(addr="0x401000") → Look for (x ^ y) + ((x & y) << 1)

2. Emulate to compute actual values:
   emulate_snippet_native(
     start_addr="0x401000",
     initial_registers={"x0": "0x12345678"}
   )

3. Pattern match against known obfuscator outputs:
   add_hypothesis(addr="0x401000", note="OLLVM_MBA_likely")

4. Trace to find true logic:
   get_data_flow_slice(
     addr="0x401234",
     register="x0",
     direction="backward"
   )
```

---

## Integration: Multi-Tool Workflows

### Complete Analysis Pipeline

```
Vulnerability Research Workflow:
  1. load_binary() & list_functions()
  2. get_function_skeleton() for all functions
  3. Annotate with set_analysis_name() based on patterns
  4. search_analysis_names() to find related functions
  5. get_xrefs() to map callers
  6. find_call_paths() to trace untrusted input
  7. get_il() for detailed analysis
  8. execute_datalog(query="flows_to") for data tracking
  9. add_hypothesis() for findings
  10. emulate_snippet_native() for validation

Crypto Analysis Workflow:
  1. search_rc4() & search_analysis_names()
  2. get_function_skeleton() to classify algorithms
  3. get_coverage() to assess lift quality
  4. get_il() or get_asm() based on quality
  5. scan_pointers() for constant tables
  6. define_struct() for round constants, keys
  7. get_data_flow_slice() for key management
  8. execute_datalog(query="reachability") for key usage
```

---

## Best Practices

### Performance Tips
- Use `get_function_skeleton()` for initial triage before `get_il()`
- Use `offset/limit` in `list_functions()` for large binaries
- Use `execute_datalog(limit=500)` initially, increase if needed
- Cache results from expensive operations like `find_call_paths(include_all_paths=true)`

### Annotation Strategy
- Use consistent naming: `crypto_*`, `vulnerability_*`, `obfuscated_*`
- Use `add_hypothesis()` to document reasoning
- Use `define_struct()` to record data layout findings
- Use `search_analysis_names()` to find related results

### Workflow Organization
- Create workflows for common tasks (vuln hunting, crypto analysis)
- Batch similar operations (analyze all functions with pattern X)
- Document findings incrementally with hypotheses
- Use `get_blackboard_entry()` to review accumulated knowledge

---

## Common Patterns & Recipes

### Pattern: Find All Memory Allocations
```
1. list_functions()
2. For each: get_xrefs() looking for calls to malloc
3. Annotate: set_analysis_name("allocation_site")
4. Query: search_analysis_names("allocation_site")
5. Analyze: get_data_flow_slice() backward from each
```

### Pattern: Trace Data Flow from Input
```
1. Identify input function (read, recv, scanf)
2. find_call_paths(start="input_handler", goal="vulnerable_sink")
3. For each path: get_il() to understand transformations
4. Use execute_datalog(query="flows_to") to track specific registers
5. Emulate: emulate_snippet_native() to verify assumptions
```

### Pattern: Identify Vtables and Dispatch
```
1. scan_vtables() to find method tables
2. get_data() at vtable locations
3. define_struct() for each vtable
4. scan_pointers() to find references to vtables
5. find_call_paths() to trace indirect calls
```

---

## Troubleshooting

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| IL lift incomplete (60%) | SIMD or special instructions | Use `get_asm()` for assembly, `emulate_snippet_native()` for behavior |
| Control flow too complex | Obfuscation or legitimate complexity | Use `execute_datalog(query="reachability")` to simplify |
| Can't find expected function | Not in .eh_frame | Use `get_asm()` to scan for entry patterns or `get_function_pointers()` |
| Symbol names missing | Stripped binary | Use `set_analysis_name()` to annotate, `search_analysis_names()` to find patterns |
| Call graph incomplete | Indirect calls via pointers | Use `scan_pointers()`, `get_function_pointers()`, check vtables |

---

## Summary

Aeon's MCP tools work best in combination:
- **Triage**: Use `get_function_skeleton()` first
- **Map**: Use `get_xrefs()` and `find_call_paths()` to understand structure
- **Analyze**: Use `get_il()` or `get_ssa()` for detail
- **Verify**: Use `emulate_snippet_native()` to confirm behavior
- **Document**: Use `set_analysis_name()`, `add_hypothesis()`, `define_struct()`

Leverage the improved tool descriptions to understand parameters, limitations, and typical use cases for each tool.
