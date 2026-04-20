# Aeon MCP Tools - Quick Reference Guide

## Tool Categories & Common Patterns

### Binary Loading & Exploration
| Goal | Tools | Example |
|------|-------|---------|
| Load binary | `load_binary` | `load_binary(path="app.elf")` |
| List functions | `list_functions` | `list_functions(offset=0, limit=100)` |
| Find function | `get_function_at` | `get_function_at(addr="0x401234")` |
| Quick analysis | `get_function_skeleton` | `get_function_skeleton(addr="0x401234")` |

### Code Analysis
| Goal | Tools | Example |
|------|-------|---------|
| View IL | `get_il` | `get_il(addr="0x401234")` |
| View assembly | `get_asm` | `get_asm(start_addr="0x401234", stop_addr="0x401300")` |
| View control flow | `get_function_cfg` | `get_function_cfg(addr="0x401234")` |
| View reduced IL | `get_reduced_il` | `get_reduced_il(addr="0x401234")` |
| Data flow analysis | `get_data_flow_slice` | `get_data_flow_slice(addr="0x401234", register="x0", direction="backward")` |

### Cross-References & Call Graphs
| Goal | Tools | Example |
|------|-------|---------|
| Find callers/callees | `get_xrefs` | `get_xrefs(addr="0x401234")` |
| Find call paths | `find_call_paths` | `find_call_paths(start_addr="0x401000", goal_addr="0x402000")` |
| Reachability analysis | `execute_datalog` | `execute_datalog(query="reachability", addr="0x401000")` |
| Find all calls to function | `get_xrefs` + filter | `get_xrefs(addr="0x401234")` → look for incoming |

### Data & Constants
| Goal | Tools | Example |
|------|-------|---------|
| Read bytes | `get_bytes` | `get_bytes(addr="0x402000", size=64)` |
| Read data section | `get_data` | `get_data(addr="0x402000", size=256)` |
| Read string | `get_string` | `get_string(addr="0x402100")` |
| Scan pointers | `scan_pointers` | `scan_pointers()` |
| Find S-boxes/constants | `scan_pointers` + `get_data` | `scan_pointers()` → filter for patterns |

### Annotation & Documentation
| Goal | Tools | Example |
|------|-------|---------|
| Name a function | `set_analysis_name` | `set_analysis_name(addr="0x401234", name="crypto_init")` |
| Define structure | `define_struct` | `define_struct(addr="0x402000", definition="{u32 magic; u32 size;}")` |
| Add note | `add_hypothesis` | `add_hypothesis(addr="0x401234", note="likely_integer_overflow")` |
| Search annotations | `search_analysis_names` | `search_analysis_names(pattern="^crypto_.*")` |
| View all annotations | `get_blackboard_entry` | `get_blackboard_entry(addr="0x401234")` |

### Emulation & Execution
| Goal | Tools | Example |
|------|-------|---------|
| Run IL interpreter | `emulate_snippet_il` | `emulate_snippet_il(start_addr="0x401234", end_addr="0x401300", initial_registers={"x0": "0x1000"}, step_limit=100)` |
| Run native emulation | `emulate_snippet_native` | `emulate_snippet_native(start_addr="0x401234", end_addr="0x401300", initial_registers={"x0": "0x1000"}, initial_memory={}, step_limit=100)` |
| Advanced emulation | `emulate_snippet_native_advanced` | `emulate_snippet_native_advanced(start_addr="0x401234", end_addr="0x401300", watchpoints=[...], address_hooks=[...])` |

### Specialized Detection
| Goal | Tools | Example |
|------|-------|---------|
| Find RC4 | `search_rc4` | `search_rc4()` |
| Find vtables | `scan_vtables` | `scan_vtables()` |
| Pointer enumeration | `get_function_pointers` | `get_function_pointers()` or `get_function_pointers(addr="0x401234")` |
| Coverage check | `get_coverage` | `get_coverage()` |

---

## Common Workflows (Copy-Paste Ready)

### Find All Crypto Functions
```
1. search_rc4()  # RC4 implementations
2. scan_pointers() AND scan_vtables()  # S-boxes, vtables
3. list_functions() → for each:
   get_function_skeleton() → look for "crypto_patterns" field
4. search_analysis_names("^crypto_")  # Prior findings
```

### Trace Data from Input to Sensitive Operation
```
1. find_call_paths(start="read_from_network", goal="decrypt_data")
2. For each address in path:
   get_il() → identify transformations
3. Result: Complete data transformation chain
```

### Analyze Obfuscated Loop
```
1. get_function_skeleton() → confirm loop exists
2. get_coverage() → assess IL lift quality
3. If >95% IL: use get_il() for instruction-level analysis
4. If <85% IL: use get_asm() then emulate_snippet_native()
5. emulate_snippet_native() with test inputs → observe behavior
6. add_hypothesis() with findings
```

### Build Command Handler Table
```
1. scan_pointers() → find arrays of function pointers
2. For each candidate vtable:
   get_data() → extract pointer values
3. define_struct() → document table layout
4. For each entry:
   get_function_at() → analyze handler
   set_analysis_name("cmd_<id>_handler")
```

### Reverse Protocol Message Format
```
1. find_call_paths(start="recv", goal="parse_function")
2. get_il() on parse_function → look for buffer offsets
3. Hardcoded offsets = field boundaries
4. define_struct() with discovered layout
5. emulate_snippet_native() with test messages → validate
```

### Find Integer Overflows
```
1. list_functions() → for each:
   get_il() → look for arithmetic operations
2. Candidates: multiplication before size check
3. emulate_snippet_native() with max values → check for truncation
4. get_xrefs() → verify vulnerability is reachable from input
```

### Map Call Graph Dependencies
```
1. execute_datalog(query="call_graph_transitive", addr="main")
2. Returns: all functions reachable from main
3. find_call_paths() → specific paths between functions
4. get_function_cfg() → for each function, understand structure
5. Result: Complete dependency map
```

---

## Debugging Tips

| Problem | Cause | Solution |
|---------|-------|----------|
| IL coverage <85% | SIMD, special instructions, obfuscation | Use `get_asm()` instead, try `emulate_snippet_native()` |
| Function not found | Not in .eh_frame | Use `get_asm()` to find entry patterns, or `get_function_pointers()` |
| Wrong call path | Indirect calls through vtables | Use `scan_pointers()` + `scan_vtables()` to find dispatch |
| Emulation stops early | Step limit reached | Increase `step_limit`, verify address range is correct |
| Emulation wrong output | Missing memory or wrong registers | Check `initial_memory` and register initialization |
| Data flow incomplete | Indirect data flow | Use `execute_datalog(query="flows_to")` for more details |

---

## Tool Aliases

**These tools are equivalent** (use primary form):

| Primary | Alias | Status |
|---------|-------|--------|
| `get_il` | `get_function_il` | Both work (alias for compatibility) |
| `emulate_snippet_native` | `emulate_snippet` | Both work (alias for compatibility) |

---

## Performance Tips

- Use `get_function_skeleton()` **before** `get_il()` to assess complexity
- Use `offset/limit` parameters in `list_functions()` for large binaries (e.g., `offset=100, limit=50`)
- Cache results from expensive operations: `get_il()`, `get_function_cfg()`, `find_call_paths(include_all_paths=true)`
- Batch similar operations: Multiple `get_xrefs()` calls in sequence
- Use `execute_datalog(limit=500)` initially, increase if needed

---

## Output Field Reference

### `get_function_skeleton` Output
```json
{
  "arg_count": 2,
  "calls": ["memcpy", "malloc"],
  "strings": ["error", "debug"],
  "loops": 3,
  "crypto_patterns": ["AES"],
  "stack_usage": 256,
  "suspicious_patterns": ["strcpy"]
}
```

### `emulate_snippet_native` Output
```json
{
  "final_registers": {"x0": "0x...", "x1": "0x..."},
  "memory_writes": [{"addr": "0x...", "size": 8, "value": "0x..."}],
  "decoded_strings": ["hello", "world"],
  "stop_reason": "range_exit" | "step_limit" | "error"
}
```

### `find_call_paths` Output
```json
{
  "paths": [
    ["0x401234", "0x401300", "0x401400"],  // direct path
  ],
  "shortest_path_length": 3,
  "total_paths_found": 1
}
```

---

## Integration Examples

### With Python (via HTTP API)
```python
import requests

API = "http://127.0.0.1:8787"

# Load binary
resp = requests.post(f"{API}/call", json={
    "name": "load_binary",
    "arguments": {"path": "app.elf"}
})

# List functions
resp = requests.post(f"{API}/call", json={
    "name": "list_functions",
    "arguments": {"offset": 0, "limit": 10}
})

# Analyze function
addr = "0x401234"
resp = requests.post(f"{API}/call", json={
    "name": "get_function_skeleton",
    "arguments": {"addr": addr}
})
```

### With Bash (via CLI)
```bash
# Search for RC4
aeon rc4 binary.elf

# Report coverage
aeon coverage binary.elf

# Get function details
aeon func binary.elf 0x401234

# List functions
aeon list binary.elf | head -20

# Scan pointers
aeon pointers binary.elf

# Find vtables
aeon vtables binary.elf

# Find call paths
aeon call-path binary.elf 0x401000 0x402000
```

---

## Commonly Used Patterns

### Pattern: Identify All Dangerous Functions
```
list_functions(offset=0, limit=1000)
  → for each: get_function_skeleton()
  → filter by: "strcpy" in calls or strings
  → result: array of vulnerable candidates
```

### Pattern: Map Input to Output
```
find_call_paths(start="input_handler", goal="output_sink")
  → trace each path with get_il()
  → document transformations
  → result: data transformation pipeline
```

### Pattern: Find All Crypto Operations
```
search_rc4()  # RC4 instances
scan_pointers()  # S-boxes, constants
list_functions() → for each: get_function_skeleton() + filter crypto
  → result: comprehensive crypto catalog
```

### Pattern: Analyze Unknown Function
```
get_function_skeleton(addr)  # quick overview
get_il(addr)  # detailed analysis
get_data_flow_slice(addr, register="x0", direction="backward")  # inputs
emulate_snippet_native() with test inputs  # behavior validation
add_hypothesis()  # document findings
```

---

## When to Use Each Analysis Type

| Analysis | Best For | Overhead |
|----------|----------|----------|
| `get_function_skeleton()` | Quick triage, pattern detection | Low |
| `get_il()` | Detailed semantics, instruction-level analysis | Medium |
| `get_asm()` | Assembly inspection, obfuscated code | Low |
| `emulate_snippet_native()` | Behavior verification, decryption, decompression | High |
| `get_data_flow_slice()` | Track variable sources/uses | Medium |
| `execute_datalog()` | Reachability, whole-program analysis | Very High |

---

## Quick Start for New Users

1. **Load binary**: `load_binary(path="...")`
2. **Find functions**: `list_functions(limit=10)` 
3. **Analyze each**: `get_function_skeleton(addr="0x401234")`
4. **Find interesting patterns**: `search_analysis_names("crypto|strcpy|malloc")`
5. **Deep dive**: `get_il(addr="0x401234")`
6. **Document findings**: `set_analysis_name()`, `add_hypothesis()`

---

## Resources

- **Foundation**: `docs/analysis-workflows.md`
- **Advanced**: `docs/advanced-workflows.md`
- **Full Reference**: `README.md` (tool descriptions)
- **Examples**: See workflow sections for concrete examples

