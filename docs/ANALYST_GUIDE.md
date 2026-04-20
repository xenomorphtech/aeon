# Aeon Analyst Guide

Complete resource guide for binary analysts using aeon MCP tools for ARM64 ELF analysis.

## Getting Started

### First Time Users

1. **Install**: Build aeon with `cargo build --release`
2. **Load binary**: `aeon load-binary --path /path/to/binary.elf`
3. **Explore**: Start with [Quick Reference Guide](#navigation-by-task) below

### Your First Analysis

1. **List functions**: Find what's in the binary
   ```
   aeon list-functions --limit 20
   ```

2. **Pick a function**: Choose one that interests you
   ```
   aeon get-function-skeleton --addr 0x401234
   ```

3. **Analyze it**: View the lifted IL representation
   ```
   aeon get-il --addr 0x401234
   ```

4. **Document findings**: Annotate what you discover
   ```
   aeon set-analysis-name --addr 0x401234 --name "my_function_purpose"
   ```

## Documentation Navigation

### By Task

| What You Want | Start Here | Then Read |
|---|---|---|
| Quick reference for all tools | [quick-reference.md](quick-reference.md) | Use the table of contents |
| Learn by example | [analysis-workflows.md](analysis-workflows.md) | 8 practical workflow examples |
| Advanced techniques | [advanced-workflows.md](advanced-workflows.md) | 5 sophisticated analysis domains |
| Specific error/problem | [quick-reference.md](quick-reference.md) § Debugging Tips | Troubleshooting table |
| Tool API reference | [README.md](../README.md) § Interfaces | JSON schema details |

### By Goal

#### Security Analysis
1. Start with [advanced-workflows.md](advanced-workflows.md) § Vulnerability Classification
2. Reference [quick-reference.md](quick-reference.md) § Debugging Tips for IL coverage
3. Use pattern templates from [analysis-workflows.md](analysis-workflows.md) § Vulnerability Hunting

#### Cryptographic Implementation Analysis
1. Start with [advanced-workflows.md](advanced-workflows.md) § Cryptographic Implementation Analysis
2. Use [analysis-workflows.md](analysis-workflows.md) § Crypto Algorithm Detection
3. Reference [quick-reference.md](quick-reference.md) § Common Workflows (Find All Crypto Functions)

#### Protocol Reverse Engineering
1. Start with [advanced-workflows.md](advanced-workflows.md) § Reverse Engineering Protocol Handlers
2. Follow the 5-phase workflow for message format discovery
3. Use emulation for validation

#### Supply Chain Analysis
1. Start with [advanced-workflows.md](advanced-workflows.md) § Supply Chain Analysis
2. Use call graph tools from [quick-reference.md](quick-reference.md) § Cross-References & Call Graphs
3. Reference library versioning patterns

### By Workflow Stage

#### Phase 1: Binary Exploration
- Tool guide: [quick-reference.md](quick-reference.md) § Binary Loading & Exploration
- Workflow: [analysis-workflows.md](analysis-workflows.md) § Quick-Start: 10-Minute Binary Survey

#### Phase 2: Function Analysis
- Tool guide: [quick-reference.md](quick-reference.md) § Code Analysis
- Workflow: [analysis-workflows.md](analysis-workflows.md) § How to Analyze an Unknown Function

#### Phase 3: Cross-Function Analysis
- Tool guide: [quick-reference.md](quick-reference.md) § Cross-References & Call Graphs
- Workflow: [advanced-workflows.md](advanced-workflows.md) § Supply Chain Analysis (Phase 3)

#### Phase 4: Specialized Analysis
- Dynamic behavior: [advanced-workflows.md](advanced-workflows.md) § Dynamic Behavior Simulation
- Cryptography: [advanced-workflows.md](advanced-workflows.md) § Cryptographic Implementation Analysis
- Obfuscation: [analysis-workflows.md](analysis-workflows.md) § Obfuscation & Deobfuscation

#### Phase 5: Documentation & Reporting
- Annotation tools: [quick-reference.md](quick-reference.md) § Annotation & Documentation
- Pattern: Use `set-analysis-name()`, `add-hypothesis()`, `define-struct()` to record findings

## Quick Command Reference

### Common Commands

```bash
# Load a binary
aeon load-binary --path samples/hello_aarch64.elf

# List functions
aeon list-functions --limit 50

# Get function details
aeon get-function-skeleton --addr 0x401234

# View IL (intermediate language)
aeon get-il --addr 0x401234

# View assembly
aeon get-asm --start-addr 0x401234 --stop-addr 0x401300

# Find cross-references
aeon get-xrefs --addr 0x401234

# Search for RC4 implementations
aeon search-rc4

# Scan for pointers
aeon scan-pointers

# Search vtables
aeon scan-vtables

# Execute code snippet
aeon emulate-snippet-native --start-addr 0x401234 --end-addr 0x401300
```

### Analysis Patterns

#### Find All Uses of a Function
```bash
# 1. Find the function address
aeon search-analysis-names --pattern "function_name"

# 2. Get cross-references (who calls it)
aeon get-xrefs --addr 0x401234
```

#### Trace Data Through Code
```bash
# 1. Find call path between two functions
aeon find-call-paths --start-addr 0x401000 --goal-addr 0x402000

# 2. Analyze each function on the path
for addr in $PATH_ADDRS; do
  aeon get-il --addr $addr
done

# 3. Look for transformations (encryption, compression, etc.)
```

#### Analyze Obfuscated Code
```bash
# 1. Get IL coverage first
aeon get-coverage

# 2. If IL coverage < 85%, use assembly instead
aeon get-asm --start-addr 0x401234 --stop-addr 0x401300

# 3. Try emulation with test inputs
aeon emulate-snippet-native \
  --start-addr 0x401234 \
  --end-addr 0x401300 \
  --initial-memory '{"0x7fff8000": "48656c6c6f"}' \
  --initial-registers '{"x0": "0x7fff8000"}'
```

## Tool Maturity Levels

### Tier 1: Core Analysis (Stable)
- `load-binary`, `list-functions`, `get-function-at`
- `get-il`, `get-asm`, `get-function-cfg`
- `get-xrefs`, `find-call-paths`
- `set-analysis-name`, `add-hypothesis`

### Tier 2: Advanced Analysis (Stable)
- `get-function-skeleton`, `get-data-flow-slice`
- `get-coverage`, `execute-datalog`
- `scan-pointers`, `scan-vtables`

### Tier 3: Specialized (Stable)
- `search-rc4`, `emulate-snippet-native`
- `define-struct`, `get-string`, `get-bytes`

### Tier 4: Performance Features (Limited Use)
- `emulate-snippet-native-advanced` (watchpoints, hooks)
- `search-analysis-names`, `get-function-pointers`

## Performance Tips

### For Large Binaries (>10MB)

1. Use pagination in `list-functions`:
   ```bash
   aeon list-functions --offset 0 --limit 100
   aeon list-functions --offset 100 --limit 100
   ```

2. Use `get-function-skeleton` before `get-il`:
   ```bash
   # Quick scan: ~10ms per function
   aeon get-function-skeleton --addr 0x401234
   
   # Detailed analysis: ~50-100ms per function
   aeon get-il --addr 0x401234
   ```

3. Cache results in your analysis script

### For Complex Workflows

1. Batch similar operations together
2. Use Datalog for reachability analysis (faster than multiple path searches)
3. For emulation, pre-allocate memory buffers

## Troubleshooting

### Common Issues

#### "Function not found at address 0x..."
- **Cause**: Address is not the start of a function, or function not in .eh_frame
- **Solution**: Use `get-asm` to find entry patterns, or use `get-function-pointers` to enumerate code references

#### "IL coverage only 50% - can't trust the analysis"
- **Cause**: SIMD instructions, special encodings, or heavy obfuscation
- **Solution**: Use `get-asm` for raw assembly analysis, or `emulate-snippet-native` to validate behavior

#### "Emulation produces wrong output"
- **Cause**: Incorrect register initialization or missing memory setup
- **Solution**: Check `initial_registers` and `initial_memory` match ARM64 calling convention

#### "PoisonError or test failures in batch runs"
- **Cause**: Concurrent test access to singleton resources
- **Solution**: Run analysis serially, or use task isolation for large batches

### Getting Help

1. Check [quick-reference.md](quick-reference.md) § Debugging Tips table
2. Review workflow examples that match your use case
3. Consult tool descriptions in [README.md](../README.md)
4. Check JSON schemas via HTTP API: `GET http://localhost:8787/tools`

## Integration Examples

### Python Script
```python
import requests
import json

API = "http://127.0.0.1:8787"

def aeon_call(tool_name, args):
    resp = requests.post(f"{API}/call", json={
        "name": tool_name,
        "arguments": args
    })
    return resp.json()

# Load binary
aeon_call("load_binary", {"path": "binary.elf"})

# List functions
result = aeon_call("list_functions", {"offset": 0, "limit": 10})
for func in result['functions']:
    print(f"0x{func['addr']:x}: {func['name']}")
```

### Bash Script
```bash
#!/bin/bash
BINARY=$1

# Find all crypto functions
echo "=== Searching for RC4 ==="
aeon rc4 "$BINARY"

echo "=== Searching for vtables ==="
aeon vtables "$BINARY"

echo "=== Finding functions with suspicious patterns ==="
aeon list "$BINARY" | head -50 | while read addr name; do
  skel=$(aeon func "$BINARY" "$addr")
  if echo "$skel" | grep -q "strcpy\|sprintf\|system"; then
    echo "SUSPICIOUS: $addr $name"
  fi
done
```

## Next Steps

### For New Users
1. Read [quick-reference.md](quick-reference.md) overview
2. Pick one of the 8 workflows from [analysis-workflows.md](analysis-workflows.md)
3. Follow it step-by-step with your own binary

### For Advanced Users
1. Review [advanced-workflows.md](advanced-workflows.md) for your domain
2. Customize the workflow patterns for your analysis goals
3. Build reusable scripts using the JSON API

### For Tool Developers
1. Check `crates/aeon-frontend/src/service.rs` for tool implementation
2. Review tool schemas in [README.md](../README.md) § Interfaces
3. Add new analysis tools following existing patterns

## Resource Index

| Document | Lines | Purpose |
|----------|-------|---------|
| [quick-reference.md](quick-reference.md) | 327 | Copy-paste ready patterns and command reference |
| [analysis-workflows.md](analysis-workflows.md) | 432 | 8 foundational analysis workflows with examples |
| [advanced-workflows.md](advanced-workflows.md) | 495 | 5 sophisticated analysis domains with detailed methodology |
| [README.md](../README.md) | ~800 | Architecture, tool descriptions, API reference |
| [ANALYST_GUIDE.md](ANALYST_GUIDE.md) | This file | Navigation guide and integration examples |

**Total documentation**: ~2100 lines covering tools, workflows, patterns, and examples.

---

## Analyst Responsibilities

When using aeon for analysis:

1. **Document findings**: Use `set-analysis-name()` and `add-hypothesis()` to record what you learn
2. **Validate results**: Cross-check findings against multiple tools (IL + assembly + emulation)
3. **Track assumptions**: Document what you assume vs. what you've verified
4. **Share patterns**: Contribute new workflow patterns to the docs

## Session Management

Aeon maintains a persistent analysis session:

- **Single binary per session**: Load one binary, then analyze repeatedly
- **State persistence**: Named functions and hypotheses persist across queries
- **HTTP API**: Stateful sessions at `http://localhost:8787`
- **CLI**: Single-query interface for one-off analysis
- **MCP**: Stateless tool calls over stdio for agent integration

---

Last updated: 2026-04-20  
Version: 1.0  
Coverage: All stable tools and tier 1-3 workflows
