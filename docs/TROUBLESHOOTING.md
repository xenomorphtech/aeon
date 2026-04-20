# Aeon Troubleshooting & FAQ

Comprehensive guide to resolving issues, understanding error messages, and best practices.

## Quick Diagnosis

### "My analysis failed"
1. Check binary is loaded: Does `list-functions` work?
2. Check IL coverage: Run `get-coverage` → if <85%, use `get-asm` instead
3. Check address validity: Is the address actually a function? Use `get-function-at` to verify
4. Check permissions: Does the binary have readable segments at that address?

### "Tool says it doesn't exist"
1. Check tool name spelling (use exact name from `quick-reference.md`)
2. Check binary is loaded (tools require loaded binary)
3. Check it's not deprecated (check git history for tool changes)
4. Try `get-function-at` with your address first

### "Emulation produced wrong result"
1. Check register initialization (are x0-x7 set correctly?)
2. Check memory initialization (is data at expected addresses?)
3. Check calling convention (ARM64 ABI may differ from your assumptions)
4. Try with known test case first (verify tool with simple example)

### "Performance is terrible"
1. Check you're using pagination (`offset` and `limit` parameters)
2. Check IL coverage (poor coverage means slower analysis)
3. Check binary size (>100MB binaries naturally slower)
4. Consider batching: process multiple items per call

## Error Messages

### "Error: Binary not loaded"
**Cause**: Tried to use analysis tool before `load-binary`

**Solution**:
```bash
aeon load-binary --path /path/to/binary.elf
```

**Prevention**: Always load binary first, before running analysis tools

---

### "Error: Function not found at 0x..."
**Cause**: Address is not in .eh_frame (function table), or address is not the function entry point

**Solutions**:
1. Use `get-function-at` to find actual function boundaries
2. Use `get-asm` to view assembly at the address and find entry point
3. Check address is in code section (not data)
4. Try `get-function-pointers` to find discovered functions

**Prevention**: 
- Verify address with `get-asm` first
- Use `list-functions` to see all discovered functions
- Cross-reference multiple tools

---

### "Error: IL coverage only 42% - can't trust this analysis"
**Cause**: IL lifting failed for many instructions (SIMD, special encodings, obfuscation)

**Why it matters**:
- <85% coverage means significant portions of code are unknown
- Analysis based on incomplete IL may miss important behavior
- False negatives likely (something may happen that IL doesn't show)

**Solutions**:
1. Use `get-asm` for raw assembly analysis (more reliable)
2. Use `emulate-snippet-native` to test actual behavior
3. Combine IL + assembly for better coverage
4. Consider obfuscation (use tools in [advanced-workflows.md](advanced-workflows.md) § Obfuscation Detection)

**When it's acceptable**:
- Pattern matching (search for signatures)
- Pointer analysis (less affected by IL coverage)
- Datalog queries on discovered facts

---

### "Error: PoisonError on mutex"
**Cause**: Another test panicked while holding a lock (threading issue)

**When you see this**:
- Typically in test suites running in parallel
- Not a problem in production code (mutexes aren't used in analysis)
- Indicates a test framework issue, not an analysis issue

**Solution**:
1. Run the specific test in isolation: `cargo test test_name`
2. Ignore the flaky test marker: `#[ignore]` tests are known issues
3. Check [FLAKY_TEST_ANALYSIS.md](../FLAKY_TEST_ANALYSIS.md) for details

---

### "Error: Operation timed out"
**Cause**: Analysis took longer than allowed (typically 5-10 seconds per tool call)

**Solutions** (in order of preference):
1. Use pagination: Add `offset` and `limit` parameters
2. Reduce scope: Analyze one function instead of all functions
3. Use `get-function-skeleton` before `get-il` (skeleton is faster)
4. Check binary size (>500MB may be naturally slow)
5. Use background processing if available (aeon-eval for batch jobs)

**Prevention**:
- Know your binary size (run `get-coverage` first to understand it)
- Start with skeleton analysis for rough estimates
- Use pagination for large datasets

---

### "Error: Memory read out of bounds"
**Cause**: Tried to read from virtual address that's not mapped in binary

**Solutions**:
1. Check address is in a mapped section: Use hex dump of ELF file
2. Check address format: Hex values should be "0x..." not decimal
3. Verify address is actually in the binary (use `get-string` with a known string to verify)
4. Check relocation (address may be different at runtime vs. in binary)

**Prevention**:
- Use `get-bytes` or `get-string` with known addresses first
- Cross-reference pointers with `scan-pointers`
- Verify addresses with `get-function-at`

---

### "Error: Step limit reached during emulation"
**Cause**: Code executed more instructions than the budget allowed

**Solutions**:
1. Increase step limit: Change `step_limit` parameter to higher value
2. Reduce code range: Emulate smaller snippet (split function into blocks)
3. Check for infinite loops: May indicate analysis should use different approach
4. Simplify test case: Use minimal input that triggers the path you care about

**Example**:
```bash
# ❌ Too conservative
aeon emulate-snippet-native --start 0x1000 --end 0x2000 --step-limit 100

# ✅ More reasonable
aeon emulate-snippet-native --start 0x1000 --end 0x2000 --step-limit 10000

# ✅ For complex code
aeon emulate-snippet-native --start 0x1000 --end 0x1500 --step-limit 5000  # Reduce range
```

---

### "Error: Datalog query returned empty results"
**Cause**: Query found no matches, or query has syntax error

**Diagnosis**:
1. Try simpler query first: Use `reachability` before complex custom queries
2. Check address validity: Use `list-functions` to verify address exists
3. Check graph connectivity: Use `get-xrefs` to see if function is connected
4. Verify starting point: Is the address actually in the binary?

**Solutions**:
1. Start with known patterns: Use built-in query types
2. Use visualization: Run `get-function-cfg` to see call graph structure
3. Add logging: Use `find-call-paths` (more verbose) instead of Datalog
4. Check binary has functions: Run `list-functions` to verify at least one exists

---

## Common Mistakes

### Mistake 1: Using Decimal Instead of Hex
```bash
# ❌ Wrong
aeon get-il --addr 4204084

# ✅ Right
aeon get-il --addr 0x401234
```

**Why**: Binary addresses are traditionally written in hex. Decimal 4204084 = 0x404084, likely wrong address.

---

### Mistake 2: Analyzing Without Checking IL Coverage
```bash
# ❌ Wrong
result = aeon.get_il(0x401234)  # Hope IL is complete

# ✅ Right
coverage = aeon.get_coverage()
if coverage < 0.85:
    # Use asm instead
    asm = aeon.get_asm(0x401234, 0x401300)
else:
    il = aeon.get_il(0x401234)
```

**Why**: IL coverage <85% means significant code is unknown. Better to use assembly.

---

### Mistake 3: Infinite Recursion in Graph Analysis
```rust
// ❌ Wrong
fn trace_reachable(addr: u64) -> Vec<u64> {
    let mut results = vec![addr];
    for next in get_callers(addr) {
        results.extend(trace_reachable(next));  // Cycles cause infinite loop!
    }
    results
}

// ✅ Right
fn trace_reachable(addr: u64) -> Vec<u64> {
    let mut visited = HashSet::new();
    let mut todo = vec![addr];
    
    while let Some(current) = todo.pop() {
        if visited.contains(&current) { continue; }
        visited.insert(current);
        
        for next in get_callers(current) {
            if !visited.contains(&next) {
                todo.push(next);
            }
        }
    }
    
    visited.into_iter().collect()
}
```

---

### Mistake 4: Processing All Functions at Once
```bash
# ❌ Wrong (may time out)
for func in $(aeon list-functions); do
  aeon get-il $func  # Slow!
done

# ✅ Right (using pagination)
aeon list-functions --offset 0 --limit 50 | while read func; do
  aeon get-il $func
done

# Then:
aeon list-functions --offset 50 --limit 50 | while read func; do
  aeon get-il $func
done
```

---

### Mistake 5: Not Validating Test Inputs
```python
# ❌ Wrong
result = aeon.emulate(start=0x401000, end=0x401100)  # Hope addresses are valid

# ✅ Right
# First, verify function exists
func_info = aeon.get_function_at(0x401000)
if func_info is None:
    raise ValueError("Not a valid function")

# Then emulate
result = aeon.emulate(start=0x401000, end=func_info.end)
```

---

## Workflow Debugging

### Debugging: "My workflow produced unexpected results"

**Systematic approach**:

1. **Verify inputs**
   ```bash
   # What addresses are we actually analyzing?
   aeon list-functions --limit 3
   
   # Are they valid?
   for addr in 0x401000 0x402000 0x403000; do
     aeon get-function-at --addr $addr
   done
   ```

2. **Verify intermediate steps**
   ```bash
   # What does each step produce?
   aeon get-il --addr 0x401000 > /tmp/il.txt
   # Inspect: Is this expected?
   ```

3. **Verify outputs**
   ```bash
   # Are results what we expected?
   # Check: addresses, names, properties
   ```

4. **Compare against baseline**
   ```bash
   # Same binary, same analysis, previously different result?
   # Might indicate non-determinism - check for HashMaps
   ```

---

## Performance Debugging

### "Analysis is slow - how to optimize?"

**1. Profile to understand where time is spent**
```bash
# Quick test
time aeon get-function-skeleton --addr 0x401000

# Batch test
time (for i in $(seq 0 50); do aeon get-function-skeleton ...; done)
```

**2. Check IL coverage (may indicate slow lifting)**
```bash
aeon get-coverage
# If <85%, consider using asm instead of IL
```

**3. Use pagination to reduce per-call overhead**
```bash
# ❌ Slow: 100 separate calls
for addr in $(aeon list-functions); do aeon get-il $addr; done

# ✅ Better: 2-5 batches
aeon list-functions --offset 0 --limit 100   # Process 100
aeon list-functions --offset 100 --limit 100 # Process next 100
```

**4. Cache results if possible**
```python
# ❌ Recalculate every time
for function in all_functions:
    skeleton = aeon.get_function_skeleton(function)
    
# ✅ Cache results
skeleton_cache = {}
for function in all_functions:
    if function not in skeleton_cache:
        skeleton_cache[function] = aeon.get_function_skeleton(function)
```

**5. Use parallel processing (carefully)**
```python
from concurrent.futures import ThreadPoolExecutor

# ✅ Process multiple functions in parallel
with ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(
        lambda addr: aeon.get_il(addr),
        all_addresses
    ))
```

---

## Analyzing Specific Binary Types

### Statically Linked Binary
**Characteristics**: Large, contains all dependencies, many functions

**Strategy**:
1. Use pagination aggressively
2. Focus on specific functions (use search first)
3. Use `get-function-skeleton` to filter

**Example**:
```bash
# Find functions with suspicious patterns
aeon list-functions | while read func; do
  skeleton=$(aeon get-function-skeleton --addr $func)
  if echo $skeleton | grep -q "strcpy"; then
    echo "SUSPICIOUS: $func"
  fi
done
```

---

### Dynamically Linked Binary
**Characteristics**: Smaller, imports from system libraries, relies on PLT

**Strategy**:
1. Analyze main code first
2. Map imported functions to known behaviors
3. Use symbol names as hints

**Example**:
```bash
# Find all calls to imported functions
aeon find-call-paths --start 0x1000 --goal 0x2000
# Many paths likely go through imports
```

---

### Obfuscated Binary
**Characteristics**: Poor IL coverage, complex control flow, non-obvious behavior

**Strategy**:
1. Check coverage: `get-coverage`
2. Use emulation: `emulate-snippet-native`
3. Use pattern matching: `search-rc4`, `scan-pointers`
4. See [advanced-workflows.md](advanced-workflows.md) § Obfuscation Detection

---

### Stripped Binary
**Characteristics**: No symbol table, function names are unknown, harder to navigate

**Strategy**:
1. Use heuristics: Look for function patterns
2. Use string references: Find strings, trace to functions
3. Use cross-references: Map calls and references

---

## Testing Your Analysis

### Validation: How to Know Your Results Are Correct

**1. Compare Against Known Ground Truth**
```bash
# If you know what should happen:
expected_result=$(some_tool_that_works)
our_result=$(aeon tool_name --addr 0x401000)
diff expected_result our_result
```

**2. Test with Multiple Tools**
```bash
# Validate with IL
il=$(aeon get-il --addr 0x401000)

# Validate with assembly
asm=$(aeon get-asm --start 0x401000 --stop 0x401100)

# Cross-check: IL and asm should match
```

**3. Emulation Test**
```bash
# If you can emulate the code:
result=$(aeon emulate-snippet-native \
  --start 0x401000 \
  --end 0x401100 \
  --initial-registers '{"x0": "0x1000"}')

# Verify output makes sense
```

**4. Incremental Validation**
```bash
# Start with simple case
aeon get-il --addr 0x401000  # Simple function

# Then more complex
aeon get-il --addr 0x401500  # Complex function

# Then edge cases
aeon get-il --addr 0x401234  # Boundary, recursion, etc.
```

---

## FAQ (Frequently Asked Questions)

### Q: How do I find cryptographic functions?

**A**: Use specialized tools in order of confidence:

1. **Exact detection**: `search-rc4` (finds RC4 specifically)
2. **Pattern matching**: 
   ```bash
   aeon list-functions | while read f; do
     skel=$(aeon get-function-skeleton $f)
     if echo $skel | grep -q "crypto\|256\|AES\|SHA"; then
       echo "POSSIBLE CRYPTO: $f"
     fi
   done
   ```
3. **Manual inspection**: Use [advanced-workflows.md](advanced-workflows.md) § Cryptographic Implementation Analysis

See [analysis-workflows.md](analysis-workflows.md) § Crypto Algorithm Detection for complete workflow.

---

### Q: How do I understand what a function does?

**A**: Use the workflow from [analysis-workflows.md](analysis-workflows.md) § How to Analyze an Unknown Function:

1. Get skeleton: Quick overview
2. Get IL: Detailed instructions  
3. Track data flow: Where does input come from?
4. Emulate: Verify behavior
5. Annotate: Document findings

---

### Q: How do I find vulnerabilities?

**A**: Use the workflow from [advanced-workflows.md](advanced-workflows.md) § Vulnerability Classification:

1. Enumerate all functions
2. Look for dangerous patterns
3. Check reachability from input
4. Verify exploitability

---

### Q: Can I use aeon to find supply chain compromises?

**A**: Yes! See [advanced-workflows.md](advanced-workflows.md) § Supply Chain Analysis

Workflow:
1. Identify third-party code
2. Extract version information
3. Analyze dependency graph
4. Detect suspicious patterns

---

### Q: How do I contribute to aeon?

**A**: See [../CONTRIBUTING.md](../CONTRIBUTING.md) (if exists) or:
1. Clone repository
2. Create feature branch
3. Implement changes with tests
4. Submit pull request

---

### Q: Where is the API documentation?

**A**: See [../README.md](../README.md) § Interfaces (CLI, MCP, HTTP)

Or tool-specific: [quick-reference.md](quick-reference.md) § Tool Categories

---

## Getting More Help

**For analysis questions**: 
→ [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Common Questions

**For tool usage**:
→ [quick-reference.md](quick-reference.md) § Debugging Tips

**For advanced techniques**:
→ [advanced-workflows.md](advanced-workflows.md) § Your domain

**For implementation**:
→ [TOOL_DEVELOPMENT.md](TOOL_DEVELOPMENT.md) § Common Pitfalls

**For architecture**:
→ [../README.md](../README.md)

---

**Last Updated**: 2026-04-20  
**Status**: Comprehensive  
**Coverage**: All common issues and error messages
