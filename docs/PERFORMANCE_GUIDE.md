# Aeon Performance Guide

Comprehensive guide for measuring, analyzing, and optimizing aeon's performance.

## Performance Baseline

### Typical Performance Characteristics

| Operation | Binary Size | Time | Notes |
|-----------|-------------|------|-------|
| Load binary | 100KB | <100ms | Parsing + function discovery |
| | 10MB | 500ms | Typical production binary |
| | 100MB | 5s | Large, pushes limits |
| List functions (limit 100) | Any | <10ms | Instant |
| Get function skeleton | Any | <10ms | Quick overview |
| Get IL (simple function) | Any | 50-100ms | Detailed analysis |
| Get IL (complex function) | Any | 100-500ms | Many instructions |
| Get CFG | Any | 50-200ms | Control flow analysis |
| Scan pointers | 10MB | 100-500ms | Data section scan |
| Execute Datalog | Any | 100-1000ms | Graph analysis |
| Emulate snippet (100 inst) | Any | 10-50ms | Native execution |

## Measuring Performance

### 1. Command-Line Timing

**Simple measurement**:
```bash
time aeon load-binary --path binary.elf
time aeon list-functions
time aeon get-il --addr 0x401234
```

**Output**:
```
real    0m0.234s
user    0m0.145s
sys     0m0.089s
```

**Interpretation**:
- **real**: Actual elapsed time
- **user**: CPU time in process
- **sys**: System call time

---

### 2. Batch Operation Timing

```bash
# Time multiple operations
echo "=== Loading binary ===" && time aeon load-binary --path binary.elf
echo "=== Listing functions ===" && time aeon list-functions --limit 100
echo "=== Scanning pointers ===" && time aeon scan-pointers

# Or run all together
time (
  aeon load-binary --path binary.elf
  aeon list-functions | head -50 | while read addr; do
    aeon get-function-skeleton --addr "$addr"
  done
)
```

---

### 3. Memory Usage

```bash
# Measure peak memory (Linux)
/usr/bin/time -v aeon load-binary --path binary.elf 2>&1 | grep "Maximum resident"

# Or use ps for live monitoring
aeon load-binary --path binary.elf &
PID=$!
while kill -0 $PID 2>/dev/null; do
  ps aux | grep $PID | grep -v grep
  sleep 0.1
done
```

**Key Metrics**:
- **RSS**: Resident Set Size (actual memory used)
- **VSZ**: Virtual memory size (allocated)
- **Peak**: Maximum memory during execution

---

### 4. Profiling with Linux Tools

```bash
# CPU profiling with perf
perf record -g aeon load-binary --path binary.elf
perf report

# Memory profiling with valgrind
valgrind --tool=massif aeon load-binary --path binary.elf
ms_print massif.out.* | head -100

# Flamegraph (if installed)
perf record -F 99 -g aeon load-binary --path binary.elf
perf script | stackcollapse-perf.pl | flamegraph.pl > graph.svg
```

---

## Performance Optimization Techniques

### 1. Pagination for Large Operations

**Problem**: Listing all 10,000 functions takes time

**Solution**: Use pagination
```bash
# ❌ Slow: Request all functions at once
aeon list-functions

# ✅ Fast: Process in batches
for offset in 0 100 200 300; do
  aeon list-functions --offset $offset --limit 100
done
```

**Impact**: No time savings (same total work), but enables streaming processing

---

### 2. Skeleton-First Analysis

**Problem**: `get-il` is slow for all functions

**Solution**: Filter with skeleton first
```bash
# ❌ Slow: Analyze all 10,000 functions in detail
for func in $(aeon list-functions); do
  aeon get-il --addr $func
done

# ✅ Fast: Filter with skeleton, then detail
aeon list-functions | while read addr; do
  skel=$(aeon get-function-skeleton --addr "$addr")
  # Only analyze interesting functions
  if echo "$skel" | grep -q "strcpy\|sprintf"; then
    aeon get-il --addr "$addr"
  fi
done
```

**Impact**: 50-90% time reduction for filtered analysis

---

### 3. Caching Results

**Problem**: Analyzing same function multiple times

**Solution**: Cache locally
```python
cache = {}

def analyze_function(addr):
    if addr not in cache:
        cache[addr] = aeon.get_il(addr)
    return cache[addr]

# Now reuse results
for addr in addresses:
    result = analyze_function(addr)  # May be cached
```

**Impact**: 95%+ time savings for repeated queries

---

### 4. Parallel Processing

**Problem**: Sequential analysis is slow

**Solution**: Parallel processing (carefully)
```python
from concurrent.futures import ThreadPoolExecutor

# ✅ Safe parallelization
with ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(
        lambda addr: aeon.get_il(addr),
        addresses[:100]  # Don't overload
    ))
```

**Constraints**:
- Max 4-8 workers (higher doesn't help, may hurt)
- Batch small operations (overhead not worth it for <10 items)
- Monitor resource usage (don't exceed system limits)

**Impact**: 2-4x speedup on multi-core systems

---

### 5. Limiting Scope

**Problem**: Analyzing entire binary is slow

**Solution**: Focus on relevant sections
```bash
# ❌ Slow: All functions
aeon list-functions | wc -l  # 10,000 functions

# ✅ Fast: Interesting functions only
aeon search-analysis-names --pattern "crypto|decrypt|key"
# 45 matches - much more manageable
```

**Impact**: 10-100x speedup for targeted analysis

---

## Binary-Specific Performance

### Small Binaries (<10MB)
**Performance**: Excellent, no special handling needed
**Recommendation**: Standard analysis workflow

---

### Medium Binaries (10-100MB)
**Performance**: Good, use pagination for large operations
**Recommendation**: 
- Use skeleton filtering
- Process in batches of 100 functions
- Cache results for repeated access

---

### Large Binaries (100MB-1GB)
**Performance**: Slower, requires optimization
**Recommendation**:
- Load only once (reuse session)
- Aggressive pagination (limit 50)
- Symbol search first (reduce scope)
- Skip IL for most functions (use skeleton/asm)
- Parallel processing with care

---

### Very Large Binaries (>1GB)
**Performance**: Limited by system resources
**Recommendation**:
- Consider if aeon is right tool (may need specialized analysis)
- Use HTTP API for persistent session
- Process in multiple passes
- Focus on specific functions/regions

---

## Memory Optimization

### Current Memory Usage

Typical binary analysis memory:
- **Binary size**: 10MB
- **Parsed structures**: ~20MB
- **Cached IL**: ~30MB
- **Total**: ~60MB

---

### Memory-Efficient Analysis

```python
# ❌ Memory-heavy
results = []
for addr in all_addresses:  # 10,000 items
    result = aeon.get_il(addr)  # Stores in memory
    results.append(result)
# Now have 10,000 IL representations in memory (300MB+)

# ✅ Memory-efficient (streaming)
def process_functions():
    for addr in all_addresses:
        result = aeon.get_il(addr)
        yield result  # Generator, not stored

# Process one at a time
for result in process_functions():
    analyze(result)  # Process and discard
    # Only one IL representation in memory at a time
```

**Impact**: 90% memory reduction for large-scale analysis

---

## Benchmarking Examples

### Example 1: Function Skeleton Performance

```bash
#!/bin/bash
# Benchmark get-function-skeleton

binary="samples/hello_aarch64.elf"
iterations=100

aeon load-binary --path "$binary"

start=$(date +%s%N)

for i in $(seq 1 $iterations); do
  aeon list-functions --limit 1 | while read addr; do
    aeon get-function-skeleton --addr "$addr" > /dev/null
  done
done

end=$(date +%s%N)
elapsed=$((($end - $start) / 1000000))  # Convert to milliseconds
avg=$(($elapsed / $iterations))

echo "Total: ${elapsed}ms for $iterations iterations"
echo "Average: ${avg}ms per call"
```

---

### Example 2: IL Lifting Performance

```bash
#!/bin/bash
# Benchmark IL lifting complexity

binary="samples/hello_aarch64.elf"

aeon load-binary --path "$binary"

# Get range of function sizes
echo "Function sizes and IL lifting times:"
aeon list-functions | head -20 | while read addr; do
  skel=$(aeon get-function-skeleton --addr "$addr")
  size=$(echo "$skel" | jq '.instruction_count')
  
  start=$(date +%s%N)
  aeon get-il --addr "$addr" > /dev/null
  end=$(date +%s%N)
  elapsed=$(( (($end - $start) / 1000000) ))
  
  echo "$size instructions: ${elapsed}ms"
done
```

---

### Example 3: Batch Processing Performance

```bash
#!/bin/bash
# Compare sequential vs pagination

binary="samples/hello_aarch64.elf"
aeon load-binary --path "$binary"

echo "=== Sequential (all at once) ==="
time aeon list-functions > /tmp/all_functions.txt

echo ""
echo "=== Paginated (100 at a time) ==="
time (
  offset=0
  while true; do
    result=$(aeon list-functions --offset $offset --limit 100)
    count=$(echo "$result" | jq '.functions | length')
    if [ "$count" -eq 0 ]; then break; fi
    offset=$(($offset + 100))
  done
)
```

---

## Performance Regression Testing

### Detecting Slowdowns

```bash
#!/bin/bash
# Compare performance between versions

baseline_binary="target/release/aeon-v1.0"
current_binary="target/release/aeon"

test_binary="samples/hello_aarch64.elf"

echo "=== Baseline (v1.0) ==="
time $baseline_binary load-binary --path "$test_binary"

echo ""
echo "=== Current version ==="
time $current_binary load-binary --path "$test_binary"

# Should be same or faster
```

---

## Performance Monitoring

### In Production

```python
import time
import json

def timed_analysis(binary_path):
    results = {}
    
    # Load
    start = time.time()
    aeon.load_binary(binary_path)
    results['load_time'] = time.time() - start
    
    # List
    start = time.time()
    functions = aeon.list_functions(limit=100)
    results['list_time'] = time.time() - start
    
    # Analyze sample
    start = time.time()
    for func in functions[:10]:
        aeon.get_il(func['address'])
    results['analysis_time'] = time.time() - start
    
    return results

# Log results
metrics = timed_analysis("binary.elf")
print(json.dumps(metrics, indent=2))
# {"load_time": 0.523, "list_time": 0.045, "analysis_time": 0.892}
```

---

## Common Performance Issues & Solutions

### Issue 1: "Listing functions takes forever"

**Likely Cause**: Large binary, no limit

**Solution**:
```bash
# ❌ Wrong
aeon list-functions  # Returns ALL functions (may be thousands)

# ✅ Right
aeon list-functions --limit 100  # Returns first 100
```

---

### Issue 2: "Memory usage exploding"

**Likely Cause**: Storing all results in memory

**Solution**: Use generators or stream processing
```python
# Process one function at a time instead of loading all
```

---

### Issue 3: "IL lifting is slow"

**Likely Cause**: Analyzing very large/complex functions

**Solution**:
```bash
# Get skeleton first to see size
aeon get-function-skeleton --addr 0x401000
# If instruction_count > 10,000, consider:
# 1. Just use assembly (get-asm)
# 2. Focus on critical parts (emulate specific snippet)
```

---

### Issue 4: "Process is using 100% CPU"

**Likely Cause**: Expensive Datalog query or large batch operation

**Solution**:
1. Reduce scope (limit number of functions)
2. Use pagination
3. Kill and restart with simpler query

---

## Performance Best Practices

✅ **Do**:
- Measure before and after changes
- Use pagination for large operations
- Filter with skeleton before detailed analysis
- Cache results locally
- Profile with real binaries (representative size)
- Set reasonable limits (step_limit for emulation, etc.)

❌ **Don't**:
- Analyze entire binary without filtering
- Store all results in memory
- Run unlimited parallel jobs
- Assume small binary performance scales to large
- Skip pagination limits
- Process without monitoring resources

---

## Recommended Reading

- **For Optimization**: § Performance Optimization Techniques
- **For Measurement**: § Measuring Performance
- **For Issues**: § Common Performance Issues & Solutions
- **For Profiling**: § Profiling with Linux Tools

---

**Guide Date**: April 20, 2026  
**Status**: Complete  
**Applicable To**: aeon 1.0+
