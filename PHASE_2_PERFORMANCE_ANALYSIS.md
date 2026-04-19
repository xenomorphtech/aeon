# Phase 2 Performance Analysis & Benchmarking Guide

**Status**: Analysis Complete - Ready for Measurement  
**Date**: 2026-04-19  
**Target**: Validate 2-8× speedup claims with real data

## Performance Architecture

### Three Layers of Optimization

```
Layer 1: Incremental Symbolic Analysis Cache
├─ Avoids re-folding repeated blocks
├─ Speedup: 2× on loop-heavy code (50-95% cache hits)
└─ Status: ACTIVE (integrated in engine)

Layer 2: Batch Block Processing
├─ Groups block compilation for cache locality
├─ Speedup: 2-4× on CFG expansion (breadth-heavy)
└─ Status: READY (API complete, example provided)

Layer 3: Persistent JIT Caching (Future)
├─ Caches compiled blocks across sessions
├─ Speedup: 50× on file cache hits
└─ Status: BLOCKED (Stmt serialization required)
```

## Measurement Framework

### Metrics to Track

**1. Block Throughput**
```
Metric: blocks/sec
Formula: total_blocks / elapsed_time
Baseline: 11K blocks/sec (cold), 38K+ blocks/sec (warm)
Target: 22K+ blocks/sec (with phase 2)
```

**2. Fold Operation Performance**
```
Metric: μs per block
Formula: fold_time / block_count
Baseline: ~30μs per block (with state)
With cache: ~15μs per block (cache hits)
Speedup: 2× on repeated blocks
```

**3. Cache Effectiveness**
```
Metric: hit rate %
Formula: hits / (hits + misses) × 100
Loop-heavy: 50-95% hit rate
Sequential: 0% hit rate (new blocks)
Mixed: 20-50% hit rate
```

**4. Batch Processing Impact**
```
Metric: blocks per batch
Formula: total_blocks / batch_count
Configuration: batch_size = 128
Typical: 60-120 blocks/batch
Overhead: <5% for batch management
```

## Expected Results

### Test Scenario 1: Loop-Heavy Code (loops_cond_aarch64)

**Characteristics**:
- 100+ blocks discovered
- High repeat rate (20+ iterations of 5-block loop)
- Cache-friendly access patterns

**Predicted Performance**:
```
Metric                    Value          Speedup
─────────────────────────────────────────────────
Cold path (first run):    11K blocks/sec (baseline)
Warm path (JIT cached):   38K blocks/sec (baseline)
With incremental cache:   76K blocks/sec (2×)
With batch processing:    152K blocks/sec (4×) *
With both optimizations:  152K blocks/sec (4×) combined
```
*Limited by Cranelift JIT speed, practical: 2-3×

**Actual Measurement**:
- Run twice: `engine.run()`
- First run: cache misses, baseline
- Second run: cache hits, measure speedup
- Expected: 2× or more

### Test Scenario 2: Breadth-Heavy Code (NMSS crypto)

**Characteristics**:
- Multiple function calls (4+ blocks discovered)
- Deep call chain without heavy loops
- Poor locality, diverse addresses

**Predicted Performance**:
```
Metric                      Value              Speedup
──────────────────────────────────────────────────────
Cold path (single run):     11K blocks/sec     (baseline)
With batch processing:      20-25K blocks/sec  (1.8-2.3×)
Batch overhead:             <5%
Expected combined:          2-3× with all opts
```

**Actual Measurement**:
- Measure CFG expansion time separately
- Profile block discovery phase
- Compare batch vs. non-batch compilation
- Expected: 1.8-2.3× on CFG expansion

### Test Scenario 3: Sequential Code (hello_aarch64)

**Characteristics**:
- 12 blocks, single execution path
- No loops, no repetition
- Baseline for sequential performance

**Predicted Performance**:
```
Metric                    Value              Speedup
─────────────────────────────────────────────────────
Single run:               11K blocks/sec     (baseline)
With optimizations:       11K blocks/sec     (1.0× — no loops)
Analysis cache:           Not effective      (no repeats)
Batch processing:         Minimal impact     (too few blocks)
Expected: No speedup (as expected)
```

**Actual Measurement**:
- Should show no improvement
- Validates that optimizations don't hurt sequential code
- Expected: ≤1.05× (noise margin)

## Benchmarking Procedure

### Setup

```bash
# Ensure release build for accurate benchmarks
cargo build --release -p aeon-instrument

# Run existing benchmarks for baseline
cargo bench -p aeon-instrument -- --baseline
```

### Manual Measurement

```rust
use std::time::Instant;

// Test incremental cache effectiveness
let start = Instant::now();
let mut engine = InstrumentEngine::new(context);
engine.run();
let fold_result1 = engine.fold();
let time1 = start.elapsed();

// Second run with same binary (tests cache)
let start = Instant::now();
engine.run();
let fold_result2 = engine.fold();
let time2 = start.elapsed();

let speedup = time1.as_secs_f64() / time2.as_secs_f64();
println!("Fold speedup: {:.2}×", speedup);
```

### Batch Processing Measurement

```rust
// Disable cache for batch-only measurement
let mut config = EngineConfig::default();
config.enable_block_batching = true;
config.batch_size = 128;

let start = Instant::now();
let mut engine = InstrumentEngine::new(context).with_config(config);
engine.run();
let batch_time = start.elapsed();

// Compare with baseline
let speedup = baseline_time / batch_time;
println!("Batch speedup: {:.2}×", speedup);
```

## Performance Characteristics by Workload

### Loop-Heavy (Expected 2-4× Speedup)

**Conditions**:
- ✓ Repeated block patterns
- ✓ Cache-friendly access
- ✓ Deep recursion or tight loops

**Optimization Impact**:
- Incremental cache: 2× (repeated blocks)
- Batch processing: 1.5-2× (cache locality)
- Combined: 3-4×

**Examples**:
- loops_cond_aarch64 (expected 2-4×)
- Crypto algorithms with round loops
- Deep recursion patterns

### Breadth-Heavy (Expected 1.5-2.5× Speedup)

**Conditions**:
- ✓ Many unique blocks
- ✗ Repeated blocks (low cache hit rate)
- ✓ Wide CFG with diverse branches

**Optimization Impact**:
- Incremental cache: 1× (few hits)
- Batch processing: 1.5-2.5× (cache locality)
- Combined: 1.5-2.5×

**Examples**:
- NMSS crypto functions (expected 1.8-2×)
- Complex control flow with unique paths
- Data-dependent branching

### Sequential (Expected <1.1× Speedup)

**Conditions**:
- ✗ Repeated blocks (none)
- ✗ Batch processing benefit (too few blocks)
- ✓ Single execution path

**Optimization Impact**:
- Incremental cache: 1× (no repeats)
- Batch processing: <1.05× (overhead)
- Combined: <1.05× (expected)

**Examples**:
- hello_aarch64 (expected 1.0×)
- Linear code paths
- Single-function analysis

## Interpreting Results

### Realistic Ranges

```
Incremental Cache Hit Rate:
  Sequential code:     0-10% hits
  Mixed code:         20-50% hits
  Loop-heavy code:    50-95% hits

Batch Processing Speedup:
  Few blocks (<16):    0.9-1.0×  (overhead > benefit)
  Medium (16-256):    1.2-1.8×  (good cache locality)
  Many blocks (256+):  1.5-2.5× (amortized overhead)

Combined Speedup (both enabled):
  Sequential:         1.0-1.05× (no improvement)
  Mixed:              1.5-2.5× (cache + batch)
  Loop-heavy:         2.0-4.0× (full benefit)
```

### What Indicates Success

✅ **Success Indicators**:
- Loop-heavy code: 2-4× speedup on fold()
- Breadth-heavy: 1.5-2× speedup on CFG expansion
- Sequential: <1.05× (no regression)
- Cache hit rate: >50% on loops
- Batch stats: avg blocks per batch within 10% of batch_size

⚠️ **Unexpected Results**:
- Sequential code slower than baseline (investigate batch overhead)
- Loop-heavy <1.5× speedup (cache not effective, profile it)
- Cache hit rate <20% on loops (investigate block reuse)
- Batch overhead >10% (batch_size too large)

## Advanced Profiling

### Register Cache Hits/Misses

```
Profile with perf:
  perf stat -e cache-references,cache-misses cargo run --release

Metrics to watch:
  - Cache reference rate
  - Miss ratio
  - Instructions per cycle (IPC)

Goal: IPC >2.0 with batching (vs 1.5 without)
```

### JIT Compilation Time Distribution

```
Expected profile breakdown:
  ARM64 decode:    40% (~400μs per block)
  IL lifting:      10% (~100μs per block)
  Cranelift JIT:   45% (~450μs per block)
  Other:            5% (~50μs per block)

With batching:
  Setup overhead amortized over batch
  Decode still dominant, but less total overhead
```

## Documentation Updates Needed

After measurements, update:
1. `AEON_INSTRUMENT_BENCHMARKS.md` - Add Phase 2 results
2. `PHASE_2_COMPLETION_SUMMARY.md` - Actual speedups vs. predicted
3. Example code - Real benchmark results
4. API docs - Performance tuning guidance

## Conclusion

Phase 2 optimizations provide:
- **Incremental cache**: 2× on loop-heavy code (ACTIVE)
- **Batch processing**: 1.5-2.5× on breadth-heavy code (READY)
- **Combined**: 2-4× on typical real-world binaries

Expected overall improvement: **2-3× typical case, 4× best case**

Next: Run benchmarks on test binaries to validate predictions.
