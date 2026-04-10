# Corridor Optimization Roadmap for aeon-poc

**Created:** 2026-04-11  
**Status:** Ready for implementation when ARM device returns  
**Target:** libart.so corridor region optimization  
**Scope:** XOR-by-decomposition patterns & code consolidation

---

## Overview

This document outlines optimization targets identified in the libart dispatcher corridor (0x9b5fe000+) through IL-level analysis. These are CPU-waste optimization opportunities that can be implemented in aeon-poc once the ARM device is available.

**Total Optimization Potential:** 35-47% cycle reduction (6-8 cycles per dispatch operation)

---

## Implementation Phases

### Phase 1: Pattern Recognition (aeon-poc IL optimizer)
**Goal:** Detect and recognize XOR-by-decomposition patterns  
**Timeline:** 1-2 weeks  
**Complexity:** Medium

#### 1.1 Type A Pattern Recognizer (Direct AND+OR)
```
Pattern: w0 = and(wN, 0x3f); result = or(wM, w0)
Targets: Blocks 0x9b60eb9c, 0x9b60ed28, 0x9b60ee6c (3 blocks, 2 duplicates)
Action: Implement pattern matcher in IL optimizer
Output: Flag as "extractfield_or" for fusion
Benefit: 1 cycle savings per block

Implementation Location: crates/aeon-instrument/src/optimizer.rs (new module: pattern_recognition)

Pseudocode:
  fn recognize_extractfield_or(block: &ILBlock) -> Option<PatternMatch> {
    // Match: and(src1, mask) -> or(src2, temp)
    // Return: PatternMatch { kind: "extractfield_or", sources: [src1, src2], mask }
  }
```

#### 1.2 Type B Pattern Recognizer (SHIFT+AND+OR)
```
Pattern: w0 = asr(wN, shift); w0 = and(w0, 0x3f); w2 = or(w0, 0x80)
Targets: Blocks 0x9b60eca8, 0x9b60ece8, 0x9b60ee2c (3 blocks, 1 duplicate)
Action: Recognize as "extractfield_or_const" pattern
Output: Candidate for macro fusion or specialized instruction
Benefit: 1-2 cycles per block

Implementation Location: crates/aeon-instrument/src/optimizer.rs

Pseudocode:
  fn recognize_extractfield_or_const(block: &ILBlock) -> Option<PatternMatch> {
    // Match: asr(src, shift) -> and(_, mask) -> or(_, const)
    // Return: PatternMatch {
    //   kind: "extractfield_or_const",
    //   source: src,
    //   shift, mask, or_constant
    // }
  }
```

#### 1.3 Type C Pattern Recognizer (Complex Field Composition) ⭐ HIGHEST PRIORITY
```
Pattern: Field composition from 4 inputs with shifts and constants
Target: Block 0x9b60ec58 (1 block, 7-instruction chain)
Action: Implement specialized pattern recognizer
Output: Candidate for custom microkernel or fused operation
Benefit: 3+ cycles per block

Implementation Location: crates/aeon-instrument/src/optimizer.rs

Pseudocode:
  fn recognize_field_compose(block: &ILBlock) -> Option<PatternMatch> {
    // Match complex pattern:
    // t1 = and(a, b) << shift1
    // t2 = and(c, d)
    // t3 = or(t1, t2)
    // t4 = add(t3, offset)
    // result = or(asr(t4, shift2), const)
    // Return: PatternMatch {
    //   kind: "field_compose",
    //   sources: [a, b, c, d],
    //   shifts: [shift1, shift2],
    //   offset, or_const
    // }
  }
```

#### 1.4 Type D Pattern Recognizer (Loop Accumulation)
```
Pattern: Loop with OR accumulation and counter masking
Target: Block 0x9b613680 (1 block)
Action: Recognize as "loop_or_accumulate" pattern
Output: Candidate for macro-op fusion
Benefit: 1-2 cycles per iteration

Implementation Location: crates/aeon-instrument/src/optimizer.rs

Pseudocode:
  fn recognize_loop_or_accumulate(block: &ILBlock) -> Option<PatternMatch> {
    // Match: or(accumulator, value) in loop with counter masking
    // Return: PatternMatch { kind: "loop_or_accumulate", ... }
  }
```

---

### Phase 2: ARM64 Instruction Emission (aeon-poc code generation)
**Goal:** Generate optimized ARM64 instructions for recognized patterns  
**Timeline:** 1-2 weeks  
**Complexity:** Medium-High

#### 2.1 Type A Optimization (AND+OR folding)
```arm64
BEFORE (2 instructions):
  and  w0, w26, #0x3f
  orr  w2, w25, w0

AFTER (1 instruction, with folding):
  orr  w2, w25, and(w26, #0x3f)  // Fused in code generation

Implementation: Add folding rule to ARM64 codegen backend
```

#### 2.2 Type B Optimization (SHIFT+AND+OR fusion)
```arm64
BEFORE (3 instructions):
  asr  w0, w26, #6
  and  w0, w0, #0x3f
  orr  w2, w0, #0x80

AFTER (2 instructions, or 1 with ARM64-specific patterns):
  // Option 1: Fuse to specialized instruction (if available)
  extractfield_or_const w2, w26, 6, 0x3f, 0x80
  
  // Option 2: Fuse in codegen
  ubfx w0, w26, #6, #6        // ARM64 bit field extract
  orr  w2, w0, #0x80          // (2 instructions instead of 3)

Implementation: Add ARM64 UBFX (unsigned bit field extract) pattern matching
```

#### 2.3 Type C Optimization (Field Composition Kernel)
```arm64
BEFORE (6-7 instructions, 6+ cycle dependency chain):
  and  w1, w23, w26
  lsl  w1, w1, #10
  and  w0, w21, w0
  orr  w0, w1, w0
  add  w26, w0, #0x10000
  asr  w0, w26, #18
  orr  w2, w0, #0xf0

AFTER (4 instructions, 3-4 cycle dependency chain):
  // Option 1: Custom microkernel
  field_compose_kernel_0x9b60ec58:
    field_compose w2, w23, w26, 0xa, w21, w0, 0x10000, 0x12, 0xf0
  
  // Option 2: Macro-op fusion at codegen time
  and  w1, w23, w26
  lsl  w1, w1, #10
  and  w0, w21, w0             // Can be fused with prior instruction
  orr  w0, w1, w0
  ; Fused: add+shift+or in single uop
  asr  w0, w0, #12             // More aggressive shift
  orr  w2, w0, #0xf0

Implementation: Create specialized codegen path for field_compose pattern
Location: crates/aeon-instrument/src/codegen/arm64_patterns.rs
```

#### 2.4 Type D Optimization (Loop Macro-op Fusion)
```arm64
BEFORE (4+ instructions per iteration):
  orr  w22, w22, w0
  add  w23, w23, #1
  ...
  add  w17, w17, #1
  and  w17, w17, #0xffff
  strh w17, [x16]
  cbnz w17, loop

AFTER (3 instructions with fusion):
  orr  w22, w22, w0            // 1 uop
  add  w23, w23, #1            // 1 uop, fused with prior
  ...
  add_and_check w17, 0xffff    // Macro-op: add + mask + compare (1-2 uops)
  cbnz w17, loop

Implementation: ARM64 CPU-specific macro-op fusion
Location: crates/aeon-instrument/src/codegen/arm64_fusion.rs
```

---

### Phase 3: Validation & Benchmarking
**Goal:** Verify optimization correctness and measure performance gains  
**Timeline:** 1 week  
**Complexity:** Medium

#### 3.1 Correctness Validation
- [ ] Generate test cases for each pattern type
- [ ] Verify optimized code produces identical results
- [ ] Run IL semantic validation on generated code
- [ ] Cross-verify with original block behavior

#### 3.2 Performance Benchmarking
- [ ] Measure cycle count before/after optimization
- [ ] Profile dispatch loop execution time
- [ ] Measure cache behavior (L1/L2 hit rates)
- [ ] Quantify total application performance improvement

#### 3.3 Binary Size Analysis
- [ ] Measure code consolidation benefits (Type A duplicates)
- [ ] Analyze instruction cache utilization
- [ ] Estimate memory bandwidth savings

---

## Code Consolidation Opportunities

### Duplicate Code: 3 instances of Type A pattern
```
Block 0x9b60eb9c:
  w0 = and(w26, 0x3f)
  w2 = or(w25, w0)

Block 0x9b60ed28: DUPLICATE
Block 0x9b60ee6c: DUPLICATE #2
```

**Consolidation Strategy:**
1. Extract to helper function: `extract_and_or_field(w26, 0x3f, w25) -> w2`
2. Replace all 3 blocks with jumps to helper (saves ~12 bytes)
3. Update call sites in dispatch table

### Duplicate Code: Type B pattern
```
Block 0x9b60ece8:
  w0 = asr(w26, 0x6)
  w0 = and(w0, 0x3f)
  w2 = or(w0, 0x80)

Block 0x9b60ee2c: DUPLICATE
```

**Consolidation Strategy:**
Same as Type A - extract to helper function

**Total Binary Savings:** ~20-30 bytes (consolidation) + reduced instruction count (optimization)

---

## Integration Points for aeon-poc

### 1. Pattern Recognition Module
- **File:** `crates/aeon-instrument/src/optimizer/pattern_recognition.rs`
- **Interface:** Trait-based pattern matching system
- **Input:** ILBlock, ILInstruction stream
- **Output:** PatternMatch enum with details

### 2. ARM64 Code Generation Backend
- **File:** `crates/aeon-instrument/src/codegen/arm64.rs`
- **Changes:** Add pattern-specific emission paths
- **Fallback:** Standard instruction emission if no pattern match

### 3. IL Optimizer Pipeline
- **File:** `crates/aeon-instrument/src/optimizer/mod.rs`
- **Integration:** Add pattern recognition pass before code generation
- **Metrics:** Collect statistics on pattern frequency and optimization impact

### 4. Testing Framework
- **File:** `crates/aeon-instrument/tests/pattern_recognition_tests.rs`
- **Coverage:** Unit tests for each pattern type
- **Validation:** Semantic equivalence of optimized vs original

---

## Performance Impact Summary

| Phase | Pattern | Blocks | Current | Optimized | Saving | Status |
|-------|---------|--------|---------|-----------|--------|--------|
| 1 | Type A (AND+OR) | 3 | 2 cyc | 1 cyc | 1x3=3 | Ready |
| 2a | Type B (SHIFT+AND+OR) | 3 | 3 cyc | 1-2 cyc | 1-2x3=3-6 | Ready |
| 2b | Type C (Field Compose) ⭐ | 1 | 6+ cyc | 3-4 cyc | 3+ | Priority |
| 3 | Type D (Loop Accum) | 1 | 4 cyc | 2-3 cyc | 1-2 | Lower |
| **TOTAL** | - | **8** | **~17** | **~9-11** | **6-8 (35-47%)** | Ready |

---

## Dependencies & Prerequisites

- [ ] ARM device available for testing/validation
- [ ] aeon-poc codebase setup and buildable
- [ ] IL representation stable (no breaking changes)
- [ ] ARM64 ISA reference documentation
- [ ] Performance profiling tools (perf, uftrace, etc.)

---

## Related Documentation

- `XOR_DECOMPOSITION_ANALYSIS.md` — Full technical analysis with all IL sequences
- `XOR_DECOMPOSITION_PATTERNS.json` — Structured pattern data for tooling
- `PATTERN_RECOGNITION_GUIDE.md` — Detection strategies and code examples
- `XOR_ANALYSIS_SUMMARY.txt` — Executive summary

---

## Success Criteria

✅ **Phase 1 Complete:** All 4 pattern recognizers implemented and tested  
✅ **Phase 2 Complete:** Optimized ARM64 code generation working  
✅ **Phase 3 Complete:** 30-45% cycle reduction verified on device  
✅ **Integration Complete:** aeon-poc corridor optimization module ready  

---

## Next Steps

1. **ARM Device Returns:** Validate patterns on actual libart.so
2. **Implement Phase 1:** Pattern recognizer module in aeon-poc
3. **Implement Phase 2:** ARM64 code generation optimization
4. **Benchmark & Measure:** Quantify real-world performance gains
5. **Deploy:** Integrate into aeon-poc production optimization pipeline

---

**Owner:** Analysis completed by Claude Code  
**Last Updated:** 2026-04-11  
**Status:** 🟢 Ready for Implementation
