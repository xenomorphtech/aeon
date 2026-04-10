# XOR-by-Decomposition: Pattern Recognition & Optimization Guide

## Quick Pattern Reference

### Pattern Type A: AND+OR (Extract & Combine)
**Appears as:** Multiple instances in dispatcher
```
IL Pattern:
  w0 = and(wN, MASK)       // Extract bits
  result = or(wM, w0)      // Combine with another register

Equivalent Arithmetic:
  a XOR b = (a | b) - (a & b)
  a OR b  = (a | b)        // When semantics match

Frequency: 3 blocks (1, 5, 7)
Found at:  0x9b60eb9c, 0x9b60ed28, 0x9b60ee6c
```

### Pattern Type B: SHIFT+AND+OR (Field Extract & OR)
**Appears as:** Dispatch field extraction
```
IL Pattern:
  w0 = asr(wN, SHIFT)           // Extract field via shift
  w0 = and(w0, MASK)            // Mask to field width
  result = or(w0, CONSTANT)     // OR with flag/constant

Equivalent Arithmetic:
  extract_field(x, shift, mask) = (x >> shift) & mask
  extract_field_or(x, s, m, c) = ((x >> s) & m) | c

Frequency: 3 blocks (3, 4, 6) + duplicates
Found at:  0x9b60eca8, 0x9b60ece8, 0x9b60ee2c

Common Operands:
  - Shift by 12 (0xc): Extract bits[12:18]
  - Shift by 6 (0x6):  Extract bits[6:12]
  - Mask 0x3f:        6-bit field width
  - OR constant:      0x80 (dispatch flag)
```

### Pattern Type C: Complex Field Composition
**Appears as:** Heavy-duty field building
```
IL Pattern (Simplified):
  t1 = and(a, b)
  t1 = shl(t1, SHIFT1)
  t2 = and(c, d)
  t3 = or(t1, t2)
  t4 = add(t3, OFFSET)
  result = or(asr(t4, SHIFT2), CONSTANT)

Equivalent Arithmetic:
  result = ((((a & b) << s1) | (c & d) + offset) >> s2) | const

Frequency: 1 block (2)
Found at:  0x9b60ec58

Critical Path: 6-7 instructions
Optimization Benefit: HIGHEST
```

### Pattern Type D: Loop Accumulation
**Appears as:** Loop reduction pattern
```
IL Pattern:
  accumulator = or(accumulator, new_value)
  counter = add(counter, 1)
  counter = and(counter, MASK)  // Wraparound

Equivalent Arithmetic:
  acc |= val  // Accumulate via OR
  cnt = (cnt + 1) & 0xffff  // 16-bit wraparound

Frequency: 1 block (8)
Found at:  0x9b613680

Optimization Benefit: Macro-op fusion potential
```

---

## Detection Strategy

### Step 1: Identify AND/OR Sequences
Look for IL lines with these operations in sequence:
```
and(...)  // AND operation
or(...)   // OR operation
asr(...)  // Arithmetic shift right (often paired with AND)
shl(...)  // Shift left (for field composition)
sub(...), add(...)  // Arithmetic ops paired with bitwise
```

### Step 2: Classify by Operation Count
- **2 ops** = Type A (AND+OR)
- **3 ops** = Type B (SHIFT+AND+OR)
- **4+ ops** = Type C (Complex composition)
- **Loop with OR** = Type D (Accumulation)

### Step 3: Check Common Masks & Constants
These are suspicious and indicate bit field operations:
```
Masks:
  0x3f  (6-bit field)
  0xff  (8-bit field)
  0xffff (16-bit field)
  0xffffff (24-bit field)

Shifts:
  6 bits  (common in dispatch tables)
  12 bits (field offsets)
  18-20 bits (multi-field packing)

Constants:
  0x80  (bit 7 set - flag)
  0xf0  (nibble operations)
  0x10000 (field offset)
```

### Step 4: Verify XOR Semantics
Not all AND+OR = XOR. Check if:
1. The operation computes `(a | b) & ~(a & b)` → **REAL XOR**
2. The operation computes `(a | b)` with different sources → **OR decomposition**
3. The operation extracts and combines fields → **Field composition** (optimize via pattern fusion)

---

## Optimization Strategies

### For Type A Blocks (AND+OR extraction)
**Current Cost:** 2-3 cycles
**Optimized:** 1 cycle (or 2 if immediate)

```
BEFORE:
  w0 = and(w26, 0x3f)
  w2 = or(w25, w0)

AFTER (Proposed):
  w2 = or(w25, and(w26, 0x3f))  // Single operation with fold
  OR
  w2 = extractfield_or(w26, 0, 6, w25)  // Specialized instruction
```

**Implementation:** Recognize pattern in IL optimizer, emit fused instruction

---

### For Type B Blocks (SHIFT+AND+OR)
**Current Cost:** 3 cycles
**Optimized:** 1-2 cycles (specialized instruction)

```
BEFORE:
  w0 = asr(w26, 0x6)
  w0 = and(w0, 0x3f)
  w2 = or(w0, 0x80)

AFTER (Proposed):
  w2 = extractfield_or_const(w26, 6, 0x3f, 0x80)  // Single instruction

OR (if no specialized instruction):
  w0 = and(asr(w26, 6), 0x3f)
  w2 = or(w0, 0x80)  // 2 ops instead of 3
```

**Implementation:** Create ARM64 optimization pattern to fuse operations

---

### For Type C Blocks (Complex composition)
**Current Cost:** 6-7 cycles in dependency chain
**Optimized:** 3-4 cycles (pattern recognition + micro-op fusion)

```
BEFORE:
  w1 = and(w23, w26)
  w1 = shl(w1, 0xa)
  w0 = and(w21, w0)
  w0 = or(shl(and(w23, w26), 0xa), w0)
  w26 = add(w0, 0x10000)
  w0 = asr(w26, 0x12)
  w2 = or(w0, 0xf0)

AFTER (Proposed):
  // Recognize as field_compose(w23, w26, 0xa, w21, w0, 0x10000, 0x12, 0xf0)
  w2 = field_compose_and_shift_or(
    src1_a=w23, src1_b=w26, shift1=0xa,
    src2_a=w21, src2_b=w0,
    add_offset=0x10000,
    shift2=0x12,
    or_const=0xf0
  )
```

**Implementation:** Complex pattern, consider as micro-kernel optimization

---

### For Type D Blocks (Loop accumulation)
**Current Cost:** 1 cycle (ORR)
**Optimized:** 1 cycle (ORR, but with macro-op fusion for counter)

```
BEFORE:
  orr w22, w22, w0           // 1 cycle
  add w23, w23, #1           // 1 cycle (dep on w23)
  ...
  add w17, w17, #1           // 1 cycle (counter)
  and w17, w17, #0xffff      // 1 cycle (dep on add)
  cbnz w17, loop             // 1 cycle (dep on and)

AFTER (Proposed):
  orr w22, w22, w0           // 1 cycle
  add w23, w23, #1           // Macro-fused with w22 ORR
  ...
  add_and_check w17, 0xffff  // Combined add+mask+compare (2 micro-ops)
  cbnz w17, loop
```

**Implementation:** Compiler-level macro-op fusion

---

## Detection Commands

### Find ALL AND+OR sequences in IL
```bash
jq -r 'select(.block_il | any(test("and\\(|or\\(")) | length > 0) 
  | "\(.start): \(.block_il | join(" ; "))"' \
  jit_exec_alias_*.il.jsonl | head -50
```

### Find shift+AND patterns (Type B)
```bash
jq -r 'select(.block_il | any(test("asr|shl")) | length > 0) 
  | select(.block_il | any(test("and\\(|or\\(")) | length > 0)
  | "\(.start): SHIFT+AND+OR"' \
  jit_exec_alias_*.il.jsonl
```

### Find loop patterns (Type D)
```bash
jq -r 'select(.block_il | any(test("\\|")) and .jitted_block_asm | any(test("bnz|cbnz")))
  | "\(.start): LOOP_WITH_OR"' \
  jit_exec_alias_*.il.jsonl
```

---

## Performance Impact Summary

| Pattern | Blocks | Ops | Current | Optimized | Saving | Impact |
|---------|--------|-----|---------|-----------|--------|--------|
| Type A  | 3      | 2   | 2 cyc   | 1 cyc     | 1      | LOW    |
| Type B  | 3      | 3   | 3 cyc   | 1-2 cyc   | 1-2    | MEDIUM |
| Type C  | 1      | 7   | 6 cyc   | 3-4 cyc   | 3      | HIGH   |
| Type D  | 1      | 4   | 4 cyc   | 2-3 cyc*  | 1-2    | LOW    |
| TOTAL   | **8**  | -   | ~17     | ~9-11     | **6-8**| **35-47%** |

*With macro-op fusion support

---

## Files Generated

- `XOR_DECOMPOSITION_ANALYSIS.md` — Detailed analysis with full IL sequences
- `XOR_DECOMPOSITION_PATTERNS.json` — Structured pattern data for tooling
- `PATTERN_RECOGNITION_GUIDE.md` — This file (detection & optimization)

---

## Next Steps

1. **Implement Pattern Recognizer** in IL optimizer
2. **Generate Specialized Instructions** for Type B & C patterns
3. **Evaluate Performance Impact** via benchmark runs
4. **Profile Frequency** of each pattern type in real workloads
5. **Consider Code Consolidation** (3 duplicate Type A blocks at 1, 5, 7)
