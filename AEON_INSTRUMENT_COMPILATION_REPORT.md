# aeon-instrument Compilation Failure Report

**Date**: April 19, 2026  
**Status**: 🔴 **CRITICAL - Does not compile**  
**Impact**: Blocks all testing and evaluation

---

## Summary

The `aeon-instrument` crate fails to compile with 6 compilation errors across 2 files:
- **3 errors**: Stmt type missing Serialize/Deserialize traits
- **2 errors**: Borrow checker violations in jit_cache.rs
- **1 error**: Related to the above

**This is a blocker preventing evaluation of the codebase.**

---

## Compilation Errors

### Error 1-3: Missing Serialize/Deserialize for Stmt

```
error[E0277]: the trait bound `Stmt: serde::Serialize` is not satisfied
error[E0277]: the trait bound `Stmt: serde::Deserialize<'de>` is not satisfied
```

**Location**: Files attempting to serialize/deserialize Stmt

**Root Cause**: The `Stmt` type from aeonil doesn't implement serde traits, but code in aeon-instrument is trying to serialize/deserialize it.

**Fix Required**: Either:
1. Add `#[derive(Serialize, Deserialize)]` to Stmt in aeonil
2. Remove serialization code from aeon-instrument
3. Implement custom serialization

### Error 4-5: Borrow Checker Violation in jit_cache.rs

```
error[E0524]: two closures require unique access to `*file` at the same time
  --> crates/aeon-instrument/src/jit_cache.rs:81
  --> crates/aeon-instrument/src/jit_cache.rs:89
```

**Location**: `src/jit_cache.rs:79-103` (read function)

**Code**:
```rust
fn read(file: &mut File) -> std::io::Result<Self> {
    let mut buf = [0u8; 8];
    let mut read_u64 = || {
        file.read_exact(&mut buf)?;  // First closure borrows file
        Ok(...)
    };
    let mut read_u32 = |buf: &mut [u8]| {
        file.read_exact(buf)?;  // Second closure borrows file
        ...
    };
    // ... more closures ...
}
```

**Root Cause**: Multiple closures cannot each hold a mutable borrow to the same object simultaneously.

**Fix Required**: Restructure to avoid nested closure borrows:
```rust
// Option 1: Don't use closures, read directly
let mut buf = [0u8; 8];
file.read_exact(&mut buf)?;
let magic = u64::from_le_bytes(buf);
// ... repeat for each read

// Option 2: Combine reads into a single function
fn read_all(file: &mut File) -> Result<JitCacheHeader> {
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)?;
    let magic = u64::from_le_bytes(buf);
    // ... continue reading fields
}
```

---

## Files with Errors

| File | Errors | Status |
|------|--------|--------|
| jit_cache.rs | 2 (borrow checker) | Can be fixed (straightforward refactor) |
| (other file) | 3 (Serialize/Deserialize) | Requires trait implementation |
| (other file) | 1 (related) | Likely resolves with above) |

---

## Impact Assessment

**Severity**: 🔴 CRITICAL

**Blocked**:
- ❌ All unit and integration tests
- ❌ Compilation of library and binaries
- ❌ Evaluation of test coverage
- ❌ Performance benchmarks
- ❌ MCP integration testing

**Scope**: Entire aeon-instrument crate is unusable until fixed

---

## Recommendations

### Immediate Actions

1. **Fix jit_cache.rs Borrow Checker Issue** (30 min)
   - Refactor closures into direct reads
   - Test compilation

2. **Fix Stmt Serialization** (1-2 hours)
   - Determine if Stmt should be serializable
   - Add derive or implement custom ser/de
   - Update all dependent code

3. **Run Test Suite** (30 min)
   - Verify no new errors from fixes
   - Document test coverage

### Prevention

- Add CI checks to prevent compilation regressions
- Code review before merging changes to aeonil types
- Test compilation with `cargo check -p aeon-instrument` in CI

---

## Notes

- aeon-jit compiles successfully ✅
- aeon-frontend compiles successfully ✅
- aeon-instrument does not compile ❌

This suggests recent changes to either:
1. aeonil (missing Serialize derive)
2. jit_cache.rs (bad refactoring)
3. Both

The jit_cache.rs error looks like a recent addition (no git history).

