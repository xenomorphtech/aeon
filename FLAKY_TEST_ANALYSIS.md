# Flaky Test Analysis: compiles_and_executes_a_basic_block

## Issue Summary
The test `tests::compiles_and_executes_a_basic_block` in `crates/aeon-jit/src/lib.rs` intermittently fails when running the full test suite, but passes 100% of the time when run in isolation.

## Failure Pattern
- **Failure rate**: ~40-60% when running `cargo test --package aeon-jit --lib`
- **When run alone**: `cargo test --package aeon-jit --lib compiles_and_executes_a_basic_block` - always passes
- **Assertion that fails**: Line 5613: `assert_eq!(ctx.pc, 0x2000)`
- **Failure values**: ctx.pc = 0x1000 (4096) instead of expected 0x2000 (8192)

## Root Cause Analysis
The test creates a JIT-compiled conditional branch that should update the program counter (pc) to 0x2000. When the test runs in isolation, the JIT code correctly executes the conditional branch and updates pc. However, in ~50% of full suite runs, pc remains at 0x1000 instead.

### Possible Causes
1. **Test ordering dependency**: The JIT compiler may cache code or state that affects subsequent tests
2. **Memory state corruption**: If another test leaves memory in an inconsistent state
3. **Compiler state persistence**: The `JitCompiler` instance may have lingering state from other tests
4. **Thread-local variable pollution**: Thread-local state (`READ_COUNT`, `WRITE_COUNT`, etc.) may not be fully reset
5. **Code generation caching**: The generated x86-64 code may be cached incorrectly across test boundaries

### Test Details
- **Test function**: `compiles_and_executes_a_basic_block` (line 5554)
- **Key setup**:
  - Creates JitCompiler with instrumentation enabled
  - Sets memory read/write callbacks
  - Sets block counters
  - Compiles ARM64 IL statements that include a conditional branch
- **Assertion**: After executing JIT code, ctx.pc should be 0x2000

## Investigation Results
- ✅ Running test in isolation: Always passes
- ✅ reset_test_statics() is called at test start
- ✅ Similar tests with callbacks (branch_translate_zero, unresolved_branch_bridge) all call reset
- ⚠️ Full suite run: ~50% failure rate, ctx.pc stuck at 0x1000

## Recommendations for Debugging
1. **Add per-test isolation**: Use `#[serial]` crate to force sequential test execution and identify blocking tests
2. **Instrument JIT compiler**: Add logging to track code generation and caching behavior
3. **Memory sanitizer**: Run tests with AddressSanitizer or MemorySanitizer to detect memory corruption
4. **Test isolation**: Create minimal reproduction with specific test sequence that triggers failure
5. **Compiler state inspection**: Log internal JIT compiler state before and after test execution

## Related Flaky Tests
- `native_smoke` tests also show intermittent failures with similar patterns (PoisonError on mutexes)
- Suggests broader test isolation or concurrency issues in JIT test suite

## Date Analyzed
2026-04-19
