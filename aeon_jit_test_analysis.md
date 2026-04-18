# aeon_jit Test Coverage & MCP Interface Analysis

## Executive Summary

**Test Status:** 268 passed, 17 failed across workspace
- **aeon_jit**: 77 passed, 8 failed (91% pass rate)
- **aeon-instrument**: 28 passed, 9 failed (integration tests with mutex issues)
- **Other crates**: 163 passed, 0 failed

**Key Findings:**
1. aeon_jit has known failing tests related to flag-based conditional branches and bridge callback invocation
2. MCP interface has minimal test coverage (1 smoke test for reduced_il)
3. aeon_jit lacks integration tests that exercise the full compilation pipeline
4. Missing tests for advanced instruction patterns and error conditions

---

## Test Status by Crate

### aeon (Core Library) - ✅ 86/86 passed
- Comprehensive test coverage across emulation, lifting, analysis, and RC4 search
- Tests cover: CFG computation, xrefs, pointer recovery, vtable detection, path search
- Well-structured unit tests with good isolation

### aeon-eval - ✅ 7/7 passed  
- Tests cover evaluation corpus, task specs, and evidence models
- Reduced IL and SSA transformation golden tests

### aeon-frontend - ✅ 6/6 passed
- 2 HTTP transport tests (binary loading, binary call smoke)
- 1 MCP transport test (single tool call smoke test)
- 3 service tests (tool surface documentation, tool surface markdown)
- **Gap**: Missing comprehensive tests for individual tool behaviors

### aeon-jit - ⚠️ 77/85 passed, 8 failed
**Failing Tests:**
1. **Flag Conditional Branches (7 failures)** - All follow same pattern:
   - `flag_cond_eq_and_ne` - Expected 0x2000, got 0
   - `flag_cond_cs_cc_unsigned_carry` - Expected 0x2000, got 0
   - `flag_cond_hi_ls_unsigned_greater` - Expected 0x2000, got 0
   - `flag_cond_gt_le_signed` - Expected 0x2000, got 0
   - `flag_cond_ge_lt_signed` - Expected 0x2000, got 0
   - `flag_cond_vs_vc_overflow` - Expected 0x2000, got 0
   - `flag_cond_mi_pl_negative` - Expected 0x2000, got 0
   - **Root Cause**: All tests compile flag-based conditional branches and expect branch target address as return value, but receive 0 instead. Suggests issue with how condition evaluation is passed through the JIT or branch target resolution.

2. **Bridge Callback Invocation (1 failure)**:
   - `unresolved_branch_bridge_sees_flushed_x30` - Expected BRIDGE_COUNT=1, got 3
   - **Root Cause**: The bridge callback for unresolved branches is being invoked 3 times for a single branch operation instead of once. Indicates either:
     - Bridge callback is being registered and called multiple times
     - Bridge is being called during setup phase + execution phase
     - Callback tracking is not resetting properly between test iterations

### survey - ✅ 49/49 passed
- Opcode survey utility has good test coverage

### aeonil - ✅ 13/13 passed
- IL type definitions and expression helpers well-tested

### aeon-instrument - ⚠️ 28/37 passed, 9 failed
- All failures are PoisonError on mutex operations
- Failures in:
  - `smoke_hello_runs_to_halt`
  - `hello_return_value`
  - `hello_traces_memory`
  - `loops_runs_to_halt`
  - `loops_has_stride_1_induction_variable`
  - `loops_symbolic_fold_finds_invariants`
  - `max_steps_stops_engine`
  - `nmss_crypto_sub_20bb48_traces_to_disk`
  - `nmss_crypto_sub_2070a8_traces_to_disk`
- These are integration tests that exercise the full engine with embedded tracing

---

## aeon_jit Test Structure

### Unit Tests (85 tests in src/lib.rs)
- **Instruction compilation**: 70+ tests covering arithmetic, bitfield, SIMD, floating-point, and memory operations
- **Branch handling**: 3 tests for direct branches, conditional branches, and bridge callbacks
- **Error cases**: 2 tests for invalid statements

### Integration Tests
- **roundtrip.rs** (29KB): Tests AeonIL→JIT roundtrip compilation; exercises full pipeline
- **native_smoke.rs** (~7KB): Smoke tests for native execution and memory access patterns

### Examples
- **dump_printf_bridge_asm.rs**: Example showing bridge callback usage with printf formatting

### Test Coverage Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| No tests for complex control flow patterns (loops, nested branches) | Cannot verify loop unrolling or complex CFG handling | Medium |
| No tests for exception/trap handling | Trap instruction handling untested | Medium |
| No tests for callback error paths | Bridge/translate callbacks with errors not tested | Low |
| No tests for register preservation across bridge calls | ABI compliance not verified | Medium |
| No systematic tool integration tests via MCP | Transport layer integration with tools untested | High |
| No fuzz tests or property-based tests | Edge cases in instruction patterns undiscovered | Low |
| No performance/benchmark tests | Regression detection impossible | Low |

---

## MCP Interface Evaluation

### Transport Implementation
- **Location**: `crates/aeon-frontend/src/mcp.rs`
- **Protocol**: JSON-RPC 2.0 over stdin/stdout
- **Status**: Minimal but functional

### Tool Surface (25 tools exposed)
All tools properly documented with schema and descriptions. Standard categories:
- **Binary loading**: `load_binary` (with schema support for path, base_addr, format)
- **Analysis**: `list_functions`, `get_il`, `get_reduced_il`, `get_ssa`, `get_function_cfg`
- **Queries**: `get_xrefs`, `find_call_paths`, `get_function_pointers`, `scan_pointers`, `scan_vtables`
- **Inspection**: `get_bytes`, `get_data`, `get_string`, `get_asm`, `get_function_at`, `get_stack_frame`
- **Behavioral search**: `search_rc4`, `search_analysis_names`
- **Semantics**: `rename_symbol`, `set_analysis_name`, `define_struct`, `add_hypothesis`
- **Metrics**: `get_coverage`

### Test Coverage
- **Total MCP tests**: 1 (in `crates/aeon-frontend/src/mcp.rs`)
  - Single smoke test: `mcp_tools_call_smoke_for_reduced_il`
  - Only exercises `load_binary` + `get_reduced_il` path
  - No tests for error cases, tool parameter validation, or edge cases

### HTTP Frontend Tests
- **Location**: `crates/aeon-frontend/src/http.rs`
- **Tests**: 2 smoke tests
  - Binary loading and basic tool invocation
  - No comprehensive tool coverage

### Quality Assessment
| Aspect | Rating | Notes |
|--------|--------|-------|
| Protocol compliance | ✅ Good | Proper JSON-RPC 2.0 structure, error handling |
| Tool schema definition | ✅ Good | All tools have clear input/output schemas |
| Error handling | ⚠️ Fair | Basic error propagation, but no schema validation tests |
| Documentation | ✅ Good | Tool descriptions auto-generated and checked (README sanity test) |
| Test coverage | ❌ Poor | Only 1 of 25 tools has any test coverage |
| Parameter validation | ? Unknown | No tests exercise validation boundaries |
| State management | ? Unknown | Session persistence not tested across multiple calls |

---

## Recommendations

### Priority 1: Fix aeon_jit Failures
1. **Flag conditional branch failure** - Investigate why branch target address returns 0 instead of target
   - Check Cranelift IL generation for condition testing
   - Verify that condition evaluation from SetFlags propagates correctly to CondBranch
   - Trace JIT entry point to see if return value is being set correctly

2. **Bridge callback count** - Reset or count callbacks per test properly
   - Verify BRIDGE_COUNT is being reset before each test
   - Add debug logging to understand when bridge is being called
   - Check if bridge is being invoked during block compilation vs execution

### Priority 2: Expand MCP Interface Tests
Create comprehensive test suite covering:
1. **Tool parameter validation tests** for each tool with schema
2. **Error case tests** - missing binaries, invalid addresses, out-of-range parameters
3. **State management tests** - multiple sequential calls, cross-tool dependencies
4. **All 25 tools** - at least smoke test coverage for each
5. **Edge cases** - very large binaries, empty functions, unusual CFGs

Suggested structure:
```
tests/
├── mcp_basic.rs          // Protocol-level tests
├── mcp_tools_core.rs     // Binary loading + analysis tools
├── mcp_tools_query.rs    // Cross-reference and path finding
├── mcp_tools_inspection.rs // Memory and disassembly inspection
├── mcp_error_cases.rs    // Invalid inputs and error paths
└── mcp_integration.rs    // Multi-tool workflows
```

### Priority 3: Add aeon_jit Integration Tests
1. **Complex control flow**: Loops with multiple exits, nested branches, switch statements
2. **Register allocation stress**: High register pressure scenarios
3. **Call graph traversal**: Functions that call other JIT-compiled functions
4. **Memory patterns**: Overlapping memory accesses, aliasing scenarios
5. **Bridge callback verification**: Ensure callbacks see correct register state

### Priority 4: aeon-instrument Mutex Debugging
1. Investigate PoisonError across 9 integration tests
2. Check if tests are properly cleaning up mutex state
3. Consider adding test-level isolation or resource pooling

### Priority 5: Improve Test Documentation
1. Add docstring to each test explaining what invariant it checks
2. Group related tests with comments
3. Create a test matrix showing coverage by instruction category/feature
4. Document known issues and blockers

---

## Test Metrics Summary

| Metric | Value | Status |
|--------|-------|--------|
| Total tests across workspace | 285 | 268 passing, 17 failing |
| aeon_jit unit tests | 85 | 77 passing, 8 failing (91%) |
| aeon_jit integration tests | 2 files | roundtrip, native_smoke |
| MCP tool coverage | 1/25 tools | 4% direct test coverage |
| HTTP tool coverage | 2/25 tools | 8% indirect coverage |
| Branch instruction tests | 3 | 2 passing, 1 failing (67%) |
| SIMD instruction tests | 20+ | 20+ passing |
| Arithmetic instruction tests | 15+ | 15+ passing |

---

## Conclusion

aeon_jit has solid unit test coverage for individual instruction patterns (91% pass rate), but suffers from:
1. **Known failures** in flag-based conditional branches and bridge callback handling
2. **Minimal integration testing** - only 2 integration test files, covering basic roundtrip scenarios
3. **No MCP interface testing** - 25 tools exposed with only 1 smoke test
4. **Limited error case coverage** - no systematic validation of tool parameter ranges and error conditions

The framework is production-ready for basic ELF analysis workflows, but needs targeted test improvements before use in mission-critical autonomous agent applications.
