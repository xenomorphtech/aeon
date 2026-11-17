# Phase 2: aeon_jit Testing Expansion Plan

**Date**: 2026-04-18  
**Status**: Planning  
**Phase 1 Summary**: ✅ Completed - 102 MCP integration tests, all passing

---

## Strategic Assessment

### Current State
- **aeon_jit**: 77/85 unit tests passing (91%), 8 known failures
- **MCP interface**: 102 new tests (Phase 1) ✅
- **Roadmap**: 6 workstreams defined, Workstreams 1-4 in planning/early implementation
- **Test coverage gaps**: Integration tests, error cases, boundary conditions

### Options for Phase 2

| Option | Value | Effort | Dependencies |
|--------|-------|--------|--------------|
| **Workstream 1 Testing** | 🔥 Very High | Medium | core aeon_jit tests |
| **Coverage Metrics** | 🔥 Very High | Low | existing tests |
| **Boundary Cases** | Medium | Medium | core tests stable |
| **Fix aeon_jit Failures** | 🔥 Very High | High | root cause analysis |

### Recommendation

**Implement Phase 2 as a two-part initiative:**

**Part A (Priority 1):** Fix aeon_jit failures + implement Workstream 1 token-efficient topology testing
- Unblock Workstream 1 implementation
- Resolve 8 known test failures
- Add test coverage for new `get_function_skeleton` and `get_data_flow_slice` tools
- **Value**: Enables agent triage workflow, fixes framework issues

**Part B (Priority 2):** Comprehensive test coverage improvements
- Add coverage metrics for Phase 1 (MCP tests)
- Implement boundary case testing for aeon_jit
- Add integration tests for complex control flow
- **Value**: Improves test robustness, prevents regressions

---

## Part A: Workstream 1 Token-Efficient Topology + aeon_jit Fixes

### A1: Fix aeon_jit Test Failures (8 tests)

**Current failures:**
1. 7 flag-conditional branch tests (branch target address returns 0)
2. 1 bridge callback test (invoked 3x instead of 1x)

**Investigation plan:**
- [ ] Debug flag conditional branch compilation
  - Trace Cranelift IL generation for SetFlags + CondBranch
  - Verify condition evaluation propagates to return value
  - Check JIT entry point for register state setup
  
- [ ] Debug bridge callback invocation count
  - Add logging to bridge callback registration
  - Verify BRIDGE_COUNT reset per test
  - Determine if called during compile vs. execute phase

**Expected outcome:** 85/85 unit tests passing

### A2: Implement Workstream 1 Features

#### Feature 1: `get_function_skeleton` Tool

**Purpose**: Agents decide whether to read full IL/assembly by getting dense function summary

**Implementation**:
```rust
// crates/aeon/src/api.rs
pub fn get_function_skeleton(&self, addr: u64) -> Result<Value, String> {
  // Returns:
  // - arg_count: number of parameters
  // - calls: [target addresses or names]
  // - strings: local string references
  // - loops: count of detected loops
  // - crypto_constants: known crypto material
  // - stack_frame_size: local variable space
  // - suspicious_patterns: potential obfuscation
}

// crates/aeon-frontend/src/service.rs
fn tool_get_function_skeleton(&self, args: &Value) -> Result<Value, String> {
  // MCP dispatch
}
```

**Test coverage needed:**
- [ ] Skeleton for simple function (no loops, no calls)
- [ ] Skeleton for function with multiple calls
- [ ] Skeleton for function with string references
- [ ] Skeleton for function with loops
- [ ] Skeleton for function with crypto operations
- [ ] Error handling (invalid address, unmapped address)

#### Feature 2: `get_data_flow_slice` Tool

**Purpose**: Agents get backward/forward slices on single values without reading whole function

**Implementation**:
```rust
// crates/aeon/src/analysis.rs
pub fn compute_backward_slice(target_addr: u64, register: Reg) -> Vec<Instruction> {
  // Return instructions that contribute to target_register at target_addr
}

pub fn compute_forward_slice(start_addr: u64, register: Reg) -> Vec<Instruction> {
  // Return instructions that consume start_register
}

// crates/aeon-frontend/src/service.rs
fn tool_get_data_flow_slice(&self, args: &Value) -> Result<Value, String> {
  // MCP dispatch with mode: "backward" | "forward"
}
```

**Test coverage needed:**
- [ ] Simple backward slice (direct assignment)
- [ ] Complex backward slice (through multiple operations)
- [ ] Backward slice with loop iterations
- [ ] Forward slice to consumer instruction
- [ ] Forward slice through multiple consumers
- [ ] Slice with invalid register
- [ ] Slice with unmapped address

### A3: Add Tests for Workstream 1 Tools

**New test file**: `crates/aeon-frontend/tests/mcp_workstream1.rs`

**Test structure:**
```
mcp_workstream1.rs (40+ tests)
├── function_skeleton tests (15 tests)
│   ├── Simple functions (no loops, no calls)
│   ├── Complex functions (calls, loops, strings)
│   ├── Edge cases (empty functions, large functions)
│   └── Error cases (invalid addresses)
└── data_flow_slice tests (25 tests)
    ├── Backward slice tests (10 tests)
    ├── Forward slice tests (10 tests)
    └── Edge cases (loops, calls, invalid registers)
```

**Expected results:** 40+ new tests, all passing

### A4: Deliverables for Part A

| Item | Status | Tests |
|------|--------|-------|
| Fix aeon_jit failures | Planned | 8 fixed |
| Implement `get_function_skeleton` | Planned | 15 tests |
| Implement `get_data_flow_slice` | Planned | 25 tests |
| **Total new tests** | — | **40+** |
| **aeon_jit tests passing** | Target | **85/85** |

---

## Part B: Test Coverage Improvement

### B1: Coverage Metrics for Phase 1 (MCP Tests)

**Objective**: Understand test coverage depth for MCP integration tests

**Analysis needed:**
- [ ] Code coverage measurement (tools, branches, statements)
  - `cargo tarpaulin` or `cargo llvm-cov` for coverage metrics
  - Identify uncovered MCP tool paths
  - Identify uncovered error paths
  
- [ ] Test matrix creation
  - Map tests to tools (25 tools × test coverage)
  - Identify untested tool combinations
  - Document coverage gaps

**Deliverable**: Coverage report showing % of lines/branches covered by Phase 1 tests

### B2: aeon_jit Boundary Case Analysis

**Objective**: Systematically test edge cases in aeon_jit instruction compilation

**New test file**: `crates/aeon-jit/tests/boundary_cases.rs`

**Test areas:**
1. **Register pressure** (10 tests)
   - All 31 ARM64 registers used simultaneously
   - Register spillage patterns
   - Nested function calls with register preservation

2. **Memory edge cases** (10 tests)
   - Misaligned memory access
   - Overlapping memory writes and reads
   - Large memory operations (> 128 bytes)
   - Memory at boundary addresses (0x0, max address)

3. **Control flow extremes** (10 tests)
   - Deep nesting (10+ levels of branches)
   - Large switch statements
   - Loop with many iterations
   - Unreachable code paths

4. **Operand boundaries** (10 tests)
   - Minimum/maximum immediate values
   - Zero operands
   - Negative operands
   - Shift counts at boundaries

**Expected**: 40 new tests covering edge cases

### B3: aeon_jit Integration Tests

**Objective**: Exercise full compilation pipeline with complex scenarios

**New test file**: `crates/aeon-jit/tests/integration_complex.rs`

**Test scenarios:**
1. **Complex control flow** (5 tests)
   - Nested loops
   - Nested branches
   - Loop with early exit
   - Switch with fallthrough
   - Function with multiple return paths

2. **Bridge callback scenarios** (5 tests)
   - Unresolved branch with register state
   - Multiple bridges in single block
   - Bridge preserving register values
   - Bridge with memory side effects

3. **Cross-block patterns** (5 tests)
   - Multiple blocks in sequence
   - Blocks with shared memory
   - Blocks with shared registers
   - Block composition patterns

**Expected**: 15 new integration tests

### B4: Deliverables for Part B

| Item | Tests | Effort |
|------|-------|--------|
| Coverage metrics | N/A | Low |
| Boundary cases (aeon_jit) | 40 | Medium |
| Integration tests (aeon_jit) | 15 | Medium |
| **Total new tests** | **55** | — |

---

## Implementation Timeline

### Phase 2A: Workstream 1 + aeon_jit Fixes (Weeks 1-2)

**Week 1:**
- [ ] Investigate + fix 8 aeon_jit failures
- [ ] Implement `get_function_skeleton` tool
- [ ] Write 15 tests for function skeleton

**Week 2:**
- [ ] Implement `get_data_flow_slice` tool
- [ ] Write 25 tests for data flow slice
- [ ] Integration testing + bug fixes

**Expected outcome:** 
- 8 aeon_jit failures fixed ✅
- 40 new tests passing ✅
- Workstream 1 tools ready for agent use ✅

### Phase 2B: Coverage Improvements (Weeks 3-4)

**Week 3:**
- [ ] Run coverage metrics on Phase 1 tests
- [ ] Implement boundary case tests for aeon_jit
- [ ] Debug and fix edge cases

**Week 4:**
- [ ] Implement integration tests for complex control flow
- [ ] Final testing and bug fixes
- [ ] Documentation and summary

**Expected outcome:**
- Coverage report generated ✅
- 55 new tests passing ✅
- Test matrix created ✅

---

## Success Criteria

### Part A Success
- ✅ All 8 aeon_jit failures fixed (85/85 tests passing)
- ✅ `get_function_skeleton` tool implemented and tested (15 tests)
- ✅ `get_data_flow_slice` tool implemented and tested (25 tests)
- ✅ Tools integrated into MCP frontend
- ✅ Documentation updated in README

### Part B Success
- ✅ Coverage metrics report generated
- ✅ Boundary cases identified and tested (40 tests)
- ✅ Integration tests for complex scenarios (15 tests)
- ✅ All new tests passing
- ✅ Coverage improved to 95%+ for Phase 1 tests

### Overall Phase 2 Success
- ✅ 95+ new tests implemented
- ✅ aeon_jit test suite 100% passing
- ✅ Workstream 1 features ready for agents
- ✅ Coverage metrics document created
- ✅ All work committed with clear messages

---

## Rationale

### Why Workstream 1 First?
1. **Enables agent efficiency**: Function skeleton helps agents make token-smart decisions
2. **High-value feature**: Critical for autonomous agent triage workflow
3. **Builds on Phase 1**: Uses existing tool infrastructure
4. **Unblocks other workstreams**: Data flow slices enable datalog queries (Workstream 2)

### Why Fix aeon_jit Failures?
1. **Unblocks development**: 8 known failures prevent progress
2. **Simple ROI**: Each failure is likely root-cause analyzable
3. **Improves confidence**: Ensures framework stability
4. **Prerequisite for advanced tests**: Complex scenarios need stable base

### Why Coverage Metrics?
1. **Quality assurance**: Understand test depth vs. breadth
2. **Identify gaps**: Systematic view of uncovered scenarios
3. **Regression prevention**: Can measure coverage regressions
4. **Credibility**: Demonstrates thorough testing to stakeholders

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| aeon_jit failures hard to fix | Medium | High | Root-cause analysis first; consider deferring |
| Workstream 1 design unclear | Low | Medium | Refer to roadmap.md; validate design before coding |
| Coverage metrics show large gaps | Medium | Low | Expected; identify priority gaps |
| Boundary tests find new bugs | Medium | Low | Expected; fix bugs as found |

---

## Conclusion

**Phase 2 recommended approach:**
- **Part A (Priority 1)**: Fix aeon_jit failures + Workstream 1 token-efficient topology (40+ tests, ~2 weeks)
- **Part B (Priority 2)**: Coverage metrics + boundary cases + integration tests (55+ tests, ~2 weeks)
- **Total**: 95+ new tests, 100% aeon_jit pass rate, Workstream 1 ready for agents

This approach:
1. ✅ Unblocks Workstream 1 (critical for roadmap)
2. ✅ Fixes framework issues (8 failures)
3. ✅ Improves test quality (coverage + boundary cases)
4. ✅ Maintains momentum (build on Phase 1 success)
5. ✅ Delivers concrete agent-facing features

**Next step**: Proceed with implementation plan approval and start Part A Week 1 work.
