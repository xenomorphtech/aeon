# Consolidated Implementation Plan

This plan consolidates:

- `docs/next-steps.md`
- `docs/plan-api-integration.md`
- `docs/plan-datalog-evolution.md`
- `docs/plan-eval-framework.md`
- `docs/plan-lifter-emulation.md`
- `roadmap.md`
- `docs/reduction-test-corpus.md`

It also reflects the current codebase state in:

- `Cargo.toml`
- `crates/aeon/Cargo.toml`
- `crates/aeon-reduce/Cargo.toml`
- `crates/aeon-frontend/Cargo.toml`
- `crates/aeon-eval/Cargo.toml`
- `crates/aeonil/Cargo.toml`
- `crates/aeon-reduce/src/lib.rs`
- `crates/aeon-reduce/src/pipeline.rs`
- `crates/aeon/src/api.rs`
- `crates/aeon-frontend/src/service.rs`

## Duplicates and overlaps

| Recommendation | Repeated in | Consolidated decision |
| --- | --- | --- |
| Make reduced IL and SSA a first-class API surface | `docs/next-steps.md`, `docs/plan-api-integration.md`, `roadmap.md`, `docs/plan-eval-framework.md` | Treat reduced IL and SSA as the default machine-facing read path after the reducer foundation is fixed. |
| Wire stack-slot recognition into the live pipeline | `docs/next-steps.md`, `docs/plan-api-integration.md`, `docs/plan-eval-framework.md`, `docs/plan-datalog-evolution.md`, `docs/plan-lifter-emulation.md`, `docs/reduction-test-corpus.md` | Land immediately in `aeon-reduce`, then use a function-level reducer as the canonical whole-function path. |
| Make SSA truly reduction-backed | `docs/next-steps.md`, `docs/plan-api-integration.md`, `docs/plan-eval-framework.md`, `docs/plan-datalog-evolution.md`, `docs/plan-lifter-emulation.md`, `docs/reduction-test-corpus.md` | This is the core dependency for API, evaluation, Datalog facts, and micro-emulation. |
| Use one canonical function-normalization pipeline | `docs/plan-api-integration.md`, `docs/plan-datalog-evolution.md`, `docs/plan-eval-framework.md`, `docs/reduction-test-corpus.md` | Build one shared decode -> reduce -> SSA path and reuse it everywhere. |
| Keep outputs structured and machine-native, not `Debug` strings | `roadmap.md`, `docs/next-steps.md`, `docs/plan-api-integration.md`, `docs/plan-eval-framework.md` | Add explicit JSON view types in `aeon`; do not expose Rust debug formatting as the long-term contract. |
| Add evaluation/golden coverage for reduced IL and SSA | `docs/next-steps.md`, `docs/plan-eval-framework.md`, `roadmap.md`, `docs/reduction-test-corpus.md` | Build real-binary goldens and per-function metrics after the reducer foundation lands. |
| Move Datalog onto normalized reduced IL plus SSA facts | `roadmap.md`, `docs/plan-datalog-evolution.md`, `docs/next-steps.md` | Use reduced IL + SSA as the fact substrate; RC4 becomes the first migrated consumer. |
| Prefer thin frontends and core-crate logic | `roadmap.md`, `docs/plan-api-integration.md`, `docs/next-steps.md` | Add new tool names in `aeon-frontend`, but keep all analysis/build logic in `aeon` and `aeon-reduce`. |
| Delay broad lifter rewrite and broad emulation until reduction/eval are live | `docs/next-steps.md`, `docs/plan-lifter-emulation.md`, `roadmap.md` | Prioritize reduction-backed APIs and eval first; then do targeted lift gaps and bounded execution. |

## Conflicts and chosen direction

- `reduce_block()` immediate patch vs function-level stack handling:
  The docs agree on the immediate readability patch, but the final architecture must use one shared `PrologueInfo` across the whole CFG. Do both: keep `reduce_block()` as a compatibility wrapper and add a function-level reducer for canonical use.
- Dynamic `execute_datalog(query_string)` vs restricted typed query tools:
  `roadmap.md` points toward arbitrary Datalog execution, while `docs/plan-datalog-evolution.md` rejects the current JIT/plugin design. Follow the Datalog evolution plan: typed tools first, restricted in-process query layer later, no host-code JIT as the default.
- Unicorn-first emulation vs AeonIL interpreter-first:
  `roadmap.md` is open-ended, but `docs/plan-lifter-emulation.md` is more concrete and better aligned with current infrastructure. Build a reduced-AeonIL bounded interpreter first and treat Unicorn as a fallback backend only if needed.

## Common themes

- One canonical function-normalization pipeline should feed API responses, evaluation, Datalog facts, and future emulation.
- Stack-slot normalization is the first meaningful abstraction boundary above raw ARM64 register/SP noise.
- SSA is the main substrate for precise dataflow; `RegisterEnv` stays a normalization tool, not the persistent fact model.
- Shared decoded-function caching is necessary to prevent drift between `get_il`, reduction, SSA, coverage, and evaluation.
- Evaluation must be evidence-first: normalized JSON artifacts, real-binary goldens, metric collectors, and SSA validation.
- The frontend should stay thin. New transport/tool names are fine, but all semantic work belongs in `aeon` or `aeon-reduce`.

## Foundational steps that must happen first

These are the true dependency roots for the rest of the project:

1. Make reduction canonical at the function level, not just block-local.
2. Ensure SSA construction consumes reduced IR, including stack-slot rewrites.
3. Preserve `StackSlot` through SSA conversion/build paths.

Without those three, the API work returns the wrong artifact, the Datalog layer extracts facts from noisy IR, the eval layer measures the wrong pipeline, and the micro-emulation plan has no stable reduced substrate to run on.

## Phase 1: Foundation

This phase is intentionally sequential. Everything else depends on it.

1. Split block-local reduction from canonical function-level reduction.
   Complexity: `M`
   Files:
   - `crates/aeon-reduce/src/pipeline.rs`
   - `crates/aeon-reduce/tests/integration.rs`
   Concrete changes:
   - Add `pub fn reduce_block_local(stmts: Vec<Stmt>) -> Vec<Stmt>`.
   - Keep `pub fn reduce_block(stmts: Vec<Stmt>) -> Vec<Stmt>` as the compatibility wrapper that applies `recognize_stack_frame()` after block-local reduction.
   - Add `pub fn reduce_function_cfg(instructions: &[(u64, Stmt, Vec<u64>)]) -> crate::ssa::cfg::Cfg` that:
     - builds CFG once,
     - reduces every block with `reduce_block_local`,
     - detects one shared prologue on the entry block,
     - rewrites stack accesses across all blocks with `rewrite_stack_accesses`.
   Tests:
   - reducer unit test for single-block stack-slot rewrite through `reduce_block()`
   - reducer unit test for cross-block stack-slot rewrite through `reduce_function_cfg()`
   - update integration tests whose expected output now includes `StackSlot`

2. Make `reduce_and_build_ssa()` actually reduce before SSA construction.
   Complexity: `S`
   Files:
   - `crates/aeon-reduce/src/ssa/pipeline.rs`
   Concrete changes:
   - Route `reduce_and_build_ssa()` through `crate::pipeline::reduce_function_cfg(...)`.
   - Build SSA from the reduced CFG, then optimize.
   Tests:
   - end-to-end SSA pipeline test that asserts a reduced stack slot survives into SSA
   - keep existing constant-propagation end-to-end coverage

3. Lock stack-slot handling into SSA conversion/build paths.
   Complexity: `S`
   Files:
   - `crates/aeon-reduce/src/ssa/convert.rs`
   - `crates/aeon-reduce/src/ssa/construct.rs`
   Concrete changes:
   - Preserve `Expr::StackSlot` -> `SsaExpr::StackSlot` conversion explicitly and test it.
   - Verify nested stack-slot loads/stores are preserved through statement conversion and SSA construction.
   Tests:
   - `convert_expr()` test for `Expr::StackSlot`
   - `convert_stmt()` test for stack-slot-backed `Store`
   - reduction-backed SSA test that observes `SsaExpr::StackSlot`

## Phase 2: Parallel tracks

These tracks can run simultaneously once Phase 1 is merged.

### Track A: API and frontend integration

- Goal:
  Expose reduced IL, SSA, and stack-frame summaries as structured tools.
- Complexity: `L`
- Files:
  - `crates/aeon/src/api.rs`
  - `crates/aeon/src/engine.rs`
  - `crates/aeon/src/function_ir.rs` (new)
  - `crates/aeon-frontend/src/service.rs`
  - `crates/aeon-frontend/src/main.rs`
- Concrete work:
  - Add decoded-function/session artifact caching in `AeonSession`.
  - Add `get_reduced_il(addr, ...)`, `get_ssa(addr, ...)`, `get_stack_frame(addr, ...)`.
  - Add explicit JSON view types for reduced IL and SSA.
  - Register thin MCP/HTTP tool schemas without changing transport.
- Tests:
  - `aeon` API tests for JSON shape and stack-slot visibility
  - frontend schema registration tests
  - `/call` and MCP smoke tests

### Track B: Evaluation and regression harness

- Goal:
  Add real-binary goldens, SSA validation, and reduction metrics.
- Complexity: `L`
- Files:
  - `crates/aeon-eval/src/lib.rs`
  - `crates/aeon-eval/src/main.rs`
  - `eval/corpus/*` (new)
  - `eval/goldens/*` (new)
  - `crates/aeon/src/api.rs`
- Concrete work:
  - Add `evaluate_reduced_il_golden(...)`, `evaluate_ssa_golden(...)`, `evaluate_reduction_metrics(...)`.
  - Add SSA validator.
  - Extend coverage reporting with reduction/SSA metrics.
- Tests:
  - smoke corpus manifests
  - golden diff tests
  - validator correctness tests

### Track C: Shared fact substrate and Datalog migration

- Goal:
  Move analyses from ad hoc extraction onto cached reduced IL + SSA facts.
- Complexity: `L`
- Files:
  - `crates/aeon/src/engine.rs`
  - `crates/aeon/src/analysis.rs`
  - `crates/aeon/src/rc4_search.rs`
  - `crates/aeon/src/facts.rs` or equivalent (new)
- Concrete work:
  - Add cached `FunctionAnalysis`/`FactDb` in `AeonEngine`.
  - Emit structural, reduced IL, SSA, dominance, and solved-constant relations.
  - Rebuild RC4 over shared facts.
  - Add typed query helpers for slices, defs/uses, and constrained reachability.
- Tests:
  - fact extraction snapshots
  - RC4 regression comparison against current behavior
  - query helper unit tests

### Track D: Targeted lifter gaps and bounded execution

- Goal:
  Improve the reduced substrate where it has the highest payoff and add a narrow executor.
- Complexity: `L`
- Files:
  - `crates/aeon/src/lifter.rs`
  - `crates/aeon/src/engine.rs`
  - `crates/aeon/src/api.rs`
  - `crates/aeon/src/emulation.rs` or equivalent (new)
  - `crates/aeon-frontend/src/service.rs`
- Concrete work:
  - Extend coverage reporting with intrinsic/opcode breakdowns.
  - Add first-class lowering for bitfield ops and `CCMP` / `CCMN`.
  - Add a reduced-AeonIL bounded snippet executor.
  - Expose structured emulation results through typed tools.
- Tests:
  - opcode-specific lifter tests
  - bounded executor state-transition tests
  - real-binary snippet smoke tests

## Phase 3: Integration

1. Unify all consumers on one cached function-analysis artifact.
   Complexity: `M`
   Files:
   - `crates/aeon/src/api.rs`
   - `crates/aeon/src/engine.rs`
   - `crates/aeon-eval/src/lib.rs`
   Tests:
   - assert API, eval, and coverage all consume the same normalized function path

2. Expose typed agent workflows on top of normalized facts.
   Complexity: `M`
   Files:
   - `crates/aeon/src/api.rs`
   - `crates/aeon-frontend/src/service.rs`
   Tests:
   - slice/def-use/behavior-template contract tests

3. Extend coverage and evaluation reports to guide the next investment.
   Complexity: `M`
   Files:
   - `crates/aeon/src/api.rs`
   - `crates/aeon-eval/src/lib.rs`
   - `crates/aeon-frontend/src/main.rs`
   Tests:
   - corpus summary regression tests

4. Only after the above is stable, evolve `survey` from opcode survey into orchestration.
   Complexity: `L`
   Files:
   - `crates/survey/src/main.rs`
   Tests:
   - headless multi-stage pipeline smoke tests

## Immediate implementation target

This change set implements Phase 1 only:

- function-level reduction helper in `aeon-reduce`
- reduction-backed `reduce_and_build_ssa()`
- explicit stack-slot conversion coverage in SSA tests
