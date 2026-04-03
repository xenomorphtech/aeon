# Evaluation Plan for Reduction and SSA

## Baseline

- `aeon-eval` already has a useful generic model (`CorpusEntry`, `TaskSpec`, `EvaluationRun`, evidence/claim/metric payloads), but it only has one concrete evaluator today: constructor-object-layout.
- `aeon-eval` CLI only exposes `constructor-layout`.
- `aeon-reduce` is well covered at the crate level, but almost entirely with synthetic `Vec<Stmt>` fixtures. On April 3, 2026, `cargo test -p aeon-reduce --quiet` passed `192` crate tests plus `6` integration tests.
- The current end-to-end gaps are real:
  - `crates/aeon-reduce/src/pipeline.rs` does not call `recognize_stack_frame()`.
  - `crates/aeon-reduce/src/ssa/pipeline.rs` claims “reduce -> CFG -> SSA -> optimize” but currently builds CFG/SSA directly from raw lifted statements.
  - `AeonSession::get_coverage()` only reports lift quality (`proper_il`, `intrinsic`, `nop`, `decode_errors`), not reduction quality or SSA quality.
- Current whole-binary lift baseline on the repo-local `libUnreal.so`:
  - SHA-256: `430eba84d24d37f9d0b39073b1f8ab3bce2491adc7fe77db13a09428083dcefe`
  - `proper_il=97.88%`
  - `intrinsic=1.91%`
  - `nop=0.12%`
  - `decode_errors=0.0873%`

Verified seed functions/slices in `libUnreal.so`:

- `0x5e66990`: short constructor/prologue case already used by constructor-layout evaluation. It contains pair flattening, SP-relative stack accesses, ADRP+ADD resolution, a call, and an epilogue.
- `0x17cd08c <Java_com_epicgames_unreal_GameActivity_nativeIsShippingBuild>`: large real function with ADRP+ADD, `cmp`/`csel`, `tst`/`cset`, `cmp`/`b.ne`, `cbz`, and stack traffic.
- `0x17d5868 <Java_com_epicgames_unreal_GameActivity_nativeSetConfigRulesVariables>`: contains a verified MOVK chain at `0x17d6024..0x17d6044`.

## 1. Extending `aeon-eval` Beyond Constructor Layout

### Immediate modeling approach

Do not block on enum churn. The existing `TaskKind::Custom(String)` and `EvidenceKind::Custom(String)` are enough to land the first reduction/SSA tasks. Add dedicated enum variants later only after the artifact shape stabilizes.

### New evaluation targets

Add function-focused evaluators that all share the same input shape:

```rust
pub struct FunctionEvalTarget {
    pub corpus_entry_id: String,
    pub binary_path: String,
    pub binary_sha256: String,
    pub function_addr: u64,
    pub context: EvalContext,
    pub slice: Option<AddressRange>,
    pub tags: Vec<String>,
}

pub enum EvalContext {
    WholeFunction,
    WholeFunctionSnapshotSlice,
}

pub struct AddressRange {
    pub start: u64,
    pub stop: u64,
}
```

`WholeFunctionSnapshotSlice` is important: reduction needs full-function context for stack-frame recognition and SSA, but the golden artifact should often only snapshot a stable address window or block.

### New evaluators

Add these runners in `crates/aeon-eval/src/lib.rs`:

1. `evaluate_reduced_il_golden(target, golden_path)`
   - Load function.
   - Lift once through the same session ingestion path used by future API tools.
   - Run block reduction.
   - Normalize the reduced artifact.
   - Compare to a checked-in golden JSON file.
   - Emit evidence for raw IL, reduced IL, and diff summary.

2. `evaluate_ssa_golden(target, golden_path, optimize: bool)`
   - Build raw SSA and reduction-backed SSA.
   - Validate SSA invariants.
   - Normalize and compare snapshot output.
   - Emit evidence for pre-opt SSA, post-opt SSA, and invariant report.

3. `evaluate_reduction_metrics(target)`
   - Run the per-function metric collector.
   - Emit only metrics and pass/fail threshold checks.
   - Useful for large functions where full goldens are too brittle.

4. `evaluate_corpus_manifest(manifest_path)`
   - Batch entry point that returns one `EvaluationRun` per target and an aggregate summary artifact.

### Evidence bundles to attach

Each reduction/SSA run should emit:

- `raw_il`
- `reduced_il`
- `ssa_raw`
- `ssa_reduced`
- `ssa_optimized`
- `ssa_validation`
- `metric_snapshot`
- `golden_diff` when a regression occurs

Use `JsonArtifact` or `Custom("reduced_il")` / `Custom("ssa_function")` until the schema settles.

### SSA correctness checks

Real-binary SSA evaluation should not rely only on snapshot diffs. Add a machine-checkable validator and fail the run if any invariant breaks:

- every `SsaVar` has exactly one definition
- every non-entry use resolves to a definition or phi input
- phi operand count matches live predecessor count
- no orphan predecessor or successor references remain after dead-block elimination
- widths stay consistent across reads/writes and phi merges
- no raw `Reg`/`Stmt` nodes survive inside SSA artifacts

That validator is the minimal “SSA correctness on real binaries” layer even before equivalence checking or emulation exists.

## 2. Golden Regression Tests That Catch Reduction Regressions

The current crate-local tests already catch local rewrite bugs. The missing layer is session/API-level goldens on real binaries.

### Golden format rules

- Store normalized JSON, not `Debug` strings.
- Canonicalize block ordering by address.
- Canonicalize SSA block IDs and variable numbering so harmless renumbering does not churn snapshots.
- Strip non-semantic noise such as disassembly text unless the test explicitly wants it.
- Record `binary_sha256` and a per-function byte hash alongside every golden.

### Concrete smoke goldens

1. `libunreal_ctor_5e66990_reduced`
   - Context: full function `0x5e66990`
   - Snapshot: full reduced function
   - Must assert:
     - `Pair` prologue/epilogue are flattened
     - frame size is recognized as `0x20`
     - `[sp,#0x10]` store/load become `StackSlot { offset: 16, size: 8 }`
     - ADRP+ADD sequences resolve to `0x8dc3738`, `0x8db2808`, and `0x8db27c8`
     - no `AdrpImm` remains in the reduced artifact
   - Catches: pair flattening, stack-slot recognition, ADRP resolution, epilogue handling

2. `libunreal_shipping_build_cmp_csel_slice`
   - Context: full function `0x17cd08c`
   - Snapshot slice: `0x17cd124..0x17cd168`
   - Must assert:
     - stack loads from `[sp,#0x10]` and `[sp,#0x8]` reduce to stack slots
     - `adrp x10, 0x508000; add x10, x10, #0x8b6` reduces to `0x5088b6`
     - `cmp w8, #0; csel x0, x10, x9, eq` becomes a fused compare/select form
     - no standalone `SetFlags` survives between the compare and select
   - Catches: ADRP resolution, flag fusion for `csel`, stack-slot propagation into fused expressions

3. `libunreal_shipping_build_tst_cset_branch_slice`
   - Context: full function `0x17cd08c`
   - Snapshot slice: `0x17cdc74..0x17cdc84`
   - Must assert:
     - `tst ...; cset ...` fuses to `Expr::Compare`
     - `cmp x8, x9; b.ne ...` becomes `BranchCond::Compare`
     - dead flag writes are removed
   - Catches: multiple flag consumers in one real function, flag liveness bugs, branch fusion regressions

4. `libunreal_config_rules_movk_slice`
   - Context: full function `0x17d5868`
   - Snapshot slice: `0x17d6024..0x17d6044`
   - Must assert:
     - MOV/MOVK chain resolves to `0x0006050403070201`
     - no `Intrinsic("movk")` remains in the reduced slice
     - the compare after materialization still references the correct value
   - Catches: MOVK chain folding and constant propagation regressions

5. `libunreal_shipping_build_ssa_validate`
   - Context: full function `0x17cd08c`
   - Snapshot: normalized SSA summary plus selected merge/branch blocks
   - Must assert:
     - SSA validator passes
     - phi arities match predecessor counts
     - optimized block count does not increase
     - optimized SSA variable count is strictly lower than raw SSA variable count
   - Catches: CFG/phi bugs, bad dead-branch cleanup, accidental loss of SSA benefit

### Negative-control goldens

For each pass, keep one “must not rewrite” case. These can be small real binaries or tiny compiled fixtures if a stable real-binary slice is hard to freeze.

- ADRP clobbered before ADD: must stay unresolved
- `cbz`/`cbnz`: must stay `Zero`/`NotZero`, not compare-on-flags
- X29 without frame-pointer setup: must not become `StackSlot`
- broken MOVK chain after clobber: must not collapse

The existing unit tests still carry most of the micro-semantics; the goldens should focus on end-to-end regressions that emerge only once lifting, block splitting, reduction, and SSA interact.

## 3. Metric Definitions

Report every metric both per function and in aggregate. Always include raw counts next to percentages.

### Stack-slot recognition rate

Definition:

```text
eligible_stack_accesses =
  count of loads/stores in functions with a detected prologue whose raw address is:
  - Reg(SP)
  - Add(Reg(SP), Imm(_))
  - Reg(X29)
  - Add(Reg(X29), Imm(_)) when has_frame_pointer=true

recognized_stack_slots =
  count of those accesses whose reduced address becomes Expr::StackSlot

stack_slot_recognition_rate = recognized_stack_slots / eligible_stack_accesses
```

Also report:

- `functions_with_prologue`
- `functions_with_stack_slots`
- `missed_fp_relative_accesses`

### ADRP resolution rate

Definition:

```text
eligible_adrp_sequences =
  count of block-local ADRP definitions that feed:
  - ADD reg, reg, imm
  - Load/Store address expressions
  - Call/Branch targets
  before the register is clobbered

resolved_adrp_sequences =
  count of eligible sequences whose reduced result contains the final Imm(resolved_addr)

adrp_resolution_rate = resolved_adrp_sequences / eligible_adrp_sequences
```

Also report:

- `unresolved_due_to_clobber`
- `unresolved_due_to_cross_block_use`
- `resolved_addrs_sample`

### Flag fusion rate

Definition:

```text
eligible_flag_consumers =
  count of CondBranch(Flag(_)) and CondSelect/CSET users with a dominating same-block SetFlags
  and no intervening flag-clobber

fused_flag_consumers =
  count of eligible consumers rewritten to:
  - BranchCond::Compare
  - Expr::Compare

flag_fusion_rate = fused_flag_consumers / eligible_flag_consumers
```

Also split by consumer kind:

- `branch_flag_fusion_rate`
- `select_flag_fusion_rate`

### SSA variable count reduction

Track all three stages:

```text
raw_ssa_var_count =
  unique SSA vars when building SSA directly from lifted IL

reduced_ssa_var_count =
  unique SSA vars when building SSA from reduced IL before cross-block optimizations

optimized_ssa_var_count =
  unique SSA vars after SCCP + dead-branch + copy-prop + CSE + DCE

ssa_variable_count_reduction_pct =
  (raw_ssa_var_count - optimized_ssa_var_count) / raw_ssa_var_count
```

Also report:

- `raw_phi_count`
- `optimized_phi_count`
- `raw_block_count`
- `optimized_block_count`
- `ssa_validator_failures`

This metric is the clearest proof that reduction is buying something before analysis begins.

### Intrinsic-to-proper-IL ratio

For whole-binary coverage:

```text
intrinsic_to_proper_il_ratio = intrinsic_count / proper_il_count
```

For reduction reports:

```text
residual_intrinsic_to_reduced_proper_ratio =
  residual_intrinsic_stmt_count / reduced_proper_stmt_count
```

Both matter:

- raw ratio tells you how much lift debt remains
- residual ratio tells you how much reduction is still blocked by unresolved intrinsics

## 4. Building a Real-Binary Evaluation Corpus

### Corpus layout

Create a repo-root `eval/` tree so the same assets are shared by `aeon-eval`, `aeon`, and frontend tests:

```text
eval/
  corpus/
    libunreal-reduction-smoke.json
    libunreal-reduction-full.json
  goldens/
    libunreal/
      430eba84d24d37f9d0b39073b1f8ab3bce2491adc7fe77db13a09428083dcefe/
        ctor_5e66990.reduced.json
        shipping_build_cmp_csel.slice.json
        shipping_build_flags_branch.slice.json
        set_config_rules_movk.slice.json
        shipping_build.ssa.json
```

### Manifest shape

```json
{
  "id": "libunreal-reduction-smoke",
  "binary": "libUnreal.so",
  "binary_sha256": "430eba84d24d37f9d0b39073b1f8ab3bce2491adc7fe77db13a09428083dcefe",
  "targets": [
    {
      "id": "ctor_5e66990",
      "function_addr": "0x5e66990",
      "context": "whole_function",
      "tags": ["pair", "stack", "adrp", "epilogue"]
    },
    {
      "id": "shipping_build_cmp_csel",
      "function_addr": "0x17cd08c",
      "context": "whole_function_snapshot_slice",
      "slice": { "start": "0x17cd124", "stop": "0x17cd168" },
      "tags": ["stack", "adrp", "cmp", "csel"]
    },
    {
      "id": "set_config_rules_movk",
      "function_addr": "0x17d5868",
      "context": "whole_function_snapshot_slice",
      "slice": { "start": "0x17d6024", "stop": "0x17d6044" },
      "tags": ["movk", "const-materialization"]
    }
  ]
}
```

### How to populate the corpus

1. Index all discovered functions once.
2. Run cheap pattern detectors over lifted IL or disassembly:
   - `Stmt::Pair` for pair flattening
   - `Expr::AdrpImm` followed by same-reg `Add` for ADRP
   - `Intrinsic("movk")` for MOVK
   - `SetFlags` + `CondBranch(Flag(_))` / `CondSelect` for flag fusion
   - prologue patterns plus SP/FP-relative loads/stores for stack slots
   - CFG backedges and merge blocks for SSA/phi coverage
3. Score candidates by:
   - shortest stable function or slice
   - highest pass density
   - low external noise
   - available symbol name when possible
4. Freeze only a small smoke set first:
   - 1 to 2 positive seeds per pass
   - 1 negative control per pass family
5. Expand to a full corpus later with broader coverage and trend metrics.

### Recommended binary mix

Use more than one binary class:

- `libUnreal.so` for large optimized C++ reality
- one small repo-local ARM64 ELF compiled specifically for reduction/SSA coverage
- one medium system/library binary when reproducibility is acceptable

The small binary is not a substitute for real binaries; it is where false-positive and near-miss cases stay stable.

## 5. Integrating With the Existing Coverage Command

The current `aeon coverage <binary>` output is the right base layer. Keep it, and add reduction/SSA reporting next to it rather than inventing a second reporting command.

### Collector structure

Factor coverage into two reusable collectors:

1. `LiftCoverageCollector`
   - current whole-`.text` counts
   - intrinsic/proper/nop/decode-error breakdown

2. `ReductionCoverageCollector`
   - runs on a corpus manifest or a sampled function set
   - emits:
     - stack-slot recognition
     - ADRP resolution
     - flag fusion
     - SSA variable count reduction
     - residual intrinsic ratio
     - SSA validator failures

### CLI/API shape

Add optional reduction arguments:

```text
aeon coverage libUnreal.so
aeon coverage libUnreal.so --reduction-corpus eval/corpus/libunreal-reduction-smoke.json
aeon coverage libUnreal.so --reduction-corpus eval/corpus/libunreal-reduction-full.json
```

Suggested JSON shape:

```json
{
  "lift": {
    "proper_il": 27513849,
    "intrinsic": 537435,
    "intrinsic_to_proper_il_ratio": 0.01953
  },
  "reduction": {
    "functions_scanned": 5,
    "stack_slot_recognition": { "recognized": 18, "eligible": 18, "rate": 1.0 },
    "adrp_resolution": { "resolved": 9, "eligible": 9, "rate": 1.0 },
    "flag_fusion": { "fused": 6, "eligible": 7, "rate": 0.8571 },
    "ssa": {
      "raw_var_count": 412,
      "optimized_var_count": 287,
      "variable_count_reduction_pct": 0.3034,
      "validator_failures": 0
    },
    "residual_intrinsic_to_reduced_proper_ratio": 0.0021
  }
}
```

### Important implementation detail

Use one shared function-ingestion path for:

- raw IL listing
- reduced IL
- SSA construction
- metric collection
- coverage output

If coverage computes reduction statistics through a different path than `aeon-eval` or the future MCP tools, the numbers will drift and the reports will not be trustworthy.

## Recommended Rollout

1. Fix the live pipeline first:
   - call `recognize_stack_frame()` from `reduce_block()`
   - make `reduce_and_build_ssa()` actually reduce before SSA
2. Add a normalized reduced-IL/SSA session API.
3. Land the `libUnreal.so` smoke corpus and the four golden tests above.
4. Add the metric collector and SSA validator.
5. Extend `aeon coverage` to emit reduction reports from a manifest.
6. Expand from smoke corpus to full corpus only after the artifact format is stable.

This gives `aeon` three layers of confidence instead of one:

- local rewrite correctness (`aeon-reduce` unit tests)
- real-binary golden regressions (reduction/SSA snapshots)
- trend metrics (`coverage` + corpus reports)
