# aeon Next Steps

This prioritization is based on:

- `roadmap.md`
- `docs/reduction-test-corpus.md`
- the current workspace/crate split
- recent commits through `25cfccf` on April 2, 2026

## Current State

- `aeon-reduce` is the newest major capability and is already well tested in isolation (`198` tests passing in `aeon-reduce`).
- `aeon-frontend` still exposes the older analysis surface only; agents cannot yet call reduction or SSA tooling over MCP/HTTP.
- `aeon-reduce::pipeline::reduce_block()` does not currently call stack-frame recognition, even though `reduce_stack.rs` implements it.
- `aeon-reduce::ssa::pipeline::reduce_and_build_ssa()` currently builds CFG/SSA directly from raw lifted statements without first running reduction.
- Existing IL endpoints return per-instruction debug strings, not machine-native reduced IL / SSA artifacts.
- Real-binary lifter coverage is already strong: on `libUnreal.so`, `proper_il=97.88%`, `intrinsic=1.91%`, `nop=0.12%`, `decode_errors=0.0873%`.
- `aeon-eval` and `survey` are still narrow: `aeon-eval` mostly covers constructor-layout evaluation, and `survey` is still an opcode survey rather than an orchestrator.

## Prioritized Next Steps

1. **Make `aeon-reduce` a first-class API surface in `aeon` and `aeon-frontend`.**

   Concrete work:
   - Add `AeonSession` methods that lift a function once, split it into blocks, run reduction, and optionally build optimized SSA.
   - Expose that through MCP/HTTP tools such as `get_reduced_il(addr)` and `build_ssa(addr, optimize=true)`.
   - Return structured JSON for reduced blocks and SSA, not `Debug` strings.
   - Reuse one shared function-ingestion path so `get_il`, CFG, reduction, and SSA all operate on the same decoded instruction stream.

   Rationale:
   - This is the highest-leverage move because it turns the last major commit into something agents can actually use.
   - It matches the roadmap's machine-native interface goal and immediately lowers token cost for analysis.
   - It will also flush out real integration gaps faster than adding another large subsystem.

2. **Wire stack-slot recognition into the live reduction pipeline immediately.**

   Concrete work:
   - Add `recognize_stack_frame()` to the end of `reduce_block()`.
   - Ensure the function-level reduction path preserves `Expr::StackSlot` in API responses and SSA conversion.
   - Add end-to-end tests at the API/tool layer that verify stack slots appear in reduced output for real prologues.

   Rationale:
   - This is already implemented and tested, so the cost is low and the payoff is immediate.
   - Stack slots are one of the biggest readability wins in reduced IL.
   - They are also the prerequisite for any useful local-variable promotion, slot typing, or mem2reg-style work.

3. **Fix the “reduce + SSA” path so it actually reduces before SSA, then build on that with stack-local promotion.**

   Concrete work:
   - Change `reduce_and_build_ssa()` to reduce each basic block before SSA construction.
   - Once stack slots are live, promote eligible stack locals into SSA variables or at least treat them as first-class symbolic locations.
   - Feed the cleaner SSA into downstream analyses that currently reason over raw registers and memory noise.

   Rationale:
   - Right now the naming and documentation promise more than the implementation delivers.
   - Clean SSA is where the reduction work compounds: fewer raw register artifacts, fewer fake memory operations, better constant propagation, and cleaner future slicing/dataflow.
   - This is a better immediate use of the new infrastructure than starting a fresh workstream.

4. **Add an evaluation and regression layer for reduced IL / SSA outputs before taking on more major capability work.**

   Concrete work:
   - Turn `docs/reduction-test-corpus.md` into tracked fixtures or golden outputs at the session/API layer, not just crate-local unit tests.
   - Extend `aeon-eval` beyond constructor layout with reduction/SSA tasks and evidence bundles.
   - Record simple metrics such as stack-slot recognition rate, SSA simplification rate, and intrinsic-family counts on representative binaries.

   Rationale:
   - The project now has enough moving parts that “tests pass in one crate” is not enough.
   - This gives a data-backed way to decide whether the next investment should go into lifter coverage, emulation, or additional query surfaces.
   - It also protects the thin-frontend goal by forcing clear contracts for tool outputs.

5. **Prototype micro-emulation narrowly after the reduction stack is live end-to-end.**

   Concrete work:
   - Start with a bounded snippet executor for straight-line or single-basic-block regions.
   - Require explicit register and memory initialization, a strict step budget, and structured outputs: final registers, touched memory, branch trace, extracted buffers.
   - Prefer a narrow, deterministic MVP that helps with decryption loops and small decoders instead of a broad general emulator API on day one.

   Rationale:
   - Micro-emulation is strategically important, but it should land after agents can already identify the right snippet using reduced IL / SSA.
   - Otherwise aeon risks adding an expensive new subsystem before fully exploiting the capabilities it just gained.

6. **Treat lifter coverage work as targeted cleanup, not the main bet right now.**

   Concrete work:
   - Add an intrinsic/opcode breakdown to coverage reporting.
   - Prioritize the highest-frequency non-SIMD, non-system intrinsic fallthroughs that block reduction, SSA quality, or call/data-flow reasoning.
   - Avoid broad “lift everything” work until the measured hot spots are clear.

   Rationale:
   - `97.88%` proper IL on `libUnreal.so` is already a strong baseline.
   - The remaining `1.91%` intrinsic bucket may still contain important instructions, but it is not obviously a higher-return investment than productizing the new reduction pipeline.
   - Coverage work becomes much more valuable once it is guided by real reduced-IL/SSA adoption and eval data.

## Recommended Execution Order

If the goal is maximum impact over the next few iterations, the order should be:

1. Expose reduced IL / SSA through `aeon` + MCP/HTTP.
2. Wire stack-slot recognition into that live path.
3. Make the SSA path truly reduction-backed and start promoting stack locals.
4. Add eval/regression coverage for the new artifacts.
5. Then choose between micro-emulation and targeted lifter cleanup based on measured gaps.

## What Not To Prioritize Yet

- Do not start with a broad lifter rewrite; current coverage is already good enough that integration work should come first.
- Do not expand `survey` into full orchestration yet; it will be more valuable after reduction/SSA and experiment APIs are available.
- Do not build a large human-facing UI layer; the roadmap and current architecture both point in the opposite direction.
