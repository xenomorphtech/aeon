# Design improvements

Written 2026-11-17 from a structural read of the workspace (crate graph, module
sizes, key types). It is not a line-by-line audit. Items are in the order they
should be tackled.

## 1. Intrinsics are stringly-typed, and every backend re-parses them

`Expr::Intrinsic { name: String, .. }` and `Stmt::Intrinsic { name: String, .. }`
in `crates/aeonil/src/lib.rs` are the contract between the lifter and everything
downstream. The JIT has about 70 string match arms (`"bsl"`, `"frintz"`,
`"ushll2"`, ...) and the interpreter has its own separate set, each with its own
`intrinsic_base_name` parsing of the arrangement suffix. A typo or a newly
lifted intrinsic fails at runtime in one backend and silently in another.

**Fix:** an `IntrinsicOp` enum plus a structured arrangement in `aeonil`, so the
compiler reports which backends lack coverage. This is the highest-leverage
change because the IL is the one thing every crate shares.

**Status (2026-11-17): done.** `aeonil::IntrinsicName` parses the name once into
an `IntrinsicOp` and an optional `VectorArrangement`; the JIT, the interpreter
and the reducer match on the op, and their private name parsers are gone. Both
backends still end their dispatch in a wildcard arm, so a missing op is a
runtime "unsupported" rather than a compile error; removing those wildcards is
the remaining step.

## 2. Three execution engines with no shared semantics

- The IL interpreter in `crates/aeon/src/emulation.rs` (3.5k lines).
- The Unicorn-backed `crates/aeon/src/sandbox.rs`.
- The Cranelift JIT in `crates/aeon-jit`.

Inside `emulation.rs`, `Executor` and `BlockExecutor` are near-copies: the same
`movk`/`smulh`/`umulh` arms and the same vector intrinsic dispatch appear twice.

**Fix:** collapse the two into one executor parameterised over the existing
`BackingStore` trait. Then make interpreter-vs-JIT-vs-Unicorn differential
testing a first-class harness; `crates/aeon-jit/tests/roundtrip.rs` is a start.

**Status (2026-11-17): interpreter merged, harness in place.** `Executor` and
`BlockExecutor` are now one `Executor` with an `ExecMode`; a snippet is a block
run with no backing store.

`crates/aeon-jit/tests/differential.rs` runs 201 AArch64 snippets through
Unicorn (the reference) and three engines over 35 input vectors: the
interpreter, the JIT, and the JIT fed with IL reduced by
`aeon_reduce::pipeline::reduce_block_local`.
It compares x0-x30, SP, NZCV, v0-v31 and a data region mapped at the same
address everywhere. Snippets can branch, so the interpreter and the JIT are
driven block by block. Engines known to disagree are listed in the test's
`KNOWN` table; the test fails on an unlisted disagreement and on a listed one
that starts passing. `tests/differential/gen_cases.py` generates the case
table; regenerating needs the `aarch64-linux-gnu` binutils, running does not.

Bugs it found and that are fixed:

- Lifter
  - `NEGS` set no flags.
  - `CINC`, `CINV` and `CNEG` applied the operation on the wrong arm.
  - `ADCS`, `SBCS` and `NGCS` updated the flags and then computed the result
    from the new carry. They are now single statements (`adcs [dst, a, b]`).
  - `UCVTF` was lifted as the signed conversion, and every `FCVT*` rounding
    mode and signedness as signed round-toward-zero.
  - `LDP` with the base register as first destination loaded the second value
    from the wrong address.
  - Vector instructions lost their shape: a lane index was dropped
    (`ins v3.s[1], w0` became `v3 = w0`), and vector forms of mnemonics that
    also have a scalar form (`sub`, `mul`, `neg`, `rev64`, `fadd`, ...) were
    lifted as scalar expressions on 128-bit registers, losing the lane width.
    Lanes are now `Extract`/`Insert`, and arranged forms are intrinsics that
    carry the arrangement (`sub.4s`).
- JIT
  - Reading an X register after a 32-bit read of it returned the low half.
  - Integer division trapped instead of returning 0 or `MIN`.
  - An operation with an immediate on the left was typed 64-bit.
  - `ADCS`/`SBCS` set no carry or overflow; `FCMP`/`FCCMP` flags came from
    the bits of a subtraction; `FCVTZS` did not saturate; an invalid operation
    returned the host's NaN instead of the default NaN.
  - A scalar FP write left the rest of the vector register in place.
  - `MOVK` with a constant-folded immediate inserted at bit 0.
  - CRC32 was missing.
- Interpreter
  - `SDIV` divided unsigned; 32-bit shifts and rotates ran at 64 bits.
  - A load overlapping an earlier store returned the stale backing bytes.
  - Scalar FP writes and 64-bit arrangements kept the upper bytes of the
    vector register.
  - Missing: `ADC`/`SBC`/`NGC`, `EXTR`, `REV16`/`REV32`, `RET`, all scalar
    floating point, and most lane-wise integer SIMD. All added.

What `KNOWN` still lists:

- **Unsupported SIMD** (no wrong answers): 37 instructions in the
  interpreter and 86 in the JIT. Both lack widening, narrowing, permutes,
  table lookup, reductions and vector floating point. The JIT has lowerings
  for many lane-wise operations, but as expression intrinsics; the lifter
  emits statements (`add.4s [dst, a, b]`), which it does not accept.
- **Reduced IL gives wrong results in 26 cases.** See item 8.

Not covered yet: calls, system registers, exclusive and atomic memory
operations, and SIMD beyond the instructions sampled.

## 3. `aeon-jit` is a single 8,640-line `lib.rs`

`impl LoweringState` alone spans roughly 4,000 lines, and the file has 192
`unsafe` mentions.

**Fix:** split into `state`, `scalar`, `simd`, `fp`, `memory`, `imports` and
`object` modules, and confine the unsafe code to a small runtime/ABI module with
documented invariants.

**Status (2026-11-17): split done.** `lib.rs` is now about 100 lines of public types;
the rest lives in `jit_compiler`, `object_compiler`, `imports`, `runtime`,
`tests` and `lower/` (largest file: `lower/simd.rs`, about 940 lines). Code was
moved, not rewritten, then formatted. Correction to the above: only 9 of the
`unsafe` uses were outside the tests, and all of them are in `runtime.rs`; the
invariants there are still undocumented. Methods of `LoweringState` became
`pub(crate)` so sibling modules can call them.

## 4. Target-specific research code lived inside library crates

A 6.5k-line evaluation binary with hardcoded libc offsets, 40+ one-off Frida
scripts, raw process captures and an emulation script for one test target sat
alongside the product code.

**Status (2026-11-17): removed.** That material was only for testing stages and
is deleted from the tree, together with the reports derived from its captures.
`jit_linear_sweep` and `jit_translate_object` used to default to those capture
paths and base address; they now require `--input` and `--base`.

Still device-specific and worth a follow-up: the hardcoded `libart.so` offsets
in `crates/aeon-instrument/src/dynffi.rs`, which match one Android build.

## 5. The program model has overlapping sources of truth

- `AeonSession` holds `binary` and also clones it into `AeonEngine`.
- Per-function state lives in three places: the ECS `World`,
  `function_analyses`, and `function_cache: HashMap<u64, FunctionArtifacts>`.
- `bevy_ecs` is queried in exactly one place, so it is a heavy dependency acting
  as a `Vec` of instructions.
- `RefCell` interior mutability makes the session `!Sync`, which limits the HTTP
  frontend and the swarm.

**Fix:** one lazily computed per-function artifact store as the single owner,
with Datalog facts derived from it. Drop ECS unless a concrete plan needs it.

## 6. The API boundary is untyped JSON with string errors

- The core returns `serde_json::Value` and `Result<_, String>` or
  `Box<dyn Error>` (about 120 such signatures, no error enum).
- Tool definitions live in three places that can drift: the dispatch match and
  `tools_list()` in `crates/aeon-frontend/src/service.rs`, and the hand-pulled
  arguments in each `tool_*` function.
- The IL has no serde derives, so `crates/aeon/src/function_ir.rs` spends about
  1,200 lines on `ExprView`/`StmtView`/`SsaExprView` mirror enums.

**Fix:** typed request/response structs deriving `Deserialize` and `JsonSchema`,
with one registry generating dispatch, schema and docs. Add an error enum with
stable codes. Put serde derives behind a feature in `aeonil` and delete most of
the view layer.

## 7. Smaller items

- **Two reduction pipelines:** `aeon-reduce/src/pipeline.rs` and
  `ssa/pipeline.rs` have fixed pass orders in free functions. A small `Pass`
  trait and a pass manager would make ordering, metrics and per-pass validation
  uniform.
- **Layering:** `aeon-swarm` depends on `aeon-frontend`, an orchestrator
  depending on the transport layer. Extract the service into its own crate.
- **Repo hygiene:** the root has about 35 generated status reports, and the
  README's workspace layout omits `aeon-jit`, `aeon-instrument`, `aeon-reduce`
  and `aeon-swarm`. Archive the reports under `docs/history/` and keep one
  living architecture doc.
- **No CI:** there is no `.github` directory despite a sizeable test suite.
- **Panics:** about 450 `unwrap`/`expect` calls in `src`. They matter most in
  the lifter, ELF and service paths, where a hostile binary should not kill a
  persistent session.

## 8. The block-local reducer changes behaviour, and its output is compiled

Found by the differential test (item 2). `aeon-instrument` passed every block
through `aeon_reduce::pipeline::reduce_block_local` before compiling it, and
that pipeline is not semantics-preserving. Causes identified so far:

- `fuse_flags` deletes a `SetFlags` when the next reader is a conditional
  select, which still needs the flags, and `eliminate_dead_flags` treats flags
  as dead at the end of a block, though a later block may read them. Neither
  knows that `adc`/`sbc`, `ccmp` or `fccmp` read flags. `CMN` and `TST` are
  fused into a `Compare` that is then evaluated as a subtraction (by reading
  the code; the cases fail earlier for the reason above).
- Constant folding turns `MIN / -1` into 0.
- A register copy is forwarded past a redefinition of its source (`mov x29,
  sp` after SP moved), into an operand that an intrinsic writes (the base of a
  post-index `LD1`), and across a GPR-to-FP move as if the type were kept.
- Folding `movk x, #0, lsl #16` to `movk(x, 0)` loses which field is cleared.
  This is an IL problem: `MOVK` should be an `Insert`, not an intrinsic whose
  shift is implied by its operand.

The passes were written to make IL readable, where dropping a `SetFlags` is
harmless. Compiling their output needs a different contract.

**Fix:** decide which it is. Either `aeon-instrument` stops reducing before
compiling (Cranelift does its own folding), or the reducer gets a
semantics-preserving mode: flags live out of a block unless proven otherwise,
copy forwarding invalidated by any write to a register the copy mentions, and
no forwarding into intrinsic operands. The pass manager in item 7 is where
per-pass differential validation belongs.

**Status (2026-11-17): mitigated.** `aeon-instrument`'s translator now
compiles the IL as lifted, so the compiled path no longer depends on the
reducer. The reducer itself is unchanged: the differential test still runs
the JIT on reduced IL and lists its 26 wrong results in `KNOWN`, and
`jit_linear_sweep` still reduces, but only to display and round-trip IL. Any
consumer that treats reduced IL as equivalent to the original (the analyses
in `aeon`, `aeon-eval`) is exposed to the same causes.

## Order of work

1, then 2: they fix a correctness risk rather than tidiness, and they make the
JIT split in 3 mostly mechanical. Items 1 to 4 are done, and the differential
test from item 2 covers scalar code, memory, branches and a sample of SIMD.
Item 8 is mitigated for the compiled path. Next: SIMD coverage in the JIT
(accept the statement form the lifter emits), making the reducer itself
semantics-preserving, then items 5 and 6.
