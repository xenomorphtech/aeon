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

`crates/aeon-jit/tests/differential.rs` runs 220 AArch64 snippets through
Unicorn (the reference) and three engines over 35 input vectors: the
interpreter, the JIT, and the JIT fed with IL reduced by
`aeon_reduce::pipeline::reduce_block_local`.
It compares x0-x30, SP, NZCV, v0-v31 and a data region mapped at the same
address everywhere. Snippets can branch, so the interpreter and the JIT are
driven block by block. An engine known to disagree goes in the test's `KNOWN`
table; the test fails on an unlisted disagreement and on a listed one that
starts passing. `tests/differential/gen_cases.py` generates the case
table; regenerating needs the `aarch64-linux-gnu` binutils, running does not.

**`KNOWN` is empty (2026-11-17):** all three engines reproduce the reference
on every case.

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
  - It had lowerings for lane-wise SIMD only as expression intrinsics, while
    the lifter emits statements (`add.4s [dst, a, b]`). `lower/lanes.rs` now
    lowers the statement form: lane-wise integer and floating-point
    arithmetic, compares, shifts, bitwise selects, lane inserts, widening,
    narrowing, permutes, table lookup, reductions, `LD1R`, and `LD1`/`ST1`
    with register lists and register post-index.
- Interpreter
  - `SDIV` divided unsigned; 32-bit shifts and rotates ran at 64 bits.
  - A load overlapping an earlier store returned the stale backing bytes.
  - Scalar FP writes and 64-bit arrangements kept the upper bytes of the
    vector register.
  - Missing: `ADC`/`SBC`/`NGC`, `EXTR`, `REV16`/`REV32`, `RET`, all scalar
    floating point, and most SIMD. All added; the SIMD that is more than a
    lane-by-lane map is in `emulation/vector.rs`.
- Reducer: see item 8.

Which lanes a widening or permuting instruction reads is decided once, in
`aeonil::simd`, and used by both engines.

Not covered yet: calls, system registers, exclusive and atomic memory
operations, and SIMD beyond the instructions sampled (saturating arithmetic,
polynomial multiply, crypto, half-precision, most by-element forms).

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

Found while running the suite repeatedly (2026-11-17):

- **The JIT's hooks were process-wide** (fixed). `JitCompiler::set_*_callback`
  and `set_block_counters` wrote statics that every compiled block read, so
  two compilers in one process overwrote each other's hooks; a unit test
  failed about one run in seven when a test on another thread installed a
  branch hook. Each compiler now owns a `RuntimeHooks` table, compiled code
  passes its address to the trampolines, and the table's invariants are
  documented in `runtime.rs` along with each `unsafe` block there. Object
  code is unaffected: it links against the runtime's own hook symbols.

Still open:

- **The trampolines append to `/tmp/aeon_jit_native.log` on every call**,
  opening the file each time, with no way to turn it off.
- **`tests/native_smoke.rs` crashes** in
  `native_jit_indirect_call_via_x30_bridges_to_printf`, which has JIT code
  call the host's `printf` through the branch bridge; the other tests in
  that file then fail on the poisoned lock.

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

**Status (2026-11-17): done.** `AeonSession` has three owners and nothing is
stored twice: the immutable `binary`, a cache of per-function
`FunctionArtifacts` (decoded instructions, reduced CFG, SSA, facts, each
computed on demand), and the `Blackboard` of analyst annotations.

- `AeonEngine` is gone. It held a second copy of the binary, an ECS world
  and its own `function_analyses` map; what is left of it is
  `blackboard::Blackboard`.
- `bevy_ecs` is removed. The function-details listing is computed from the
  decoded function directly.
- `facts::analyze_function`, a second decode-lift-reduce-SSA pipeline, is
  removed; facts come from `FunctionArtifacts::facts()`.
- The `RefCell`s are a `RwLock` and a `Mutex`, and a compile-time assertion
  keeps `AeonSession` `Send + Sync`.

Left: several analyses still run their own decode loop instead of asking for
a `DecodedFunction` (`pointer_analysis`, `object_layout`, the disassembly
listings in `api.rs` and `rc4_search`). They do not store anything, so they
are duplication rather than a second source of truth. The frontends still
wrap the whole service in one `Mutex`; the session no longer forces that.

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

**Status (2026-11-17): requests, errors and the IL on the wire are typed.**

- `aeon-frontend`'s `TOOLS` table is the only list of tools: name,
  description, request type and handler in one entry. Dispatch, the
  `tools/list` result and the README table are derived from it. Before, the
  dispatch match and the schema list were separate, and the schema list
  existed twice, one copy dead. A test calls every listed tool.
- Each tool's arguments are a struct in `requests.rs` deriving `Deserialize`
  and `schemars::JsonSchema`. The published schema is generated from the same
  type the arguments are parsed into; the hand-written schemas and the
  per-handler `args.get(..)` code are gone. Arguments of the wrong type are
  now rejected instead of silently replaced by the default.
- The session API returns `aeon::Error`, which has an `ErrorKind`
  (`NotFound`, `OutOfRange`, `InvalidInput`, `Load`, `Emulation`,
  `Internal`) and a message. `Error` converts to `String` for callers that
  only want the text.
- Tool calls fail with a `ToolError` carrying an `ErrorCode` whose string
  form is stable: `unknown_tool`, `no_binary_loaded`, `invalid_argument`,
  `not_found`, `out_of_range`, `load_failed`, `emulation_failed`,
  `internal`. HTTP returns it as `"code"` next to `"error"`; MCP puts it in
  the result's `_meta`. `call_tool` still returns the message alone.
- The frontend's integration tests use the library crate instead of
  including `service.rs` by path.

- `aeonil` and `aeon-reduce` have a `serde` feature that derives
  `Serialize`/`Deserialize` on the IL and SSA types. The reduced-IL and SSA
  tool results serialise those types directly, in serde's default shape
  (`{"Assign": {"dst": {"X": 0}, "src": {"Imm": 5}}}`). The
  `ExprView`/`StmtView`/`SsaExprView` mirror enums and their conversions are
  deleted (`function_ir.rs`: 2,137 lines to 786), and so is `aeon-eval`'s own
  third serialiser. **This changed the wire format**: statements were
  `{"op": "assign", ...}` in tool results and `["assign", "x0", ...]` in
  goldens, with addresses as hex strings; addresses inside IL are now
  numbers. The goldens are regenerated;
  `AEON_UPDATE_GOLDENS=1 cargo test -p aeon-eval` rewrites them.

Open:

- `sandbox.rs` still reports every failure as a string, so all of them are
  `emulation_failed`, including a misspelt register name.
- Tool results other than the IL are still built as `serde_json::Value` by
  hand in `api.rs`.

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

## 8. The block-local reducer changed behaviour

Found by the differential test (item 2). `aeon_reduce::pipeline::reduce_block_local`
was not semantics-preserving, and `aeon-instrument` compiled its output. Its
output also feeds SSA, the API and `aeon-eval`, so the analyses saw the same
wrong IL.

**Status (2026-11-17): fixed.** The differential test runs the JIT on reduced
IL and it matches Unicorn on every case. What was wrong, and what it does now:

- **Flags.** A `SetFlags` was deleted when the next reader was a conditional
  select, and flags counted as dead at the end of a block. Now `fuse_flags`
  only rewrites the branch, and `eliminate_dead_flags` removes a `SetFlags`
  by liveness: every reader is recognised (`csel`, `adc`/`sbc`, `adcs`,
  `ccmp`, `fccmp`, `mrs nzcv`, unknown intrinsics), and flags are live at the
  end of a block. `reduce_function_cfg` then removes the ones that are dead
  across the function, assuming AAPCS64 at calls and returns.
- **`CMN` and `TST`** were fused into a `Compare` that is evaluated as a
  subtraction. They now become a comparison of the sum or the mask with
  zero, and only for conditions that this reproduces.
- **A compare fused past a redefinition of its operand** read the new value.
  Fusion stops at any write to a register (or memory) the compare reads.
- **Forwarding.** Any assigned expression was substituted into later uses:
  past a redefinition of its source (`mov x29, sp` after SP moved), into an
  operand an intrinsic writes, across a GPR-to-FP move, and through repeated
  loads. Only integer constants are forwarded now.
- **Constant folding** treated `Div` as unsigned (`MIN / -1` gave 0), shifted
  by the full amount instead of modulo the width, and simplified the
  top-level operator of a `SetFlags` (`cmp x, #0` became a bare register,
  `cmp` of two known constants became a literal NZCV of 0).
- **`movk x, #0, lsl #16`** folded to `movk(x, 0)`, losing which field is
  cleared. `MOVK` is now an `Insert` that names its field (see below).
- **SSA passes** removed unreachable blocks but kept indexing blocks by
  their old ids, and crashed once a branch on constants became decidable.
  Blocks are renumbered after removal.

Two `aeon-eval` goldens had pinned wrong output (a `branch x1` that is a
`branch x16`, a stack offset subtracted twice, `tst` as `== 1`) and are
regenerated.

**Widths (2026-11-18).** AeonIL inferred an operation's width from its
register operands, so replacing a W register with a constant turned a 32-bit
shift or division into a 64-bit one, and constants in W registers could not
be forwarded. Now:

- `Expr::Imm32` is a constant that is 32-bit by itself. `Expr::Imm` stays an
  untyped literal that takes the width of its sibling operand (`w1 + 5`),
  which is what the lifter emits and what the 900-odd existing uses mean.
- `Expr::int_bits` in `aeonil` is the one definition of an integer
  expression's width. The interpreter uses it; the JIT keeps its own
  Cranelift type inference, extended with the same rule for `Imm32`.
- The reducer forwards a constant assigned to a W register as an `Imm32`
  and folds operations on it at 32 bits. The differential test has nine
  cases that read such a constant from shifts, divisions, flags, branches,
  bit operations, extensions, FP moves, selects, bitfields and stores.

- `MOVK` is lifted as `Insert { dst, src: Imm(imm16), lsb, width: 16 }`.
  The `movk` intrinsic, whose field was implied by the shape or value of
  its operand, is gone, and with it the special cases in the folder and in
  both engines. `reduce_movk.rs` is deleted: forwarding plus folding an
  `Insert` into a constant resolves the same chains, for W registers too.
  The `movk_chain_resolutions` metric went with it.

This is the small version: a width on the one leaf that lacked it, not a
width on every node. Not done: a constant known through the X view is not
used for a read of the W view (or the reverse), and SSA still spells a
32-bit value as an `Extract`.

`aeon-instrument` still compiles the IL as lifted: Cranelift does its own
folding, so reducing first gains nothing there.

## Order of work

1, then 2: they fix a correctness risk rather than tidiness, and they make the
JIT split in 3 mostly mechanical. Items 1 to 5 and 8 are done, and the
differential test from item 2 covers scalar code, memory, branches, a sample
of SIMD and the reducer, with no known disagreements. Item 6 is done
but for typed non-IL responses. Constants carry their width where it
matters (item 8). Next: the pass manager from item 7 with per-pass
differential validation.
