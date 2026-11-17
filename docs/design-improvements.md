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

**Status (2026-11-17): interpreter merged, harness not started.** `Executor` and
`BlockExecutor` are now one `Executor` with an `ExecMode`; a snippet is a block
run with no backing store. The differential harness is still to do.

## 3. `aeon-jit` is a single 8,640-line `lib.rs`

`impl LoweringState` alone spans roughly 4,000 lines, and the file has 192
`unsafe` mentions.

**Fix:** split into `state`, `scalar`, `simd`, `fp`, `memory`, `imports` and
`object` modules, and confine the unsafe code to a small runtime/ABI module with
documented invariants.

## 4. Target-specific research code lives inside library crates

- `crates/aeon-instrument/src/bin/live_cert_eval.rs` is 6.5k lines with
  hardcoded libc offsets and a default PC.
- `crates/aeon-instrument/src/bin/jit_linear_sweep.rs` is another 2.4k lines.
- `frida/` holds 40+ one-off scripts keyed to absolute addresses, and
  `nmss_emu_cert.py` sits at the repo root.

This is campaign work for one target, not product.

**Fix:** move it under `research/` or `targets/nmss/` (or a separate repo), put
the offsets in a data file, and lift the reusable parts (libc stubs, ptrace
snapshot) into `aeon-instrument` proper.

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

## Order of work

1, then 2: they fix a correctness risk rather than tidiness, and they make the
JIT split in 3 mostly mechanical. Item 4 is cheap and independent.
