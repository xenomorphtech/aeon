# Lifter Coverage and Micro-Emulation Plan

## Scope and inputs

This note is based on:

- `roadmap.md`
- `docs/next-steps.md`
- `crates/aeon/src/lifter.rs`
- `crates/aeonil/src/lib.rs`
- `crates/aeon-reduce`
- `cargo run -p aeon-frontend --bin aeon -- coverage samples/hello_aarch64.elf`
- `cargo run -p aeon-frontend --bin aeon -- coverage libUnreal.so`
- `cargo run -p survey -- libUnreal.so --limit 80 --json`

The sample binary is useful as a sanity check, but it is too small to expose the real intrinsic hot spots. `hello_aarch64.elf` has zero intrinsic fallthroughs, so the representative gap analysis below uses `libUnreal.so`, which is already in this repo and matches the baseline quoted in `docs/next-steps.md`.

## 1. Current lifter coverage

### Measured coverage

`samples/hello_aarch64.elf`:

- `proper_il=128 / 135 = 94.81%`
- `intrinsic=0`
- `nop=7 / 135 = 5.19%`
- `decode_errors=0`

`libUnreal.so`:

- `proper_il=27,513,849 / 28,110,566 = 97.88%`
- `intrinsic=537,435 / 28,110,566 = 1.91%`
- `nop=34,742 / 28,110,566 = 0.12%`
- `decode_errors=24,540 / 28,110,566 = 0.0873%`

The current coverage baseline is already strong. The problem is not gross decode failure. The remaining quality loss is concentrated in a relatively small intrinsic bucket, and some of that bucket is far more important to reduction than the raw percentages suggest.

### What currently falls through to intrinsics

From `crates/aeon/src/lifter.rs`, the intrinsic bucket is a mix of three very different things:

1. Scalar instructions that are close to first-class IL already, but still emitted as intrinsics.

- `MOVK`
- `SMULH`, `UMULH`
- `ADC`, `ADCS`, `SBC`, `SBCS`, `NGC`, `NGCS`
- `BFI`, `BFXIL`, `SBFIZ`, `SBFX`, `UBFX`, `UBFIZ`, `EXTR`
- `REV16`, `REV32`, `CNT`
- `CCMP`, `CCMN`
- `FNMADD`, `FNMSUB`
- `FCCMP`, `FCCMPE`
- `FRINT*`
- `FRECPE`, `FRECPS`, `FRSQRTE`, `FRSQRTS`
- `MSR`, `SVC`, `HVC`, `SMC`, `SYS`, `SYSL`
- MTE ops such as `ADDG`, `STG`, `LDG`

2. Whole families intentionally modeled as `Stmt::Intrinsic`.

- SIMD / NEON arithmetic and shuffles
- SIMD loads/stores such as `LD1` and `ST1`
- Atomic read-modify-write and exclusive pair ops
- Crypto instructions such as AES and SHA opcodes

3. True catch-all fallback.

- Any opcode not explicitly matched lands in a named intrinsic.

The `nop` bucket is mostly harmless for reduction quality:

- `NOP`, `YIELD`, `HINT`
- `PACIASP`, `AUTIASP`, `BTI`, `XPACLRI`
- `PRFM`, `PRFUM`
- `CLREX`

`DMB`, `DSB`, and `ISB` are not lost. They become `Stmt::Barrier`.

### Highest-frequency gaps in the local real-binary corpus

Using the `libUnreal.so` opcode survey and mapping those opcodes back to the lifter:

| Gap family | Example opcodes | Observed count | Reduction impact |
| --- | --- | ---: | --- |
| `MOVK` intrinsic-expression | `MOVK` | 67,551 | High frequency, but already partly mitigated by `reduce_movk`; not the first lifter fix to prioritize |
| SIMD / NEON arithmetic | `FMLA`, `FMLS` | 59,020 + 17,836 | Largest true semantic gap by volume; blocks any IL-level reasoning about vectorized math or decode loops |
| SIMD loads/stores | `LD1`, `ST1` | 54,185 + 30,615 | Same as above; especially relevant if string/decryption loops are vectorized |
| Bitfield family | `BFI`, `SBFIZ`, `UBFX` | 45,382 + 19,917 + 14,308 | High ROI: blocks address arithmetic, mask extraction, switch decoding, field recovery |
| SIMD shuffle / lane ops | `EXT`, `DUP` | 38,426 + 28,436 | Important for vectorized data movement and decode routines |
| Conditional compare | `CCMP` | 13,492 | Moderate frequency, disproportionately high impact on branch simplification and SCCP |

Observations:

- The biggest raw intrinsic family in this local corpus is SIMD / NEON, not atomics.
- The biggest scalar gap with immediate reduction payoff is the bitfield family.
- `MOVK` is numerically the single largest intrinsic-bearing opcode, but it is already on a reduction path, so its marginal payoff is lower than the raw count suggests.
- Atomic ops do not show up in the top 80 opcodes here, so they are not the highest-frequency gap locally, but they are still a major semantic blind spot where they do appear.

## 2. What a minimal bounded AeonIL executor should look like

The right MVP is not a full architectural emulator. It is a concrete, bounded interpreter for reduced AeonIL windows.

### Design goals

- Execute reduced IL, not raw lifted IL, whenever possible.
- Be deterministic and cheap enough to invoke as part of reduction.
- Require explicit register and memory initialization.
- Stop cleanly on unsupported intrinsics or unresolved addresses.
- Return structured artifacts that reduction can feed back into IL and SSA.

### Core execution model

The core should interpret a straight-line slice of `(addr, Stmt)` values and optionally allow a very small bounded amount of local control flow:

- Default mode: strict straight-line execution, stop on the first branch.
- Phase 1.5: permit re-entering the same block for a small number of visits when the branch target is concrete and local.

That keeps the engine simple while still covering most constant-expression windows and some tight decode loops.

### Minimal API shape

```rust
pub struct EmuConfig {
    pub max_steps: usize,
    pub max_block_visits: usize,
    pub stop_on_intrinsic: bool,
    pub read_binary_memory: bool,
}

pub struct MemoryInit {
    pub addr: u64,
    pub bytes: Vec<u8>,
}

pub struct EmuState {
    pub regs: BTreeMap<aeonil::Reg, Value>,
    pub flags: Option<Nzcv>,
    pub abs_mem: SparseMemory,
    pub stack_slots: BTreeMap<i64, Vec<u8>>,
}

pub enum StopReason {
    Completed,
    StepLimit,
    UnsupportedIntrinsic { name: String, addr: u64 },
    UnresolvedAddress { addr: u64 },
    BranchExit { target: Option<u64> },
    Trap,
}

pub struct EmuResult {
    pub stop: StopReason,
    pub steps: usize,
    pub final_state: EmuState,
    pub reads: Vec<MemAccess>,
    pub writes: Vec<MemAccess>,
    pub branch_trace: Vec<BranchEvent>,
}

pub fn execute_snippet(
    snippet: &[(u64, aeonil::Stmt)],
    state: EmuState,
    cfg: &EmuConfig,
) -> EmuResult;
```

### Value model

For the first version, `Value` should stay concrete and small:

```rust
pub enum Value {
    U64(u64),
    U128(u128),
    F64(f64),
    Unknown,
}
```

That is enough for:

- scalar integer arithmetic
- addresses
- 128-bit vector payload storage if needed later
- explicit bailout on unsupported semantics

Do not start with symbolic execution. A concrete interpreter with `Unknown` is enough for the intended use cases.

### Expression support for MVP

The evaluator should support all non-intrinsic AeonIL forms that already exist in `aeonil`:

- integer arithmetic and logic
- shifts and extensions
- `Load`
- `CondSelect`
- `Compare`
- `AdrpImm` and `AdrImm`
- `StackSlot`

For statements:

- `Assign`
- `Store`
- `SetFlags`
- `Branch`
- `CondBranch`
- `Nop`
- `Barrier`
- `Ret`

The key simplification is that `Intrinsic` should not be interpreted generically. Either:

- eliminate it earlier in reduction, or
- handle a short allowlist of cheap cases, or
- stop with `UnsupportedIntrinsic`

That keeps the executor honest and easy to reason about.

### Memory model

The executor needs two memory spaces:

1. Absolute binary memory keyed by `u64` address.

- Seed from ELF segments when `read_binary_memory=true`
- Allow overlays from the caller for decoded buffers or synthetic heap state

2. Stack-slot memory keyed by stack offset.

- If reduction already rewrites stack accesses to `Expr::StackSlot`, the executor should not force them back into fake absolute addresses
- This is a real advantage over a raw hardware emulator

### Flags handling

`SetFlags` is currently generated for `CMP`, `CMN`, `TST`, and FP compare cases. The interpreter only needs to support the same subset the reducer already understands:

- `Sub` for `CMP`
- `Add` for `CMN`
- `And` for `TST`

In practice, many branches should already be reduced to `BranchCond::Compare`. Supporting simple NZCV evaluation is still worthwhile so the executor can run on pre-SSA or partially reduced windows.

## 3. How micro-emulation should integrate with reduction

The executor should sit inside the reduction pipeline, not beside it.

### Recommended position in the pipeline

Current `reduce_block()` order is:

1. flatten pairs
2. constant fold
3. ADRP/ADR + ADD resolution
4. MOVK chain resolution
5. constant fold again
6. flag fusion
7. dead-flag elimination
8. extension folding

The executor should run after those passes, and after stack-frame recognition is wired into the live path. That gives it:

- fewer intrinsics
- more concrete addresses
- cleaner branch conditions
- stack slots instead of noisy `SP` arithmetic

In practice the integration point should look like:

1. Lift function
2. Split into blocks
3. Run normal block reduction
4. Run stack-frame recognition
5. Identify candidate windows
6. Execute bounded windows where the address/register environment is concrete enough
7. Feed concrete results back into reduced IL before SSA

### What should be fed back into reduction

The executor is valuable only if it produces reusable facts. The first rewrite targets should be:

- Replace `Load(Imm(addr), size)` with `Imm(...)` when the address is in mapped read-only memory
- Replace a final computed indirect branch register with `Branch { target: Imm(...) }` or an equivalent resolved branch fact
- Materialize a stack-slot or buffer write sequence as concrete bytes
- Collapse branch conditions to constants when the compare operands become concrete

### High-value use cases

#### Decryption or small decode loops

These are the main reason to add bounded execution.

The MVP does not need a full CFG emulator. It only needs:

- reduced integer IL
- binary-backed memory reads
- local writes
- optional bounded block re-entry

That is enough for many single-block loops, small table walkers, and stack-buffer decoders.

#### Switch table recovery

This is an especially good fit:

- reduction already resolves many `ADRP + ADD` patterns
- a better bitfield lift would remove another major blocker
- the executor can read the table entry from binary memory
- the final `BR Xn` target can be concretized without emulating an entire function

#### Constant-expression evaluation at known addresses

The current reduction pipeline stops at pure expression folding plus register substitution. It does not read memory. The executor can bridge that gap when:

- an address is concrete
- the bytes live in mapped binary memory
- the snippet has no unresolved side effects

This is exactly what is needed for table constants, vtable offsets, literal decode helpers, and some constructor-layout cases.

## 4. Lifter improvements with the highest reduction payoff

### 1. Bitfield family: highest scalar ROI

Target:

- `BFI`
- `BFXIL`
- `SBFIZ`
- `SBFX`
- `UBFX`
- `UBFIZ`
- `EXTR`

Why this is high leverage:

- These are frequent in the local corpus.
- AeonIL already has `Extract` and `Insert`, so the IR can represent them directly.
- They matter for pointer arithmetic, field extraction, mask normalization, and switch decoding.

This is the best immediate lifter cleanup for reduction quality.

### 2. `CCMP` / `CCMN`: highest control-flow ROI

Target:

- `CCMP`
- `CCMN`
- likely `FCCMP` / `FCCMPE` later

Why this matters:

- They currently block the existing flag-fusion and SCCP flow.
- `CCMP` already appears often enough in `libUnreal.so` to justify dedicated handling.
- Control-flow cleanup compounds across CFG, SSA, and dead-branch elimination.

This likely needs either:

- a richer `SetFlags` representation, or
- a new AeonIL node that captures conditional flag-setting explicitly

### 3. Atomic and exclusive RMW ops: high semantic ROI

Target:

- `CAS`, `CASA`, `CASAL`, `CASL`
- `LDADD*`, `LDCLR*`, `LDSET*`, `SWP*`
- `LDAXP`, `LDXP`, `STLXP`, `STXP`

Why this matters:

- They are currently opaque `Stmt::Intrinsic` nodes.
- They block reasoning about synchronization code, lock-free queues, and refcounting.
- Even a single-thread reduction pipeline benefits from explicit read, compare, write, and status-register effects.

The first lift does not need full memory-order modeling. It does need explicit dataflow.

### 4. Carry and high-multiply ops: medium ROI

Target:

- `ADC`, `ADCS`, `SBC`, `SBCS`, `NGC`, `NGCS`
- `SMULH`, `UMULH`

Why:

- They show up in arithmetic-heavy helpers, hash code, and some decode loops.
- They improve constant propagation and exactness in address or index calculations.

These matter less than bitfield and conditional compare, but more than broad system-op cleanup.

### 5. Acquire / release semantics: useful, but not first for reduction

Current state:

- `LDAR`, `LDLAR`, `STLR`, `STLLR`, etc. already lift as plain loads/stores

Gap:

- Ordering semantics are lost

Impact:

- This is important for semantic fidelity and eventual concurrency-aware analysis
- It is lower priority for reduction quality than ops that are still completely intrinsic

Recommendation:

- add ordering metadata later
- do not treat this as a first-wave blocker for micro-emulation

### 6. SIMD / NEON: biggest volume gap, but not the first reduction bet

SIMD is the largest true intrinsic family in the local corpus. That does not automatically make it the first investment.

For general reduction quality:

- broad NEON lifting is expensive
- most pointer/control-flow analyses do not need it

For decode and decryption use cases:

- some targeted vector support may become necessary later

Recommendation:

- do not attempt a broad SIMD rewrite first
- instead, keep SIMD as the likely trigger for a future fallback backend

## 5. AeonIL interpreter vs `unicorn-rs`

### AeonIL interpreter

Pros:

- Executes the same reduced representation the rest of the pipeline already uses
- Naturally understands `StackSlot`, folded `ADRP`, simplified compares, and reduced branches
- Deterministic and cheap
- Easy to instrument with exact reads, writes, and reduction facts
- No need to reconstruct raw ARM64 state or remap the world into guest memory

Cons:

- Limited by current lifter quality
- Will stop on unsupported intrinsics unless handlers are added
- Needs its own semantics for flags, memory, and any supported intrinsics

Verdict:

- high feasibility
- best choice for the first bounded-execution backend

### `unicorn-rs`

Pros:

- Broader raw ARM64 instruction coverage out of the box
- Better long-term escape hatch for SIMD-heavy or atomic-heavy windows
- Can validate tricky instruction semantics independently of the lifter

Cons:

- Higher integration cost
- Must map ELF memory faithfully
- Must seed architectural state from analysis facts
- Must stub calls, traps, sysregs, and external memory effects
- Produces results in raw machine terms, not reduced IL terms
- Loses some of the advantage of already having reduced `StackSlot` and symbolic-address information

Verdict:

- feasible, but heavier than the MVP needs
- a good fallback backend, not the first one to build

### Recommended strategy

Do not choose one forever. Build a two-tier model:

1. Primary backend: reduced AeonIL interpreter for straight-line and tiny bounded windows
2. Optional fallback: Unicorn for snippets that fail because of unsupported vector, crypto, or atomic instruction semantics

That keeps the default path deterministic and tightly integrated with reduction while preserving an escape hatch for the hard cases.

## Recommended implementation order

1. Extend coverage reporting to emit intrinsic breakdowns by opcode or intrinsic name.
2. Wire stack-frame recognition into the live reduction path and make SSA truly reduction-backed first.
3. Add a reduced-AeonIL straight-line executor with binary-backed memory and structured traces.
4. Prioritize bitfield lifting and `CCMP` / `CCMN`.
5. Add explicit semantics for atomic/exclusive RMW ops.
6. Only then consider a `unicorn-rs` fallback for unsupported SIMD-heavy windows.

## Bottom line

The current lifter is already good enough to justify micro-emulation work, but the right MVP is an AeonIL interpreter, not immediate Unicorn integration. The highest-value lifter work for reduction is not "lift everything"; it is:

- first-class bitfield lowering
- conditional compare lowering
- explicit atomic/exclusive dataflow

That combination gives the reduction pipeline a much better substrate for switch recovery, constant-address evaluation, and bounded decode/decryption experiments without paying the integration cost of a full machine emulator up front.
