# Frida Instrumentator Handoff

This note captures the current Aeon/Frida integration points that matter if you are extending the Frida-side instrumentation or wiring Frida into the translated JIT object path.

## Current Frida-side control path

Device server prerequisite:
- run `/data/local/tmp/xerda-server`
- host tooling forwards `localhost:27043` to device port `27042` on that exact binary
- do not substitute `/data/local/tmp/frida-server`

Primary script:
- [jit_trace_gate.js](/home/sdancer/aeon/frida/jit_trace_gate.js)

What it does:
- Tracks hot JIT pages / PCs / edges / threads
- Arms a page-trap window over the first `0x50000` bytes of the chosen JIT exec range
- Can freeze the process on execute fault
- Writes freeze state to `/data/local/tmp/aeon_capture/freeze.json`
- Wraps `rpc.exports.callCert`

Logging style:
- Mostly `console.log(...)`
- Prefix is usually `[CAPTURE] [GATE] ...`
- This is not using `send(...)` for the main gate flow

Important globals exposed by `jit_trace_gate.js`:
- `__jitGateFreezeArm(challenge, minPcHex)`
- `__jitGateFreezeClear()`
- `__jitGateFreezeStatus()`
- `__jitGateTranslatedLoad(elfPath, mapPath)`
- `__jitGateTranslatedArm(elfPath, mapPath, minPcHex, maxSteps)`
- `__jitGateTranslatedClear()`
- `__jitGateTranslatedStatus()`
- `__jitGateDynamicLoad(libPath)`
- `__jitGateDynamicArm(libPath, minPcHex, maxSteps)`
- `__jitGateDynamicClear()`
- `__jitGateDynamicStatus()`
- `__jitGateTraceDump()`
- `__jitGateTraceTopPages(limit)`
- `__jitGateTraceTopThreads(limit)`
- `__jitGateTraceTopEdges(limit)`
- `__jitGateFixedThreadTraceRun(challenge, jsonThreads)`
- `__jitGateFixedThreadTraceArm(jsonThreads)`
- `__jitGateFixedThreadTraceStatus()`
- `__jitGateFixedThreadTraceClear()`
- `__jitGateStalkerArm()`
- `__jitGateStalkerDisarm()`
- `__jitGateStalkerDump()`

`callCert` behavior:
- If `rpc.exports.callCert` exists, the gate wraps it and keeps the original in `originalCallCertExport`
- Fallback path is Java:
  - `nmss.app.NmssSa.getInstObj().getCertValue(challenge)`

One script that does use `send(...)`:
- [jit_direct_diff_driver.js](/home/sdancer/aeon/frida/jit_direct_diff_driver.js)
- It emits `ready`, `warm`, `final`, dump, and refresh messages via `send(...)`

## Freeze status JSON

Status path on device:
- `/data/local/tmp/aeon_capture/freeze.json`

Armed status written by `__jitGateFreezeArm(...)`:
```json
{
  "status": "armed",
  "timestamp": "...",
  "pid": 12345,
  "challenge": "AABBCCDDEEFF0011",
  "corridor": "0x9be95000",
  "corridorSize": 327680,
  "freeze_status_path": "/data/local/tmp/aeon_capture/freeze.json"
}
```

Triggered status written on execute fault:
```json
{
  "status": "triggered",
  "timestamp": "...",
  "pid": 12345,
  "thread_id": 12367,
  "challenge": "AABBCCDDEEFF0011",
  "type": "...",
  "address": "0x...",
  "pc": "0x...",
  "lr": "0x...",
  "registers": {
    "pc": "0x...",
    "sp": "0x...",
    "x0": "0x...",
    "...": "...",
    "x30": "0x...",
    "nzcv": "...",
    "simd": {
      "q0": "<16-byte hex>",
      "...": "...",
      "q31": "<16-byte hex>"
    }
  },
  "page": "0x...",
  "edge": "0x...->0x...",
  "trap_count": 1,
  "freeze_status_path": "/data/local/tmp/aeon_capture/freeze.json"
}
```

Register capture details:
- GPRs are stringified pointers / integers
- `nzcv` is included if available
- SIMD lives under `registers.simd.q0..q31`
- Each `qN` is hex-encoded raw bytes from Frida’s context object

Relevant code:
- `FREEZE_STATUS_PATH`: [jit_trace_gate.js](/home/sdancer/aeon/frida/jit_trace_gate.js#L72)
- register capture: [jit_trace_gate.js](/home/sdancer/aeon/frida/jit_trace_gate.js#L218)
- freeze arm: [jit_trace_gate.js](/home/sdancer/aeon/frida/jit_trace_gate.js#L1189)
- freeze trigger write: [jit_trace_gate.js](/home/sdancer/aeon/frida/jit_trace_gate.js#L1336)

## Current translated JIT object path

Translator:
- [jit_translate_object.rs](/home/sdancer/aeon/crates/aeon-instrument/src/bin/jit_translate_object.rs)

Current translator config:
```rust
JitConfig {
    instrument_memory: true,
    instrument_blocks: true,
}
```

Important consequence:
- translated object emits memory-read hook calls
- translated object emits block-entry hook calls
- compact map includes `block_id_map` so Frida can resolve `block_id -> source_block`

## Current translated in-process dispatch mode

`jit_trace_gate.js` now has a second control mode alongside freeze:
- keep the live JIT corridor non-executable
- current trap window is the first `0x50000` bytes of the chosen exec alias, not the older `0x12000..0x20000` sub-corridor
- on execute fault inside the corridor, snapshot the live thread context into `JitContext`
- run translated blocks in-process until the first unresolved target
- write guest register state back into the live Frida exception context
- resume the real process at the unresolved target instead of SIGSTOPing

Important caveat:
- this mode does **not** execute external/libart/libc targets inside the translated block itself
- instead, translated block exits return the first unresolved guest target, and the real process resumes there
- this works because object translation rewrites `Call`/`Ret` into branch form before compilation

Current control globals:
- `__jitGateTranslatedLoad(elfPath, mapPath)`
  - `dlopen()` translated ELF
  - parse translation map JSON
  - hook helper exports inside the translated image
- `__jitGateTranslatedArm(elfPath, mapPath, minPcHex, maxSteps)`
  - optional load if paths are provided
  - enable execute-fault diversion into translated dispatch
  - keep JIT corridor protected as `r--`
- `__jitGateTranslatedClear()`
  - disable translated diversion
- `__jitGateTranslatedStatus()`
  - returns armed/loaded status plus last run summary

Current helper-export behavior in this mode:
- `aeon_translate_branch_target(source_target)` is replaced with identity
- `aeon_bridge_branch_target(ctx, source_target)` is replaced with identity
- `aeon_unknown_block_addr(source_target)` logs unknown in-range targets
- `aeon_log_mem_read(addr)` optionally logs reads
- `aeon_log_trap(block_addr, kind_code, imm)` logs traps
- `on_block_enter(block_id)` logs translated block hits and resolves source block using `block_id_map`

Current dispatch behavior:
- translated block chaining is done in JavaScript, not inside the translated helper callbacks
- each translated block is called as `uint64 fn(pointer ctx)`
- the returned `uint64` is treated as the next guest/source PC
- if the next PC rebases to another translated block, dispatch continues in-process
- otherwise Frida writes registers back to `details.context`, sets `pc = next_target`, and lets the real process continue normally

## Current dynamic exact-PC runtime path

Resident library:
- Android build artifact: [libaeon_instrument.so](/home/sdancer/aeon/target/aarch64-linux-android/debug/libaeon_instrument.so)
- intended device path: `/data/user/0/com.netmarble.thered/files/libaeon_instrument.so`

Control globals:
- `__jitGateDynamicLoad(libPath)`
- `__jitGateDynamicArm(libPath, minPcHex, maxSteps)`
- `__jitGateDynamicClear()`
- `__jitGateDynamicStatus()`

What this path does:
- loads one resident Aeon runtime `.so`
- creates a runtime handle for the live JIT code window
- compiles blocks lazily from the exact current fault PC
- does not need a precomputed translated ELF or block map
- logs block hits through the runtime `block_id -> source_pc` lookup export

Current Frida behavior:
- load with `dlopen()`
- resolve native exports like `aeon_dyn_runtime_create`, `aeon_dyn_runtime_run_out`, and `aeon_dyn_runtime_lookup_block_source`
- on execute fault in the scoped cert thread:
  - seed a `JitContext`
  - call `aeon_dyn_runtime_run_out`
  - write the updated guest state back to `details.context`
  - if stop reason is `code_range_exit`, resume the real process at that returned PC

Current callback wiring:
- memory read callback: optional logging only
- memory write callback: optional logging only
- branch translate callback: identity
- branch bridge callback: identity
- block enter callback: resolves `block_id -> source_block` using `aeon_dyn_runtime_lookup_block_source`

Important consequence:
- because `DynCfg` rewrites `call`/`ret` into branch form, the dynamic runtime can stay in exact-PC mode within the JIT window and simply hand off to the original process when execution exits that range
- this avoids the static translated-path failure mode where a cert-thread fault lands in the middle of a block and no precomputed block head exists for that exact PC

## Hook ABI emitted by the translated object

Backend implementation:
- [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs)

Current emitted object-mode hooks:
- `aeon_log_mem_read(u64 addr)`
- `aeon_log_trap(u64 block_addr, u64 kind_code, u64 imm)`
- `aeon_translate_branch_target(u64 source_target) -> u64`
- `aeon_bridge_branch_target(JitContext *ctx, u64 source_target) -> u64`
- `aeon_unknown_block_addr(u64 source_target)`
- `on_block_enter(u64 block_id)`

Important caveat:
- this is currently defined as an exported no-op helper inside the generated object
- it is not currently an unresolved import that Frida can satisfy externally

Where that comes from:
- object compiler creates helper with `define_void_helper(...)`: [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs#L542)
- object-mode read hook symbol name: [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs#L25)
- object compiler enables it when `instrument_memory: true`: [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs#L369)

Current lowering behavior for loads:
- every lowered `Expr::Load` emits a call before the actual load
- in object mode it is address-only, not `(addr, size)`

Load instrumentation site:
- [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs#L1045)

Why address-only:
- `compile_block(...)` calls `imports.declare(..., true)` in object mode
- that sets `memory_read_addr_only = true`
- so read hook signature becomes one `I64` parameter only

Relevant code:
- object-mode import declaration: [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs#L462)
- hook signature selection: [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs#L684)

Current object-mode hook behavior summary:
- Reads: yes, `aeon_log_mem_read(addr)`
- Writes: no object-mode write hook currently emitted
- Block entry: yes, `on_block_enter(block_id)`
- Dynamic branch translation: yes, via `aeon_translate_branch_target(source_target)`
- Unresolved branch bridge: yes, via `aeon_bridge_branch_target(ctx, source_target)`

## Host JIT mode hooks

These are separate from the translated ELF path.

## Dynamic runtime C ABI

Exported by `libaeon_instrument.so`:
- `aeon_dyn_runtime_create(source_base, source_size) -> handle`
- `aeon_dyn_runtime_destroy(handle)`
- `aeon_dyn_runtime_set_max_steps(handle, max_steps)`
- `aeon_dyn_runtime_set_code_range(handle, start, end)`
- `aeon_dyn_runtime_clear_code_range(handle)`
- `aeon_dyn_runtime_set_memory_read_callback(handle, cb)`
- `aeon_dyn_runtime_set_memory_write_callback(handle, cb)`
- `aeon_dyn_runtime_set_branch_translate_callback(handle, cb)`
- `aeon_dyn_runtime_set_branch_bridge_callback(handle, cb)`
- `aeon_dyn_runtime_set_block_enter_callback(handle, cb)`
- `aeon_dyn_runtime_compiled_blocks(handle) -> u64`
- `aeon_dyn_runtime_lookup_block_source(handle, block_id) -> u64`
- `aeon_dyn_runtime_result_size() -> u64`
- `aeon_dyn_runtime_run_out(handle, ctx_ptr, out_result) -> u32`

`AeonDynRuntimeResult` layout:
- `u32 stop_code`
- 4-byte padding
- `u64 start_pc`
- `u64 final_pc`
- `u64 steps`
- `u64 compiled_blocks`
- `u64 info_pc`

Stop codes:
- `0`: halted
- `1`: max_steps
- `2`: code_range_exit
- `3`: lift_error
- `0xffffffff`: invalid_argument

Host JIT supports:
- `on_memory_read(u64 addr, u8 size)`
- `on_memory_write(u64 addr, u8 size, u64 value)`
- `on_block_enter(u64 block_id)`

These are normal native callbacks used by the host JIT compiler, not Frida APIs.

Relevant code:
- callback exports: [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs#L93)
- JIT symbol registration: [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs#L220)

## Current logging emitted by translated path

The translated binary is not directly emitting Frida `console.log` or `send`.

What it emits today:
- native call to local helper `aeon_log_mem_read(addr)` before each instrumented load
- native call to local helper `aeon_log_trap(block_addr, kind_code, imm)` immediately before each lowered trap
- native call to local helper `aeon_translate_branch_target(source_target)` before returning from lowered `Branch` / `CondBranch`
- native call to local helper `aeon_bridge_branch_target(ctx, source_target)` for unresolved translated branches
- native call to local helper `on_block_enter(block_id)` at translated block entry

That means:
- if Frida wants per-read logs from the translated binary, it must hook or patch `aeon_log_mem_read`
- if Frida wants runtime trap logs from the translated binary, it must hook or patch `aeon_log_trap`
- if Frida wants per-block hit logs from the translated binary, it must hook or patch `on_block_enter`
- if Frida wants in-range translated `BR` / `B.*` chaining, it must hook or replace `aeon_translate_branch_target`
- if Frida wants untranslated/libc/libart/original edges to execute, it must replace `aeon_bridge_branch_target`
- or Aeon must be changed to emit imports instead of local export stubs

Trap hook argument meaning:
- `block_addr`: source block start VA used during translation

## Dynamic runtime path

This is the newer path intended to replace the per-run translated-ELF flow for live JIT interception.

Implemented pieces:
- exact-PC lazy block compilation in [dynruntime.rs](/home/sdancer/aeon/crates/aeon-instrument/src/dynruntime.rs)
- compile-on-miss CFG expansion in [dyncfg.rs](/home/sdancer/aeon/crates/aeon-instrument/src/dyncfg.rs)
- resident C ABI in [dynffi.rs](/home/sdancer/aeon/crates/aeon-instrument/src/dynffi.rs)
- Android build script: [build-android-aeon-dyn-runtime.sh](/home/sdancer/aeon/scripts/build-android-aeon-dyn-runtime.sh)

Why this exists:
- live execute faults often land in the middle of a real block, not at a precomputed block head
- static translated maps then report `steps=0 unresolved=true`
- dynamic runtime fixes this by compiling from the exact current `pc`

Current exported C ABI:
- `aeon_dyn_runtime_create(u64 source_base, usize source_size) -> void *`
- `aeon_dyn_runtime_destroy(void *handle)`
- `aeon_dyn_runtime_set_max_steps(void *handle, usize max_steps)`
- `aeon_dyn_runtime_set_code_range(void *handle, u64 start, u64 end)`
- `aeon_dyn_runtime_clear_code_range(void *handle)`
- `aeon_dyn_runtime_set_memory_read_callback(void *handle, MemoryReadCallback cb)`
- `aeon_dyn_runtime_set_memory_write_callback(void *handle, MemoryWriteCallback cb)`
- `aeon_dyn_runtime_set_branch_translate_callback(void *handle, BranchTranslateCallback cb)`
- `aeon_dyn_runtime_set_branch_bridge_callback(void *handle, BranchBridgeCallback cb)`
- `aeon_dyn_runtime_set_block_enter_callback(void *handle, BlockEnterCallback cb)`
- `aeon_dyn_runtime_compiled_blocks(void *handle) -> usize`
- `aeon_dyn_runtime_run(void *handle, JitContext *ctx) -> AeonDynRuntimeResult`

Current `AeonDynRuntimeResult` layout:
- `stop_code`
  - `0`: halted
  - `1`: max steps
  - `2`: code range exit
  - `3`: lift error
  - `0xffffffff`: invalid argument
- `start_pc`
- `final_pc`
- `steps`
- `compiled_blocks`
- `info_pc`

Current memory model:
- `aeon_dyn_runtime_create()` uses a code-window reader over `[source_base, source_base + source_size)`
- this is enough for lifting instructions from the trapped JIT window
- it is not yet a full live-process memory abstraction for arbitrary unmapped code regions

Current proven regressions:
- exact mid-block start compiles and executes from the precise `pc`
- direct call returns compile the exact continuation PC after the call

Important limitation:
- this resident runtime is now a better foundation for Frida than the static ELF path, but the actual in-process Frida glue has not been switched over to it yet
- external/original/libc/libart call bridging still needs a real `branch_bridge` implementation that materializes guest state when required
- `kind_code`: `1 = brk`, `2 = udf`
- `imm`: original trap immediate preserved from lifted Aeon IL

Branch translation hook argument meaning:
- `source_target`: raw guest/source VA the translated block wants to branch to
- return value: translated block function address to call, or the original `source_target` unchanged to leave the branch unresolved

Current lowering behavior for translated branches:
- direct translated tail-calls are not used in object mode because Cranelift AArch64 `system_v` rejects `return_call_indirect`
- current behavior is:
  1. call `aeon_translate_branch_target(source_target)`
  2. if return differs from `source_target`, call that translated block function with the shared `JitContext *`
  3. immediately return that callee's next target
  4. if return equals `source_target`, call `aeon_bridge_branch_target(ctx, source_target)`
  5. immediately return the bridge helper's next target

Practical implication:
- this already removes the need for an outer dispatcher on in-range translated branches
- unresolved exits now have a dedicated runtime hook instead of falling straight back to raw target return
- but it still uses normal host calls, so long translated-only loops will grow the host call stack until a non-translated exit returns control outward

Bridge hook argument meaning:
- `ctx`: pointer to the live `JitContext`
- `source_target`: raw guest VA the translated block wanted to branch to
- return value: next guest/source target to continue from after the bridge runtime finishes

Intended bridge behavior:
- materialize guest regs from `JitContext` into hardware regs
- execute original/libc/libart target
- trap or return back into translator world
- snapshot machine regs back into `JitContext`
- return the next guest target

Unknown block logging:
- if `source_target` is within the translated source JIT window but not present in the translation dictionary, the Frida/runtime side should call `aeon_unknown_block_addr(source_target)` before falling back to the bridge path
- the helper is exported as a no-op stub by default; replace or hook it from Frida if you want logs

## Recommended Frida-side action

For the current translated ELF path, the least invasive options are:

1. Hook the exported `aeon_log_mem_read` function inside the translated image
- ABI is currently one argument: `u64 addr`
- no size is passed in object mode right now

2. Patch the helper body or redirect it to a Frida `NativeCallback`
- because the helper is currently a no-op export

3. Replace `aeon_translate_branch_target` with a mapping-aware callback
- recommended signature in Frida terms: one `uint64` arg, one `uint64` return
- implement:
  - range check against source JIT base + size
  - dictionary lookup from source block VA -> translated block symbol VA
  - return the original input for anything outside the translated block set
  - if inside the translated source window but missing from the dictionary, call `aeon_unknown_block_addr(source_target)`

4. Replace `aeon_bridge_branch_target` with the actual bridge runtime
- recommended signature in Frida terms: `pointer, uint64 -> uint64`
- this is where libc/libart/original-code calls have to be bridged
- this hook owns the guest<->machine register materialization and re-entry path

5. If size matters, change Aeon object mode to pass `(addr, size)`
- host JIT already supports that shape
- object mode currently forces address-only

6. Block logging is already enabled in the current translator config
- hook `on_block_enter(u64 block_id)`
- use `block_id_map` from the compact map to resolve `block_id -> source_block`

## Translated map / trap metadata

Translator outputs:
- ELF/object/map are written by [jit_translate_object.rs](/home/sdancer/aeon/crates/aeon-instrument/src/bin/jit_translate_object.rs)
- map JSON includes `memory_read_hook`
- compact map JSON includes `block_enter_hook` and `block_id_map`
- trap log sidecar includes trap-only translated blocks

Trap log format is now:
```text
<source_block> <translated_addr> <symbol> <kind> <imm>
```

Example fields:
- `0x9b5fe000 0x7100000004 aeon_jit_block_... brk 0x4711`

This is source-side fidelity only. Exact original trap byte emission is still not preserved by Cranelift.

## Trap fidelity caveat

Aeon IL now preserves:
- trap opcode kind: `brk` vs `udf`
- original immediate

But Cranelift AArch64 does not expose arbitrary original trap re-emission through its generic trap IR.

Current backend reality:
- generic `trap` lowers through Cranelift `TrapCode`
- `TrapCode` is only an 8-bit reason tag
- AArch64 backend uses fixed encodings for trap instructions

Observed backend behavior:
- `Inst::Brk` pretty-prints as `brk #0xf000`
- `Inst::Udf { .. }` pretty-prints as `udf #0xc11f`

So:
- IL / sweep / JSON / trap logs preserve original trap metadata
- emitted ELF does not yet preserve original arbitrary trap bytes

## Files to read first

Frida side:
- [jit_trace_gate.js](/home/sdancer/aeon/frida/jit_trace_gate.js)
- [sprintf_hook.js](/home/sdancer/aeon/frida/sprintf_hook.js)
- [jit_direct_diff_driver.js](/home/sdancer/aeon/frida/jit_direct_diff_driver.js)

Aeon side:
- [jit_translate_object.rs](/home/sdancer/aeon/crates/aeon-instrument/src/bin/jit_translate_object.rs)
- [lib.rs](/home/sdancer/aeon/crates/aeon-jit/src/lib.rs)
- [live_cert_eval.rs](/home/sdancer/aeon/crates/aeon-instrument/src/bin/live_cert_eval.rs)

## Practical summary

Today’s real interface is:
- Frida gate logs via `console.log`
- freeze state is written to `/data/local/tmp/aeon_capture/freeze.json`
- translated ELF emits calls to local exported no-op helpers:
  - `aeon_log_mem_read(addr)`
  - `aeon_log_trap(block_addr, kind_code, imm)`
- no object-mode write hook is emitted
- no block-entry hook is emitted unless translator config is changed

If you are wiring Frida into the translated JIT path, assume you need to hook or replace `aeon_log_mem_read` and `aeon_log_trap` yourself.
