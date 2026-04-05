# Live Cert Freeze Verification (2026-04-05)

## Verified Frozen State

The cert call was verified as correct before the process was frozen.

| Field | Value |
|---|---|
| PID | `22833` |
| TID | `22920` |
| State | `T (stopped)` |
| PC | `0x9b611090` |
| LR | `0x9b6078b8` |
| Challenge | `AABBCCDDEEFF0011` |
| Token | `3DBAB9F744F6B601E62D42B80212A8DFCD8E42847FE6C6D2` |

## Key Result

The cert output for challenge `AABBCCDDEEFF0011` was confirmed as:

```text
3DBAB9F744F6B601E62D42B80212A8DFCD8E42847FE6C6D2
```

That means this frozen process state is a valid reference point for dependency analysis. The evaluator no longer needs to prove the token exists in principle; it needs to recover how the JIT corridor computes that already-validated output.

## Formatting Boundary

During the cert window, only one libc `sprintf`-family call was observed, and it was classified as background noise. The cert JIT path itself does **not** format the token through libc `sprintf`/`snprintf`.

Implications:

- token formatting is happening inside JIT-generated code
- the earlier printable/sanitization loop around `0x9b61ccc0` remains the strongest formatting candidate
- tracing libc formatting calls is not a useful primary sink for this cert path

Related native finding:

- the observed native `S1` helper at `0xce75c` is a flattened dispatcher, not a real `sprintf`
- the actual formatter-like call inside that path is `0xce884 -> 0x6be48`
- two explicit global dependencies in that native `S1` path are `[0x447ba8]` and `[0x447608]`

## Relevant Files

- `capture/manual/freeze.json`
- `capture/manual/sprintf_log.txt`
- `/proc/22833/mem`
- `/proc/22833/maps`

## Immediate Consequence For Aeon

The next useful sink is not libc formatting. The evaluator should focus on:

1. reaching the entry `lr` (`0x9b6078b8`) from `pc=0x9b611090`
2. decoding the returned ART `String` or equivalent output object
3. tracing JIT-side byte emission / sanitization blocks rather than waiting for libc string builders

## Addendum: SIMD Capture Gap

On the later freeze at `pid=28164`, `pc=0x9b612074`, the first `--stop-on-non-concrete` hit was not a real cert dependency. It was a `boot-framework.oat` callee-save prologue at `0x70d4a270` spilling unknown `d8..d15` to the stack:

```asm
70d4a28c: stp d8, d9, [sp, #16]
70d4a290: stp d10, d11, [sp, #32]
70d4a294: stp d12, d13, [sp, #48]
70d4a298: stp d14, d15, [sp, #64]
```

Those SIMD registers were not present in `freeze.json`, so Aeon treated the spills as symbolic even though all incoming GPR state was concrete.

Implication for the next capture:

- include SIMD state in the exception JSON, ideally `q0..q31`
- minimum useful subset: `d8..d15` because they are callee-saved and immediately spilled by runtime helpers
