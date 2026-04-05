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
