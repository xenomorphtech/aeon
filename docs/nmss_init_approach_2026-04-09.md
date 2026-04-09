# NmssSa Init Approach

Date: 2026-04-09

## Goal

Reach a non-empty `NmssSa.getCertValue(challenge)` result on a live device session without forcing an unsafe re-init path.

## Current Working Approach

The stable readiness path is intentionally minimal. It does not try to recreate the full app bootstrap, and it avoids the crash-prone `loadCr()` / forced native re-init sequence.

The working sequence is:

1. Wait for a real `com.epicgames.unreal.GameActivity` instance.
2. Resolve `nmss.app.NmssSa` through the app class loader.
3. Get the existing `NmssSa` instance.
   - First try `NmssSa.getInstObj()`.
   - Fall back to `Java.choose('nmss.app.NmssSa')` if needed.
4. Inspect `inst.m_activity`.
   - If an activity is already present, do not call `SecurityUnrealBridge.init(...)`.
   - This is the common stable case.
5. Do not call `loadCr()` in the readiness preflight.
6. Call `inst.onResume()`.
7. Call `inst.run(READY_CHALLENGE)`.
   - Current warmup challenge: `6BA4D60738580083`
8. Call `inst.getCertValue(requestedChallenge)`.

## Why This Path

The earlier aggressive init path was unstable for two reasons:

- `nmssLoadCr()` could abort with:
  - `Check failed: c->IsInitializing()`
- forcing `SecurityUnrealBridge.init(...)` or other eager setup on an already-live `NmssSa` instance increased attach/session instability

The current approach works because it reuses the app's existing `GameActivity` and `NmssSa` state instead of trying to rebuild it.

## Expected Observable Result

For the challenge `AABBCCDDEEFF0011`, the current plain readiness flow returns a non-empty 48-hex token in a good live session, for example:

`CC1583586D18D1BE28F5E4B48C554F0DA21FA3FFC05413A0`

This is a session-valid live-device token, not a globally stable golden token.

## State Notes

Even when the plain readiness path works, `NmssSa` fields may still look "not ready" in a naive snapshot:

- `m_bAppExit = true`
- `m_bIsRPExists = false`
- `m_nCode = 0`
- `m_strMsg = null`

Those fields alone are not sufficient to decide readiness. The real gate is whether the minimal `onResume() -> run(READY_CHALLENGE) -> getCertValue()` sequence succeeds on the existing instance.

## Implementation Sites

Current implementation lives in:

- `/home/sdancer/aeon/frida/nmss_capture.py`
  - `prepareCertReadyCore(...)`
  - `waitForGameActivity(...)`
  - `getNmssInstance(...)`
- `/home/sdancer/aeon/frida/jit_trace_gate.js`
  - plain-token readiness gating before mem/dynamic tracing

## Practical Rule

Before enabling mem hooks, dynamic JIT tracing, or cert-core page tracing:

1. Verify that plain `/prepare?c=<challenge>` returns a non-empty token.
2. Only then load the heavier relay/tracing logic.

If plain `/prepare` returns an empty token, fix readiness first instead of debugging the trace path.
