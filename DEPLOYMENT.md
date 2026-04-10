# Deployment

Date: 2026-04-10

## Production State

The production-ready all-thread trace collection path is validated on:

- [allthread_12313](/home/sdancer/aeon/nmss_trace_runs/allthread_12313)
- [batch_12313_12313.json](/home/sdancer/aeon/nmss_trace_runs/batch_12313_12313.json)

Validated token result:

- `CC1583586D18D1BE28F5E4B48C554F0DA21FA3FFC05413A0`

Primary success artifact:

- [call_12313.json](/home/sdancer/aeon/nmss_trace_runs/allthread_12313/call_12313.json)

## What Was Fixed

### Heartbeat Keepalive

Long traced `/call` executions can remain active for minutes while continuing to hit the trapped corridor. The host must not treat those calls as hung while real trace activity is still happening.

The keepalive logic now:

- keeps `/call` alive while trace progress continues
- resets the idle deadline on new heartbeat activity
- only fails the call after trace activity goes idle

Implemented in:

- [nmss_capture.py](/home/sdancer/aeon/frida/nmss_capture.py)
- [harvest_allthread_batch.py](/home/sdancer/aeon/scripts/harvest_allthread_batch.py)

### File-Based Logging

The high-volume corridor-hit path no longer depends on Frida stdout for liveness.

The relay now writes heartbeat lines to:

- `/data/local/tmp/aeon_capture/aeon_trace.log`

This avoids the previous stdout bottleneck during sustained multi-threaded tracing.

Implemented in:

- [jit_trace_gate_v2.js](/home/sdancer/aeon/frida/jit_trace_gate_v2.js)

Validated `12313` file artifact:

- [aeon_trace.log](/home/sdancer/aeon/nmss_trace_runs/allthread_12313/aeon_trace.log)
- pulled size: `792247` bytes

## Enabled Production Path

Validated stack:

- relay bootstrap
- exception handler
- `wrapMaybeAdoptJit`
- `callCertTraced` export
- translated load + arm
- dynamic load + arm
- `/prepare` before `/call`
- file-based heartbeat keepalive

## Operational Outcome

Before the fix:

- long traced runs could stay active but die or be cut off before `/call` returned

After the fix:

- `/prepare` succeeds
- full traced `/call` succeeds
- token returns cleanly under the full traced stack

This is the current production-ready recipe for all-thread trace collection.
