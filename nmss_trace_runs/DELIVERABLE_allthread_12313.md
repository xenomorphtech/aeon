# Full Traced Call Deliverable

Date: 2026-04-10

## Production Result

Validated production run:

- [allthread_12313](/home/sdancer/aeon/nmss_trace_runs/allthread_12313)
- [batch_12313_12313.json](/home/sdancer/aeon/nmss_trace_runs/batch_12313_12313.json)

This run completed the full traced path successfully:

- relay bootstrap enabled
- translated load + arm enabled
- dynamic load + arm enabled
- `/prepare` completed successfully
- traced `/call` completed successfully
- no Frida crash during the call

Returned token:

- `CC1583586D18D1BE28F5E4B48C554F0DA21FA3FFC05413A0`

Primary call artifact:

- [call_12313.json](/home/sdancer/aeon/nmss_trace_runs/allthread_12313/call_12313.json)

## File-Based Heartbeat

The high-volume corridor-hit liveness path now uses a device-side file sink instead of Frida stdout.

Validated behavior on `12313`:

- device trace file grew during the traced run
- pulled artifact:
  - [aeon_trace.log](/home/sdancer/aeon/nmss_trace_runs/allthread_12313/aeon_trace.log)
- pulled size after completion:
  - `792247` bytes

This confirms the file-based heartbeat path was exercised under the successful traced run.

## Relevant Changes

Code implementing the production fix:

- [jit_trace_gate_v2.js](/home/sdancer/aeon/frida/jit_trace_gate_v2.js)
- [nmss_capture.py](/home/sdancer/aeon/frida/nmss_capture.py)
- [harvest_allthread_batch.py](/home/sdancer/aeon/scripts/harvest_allthread_batch.py)

What changed:

- corridor-hit heartbeat logging moved off Frida `console.log` and into a native file sink
- relay writes heartbeat lines to `/data/local/tmp/aeon_capture/aeon_trace.log`
- capture server extends `/call` based on trace-file growth
- batch watchdog also extends `/call` based on trace-file growth

## Operational Conclusion

The previous long-run failure mode was consistent with the Frida stdout/log channel becoming a bottleneck under sustained multi-threaded corridor activity.

After the file-based heartbeat pivot:

- full traced setup remains active
- `/prepare` still succeeds
- `/call` returns the expected token
- the run completes cleanly

This is the current production-ready traced-call recipe.
