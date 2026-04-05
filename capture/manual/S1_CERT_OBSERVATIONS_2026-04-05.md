# S1 Cert Call Observations (2026-04-05)

## Fresh Spawn

- JIT=`be971a8e218e1` base=`0x75cbf9d000` size=`0x453000`
- S1 hook installed at `0x75cc0f2d60`

## Raw Trace

```text
S1_ARGS during init (before our queries):
S1_ARGS x25=0x763ac790a0 vals=0000000100000001000000000000000000000000400300CC
S1_ARGS x25=0x763ac790a0 vals=000000013AC79970D1966ED0719C74703AC791E0CC16EDB0
S1_ARGS x25=0x763ac78a70 vals=000000013AC78AF8000000006FAE3C703AC78B1070D35838

Challenge 0000000000000000:
S1_ARGS x25=0x763ac790a0 vals=0000000100000001000000000000000000000000400300CC
S1_ARGS x25=0x763ac790a0 vals=000000013AC79970D1966ED0719C5DF03AC791E0CC16EDB0
S1_ARGS x25=0x763ac78a70 vals=000000013AC78AF8000000006FAE3C703AC78B1070D35838
CERT 0000000000000000 = 2C98831C2D205C5650AEC8BE0DC443E5A1E49A8AAF93ABA8

Challenge AABBCCDDEEFF0011:
S1_ARGS x25=0x763ac790a0 vals=0000000100000001000000000000000000000000400300CC
S1_ARGS x25=0x763ac790a0 vals=000000013AC79970D1966ED0719C9CF03AC791E0CC16EDB0
S1_ARGS x25=0x763ac78a70 vals=000000013AC78AF8000000006FAE3C703AC78B1070D35838
CERT AABBCCDDEEFF0011 = F6EE2878618D9EB4649BE8D98B45DFF30CAF9104B2EA8239
```

## Stable Facts

- Each cert call triggers exactly `3` `S1_ARGS` records.
- `call[0]` is invariant across init and both challenge-bearing queries.
- `call[2]` is also invariant across init and both challenge-bearing queries.
- `call[1]` is the only challenge-sensitive record in this sample set.
- The cert output changed from the earlier run because this is a fresh spawn with a different live process layout.

## Important Offset Correction

The varying field in `call[1]` is best described as:

- zero-based byte offsets `[14:16)` within the 24-byte `vals` payload, or
- the low 16 bits of 32-bit word index `3`

The three observed `call[1]` values are:

- init: `000000013AC79970D1966ED0719C74703AC791E0CC16EDB0`
- challenge `0000000000000000`: `000000013AC79970D1966ED0719C5DF03AC791E0CC16EDB0`
- challenge `AABBCCDDEEFF0011`: `000000013AC79970D1966ED0719C9CF03AC791E0CC16EDB0`

Only the tail of the fourth 32-bit lane changes:

- init: `0x719c7470`
- challenge `0000000000000000`: `0x719c5df0`
- challenge `AABBCCDDEEFF0011`: `0x719c9cf0`

So the earlier shorthand "bytes 16-19" was too loose. The concrete diff in this capture is narrower than that.

## Immediate Interpretation

- `call[0]` and `call[2]` look like fixed context or formatting material for this process instance.
- `call[1]` likely carries the challenge-fed selector, pointer, or short-lived state handle that makes the cert output query-specific.
- Because only one narrow field changes while the final cert changes completely, the nonlinear mixing likely happens after this `S1` formatting step rather than inside the fixed fields themselves.

## Local Helper

Use the local parser to diff future traces:

```bash
python3 scripts/analyze_s1_args.py capture/manual/S1_CERT_OBSERVATIONS_2026-04-05.md
```
