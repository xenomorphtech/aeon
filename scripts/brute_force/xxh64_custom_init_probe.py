#!/usr/bin/env python3
"""Custom-init xxHash64 cert pipeline probe.

Per fact nmss-xxh64-custom-init, cert is produced by xxHash64 with
non-canonical INIT lanes over a 16449-byte template buffer.  This probe:

1. Loads the reference implementation from aeon-trace.
2. Verifies against the static capture (matches raw32_02 post-update AND
   the reference cert "22091D63..." from codex-tui.log for the challenge
   "test_challenge_12345").
3. Tests the reference INIT against the session-5 wire pairs in
   hash32_flip_corpus.json — result: 0/N matches under the capture's
   template.
4. Demonstrates that v1, v2 appear session-invariant across pairs WHEN
   the capture's template is reused — this is an ARTEFACT of using the
   wrong (unsubstituted) template, not evidence of a real structural
   invariant.  With the real per-session substituted template, v1, v2
   would vary per pair because the substituted template's trailing
   bytes (before 0x2010) contain per-call session data (timestamps, PID,
   UdId, CODE_*, etc.).
5. Sweeps session-material-derived INIT candidates and page-resident
   INIT candidates — all negative.

REVISED CONCLUSION (per fact xxh64-init-captured-5556):
------------------------------------------------------
The INIT quartet is STATIC — binary-confirmed by trace-claude2
(load+store path at 0xf9728 / 0xf9868 with no intermediate modification).
The blocker is NOT the INIT lanes; it's the 495-byte TEMPLATE at buffer
offset 0x0..0x1EF, which is a printf(%s/%d) format string whose
placeholders get substituted at runtime with session-specific data
(session token, device_id, PID, CODE_* values, timestamps, PlayerId,
etc.).

Unblock gate:  the live 16449-byte buffer content itself, obtained via a
Frida hook at the xxHash64 call site (data_ptr 0xb4000075254959a0 on
device 5558 per fact xxh64-init-captured-5556).  Once the buffer is
dumped, feed it into xxh64_live_buffer_validator.py — the moment any
wire-pair cert matches, the pipeline closes.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path


REFERENCE_PY = Path("/home/sdancer/aeon-trace/scripts/nmss_cert_hash.py")
CAPTURE_DIR = Path("/home/sdancer/aeon-ollvm/analysis/hash_attempt_4/cert_trace")
WIRE_CORPUS = Path("/home/sdancer/aeon-trace/capture/hash32_flip_corpus.json")
PAGE_436 = Path("/home/sdancer/aeon-ollvm/capture/manual/nmss_emu/del3_DATA_436.bin")


def _import_reference():
    sys.path.insert(0, str(REFERENCE_PY.parent))
    import nmss_cert_hash
    return nmss_cert_hash


def verify_reference_against_capture(mod) -> bool:
    """Confirm the reference .py reproduces the capture's raw32_02 + cert."""
    body = (CAPTURE_DIR / "hash_update_16449.bin").read_bytes()
    raw32_02 = struct.unpack("<4Q", (CAPTURE_DIR / "cmd1e_hash_raw32_02.bin").read_bytes())
    v1, v2, v3, v4, rem, total = mod.hash_update(
        body, mod.INIT_V1, mod.INIT_V2, mod.INIT_V3, mod.INIT_V4)
    state_ok = (v1, v2, v3, v4) == raw32_02

    fold = mod.hash_finalize(v1, v2, v3, v4, rem, total)
    cert24 = fold[:24].hex().upper()
    # Known-good cert from codex-tui.log for challenge "test_challenge_12345":
    cert_ok = cert24 == "22091D63655A6D98683CC13C3D811B295AAD9FC924A72674"
    return state_ok and cert_ok


def test_session5_pairs(mod) -> tuple[int, int]:
    """Run reference hash against 19 wire pairs — expected 0 until
    session-5 INIT lanes are known."""
    template = (CAPTURE_DIR / "hash_update_16449.bin").read_bytes()[:0x1EF]
    data = [json.loads(l) for l in WIRE_CORPUS.read_text().splitlines() if l.strip()]
    hits = 0
    for d in data:
        buf = mod.build_hash_buffer(template, d["challenge"])
        v1, v2, v3, v4, rem, total = mod.hash_update(
            buf, mod.INIT_V1, mod.INIT_V2, mod.INIT_V3, mod.INIT_V4)
        fold = mod.hash_finalize(v1, v2, v3, v4, rem, total)
        if fold[:24].hex().upper() == d["cert"]:
            hits += 1
    return hits, len(data)


def prove_v1v2_invariant(mod) -> tuple[int, int]:
    """Demonstrate v1, v2 are constant across all session-5 pairs."""
    template = (CAPTURE_DIR / "hash_update_16449.bin").read_bytes()[:0x1EF]
    data = [json.loads(l) for l in WIRE_CORPUS.read_text().splitlines() if l.strip()]
    v1_set, v2_set, v3_set, v4_set = set(), set(), set(), set()
    for d in data:
        buf = mod.build_hash_buffer(template, d["challenge"])
        v1, v2, v3, v4, _, _ = mod.hash_update(
            buf, mod.INIT_V1, mod.INIT_V2, mod.INIT_V3, mod.INIT_V4)
        v1_set.add(v1); v2_set.add(v2); v3_set.add(v3); v4_set.add(v4)
    return len(v1_set), len(v2_set), len(v3_set), len(v4_set)


def sweep_page_resident_inits(mod) -> int:
    """Scan del3_DATA_436 for any 4-u64 window that matches session 5 certs."""
    template = (CAPTURE_DIR / "hash_update_16449.bin").read_bytes()[:0x1EF]
    data = [json.loads(l) for l in WIRE_CORPUS.read_text().splitlines() if l.strip()][:3]
    page = PAGE_436.read_bytes()
    total = 0
    for xor_key in (0x00, 0x78):
        p = bytes(b ^ xor_key for b in page) if xor_key else page
        for off in range(0, len(p) - 32, 8):
            for endian in ("<", ">"):
                V = struct.unpack(f"{endian}4Q", p[off:off+32])
                total += 1
                hits = 0
                for d in data:
                    buf = mod.build_hash_buffer(template, d["challenge"])
                    v1, v2, v3, v4, rem, tl = mod.hash_update(buf, *V)
                    fold = mod.hash_finalize(v1, v2, v3, v4, rem, tl)
                    if fold[:24].hex().upper() == d["cert"]:
                        hits += 1
                if hits:
                    return hits  # early-exit on any win
    return 0  # all negative


def main() -> int:
    mod = _import_reference()

    print("=== Reference .py self-verification ===")
    if not verify_reference_against_capture(mod):
        print("  FAIL: reference doesn't match capture — aborting")
        return 1
    print("  OK: matches raw32_02 AND cert '22091D63...' for test_challenge_12345")

    print("\n=== Session-5 wire pairs against reference INIT ===")
    hits, total = test_session5_pairs(mod)
    print(f"  {hits}/{total} match")
    if hits == total:
        print("  *** ALL PAIRS MATCH — cert pipeline closed ***")
        return 0

    print("\n=== v1, v2 invariance across session-5 pairs ===")
    n1, n2, n3, n4 = prove_v1v2_invariant(mod)
    print(f"  unique v1={n1}  v2={n2}  v3={n3}  v4={n4}")
    print(f"  (v1, v2 should be 1/1 — challenge only enters lanes v3, v4)")

    print("\n=== Page-resident INIT sweep ===")
    sweep_hits = sweep_page_resident_inits(mod)
    print(f"  sweep hits: {sweep_hits}")

    print("\nREVISED: INIT is static (binary-confirmed). Remaining unknown is")
    print("the 495-byte template contents (session-substituted printf fields).")
    print("Drop a live 16449-byte buffer into")
    print("  python3 scripts/brute_force/xxh64_live_buffer_validator.py BUF.bin")
    print("to close the loop as soon as trace-claude dumps the live buffer.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
