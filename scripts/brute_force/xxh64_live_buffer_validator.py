#!/usr/bin/env python3
"""Validator: given a live 16449-byte hash-update buffer dumped from a
session's xxHash64 input, verify that the reference pipeline reproduces
every wire-captured cert in hash32_flip_corpus.json.

Post-fact cert-emu-custom-init-validated-not-solved revision: per fact
xxh64-init-captured-5556, INIT is static (binary-confirmed load+store
path at 0xf9728/0xf9868).  The per-session variability lives in the
495-byte template region at buffer offset 0x0..0x1EF, which contains
session-substituted printf(%s/%d) placeholders (PID, UdId, timestamps,
CODE_*, etc.).

Usage:
    $ python3 scripts/brute_force/xxh64_live_buffer_validator.py BUF.bin

If BUF.bin is 16449 bytes, overlays each wire-pair challenge at offset
0x2010, re-hashes, and compares to the cert.  Exits 0 on full match.

When the buffer dump is for a SINGLE session-5 pair (real template +
real challenge baked in), we still overlay the other 18 pairs' challenges
to test the template fix.  This works because the template (bytes
[0:0x2010]) is pair-invariant within a session so long as timestamps
don't embed into it — if they do, only the pair whose challenge
ORIGINALLY went with that template will match.
"""
import json
import struct
import sys
from pathlib import Path


BUFFER_SIZE = 16449
CHALLENGE_OFF = 0x2010
CHALLENGE_LEN = 16  # wire challenges are 16 ASCII hex chars

REFERENCE_PY_DIR = Path("/home/sdancer/aeon-trace/scripts")
WIRE_CORPUS = Path("/home/sdancer/aeon-trace/capture/hash32_flip_corpus.json")


def _import_reference():
    sys.path.insert(0, str(REFERENCE_PY_DIR))
    import nmss_cert_hash
    return nmss_cert_hash


def _load_wire_pairs() -> list[dict]:
    return [json.loads(l) for l in WIRE_CORPUS.read_text().splitlines() if l.strip()]


def validate_buffer(buf_path: Path, verbose: bool = True) -> tuple[int, int]:
    mod = _import_reference()
    if len(buf_path.read_bytes()) != BUFFER_SIZE:
        print(f"  ERROR: buffer is {len(buf_path.read_bytes())} bytes, "
              f"expected {BUFFER_SIZE}", file=sys.stderr)
        return 0, 0

    buf = buf_path.read_bytes()
    pairs = _load_wire_pairs()
    if verbose:
        print(f"  Buffer: {buf_path} ({len(buf)} B)")
        print(f"  Wire pairs: {len(pairs)}")
        print(f"  Template head ({buf[:60].decode('ascii', errors='replace')!r}...)")
        print(f"  Challenge slot @0x{CHALLENGE_OFF:04x}: "
              f"{buf[CHALLENGE_OFF:CHALLENGE_OFF+CHALLENGE_LEN]!r}")

    hits = 0
    for d in pairs:
        ch = d["challenge"]
        cert_expected = d["cert"]
        # Overlay this pair's challenge at offset 0x2010
        swapped = bytearray(buf)
        swapped[CHALLENGE_OFF:CHALLENGE_OFF + CHALLENGE_LEN] = ch.encode()
        v1, v2, v3, v4, rem, total = mod.hash_update(
            bytes(swapped), mod.INIT_V1, mod.INIT_V2, mod.INIT_V3, mod.INIT_V4)
        fold = mod.hash_finalize(v1, v2, v3, v4, rem, total)
        got = fold[:24].hex().upper()
        if got == cert_expected:
            hits += 1
            if verbose:
                print(f"    ✓ {ch} → {got}")
        else:
            if verbose:
                print(f"    ✗ {ch}  want {cert_expected[:24]}…  got {got[:24]}…")
    return hits, len(pairs)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        print(f"Usage: {sys.argv[0]} BUFFER.bin", file=sys.stderr)
        return 2
    p = Path(sys.argv[1])
    if not p.exists():
        print(f"no such file: {p}", file=sys.stderr)
        return 2
    hits, total = validate_buffer(p, verbose=True)
    print(f"\nResult: {hits}/{total} match")
    if hits == total and total > 0:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
