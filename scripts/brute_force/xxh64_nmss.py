#!/usr/bin/env python3
"""Reference xxHash64 with selectable P5 — validates std first then swaps."""
import struct
import xxhash


MASK64 = (1 << 64) - 1

# Canonical xxHash64 primes (verified against real xxhash C lib output).
# The Rust file's "STANDARD_PRIME5 = ...C1" label is incorrect — real
# canonical P5 ends in C5.  We follow the canonical reference here and
# treat the alternate value as the NMSS-specific candidate.
STD_P1 = 0x9E3779B185EBCA87
STD_P2 = 0xC2B2AE3D27D4EB4F
STD_P3 = 0x165667B19E3779F9
STD_P4 = 0x85EBCA77C2B2AE63
STD_P5 = 0x27D4EB2F165667C5  # canonical

# Rust crate exposes XXHASH64_NMSS_PRIME5 = 0x...C5 (same as canonical).
# The Rust comment's "std ends C1" is reversed — canonical std IS C5.
# If hash-worker observed C5 at the corridor, NMSS may be using standard
# P5.  The *candidate tweaked value* (bit-2 cleared from canonical) is
# 0x...C1 — still worth testing in case the direction was mislabeled.
NMSS_P5_CANDIDATE_A = 0x27D4EB2F165667C5  # Rust NMSS_PRIME5 = canonical
NMSS_P5_CANDIDATE_B = 0x27D4EB2F165667C1  # Rust "std" = possible tweak


def _rotl64(x: int, r: int) -> int:
    x &= MASK64
    return ((x << r) | (x >> (64 - r))) & MASK64


def xxh64(data: bytes, seed: int = 0,
          p1: int = STD_P1, p2: int = STD_P2,
          p3: int = STD_P3, p4: int = STD_P4, p5: int = STD_P5) -> int:
    """Portable xxHash64 with selectable primes."""
    seed &= MASK64
    n = len(data)
    i = 0

    def _round(v: int, k: int) -> int:
        v = (v + (k & MASK64) * p2) & MASK64
        v = _rotl64(v, 31)
        v = (v * p1) & MASK64
        return v

    def _merge(h: int, v: int) -> int:
        v = _round(0, v)
        h ^= v
        h = ((h * p1) + p4) & MASK64
        return h

    if n >= 32:
        v1 = (seed + p1 + p2) & MASK64
        v2 = (seed + p2) & MASK64
        v3 = (seed + 0) & MASK64
        v4 = (seed - p1) & MASK64
        while i + 32 <= n:
            k1 = struct.unpack_from("<Q", data, i)[0]
            k2 = struct.unpack_from("<Q", data, i + 8)[0]
            k3 = struct.unpack_from("<Q", data, i + 16)[0]
            k4 = struct.unpack_from("<Q", data, i + 24)[0]
            v1 = _round(v1, k1)
            v2 = _round(v2, k2)
            v3 = _round(v3, k3)
            v4 = _round(v4, k4)
            i += 32
        h64 = (_rotl64(v1, 1) + _rotl64(v2, 7)
               + _rotl64(v3, 12) + _rotl64(v4, 18)) & MASK64
        h64 = _merge(h64, v1)
        h64 = _merge(h64, v2)
        h64 = _merge(h64, v3)
        h64 = _merge(h64, v4)
    else:
        h64 = (seed + p5) & MASK64

    h64 = (h64 + n) & MASK64

    # 8-byte tail chunks
    while i + 8 <= n:
        k1 = struct.unpack_from("<Q", data, i)[0]
        k1 = _round(0, k1)
        h64 ^= k1
        h64 = (_rotl64(h64, 27) * p1 + p4) & MASK64
        i += 8

    # 4-byte tail
    if i + 4 <= n:
        k32 = struct.unpack_from("<I", data, i)[0] & 0xFFFFFFFF
        h64 ^= (k32 * p1) & MASK64
        h64 = (_rotl64(h64, 23) * p2 + p3) & MASK64
        i += 4

    # remaining bytes
    while i < n:
        b = data[i]
        h64 ^= (b * p5) & MASK64
        h64 = (_rotl64(h64, 11) * p1) & MASK64
        i += 1

    # finalizer
    h64 ^= h64 >> 33
    h64 = (h64 * p2) & MASK64
    h64 ^= h64 >> 29
    h64 = (h64 * p3) & MASK64
    h64 ^= h64 >> 32
    return h64


if __name__ == "__main__":
    # -- Validation against C library (standard primes) --
    test_cases = [
        (b"", 0),
        (b"", 1),
        (b"hello", 0),
        (b"hello world", 42),
        (b"A" * 32, 0),
        (b"A" * 33, 0),
        (b"A" * 40, 0xdeadbeef),
        (b"0123456789ABCDEF", 0),
        (b"0123456789ABCDEF", 0x9E3779B97F4A7C15),
        (bytes(range(100)), 0x1234),
    ]
    print("=== Validating standard primes against xxhash C impl ===")
    all_ok = True
    for data, seed in test_cases:
        my = xxh64(data, seed)
        ref = xxhash.xxh64_intdigest(data, seed=seed)
        ok = "OK" if my == ref else "FAIL"
        if my != ref:
            all_ok = False
        print(f"  {ok}  len={len(data):3d} seed=0x{seed:x}: "
              f"mine=0x{my:016x}  ref=0x{ref:016x}")
    print(f"Overall: {'PASS' if all_ok else 'FAIL'}")

    # -- Candidate P5 values — tiny input triggers P5 --
    print("\n=== Tiny-input P5 sensitivity ===")
    for data, seed in [(b"", 0), (b"A", 0), (b"ABCDEFGH", 0),
                       (b"0123456789ABCDEF", 0)]:
        a = xxh64(data, seed, p5=NMSS_P5_CANDIDATE_A)
        b = xxh64(data, seed, p5=NMSS_P5_CANDIDATE_B)
        diff = "DIFFERS" if a != b else "SAME"
        print(f"  len={len(data)} seed=0x{seed:x}: "
              f"candA(C5)=0x{a:016x}  candB(C1)=0x{b:016x}  {diff}")
