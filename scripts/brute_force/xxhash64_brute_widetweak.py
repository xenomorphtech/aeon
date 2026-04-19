#!/usr/bin/env python3
"""Wide 1-bit-tweak brute force over xxHash64 primes P1..P5.

For each of 5 primes, flip each of 64 bits (320 candidate prime sets).
Per candidate, scan a reduced seed/input pool against the 17 wire pairs.
k >= 1 pair match is diagnostic (chance ~10^-18 per scan).

If zero k>=1 hits across 320 × 2 endians × 3 windows × pool, the
primes-with-1-bit-tweak hypothesis is fully exhausted — the remaining
live theory is the ~232B pre-processed input buffer.
"""
import hashlib
import json
import struct
import sys
import time

sys.path.insert(0, "/home/sdancer/aeon-ollvm-codex1/scripts/brute_force")
from xxh64_nmss import xxh64, STD_P1, STD_P2, STD_P3, STD_P4, STD_P5


DATA = [json.loads(l) for l in open(
    "/home/sdancer/aeon-trace/capture/hash32_flip_corpus.json") if l.strip()]
print(f"{len(DATA)} pairs loaded")
S = DATA[0]["session"]

device_id_bytes = bytes.fromhex(S["device_id"])
token_bytes = bytes.fromhex(S["token"])
account_pid_bytes = bytes.fromhex(S["account_pid"])
nmnid_bytes = bytes.fromhex(S["nmnid"])
nid_ascii = S["nid"].encode()
server_id = S["server_id"]

pair_windows = []
for d in DATA:
    cert = bytes.fromhex(d["cert"])
    w = []
    for off in (0, 8, 16):
        blk = cert[off:off+8]
        w.append({"le": struct.unpack("<Q", blk)[0],
                  "be": struct.unpack(">Q", blk)[0]})
    pair_windows.append(w)


def u64(b, o): return struct.unpack("<Q" if o == "le" else ">Q", b)[0]


# Small seed pool — keep brute tractable
seed_candidates: list[tuple[str, int]] = []
for v in (0, 1, 0xdeadbeef, 0xcafebabe, 0x9E3779B97F4A7C15,
          0xC6BC279692B5C323, server_id):
    seed_candidates.append((f"const_0x{v:x}", v))
for mat_name, mat in [("devid", device_id_bytes),
                       ("token", token_bytes),
                       ("nmnid8", nmnid_bytes[:8]),
                       ("nmnid16", nmnid_bytes[8:16]),
                       ("acct8", account_pid_bytes[:8])]:
    seed_candidates.append((f"{mat_name}_le", u64(mat, "le")))
    seed_candidates.append((f"{mat_name}_be", u64(mat, "be")))
_seen = set(); uniq = []
for n, v in seed_candidates:
    if v in _seen: continue
    _seen.add(v); uniq.append((n, v))
seed_candidates = uniq
print(f"Seed pool: {len(seed_candidates)}")


# Small input pool — forms most likely given session-scoped hashing
def input_candidates(challenge: str):
    ch_up = challenge.encode()
    ch_bytes = bytes.fromhex(challenge)
    return [
        ("ascii_up", ch_up),
        ("hex8", ch_bytes),
        ("ascii+devid", ch_up + device_id_bytes),
        ("devid+ascii", device_id_bytes + ch_up),
        ("hex8+devid", ch_bytes + device_id_bytes),
        ("devid+hex8", device_id_bytes + ch_bytes),
        ("hex8+nmnid8", ch_bytes + nmnid_bytes[:8]),
        ("hex8+token", ch_bytes + token_bytes),
    ]
msg_names = [n for n, _ in input_candidates(DATA[0]["challenge"])]
print(f"Input pool: {len(msg_names)}")

STD_PRIMES = [STD_P1, STD_P2, STD_P3, STD_P4, STD_P5]


def scan_primeset(primes, seed_val, input_name, window, endian) -> int:
    """Return number of pairs matching under these primes/config."""
    k = 0
    for idx, d in enumerate(DATA):
        data_bytes = dict(input_candidates(d["challenge"]))[input_name]
        got = xxh64(data_bytes, seed_val,
                    p1=primes[0], p2=primes[1], p3=primes[2],
                    p4=primes[3], p5=primes[4])
        expected = pair_windows[idx][window][endian]
        if got == expected:
            k += 1
    return k


print("\nWide 1-bit-tweak sweep (5 primes × 64 bits each)...")
t0 = time.time()
total_scans = 0
hits = []

for prime_idx in range(5):
    for bit_pos in range(64):
        candidate = STD_PRIMES.copy()
        candidate[prime_idx] ^= (1 << bit_pos)
        for seed_name, seed_val in seed_candidates:
            for input_name in msg_names:
                for window in (0, 1, 2):
                    for endian in ("le", "be"):
                        total_scans += 1
                        k = scan_primeset(candidate, seed_val, input_name,
                                           window, endian)
                        if k >= 1:
                            hits.append((k, prime_idx, bit_pos,
                                          seed_name, input_name, window, endian))
    # progress heartbeat per prime
    print(f"  P{prime_idx+1} done  elapsed={time.time()-t0:.1f}s  "
          f"scans={total_scans}  hits_so_far={len(hits)}")

dt = time.time() - t0
print(f"\nTotal scans: {total_scans}  elapsed: {dt:.1f}s")
print(f"k>=1 hits: {len(hits)}")
hits.sort(reverse=True)
for h in hits[:25]:
    k, pidx, bp, sn, inn, w, e = h
    print(f"  k={k}/{len(DATA)}  P{pidx+1}^bit{bp}  seed={sn}  input={inn}  "
          f"WIN{w} {e}")

# If any k>=2, highlight
big = [h for h in hits if h[0] >= 2]
print(f"\nk>=2 hits: {len(big)}")
for h in big:
    print(f"  {h}")
