#!/usr/bin/env python3
"""Test mask hypothesis: cert_window = xxh64(input, seed) XOR mask_window.

If the mask is session-fixed per window, then for any correct (seed,
input_fn, window, endian), the residual xxh64(input, seed) XOR cert_window
is CONSTANT across all 17 pairs.  Search over the same seed/input pool
looking for constant residuals.
"""
import hashlib
import json
import struct
import xxhash
from collections import Counter


DATA = [json.loads(l) for l in open(
    "/home/sdancer/aeon-trace/capture/hash32_flip_corpus.json") if l.strip()]
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

# A narrower seed pool for speed (this test does more per-combo work)
seed_candidates = []
for v in (0, 1, 0xdeadbeef, 0xcafebabe,
          0x9E3779B97F4A7C15, 0xC6BC279692B5C323,
          0x1F16DAEBE44B8A35, 0x4BA4D4A13AB6F24F,
          server_id):
    seed_candidates.append((f"const_0x{v:x}", v))
for mat_name, mat in [("devid", device_id_bytes),
                       ("token", token_bytes),
                       ("nmnid[0:8]", nmnid_bytes[0:8]),
                       ("nmnid[8:16]", nmnid_bytes[8:16]),
                       ("nmnid[16:24]", nmnid_bytes[16:24]),
                       ("nmnid[24:32]", nmnid_bytes[24:32]),
                       ("acct[0:8]", account_pid_bytes[0:8]),
                       ("acct[8:16]", account_pid_bytes[8:16])]:
    for o in ("le", "be"):
        seed_candidates.append((f"{mat_name}_{o}", u64(mat, o)))
    seed_candidates.append((f"xxh64({mat_name})",
                             xxhash.xxh64_intdigest(mat)))

def input_candidates(challenge: str):
    ch_up = challenge.encode()
    ch_lo = challenge.lower().encode()
    ch_bytes = bytes.fromhex(challenge)
    return [
        ("ascii_up", ch_up),
        ("ascii_lo", ch_lo),
        ("hex8", ch_bytes),
        ("hex8_rev", ch_bytes[::-1]),
        ("hex8+devid", ch_bytes + device_id_bytes),
        ("devid+hex8", device_id_bytes + ch_bytes),
        ("hex8+nmnid[:8]", ch_bytes + nmnid_bytes[:8]),
        ("ascii+devid", ch_up + device_id_bytes),
    ]

msg_name_set = [n for n, _ in input_candidates(DATA[0]["challenge"])]

hash_fns = [
    ("xxh64", lambda data, seed: xxhash.xxh64_intdigest(data, seed=seed)),
    ("xxh3_64", lambda data, seed: xxhash.xxh3_64_intdigest(data, seed=seed)),
]

print(f"pairs={len(DATA)} seeds={len(seed_candidates)} "
      f"inputs={len(msg_name_set)} × 3 windows × 2 endians × 2 hashes")
print("Scanning for constant-residual (mask) hypothesis...")

found = []
total = 0
near = []  # (max_count_of_most_common_residual, ...)

for hf_name, hf in hash_fns:
    for window in (0, 1, 2):
        for endian in ("le", "be"):
            for seed_name, seed_val in seed_candidates:
                for input_name in msg_name_set:
                    total += 1
                    residuals = []
                    try:
                        for idx, d in enumerate(DATA):
                            data_bytes = dict(input_candidates(d["challenge"]))[input_name]
                            got = hf(data_bytes, seed_val)
                            exp = pair_windows[idx][window][endian]
                            residuals.append(got ^ exp)
                    except Exception:
                        continue
                    unique = set(residuals)
                    # ALL pairs produce same residual → mask found
                    if len(unique) == 1:
                        found.append((hf_name, window, endian, seed_name,
                                       input_name, seed_val, residuals[0]))
                    else:
                        most_common = Counter(residuals).most_common(1)[0]
                        if most_common[1] >= 3:
                            near.append((most_common[1], hf_name, window,
                                          endian, seed_name, input_name,
                                          most_common[0]))

print(f"Total scans: {total}")
print(f"CONSTANT-RESIDUAL hits (mask hypothesis confirmed): {len(found)}")
for h in found:
    print(f"  {h[0]} WIN{h[1]} {h[2]}: seed={h[3]}(=0x{h[5]:x}) "
          f"input={h[4]} mask=0x{h[6]:016x}")

near.sort(reverse=True)
print(f"\nTop near-constant residuals (>=3/{len(DATA)} pairs share one residual):")
for k, hf_name, w, e, sn, inn, r in near[:15]:
    print(f"  {k}/{len(DATA)}  {hf_name} WIN{w} {e}  seed={sn} input={inn} "
          f"residual=0x{r:016x}")
