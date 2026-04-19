#!/usr/bin/env python3
"""Brute force 3× xxHash64 with NMSS P5=0x...C1 (bit-2 cleared from canonical).

Same (seed, input) enumeration as the earlier std-prime scan.  If this
scan also produces 0 matches, the hypothesis is that input preprocessing
differs (~232-byte buffer) — not the primes.
"""
import hashlib
import json
import struct
import sys
sys.path.insert(0, "/tmp")
from xxh64_nmss import xxh64, STD_P1, STD_P2, STD_P3, STD_P4, NMSS_P5_CANDIDATE_A, NMSS_P5_CANDIDATE_B


DATA = [json.loads(l) for l in open(
    "/home/sdancer/aeon-trace/capture/hash32_flip_corpus.json") if l.strip()]
print(f"{len(DATA)} pairs loaded")
S = DATA[0]["session"]

device_id_bytes = bytes.fromhex(S["device_id"])
device_id_lo = S["device_id"].lower().encode()
device_id_up = S["device_id"].upper().encode()
token_bytes = bytes.fromhex(S["token"])
token_ascii = S["token"].encode()
account_pid_bytes = bytes.fromhex(S["account_pid"])
account_pid_ascii = S["account_pid"].encode()
nmnid_bytes = bytes.fromhex(S["nmnid"])
nmnid_ascii = S["nmnid"].encode()
nid_ascii = S["nid"].encode()
server_id = S["server_id"]
asset_version = S["asset_version"]


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


# Seed candidates (same pool that failed earlier, plus a few more)
seed_candidates = []
for v in (0, 1, 2, 3, 0xdeadbeef, 0xcafebabe,
          0x9E3779B97F4A7C15, 0xC6BC279692B5C323,
          0x1F16DAEBE44B8A35, 0x4BA4D4A13AB6F24F,
          server_id, asset_version, 0x41, 0x30, 0x43, 0x5506, 0x5501):
    seed_candidates.append((f"const_0x{v:x}", v))

material = {
    "device_id_bytes": device_id_bytes,
    "token_bytes": token_bytes,
    "account_pid_bytes": account_pid_bytes,
    "nmnid_bytes": nmnid_bytes,
    "device_id_lo": device_id_lo,
    "device_id_up": device_id_up,
    "token_ascii": token_ascii,
    "nmnid_ascii": nmnid_ascii,
    "account_pid_ascii": account_pid_ascii,
    "nid_ascii": nid_ascii,
}
for mname, mbytes in material.items():
    for start in range(0, max(1, len(mbytes) - 7)):
        if start + 8 > len(mbytes):
            break
        for o in ("le", "be"):
            seed_candidates.append(
                (f"{mname}[{start}:{start+8}]_{o}",
                 u64(mbytes[start:start+8], o)))
    h = hashlib.sha256(mbytes).digest()
    seed_candidates.append((f"sha256({mname})[:8]_le", u64(h[:8], "le")))
    seed_candidates.append((f"sha256({mname})[:8]_be", u64(h[:8], "be")))

# Dedup
_seen = set()
uniq = []
for n, v in seed_candidates:
    if v in _seen:
        continue
    _seen.add(v)
    uniq.append((n, v))
seed_candidates = uniq
print(f"Unique seed candidates: {len(seed_candidates)}")


def input_candidates(challenge: str):
    ch_up = challenge.encode()
    ch_lo = challenge.lower().encode()
    ch_bytes = bytes.fromhex(challenge)
    return [
        ("ascii_up", ch_up),
        ("ascii_lo", ch_lo),
        ("hex8", ch_bytes),
        ("hex8_rev", ch_bytes[::-1]),
        ("empty", b""),
        ("hex8+devid", ch_bytes + device_id_bytes),
        ("devid+hex8", device_id_bytes + ch_bytes),
        ("ascii+devid", ch_up + device_id_bytes),
        ("devid+ascii", device_id_bytes + ch_up),
        ("hex8+token", ch_bytes + token_bytes),
        ("token+hex8", token_bytes + ch_bytes),
        ("hex8+nmnid", ch_bytes + nmnid_bytes),
        ("nmnid+hex8", nmnid_bytes + ch_bytes),
        ("hex8+nmnid8", ch_bytes + nmnid_bytes[:8]),
        ("nmnid8+hex8", nmnid_bytes[:8] + ch_bytes),
        ("hex8+acct", ch_bytes + account_pid_bytes),
        ("acct+hex8", account_pid_bytes + ch_bytes),
        ("ascii+hex8", ch_up + ch_bytes),
        ("hex8+dev+token", ch_bytes + device_id_bytes + token_bytes),
    ]

msg_name_set = [n for n, _ in input_candidates(DATA[0]["challenge"])]
print(f"Input constructions: {len(msg_name_set)}")


# Use NMSS primes P1..P4 (std) + P5 = Candidate B (0x...C1)
def nmss_xxh64(data: bytes, seed: int) -> int:
    return xxh64(data, seed, p1=STD_P1, p2=STD_P2, p3=STD_P3, p4=STD_P4,
                 p5=NMSS_P5_CANDIDATE_B)


def std_xxh64(data: bytes, seed: int) -> int:
    return xxh64(data, seed, p5=NMSS_P5_CANDIDATE_A)


hash_fns = [
    ("nmss_xxh64", nmss_xxh64),
    ("std_xxh64",  std_xxh64),
]

print("\nScanning NMSS xxh64 + std xxh64 against 17 pairs...")
total = 0
hits = []
from collections import Counter
k_dist = Counter()

for hf_name, hf in hash_fns:
    for window in (0, 1, 2):
        for endian in ("le", "be"):
            for seed_name, seed_val in seed_candidates:
                for input_name in msg_name_set:
                    total += 1
                    k = 0
                    for idx, d in enumerate(DATA):
                        data_bytes = dict(input_candidates(d["challenge"]))[input_name]
                        got = hf(data_bytes, seed_val)
                        expected = pair_windows[idx][window][endian]
                        if got == expected:
                            k += 1
                    k_dist[k] += 1
                    if k == len(DATA):
                        hits.append((hf_name, window, endian, seed_name,
                                      input_name, seed_val))
                        print(f"  !!! FULL HIT {hf_name} WIN{window} {endian} "
                              f"seed={seed_name}(=0x{seed_val:x}) input={input_name}")

print(f"\nTotal scans: {total}")
print(f"k-hit distribution: {sorted(k_dist.items(), reverse=True)[:20]}")
print(f"Full hits: {len(hits)}")

# Also: mask hypothesis with NMSS P5
print("\n=== Mask hypothesis under NMSS P5=Candidate B ===")
mask_hits = 0
for hf_name, hf in hash_fns:
    for window in (0, 1, 2):
        for endian in ("le", "be"):
            for seed_name, seed_val in seed_candidates:
                for input_name in msg_name_set:
                    residuals = []
                    for idx, d in enumerate(DATA):
                        data_bytes = dict(input_candidates(d["challenge"]))[input_name]
                        got = hf(data_bytes, seed_val)
                        exp = pair_windows[idx][window][endian]
                        residuals.append(got ^ exp)
                    if len(set(residuals)) == 1:
                        mask_hits += 1
                        print(f"  !!! MASK HIT {hf_name} WIN{window} {endian} "
                              f"seed={seed_name}(=0x{seed_val:x}) "
                              f"input={input_name} mask=0x{residuals[0]:016x}")
print(f"Total mask hits: {mask_hits}")
