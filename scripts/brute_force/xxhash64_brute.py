#!/usr/bin/env python3
"""Brute-force 3× xxHash64 seeds + input construction against 7 wire pairs.

Per fact cert-architecture-3-xxhash64: cert (24B) = xxHash64(data0, seed0) ||
xxHash64(data1, seed1) || xxHash64(data2, seed2).  xxHash64 is known and
confirmed at corridor 0x134F30.

Since xxHash64 has strong avalanche, a false-positive across 7 pairs has
probability ~2^(-448).  Any full-match of (seed, input_fn) is definitive.
"""
import json
import struct
import xxhash
from itertools import product


DATA = [json.loads(l) for l in open(
    "/home/sdancer/aeon-trace/capture/hash32_flip_corpus.json") if l.strip()]
print(f"{len(DATA)} pairs loaded")

S = DATA[0]["session"]
device_id_bytes = bytes.fromhex(S["device_id"])
token_bytes = bytes.fromhex(S["token"])
account_pid_bytes = bytes.fromhex(S["account_pid"])
nmnid_bytes = bytes.fromhex(S["nmnid"])
nid_ascii = S["nid"].encode()
nid_after_N = S["nid"][1:].encode()
server_id = S["server_id"]
asset_version = S["asset_version"]

# Pre-decompose each pair's cert into 3 × 8-byte windows, each as LE and BE u64
pair_windows = []
for d in DATA:
    cert = bytes.fromhex(d["cert"])
    w = []
    for off in (0, 8, 16):
        blk = cert[off:off+8]
        w.append({"le": struct.unpack("<Q", blk)[0],
                  "be": struct.unpack(">Q", blk)[0]})
    pair_windows.append(w)


# -- Seed candidate generator (u64 values) ---------------------------------
def u64(b: bytes, order: str) -> int:
    return struct.unpack("<Q" if order == "le" else ">Q", b)[0]

seed_candidates: list[tuple[str, int]] = []
# Fixed small constants
for v in (0, 1, 0xdeadbeef, 0xcafebabe, 0xDEADBABE, 0x9E3779B97F4A7C15):
    seed_candidates.append((f"const_0x{v:x}", v))
# Session numeric fields
seed_candidates.append(("server_id", server_id))
seed_candidates.append(("asset_version", asset_version))
# Device id as u64 (both endian)
for o in ("le", "be"):
    seed_candidates.append((f"device_id_{o}", u64(device_id_bytes, o)))
    seed_candidates.append((f"token_{o}", u64(token_bytes, o)))
    for start in range(0, 32, 8):
        seed_candidates.append(
            (f"nmnid[{start}:{start+8}]_{o}",
             u64(nmnid_bytes[start:start+8], o)))
    for start in range(0, 16, 8):
        seed_candidates.append(
            (f"account_pid[{start}:{start+8}]_{o}",
             u64(account_pid_bytes[start:start+8], o)))
# XOR combos
for o in ("le",):
    d = u64(device_id_bytes, o)
    t = u64(token_bytes, o)
    n0 = u64(nmnid_bytes[0:8], o)
    seed_candidates.append(("dev_xor_tok", d ^ t))
    seed_candidates.append(("dev_xor_nm0", d ^ n0))
    seed_candidates.append(("tok_xor_nm0", t ^ n0))

print(f"Seed candidates: {len(seed_candidates)}")


# -- Input construction candidates (functions of challenge) ----------------
def input_candidates(challenge: str) -> list[tuple[str, bytes]]:
    ch_up = challenge.encode()
    ch_lo = challenge.lower().encode()
    ch_bytes = bytes.fromhex(challenge)  # 8 bytes
    out = [
        ("ascii_up", ch_up),
        ("ascii_lo", ch_lo),
        ("hex8", ch_bytes),
        ("hex8_rev", ch_bytes[::-1]),
        ("ascii+devid_bytes", ch_up + device_id_bytes),
        ("devid_bytes+ascii", device_id_bytes + ch_up),
        ("hex8+devid", ch_bytes + device_id_bytes),
        ("devid+hex8", device_id_bytes + ch_bytes),
        ("hex8+token", ch_bytes + token_bytes),
        ("token+hex8", token_bytes + ch_bytes),
        ("hex8+nmnid", ch_bytes + nmnid_bytes),
        ("nmnid+hex8", nmnid_bytes + ch_bytes),
        ("hex8+nmnid[:16]", ch_bytes + nmnid_bytes[:16]),
        ("hex8+acct", ch_bytes + account_pid_bytes),
        ("acct+hex8", account_pid_bytes + ch_bytes),
        ("ascii+hex8", ch_up + ch_bytes),
        ("empty", b""),  # challenge conveyed via seed only
    ]
    return out

msg_name_set = [n for n, _ in input_candidates(DATA[0]["challenge"])]
print(f"Input constructions: {len(msg_name_set)}")


# -- Main loop: per-window search ------------------------------------------
hits = []  # (window, endian, seed_name, input_name, seed_value)
total = 0

for window in (0, 1, 2):
    for endian in ("le", "be"):
        for seed_name, seed_val in seed_candidates:
            for input_name in msg_name_set:
                total += 1
                ok = True
                for idx, d in enumerate(DATA):
                    inputs = dict(input_candidates(d["challenge"]))
                    data_bytes = inputs[input_name]
                    got = xxhash.xxh64_intdigest(data_bytes,
                                                  seed=seed_val)
                    expected = pair_windows[idx][window][endian]
                    if got != expected:
                        ok = False
                        break
                if ok:
                    hits.append((window, endian, seed_name,
                                 input_name, seed_val))

print(f"\nScans: {total}")
print(f"Hits: {len(hits)}")
for h in hits:
    print(f"  WIN{h[0]} {h[1]}: seed={h[2]}(=0x{h[4]:x}) input={h[3]}")

# Even without full match, report partial-coverage hits per window:
# for each (window, endian, seed, input) combo that matches k/7 pairs.
print("\nPartial hits (>=2 of 7 pairs match):")
partial = []
for window in (0, 1, 2):
    for endian in ("le", "be"):
        for seed_name, seed_val in seed_candidates:
            for input_name in msg_name_set:
                k = 0
                for idx, d in enumerate(DATA):
                    inputs = dict(input_candidates(d["challenge"]))
                    data_bytes = inputs[input_name]
                    got = xxhash.xxh64_intdigest(data_bytes, seed=seed_val)
                    expected = pair_windows[idx][window][endian]
                    if got == expected:
                        k += 1
                if k >= 2:
                    partial.append((k, window, endian, seed_name, input_name))
partial.sort(reverse=True)
for p in partial[:10]:
    print(f"  {p[0]}/7  WIN{p[1]} {p[2]}  seed={p[3]}  input={p[4]}")
