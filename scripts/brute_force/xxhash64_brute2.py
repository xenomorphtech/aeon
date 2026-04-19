#!/usr/bin/env python3
"""Expanded search: xxHash64 + xxh3_64 × derived seeds × many input forms."""
import hashlib
import json
import struct
import xxhash


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

# Pre-decompose each cert
pair_windows = []
for d in DATA:
    cert = bytes.fromhex(d["cert"])
    w = []
    for off in (0, 8, 16):
        blk = cert[off:off+8]
        w.append({"le": struct.unpack("<Q", blk)[0],
                  "be": struct.unpack(">Q", blk)[0]})
    pair_windows.append(w)


def u64(b: bytes, order: str) -> int:
    return struct.unpack("<Q" if order == "le" else ">Q", b)[0]


# --- WIDER seed generation ---
seed_candidates: list[tuple[str, int]] = []
for v in (0, 1, 2, 3, 0xdeadbeef, 0xcafebabe,
          0x9E3779B97F4A7C15, 0xC6BC279692B5C323,  # golden ratio, XXH64 prime
          0x1F16DAEBE44B8A35, 0x4BA4D4A13AB6F24F,
          server_id, asset_version):
    seed_candidates.append((f"const_0x{v:x}", v))

# All 8-byte windows of each material in both orders
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
    # Whole thing hashed to a seed via SHA-256
    h = hashlib.sha256(mbytes).digest()
    seed_candidates.append(
        (f"sha256({mname})[:8]_le", u64(h[:8], "le")))
    seed_candidates.append(
        (f"sha256({mname})[:8]_be", u64(h[:8], "be")))
    # xxHash64 of material as seed
    seed_candidates.append(
        (f"xxh64({mname})", xxhash.xxh64_intdigest(mbytes)))

# Deduplicate by numeric value
_seen = set()
uniq = []
for n, v in seed_candidates:
    if v in _seen:
        continue
    _seen.add(v)
    uniq.append((n, v))
seed_candidates = uniq
print(f"Unique seed candidates: {len(seed_candidates)}")


# --- WIDER input construction ---
def input_candidates(challenge: str) -> list[tuple[str, bytes]]:
    ch_up = challenge.encode()
    ch_lo = challenge.lower().encode()
    ch_bytes = bytes.fromhex(challenge)
    out = [
        ("ascii_up", ch_up),
        ("ascii_lo", ch_lo),
        ("hex8", ch_bytes),
        ("hex8_rev", ch_bytes[::-1]),
        ("empty", b""),
    ]
    # challenge bytes + each session piece
    for name, piece in [
        ("devid", device_id_bytes),
        ("token", token_bytes),
        ("acct", account_pid_bytes),
        ("nmnid", nmnid_bytes),
        ("nmnid16", nmnid_bytes[:16]),
        ("nmnid8", nmnid_bytes[:8]),
    ]:
        out.append((f"hex8+{name}", ch_bytes + piece))
        out.append((f"{name}+hex8", piece + ch_bytes))
        out.append((f"ascii+{name}", ch_up + piece))
        out.append((f"{name}+ascii", piece + ch_up))
    # challenge ASCII with concatenated ASCII material
    out.append(("ascii+devid_ascii_up", ch_up + device_id_up))
    out.append(("ascii+nmnid_ascii", ch_up + nmnid_ascii))
    out.append(("ascii+token_ascii", ch_up + token_ascii))
    # Multi-material combos
    out.append(("hex8+devid+token", ch_bytes + device_id_bytes + token_bytes))
    out.append(("devid+token+hex8", device_id_bytes + token_bytes + ch_bytes))
    out.append(("hex8+nmnid8+devid", ch_bytes + nmnid_bytes[:8] + device_id_bytes))
    return out

msg_name_set = [n for n, _ in input_candidates(DATA[0]["challenge"])]
print(f"Input constructions: {len(msg_name_set)}")


# --- Hash function variants ---
hash_fns = [
    ("xxh64",    lambda data, seed: xxhash.xxh64_intdigest(data, seed=seed)),
    ("xxh3_64",  lambda data, seed: xxhash.xxh3_64_intdigest(data, seed=seed)),
]


# --- Main loop: find seeds/inputs that match ALL pairs per window ---
hits = []
total = 0
full_hits_per_window = {0: 0, 1: 0, 2: 0}

print("\nScanning...")
for hf_name, hf in hash_fns:
    for window in (0, 1, 2):
        for endian in ("le", "be"):
            for seed_name, seed_val in seed_candidates:
                for input_name in msg_name_set:
                    total += 1
                    ok = True
                    for idx, d in enumerate(DATA):
                        data_bytes = dict(input_candidates(d["challenge"]))[input_name]
                        got = hf(data_bytes, seed_val)
                        expected = pair_windows[idx][window][endian]
                        if got != expected:
                            ok = False
                            break
                    if ok:
                        hits.append((hf_name, window, endian, seed_name,
                                     input_name, seed_val))
                        full_hits_per_window[window] += 1

print(f"Total scans: {total}")
print(f"Full hits: {len(hits)}")
for h in hits:
    print(f"  {h[0]} WIN{h[1]} {h[2]}: seed={h[3]}(=0x{h[5]:x}) input={h[4]}")

# Partial coverage report — most informative if zero full hits
if not hits:
    print("\n=== Partial-hit distribution (k = number of matching pairs) ===")
    from collections import Counter
    dist = Counter()
    best = []
    for hf_name, hf in hash_fns:
        for window in (0, 1, 2):
            for endian in ("le", "be"):
                for seed_name, seed_val in seed_candidates:
                    for input_name in msg_name_set:
                        k = 0
                        for idx, d in enumerate(DATA):
                            data_bytes = dict(input_candidates(d["challenge"]))[input_name]
                            got = hf(data_bytes, seed_val)
                            expected = pair_windows[idx][window][endian]
                            if got == expected:
                                k += 1
                        dist[k] += 1
                        if k >= 2:
                            best.append((k, hf_name, window, endian, seed_name, input_name))
    print("Distribution:", sorted(dist.items()))
    print(f"Top partial hits ({len(best)}):")
    best.sort(reverse=True)
    for p in best[:20]:
        print(f"  {p[0]}/{len(DATA)}  {p[1]} WIN{p[2]} {p[3]}  seed={p[4]}  input={p[5]}")
