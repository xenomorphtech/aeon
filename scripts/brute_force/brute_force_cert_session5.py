#!/usr/bin/env python3
"""Brute-force keyed hashes vs 6 (challenge, cert) pairs from session 5.

Per fact hmac-sha256-hypothesis: cert pipeline is suspected White-Box
HMAC-SHA256 with device key.  Now that we have new session material
(token, nmnid, account_pid, nid), expand the key search.

Hypothesis A: cert = HMAC-SHA256(key, challenge)[0:24]
Hypothesis B: cert = SHA-256(key + challenge)[0:24]   (ditto variants)
Hypothesis C: cert_prefix = challenge_hash32 (u32 LE) or fold
"""
import hashlib
import hmac
import json
import struct
from itertools import product


DATA = [json.loads(l) for l in open(
    "/home/sdancer/aeon-trace/capture/hash32_flip_corpus.json") if l.strip()]
print(f"{len(DATA)} pairs loaded")

S = DATA[0]["session"]
device_id_bytes = bytes.fromhex(S["device_id"])
device_id_ascii_lo = S["device_id"].lower().encode()
device_id_ascii_up = S["device_id"].upper().encode()
token_bytes = bytes.fromhex(S["token"])
token_ascii = S["token"].encode()
account_pid_bytes = bytes.fromhex(S["account_pid"])
account_pid_ascii = S["account_pid"].encode()
nmnid_bytes = bytes.fromhex(S["nmnid"])
nmnid_ascii = S["nmnid"].encode()
nid_ascii = S["nid"].encode()
nid_after_N = S["nid"][1:].encode()

# Build key candidates — full or fragments, byte and ASCII forms
key_pool = []
def add(name, b):
    key_pool.append((name, b))
    key_pool.append((f"{name}_rev", b[::-1]))

add("device_id_bytes", device_id_bytes)
add("device_id_lo_ascii", device_id_ascii_lo)
add("device_id_up_ascii", device_id_ascii_up)
add("token_bytes", token_bytes)
add("token_ascii", token_ascii)
add("account_pid_bytes", account_pid_bytes)
add("account_pid_ascii", account_pid_ascii)
add("nmnid_bytes", nmnid_bytes)
add("nmnid_ascii", nmnid_ascii)
add("nid_ascii", nid_ascii)
add("nid_after_N", nid_after_N)

# Pair combos
for (n1, b1), (n2, b2) in product(
    [("device_id_bytes", device_id_bytes), ("token_bytes", token_bytes),
     ("nmnid_bytes", nmnid_bytes), ("account_pid_bytes", account_pid_bytes)],
    [("device_id_bytes", device_id_bytes), ("token_bytes", token_bytes),
     ("nmnid_bytes", nmnid_bytes), ("account_pid_bytes", account_pid_bytes)]
):
    if n1 == n2:
        continue
    add(f"{n1}+{n2}", b1 + b2)

# Some prefixes of nmnid (32 byte; try :16, :24)
add("nmnid_bytes[:16]", nmnid_bytes[:16])
add("nmnid_bytes[:24]", nmnid_bytes[:24])
add("nmnid_bytes[:8]",  nmnid_bytes[:8])

print(f"Key candidates: {len(key_pool)}")

# Message forms per challenge
def msg_forms(challenge: str):
    ch_ascii = challenge.encode()
    ch_lo = challenge.lower().encode()
    try:
        ch_bytes = bytes.fromhex(challenge)
    except ValueError:
        ch_bytes = ch_ascii  # fallback for non-hex dummy
    forms = [
        ("ascii_up", ch_ascii),
        ("ascii_lo", ch_lo),
        ("hex_bytes", ch_bytes),
        ("hex_rev", ch_bytes[::-1]),
        ("ascii+nl", ch_ascii + b"\n"),
        ("ascii+devid", ch_ascii + device_id_bytes),
        ("devid+ascii", device_id_bytes + ch_ascii),
        ("hex+devid", ch_bytes + device_id_bytes),
        ("devid+hex", device_id_bytes + ch_bytes),
        ("hex+nmnid", ch_bytes + nmnid_bytes),
        ("nmnid+hex", nmnid_bytes + ch_bytes),
        ("hex+token", ch_bytes + token_bytes),
        ("token+hex", token_bytes + ch_bytes),
        ("ascii+token+devid", ch_ascii + token_bytes + device_id_bytes),
    ]
    return forms

# Expected cert per challenge as 24 bytes
expected = {d["challenge"]: bytes.fromhex(d["cert"]) for d in DATA}

exact_hits = []
best_prefix_matches = []
best_slice_matches = []

def test_digest(digest: bytes, challenge: str, tag: str):
    exp = expected[challenge]
    if len(digest) < 24:
        return False
    # Exact match on first 24 bytes?
    if digest[:24] == exp:
        exact_hits.append((tag, challenge, "first24"))
        return True
    # Exact match on any 24-byte window?
    for off in range(0, len(digest) - 23):
        if digest[off:off+24] == exp:
            exact_hits.append((tag, challenge, f"window@{off}"))
            return True
    # Prefix near-miss: how many bytes match from offset 0?
    n = 0
    while n < min(24, len(digest)) and digest[n] == exp[n]:
        n += 1
    if n >= 4:
        best_prefix_matches.append((n, tag, challenge))
    return False

print("\n=== Scanning HMAC-SHA256 / SHA-256 / SHA-512 ===")
total_scans = 0
for key_name, key in key_pool:
    for msg_name, _ in msg_forms("dummy"):
        pass
    # Per-challenge evaluation
    for msg_name in [m[0] for m in msg_forms("dummy")]:
        all_match = True
        for d in DATA:
            ch = d["challenge"]
            msg = dict(msg_forms(ch))[msg_name]
            for alg_name, alg in [("hmac256", lambda k, m: hmac.new(k, m, hashlib.sha256).digest()),
                                  ("hmac512", lambda k, m: hmac.new(k, m, hashlib.sha512).digest()),
                                  ("sha256", lambda k, m: hashlib.sha256(k + m).digest()),
                                  ("sha256_kmk", lambda k, m: hashlib.sha256(k + m + k).digest()),
                                  ("sha512", lambda k, m: hashlib.sha512(k + m).digest())]:
                total_scans += 1
                digest = alg(key, msg)
                if test_digest(digest, ch, f"{alg_name}(key={key_name}, msg={msg_name})"):
                    pass

print(f"\nScans: {total_scans}")
print(f"Exact 24-byte matches: {len(exact_hits)}")
for h in exact_hits[:20]:
    print(f"  {h}")

best_prefix_matches.sort(reverse=True)
print(f"\nTop prefix-byte matches (>= 4 bytes):")
for n, tag, ch in best_prefix_matches[:15]:
    print(f"  {n}B match for {ch}: {tag}")

# Summary per-challenge: how many configurations hit all 6 pairs
print("\nConfigurations producing >=2 exact matches across different challenges:")
from collections import Counter
cfg_hits = Counter()
for tag, ch, _ in exact_hits:
    # extract config (tag before 'challenge' field)
    cfg_hits[tag] += 1
for cfg, n in cfg_hits.most_common(10):
    if n >= 2:
        print(f"  {n}x {cfg}")
