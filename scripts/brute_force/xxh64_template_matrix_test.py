#!/usr/bin/env python3
"""Matrix test: 5 candidate templates × 40+ known (challenge, cert) pairs
under the custom-init xxHash64 cert pipeline.

Templates tested:
  - unsub: unsubstituted template from hash_update_16449.bin[:0x1EF]
  - tpl0..tpl3: substituted templates captured in v1716_files/template_scan_hit_*.bin

Pairs tested:
  - 26 wire captures from hash32_flip_corpus.json (device_id=7B0D26CDC87D42EA)
  - 5 TRACED Frida-patched certs (session 1)
  - 5 SESSION2 certs
  - 4 hash_final.json certs
  - 1 codex-tui.log reference cert (test_challenge_12345 → 22091D63…)

Result (as of this commit):
  - Only 1 match: unsub × test_challenge_12345 → codex-tui reference cert.
    This is circular — both sides come from nmss_cert_hash.py.
  - Zero matches across the 40 real captured (challenge, cert) pairs with
    any of the 5 templates.

Interpretation:
  - The captured substituted templates (tpl0..tpl3) have
    PlayerId="6BA4D60738580083" (device 5558), while hash32_flip_corpus's
    26 wire pairs come from a different device (device_id=7B0D26CDC87D42EA,
    account_pid=2FCF9977…).  Template device != corpus device.
  - Even if the cert pipeline is correctly (template+challenge)→hash, we
    cannot verify against these corpora without either:
      (a) paired (substituted_template, challenge, cert) triples captured
          simultaneously from one device, OR
      (b) the on-disk template file loaded via openat (per fact
          template-is-file-backed) from a device whose (challenge, cert)
          pairs we have.
  - tpl0 and tpl1 are byte-identical (duplicate captures); only 3 distinct
    substituted templates exist across the 4 captures.
"""
import json
import sys
from pathlib import Path


REFERENCE_PY_DIR = Path("/home/sdancer/aeon-trace/scripts")
CAPTURE_DIR = Path("/home/sdancer/aeon-ollvm/analysis/hash_attempt_4/cert_trace")
V1716_FILES = Path("/home/sdancer/aeon-trace/capture/v1716_files")
WIRE_CORPUS = Path("/home/sdancer/aeon-trace/capture/hash32_flip_corpus.json")


def _import_reference():
    sys.path.insert(0, str(REFERENCE_PY_DIR))
    import nmss_cert_hash
    return nmss_cert_hash


BUFFER_SIZE = 16449


def build_buf(tpl_bytes: bytes, challenge: str) -> bytes:
    buf = bytearray(BUFFER_SIZE)
    buf[:len(tpl_bytes)] = tpl_bytes
    ch = challenge.encode()
    buf[0x2010:0x2010 + len(ch)] = ch
    buf[0x2230:0x2234] = b"%02x"
    return bytes(buf)


def load_all_templates() -> dict[str, bytes]:
    out = {}
    ref = (CAPTURE_DIR / "hash_update_16449.bin").read_bytes()
    out["unsub"] = ref[:0x1EF]
    for i in range(4):
        p = V1716_FILES / f"template_scan_hit_{i}.bin"
        if p.exists():
            out[f"tpl{i}"] = p.read_bytes()
    return out


def load_all_pairs() -> list[tuple[str, str, str]]:
    pairs = []
    if WIRE_CORPUS.exists():
        for line in WIRE_CORPUS.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            pairs.append((d["challenge"], d["cert"], "wire"))
    for ch, cert in [
        ("AABBCCDDEEFF0011", "4A29DDFD50AE53A1BE1BB551C2974A7B80099FD572C22394"),
        ("0000000000000000", "ED386B8A70406B6916ABEBBCCBA854DAD43C4AF8F9AED78C"),
        ("1111111111111111", "3192F8B7BBD9FF43A4ED8A68151A82BEFDD660319E4DAF8E"),
        ("6BA4D60738580083", "AF823D54A3FAA352C0C307CE9D3D34F572012D23A38A01AC"),
        ("DEADBEEF12345678", "5C1FA61FAA3314F77713C6216EA63DFD0C02E2766E75EE61"),
    ]:
        pairs.append((ch, cert, "TRACED"))
    for ch, cert in [
        ("AABBCCDDEEFF0011", "4ED774B54D8F79C051B87BAF48A70CE2E5EC8016DBF4086A"),
        ("0000000000000000", "F71EC1013641153426575B052E82CB3883BE11DE78BB4041"),
        ("1111111111111111", "C161226B3E63C69023870F12E52451C9BB123D386F509BCF"),
        ("FFFFFFFFFFFFFFFF", "EDB336D4D8A6F3EEF715B342D032CF199E0CB6B4E734AF31"),
        ("DEADBEEF00000001", "D2E52055BA13CAF359CBA481FDEC3032C48F3E488C04B7D5"),
    ]:
        pairs.append((ch, cert, "SESSION2"))
    pairs.append(("test_challenge_12345",
                  "22091D63655A6D98683CC13C3D811B295AAD9FC924A72674",
                  "codex-tui"))
    return pairs


def main() -> int:
    mod = _import_reference()
    templates = load_all_templates()
    pairs = load_all_pairs()
    print(f"Templates: {len(templates)}  Pairs: {len(pairs)}")
    print(f"Total combinations: {len(templates) * len(pairs)}")

    hits = []
    for tpl_name, tpl in templates.items():
        for ch, expected, corpus in pairs:
            buf = build_buf(tpl, ch)
            v1, v2, v3, v4, rem, total = mod.hash_update(
                buf, mod.INIT_V1, mod.INIT_V2, mod.INIT_V3, mod.INIT_V4)
            fold = mod.hash_finalize(v1, v2, v3, v4, rem, total)
            got = fold[:24].hex().upper()
            if got == expected:
                hits.append((tpl_name, ch, corpus))
                print(f"  ✓ {tpl_name} × {ch} ({corpus}) → {got}")

    print(f"\nMatches: {len(hits)}")
    real_pairs = [h for h in hits if h[2] != "codex-tui"]
    if real_pairs:
        print(f"  Real-corpus hits (excluding self-reference): {len(real_pairs)}")
        for h in real_pairs:
            print(f"    {h}")
    else:
        print("  No real-corpus hits.  The captured templates don't "
              "correspond to any (challenge, cert) pair in our corpora.")
    return 0 if real_pairs else 1


if __name__ == "__main__":
    sys.exit(main())
