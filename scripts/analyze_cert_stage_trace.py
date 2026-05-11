#!/usr/bin/env python3
"""
Consumes a trace.json produced by frida/x21_cert_stage_trace_5558.py and
attempts to reproduce the cert from the captured stage-boundary windows.

Strategy:

  1. Find seq with hook='H' when='enter' — its `x0_plus_70_24B` is the
     deterministic MD5 input (per cert-stage5-sha256-input-format).
  2. Compute MD5 of that 24-byte slice.
  3. Try several cert-tail candidates:
       - the 8-byte window at (x0)+0x30 captured at H-enter (xxh-trunc slot)
       - the xxh64 result from stage X exit (post-xxh, big- and little-endian)
       - the same window post stage 6 (if there's a second H-enter, repeat)
  4. Compare each composed cert against any known challenge→cert pairs from
     capture/cert_trace/derive_*.json or buffer_cert_*.json.

Usage:
  scripts/analyze_cert_stage_trace.py /path/to/cert_stage_trace_<ts>/

Exits 0 if any composition matches a known cert; non-zero otherwise.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def load_known_ground_truth():
    """Return list of (label, challenge_hex, cert_hex_upper) from existing artifacts."""
    pairs = []
    for src in sorted(Path('/home/sdancer/aeon-trace/capture/cert_trace').glob('derive_*.json')):
        try:
            j = json.loads(src.read_text())
            ch = j.get('challenge', '').upper()
            ct = j.get('cert', '').upper()
            if ch and ct:
                pairs.append((src.name, ch, ct))
        except Exception:
            pass
    for src in sorted(Path('/home/sdancer/aeon-trace/capture/cert_trace_A').glob('buffer_cert_*.json')):
        try:
            j = json.loads(src.read_text())
            ch = j.get('challenge', '').upper()
            ct = j.get('cert', '').upper()
            if ch and ct:
                pairs.append((src.name, ch, ct))
        except Exception:
            pass
    return pairs


def find_obs(trace, hook, when, occurrence=1):
    matches = [o for o in trace['stage_observations']
               if o.get('hook') == hook and o.get('when') == when]
    if len(matches) >= occurrence:
        return matches[occurrence - 1]
    return None


def hex_to_bytes(s):
    if not s:
        return None
    return bytes.fromhex(s)


def main(argv):
    if len(argv) < 2:
        print(f'usage: {argv[0]} <cert_stage_trace_dir>')
        return 2
    trace_dir = Path(argv[1])
    trace_path = trace_dir / 'trace.json'
    if not trace_path.exists():
        print(f'missing: {trace_path}')
        return 2

    trace = json.loads(trace_path.read_text())
    obs = trace.get('stage_observations') or []
    print(f'loaded {len(obs)} observations from {trace_path}')

    # Manager / auth sanity
    mgr = trace.get('manager_summary') or {}
    print(f"manager: singleton={mgr.get('singleton')} post_auth={mgr.get('post_auth')}")
    print(f"         session_key_hex={mgr.get('session_key_hex')}")
    print(f"         auth_key_hex={mgr.get('auth_key_hex')}")

    h_enter = find_obs(trace, 'H', 'enter', 1)
    h_leave = find_obs(trace, 'H', 'leave', 1)
    h_enter_2 = find_obs(trace, 'H', 'enter', 2)
    h_leave_2 = find_obs(trace, 'H', 'leave', 2)
    x_leave = find_obs(trace, 'X', 'leave', 1)

    if h_enter is None:
        print('ERROR: no H-enter observation in trace — probe may have missed stage 5')
        return 3

    md5_input = hex_to_bytes(h_enter['x0_plus_70_24B'])
    xxh_slot  = hex_to_bytes(h_enter.get('x0_plus_30_8B'))
    print(f'\nH-enter[seq={h_enter["seq"]}] x0=0x{int(h_enter["x0"], 16):x}')
    print(f'  x0+0x70 24B (MD5 input): {md5_input.hex()}')
    print(f'  x0+0x30  8B (xxh slot):  {xxh_slot.hex() if xxh_slot else "<unreadable>"}')

    md5_out = md5(md5_input)
    print(f'  MD5(input) = {md5_out.hex().upper()}')

    # Compose candidates
    candidates = {}
    if xxh_slot:
        candidates['MD5 || xxh_slot_at_x0+0x30'] = md5_out + xxh_slot
    # If we have x_leave's xxh value, try its raw LE/BE forms
    if x_leave:
        x_window = hex_to_bytes(x_leave.get('x0_plus_70_24B'))
        if x_window:
            # First 8 bytes of x_leave's window could carry the xxh result
            candidates['MD5 || X-leave[0x70:0x78]'] = md5_out + x_window[:8]
    if h_leave:
        # The cert may be the 24B post-HASH2 directly
        cert_post_h1 = hex_to_bytes(h_leave.get('x0_plus_70_24B'))
        if cert_post_h1:
            candidates['H-leave[1] x0+0x70 24B'] = cert_post_h1
    if h_leave_2:
        cert_post_h2 = hex_to_bytes(h_leave_2.get('x0_plus_70_24B'))
        if cert_post_h2:
            candidates['H-leave[2] x0+0x70 24B (post stage 6)'] = cert_post_h2

    if not candidates:
        print('no cert candidates derivable from this trace')
        return 4

    # Compare against ground-truth pairs
    gts = load_known_ground_truth()
    print(f'\nloaded {len(gts)} ground-truth challenge→cert pairs')

    print('\n--- cert candidates ---')
    matched = False
    for name, cert in candidates.items():
        ch = cert.hex().upper()
        match_label = next((label + ' (challenge=' + chal + ')'
                            for (label, chal, gt) in gts if gt == ch), None)
        flag = f'  ✓ MATCHES {match_label}' if match_label else ''
        print(f'  {name:60s} -> {ch}{flag}')
        if match_label:
            matched = True

    return 0 if matched else 5


if __name__ == '__main__':
    sys.exit(main(sys.argv))
