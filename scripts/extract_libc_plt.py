#!/usr/bin/env python3
"""
Extract libc PLT call destinations from the corridor dump.

A typical AArch64 PLT stub:
    adrp x16, <got_page>
    ldr  x17, [x16, #<got_off>]
    br   x17
    (nop/pacbti)

The .got.plt slot at <got_page+got_off> contains the resolved address of the
libc function after the dynamic linker has applied relocations. We read the
slot from the corridor dump's rw region(s) to get the libc absolute address,
then compute libc-relative offsets.

Outputs a JSON map: { corridor_offset: { 'got_va': ..., 'libc_offset': ..., 'libc_va': ... } }
plus a Rust-paste-ready const block for live_cert_eval.rs.
"""
import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


def load_corridor(freeze_path: Path):
    """Return (corridor_base, range_table, full_bytes) where range_table is a list of
    (base_va, end_va, file_offset_in_bin, perms) covering the dumped corridor regions."""
    freeze = json.loads(freeze_path.read_text())
    bin_bytes = Path(freeze['bin_path']).read_bytes()
    seen = set(); ranges = []
    cursor = 0
    for r in freeze['ranges']:
        base = int(r['base'], 16); size = int(r['size'])
        perms = r.get('protection', 'r--')
        key = (base, size, perms)
        if key in seen: continue
        seen.add(key)
        ranges.append({'va': base, 'end': base + size, 'file_off': cursor,
                       'perms': perms, 'size': size})
        cursor += size
    return int(freeze['base'], 16), ranges, bin_bytes, freeze


def read_at_va(va, n, ranges, bin_bytes):
    """Read n bytes at virtual address va by finding which corridor range contains it."""
    for r in ranges:
        if r['va'] <= va < r['end']:
            off = r['file_off'] + (va - r['va'])
            return bin_bytes[off:off + n]
    return None


def detect_plt_stubs(corridor_base, ranges, bin_bytes):
    """Scan r-x regions for adrp/ldr-x17/br-x17 PLT patterns. Yield (plt_va, got_va)."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for r in ranges:
        if 'x' not in r['perms']:
            continue
        data = bin_bytes[r['file_off']:r['file_off'] + r['size']]
        # Walk in 16-byte windows (PLT stubs are 16 bytes typically)
        for i in range(0, len(data) - 16, 4):
            window = data[i:i + 16]
            try:
                ins = list(md.disasm(window, r['va'] + i, count=3))
            except Exception:
                continue
            if len(ins) != 3:
                continue
            # adrp x16, ... ; ldr x17, [x16, #imm] ; br x17
            if (ins[0].mnemonic == 'adrp' and ins[0].op_str.startswith('x16, ')
                    and ins[1].mnemonic == 'ldr' and 'x17' in ins[1].op_str and '[x16' in ins[1].op_str
                    and ins[2].mnemonic == 'br' and ins[2].op_str == 'x17'):
                # adrp target page is the second operand of ins[0]
                adrp_target = int(ins[0].op_str.split(', ')[1], 16)
                # ldr offset
                ldr_op = ins[1].op_str
                # parse '#imm' from [x16, #imm]
                if '#' in ldr_op:
                    after = ldr_op.split('#')[1]
                    off = int(after.rstrip(']'), 16) if after.startswith('0x') else int(after.rstrip(']'))
                else:
                    off = 0
                got_va = adrp_target + off
                yield r['va'] + i, got_va


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--corridor-freeze', required=True)
    ap.add_argument('--libc-base', required=True, help='libc.so module base (hex)')
    args = ap.parse_args()

    libc_base = int(args.libc_base, 16)
    corridor_base, ranges, bin_bytes, freeze = load_corridor(Path(args.corridor_freeze))
    print(f'corridor base = 0x{corridor_base:x}, dumped ranges = {len(ranges)}')

    # Find PLT stubs
    plts = list(detect_plt_stubs(corridor_base, ranges, bin_bytes))
    print(f'found {len(plts)} PLT stubs')

    # For each PLT, read its .got.plt slot and check if it points into libc
    libc_targets = {}
    for plt_va, got_va in plts:
        slot = read_at_va(got_va, 8, ranges, bin_bytes)
        if slot is None or len(slot) < 8:
            continue
        target_va = struct.unpack('<Q', slot)[0]
        plt_off = plt_va - corridor_base
        # Only keep targets in libc.so address range (within 8 MB above its base)
        if libc_base <= target_va < libc_base + 0x800000:
            libc_off = target_va - libc_base
            libc_targets[plt_off] = {
                'got_va': got_va,
                'libc_va': target_va,
                'libc_offset': libc_off,
            }

    print(f'\nPLT slots resolving into libc.so: {len(libc_targets)}')
    print('\ncorridor_off    libc_off    libc_va         got_slot_va')
    for plt_off in sorted(libc_targets):
        e = libc_targets[plt_off]
        print(f'  0x{plt_off:6x}      0x{e["libc_offset"]:6x}    0x{e["libc_va"]:x}   0x{e["got_va"]:x}')

    out = Path('/tmp/libc_plt_table.json')
    out.write_text(json.dumps(libc_targets, indent=2))
    print(f'\nwrote {out}')


if __name__ == '__main__':
    main()
