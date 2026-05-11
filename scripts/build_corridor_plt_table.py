#!/usr/bin/env python3
"""
Build the mapping  corridor_offset → symbol_name  by:

  1. Scanning the corridor's r-x ranges for AArch64 PLT stubs
     (adrp x16 / ldr x17,[x16,#imm] / add x16,x16,#imm / br x17 — 16-byte stub).
  2. Extracting each stub's got_slot virtual address.
  3. Computing got_slot file-offset within nmsscr.dec.
  4. Cross-referencing got_slot offset against nmsscr.dec's PLT-GOT relocations
     (lief: r.address == got_slot_file_offset) to recover the symbol name.

Output: a JSON map  { corridor_offset_hex: { 'got_va': ..., 'symbol': ... } }
plus a Rust paste-ready const block.
"""
import argparse
import json
import struct
from pathlib import Path

import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


def load_corridor_freeze(p: Path):
    f = json.loads(p.read_text())
    bin_bytes = Path(f['bin_path']).read_bytes()
    seen = set(); ranges = []
    cursor = 0
    for r in f['ranges']:
        base = int(r['base'], 16); size = int(r['size']); perms = r.get('protection', 'r--')
        key = (base, size, perms)
        if key in seen: continue
        seen.add(key)
        ranges.append({'va': base, 'end': base + size, 'file_off': cursor,
                       'perms': perms, 'size': size})
        cursor += size
    return f, ranges, bin_bytes


def detect_plt_stubs(ranges, bin_bytes):
    """Yield (plt_va, got_va) for each 4-instruction PLT stub in r-x ranges."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for r in ranges:
        if 'x' not in r['perms']:
            continue
        data = bin_bytes[r['file_off']:r['file_off'] + r['size']]
        i = 0
        while i < len(data) - 16:
            window = data[i:i + 16]
            try:
                ins = list(md.disasm(window, r['va'] + i, count=4))
            except Exception:
                i += 4; continue
            if (len(ins) == 4
                    and ins[0].mnemonic == 'adrp' and 'x16, ' in ins[0].op_str
                    and ins[1].mnemonic == 'ldr'  and 'x17' in ins[1].op_str and '[x16' in ins[1].op_str
                    and ins[2].mnemonic == 'add'  and 'x16, x16, ' in ins[2].op_str
                    and ins[3].mnemonic == 'br'   and ins[3].op_str == 'x17'):
                adrp_target = int(ins[0].op_str.split(', ')[1].lstrip('#'), 16)
                after = ins[1].op_str.split('#')[1]
                off = int(after.rstrip(']'), 16) if after.startswith('0x') else int(after.rstrip(']'))
                yield r['va'] + i, adrp_target + off
                i += 16
            else:
                i += 4


def build_reloc_index(nmsscr_path: Path):
    """Return {file_offset → symbol_name} from PLT-GOT JUMP_SLOT relocations."""
    nm = lief.parse(str(nmsscr_path))
    out = {}
    for r in nm.pltgot_relocations:
        if r.symbol and r.symbol.name:
            out[r.address] = r.symbol.name
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--corridor-freeze', required=True)
    ap.add_argument('--nmsscr-static', default='/home/sdancer/nmss/output/decrypted/nmsscr.dec')
    ap.add_argument('--out-json', default='/tmp/corridor_plt_symbols.json')
    args = ap.parse_args()

    freeze, ranges, bin_bytes = load_corridor_freeze(Path(args.corridor_freeze))
    corridor_base = int(freeze['base'], 16)
    print(f'corridor base = 0x{corridor_base:x}, dumped ranges = {len(ranges)}')

    reloc_idx = build_reloc_index(Path(args.nmsscr_static))
    print(f'PLT-GOT relocations in static nmsscr.dec: {len(reloc_idx)}')

    plts = list(detect_plt_stubs(ranges, bin_bytes))
    print(f'PLT stubs detected in corridor: {len(plts)}')

    # got_va → file_offset within nmsscr.dec
    # The static and runtime layouts should agree on file_offset (PT_LOAD identical),
    # so got_va - corridor_base == file_offset in nmsscr.dec.
    table = {}
    matched = 0
    for plt_va, got_va in plts:
        file_off = got_va - corridor_base
        sym = reloc_idx.get(file_off)
        if sym is None:
            continue
        plt_off = plt_va - corridor_base
        table[plt_off] = {'got_va': got_va, 'symbol': sym, 'plt_va': plt_va}
        matched += 1
    print(f'PLT stubs with resolved symbol: {matched}/{len(plts)}')

    # Save and print Phase 1 symbol list
    Path(args.out_json).write_text(json.dumps(
        {f'0x{k:x}': v for k, v in sorted(table.items())}, indent=2))
    print(f'wrote {args.out_json}')

    phase1 = ['malloc', 'free', 'memmove', 'memcmp', 'calloc', '__stack_chk_fail',
              'memset', 'memcpy', 'memcpy_chk', 'memmove_chk',
              'strlen', 'strchr', 'strcmp', 'strncmp']
    print('\n--- Phase 1 + already-shimmed symbols' )
    print('corridor_off    got_va         symbol')
    for plt_off in sorted(table):
        e = table[plt_off]
        if e['symbol'] in phase1:
            print(f'  0x{plt_off:6x}      0x{e["got_va"]:x}    {e["symbol"]}')

    # Rust-paste-ready
    print('\n--- Rust const block (paste into live_cert_eval.rs) ---')
    for sym in phase1:
        offs = [plt_off for plt_off, e in table.items() if e['symbol'] == sym]
        if offs:
            for o in offs:
                print(f'const CORRIDOR_PLT_{sym.upper()}_OFFSET: u64 = 0x{o:x};')


if __name__ == '__main__':
    main()
