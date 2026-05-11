#!/usr/bin/env python3
"""
Merge corridor + libc + libnmsssa live dumps into one offline page cache.

Inputs (defaults match the 2026-05-11T15:06:50Z capture):
  - nmsscr_live_corridor_<ts>.bin + .freeze_state.json (contains dependency_images
    listing libc + libnmsssa range tables + their dump paths)
  - libc_live_<ts>.bin
  - libnmsssa_live_<ts>.bin

The freeze_state .bin files are CONCATENATIONS of multiple memory ranges in
the order listed under `dependency_images[*].ranges` (for libs) and top-level
`ranges` (for the corridor — deduped).

This script:
  1. Reads each freeze_state.json
  2. Deduplicates ranges
  3. Partitions each .bin by ranges (cumulative file offsets)
  4. Writes per-page cache files at the harness's expected layout
  5. Synthesizes a single maps.txt covering all unique ranges
  6. Writes state.json with pc + minimal registers + tpidr_el0 placeholder

The harness's stable_string_hash uses prime 0x1000001b3 (NOT standard FNV-1a 64).
"""

import argparse
import json
from pathlib import Path

PAGE_SIZE = 4096
FNV_BASIS = 0xCBF29CE484222325
FNV_PRIME = 0x0000_0001_0000_01b3
DEFAULT_SERIAL = 'merged-live-20260511T150650Z'


def fnv1a64(s: str) -> int:
    h = FNV_BASIS
    for b in s.encode('utf-8'):
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def sanitize(s: str) -> str:
    if not s:
        return '_'
    return ''.join(c if (c.isascii() and (c.isalnum() or c in '.-_')) else '_' for c in s) or '_'


def is_stable_region(path: str) -> bool:
    p = path.strip()
    if (not p
            or p.startswith('/memfd:')
            or p.startswith('/dev/ashmem/')
            or p == '[heap]'
            or p.startswith('[stack')
            or p.startswith('[anon')):
        return False
    return True


def namespace_for(region: dict, pid: int, serial: str) -> str:
    path = region['path'].strip()
    if is_stable_region(path):
        return f'stable:{path}'
    return 'volatile:{pid}:{serial}:{base:x}:{end:x}:{off:x}:{perms}:{path}'.format(
        pid=pid, serial=serial, base=region['base'], end=region['end'],
        off=region['offset'], perms=region['perms'], path=path,
    )


def label_for(namespace: str, region: dict) -> str:
    """basename(namespace) || basename(region.path) || namespace"""
    parts = namespace.rstrip('/').split('/')
    if parts and parts[-1]:
        return parts[-1]
    rp = region['path'].rstrip('/').split('/')
    if rp and rp[-1]:
        return rp[-1]
    return namespace


def stage_pages(region: dict, data: bytes, cache_root: Path, serial: str, pid: int, verbose: bool):
    base = region['base']
    end = base + len(data)
    ns = namespace_for(region, pid, serial)
    h = fnv1a64(ns)
    label = label_for(ns, region)
    dir_part = cache_root / sanitize(serial) / f'{h:016x}_{sanitize(label)}'
    dir_part.mkdir(parents=True, exist_ok=True)
    page_addr = base
    written = 0
    while page_addr < end:
        page_len = min(PAGE_SIZE, end - page_addr)
        page_off = region['offset'] + (page_addr - base)
        fname = f'{page_off:016x}_{page_len:04x}.bin'
        chunk = data[page_addr - base: page_addr - base + page_len]
        (dir_part / fname).write_bytes(chunk)
        page_addr += page_len
        written += 1
    if verbose:
        print(f'  staged {written:5d} pages: 0x{base:x}-0x{end:x} '
              f'perms={region["perms"]} ns={ns[:80]!r}')
    return written


def dedupe_ranges(raw_ranges):
    seen = set()
    out = []
    for r in raw_ranges:
        base = int(r['base'], 16)
        size = int(r['size'])
        perms = r.get('protection') or 'r--'
        f = r.get('file') or {}
        path = f.get('path', '') or ''
        offset = int(f.get('offset', 0) or 0)
        key = (base, size, perms, offset, path)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            'base': base,
            'end': base + size,
            'size': size,
            'perms': (perms + 'p') if len(perms) == 3 else perms,
            'offset': offset,
            'path': path,
        })
    return out


def synth_maps_line(r: dict) -> str:
    return '{base:08x}-{end:08x} {perms} {off:08x} 00:00 0                                  {path}\n'.format(
        base=r['base'], end=r['end'], perms=r['perms'], off=r['offset'], path=r['path'],
    )


def partition_bin(bin_path: Path, ranges):
    """Return list of (range, bytes) pairs by slicing bin at cumulative offsets."""
    data = bin_path.read_bytes()
    total = sum(r['size'] for r in ranges)
    if total != len(data):
        print(f'  WARNING: bin size {len(data)} != sum of ranges {total} (expected mismatch if dumper had skips)')
    out = []
    cursor = 0
    for r in ranges:
        sl = data[cursor:cursor + r['size']]
        cursor += r['size']
        out.append((r, sl))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--corridor-freeze',  required=True, help='nmsscr_live_corridor_<ts>.freeze_state.json')
    ap.add_argument('--out', required=True, help='output directory')
    ap.add_argument('--serial', default=DEFAULT_SERIAL)
    ap.add_argument('--challenge', required=True)
    ap.add_argument('--pc', required=True, help='start PC as 0x... hex')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    freeze = json.loads(Path(args.corridor_freeze).read_text())
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    cache_root = out / 'page_cache'; cache_root.mkdir(parents=True, exist_ok=True)

    sources = []

    # --- corridor ---
    corridor_bin = Path(freeze['bin_path'])
    corridor_ranges_raw = freeze.get('ranges', [])
    corridor_ranges = dedupe_ranges(corridor_ranges_raw)
    sources.append(('corridor', corridor_bin, corridor_ranges))

    # --- dependency images: libc, libnmsssa ---
    deps = freeze.get('dependency_images') or {}
    for tag, dep in deps.items():
        bin_path = Path(dep['bin_path'])
        rs = dedupe_ranges(dep.get('ranges', []))
        sources.append((tag, bin_path, rs))

    # Stage everything
    all_regions = []
    for tag, bin_path, ranges in sources:
        print(f'== {tag}: {bin_path.name} ({len(ranges)} unique ranges) ==')
        parts = partition_bin(bin_path, ranges)
        for r, bytes_ in parts:
            stage_pages(r, bytes_, cache_root, args.serial, pid=int(freeze.get('pid', 1)),
                        verbose=args.verbose)
            all_regions.append(r)

    # maps.txt — sorted by base
    all_regions.sort(key=lambda r: r['base'])
    (out / 'maps.txt').write_text(''.join(synth_maps_line(r) for r in all_regions))
    print(f'wrote maps.txt with {len(all_regions)} regions')

    # state.json — minimal registers, tpidr_el0 pointing at libc-region-ish
    # (the harness will read TLS canary; use any readable address)
    # First readable region: pick corridor base as default tpidr_el0
    pc_val = int(args.pc, 16)
    regs = {f'x{i}': '0x0' for i in range(31)}
    regs['sp'] = f'0x{freeze.get("base", "0x0")}'   # placeholder; will likely need real value
    regs['pc'] = args.pc
    regs['nzcv'] = '0'
    state = {
        'pid': int(freeze.get('pid', 1)),
        'challenge': args.challenge,
        'pc': args.pc,
        'registers': regs,
        'system_registers': {'tpidr_el0': f'0x{int(freeze.get("base", "0x0"), 16):x}'},
    }
    (out / 'state.json').write_text(json.dumps(state, indent=2))
    print(f'wrote state.json with pc={args.pc}, tpidr_el0=0x{int(freeze.get("base", "0x0"), 16):x}')

    print('\ndone. Run live_cert_eval with:')
    print(f'  --state-json {out}/state.json')
    print(f'  --maps-file {out}/maps.txt')
    print(f'  --adb-serial {args.serial}')
    print(f'  --offline-cache')
    print(f'  --page-cache-dir {out}/page_cache')
    print(f'  --pc {args.pc}')
    print(f'  --challenge {args.challenge}')


if __name__ == '__main__':
    main()
