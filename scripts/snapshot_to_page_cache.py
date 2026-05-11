#!/usr/bin/env python3
"""
Convert a process-memory snapshot into the on-disk layout that
`live_cert_eval --offline-cache` consumes.

Outputs:

  <out>/maps.txt                       proc-maps formatted region list
  <out>/state.json                     pc + registers (for --state-json)
  <out>/page_cache/<serial>/<hash>_<label>/<offset>_<plen>.bin

Inputs (two modes):

  manifest mode:
    --manifest      JSON in process_snapshot_20260405 or trampoline_proc_memdump_5558 schema
    --memdump-dir   directory holding the per-region <base_hex>.bin blobs
    --maps          optional existing maps.txt; otherwise synthesized from manifest
    --challenge     hex challenge to record in state.json

  single-region mode (for the corridor .bin case):
    --single-bin    path to a single contiguous region blob (e.g. jit_live_corridor_9d164000.bin)
    --base          guest virtual base address of that blob (hex)
    --perms         maps-format permissions string, default "r-xp"
    --path          maps "pathname" column, default "/jit-corridor"
    --pc            faulting PC to seed state.json (hex)
    --challenge     hex challenge

The cache layout exactly matches `remote_page_cache_path` in
`crates/aeon-instrument/src/bin/live_cert_eval.rs`:

  path = root/<sanitize(serial)>
              /<stable_hash16(namespace)>_<sanitize(label)>
              /<file_offset:016x>_<page_len:04x>.bin

  - "stable" regions (real file-backed paths) use namespace=`stable:<path>`
  - everything else (anon / memfd / ashmem / heap / stack) uses
    namespace=`volatile:<pid>:<serial>:<base>:<end>:<offset>:<perms>:<path>`
"""

import argparse
import json
import os
from pathlib import Path

PAGE_SIZE = 4096

# FNV-1a 64 with the same constants the harness uses (stable_string_hash)
# Match the harness's `stable_string_hash` (live_cert_eval.rs L1014).
# The Rust literal 0x0000_0001_0000_01b3 is NOT the standard FNV-1a 64 prime
# (0x100000001b3); it is 0x1000001b3. The basis is the standard FNV one.
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME  = 0x0000_0001_0000_01b3  # = 0x1000001b3, harness-specific

def fnv1a64(s: str) -> int:
    h = FNV_OFFSET
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def sanitize(s: str) -> str:
    if not s:
        return "_"
    out = []
    for ch in s:
        if ch.isascii() and (ch.isalnum() or ch in ".-_"):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out) or "_"

def is_stable_region(path: str) -> bool:
    p = path.strip()
    if not p:
        return False
    if p.startswith("/memfd:"):
        return False
    if p.startswith("/dev/ashmem/"):
        return False
    if p == "[heap]":
        return False
    if p.startswith("[stack"):
        return False
    if p.startswith("[anon"):
        return False
    return True

def namespace_for(region: dict, pid: int, serial: str) -> str:
    path = region["path"].strip()
    if is_stable_region(path):
        return f"stable:{path}"
    return "volatile:{pid}:{serial}:{base:x}:{end:x}:{off:x}:{perms}:{path}".format(
        pid=pid, serial=serial, base=region["base"], end=region["end"],
        off=region["offset"], perms=region["perms"], path=path,
    )

def label_for(namespace: str, region: dict) -> str:
    """Mirror cache_namespace_label: basename of namespace, falling back to basename of region path."""
    parts = namespace.rstrip("/").split("/")
    if parts and parts[-1]:
        return parts[-1]
    rparts = region["path"].rstrip("/").split("/")
    if rparts and rparts[-1]:
        return rparts[-1]
    return namespace

def parse_hex(v):
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s, 16)

def load_manifest(path: Path):
    """Return (pid, registers, regions[]) from either manifest schema."""
    obj = json.loads(path.read_text())
    pid = int(obj.get("pid", 0))
    regs = obj.get("registers", {}) or {}
    regions = []
    for r in obj.get("regions", []) or []:
        if r.get("dumped") is False:
            continue
        if not r.get("dump_file"):
            continue
        regions.append({
            "base":      parse_hex(r["base"]),
            "end":       parse_hex(r["end"]),
            "perms":     r["perms"],
            "offset":    parse_hex(r.get("offset", "0x0")),
            "path":      r.get("file_path", "") or "",
            "dump_file": r["dump_file"],
            "dump_size": int(r.get("dump_size", 0) or 0),
            "dev":       r.get("dev", "00:00"),
            "inode":     r.get("inode", "0"),
        })
    pc = obj.get("faulting_pc") or regs.get("pc")
    return pid, pc, regs, regions

def write_state_json(out_path: Path, pid: int, pc, registers: dict, challenge: str,
                     tpidr_el0: int = None):
    state = {
        "pid": pid,
        "challenge": challenge,
        "pc": pc if isinstance(pc, str) else f"0x{pc:x}",
        "registers": dict(registers),
    }
    if tpidr_el0:
        state["system_registers"] = {"tpidr_el0": f"0x{tpidr_el0:x}"}
    out_path.write_text(json.dumps(state, indent=2))

def synth_maps_line(r: dict) -> str:
    perms = r["perms"]
    if len(perms) == 3:  # legacy "r-x" without sharing flag
        perms = perms + "p"
    return "{base:08x}-{end:08x} {perms} {off:08x} {dev} {inode}{pad}{path}\n".format(
        base=r["base"], end=r["end"], perms=perms,
        off=r["offset"], dev=r.get("dev", "00:00"),
        inode=r.get("inode", "0"),
        pad="                                  " if r["path"] else "\n",
        path=r["path"],
    ).rstrip("\n") + "\n"

def write_maps(out_path: Path, regions):
    with out_path.open("w") as f:
        for r in regions:
            f.write(synth_maps_line(r))

def stage_pages(region: dict, data: bytes, cache_root: Path, serial: str, pid: int,
                verbose: bool):
    """Write per-page cache files for a region's content."""
    base = region["base"]
    end  = base + len(data)
    namespace = namespace_for(region, pid, serial)
    label = label_for(namespace, region)
    h = fnv1a64(namespace)
    dir_part = cache_root / sanitize(serial) / f"{h:016x}_{sanitize(label)}"
    dir_part.mkdir(parents=True, exist_ok=True)
    pages = 0
    page_addr = base
    while page_addr < end:
        page_len = min(PAGE_SIZE, end - page_addr)
        page_offset = region["offset"] + (page_addr - base)
        fname = f"{page_offset:016x}_{page_len:04x}.bin"
        chunk = data[page_addr - base : page_addr - base + page_len]
        (dir_part / fname).write_bytes(chunk)
        page_addr += page_len
        pages += 1
    if verbose:
        print(f"  wrote {pages:>5} pages for {region['path'] or '<anon>'} @ 0x{base:x} "
              f"(ns={namespace[:64]!r})")
    return pages

def convert_manifest(args):
    pid, pc, regs, regions = load_manifest(Path(args.manifest))
    memdump = Path(args.memdump_dir)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    cache_root = out / "page_cache"
    cache_root.mkdir(parents=True, exist_ok=True)

    if args.maps:
        # copy provided maps
        (out / "maps.txt").write_bytes(Path(args.maps).read_bytes())
    else:
        write_maps(out / "maps.txt", regions)

    total_pages = 0
    written_regions = 0
    missing = []
    for r in regions:
        if not r["perms"].startswith("r"):
            continue
        bin_path = memdump / r["dump_file"]
        if not bin_path.exists():
            missing.append(r["dump_file"])
            continue
        data = bin_path.read_bytes()
        # The dump may be shorter than region size (truncated capture)
        if len(data) > r["end"] - r["base"]:
            data = data[: r["end"] - r["base"]]
        total_pages += stage_pages(r, data, cache_root, args.serial, pid, args.verbose)
        written_regions += 1

    pc_val = args.pc or pc or regs.get("pc")
    write_state_json(out / "state.json", pid=pid, pc=pc_val, registers=regs,
                     challenge=args.challenge)
    print(f"converted: regions_written={written_regions}/{len(regions)} pages={total_pages}")
    if missing:
        print(f"missing dump files: {len(missing)} (first 5: {missing[:5]})")
    return 0 if written_regions > 0 else 2

def convert_single_bin(args):
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    cache_root = out / "page_cache"
    cache_root.mkdir(parents=True, exist_ok=True)
    base = parse_hex(args.base)
    data = Path(args.single_bin).read_bytes()
    end  = base + len(data)
    region = {
        "base": base, "end": end, "perms": args.perms, "offset": 0,
        "path": args.path, "dev": "00:00", "inode": "0",
    }
    write_maps(out / "maps.txt", [region])
    pages = stage_pages(region, data, cache_root, args.serial, args.pid, args.verbose)

    regs = {}
    pc_val = args.pc
    # minimal sane defaults; harness reads x0..x30 + sp from state.json
    for i in range(31):
        regs[f"x{i}"] = "0x0"
    regs["sp"] = "0x70000000"   # arbitrary readable-stack-ish; will fault on use
    regs["pc"] = pc_val if isinstance(pc_val, str) else f"0x{pc_val:x}"
    regs["nzcv"] = "0"
    write_state_json(out / "state.json", pid=args.pid, pc=pc_val, registers=regs,
                     challenge=args.challenge)
    print(f"single-region snapshot: base=0x{base:x} size={len(data)} pages={pages}")
    return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--serial", default="synthetic", help="cache namespace serial")
    ap.add_argument("--challenge", default="AABBCCDD11223344")
    ap.add_argument("--pc", help="hex PC override")
    ap.add_argument("--verbose", action="store_true")

    sub = ap.add_subparsers(dest="mode", required=True)

    m = sub.add_parser("manifest", help="convert from manifest+memdump dir")
    m.add_argument("--manifest", required=True)
    m.add_argument("--memdump-dir", required=True)
    m.add_argument("--maps", help="optional existing maps.txt")
    m.set_defaults(func=convert_manifest)

    s = sub.add_parser("single-bin", help="wrap one region blob as a single-region snapshot")
    s.add_argument("--single-bin", required=True)
    s.add_argument("--base", required=True)
    s.add_argument("--perms", default="r-xp")
    s.add_argument("--path", default="/jit-corridor")
    s.add_argument("--pid", type=int, default=1)
    s.set_defaults(func=convert_single_bin)

    args = ap.parse_args()
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
