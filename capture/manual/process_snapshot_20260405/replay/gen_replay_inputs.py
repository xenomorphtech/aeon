#!/usr/bin/env python3

import json
from pathlib import Path

SNAPSHOT_DIR = Path(__file__).resolve().parent.parent
MANIFEST_PATH = SNAPSHOT_DIR / "before_manifest.json"
OUT_DIR = Path(__file__).resolve().parent / "generated"
REGIONS_TSV = OUT_DIR / "replay_regions.tsv"
REGS_H = OUT_DIR / "replay_regs.h"
PUSH_LIST = OUT_DIR / "replay_files.txt"

FILE_ENTRIES = [
    {"base": 0x75ACCB6000},
    {"base": 0x762082C000},
    {"base": 0x7636BF8000},
    {"base": 0x76ACE00000},
    {"base": 0x76BF800000},
    {"base": 0x76BFA00000},
    {"base": 0x76BFA84000},
    {"base": 0x76BFA85000},
    {"base": 0x76BFCC4000},
    {"base": 0x76BFCC6000},
    {"base": 0x76BFE34000},
    {"base": 0x76BFE36000},
    {"base": 0x76C0000000},
    {"base": 0x76C0212000},
    {"base": 0x76C0216000},
    {"base": 0x76E1949000},
    {"base": 0x76E1989000},
    {"base": 0x76F194B000},
    {"base": 0x76F19CB000},
    {"base": 0x77F1956000},
    {"base": 0x77F1996000},
    {"base": 0x783194C000},
    {"base": 0x783198C000},
    {"base": 0x7954B1E000},
    {"base": 0x7954B67000},
    {"base": 0x7954BC1000},
    {"base": 0x7954BC8000},
    {"base": 0x7954BC9000},
    {"base": 0x795E33C000},
    {"base": 0x795E378000},
    {"base": 0x795E385000},
    {"base": 0x795E386000},
    {"base": 0x795E387000},
    {"base": 0x795E388000},
    {"base": 0x795E38B000},
    {"base": 0x795E38C000},
    {"base": 0x795E38D000},
    {"base": 0x795E38E000},
    {"base": 0x795E3E2000},
    {"base": 0x795E3E3000},
    {"base": 0x795E3E5000},
    {"base": 0x795E3E6000},
    {"base": 0x795E3E8000},
    {"base": 0x795E3E9000},
    {"base": 0x795E3F6000},
    {"base": 0x795E3F7000},
    {"base": 0x795E3F9000},
    {"base": 0x795E3FD000},
    {"base": 0x795E3FF000},
    {"base": 0x795E404000},
    {"base": 0x795E405000},
    {"base": 0x796F25E000},
    {"base": 0x796F260000},
    {"base": 0x796F261000},
    {"base": 0x796F262000},
    {"base": 0x796F1D8000},
    {"base": 0x796F1DC000},
    {"base": 0x796F1E0000},
    {"base": 0x796F1E1000},
    {"base": 0x9B5FE000},
    {"base": 0x9B610000, "size": 0x1000, "dump_file": "9b610000.bin"},
    {"base": 0x9B611000, "size": 0x1000, "dump_file": "9b611000.bin", "perms": "r-x"},
    {"base": 0x9B612000, "size": 0xC000, "dump_file": "9b612000.bin"},
    {"base": 0x9B61E000},
]

LIVE_REGIONS = [
    {
        "base": 0x12C00000,
        "size": 0x18000000,
        "perms": "rw-",
    },
]

PERM_OVERRIDES = {
    0x9B5FE000: "r-x",
    0x9B610000: "r-x",
    0x9B611000: "r-x",
    0x9B612000: "r-x",
    0x9B61E000: "r-x",
}

SEED_PAGES = [
    0x13402000,
    0x13264000,
]


def hex_u64(value: int) -> str:
    return f"0x{value:016x}"


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


def normalize_perms(perms: str) -> str:
    out = ["-", "-", "-"]
    if "r" in perms:
        out[0] = "r"
    if "w" in perms:
        out[1] = "w"
    if "x" in perms:
        out[2] = "x"
    return "".join(out)


def build_region_lookup(manifest: dict) -> dict[int, dict]:
    return {int(region["base"], 16): region for region in manifest["regions"]}


def emit_regions(manifest: dict) -> list[str]:
    lookup = build_region_lookup(manifest)
    lines = [
        "# kind base size perms eager path",
    ]
    push_paths: list[str] = []

    for entry in FILE_ENTRIES:
        base = entry["base"]
        region = lookup.get(base)
        if region is None and "dump_file" not in entry:
            raise SystemExit(f"missing region 0x{base:x} in manifest")
        if region is not None and (not region.get("dumped") or not region.get("dump_file")) and "dump_file" not in entry:
            raise SystemExit(f"region 0x{base:x} has no dump file")
        perms = entry.get("perms")
        if perms is None:
            perms = PERM_OVERRIDES.get(base)
        if perms is None and region is not None:
            perms = normalize_perms(region["perms"])
        if perms is None:
            raise SystemExit(f"missing perms for 0x{base:x}")
        size = entry.get("size", region["size"] if region is not None else None)
        if size is None:
            raise SystemExit(f"missing size for 0x{base:x}")
        dump_file = entry.get("dump_file", region["dump_file"] if region is not None else None)
        if dump_file is None:
            raise SystemExit(f"missing dump file for 0x{base:x}")
        path = f"memdump/{dump_file}"
        lines.append(
            f"file {hex_u64(base)} {hex_u64(int(size))} {perms} 1 {path}"
        )
        push_paths.append(path)

    for region in LIVE_REGIONS:
        lines.append(
            f"live {hex_u64(region['base'])} {hex_u64(region['size'])} {region['perms']} 0 -"
        )

    REGIONS_TSV.write_text("\n".join(lines) + "\n")
    PUSH_LIST.write_text("\n".join(push_paths) + "\n")
    return push_paths


def emit_regs(manifest: dict) -> None:
    regs = manifest["registers"]
    lines = [
        "static const struct ReplayRegs kReplayRegs = {",
        "    .x = {",
    ]
    for idx in range(31):
        value = int(regs[f"x{idx}"], 16)
        lines.append(f"        {hex_u64(value)}ULL,")
    lines.append("    },")
    lines.append(f"    .sp = {hex_u64(int(regs['sp'], 16))}ULL,")
    lines.append(f"    .pc = {hex_u64(int(regs['pc'], 16))}ULL,")
    lines.append("};")
    lines.append("")
    lines.append("static const struct LiveSeed kSeedLivePages[] = {")
    for page in SEED_PAGES:
        lines.append(f"    {{ .page_base = {hex_u64(page)}ULL }},")
    lines.append("};")
    lines.append(
        "static const size_t kSeedLivePageCount = sizeof(kSeedLivePages) / sizeof(kSeedLivePages[0]);"
    )
    lines.append("")
    REGS_H.write_text("\n".join(lines))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest()
    emit_regions(manifest)
    emit_regs(manifest)
    print(f"wrote {REGIONS_TSV}")
    print(f"wrote {REGS_H}")
    print(f"wrote {PUSH_LIST}")


if __name__ == "__main__":
    main()
