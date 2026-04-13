#!/usr/bin/env python3
"""
Offline NMSS cert-stage reproducer from the recovered detection-window -> SHA-256
round chain.

This models the current best cert-stage reconstruction:

1. Obtain the 8-byte windows used by the late cert rounds.
   Those can come from:
   - a captured 1040/1041-byte cert-stage buffer,
   - a WELL512-generated candidate buffer, or
   - the traced round log in /tmp/nmss_round_windows.txt.
2. Run the traced SHA-256 round chain.
3. Emit digest[4:28].hex().upper() as the 48-char cert.

Important nuance:
- The late windows are consumed through the detection-buffer indirection behind
  sp+0x1D0 in the live JIT path.
- When a captured cert-stage buffer is available, the required late windows
  are still observable at the fixed offsets used below.
- The early bootstrap rounds (D01-D09) are still represented by traced digests,
  not a fully reduced upstream builder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CAPTURE_SUMMARY = Path("/tmp/nmss_capture_summary.json")
DEFAULT_STAGE_BUFFER = Path("/tmp/nmss_phase_data/cert_time_merkle_14_buffer.bin")
DEFAULT_ROUND_WINDOWS = Path("/tmp/nmss_round_windows.txt")

HEX_ALPHABET = "0123456789ABCDEF"
TRANSLIT_HEX_TO_DIGITS = str.maketrans(
    {
        "A": "1",
        "B": "2",
        "C": "3",
        "D": "4",
        "E": "5",
        "F": "6",
        "a": "1",
        "b": "2",
        "c": "3",
        "d": "4",
        "e": "5",
        "f": "6",
    }
)

WINDOW_OFFSETS = {
    "d05": 0x0F,
    "d11": 0x32F,
    "d12": 0x394,
    "d13": 0x3F3,
}
WINDOW_SIZE = 8
BOARD_WINDOW = b"rk3588_s"

# Traced bootstrap digests from /tmp/nmss_round_windows.txt.
D04_DIGEST = bytes.fromhex(
    "CC937E2C28215FFA6B8225140B57DB0BA90E5C179BF0CAD559F91FFFB7C29C38"
)
D09_DIGEST = bytes.fromhex(
    "0929980627E33BBAED09DA0248A00147FBD10ACB0980798ACA74BC7FD8E0D33A"
)


@dataclass(frozen=True)
class Well512Snapshot:
    state_words: tuple[int, ...]
    index: int
    source: str


@dataclass(frozen=True)
class MerkleStageResult:
    transliterated_buffer: bytes
    d05_window: bytes
    d11_window: bytes
    d12_window: bytes
    d13_window: bytes
    phase2a_digest: bytes
    final_digest: bytes
    cert_hex: str


@dataclass(frozen=True)
class TracedRoundChain:
    windows: dict[str, bytes]
    digests: dict[str, bytes]
    source: str


def _u64(value: int) -> int:
    return value & 0xFFFFFFFFFFFFFFFF


def well512_step(state_words: list[int], index: int) -> tuple[int, int]:
    z0 = state_words[index]
    z1 = state_words[(index + 13) & 0xF]
    z2 = state_words[(index + 9) & 0xF]

    v0 = _u64(z1 ^ z0)
    v0 = _u64(v0 ^ _u64(z0 << 16))
    z2 = _u64(z2 ^ (z2 >> 11))
    v0 = _u64(v0 ^ _u64(z1 << 15))
    v1 = _u64(v0 ^ z2)
    state_words[index] = v1

    index = (index + 15) & 0xF
    old = state_words[index]
    result = _u64(old ^ z2)
    result = _u64(result ^ _u64(v0 << 18))
    result = _u64(result ^ _u64(z2 << 28))
    result = _u64(result ^ _u64(old << 2))
    result = _u64(result ^ (_u64(v1 << 5) & 0xDA442D20))
    state_words[index] = result
    return result, index


def parse_well512_state_hex(state_hex: str, index: int, source: str) -> Well512Snapshot:
    raw = bytes.fromhex(state_hex)
    if len(raw) != 16 * 8:
        raise ValueError(f"WELL512 state must be 128 bytes, got {len(raw)}")
    words = tuple(int.from_bytes(raw[i * 8 : (i + 1) * 8], "little") for i in range(16))
    return Well512Snapshot(state_words=words, index=index & 0xF, source=source)


def load_well512_snapshot_from_summary(
    summary_path: Path,
    session_name: str,
) -> Well512Snapshot:
    summary = json.loads(summary_path.read_text())
    well = summary["well512"]
    return parse_well512_state_hex(
        well[f"{session_name}_state"],
        int(well[f"{session_name}_index"]),
        source=f"{summary_path}:{session_name}",
    )


def generate_well512_hex_buffer(snapshot: Well512Snapshot, length: int = 1040) -> str:
    state_words = list(snapshot.state_words)
    index = snapshot.index
    out: list[str] = []
    for _ in range(length):
        value, index = well512_step(state_words, index)
        out.append(HEX_ALPHABET[value & 0xF])
    return "".join(out)


def advance_well512_snapshot(snapshot: Well512Snapshot, steps: int) -> Well512Snapshot:
    state_words = list(snapshot.state_words)
    index = snapshot.index
    for _ in range(steps):
        _, index = well512_step(state_words, index)
    return Well512Snapshot(
        state_words=tuple(state_words),
        index=index,
        source=f"{snapshot.source}+{steps}",
    )


def transliterate_hex_buffer(hex_buffer: str) -> bytes:
    return hex_buffer.translate(TRANSLIT_HEX_TO_DIGITS).encode("ascii")


def read_stage_buffer(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) == 1041 and data[-1] == 0:
        return data[:-1]
    if len(data) == 1040:
        return data
    raise ValueError(f"expected 1040 or 1041 bytes, got {len(data)} from {path}")


def sha256_once(window8: bytes, previous_digest32: bytes) -> bytes:
    if len(window8) != 8:
        raise ValueError(f"window must be 8 bytes, got {len(window8)}")
    if len(previous_digest32) != 32:
        raise ValueError(f"previous digest must be 32 bytes, got {len(previous_digest32)}")
    return hashlib.sha256(window8 + previous_digest32).digest()


def cert_hex_from_digest(digest: bytes) -> str:
    return digest[4:28].hex().upper()


def compute_merkle_cert_stage(
    transliterated_buffer: bytes,
    board_window: bytes = BOARD_WINDOW,
) -> MerkleStageResult:
    if len(transliterated_buffer) != 1040:
        raise ValueError(f"transliterated buffer must be 1040 bytes, got {len(transliterated_buffer)}")
    if len(board_window) != 8:
        raise ValueError(f"board window must be exactly 8 bytes, got {len(board_window)}")

    d05_window = transliterated_buffer[WINDOW_OFFSETS["d05"] : WINDOW_OFFSETS["d05"] + WINDOW_SIZE]
    d11_window = transliterated_buffer[WINDOW_OFFSETS["d11"] : WINDOW_OFFSETS["d11"] + WINDOW_SIZE]
    d12_window = transliterated_buffer[WINDOW_OFFSETS["d12"] : WINDOW_OFFSETS["d12"] + WINDOW_SIZE]
    d13_window = transliterated_buffer[WINDOW_OFFSETS["d13"] : WINDOW_OFFSETS["d13"] + WINDOW_SIZE]

    phase2a = D04_DIGEST
    for _ in range(4):
        phase2a = sha256_once(d05_window, phase2a)

    digest = D09_DIGEST
    for window in (board_window, d11_window, d12_window, d13_window):
        digest = sha256_once(window, digest)

    return MerkleStageResult(
        transliterated_buffer=transliterated_buffer,
        d05_window=d05_window,
        d11_window=d11_window,
        d12_window=d12_window,
        d13_window=d13_window,
        phase2a_digest=phase2a,
        final_digest=digest,
        cert_hex=cert_hex_from_digest(digest),
    )


def extract_fixed_windows(transliterated_buffer: bytes) -> dict[str, str]:
    return {
        key: transliterated_buffer[offset : offset + WINDOW_SIZE].decode("ascii")
        for key, offset in WINDOW_OFFSETS.items()
    }


WINDOW_LINE_RE = re.compile(
    r'^(D\d\d)\s+JIT\+0x[0-9a-fA-F]+\s+"([^"]*)"\s+\([0-9a-fA-F]+\)\s+"([^"]*)"',
    re.MULTILINE,
)
DIGEST_LINE_RE = re.compile(
    r"^(D\d\d)\s+JIT\+0x[0-9a-fA-F]+:\s+output=([0-9A-Fa-f]{64})",
    re.MULTILINE,
)


def parse_round_windows_trace(path: Path) -> TracedRoundChain:
    text = path.read_text()
    windows: dict[str, bytes] = {}
    required_windows = {"d05", "d10", "d11", "d12", "d13"}
    for round_id, pre_rev32, _post_rev32 in WINDOW_LINE_RE.findall(text):
        round_key = round_id.lower()
        if round_key in required_windows and pre_rev32:
            windows[round_id.lower()] = pre_rev32.encode("ascii")
    digests = {
        round_id.lower(): bytes.fromhex(digest_hex)
        for round_id, digest_hex in DIGEST_LINE_RE.findall(text)
    }
    required_digests = {"d04", "d09", "d13"}
    missing_windows = sorted(required_windows - windows.keys())
    missing_digests = sorted(required_digests - digests.keys())
    if missing_windows or missing_digests:
        problems = []
        if missing_windows:
            problems.append(f"windows={','.join(missing_windows)}")
        if missing_digests:
            problems.append(f"digests={','.join(missing_digests)}")
        raise ValueError(f"incomplete round trace in {path}: {' '.join(problems)}")
    return TracedRoundChain(windows=windows, digests=digests, source=str(path))


def compute_merkle_from_traced_windows(trace: TracedRoundChain) -> MerkleStageResult:
    d05_window = trace.windows["d05"]
    d11_window = trace.windows["d11"]
    d12_window = trace.windows["d12"]
    d13_window = trace.windows["d13"]
    board_window = trace.windows["d10"]

    phase2a = trace.digests["d04"]
    for _ in range(4):
        phase2a = sha256_once(d05_window, phase2a)

    digest = trace.digests["d09"]
    for window in (board_window, d11_window, d12_window, d13_window):
        digest = sha256_once(window, digest)

    return MerkleStageResult(
        transliterated_buffer=b"",
        d05_window=d05_window,
        d11_window=d11_window,
        d12_window=d12_window,
        d13_window=d13_window,
        phase2a_digest=phase2a,
        final_digest=digest,
        cert_hex=cert_hex_from_digest(digest),
    )


def search_well512_window_matches(
    snapshot: Well512Snapshot,
    target_buffer: bytes,
    max_advance: int,
) -> dict[str, object]:
    if len(target_buffer) != 1040:
        raise ValueError(f"target buffer must be 1040 bytes, got {len(target_buffer)}")

    target_windows = extract_fixed_windows(target_buffer)
    best_score = -1
    best_advance = 0
    best_windows: dict[str, str] = {}
    exact_match_advance: int | None = None

    current = snapshot
    for advance in range(max_advance + 1):
        generated = transliterate_hex_buffer(generate_well512_hex_buffer(current))
        windows = extract_fixed_windows(generated)
        score = sum(windows[key] == target_windows[key] for key in target_windows)
        if score > best_score:
            best_score = score
            best_advance = advance
            best_windows = windows
        if generated == target_buffer:
            exact_match_advance = advance
            break
        current = advance_well512_snapshot(current, 1)

    return {
        "target_windows": target_windows,
        "best_score": best_score,
        "best_advance": best_advance,
        "best_windows": best_windows,
        "exact_match_advance": exact_match_advance,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compute the recovered NMSS cert-stage Merkle digest from a captured stage buffer or WELL512 snapshot."
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "--buffer",
        type=Path,
        default=DEFAULT_STAGE_BUFFER,
        help=f"Captured 1040/1041-byte cert-stage buffer (default: {DEFAULT_STAGE_BUFFER})",
    )
    input_group.add_argument(
        "--round-windows",
        type=Path,
        help=f"Trace file with D00-D13 windows/digests (default trace path: {DEFAULT_ROUND_WINDOWS})",
    )
    input_group.add_argument(
        "--well512-session",
        choices=("session1", "session5"),
        help="Generate the 1040-char stage buffer from the WELL512 snapshot stored in the capture summary.",
    )
    input_group.add_argument(
        "--well512-state-hex",
        help="128-byte WELL512 state as hex. Requires --well512-index.",
    )
    parser.add_argument(
        "--well512-index",
        type=int,
        help="WELL512 index (0-15) for --well512-state-hex.",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=DEFAULT_CAPTURE_SUMMARY,
        help=f"Capture summary JSON (default: {DEFAULT_CAPTURE_SUMMARY})",
    )
    parser.add_argument(
        "--board",
        default=BOARD_WINDOW.decode("ascii"),
        help=f"8-byte board/SoC window (default: {BOARD_WINDOW.decode('ascii')})",
    )
    parser.add_argument(
        "--advance",
        type=int,
        default=0,
        help="Advance the WELL512 snapshot by N calls before generating the 1040-char buffer.",
    )
    parser.add_argument(
        "--search-window-match",
        type=int,
        help="Search advances [0..N] for the best fixed-window match against --target-buffer.",
    )
    parser.add_argument(
        "--target-buffer",
        type=Path,
        default=DEFAULT_STAGE_BUFFER,
        help=f"Target 1040/1041-byte cert-stage buffer for --search-window-match (default: {DEFAULT_STAGE_BUFFER})",
    )
    parser.add_argument(
        "--dump-buffer",
        action="store_true",
        help="Print the transliterated 1040-byte buffer.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON report instead of key=value lines.",
    )
    return parser


def load_transliterated_buffer(args: argparse.Namespace) -> tuple[bytes, str]:
    if args.round_windows:
        raise SystemExit("--round-windows does not provide a transliterated buffer")
    if args.well512_state_hex:
        if args.well512_index is None:
            raise SystemExit("--well512-index is required with --well512-state-hex")
        snapshot = parse_well512_state_hex(
            args.well512_state_hex,
            args.well512_index,
            source="cli",
        )
        if args.advance:
            snapshot = advance_well512_snapshot(snapshot, args.advance)
        generated = generate_well512_hex_buffer(snapshot)
        return transliterate_hex_buffer(generated), snapshot.source

    if args.well512_session:
        snapshot = load_well512_snapshot_from_summary(args.summary, args.well512_session)
        if args.advance:
            snapshot = advance_well512_snapshot(snapshot, args.advance)
        generated = generate_well512_hex_buffer(snapshot)
        return transliterate_hex_buffer(generated), snapshot.source

    return read_stage_buffer(args.buffer), str(args.buffer)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    board_bytes = args.board.encode("ascii")

    if args.search_window_match is not None:
        if args.well512_state_hex:
            if args.well512_index is None:
                raise SystemExit("--well512-index is required with --well512-state-hex")
            snapshot = parse_well512_state_hex(
                args.well512_state_hex,
                args.well512_index,
                source="cli",
            )
        elif args.well512_session:
            snapshot = load_well512_snapshot_from_summary(args.summary, args.well512_session)
        else:
            raise SystemExit("--search-window-match requires --well512-session or --well512-state-hex")

        target_buffer = read_stage_buffer(args.target_buffer)
        report = search_well512_window_matches(snapshot, target_buffer, args.search_window_match)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(f"best_score={report['best_score']}")
            print(f"best_advance={report['best_advance']}")
            print(f"exact_match_advance={report['exact_match_advance']}")
            print("target_windows=" + ",".join(f"{k}:{v}" for k, v in report["target_windows"].items()))
            print("best_windows=" + ",".join(f"{k}:{v}" for k, v in report["best_windows"].items()))
        return 0

    if args.round_windows:
        trace = parse_round_windows_trace(args.round_windows)
        result = compute_merkle_from_traced_windows(trace)
        transliterated_buffer = b""
        source = trace.source
        board_bytes = trace.windows["d10"]
        report = {
            "source": source,
            "mode": "round_windows",
            "board_window": board_bytes.decode("ascii", errors="replace"),
            "d05_window": result.d05_window.decode("ascii"),
            "d11_window": result.d11_window.decode("ascii"),
            "d12_window": result.d12_window.decode("ascii"),
            "d13_window": result.d13_window.decode("ascii"),
            "phase2a_digest_hex": result.phase2a_digest.hex().upper(),
            "final_digest_hex": result.final_digest.hex().upper(),
            "cert_hex": result.cert_hex,
            "trace_d13_digest_hex": trace.digests["d13"].hex().upper(),
            "trace_matches_recomputed": trace.digests["d13"] == result.final_digest,
        }
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            for key, value in report.items():
                print(f"{key}={value}")
        return 0

    transliterated_buffer, source = load_transliterated_buffer(args)
    result = compute_merkle_cert_stage(transliterated_buffer, board_bytes)

    if args.dump_buffer:
        print(transliterated_buffer.decode("ascii"))
        return 0

    report = {
        "source": source,
        "mode": "buffer_or_well512",
        "buffer_len": len(transliterated_buffer),
        "buffer_sha256": hashlib.sha256(transliterated_buffer).hexdigest(),
        "board_window": board_bytes.decode("ascii", errors="replace"),
        "d05_offset": hex(WINDOW_OFFSETS["d05"]),
        "d05_window": result.d05_window.decode("ascii"),
        "d11_offset": hex(WINDOW_OFFSETS["d11"]),
        "d11_window": result.d11_window.decode("ascii"),
        "d12_offset": hex(WINDOW_OFFSETS["d12"]),
        "d12_window": result.d12_window.decode("ascii"),
        "d13_offset": hex(WINDOW_OFFSETS["d13"]),
        "d13_window": result.d13_window.decode("ascii"),
        "phase2a_digest_hex": result.phase2a_digest.hex().upper(),
        "final_digest_hex": result.final_digest.hex().upper(),
        "cert_hex": result.cert_hex,
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for key, value in report.items():
            print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
