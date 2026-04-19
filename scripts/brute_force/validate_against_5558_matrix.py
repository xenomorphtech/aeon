#!/usr/bin/env python3
"""Validate any candidate cert reproducer against the 5558-auth matrix.

Source: trace-claude3 capture at capture/session_keys_auth_det.json,
3 real device cert pairs from an authenticated 5558 session where the
direct-call path (corridor+0x101115cc) was hit without OLLVM dispatch.

Usage:
    # Check the matrix is present and display it
    $ python3 scripts/brute_force/validate_against_5558_matrix.py show

    # Run a proposed reproducer function against the 3 pairs
    $ python3 scripts/brute_force/validate_against_5558_matrix.py run \\
        --reproducer path/to/reproducer.py

The reproducer must expose `compute_cert(challenge: str) -> str` returning
the 48-char uppercase hex cert.  The matrix entries' `session_key` field
is empty — the reproducer must know the session key internally (via its
own config / env / embedded value).  All 3 pairs come from the SAME
session, so if the key is right for one it is right for all.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import sys
from pathlib import Path


MATRIX_PATH = Path(__file__).resolve().parent.parent.parent / \
              "fixtures" / "validation_matrix_5558_auth.json"


def load_matrix() -> list[tuple[str, str]]:
    d = json.loads(MATRIX_PATH.read_text())
    return [(p["challenge"], p["token"]) for p in d["pairs"]]


def cmd_show(args):
    d = json.loads(MATRIX_PATH.read_text())
    print(f"Matrix: {MATRIX_PATH}")
    print(f"  source: {d.get('source')}")
    print(f"  session_key: {d.get('session_key', '<empty>')!r}")
    print(f"  pairs: {len(d['pairs'])}")
    for p in d["pairs"]:
        ch = p["challenge"]
        tk = p["token"]
        print(f"    {ch} → {tk}")
    return 0


def cmd_run(args):
    spec = importlib.util.spec_from_file_location("repro", args.reproducer)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "compute_cert"):
        print(f"reproducer must expose compute_cert(challenge: str) -> str",
              file=sys.stderr)
        return 2

    pairs = load_matrix()
    wins = 0
    for ch, expected in pairs:
        got = mod.compute_cert(ch)
        match = "✓" if got == expected else "✗"
        if got == expected:
            wins += 1
        print(f"  {match} {ch} → want {expected}")
        print(f"         got  {got}")
    total = len(pairs)
    print(f"\nResult: {wins}/{total}")
    return 0 if wins == total else 1


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("show", help="display the matrix")
    sp.set_defaults(fn=cmd_show)
    sp = sub.add_parser("run", help="run a reproducer against the matrix")
    sp.add_argument("--reproducer", required=True,
                    help="path to a .py exposing compute_cert(challenge)->str")
    sp.set_defaults(fn=cmd_run)
    args = p.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
