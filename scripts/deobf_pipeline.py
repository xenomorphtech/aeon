#!/usr/bin/env python3
"""Deobfuscation pipeline skeleton: aeon IL → symbolic expression → LLM-ready JSON.

Intended targets:
  * challenge_hash32 — custom/MBA-obfuscated 16-byte-string → u32 function,
    suspected to live inside stage[0/3]=corr+0x1475A8 or stage[5/6]=corr+0x135658.
  * derive_well512_state — how session_key + challenge_hash32 →
    16×u64 WELL512 state at corridor+0x0A7740.

Pipeline stages
---------------
1. pull_block_il(binary, func, block) → list of aeon IL statements (JSON).
2. lift_to_symbolic(il_statements, inputs) → claripy.ast.Bits (pure SMT).
3. simplify_local(expr) → apply cheap rewrites (bitvec algebra, ite
   collapsing, constant folding).
4. emit_llm_request(expr, metadata) → JSON payload describing the residual
   symbolic form plus ground-truth test vectors — the thing an external
   LLM simplifier can consume.

Design constraints
------------------
* No live aeon MCP dependency in this file; the aeon puller is an adapter
  that can be swapped for a cache/fixture. The skeleton runs in dry-run
  mode without any external tool.
* claripy is optional; when absent, the lifter emits a lossless
  IR-as-JSON representation so callers can still produce the LLM request.
* Target-agnostic: any (binary, func_addr, block_addr) triple that aeon
  knows about. The symbolic inputs and test vectors are declared per-target
  in a small registry at the bottom.

Run locally
-----------
    $ python3 scripts/deobf_pipeline.py list
    $ python3 scripts/deobf_pipeline.py dry-run challenge_hash32
    $ python3 scripts/deobf_pipeline.py emit challenge_hash32 \\
        --il-fixture /tmp/il_block_0x1475a8.json \\
        --out /tmp/deobf_request_challenge_hash32.json
    $ python3 scripts/deobf_pipeline.py verify challenge_hash32 \\
        /tmp/proposed_challenge_hash32.py --fuzz 10000
    $ python3 scripts/deobf_pipeline.py send /tmp/deobf_request.json \\
        --model gemini-2.0-flash-lite

LLM wire format (reference, no client dependency)
-------------------------------------------------
The `send` subcommand supports two providers via ``--provider``:

    openrouter  (default)
        POST https://openrouter.ai/api/v1/chat/completions
        Header: Authorization: Bearer $OPENROUTER_API_KEY
        Body:  {"model": $OPENROUTER_MODEL,
                "messages": [{"role":"user","content": <PROMPT>}],
                "temperature": 0.2, "max_tokens": 4096}
        Read:  resp["choices"][0]["message"]["content"]
               resp["choices"][0]["finish_reason"]  (stop|length|
                                                     content_filter|tool_calls)
               resp["usage"].{prompt_tokens,completion_tokens,total_tokens}

    gemini
        POST https://generativelanguage.googleapis.com/v1beta/models/
             {model}:generateContent?key=$GEMINI_API_KEY
        Body:  {"contents":[{"parts":[{"text": <PROMPT>}]}],
                "generationConfig":{"temperature":0.2,"maxOutputTokens":4096}}
        Read:  resp["candidates"][0]["content"]["parts"][0]["text"]
               resp["candidates"][0]["finishReason"]
               resp["usageMetadata"].{promptTokenCount,candidatesTokenCount,
                                      totalTokenCount}

OPENROUTER_API_KEY and OPENROUTER_MODEL are loaded automatically from
/home/sdancer/orchestrator/.env (chmod 600, gitignored).  Both providers
are backed by stdlib urllib only — no third-party SDK required.
"""
from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import os
import random
import struct
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable


# ---------------------------------------------------------------------------
# Target registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SymInput:
    """A symbolic input to the lifted expression."""
    name: str
    width_bits: int
    description: str


@dataclass(frozen=True)
class TestVector:
    """Ground-truth (input_assignment → expected_output) observation."""
    inputs: dict[str, int]
    output: int
    source: str


@dataclass(frozen=True)
class Target:
    name: str
    binary: str
    func_addr: int
    block_addrs: tuple[int, ...]
    inputs: tuple[SymInput, ...]
    output: SymInput
    test_vectors: tuple[TestVector, ...]
    # Produces one random input-assignment per call, matching `inputs`.
    # When None, property-based fuzzing is skipped for this target.
    fuzz_sample: Callable[["random.Random"], dict[str, int]] | None = None
    notes: str = ""


# Known test vectors (session ea7d27…).  Kept in this file so the skeleton is
# self-contained; when more are traced, append to these tuples.
_CHALLENGE_HASH32_VECTORS = (
    TestVector({"challenge_ascii16_lo_u64": 0x4444434342424141,
                "challenge_ascii16_hi_u64": 0x3131303046464545}, 0xa0ccbf06,
               "traced session_patched_trace.json"),
    TestVector({"challenge_ascii16_lo_u64": 0x3030303030303030,
                "challenge_ascii16_hi_u64": 0x3030303030303030}, 0xecde5cf0,
               "traced"),
    TestVector({"challenge_ascii16_lo_u64": 0x3131313131313131,
                "challenge_ascii16_hi_u64": 0x3131313131313131}, 0xe06bf3e8,
               "traced"),
    TestVector({"challenge_ascii16_lo_u64": 0x3730364434414236,
                "challenge_ascii16_hi_u64": 0x3338303038353833}, 0xcf9ffab6,
               "traced"),
    TestVector({"challenge_ascii16_lo_u64": 0x4645454244414544,
                "challenge_ascii16_hi_u64": 0x3837363534333231}, 0x04b5fd7c,
               "traced"),
)


def _fuzz_challenge_hash32(rng: "random.Random") -> dict[str, int]:
    """Random 16-char ASCII-hex challenge, packed LE into two u64s."""
    alphabet = b"0123456789ABCDEF"
    ascii16 = bytes(alphabet[rng.randrange(16)] for _ in range(16))
    return {
        "challenge_ascii16_lo_u64": struct.unpack("<Q", ascii16[0:8])[0],
        "challenge_ascii16_hi_u64": struct.unpack("<Q", ascii16[8:16])[0],
    }


def _toy_hash32(lo: int, hi: int) -> int:
    """Synthetic MBA-obfuscated toy that simplifies to (lo ^ hi) & 0xffffffff.

    Used only to exercise the emit → send → verify round trip before the
    real corridor IL arrives.  The MBA identity in play:

        (x ^ y) + 2·(x & y) == x + y
        ⇒ ((x ^ y) + 2·(x & y)) − 2·(x & y) == x ^ y

    The IL fixture at `fixtures/challenge_hash32_toy_block.json` expresses
    exactly this sequence, so an LLM simplifier should collapse it to the
    XOR form.
    """
    m64 = (1 << 64) - 1
    t0 = (lo ^ hi) & m64
    t1 = (lo & hi) & m64
    t2 = (t1 << 1) & m64
    t3 = (t0 + t2) & m64
    t4 = (t3 - t2) & m64
    return t4 & 0xffffffff


def _toy_vectors() -> tuple[TestVector, ...]:
    samples = [
        (0x4444434342424141, 0x3131303046464545),  # AABBCCDDEEFF0011
        (0x3030303030303030, 0x3030303030303030),  # 0000000000000000
        (0x3131313131313131, 0x3131313131313131),  # 1111111111111111
        (0x3730364434414236, 0x3338303038353833),  # 6BA4D60738580083
        (0x4645454244414544, 0x3837363534333231),  # DEADBEEF12345678
    ]
    return tuple(
        TestVector({"challenge_ascii16_lo_u64": lo,
                    "challenge_ascii16_hi_u64": hi},
                   _toy_hash32(lo, hi), "synthetic")
        for lo, hi in samples
    )


def _fuzz_derive_well512(rng: "random.Random") -> dict[str, int]:
    return {
        "session_key_lo_u64": rng.getrandbits(64),
        "session_key_hi_u64": rng.getrandbits(64),
        "challenge_hash32": rng.getrandbits(32),
        "time_millis_u64": rng.getrandbits(64),
    }


TARGETS: dict[str, Target] = {
    "challenge_hash32": Target(
        name="challenge_hash32",
        binary="/home/sdancer/aeon-trace/capture/binaries/libnmsssa.so",
        func_addr=0x1475A8,  # stage[0/3] candidate
        block_addrs=(0x1475A8,),
        inputs=(
            SymInput("challenge_ascii16_lo_u64", 64, "challenge LE first 8 ASCII bytes"),
            SymInput("challenge_ascii16_hi_u64", 64, "challenge LE second 8 ASCII bytes"),
        ),
        output=SymInput("hash32", 32, "mode=4 cmd=0x5501 request u32 at offset 20"),
        test_vectors=_CHALLENGE_HASH32_VECTORS,
        fuzz_sample=_fuzz_challenge_hash32,
        notes=(
            "Crypto-grade avalanche confirmed (~50% flip ratio). "
            "Candidate also at stage[5/6]=0x135658 (73KB) — run on both."
        ),
    ),
    "challenge_hash32_toy": Target(
        name="challenge_hash32_toy",
        binary="<synthetic>",
        func_addr=0xDEAD00,
        block_addrs=(0xDEAD00,),
        inputs=(
            SymInput("challenge_ascii16_lo_u64", 64, "toy input LE lo u64"),
            SymInput("challenge_ascii16_hi_u64", 64, "toy input LE hi u64"),
        ),
        output=SymInput("hash32", 32, "(lo ^ hi) & 0xffffffff — MBA-obfuscated"),
        test_vectors=_toy_vectors(),
        fuzz_sample=_fuzz_challenge_hash32,
        notes=(
            "Synthetic pipeline self-test target.  IL fixture expresses the "
            "MBA identity (x^y) = ((x^y)+2·(x&y)) − 2·(x&y).  Closed form: "
            "(lo ^ hi) & 0xffffffff."
        ),
    ),
    "derive_well512_state": Target(
        name="derive_well512_state",
        binary="/home/sdancer/aeon-trace/capture/binaries/libnmsssa.so",
        func_addr=0x0A7740,  # WELL512 state site per fact well512_64bit
        block_addrs=(0x0A7740,),
        inputs=(
            SymInput("session_key_lo_u64", 64, "session_key LE [0:8]"),
            SymInput("session_key_hi_u64", 64, "session_key LE [8:16]"),
            SymInput("challenge_hash32", 32, "u32 produced by challenge_hash32"),
            SymInput("time_millis_u64", 64, "gettimeofday-derived srand seed"),
        ),
        output=SymInput("well512_state_bytes", 128 * 8,
                        "16 × u64 WELL512 state serialized LE"),
        test_vectors=(),  # none yet — blocked on live capture
        fuzz_sample=_fuzz_derive_well512,
        notes=(
            "Per fact well512_64bit: gettimeofday → millis → srand → "
            "16×(rand()^(rand()<<16)).  Challenge/session coupling still "
            "unverified."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Stage 1 — pull aeon IL for a basic block (adapter, no live deps)
# ---------------------------------------------------------------------------


def pull_block_il(target: Target, block_addr: int,
                  fixture_path: Path | None = None) -> dict[str, Any]:
    """Return an aeon IL block as a JSON dict.

    Live mode (future): invoke mcp__aeon__get_il / get_reduced_il with narrow
    args.  For now this reads a JSON fixture file on disk — produced offline
    by a wrapper that calls aeon and writes the result to a cache.

    The expected fixture schema is a thin wrapper around aeon's existing IL
    dump:

        {
          "target": "challenge_hash32",
          "func_addr": "0x1475A8",
          "block_addr": "0x1475A8",
          "instructions": [
            {"addr": "0x1475A8", "il": "x8 = x1 ^ 0x1234"},
            {"addr": "0x1475AC", "il": "x9 = x8 * 0xdeadbeef"},
            ...
          ]
        }
    """
    if fixture_path is not None and fixture_path.exists():
        return json.loads(fixture_path.read_text())
    # Empty shell for dry-run
    return {
        "target": target.name,
        "func_addr": f"0x{target.func_addr:x}",
        "block_addr": f"0x{block_addr:x}",
        "instructions": [],
        "note": "DRY-RUN — no fixture supplied; stage 2 will lift a no-op.",
    }


# ---------------------------------------------------------------------------
# Stage 2 — lift IL to a symbolic expression (claripy-optional)
# ---------------------------------------------------------------------------


def _try_import_claripy():
    try:
        import claripy  # type: ignore
        return claripy
    except ImportError:
        return None


@dataclass
class SymbolicResult:
    """Carrier for a lifted expression across the claripy ↔ JSON boundary."""
    symbolic_inputs: list[dict[str, Any]]
    statements: list[dict[str, Any]]  # [{"dst": "t3", "op": "xor", "args": [...]}]
    final_expr: str                    # textual S-expr OR claripy repr
    register_map: dict[str, str]       # final SSA name → register label
    metadata: dict[str, Any] = field(default_factory=dict)


# -- Pure-Python symbolic IR (claripy-free) -------------------------------


@dataclass(frozen=True)
class BV:
    """A bit-vector expression node.

    ``kind`` is one of {"var", "const", "op"}.
    ``value`` is the constant integer for kind=="const", else ignored.
    ``name`` is the identifier for kind=="var", else "".
    ``op`` is the operator for kind=="op": one of OP_NAMES below.
    ``args`` is the tuple of child BVs for kind=="op", else ().
    ``width`` is the bit-width.
    """
    kind: str
    width: int
    value: int = 0
    name: str = ""
    op: str = ""
    args: tuple = ()

    def __repr__(self) -> str:
        if self.kind == "var":
            return self.name
        if self.kind == "const":
            return f"0x{self.value & ((1 << self.width) - 1):x}u{self.width}"
        return f"({self.op} {' '.join(repr(a) for a in self.args)})"


OP_NAMES = {
    "xor", "and", "or", "add", "sub", "mul",
    "shl", "shr", "ashr", "rotl", "rotr",
    "neg", "not",
    "trunc", "zext", "sext", "copy",
}


def _bv_const(value: int, width: int) -> BV:
    return BV(kind="const", width=width,
              value=value & ((1 << width) - 1))


def _bv_var(name: str, width: int) -> BV:
    return BV(kind="var", width=width, name=name)


def _bv_op(op: str, args: tuple[BV, ...], width: int) -> BV:
    return BV(kind="op", width=width, op=op, args=args)


def _parse_arg(token: str, env: dict[str, BV], default_width: int) -> BV:
    """Resolve an IL argument token into a BV node.

    Tokens can be:
      * SSA name already in env ("x0", "t1", ...)
      * Immediate "#1" or "0x1234" or "1234"  (decimal/hex)
    """
    t = token.strip()
    if t.startswith("#"):
        t = t[1:]
    if t in env:
        return env[t]
    # Numeric literal — accept hex (0x prefix), decimal, or signed.
    try:
        if t.lower().startswith("0x"):
            v = int(t, 16)
        else:
            v = int(t)
    except ValueError:
        # Unknown identifier — surface as a fresh variable so the lifter
        # never silently drops information.
        return _bv_var(t, default_width)
    return _bv_const(v, default_width)


def lift_to_symbolic(il_block: dict[str, Any], target: Target) -> SymbolicResult:
    """Build a structured symbolic IR from an aeon IL block.

    The lifter consumes the fixture's structured ``op/dst/args/width`` fields
    (preferred) and falls back to preserving the raw ``il`` string when those
    fields are absent.  Output is a pure-Python expression tree (see ``BV``)
    keyed by SSA name plus the original instruction list.

    Recognised ops: copy, add, sub, mul, and, or, xor, shl, shr, ashr, rotl,
    rotr, neg, not, trunc, zext, sext, ret.  Unknown ops are preserved
    verbatim.
    """
    sym_inputs: list[dict[str, Any]] = [
        {"name": i.name, "width_bits": i.width_bits} for i in target.inputs
    ]
    register_map = dict(il_block.get("register_map", {}))

    # Seed SSA env with declared target inputs.
    env: dict[str, BV] = {i.name: _bv_var(i.name, i.width_bits)
                          for i in target.inputs}
    # Pre-populate any inputs that the IL block aliases via register_map
    # (e.g. fixture register x0 → challenge_ascii16_lo_u64 input).
    for reg, mapped in register_map.items():
        if mapped in env:
            env[reg] = env[mapped]

    statements: list[dict[str, Any]] = []
    final_node: BV | None = None
    for instr in il_block.get("instructions", []):
        addr = instr.get("addr", "?")
        op = instr.get("op")
        dst = instr.get("dst")
        raw_args = instr.get("args", []) or []
        width = int(instr.get("width", target.output.width_bits) or
                    target.output.width_bits)

        if op == "ret":
            # Return value is whichever SSA name was passed.
            ret_name = raw_args[0] if raw_args else None
            if ret_name and ret_name in env:
                final_node = env[ret_name]
            statements.append({"addr": addr, "op": "ret",
                               "dst": None, "args": list(raw_args),
                               "width": width})
            continue

        if op in OP_NAMES and dst:
            arg_nodes = tuple(_parse_arg(a, env, width) for a in raw_args)
            node = _bv_op(op, arg_nodes, width)
            env[dst] = node
            statements.append({"addr": addr, "op": op, "dst": dst,
                               "args": [str(a) for a in raw_args],
                               "width": width,
                               "node": repr(node)})
        else:
            # Unknown op or no dst — preserve verbatim so emit can still ship.
            statements.append({"addr": addr, "il": instr.get("il", ""),
                               "op": op, "dst": dst,
                               "args": list(raw_args), "width": width})

    if final_node is None:
        # No explicit ret — final_node is the last assignment if available.
        for s in reversed(statements):
            if s.get("dst") and s["dst"] in env:
                final_node = env[s["dst"]]
                break

    final_repr = repr(final_node) if final_node is not None else "<no expression>"

    return SymbolicResult(
        symbolic_inputs=sym_inputs,
        statements=statements,
        final_expr=final_repr,
        register_map=register_map,
        metadata={
            "used_claripy": False,
            "instruction_count": len(statements),
            "final_node": final_repr,
            "lifter_version": 2,
        },
    )


# ---------------------------------------------------------------------------
# Stage 3 — cheap local simplification (constant folding, identities, MBA)
# ---------------------------------------------------------------------------


def _mask(width: int) -> int:
    return (1 << width) - 1


def _eval_const_op(op: str, args: tuple[BV, ...], width: int) -> int | None:
    """Evaluate an op whose args are all constants; return the result int."""
    m = _mask(width)
    vals = [a.value & _mask(a.width) for a in args]
    if op == "add":  return (vals[0] + vals[1]) & m
    if op == "sub":  return (vals[0] - vals[1]) & m
    if op == "mul":  return (vals[0] * vals[1]) & m
    if op == "and":  return (vals[0] & vals[1]) & m
    if op == "or":   return (vals[0] | vals[1]) & m
    if op == "xor":  return (vals[0] ^ vals[1]) & m
    if op == "shl":  return (vals[0] << vals[1]) & m
    if op == "shr":  return (vals[0] >> vals[1]) & m
    if op == "neg":  return (-vals[0]) & m
    if op == "not":  return (~vals[0]) & m
    if op == "copy": return vals[0] & m
    if op == "trunc": return vals[0] & m
    if op == "zext": return vals[0] & m
    return None


def _is_const(n: BV, value: int | None = None) -> bool:
    if n.kind != "const":
        return False
    if value is None:
        return True
    return (n.value & _mask(n.width)) == (value & _mask(n.width))


def _simplify_node(n: BV) -> BV:
    """Bottom-up simplification of a single BV node.

    Applies (in order):
      1. recursive simplify of children
      2. constant folding
      3. algebraic identities (x+0, x-x, x^x, x&0, x|0, …)
      4. structural cancellation: (a OP b) INV-OP b = a for add/sub, xor/xor
      5. MBA contraction:  (x^y) + 2·(x&y)        →  x + y
                           (x^y) + (x&y) + (x&y) →  x + y
                           (x|y) - (x&y)         →  x ^ y
                           (x+y) - (x&y)         →  x | y
      6. trunc collapse: trunc(N, e) where e.width <= N → zext to N
    """
    if n.kind != "op":
        return n

    args = tuple(_simplify_node(a) for a in n.args)
    op, w = n.op, n.width

    # 2. constant folding
    if all(a.kind == "const" for a in args):
        v = _eval_const_op(op, args, w)
        if v is not None:
            return _bv_const(v, w)

    # 3. algebraic identities
    if op in ("add", "sub", "or", "xor") and len(args) == 2:
        a, b = args
        if op == "add" and _is_const(b, 0): return a
        if op == "add" and _is_const(a, 0): return b
        if op == "sub" and _is_const(b, 0): return a
        if op == "sub" and a == b:          return _bv_const(0, w)
        if op == "or"  and _is_const(b, 0): return a
        if op == "or"  and _is_const(a, 0): return b
        if op == "xor" and _is_const(b, 0): return a
        if op == "xor" and _is_const(a, 0): return b
        if op == "xor" and a == b:          return _bv_const(0, w)
    if op == "and" and len(args) == 2:
        a, b = args
        if _is_const(b, 0): return _bv_const(0, w)
        if _is_const(a, 0): return _bv_const(0, w)
        if _is_const(b, _mask(w)): return a
        if _is_const(a, _mask(w)): return b
        if a == b: return a
    if op in ("shl", "shr") and len(args) == 2 and _is_const(args[1], 0):
        return args[0]

    # 4. structural cancellation: (a + b) - b = a, (a - b) + b = a
    if op == "sub" and len(args) == 2:
        a, b = args
        if a.kind == "op" and a.op == "add" and len(a.args) == 2:
            x, y = a.args
            if y == b: return x
            if x == b: return y
        if a.kind == "op" and a.op == "sub" and len(a.args) == 2:
            x, y = a.args
            if y == b: return _bv_op("sub", (x, _bv_op("mul",
                                                        (b, _bv_const(2, w)),
                                                        w)), w)
    if op == "add" and len(args) == 2:
        a, b = args
        if a.kind == "op" and a.op == "sub" and len(a.args) == 2:
            x, y = a.args
            if y == b: return x

    # 5. MBA contractions
    #    (x^y) + 2·(x&y) → x + y      (and the symmetric form)
    #    (x^y) + (x&y) + (x&y) → same
    if op == "add" and len(args) == 2:
        a, b = args
        for lhs, rhs in ((a, b), (b, a)):
            if (lhs.kind == "op" and lhs.op == "xor"
                and rhs.kind == "op" and rhs.op == "mul"
                and len(rhs.args) == 2
                and any(_is_const(c, 2) for c in rhs.args)):
                xy = lhs.args
                # find the AND child of mul
                non_const = [c for c in rhs.args if not _is_const(c, 2)]
                if len(non_const) == 1:
                    inner = non_const[0]
                    if (inner.kind == "op" and inner.op == "and"
                        and tuple(sorted([repr(x) for x in inner.args]))
                        == tuple(sorted([repr(x) for x in xy]))):
                        return _bv_op("add", xy, w)
            # Form: (x^y) + (x&y << 1)
            if (lhs.kind == "op" and lhs.op == "xor"
                and rhs.kind == "op" and rhs.op == "shl"
                and len(rhs.args) == 2 and _is_const(rhs.args[1], 1)):
                xy = lhs.args
                inner = rhs.args[0]
                if (inner.kind == "op" and inner.op == "and"
                    and tuple(sorted([repr(x) for x in inner.args]))
                    == tuple(sorted([repr(x) for x in xy]))):
                    return _bv_op("add", xy, w)

    # (x|y) - (x&y) → x ^ y;  (x+y) - (x&y) → x|y
    # (x+y) - 2·(x&y) → x ^ y ;  (x+y) - ((x&y)<<1) → x ^ y
    if op == "sub" and len(args) == 2:
        a, b = args
        if (a.kind == "op" and a.op == "or"
            and b.kind == "op" and b.op == "and"
            and tuple(sorted([repr(x) for x in a.args]))
                == tuple(sorted([repr(x) for x in b.args]))):
            return _bv_op("xor", a.args, w)
        if (a.kind == "op" and a.op == "add"
            and b.kind == "op" and b.op == "and"
            and tuple(sorted([repr(x) for x in a.args]))
                == tuple(sorted([repr(x) for x in b.args]))):
            return _bv_op("or", a.args, w)

        # Helper: does `b` denote 2·(x&y) where {x,y} matches a's args?
        if a.kind == "op" and a.op == "add":
            ab_keys = tuple(sorted([repr(x) for x in a.args]))
            inner = None
            if (b.kind == "op" and b.op == "shl" and len(b.args) == 2
                and _is_const(b.args[1], 1)):
                inner = b.args[0]
            elif (b.kind == "op" and b.op == "mul" and len(b.args) == 2
                  and any(_is_const(c, 2) for c in b.args)):
                inner = next((c for c in b.args if not _is_const(c, 2)), None)
            if (inner is not None
                and inner.kind == "op" and inner.op == "and"
                and tuple(sorted([repr(x) for x in inner.args])) == ab_keys):
                return _bv_op("xor", a.args, w)

    # 6. trunc collapse: trunc(N, e) where e is already N-bit-wide
    if op == "trunc" and len(args) == 1 and args[0].width <= w:
        return args[0]

    # No rewrite applied — rebuild with simplified children.
    if args == n.args:
        return n
    return _bv_op(op, args, w)


def _fixed_point_simplify(node: BV, max_iter: int = 16) -> BV:
    cur = node
    for _ in range(max_iter):
        nxt = _simplify_node(cur)
        if nxt == cur:
            return nxt
        cur = nxt
    return cur


def simplify_local(result: SymbolicResult) -> SymbolicResult:
    """Apply local rewrites: constant folding, identities, MBA contractions.

    Reads ``metadata['final_node']`` (the IR repr) — the IR itself is in the
    SSA env that the lifter no longer carries forward.  We re-parse the
    final repr structure by walking the statements list to rebuild the
    expression tree, then run rewrites to fixed-point.

    NOTE: To keep the data model simple and serialisable, we attach the
    simplified node's repr to ``metadata['simplified']``.  Downstream stages
    (emit, verify) can use this to short-circuit the LLM call when the local
    pass succeeds.
    """
    # Rebuild the SSA env from the structured statements list.
    env: dict[str, BV] = {}
    for s in result.symbolic_inputs:
        env[s["name"]] = _bv_var(s["name"], s["width_bits"])
    final_node: BV | None = None
    for s in result.statements:
        op = s.get("op")
        dst = s.get("dst")
        if op == "ret":
            ret_args = s.get("args", [])
            if ret_args and ret_args[0] in env:
                final_node = env[ret_args[0]]
            continue
        if op in OP_NAMES and dst:
            args = tuple(_parse_arg(a, env, s.get("width",
                                                  result.symbolic_inputs[0]["width_bits"]))
                         for a in s.get("args", []))
            env[dst] = _bv_op(op, args, int(s.get("width", 64)))
            final_node = env[dst]

    if final_node is None:
        result.metadata["simplified"] = "<no expression>"
        result.metadata["simplified_via"] = "noop"
        return result

    simplified = _fixed_point_simplify(final_node)
    result.metadata["simplified"] = repr(simplified)
    result.metadata["simplified_via"] = "local-passes"
    result.metadata["fully_reduced"] = simplified.kind != "op" or _expr_is_pure(simplified)
    return result


def _expr_is_pure(node: BV) -> bool:
    """An expression is 'pure' if it contains no nested ops of the same kind
    that would suggest a still-obfuscated form (rough heuristic for whether
    the local passes were sufficient)."""
    if node.kind != "op":
        return True
    # If there are MBA-suggesting nested patterns, mark impure.
    if node.op in ("add", "sub", "mul"):
        for a in node.args:
            if a.kind == "op" and a.op in ("and", "or"):
                return False
    return all(_expr_is_pure(a) for a in node.args)


# ---------------------------------------------------------------------------
# Stage 4 — emit an LLM-ready JSON request
# ---------------------------------------------------------------------------


def emit_llm_request(target: Target, block_addr: int,
                     lifted: SymbolicResult) -> dict[str, Any]:
    """Pack everything an LLM needs to propose a closed-form simplification."""
    return {
        "schema_version": 1,
        "target": target.name,
        "binary": target.binary,
        "func_addr": f"0x{target.func_addr:x}",
        "block_addr": f"0x{block_addr:x}",
        "inputs": [dataclasses.asdict(i) for i in target.inputs],
        "output": dataclasses.asdict(target.output),
        "test_vectors": [
            {"inputs": {k: f"0x{v:x}" for k, v in tv.inputs.items()},
             "output": f"0x{tv.output:x}",
             "source": tv.source}
            for tv in target.test_vectors
        ],
        "symbolic": {
            "inputs": lifted.symbolic_inputs,
            "statements": lifted.statements,
            "final_expr": lifted.final_expr,
            "simplified_expr": lifted.metadata.get("simplified",
                                                   lifted.final_expr),
            "fully_reduced_locally": bool(
                lifted.metadata.get("fully_reduced", False)),
            "register_map": lifted.register_map,
            "metadata": lifted.metadata,
        },
        "notes": target.notes,
        "task_prompt": (
            f"You are given a list of lifted IL statements from "
            f"{target.name} at {target.binary}:{hex(target.func_addr)}. "
            "Propose the simplest closed-form expression that matches ALL "
            "supplied test vectors.  If MBA obfuscation is suspected, apply "
            "the standard rewrites: x+y = (x^y)+2·(x&y), x|y = x+y-(x&y), "
            "etc.\n\n"
            "Respond with ONE fenced ```python``` code block containing a "
            "top-level function with this exact signature:\n\n"
            "    def simplified("
            + ", ".join(i.name for i in target.inputs)
            + ") -> int:\n"
            "        ...\n\n"
            "The function must return the output as a non-negative Python int "
            f"fitting in {target.output.width_bits} bits.  Do not include "
            "any other code blocks or explanations inside the fence."
        ),
    }


# ---------------------------------------------------------------------------
# Stage 5 — verify a proposed simplified expression
# ---------------------------------------------------------------------------


def _load_expression_module(path: Path) -> Any:
    """Import a user-supplied Python file exposing `simplified(**inputs)`."""
    spec = importlib.util.spec_from_file_location("proposed_expr", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    if not hasattr(mod, "simplified"):
        raise RuntimeError(
            f"{path} must define a top-level `simplified(**kwargs) -> int`"
        )
    return mod


def _popcount(x: int) -> int:
    return bin(x & ((1 << 64) - 1)).count("1")


@dataclass
class VerifyReport:
    target: str
    ground_truth_passed: int
    ground_truth_failed: int
    ground_truth_mismatches: list[dict[str, Any]]
    fuzz_runs: int
    fuzz_errors: int
    fuzz_out_of_range: int
    avalanche_ratio_mean: float | None
    avalanche_ratio_stdev: float | None
    distribution_bit_bias: list[float] | None  # per-output-bit P(bit=1)

    def as_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _avalanche_one_bit_flip(fn: Callable[..., int], sample: dict[str, int],
                            target: Target, rng: random.Random) -> int | None:
    """Flip a single random bit in one input and return new output."""
    flipped = dict(sample)
    # pick an input uniformly, then a bit in its declared width
    sym = rng.choice(target.inputs)
    bit = rng.randrange(sym.width_bits)
    flipped[sym.name] = flipped[sym.name] ^ (1 << bit)
    try:
        return int(fn(**flipped)) & ((1 << target.output.width_bits) - 1)
    except Exception:
        return None


def verify_expression(target: Target, expr_path: Path, fuzz_runs: int = 10000,
                      seed: int = 0xdeadbeef) -> VerifyReport:
    mod = _load_expression_module(expr_path)
    fn: Callable[..., int] = mod.simplified
    out_mask = (1 << target.output.width_bits) - 1

    # 1) Ground-truth pass
    gt_pass = 0
    gt_fail = 0
    mismatches: list[dict[str, Any]] = []
    for tv in target.test_vectors:
        try:
            got = int(fn(**tv.inputs)) & out_mask
        except Exception as e:
            got = None
        if got == tv.output:
            gt_pass += 1
        else:
            gt_fail += 1
            mismatches.append({
                "inputs": {k: f"0x{v:x}" for k, v in tv.inputs.items()},
                "expected": f"0x{tv.output:x}",
                "got": f"0x{got:x}" if isinstance(got, int) else str(got),
                "source": tv.source,
            })

    # 2) Property fuzz
    rng = random.Random(seed)
    errors = 0
    oor = 0
    outputs: list[int] = []
    avalanche_flips: list[int] = []  # bits changed after 1-bit input flip
    if target.fuzz_sample is not None and fuzz_runs > 0:
        for _ in range(fuzz_runs):
            sample = target.fuzz_sample(rng)
            try:
                out = fn(**sample)
            except Exception:
                errors += 1
                continue
            if not isinstance(out, int):
                errors += 1
                continue
            if out < 0 or out > out_mask:
                oor += 1
                out = out & out_mask
            outputs.append(out)
            flipped = _avalanche_one_bit_flip(fn, sample, target, rng)
            if flipped is not None:
                avalanche_flips.append(_popcount(out ^ flipped))

    # 3) Stats
    aval_mean = aval_stdev = None
    if avalanche_flips:
        n = len(avalanche_flips)
        width = target.output.width_bits
        aval_mean = sum(avalanche_flips) / (n * width)
        var = sum(((f / width) - aval_mean) ** 2 for f in avalanche_flips) / n
        aval_stdev = var ** 0.5
    bit_bias: list[float] | None = None
    if outputs:
        width = target.output.width_bits
        bit_counts = [0] * width
        for o in outputs:
            for b in range(width):
                if (o >> b) & 1:
                    bit_counts[b] += 1
        bit_bias = [c / len(outputs) for c in bit_counts]

    return VerifyReport(
        target=target.name,
        ground_truth_passed=gt_pass,
        ground_truth_failed=gt_fail,
        ground_truth_mismatches=mismatches,
        fuzz_runs=fuzz_runs if target.fuzz_sample is not None else 0,
        fuzz_errors=errors,
        fuzz_out_of_range=oor,
        avalanche_ratio_mean=aval_mean,
        avalanche_ratio_stdev=aval_stdev,
        distribution_bit_bias=bit_bias,
    )


# ---------------------------------------------------------------------------
# Stage 6 — send an emit_llm_request JSON to an LLM endpoint (stdlib only)
# ---------------------------------------------------------------------------
#
# Two providers are supported:
#
#   openrouter (default)  —  POST https://openrouter.ai/api/v1/chat/completions
#                            Authorization: Bearer $OPENROUTER_API_KEY
#                            Body: OpenAI-compatible chat.completions shape
#                            OPENROUTER_MODEL in .env pins the default model
#                            (currently google/gemini-2.5-flash; google/
#                            gemini-3.1-flash doesn't exist on OpenRouter —
#                            closest is google/gemini-3.1-flash-lite-preview)
#
#   gemini                —  POST generativelanguage.googleapis.com
#                            /v1beta/models/{model}:generateContent?key=…
#                            Body: Gemini-native {contents, generationConfig}
#
# Both providers return a canonical UsageMetadata + ExtractResult via
# provider-specific constructors / extractors.

GEMINI_ENDPOINT_TMPL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "{model}:generateContent?key={api_key}"
)
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

# Default model IDs per provider.
DEFAULT_GEMINI_MODEL = "gemini-2.0-flash-lite"
DEFAULT_OPENROUTER_MODEL = "google/gemini-2.5-flash"

# OpenRouter etiquette headers — identify the caller so rate limits can be
# tracked per-project.  Both are optional.
OPENROUTER_REFERER = "https://github.com/anthropics/aeon-ollvm-codex1"
OPENROUTER_TITLE = "cert-emu-deobf-pipeline"


def load_env_file(path: Path | str = "/home/sdancer/orchestrator/.env") -> dict[str, str]:
    """Parse a simple KEY="VALUE" .env file.

    Returns the parsed map (also merged into os.environ for any keys not
    already set).  No third-party dotenv dependency; a minimal hand-rolled
    parser is enough for the single-line assignments we use.
    """
    out: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        return out
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        # strip surrounding quotes (single or double)
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        out[k] = v
        os.environ.setdefault(k, v)
    return out


def _build_prompt_string(request_payload: dict[str, Any]) -> str:
    """Canonical prompt serialisation used by both providers."""
    return (
        request_payload.get("task_prompt", "") + "\n\n"
        "Payload:\n" + json.dumps(request_payload, indent=2)
    )


def send_to_gemini(request_payload: dict[str, Any], model: str,
                   api_key: str, timeout: float = 60.0) -> dict[str, Any]:
    """POST emit_llm_request's JSON to Gemini's generateContent endpoint."""
    body = {
        "contents": [{"parts": [{"text": _build_prompt_string(request_payload)}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096},
    }
    url = GEMINI_ENDPOINT_TMPL.format(model=model, api_key=api_key)
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def send_to_openrouter(request_payload: dict[str, Any], model: str,
                       api_key: str, timeout: float = 60.0,
                       referer: str = OPENROUTER_REFERER,
                       title: str = OPENROUTER_TITLE) -> dict[str, Any]:
    """POST emit_llm_request's JSON to OpenRouter's chat.completions endpoint.

    OpenRouter speaks the OpenAI chat.completions wire format:

        body = {"model": ..., "messages": [{"role":"user","content": ...}],
                "temperature": 0.2, "max_tokens": 4096}
        response["choices"][0]["message"]["content"]  # extracted text
        response["choices"][0]["finish_reason"]       # stop|length|
                                                      # content_filter|tool_calls
        response["usage"] = {"prompt_tokens", "completion_tokens",
                             "total_tokens"}
    """
    body = {
        "model": model,
        "messages": [{"role": "user",
                      "content": _build_prompt_string(request_payload)}],
        "temperature": 0.2,
        "max_tokens": 4096,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-Title"] = title
    req = urllib.request.Request(
        OPENROUTER_ENDPOINT,
        data=json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


@dataclass
class UsageMetadata:
    """Canonical token-accounting.  Zero if absent from the response."""
    prompt_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    @classmethod
    def from_gemini_response(cls, resp: dict[str, Any]) -> "UsageMetadata":
        um = resp.get("usageMetadata") or {}
        return cls(
            prompt_tokens=int(um.get("promptTokenCount", 0) or 0),
            output_tokens=int(um.get("candidatesTokenCount", 0) or 0),
            total_tokens=int(um.get("totalTokenCount", 0) or 0),
        )

    @classmethod
    def from_openrouter_response(cls, resp: dict[str, Any]) -> "UsageMetadata":
        um = resp.get("usage") or {}
        return cls(
            prompt_tokens=int(um.get("prompt_tokens", 0) or 0),
            output_tokens=int(um.get("completion_tokens", 0) or 0),
            total_tokens=int(um.get("total_tokens", 0) or 0),
        )

    def as_log_line(self) -> str:
        return (
            f"usage: prompt_tokens={self.prompt_tokens} "
            f"output_tokens={self.output_tokens} "
            f"total_tokens={self.total_tokens}"
        )


@dataclass
class ExtractResult:
    """Canonical outcome of parsing an LLM response (provider-agnostic).

    ``status`` is one of:
      - "ok"              — text extracted, normal completion
      - "truncated"       — hit output-token cap but text is usable
      - "safety_blocked"  — content filter (prompt or candidate)
      - "function_call"   — response is a tool/function-call, no text
      - "empty"           — no choices / no content
      - "error"           — malformed response / unexpected shape
    """
    status: str
    text: str
    finish_reason: str | None
    usage: UsageMetadata
    candidate_index: int | None = None
    raw_response: dict[str, Any] | None = None
    error_message: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


# -- Gemini-specific extractor ---------------------------------------------

# finishReason values considered partial-success (still have usable text)
_GEMINI_TERMINAL_WITH_TEXT = {"STOP", "MAX_TOKENS", None, ""}


def extract_text_result_gemini(resp: dict[str, Any]) -> ExtractResult:
    """Parse a Gemini generateContent response into an ExtractResult.

    Handles every Gemini-specific failure mode: prompt-level blockReason,
    candidate finishReason (SAFETY/MAX_TOKENS/RECITATION/OTHER), function-call
    responses, missing content / parts, malformed shapes.
    """
    usage = UsageMetadata.from_gemini_response(resp)

    pfb = resp.get("promptFeedback") or {}
    if pfb.get("blockReason"):
        return ExtractResult(
            status="safety_blocked",
            text="",
            finish_reason=f"prompt:{pfb.get('blockReason')}",
            usage=usage,
            raw_response=resp,
            error_message=f"prompt blocked: {pfb.get('blockReason')}",
        )

    candidates = resp.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return ExtractResult(
            status="empty",
            text="",
            finish_reason=None,
            usage=usage,
            raw_response=resp,
            error_message="no candidates in response",
        )

    cand = candidates[0]
    if not isinstance(cand, dict):
        return ExtractResult(
            status="error",
            text="",
            finish_reason=None,
            usage=usage,
            raw_response=resp,
            error_message="candidates[0] is not an object",
        )

    finish = cand.get("finishReason")
    content = cand.get("content") or {}
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list):
        parts = []

    text_pieces: list[str] = []
    has_function_call = False
    for p in parts:
        if not isinstance(p, dict):
            continue
        if "text" in p and isinstance(p["text"], str):
            text_pieces.append(p["text"])
        if "functionCall" in p:
            has_function_call = True
    text = "".join(text_pieces)

    if finish == "SAFETY":
        return ExtractResult(
            status="safety_blocked", text=text, finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message="candidate blocked by SAFETY",
        )
    if has_function_call and not text:
        return ExtractResult(
            status="function_call", text="", finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message="response is a function-call, no text part",
        )
    if not text:
        return ExtractResult(
            status="empty", text="", finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message="no text parts in candidate",
        )
    if finish == "MAX_TOKENS":
        return ExtractResult(
            status="truncated", text=text, finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message="response truncated at maxOutputTokens",
        )
    if finish not in _GEMINI_TERMINAL_WITH_TEXT:
        return ExtractResult(
            status="error", text=text, finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message=f"unexpected finishReason={finish}",
        )

    return ExtractResult(
        status="ok", text=text, finish_reason=finish,
        usage=usage, candidate_index=0, raw_response=resp,
    )


# -- OpenRouter / OpenAI-style extractor -----------------------------------

# OpenAI-style finish_reason values that imply partial-or-complete text.
_OPENAI_TERMINAL_WITH_TEXT = {"stop", "length", None, ""}


def extract_text_result_openrouter(resp: dict[str, Any]) -> ExtractResult:
    """Parse an OpenRouter (OpenAI chat.completions) response.

    OpenAI-style ``finish_reason`` values:
      - ``stop``           → ok
      - ``length``         → truncated (analogous to Gemini MAX_TOKENS)
      - ``content_filter`` → safety_blocked
      - ``tool_calls``     → function_call
      - ``function_call``  → function_call (deprecated name)
      - missing / null     → ok (most providers omit when completing)

    Also handles:
      - OpenRouter's top-level ``error`` object (rate limit / upstream fail)
      - empty/missing ``choices`` list
      - missing ``message`` / ``content``
      - ``message.tool_calls`` present without text (new-style function call)
    """
    usage = UsageMetadata.from_openrouter_response(resp)

    # OpenRouter surfaces upstream errors in a top-level "error" object rather
    # than relying purely on HTTP status codes.
    err = resp.get("error")
    if isinstance(err, dict) and err.get("message"):
        return ExtractResult(
            status="error",
            text="",
            finish_reason=None,
            usage=usage,
            raw_response=resp,
            error_message=f"upstream error: {err.get('message')}",
        )

    choices = resp.get("choices")
    if not isinstance(choices, list) or not choices:
        return ExtractResult(
            status="empty",
            text="",
            finish_reason=None,
            usage=usage,
            raw_response=resp,
            error_message="no choices in response",
        )

    choice = choices[0]
    if not isinstance(choice, dict):
        return ExtractResult(
            status="error",
            text="",
            finish_reason=None,
            usage=usage,
            raw_response=resp,
            error_message="choices[0] is not an object",
        )

    finish = choice.get("finish_reason")
    raw_message = choice.get("message")
    message = raw_message if isinstance(raw_message, dict) else {}
    content = message.get("content")
    text = ""
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        # Some providers return content as a list of parts.
        pieces = []
        for p in content:
            if isinstance(p, dict) and isinstance(p.get("text"), str):
                pieces.append(p["text"])
        text = "".join(pieces)

    has_tool_call = bool(message.get("tool_calls") or message.get("function_call"))

    if finish == "content_filter":
        return ExtractResult(
            status="safety_blocked", text=text, finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message="response blocked by content filter",
        )
    if finish in ("tool_calls", "function_call") or (has_tool_call and not text):
        return ExtractResult(
            status="function_call", text="", finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message="response is a tool/function-call, no text",
        )
    if not text:
        return ExtractResult(
            status="empty", text="", finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message="no text content in choice",
        )
    if finish == "length":
        return ExtractResult(
            status="truncated", text=text, finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message="response truncated at max_tokens",
        )
    if finish not in _OPENAI_TERMINAL_WITH_TEXT:
        return ExtractResult(
            status="error", text=text, finish_reason=finish,
            usage=usage, candidate_index=0, raw_response=resp,
            error_message=f"unexpected finish_reason={finish}",
        )

    return ExtractResult(
        status="ok", text=text, finish_reason=finish,
        usage=usage, candidate_index=0, raw_response=resp,
    )


# Legacy alias — callers may still invoke `extract_text_result` for Gemini.
extract_text_result = extract_text_result_gemini


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_list(_args) -> int:
    for name, t in TARGETS.items():
        print(f"{name:24s} {t.binary}:{hex(t.func_addr)}  "
              f"blocks={[hex(b) for b in t.block_addrs]}  "
              f"vectors={len(t.test_vectors)}")
    return 0


def _cmd_dry_run(args) -> int:
    if args.target not in TARGETS:
        print(f"unknown target: {args.target}", file=sys.stderr)
        return 2
    target = TARGETS[args.target]
    for block in target.block_addrs:
        il = pull_block_il(target, block, fixture_path=None)
        lifted = lift_to_symbolic(il, target)
        lifted = simplify_local(lifted)
        req = emit_llm_request(target, block, lifted)
        print(json.dumps(req, indent=2))
    return 0


def _cmd_emit(args) -> int:
    if args.target not in TARGETS:
        print(f"unknown target: {args.target}", file=sys.stderr)
        return 2
    target = TARGETS[args.target]
    fixture = Path(args.il_fixture) if args.il_fixture else None
    out = Path(args.out) if args.out else None
    payloads = []
    for block in target.block_addrs:
        il = pull_block_il(target, block, fixture_path=fixture)
        lifted = lift_to_symbolic(il, target)
        lifted = simplify_local(lifted)
        payloads.append(emit_llm_request(target, block, lifted))
    blob = payloads if len(payloads) > 1 else payloads[0]
    text = json.dumps(blob, indent=2)
    if out:
        out.write_text(text)
        print(f"wrote {out} ({len(text)} bytes)")
    else:
        print(text)
    return 0


def _cmd_verify(args) -> int:
    if args.target not in TARGETS:
        print(f"unknown target: {args.target}", file=sys.stderr)
        return 2
    target = TARGETS[args.target]
    report = verify_expression(target, Path(args.expr_file),
                               fuzz_runs=args.fuzz, seed=args.seed)
    if args.json:
        print(json.dumps(report.as_json(), indent=2))
    else:
        print(f"target          : {report.target}")
        print(f"ground truth    : {report.ground_truth_passed} passed / "
              f"{report.ground_truth_failed} failed "
              f"({len(target.test_vectors)} total)")
        for m in report.ground_truth_mismatches:
            print(f"  MISMATCH inputs={m['inputs']} "
                  f"expected={m['expected']} got={m['got']}")
        if report.fuzz_runs:
            print(f"fuzz runs       : {report.fuzz_runs}  "
                  f"errors={report.fuzz_errors}  "
                  f"oor={report.fuzz_out_of_range}")
            if report.avalanche_ratio_mean is not None:
                print(f"avalanche ratio : mean={report.avalanche_ratio_mean:.4f} "
                      f"stdev={report.avalanche_ratio_stdev:.4f} "
                      f"(crypto-grade is ~0.5)")
            if report.distribution_bit_bias is not None:
                bias_extreme = [
                    (i, p) for i, p in enumerate(report.distribution_bit_bias)
                    if p < 0.45 or p > 0.55
                ]
                print(f"bit bias        : "
                      f"{len(bias_extreme)} / {target.output.width_bits} bits "
                      f"outside [0.45, 0.55]")
        else:
            print("fuzz runs       : skipped (no fuzz_sample registered)")
    return 0 if report.ground_truth_failed == 0 else 1


def _cmd_send(args) -> int:
    # Auto-load the orchestrator .env so OPENROUTER_API_KEY / OPENROUTER_MODEL
    # are available without the caller having to source it manually.
    load_env_file()

    # Resolve provider-specific defaults if --model wasn't explicitly set.
    provider = args.provider
    model = args.model
    if not model:
        if provider == "openrouter":
            model = os.environ.get("OPENROUTER_MODEL") or DEFAULT_OPENROUTER_MODEL
        else:
            model = os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL

    # Resolve env var holding the key based on provider, unless overridden.
    key_env = args.api_key_env
    if not key_env:
        key_env = ("OPENROUTER_API_KEY" if provider == "openrouter"
                   else "GEMINI_API_KEY")

    api_key = os.environ.get(key_env)
    if not api_key:
        print(f"missing env var {key_env} (provider={provider})", file=sys.stderr)
        return 2

    payload = json.loads(Path(args.request_file).read_text())
    try:
        if provider == "openrouter":
            resp = send_to_openrouter(payload, model, api_key)
        else:
            resp = send_to_gemini(payload, model, api_key)
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode(errors='replace')}",
              file=sys.stderr)
        return 1

    if provider == "openrouter":
        result = extract_text_result_openrouter(resp)
    else:
        result = extract_text_result_gemini(resp)
    # Always log usage to stderr unless caller explicitly silenced it.
    if args.emit_usage:
        print(result.usage.as_log_line(), file=sys.stderr)

    if not result.ok:
        # Dump the diagnostic to stderr AND (if available) the raw response
        # so downstream callers can recover.
        print(f"send: status={result.status} finish_reason={result.finish_reason} "
              f"error={result.error_message}", file=sys.stderr)
        if args.out and result.raw_response is not None:
            Path(args.out).write_text(json.dumps(result.raw_response, indent=2))
            print(f"wrote raw response to {args.out}", file=sys.stderr)
        elif result.raw_response is not None:
            print(json.dumps(result.raw_response, indent=2), file=sys.stderr)
        if result.status == "truncated":
            # Truncated responses still carry usable text; print it and exit 0.
            if args.print_text:
                print(result.text)
            return 0
        return 1

    if args.print_text:
        print(result.text)
    else:
        out = json.dumps(resp, indent=2)
        if args.out:
            Path(args.out).write_text(out)
            print(f"wrote {args.out} ({len(out)} bytes)")
        else:
            print(out)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="deobf_pipeline",
                                description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list", help="list registered targets")
    sp.set_defaults(fn=_cmd_list)

    sp = sub.add_parser("dry-run", help="run pipeline with an empty IL block")
    sp.add_argument("target")
    sp.set_defaults(fn=_cmd_dry_run)

    sp = sub.add_parser("emit", help="emit an LLM JSON request")
    sp.add_argument("target")
    sp.add_argument("--il-fixture", help="path to an aeon IL JSON fixture")
    sp.add_argument("--out", help="write JSON request to this path")
    sp.set_defaults(fn=_cmd_emit)

    sp = sub.add_parser("verify",
        help="check a proposed simplified expression against ground truth + fuzz")
    sp.add_argument("target")
    sp.add_argument("expr_file",
        help="Python file exposing simplified(**kwargs) -> int")
    sp.add_argument("--fuzz", type=int, default=10_000,
        help="number of random-input property-fuzz iterations (default 10000)")
    sp.add_argument("--seed", type=lambda s: int(s, 0), default=0xdeadbeef,
        help="PRNG seed for reproducible fuzzing")
    sp.add_argument("--json", action="store_true",
        help="emit the report as JSON")
    sp.set_defaults(fn=_cmd_verify)

    sp = sub.add_parser("send",
        help="POST an emit_llm_request JSON to an LLM endpoint")
    sp.add_argument("request_file", help="path to emit's JSON output")
    sp.add_argument("--provider", choices=("openrouter", "gemini"),
        default="openrouter",
        help="LLM provider (default openrouter; reads /home/sdancer/"
             "orchestrator/.env for OPENROUTER_API_KEY + OPENROUTER_MODEL)")
    sp.add_argument("--model", default=None,
        help="model ID — default is $OPENROUTER_MODEL for openrouter "
             f"(fallback {DEFAULT_OPENROUTER_MODEL}) or {DEFAULT_GEMINI_MODEL} "
             "for gemini")
    sp.add_argument("--api-key-env", default=None,
        help="env var holding the API key (default OPENROUTER_API_KEY "
             "for openrouter, GEMINI_API_KEY for gemini)")
    sp.add_argument("--out", help="write response JSON to this path")
    sp.add_argument("--print-text", action="store_true",
        help="print only the first candidate's text")
    sp.add_argument("--emit-usage", action=argparse.BooleanOptionalAction,
        default=True, help="log usageMetadata (tokens) to stderr")
    sp.set_defaults(fn=_cmd_send)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
