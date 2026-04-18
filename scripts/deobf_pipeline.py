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
    POST https://generativelanguage.googleapis.com/v1beta/models/
         gemini-2.0-flash-lite:generateContent?key=$GEMINI_API_KEY

    Request body (application/json):
        {"contents":[{"parts":[{"text": <PROMPT_STRING>}]}],
         "generationConfig":{"temperature":0.2,"maxOutputTokens":4096}}

    Response body:
        {"candidates":[{"content":{"parts":[{"text": <REPLY>}]}}]}

    The `send` subcommand implements exactly this via stdlib urllib — no
    third-party SDK required.  No `llm-pkg`, `google-generativeai`, or
    `google-genai` package is installed anywhere in /home/sdancer (only
    `llm-viewer-server`, which is an unrelated relay).
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


def lift_to_symbolic(il_block: dict[str, Any], target: Target) -> SymbolicResult:
    """Produce a symbolic-IR representation of a lifted block.

    The lifter is written as a pure-Python state machine so it runs without
    claripy.  When claripy is available, `final_expr` is the claripy
    `.__repr__()` of the deepest residual expression, otherwise it is a
    compact prefix-notation string.

    The lifter recognises the narrow subset of aeon IL ops we expect in the
    NMSS corridor:

        copy | load | store | add | sub | mul | and | or  | xor |
        shl  | shr  | rotl  | rotr | neg | not | ite | eq  | ult |
        sext | zext | trunc | phi | call | ret

    Anything else is emitted verbatim; the LLM request carries the raw
    instruction so the external simplifier can reason about it textually.
    """
    claripy = _try_import_claripy()
    sym_inputs: list[dict[str, Any]] = [
        {"name": i.name, "width_bits": i.width_bits} for i in target.inputs
    ]
    statements: list[dict[str, Any]] = []
    register_map: dict[str, str] = {}

    # Seed SSA env with the declared target inputs (they're callee-ABI regs).
    env: dict[str, Any] = {}
    if claripy is not None:
        for i in target.inputs:
            env[i.name] = claripy.BVS(i.name, i.width_bits)

    for instr in il_block.get("instructions", []):
        il = instr.get("il", "")
        addr = instr.get("addr", "?")
        statements.append({"addr": addr, "il": il})
        # Placeholder: a real lifter parses `il` into op/dst/args and updates
        # env + statements with structured entries.  The skeleton keeps the
        # raw IL string so stage 4 can still emit a useful payload.

    if claripy is not None and env:
        final = next(iter(env.values()))
        final_repr = repr(final)
    else:
        final_repr = "(no claripy — raw IL preserved in `statements`)"

    return SymbolicResult(
        symbolic_inputs=sym_inputs,
        statements=statements,
        final_expr=final_repr,
        register_map=register_map,
        metadata={"used_claripy": claripy is not None,
                  "instruction_count": len(statements)},
    )


# ---------------------------------------------------------------------------
# Stage 3 — cheap local simplification
# ---------------------------------------------------------------------------


def simplify_local(result: SymbolicResult) -> SymbolicResult:
    """Apply cheap, purely-local rewrites.

    When claripy is present, we call `.simplify()` on the final expression.
    Otherwise we return the result unchanged — the LLM stage will handle
    heavy lifting.  Future: add target-agnostic MBA-reduction passes here
    (e.g. replace `x + y - (x ^ y)` with `2·(x & y)`).
    """
    claripy = _try_import_claripy()
    if claripy is not None:
        try:
            import claripy as _c  # noqa: F401  (reserved for real lift)
            # result.final_expr is a string repr here; a real impl would
            # carry the live claripy BV and call .simplify() on it.
        except Exception:
            pass
    return result


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
            "etc.  Return the final expression in SMT-LIB or Python syntax."
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
# Stage 6 — send an emit_llm_request JSON to a Gemini endpoint (stdlib only)
# ---------------------------------------------------------------------------

GEMINI_ENDPOINT_TMPL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "{model}:generateContent?key={api_key}"
)


def send_to_gemini(request_payload: dict[str, Any], model: str,
                   api_key: str, timeout: float = 60.0) -> dict[str, Any]:
    """POST emit_llm_request's JSON to Gemini and return the parsed response.

    Uses only stdlib urllib — no third-party SDK needed.  The request payload
    (as produced by `emit_llm_request`) is serialised into a single prompt
    `text` part.  Use `extract_text_result` on the return value to get a
    structured (status, text) pair that handles SAFETY / MAX_TOKENS / missing
    parts correctly.
    """
    prompt = (
        request_payload.get("task_prompt", "") + "\n\n"
        "Payload:\n" + json.dumps(request_payload, indent=2)
    )
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
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


@dataclass
class UsageMetadata:
    """Gemini's token-accounting fields.  Zero if absent from the response."""
    prompt_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    @classmethod
    def from_response(cls, resp: dict[str, Any]) -> "UsageMetadata":
        um = resp.get("usageMetadata") or {}
        return cls(
            prompt_tokens=int(um.get("promptTokenCount", 0) or 0),
            output_tokens=int(um.get("candidatesTokenCount", 0) or 0),
            total_tokens=int(um.get("totalTokenCount", 0) or 0),
        )

    def as_log_line(self) -> str:
        return (
            f"usage: prompt_tokens={self.prompt_tokens} "
            f"output_tokens={self.output_tokens} "
            f"total_tokens={self.total_tokens}"
        )


@dataclass
class ExtractResult:
    """Structured outcome of parsing a Gemini generateContent response.

    ``status`` is one of:
      - "ok"              — text extracted; finishReason STOP or unspecified
      - "truncated"       — finishReason MAX_TOKENS; text present but partial
      - "safety_blocked"  — finishReason SAFETY (prompt or candidate blocked)
      - "function_call"   — candidate is a function-call, no text part
      - "empty"           — no candidates or no parts at all
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


# finishReason values considered partial-success (still have usable text)
_TERMINAL_WITH_TEXT = {"STOP", "MAX_TOKENS", None, ""}


def extract_text_result(resp: dict[str, Any]) -> ExtractResult:
    """Parse a Gemini generateContent response into a structured result.

    Handles every failure mode observed in the Gemini v1beta API:
      - prompt-level safety block (``promptFeedback.blockReason`` set)
      - candidate-level safety block (``finishReason == "SAFETY"``)
      - MAX_TOKENS truncation (still returns the partial text)
      - function-call responses (``parts[*].functionCall`` without text)
      - empty response / missing candidates / missing content / missing parts
      - unexpected top-level shapes
    """
    usage = UsageMetadata.from_response(resp)

    # Prompt-level block — the model refused the whole prompt.
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
            status="safety_blocked",
            text=text,
            finish_reason=finish,
            usage=usage,
            candidate_index=0,
            raw_response=resp,
            error_message="candidate blocked by SAFETY",
        )
    if has_function_call and not text:
        return ExtractResult(
            status="function_call",
            text="",
            finish_reason=finish,
            usage=usage,
            candidate_index=0,
            raw_response=resp,
            error_message="response is a function-call, no text part",
        )
    if not text:
        return ExtractResult(
            status="empty",
            text="",
            finish_reason=finish,
            usage=usage,
            candidate_index=0,
            raw_response=resp,
            error_message="no text parts in candidate",
        )
    if finish == "MAX_TOKENS":
        return ExtractResult(
            status="truncated",
            text=text,
            finish_reason=finish,
            usage=usage,
            candidate_index=0,
            raw_response=resp,
            error_message="response truncated at maxOutputTokens",
        )
    if finish not in _TERMINAL_WITH_TEXT:
        # RECITATION, OTHER, LANGUAGE, etc. — surface verbatim as error.
        return ExtractResult(
            status="error",
            text=text,
            finish_reason=finish,
            usage=usage,
            candidate_index=0,
            raw_response=resp,
            error_message=f"unexpected finishReason={finish}",
        )

    return ExtractResult(
        status="ok",
        text=text,
        finish_reason=finish,
        usage=usage,
        candidate_index=0,
        raw_response=resp,
    )


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
    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        print(f"missing env var {args.api_key_env}", file=sys.stderr)
        return 2
    payload = json.loads(Path(args.request_file).read_text())
    try:
        resp = send_to_gemini(payload, args.model, api_key)
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode(errors='replace')}",
              file=sys.stderr)
        return 1

    result = extract_text_result(resp)
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
        help="POST an emit_llm_request JSON to Gemini generateContent")
    sp.add_argument("request_file", help="path to emit's JSON output")
    sp.add_argument("--model", default="gemini-2.0-flash-lite",
        help="Gemini model ID (default gemini-2.0-flash-lite)")
    sp.add_argument("--api-key-env", default="GEMINI_API_KEY",
        help="env var holding the API key (default GEMINI_API_KEY)")
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
