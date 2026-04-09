#!/usr/bin/env python3

import argparse
import dataclasses
import json
import re
import sys
from collections import OrderedDict


CHALLENGE_RE = re.compile(r"^Challenge ([0-9A-Fa-f]+):$")
CERT_RE = re.compile(r"^CERT ([0-9A-Fa-f]+) = ([0-9A-Fa-f]+)$")
S1_RE = re.compile(r"^S1_ARGS x25=(0x[0-9A-Fa-f]+) vals=([0-9A-Fa-f]+)$")
JIT_RE = re.compile(r"^- JIT=([0-9A-Fa-f]+) base=(0x[0-9A-Fa-f]+) size=(0x[0-9A-Fa-f]+)$")
HOOK_RE = re.compile(r"^- S1 hook installed at (0x[0-9A-Fa-f]+)$")


@dataclasses.dataclass
class S1Call:
    slot: str
    payload_hex: str

    @property
    def payload(self) -> bytes:
        return bytes.fromhex(self.payload_hex)


@dataclasses.dataclass
class Scenario:
    label: str
    s1_calls: list[S1Call] = dataclasses.field(default_factory=list)
    cert: str | None = None


@dataclasses.dataclass
class TraceDoc:
    jit_id: str | None = None
    jit_base: str | None = None
    jit_size: str | None = None
    s1_hook: str | None = None
    scenarios: "OrderedDict[str, Scenario]" = dataclasses.field(
        default_factory=OrderedDict
    )

    def get_or_create(self, label: str) -> Scenario:
        if label not in self.scenarios:
            self.scenarios[label] = Scenario(label=label)
        return self.scenarios[label]


def parse_trace(text: str) -> TraceDoc:
    doc = TraceDoc()
    current = doc.get_or_create("init")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line in {"```", "```text"}:
            continue
        normalized = line.replace("`", "")

        if line.startswith("S1_ARGS during init"):
            current = doc.get_or_create("init")
            continue

        match = JIT_RE.match(normalized)
        if match:
            doc.jit_id, doc.jit_base, doc.jit_size = match.groups()
            continue

        match = HOOK_RE.match(normalized)
        if match:
            doc.s1_hook = match.group(1)
            continue

        match = CHALLENGE_RE.match(normalized)
        if match:
            current = doc.get_or_create(match.group(1).upper())
            continue

        match = S1_RE.match(normalized)
        if match:
            slot, payload = match.groups()
            current.s1_calls.append(S1Call(slot=slot.lower(), payload_hex=payload.upper()))
            continue

        match = CERT_RE.match(normalized)
        if match:
            challenge, cert = match.groups()
            doc.get_or_create(challenge.upper()).cert = cert.upper()
            continue

    return doc


def changed_offsets(payloads: list[bytes]) -> list[int]:
    if not payloads:
        return []
    width = len(payloads[0])
    offsets: list[int] = []
    for offset in range(width):
        column = {payload[offset] for payload in payloads}
        if len(column) > 1:
            offsets.append(offset)
    return offsets


def contiguous_ranges(offsets: list[int]) -> list[tuple[int, int]]:
    if not offsets:
        return []
    ranges: list[tuple[int, int]] = []
    start = prev = offsets[0]
    for offset in offsets[1:]:
        if offset == prev + 1:
            prev = offset
            continue
        ranges.append((start, prev + 1))
        start = prev = offset
    ranges.append((start, prev + 1))
    return ranges


def word_deltas(payloads: list[bytes]) -> list[int]:
    if not payloads or len(payloads[0]) % 4 != 0:
        return []
    words = len(payloads[0]) // 4
    changed: list[int] = []
    for word_index in range(words):
        start = word_index * 4
        word_values = {payload[start : start + 4] for payload in payloads}
        if len(word_values) > 1:
            changed.append(word_index)
    return changed


def build_report(doc: TraceDoc) -> dict:
    scenarios = list(doc.scenarios.values())
    call_count = max((len(s.s1_calls) for s in scenarios), default=0)
    calls: list[dict] = []
    for call_index in range(call_count):
        per_scenario = []
        payloads: list[bytes] = []
        for scenario in scenarios:
            if call_index >= len(scenario.s1_calls):
                continue
            call = scenario.s1_calls[call_index]
            payloads.append(call.payload)
            per_scenario.append(
                {
                    "scenario": scenario.label,
                    "slot": call.slot,
                    "payload_hex": call.payload_hex,
                }
            )
        offsets = changed_offsets(payloads)
        ranges = contiguous_ranges(offsets)
        words = word_deltas(payloads)
        call_report = {
            "call_index": call_index,
            "payload_size": len(payloads[0]) if payloads else 0,
            "changed_offsets": offsets,
            "changed_ranges": [{"start": start, "end": end} for start, end in ranges],
            "changed_words": words,
            "scenarios": per_scenario,
        }
        calls.append(call_report)

    return {
        "jit": {
            "id": doc.jit_id,
            "base": doc.jit_base,
            "size": doc.jit_size,
            "s1_hook": doc.s1_hook,
        },
        "scenarios": [
            {
                "label": scenario.label,
                "call_count": len(scenario.s1_calls),
                "cert": scenario.cert,
            }
            for scenario in scenarios
        ],
        "calls": calls,
    }


def format_report(report: dict) -> str:
    lines: list[str] = []
    jit = report["jit"]
    if jit["id"]:
        lines.append(
            f"JIT {jit['id']} base={jit['base']} size={jit['size']} s1_hook={jit['s1_hook']}"
        )
        lines.append("")

    lines.append("Scenarios:")
    for scenario in report["scenarios"]:
        cert = scenario["cert"] or "-"
        lines.append(
            f"  {scenario['label']}: s1_calls={scenario['call_count']} cert={cert}"
        )
    lines.append("")

    lines.append("Per-call comparison:")
    for call in report["calls"]:
        lines.append(
            f"  call[{call['call_index']}] payload_size={call['payload_size']} bytes"
        )
        scenario_slots = sorted({entry["slot"] for entry in call["scenarios"]})
        lines.append(f"    slots={', '.join(scenario_slots)}")
        if call["changed_offsets"]:
            offsets = ", ".join(str(offset) for offset in call["changed_offsets"])
            ranges = ", ".join(
                f"[{entry['start']}:{entry['end']})" for entry in call["changed_ranges"]
            )
            words = ", ".join(str(word) for word in call["changed_words"]) or "-"
            lines.append(f"    changed_offsets={offsets}")
            lines.append(f"    changed_ranges={ranges}")
            lines.append(f"    changed_words={words}")
        else:
            lines.append("    changed_offsets=none")
        for entry in call["scenarios"]:
            lines.append(
                f"    {entry['scenario']}: slot={entry['slot']} payload={entry['payload_hex']}"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def read_inputs(paths: list[str]) -> str:
    if not paths:
        return sys.stdin.read()
    parts = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            parts.append(handle.read())
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse S1_ARGS traces and report which payload bytes vary by challenge."
    )
    parser.add_argument("paths", nargs="*", help="Input files. Reads stdin if omitted.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    doc = parse_trace(read_inputs(args.paths))
    report = build_report(doc)
    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=False)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
