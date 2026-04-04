#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mock MCP server for tool-routing evals.")
    parser.add_argument("--tools-json", required=True, help="Path to JSON file with a top-level tools array.")
    parser.add_argument("--log-file", required=True, help="Path to JSONL log file for tool calls.")
    return parser.parse_args()


def write_response(response: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def make_initialize_result() -> dict[str, Any]:
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "aeon-eval", "version": "0.1.0"},
    }


def append_log(log_path: Path, payload: dict[str, Any]) -> None:
    payload = dict(payload)
    payload["timestamp"] = time.time()
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


def tool_result(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    body = {
        "ok": True,
        "tool": name,
        "arguments": arguments,
        "note": "Dry-run eval result. Tool output is a placeholder; stop after selecting tools.",
    }
    return {
        "content": [{"type": "text", "text": json.dumps(body)}],
        "isError": False,
    }


def main() -> int:
    args = parse_args()
    tools_path = Path(args.tools_json)
    log_path = Path(args.log_file)

    payload = json.loads(tools_path.read_text(encoding="utf-8"))
    tools = payload["tools"] if isinstance(payload, dict) else payload

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            write_response(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
            )
            continue

        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        if method == "initialize":
            result = make_initialize_result()
        elif method == "tools/list":
            result = {"tools": tools}
        elif method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments") or {}
            append_log(
                log_path,
                {
                    "method": method,
                    "name": name,
                    "arguments": arguments,
                },
            )
            result = tool_result(name, arguments)
        else:
            write_response(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            )
            continue

        write_response({"jsonrpc": "2.0", "id": request_id, "result": result})

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
