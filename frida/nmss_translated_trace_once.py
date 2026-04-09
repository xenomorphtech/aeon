#!/usr/bin/env python3
"""Run one short-lived translated JIT trace around a safe NmssSa cert flow.

This avoids the unstable long-lived Frida server/session model by:
1. ensuring the app is running
2. pushing the translated ELF + map to the device
3. attaching once
4. verifying a plain non-empty token with the documented readiness flow
5. arming translated tracing
6. running one traced `onResume() -> run() -> getCertValue()` cycle
7. dumping coverage and detaching immediately
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

import frida  # type: ignore


PACKAGE = "com.netmarble.thered"
ADB_SERIAL = "localhost:5556"
FRIDA_REMOTE = "127.0.0.1:27042"
READY_CHALLENGE = "6BA4D60738580083"

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
CAPTURE_MANUAL = REPO_ROOT / "capture" / "manual"
BOOTSTRAP_JS = HERE / "jit_direct_bootstrap.js"
GATE_JS = HERE / "jit_trace_gate.js"
LOCAL_TRANSLATED_ELF = CAPTURE_MANUAL / "jit_exec_alias_0x9b5fe000.translated.elf"
LOCAL_TRANSLATED_MAP = CAPTURE_MANUAL / "jit_exec_alias_0x9b5fe000.translated.map.json.compact.blockmap.jsonl"
DEVICE_BOOTSTRAP_JS = "/data/local/tmp/jit_direct_bootstrap.js"
DEVICE_GATE_JS = "/data/local/tmp/jit_trace_gate.js"
DEVICE_TRANSLATED_ELF = "/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.elf"
DEVICE_TRANSLATED_MAP = "/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.map.json.compact.blockmap.jsonl"


def run(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        capture_output=capture,
        text=text,
    )


def adb_cmd(*rest: str) -> list[str]:
    return ["adb", "-s", ADB_SERIAL, *rest]


def adb_shell(cmd: str, *, check: bool = True) -> str:
    proc = run(adb_cmd("shell", cmd), check=check)
    return proc.stdout.strip()


def ensure_local_file(path: pathlib.Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing file: {path}")


def ensure_device_artifact(local_path: pathlib.Path, device_path: str) -> None:
    run(adb_cmd("push", str(local_path), device_path))
    adb_shell(f"chmod 0644 {device_path}", check=False)


def current_pid() -> int | None:
    out = adb_shell(f"pidof {PACKAGE}", check=False).strip()
    if not out:
        return None
    try:
        return int(out.split()[0])
    except ValueError:
        return None


def launch_app() -> None:
    run(
        adb_cmd(
            "shell",
            "monkey",
            "-p",
            PACKAGE,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ),
        check=False,
    )


def ensure_running(timeout_s: float) -> int:
    pid = current_pid()
    if pid is not None:
        return pid
    launch_app()
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        pid = current_pid()
        if pid is not None:
            return pid
        time.sleep(0.5)
    raise RuntimeError(f"{PACKAGE} did not start within {timeout_s:.1f}s")


def build_loader_source() -> str:
    return f"""'use strict';
(function () {{
    function readTextFile(path) {{
        var libc = Process.getModuleByName('libc.so');
        var openPtr = libc.getExportByName('open');
        var readPtr = libc.getExportByName('read');
        var closePtr = libc.getExportByName('close');
        var openFn = new NativeFunction(openPtr, 'int', ['pointer', 'int', 'int']);
        var readFn = new NativeFunction(readPtr, 'int', ['int', 'pointer', 'int']);
        var closeFn = new NativeFunction(closePtr, 'int', ['int']);
        var fd = openFn(Memory.allocUtf8String(path), 0, 0);
        if (fd < 0) return null;
        var chunkSize = 0x4000;
        var chunks = [];
        try {{
            while (true) {{
                var buf = Memory.alloc(chunkSize);
                var n = readFn(fd, buf, chunkSize);
                if (n <= 0) break;
                chunks.push(buf.readUtf8String(n) || '');
                if (n < chunkSize) break;
            }}
        }} finally {{
            closeFn(fd);
        }}
        return chunks.join('');
    }}

    function loadOne(path) {{
        var source = readTextFile(path);
        if (source === null) throw new Error('failed to read agent source: ' + path);
        (0, eval)(source);
    }}

    loadOne({DEVICE_BOOTSTRAP_JS!r});
    loadOne({DEVICE_GATE_JS!r});
}})();
"""


def parse_json_maybe(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def summarize_token(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not token:
        return None
    return token


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", default=READY_CHALLENGE, help="target cert challenge")
    parser.add_argument("--ready-challenge", default=READY_CHALLENGE, help="readiness challenge for run()")
    parser.add_argument("--max-steps", type=int, default=200000, help="translated max steps")
    parser.add_argument("--max-events", type=int, default=4096, help="ring events to dump")
    parser.add_argument("--max-counters", type=int, default=0, help="counter entries to dump (0 = all)")
    parser.add_argument("--min-pc", default=None, help="optional translated min PC hex filter")
    parser.add_argument("--startup-timeout", type=float, default=20.0, help="seconds to wait for app startup")
    parser.add_argument("--java-timeout", type=float, default=15.0, help="seconds to wait for Frida Java bridge")
    parser.add_argument("--output", default=None, help="path for JSON result")
    return parser


def default_output_path() -> pathlib.Path:
    ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    return CAPTURE_MANUAL / f"nmss_translated_trace_once_{ts}.json"


def main() -> int:
    args = build_parser().parse_args()
    ensure_local_file(LOCAL_TRANSLATED_ELF)
    ensure_local_file(LOCAL_TRANSLATED_MAP)
    ensure_local_file(BOOTSTRAP_JS)
    ensure_local_file(GATE_JS)
    output_path = pathlib.Path(args.output) if args.output else default_output_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    ensure_device_artifact(BOOTSTRAP_JS, DEVICE_BOOTSTRAP_JS)
    ensure_device_artifact(GATE_JS, DEVICE_GATE_JS)
    ensure_device_artifact(LOCAL_TRANSLATED_ELF, DEVICE_TRANSLATED_ELF)
    ensure_device_artifact(LOCAL_TRANSLATED_MAP, DEVICE_TRANSLATED_MAP)

    pid = ensure_running(args.startup_timeout)
    device = frida.get_device_manager().add_remote_device(FRIDA_REMOTE)
    session = None
    script = None
    messages: list[dict[str, Any]] = []

    def on_message(message: dict[str, Any], data: bytes | None) -> None:
        entry: dict[str, Any] = {
            "message": message,
            "has_data": data is not None,
        }
        if data is not None:
            entry["data_size"] = len(data)
        messages.append(entry)
        mtype = message.get("type")
        if mtype == "error":
            desc = message.get("description") or "<error>"
            print(f"[frida-error] {desc}", file=sys.stderr)
        elif mtype == "send":
            print(f"[frida-send] {message.get('payload')}", flush=True)

    result: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "package": PACKAGE,
        "pid": pid,
        "challenge": args.challenge,
        "ready_challenge": args.ready_challenge,
        "frida_remote": FRIDA_REMOTE,
        "device_translated_elf": DEVICE_TRANSLATED_ELF,
        "device_translated_map": DEVICE_TRANSLATED_MAP,
        "messages": messages,
    }
    current_stage = "attach"

    def set_stage(stage: str) -> None:
        nonlocal current_stage
        current_stage = stage
        result["stage"] = stage
        print(f"[stage] {stage}", file=sys.stderr, flush=True)

    try:
        set_stage("attach")
        session = device.attach(pid)
        set_stage("create_script")
        script = session.create_script(build_loader_source())
        script.on("message", on_message)
        set_stage("load_script")
        script.load()

        exports = script.exports_sync

        preflight: Any = None
        java_deadline = time.time() + args.java_timeout
        set_stage("preflight")
        while True:
            preflight = parse_json_maybe(
                exports.jit_gate_prepare_nmss(args.ready_challenge, args.ready_challenge)
            )
            if not (
                isinstance(preflight, dict)
                and preflight.get("error") in {"java_undefined", "java_unavailable"}
            ):
                break
            if time.time() >= java_deadline:
                break
            time.sleep(0.5)
        result["preflight"] = preflight
        preflight_token = summarize_token(preflight.get("token") if isinstance(preflight, dict) else None)
        preflight_thread_id = None
        if isinstance(preflight, dict):
            try:
                tid = preflight.get("thread_id")
                if tid is not None:
                    parsed_tid = int(tid)
                    if parsed_tid > 0:
                        preflight_thread_id = parsed_tid
            except (TypeError, ValueError):
                preflight_thread_id = None
        if not (isinstance(preflight, dict) and preflight.get("ok") and preflight_token):
            result["status"] = "preflight_failed"
            output_path.write_text(json.dumps(result, indent=2))
            print(json.dumps({
                "status": "preflight_failed",
                "output": str(output_path),
                "preflight": preflight,
            }, indent=2))
            return 2

        set_stage("translated_arm")
        arm = parse_json_maybe(
            exports.jit_gate_translated_arm(
                DEVICE_TRANSLATED_ELF,
                DEVICE_TRANSLATED_MAP,
                args.min_pc,
                args.max_steps,
            )
        )
        result["arm"] = arm

        set_stage("scope_begin")
        scope_begin = parse_json_maybe(
            exports.jit_gate_translated_scope_begin(args.challenge, preflight_thread_id)
        )
        result["scope_begin"] = scope_begin

        set_stage("traced_call")
        traced = parse_json_maybe(
            exports.jit_gate_prepare_nmss(args.challenge, args.ready_challenge)
        )
        result["traced_call"] = traced

        set_stage("scope_end")
        scope_end = parse_json_maybe(exports.jit_gate_translated_scope_end())
        result["scope_end"] = scope_end

        set_stage("trace_dump")
        trace_dump = parse_json_maybe(
            exports.jit_gate_translated_trace_dump(
                args.max_counters,
                args.max_events,
                True,
            )
        )
        result["trace_dump"] = trace_dump

        set_stage("translated_status")
        status = parse_json_maybe(exports.jit_gate_translated_status())
        result["translated_status"] = status
        result["status"] = "ok"

        try:
            set_stage("translated_clear")
            result["translated_clear"] = parse_json_maybe(exports.jit_gate_translated_clear())
        except Exception as exc:  # noqa: BLE001
            result["translated_clear_error"] = str(exc)
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = str(exc)
        result["stage"] = current_stage
        output_path.write_text(json.dumps(result, indent=2))
        print(json.dumps({
            "status": "error",
            "stage": current_stage,
            "error": str(exc),
            "output": str(output_path),
        }, indent=2), file=sys.stderr)
        return 1
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:  # noqa: BLE001
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:  # noqa: BLE001
                pass

    output_path.write_text(json.dumps(result, indent=2))

    trace_dump = result.get("trace_dump") if isinstance(result, dict) else None
    if not isinstance(trace_dump, dict):
        trace_dump = {}
    top_blocks = trace_dump.get("top_blocks") if isinstance(trace_dump.get("top_blocks"), list) else []
    events = trace_dump.get("events") if isinstance(trace_dump.get("events"), list) else []
    traced_call = result.get("traced_call") if isinstance(result.get("traced_call"), dict) else {}

    summary = {
        "status": result.get("status"),
        "output": str(output_path),
        "preflight_token": preflight_token,
        "preflight_thread_id": preflight_thread_id,
        "traced_token": traced_call.get("token"),
        "total_hits": trace_dump.get("total_hits"),
        "hit_blocks": trace_dump.get("hit_blocks"),
        "event_count": len(events),
        "top_blocks": top_blocks[:16],
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
