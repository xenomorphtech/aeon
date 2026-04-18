#!/usr/bin/env python3
"""Run repeatable all-thread corridor harvests and store per-run artifacts.

This codifies the current production recipe:
- full-window dynamic arm
- trace_all_threads=1
- long /call timeout
- per-run artifact directories under nmss_trace_runs/
- bounded adb pull timeouts so one bad pull does not wedge the batch
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


REPO = Path("/home/sdancer/aeon")
DEFAULT_CHALLENGES = [
    "AABBCCDDEEFF0011",
    "0011223344556677",
    "1122334455667788",
    "89ABCDEF01234567",
    "DEADBEEFCAFEBABE",
]
DEVICE_RUNTIME_LOG = "/data/user/0/com.netmarble.thered/files/aeon_dyn_runtime.log"
DEVICE_TRACE_JSONL = "/data/user/0/com.netmarble.thered/files/aeon_dyn_trace.jsonl"
DEVICE_RUNTIME_LIB = "/data/local/tmp/libaeon_instrument.so"
DEVICE_GATE_TRACE_LOG = "/data/local/tmp/aeon_capture/aeon_trace.log"
TRANSLATED_DEVICE_ELF = "/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.elf"
TRANSLATED_DEVICE_MAP = "/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.map.json.compact.blockmap.jsonl"
RELAY_JS = "/home/sdancer/aeon/frida/jit_trace_gate_v2.js"
ADB_SERIAL = os.environ.get("AEON_ADB_SERIAL", "localhost:5555")
ADB = ["adb", "-s", ADB_SERIAL]


def http_get(url: str, timeout: int | None) -> str:
    if timeout is None:
        with urllib.request.urlopen(url) as response:
            return response.read().decode()
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode()


def http_post(url: str, body: str, timeout: int | None) -> str:
    data = body.encode()
    req = urllib.request.Request(url, data=data, method="POST")
    if timeout is None:
        with urllib.request.urlopen(req) as response:
            return response.read().decode()
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode()


def read_text_tail(path: Path, max_chars: int = 20000) -> str:
    try:
        data = path.read_text(errors="replace")
    except Exception:  # noqa: BLE001
        return ""
    if len(data) <= max_chars:
        return data
    return data[-max_chars:]


def device_file_size(path: str, timeout: int = 3) -> int | None:
    try:
        proc = subprocess.run(
            ADB + [
                "shell",
                "sh",
                "-c",
                f"if [ -f {path!r} ]; then wc -c < {path!r}; else echo 0; fi",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip()
    try:
        return int(out) if out else 0
    except ValueError:
        return None


def call_with_capture_watch(
    port: int,
    challenge: str,
    call_timeout: int,
    capture_out: Path,
    proc: subprocess.Popen | None,
    prepare_before_call: bool,
) -> str:
    url = f"http://127.0.0.1:{port}/call?c={challenge}&timeout={call_timeout}"
    if prepare_before_call:
        url += "&prepare=1"
    result: dict[str, object] = {"done": False, "value": None}

    def worker() -> None:
        try:
            result["value"] = http_get(url, timeout=None)
        except Exception as exc:  # noqa: BLE001
            result["value"] = f"ERR:{exc}"
        finally:
            result["done"] = True

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    deadline = time.time() + call_timeout + 20
    last_keepalive_count = 0
    last_trace_bytes = 0
    while True:
        if result["done"]:
            return str(result["value"])
        if proc is not None and proc.poll() is not None:
            tail = read_text_tail(capture_out)
            if "Frida process ended" in tail:
                return "ERR:frida process ended before /call completed"
        if capture_out.exists():
            tail = read_text_tail(capture_out)
            if "Frida process ended" in tail:
                return "ERR:frida process ended before /call completed"
            keepalive_count = tail.count("RPC keepalive extend trace_bytes=")
            if keepalive_count > last_keepalive_count:
                last_keepalive_count = keepalive_count
                deadline = time.time() + 15
        trace_bytes = device_file_size(DEVICE_GATE_TRACE_LOG)
        if trace_bytes is not None and trace_bytes > last_trace_bytes:
            last_trace_bytes = trace_bytes
            deadline = time.time() + 15
        if time.time() >= deadline:
            return f"ERR:/call watchdog timeout after idle 15s (requested timeout {call_timeout}s)"
        time.sleep(1)


def wait_http_ready(base_url: str, timeout_s: int) -> None:
    deadline = time.time() + timeout_s
    last_error = None
    parsed = urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"capture server did not start: {last_error}")


def kill_capture(port: int, proc: subprocess.Popen | None) -> None:
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    subprocess.run(
        ["pkill", "-f", f"nmss_capture.py --port {port}"],
        check=False,
        capture_output=True,
        text=True,
    )


def adb_run(args: list[str], timeout: int) -> dict:
    try:
        proc = subprocess.run(
            ADB + args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "timeout": True,
            "stdout": (exc.stdout or "")[-4000:],
            "stderr": (exc.stderr or "")[-4000:],
        }


def parse_trace(trace_path: Path) -> dict:
    summary: dict[str, object] = {
        "trace_exists": trace_path.exists(),
        "valid_lines": 0,
        "invalid_lines": 0,
        "kinds": {},
        "tids": [],
        "unique_compiled_addrs": 0,
        "top_compiled_addrs": [],
        "stops": [],
        "calltargets": [],
    }
    if not trace_path.exists():
        return summary

    tids = set()
    kinds: Counter[str] = Counter()
    compiled_addrs: Counter[str] = Counter()
    stops = []
    calltargets = []

    for raw_line in trace_path.read_text(errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:  # noqa: BLE001
            summary["invalid_lines"] = int(summary["invalid_lines"]) + 1
            continue
        summary["valid_lines"] = int(summary["valid_lines"]) + 1
        tid = obj.get("tid")
        if tid is not None:
            tids.add(tid)
        kind = obj.get("kind")
        if isinstance(kind, str):
            kinds[kind] += 1
        if kind == "compiled" and obj.get("addr"):
            compiled_addrs[str(obj["addr"])] += 1
        elif kind == "stop":
            stops.append(obj)
        elif kind == "dynamic_call_target":
            calltargets.append(obj)

    summary["kinds"] = dict(kinds)
    summary["tids"] = sorted(tids)
    summary["unique_compiled_addrs"] = len(compiled_addrs)
    summary["top_compiled_addrs"] = compiled_addrs.most_common(16)
    summary["stops"] = stops[:20]
    summary["calltargets"] = calltargets[:20]
    return summary


def parse_runtime_log(log_path: Path) -> dict:
    summary: dict[str, object] = {
        "runtime_exists": log_path.exists(),
        "runtime_compiled_hits": 0,
        "runtime_enter_hits": 0,
        "runtime_leave_hits": 0,
        "max_step_seen": -1,
        "resume_traps": [],
    }
    if not log_path.exists():
        return summary

    lines = log_path.read_text(errors="replace").splitlines()
    summary["runtime_compiled_hits"] = sum(" compiled addr=" in line for line in lines)
    summary["runtime_enter_hits"] = sum(" enter addr=" in line for line in lines)
    summary["runtime_leave_hits"] = sum(" leave addr=" in line for line in lines)

    max_step = -1
    resume_traps = []
    for line in lines:
        if " step=" in line:
            try:
                step_str = line.split(" step=", 1)[1].split()[0]
                max_step = max(max_step, int(step_str))
            except Exception:  # noqa: BLE001
                pass
        if "dynamic resume trap parsed raw" in line:
            resume_traps.append(line)
    summary["max_step_seen"] = max_step
    summary["resume_traps"] = resume_traps[-20:]
    return summary


def parse_capture_log(log_path: Path) -> dict:
    summary: dict[str, object] = {
        "capture_log_exists": log_path.exists(),
        "capture_size": log_path.stat().st_size if log_path.exists() else 0,
        "capture_dynamic_thread_starts": 0,
        "capture_resume_traps": 0,
    }
    if not log_path.exists():
        return summary

    lines = log_path.read_text(errors="replace").splitlines()
    summary["capture_dynamic_thread_starts"] = sum(
        "dynamic thread start tid=" in line for line in lines
    )
    summary["capture_resume_traps"] = sum(
        "dynamic resume trap parsed raw" in line for line in lines
    )
    summary["capture_tail"] = lines[-80:]
    return summary


def choose_challenge(index: int, challenges: list[str]) -> str:
    return challenges[index % len(challenges)]


def run_one(
    port: int,
    challenge: str,
    out_root: Path,
    call_timeout: int,
    adb_timeout: int,
    prepare_before_call: bool,
    bootstrap_delay_ms: int,
    skip_relay: bool,
    enable_translated: bool,
    enable_dynamic: bool,
) -> dict:
    run_dir = out_root / f"allthread_{port}"
    run_dir.mkdir(parents=True, exist_ok=True)
    capture_out = Path(f"/tmp/nmss_capture_{port}.out")
    if capture_out.exists():
        capture_out.unlink()

    summary: dict[str, object] = {
        "port": port,
        "challenge": challenge,
        "call_timeout": call_timeout,
        "prepare_before_call": prepare_before_call,
        "bootstrap_delay_ms": bootstrap_delay_ms,
        "skip_relay": skip_relay,
        "enable_translated": enable_translated,
        "enable_dynamic": enable_dynamic,
        "run_dir": str(run_dir),
    }

    summary["adb_clear"] = adb_run(
        ["shell", "rm", "-f", DEVICE_RUNTIME_LOG, DEVICE_TRACE_JSONL, DEVICE_GATE_TRACE_LOG],
        timeout=adb_timeout,
    )

    proc: subprocess.Popen | None = None
    try:
        with capture_out.open("w") as outf:
            proc = subprocess.Popen(
                ["python3", "frida/nmss_capture.py", "--port", str(port)],
                cwd=REPO,
                stdout=outf,
                stderr=subprocess.STDOUT,
            )
        wait_http_ready(f"http://127.0.0.1:{port}", timeout_s=150)

        def safe_get(name: str, path: str, timeout: int) -> str:
            try:
                return http_get(f"http://127.0.0.1:{port}{path}", timeout=timeout)
            except Exception as exc:  # noqa: BLE001
                return f"ERR:{exc}"

        artifacts = {
            "prepare": safe_get("prepare", f"/prepare?c={challenge}", timeout=60),
        }
        if skip_relay:
            artifacts["relay"] = "SKIPPED"
            artifacts["bootstrap"] = "SKIPPED"
            artifacts["dload"] = "SKIPPED"
            artifacts["darm"] = "SKIPPED"
        else:
            bootstrap_expr = (
                "globalThis.__jitGateBootstrapConfig = "
                "{installExceptionHandler:true, wrapMaybeAdoptJit:true, "
                "exportTracedCall:true, installNmssCoreHooks:false, "
                f"bootstrapDelayMs:{bootstrap_delay_ms}"
                "}; 'OK'"
            )
            try:
                artifacts["bootstrap"] = http_post(
                    f"http://127.0.0.1:{port}/eval?timeout=30",
                    bootstrap_expr,
                    timeout=30,
                )
            except Exception as exc:  # noqa: BLE001
                artifacts["bootstrap"] = f"ERR:{exc}"
            artifacts["relay"] = safe_get(
                "relay",
                f"/relay?path={RELAY_JS}",
                timeout=30,
            )
            time.sleep((bootstrap_delay_ms / 1000.0) + 2.0)
            if enable_translated:
                artifacts["tload"] = safe_get(
                    "tload",
                    f"/translated/load?elf={TRANSLATED_DEVICE_ELF}&map={TRANSLATED_DEVICE_MAP}",
                    timeout=120,
                )
                artifacts["tarm"] = safe_get(
                    "tarm",
                    f"/translated/arm?elf={TRANSLATED_DEVICE_ELF}&map={TRANSLATED_DEVICE_MAP}&max_steps=4096",
                    timeout=120,
                )
            else:
                artifacts["tload"] = "SKIPPED"
                artifacts["tarm"] = "SKIPPED"
            if enable_dynamic:
                artifacts["dload"] = safe_get(
                    "dload",
                    f"/dynamic/load?lib={DEVICE_RUNTIME_LIB}",
                    timeout=120,
                )
                artifacts["darm"] = safe_get(
                    "darm",
                    f"/dynamic/arm?lib={DEVICE_RUNTIME_LIB}&max_steps=4096&trace_all_threads=1",
                    timeout=120,
                )
            else:
                artifacts["dload"] = "SKIPPED"
                artifacts["darm"] = "SKIPPED"
        artifacts["call"] = call_with_capture_watch(
            port=port,
            challenge=challenge,
            call_timeout=call_timeout,
            capture_out=capture_out,
            proc=proc,
            prepare_before_call=prepare_before_call,
        )

        for name, body in artifacts.items():
            (run_dir / f"{name}_{port}.json").write_text(body)
        summary["call_result"] = artifacts["call"]
    finally:
        time.sleep(2)
        kill_capture(port, proc)
        if capture_out.exists():
            shutil.copy2(capture_out, run_dir / capture_out.name)

    summary["adb_pull_runtime"] = adb_run(
        ["pull", DEVICE_RUNTIME_LOG, str(run_dir / "aeon_dyn_runtime.log")],
        timeout=adb_timeout,
    )
    summary["adb_pull_trace"] = adb_run(
        ["pull", DEVICE_TRACE_JSONL, str(run_dir / "aeon_dyn_trace.jsonl")],
        timeout=adb_timeout,
    )
    summary["adb_pull_gate_trace"] = adb_run(
        ["pull", DEVICE_GATE_TRACE_LOG, str(run_dir / "aeon_trace.log")],
        timeout=adb_timeout,
    )

    summary.update(parse_trace(run_dir / "aeon_dyn_trace.jsonl"))
    summary.update(parse_runtime_log(run_dir / "aeon_dyn_runtime.log"))
    summary.update(parse_capture_log(run_dir / capture_out.name))

    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-port", type=int, default=12270)
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--call-timeout", type=int, default=300)
    parser.add_argument("--adb-timeout", type=int, default=25)
    parser.add_argument(
        "--out-root",
        type=Path,
        default=REPO / "nmss_trace_runs",
    )
    parser.add_argument("--challenges", nargs="*", default=DEFAULT_CHALLENGES)
    args = parser.parse_args()

    # Current validated control path: plain spawn + /prepare + /call.
    # Current bisect step: re-enable only the safest relay component
    # (exception handler) while keeping dynamic tracing disabled.
    prepare_before_call = True
    bootstrap_delay = 3000
    skip_relay = False
    enable_translated = True
    enable_dynamic = True

    args.out_root.mkdir(parents=True, exist_ok=True)

    batch = {
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "start_port": args.start_port,
        "count": args.count,
        "call_timeout": args.call_timeout,
        "adb_timeout": args.adb_timeout,
        "prepare_before_call": prepare_before_call,
        "bootstrap_delay": bootstrap_delay,
        "skip_relay": skip_relay,
        "enable_translated": enable_translated,
        "enable_dynamic": enable_dynamic,
        "results": [],
    }

    for i in range(args.count):
        port = args.start_port + i
        challenge = choose_challenge(i, args.challenges)
        result = run_one(
            port=port,
            challenge=challenge,
            out_root=args.out_root,
            call_timeout=args.call_timeout,
            adb_timeout=args.adb_timeout,
            prepare_before_call=prepare_before_call,
            bootstrap_delay_ms=bootstrap_delay,
            skip_relay=skip_relay,
            enable_translated=enable_translated,
            enable_dynamic=enable_dynamic,
        )
        batch["results"].append(result)
        print(json.dumps(
            {
                "port": result["port"],
                "challenge": result["challenge"],
                "call_result": result.get("call_result"),
                "valid_lines": result.get("valid_lines"),
                "invalid_lines": result.get("invalid_lines"),
                "runtime_compiled_hits": result.get("runtime_compiled_hits"),
                "max_step_seen": result.get("max_step_seen"),
            },
            indent=2,
        ))
        sys.stdout.flush()

    batch["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    batch_path = args.out_root / f"batch_{args.start_port}_{args.start_port + args.count - 1}.json"
    batch_path.write_text(json.dumps(batch, indent=2))
    print(f"batch_summary={batch_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
