#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
EVAL_DIR = REPO_ROOT / "eval"
MOCK_SERVER = EVAL_DIR / "mock_mcp_server.py"
RESULTS_PATH = EVAL_DIR / "mcp_eval_results.json"
RECOMMENDATIONS_PATH = EVAL_DIR / "mcp_description_recommendations.md"
DEFAULT_MODEL = "sonnet"
SERVER_NAME = "aeoneval"
SDK_MODEL = "claude-sonnet-4-20250514"
SCHEMA_VERSION = 1

SYSTEM_PROMPT = (
    "You are evaluating MCP tool routing only.\n"
    "Assume a binary is already loaded unless the user explicitly asks to load one.\n"
    "You must call at least one MCP tool.\n"
    "Call only the tool or tools you would actually choose first for the request.\n"
    "Use the minimal set of tools.\n"
    "Tool results are dry-run placeholders, so do not keep exploring after the selection.\n"
    "After tool calls, respond with JSON that matches the provided schema.\n"
    "In selected_tools, list bare tool names without any mcp__ prefix, in call order, without duplicates."
)

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "selected_tools": {
            "type": "array",
            "items": {"type": "string"},
        }
    },
    "required": ["selected_tools"],
}

DESCRIPTION_REWRITES = {
    "load_binary": "Load the ELF at path so other aeon tools can query it.",
    "list_functions": "List discovered functions; filter by name or paginate.",
    "set_analysis_name": "Alias of rename_symbol: set a semantic name at addr.",
    "rename_symbol": "Name addr with a semantic symbol.",
    "define_struct": "Attach a struct definition to addr.",
    "add_hypothesis": "Attach an analyst note to addr.",
    "search_analysis_names": "Find named addresses by regex.",
    "get_il": "Lift function at addr to raw AeonIL. Use get_reduced_il or get_ssa for cleaner IR.",
    "get_function_il": "Alias of get_il: lift function at addr to raw AeonIL.",
    "get_reduced_il": "Lift function at addr to reduced IL. Use get_ssa for SSA form.",
    "get_ssa": "Lift function at addr to SSA. Use get_reduced_il for non-SSA IR.",
    "get_stack_frame": "Show the stack frame and stack-slot accesses for function at addr.",
    "get_function_cfg": "Graph control flow for function at addr.",
    "get_xrefs": "List callers and callees for function at addr.",
    "scan_pointers": "Scan mapped data for internal pointers. Use get_function_pointers for one function.",
    "scan_vtables": "Scan mapped data for candidate C++ vtables.",
    "get_function_pointers": "List code and data pointers used by function at addr, or scan many functions.",
    "find_call_paths": "Find call paths from start_addr to goal_addr.",
    "get_bytes": "Read hex bytes at addr. Use get_data for hex plus ASCII.",
    "search_rc4": "Find RC4 implementations.",
    "get_coverage": "Report IL lift coverage for the loaded binary.",
    "get_asm": "Disassemble ARM64 from start_addr to stop_addr.",
    "get_function_at": "Show the function containing addr; set include_asm or include_il to inline code.",
    "get_string": "Read a null-terminated string at addr.",
    "get_data": "Read bytes plus ASCII at addr. Use get_bytes for hex only.",
}

PARAM_REWRITES = {
    "load_binary": {
        "path": "ELF path like samples/hello_aarch64.elf",
    },
    "list_functions": {
        "offset": "Start index like 0",
        "limit": "Max results like 100",
        "name_filter": "Symbol substring like recv",
    },
    "set_analysis_name": {
        "addr": "Hex address like 0x5e611fc",
        "name": "Semantic name like packet_dispatch",
    },
    "rename_symbol": {
        "addr": "Hex address like 0x5e611fc",
        "name": "Semantic name like packet_dispatch",
    },
    "define_struct": {
        "addr": "Hex address like 0x5e611fc",
        "definition": "Struct text like Packet { len: u32, data: char* }",
    },
    "add_hypothesis": {
        "addr": "Hex address like 0x5e611fc",
        "note": "Analyst note like Likely decrypt loop",
    },
    "search_analysis_names": {
        "pattern": "Regex like ^rc4_.*$",
    },
    "get_il": {
        "addr": "Hex address like 0x5e611fc",
    },
    "get_function_il": {
        "addr": "Hex address like 0x5e611fc",
    },
    "get_reduced_il": {
        "addr": "Hex address like 0x5e611fc",
    },
    "get_ssa": {
        "addr": "Hex address like 0x5e611fc",
        "optimize": "Run SSA cleanup before returning JSON",
    },
    "get_stack_frame": {
        "addr": "Hex address like 0x5e611fc",
    },
    "get_function_cfg": {
        "addr": "Function address like 0x5e611fc",
    },
    "get_xrefs": {
        "addr": "Function address like 0x5e611fc",
    },
    "get_function_pointers": {
        "addr": "Optional function address like 0x5e611fc",
        "offset": "Start index like 0",
        "limit": "Max functions like 50 when addr is omitted",
    },
    "find_call_paths": {
        "start_addr": "Start function address like 0x5e611fc",
        "goal_addr": "Goal function address like 0x5e61234",
        "max_depth": "Max call depth like 6",
        "include_all_paths": "Return all simple paths up to max_depth",
        "max_paths": "Max returned paths like 32 when include_all_paths is true",
    },
    "get_bytes": {
        "addr": "Hex address like 0x5e611fc",
        "size": "Byte count like 64",
    },
    "get_asm": {
        "start_addr": "Hex start address like 0x512025c",
        "stop_addr": "Hex stop address like 0x51202cc",
    },
    "get_function_at": {
        "addr": "Hex address like 0x5e611fc",
        "include_asm": "Attach asm to the result",
        "include_il": "Attach AeonIL to the result",
    },
    "get_string": {
        "addr": "Hex address like 0x5e611fc",
        "max_len": "Max bytes to scan like 256",
    },
    "get_data": {
        "addr": "Hex address like 0x5e611fc",
        "size": "Byte count like 64",
    },
}

SCENARIOS = [
    {
        "id": "load_binary_basic",
        "query": "Load samples/hello_aarch64.elf into aeon so I can analyze it.",
        "gold_tools": ["load_binary"],
        "accepted_tools": [["load_binary"]],
        "notes": "Explicit session setup",
    },
    {
        "id": "load_binary_library",
        "query": "Open libUnreal.so in aeon first.",
        "gold_tools": ["load_binary"],
        "accepted_tools": [["load_binary"]],
        "notes": "Explicit binary ingest",
    },
    {
        "id": "list_functions_basic",
        "query": "List the first 20 discovered functions in this binary.",
        "gold_tools": ["list_functions"],
        "accepted_tools": [["list_functions"]],
        "notes": "Simple function inventory",
    },
    {
        "id": "list_functions_filtered",
        "query": "Show me functions whose name contains recv.",
        "gold_tools": ["list_functions"],
        "accepted_tools": [["list_functions"]],
        "notes": "Name filter should steer to list_functions",
    },
    {
        "id": "list_functions_page",
        "query": "Give me the next page of function names starting at index 100.",
        "gold_tools": ["list_functions"],
        "accepted_tools": [["list_functions"]],
        "notes": "Pagination",
    },
    {
        "id": "rename_symbol_basic",
        "query": "Rename 0x5e611fc to packet_dispatch.",
        "gold_tools": ["rename_symbol"],
        "accepted_tools": [["rename_symbol"], ["set_analysis_name"]],
        "notes": "General semantic rename",
    },
    {
        "id": "rename_symbol_semantic",
        "query": "Attach the semantic symbol rc4_ksa to 0x401000.",
        "gold_tools": ["rename_symbol"],
        "accepted_tools": [["rename_symbol"], ["set_analysis_name"]],
        "notes": "Should still pick rename_symbol for generic naming",
    },
    {
        "id": "set_analysis_name_alias",
        "query": "Use the set_analysis_name alias to label 0x401200 as init_state.",
        "gold_tools": ["set_analysis_name"],
        "accepted_tools": [["set_analysis_name"], ["rename_symbol"]],
        "notes": "Alias-specific wording",
    },
    {
        "id": "define_struct_attach",
        "query": "Attach this struct at 0x500000: Packet { len: u32, data: char* }.",
        "gold_tools": ["define_struct"],
        "accepted_tools": [["define_struct"]],
        "notes": "Semantic struct annotation",
    },
    {
        "id": "define_struct_overwrite",
        "query": "Overwrite the structure definition at 0x500120 with Header { magic: u32, size: u16 }.",
        "gold_tools": ["define_struct"],
        "accepted_tools": [["define_struct"]],
        "notes": "Existing annotation update",
    },
    {
        "id": "add_hypothesis_note",
        "query": "Add a note at 0x401234 that this looks like the decrypt loop.",
        "gold_tools": ["add_hypothesis"],
        "accepted_tools": [["add_hypothesis"]],
        "notes": "Free-form analyst note",
    },
    {
        "id": "add_hypothesis_duplicate_note",
        "query": "Record a hypothesis on 0x401260: likely packet header parser.",
        "gold_tools": ["add_hypothesis"],
        "accepted_tools": [["add_hypothesis"]],
        "notes": "Another semantic note",
    },
    {
        "id": "search_analysis_names_regex",
        "query": "Find all saved analysis names matching ^rc4_.*$.",
        "gold_tools": ["search_analysis_names"],
        "accepted_tools": [["search_analysis_names"]],
        "notes": "Regex lookup",
    },
    {
        "id": "search_analysis_names_family",
        "query": "Search my named addresses for anything in the packet_ family.",
        "gold_tools": ["search_analysis_names"],
        "accepted_tools": [["search_analysis_names"]],
        "notes": "Search semantic names",
    },
    {
        "id": "get_il_raw_lift",
        "query": "Lift the function at 0x5e611fc to raw AeonIL.",
        "gold_tools": ["get_il"],
        "accepted_tools": [["get_il"], ["get_function_il"]],
        "notes": "Raw IR request",
    },
    {
        "id": "get_il_listing",
        "query": "Show me the un-reduced IL listing for the function containing 0x5e611fc.",
        "gold_tools": ["get_il"],
        "accepted_tools": [["get_il"], ["get_function_il"]],
        "notes": "Raw IL again",
    },
    {
        "id": "get_function_il_alias",
        "query": "Call get_function_il for 0x718.",
        "gold_tools": ["get_function_il"],
        "accepted_tools": [["get_function_il"], ["get_il"]],
        "notes": "Alias-specific wording",
    },
    {
        "id": "get_reduced_il_explain",
        "query": "What does the function at 0x5e611fc do? Show the reduced IL.",
        "gold_tools": ["get_reduced_il"],
        "accepted_tools": [["get_reduced_il"], ["get_ssa"]],
        "notes": "Common analysis query",
    },
    {
        "id": "get_reduced_il_clean",
        "query": "I want the cleaned-up IR for 0x5e611fc, not raw lift output.",
        "gold_tools": ["get_reduced_il"],
        "accepted_tools": [["get_reduced_il"]],
        "notes": "Distinguish from get_il",
    },
    {
        "id": "get_reduced_il_blocks",
        "query": "Show block-structured IR for the function around 0x5e611fc.",
        "gold_tools": ["get_reduced_il"],
        "accepted_tools": [["get_reduced_il"]],
        "notes": "Reduced block form",
    },
    {
        "id": "get_ssa_dataflow",
        "query": "Show SSA for 0x5e611fc so I can reason about data flow.",
        "gold_tools": ["get_ssa"],
        "accepted_tools": [["get_ssa"]],
        "notes": "SSA terminology",
    },
    {
        "id": "get_ssa_phi",
        "query": "I need phi nodes and versioned variables for the function at 0x5e611fc.",
        "gold_tools": ["get_ssa"],
        "accepted_tools": [["get_ssa"]],
        "notes": "SSA-specific wording",
    },
    {
        "id": "get_ssa_optimized",
        "query": "Give me the optimized SSA form for 0x718.",
        "gold_tools": ["get_ssa"],
        "accepted_tools": [["get_ssa"]],
        "notes": "Optimized SSA",
    },
    {
        "id": "get_stack_frame_locals",
        "query": "Show locals and stack-slot accesses for the function containing 0x5e611fc.",
        "gold_tools": ["get_stack_frame"],
        "accepted_tools": [["get_stack_frame"]],
        "notes": "Stack analysis",
    },
    {
        "id": "get_stack_frame_layout",
        "query": "What does this function's stack frame look like at 0x5e611fc?",
        "gold_tools": ["get_stack_frame"],
        "accepted_tools": [["get_stack_frame"]],
        "notes": "Stack layout wording",
    },
    {
        "id": "get_function_cfg_cfg",
        "query": "Build the control-flow graph for function 0x5e611fc.",
        "gold_tools": ["get_function_cfg"],
        "accepted_tools": [["get_function_cfg"]],
        "notes": "Explicit CFG",
    },
    {
        "id": "get_function_cfg_branches",
        "query": "Show the branch graph for 0x5e611fc.",
        "gold_tools": ["get_function_cfg"],
        "accepted_tools": [["get_function_cfg"]],
        "notes": "CFG paraphrase",
    },
    {
        "id": "get_xrefs_callers",
        "query": "Who calls 0x5e611fc, and what does that function call out to?",
        "gold_tools": ["get_xrefs"],
        "accepted_tools": [["get_xrefs"]],
        "notes": "Incoming and outgoing refs",
    },
    {
        "id": "get_xrefs_incoming_outgoing",
        "query": "List incoming and outgoing call references for function 0x5e611fc.",
        "gold_tools": ["get_xrefs"],
        "accepted_tools": [["get_xrefs"]],
        "notes": "Cross-reference wording",
    },
    {
        "id": "scan_pointers_data",
        "query": "Scan mapped data sections for internal pointers.",
        "gold_tools": ["scan_pointers"],
        "accepted_tools": [["scan_pointers"]],
        "notes": "Whole-binary pointer scan",
    },
    {
        "id": "scan_pointers_data_refs",
        "query": "Find global data words that point back into code or data.",
        "gold_tools": ["scan_pointers"],
        "accepted_tools": [["scan_pointers"]],
        "notes": "Pointer scan paraphrase",
    },
    {
        "id": "scan_vtables_find",
        "query": "Find candidate C++ vtables in this binary.",
        "gold_tools": ["scan_vtables"],
        "accepted_tools": [["scan_vtables"]],
        "notes": "Whole-binary vtable scan",
    },
    {
        "id": "scan_vtables_arrays",
        "query": "Look for arrays of function pointers that resemble vtables.",
        "gold_tools": ["scan_vtables"],
        "accepted_tools": [["scan_vtables"]],
        "notes": "Vtable phrasing without the tool name",
    },
    {
        "id": "get_function_pointers_single",
        "query": "For function 0x5e66990, enumerate resolved code and data pointer references.",
        "gold_tools": ["get_function_pointers"],
        "accepted_tools": [["get_function_pointers"]],
        "notes": "Per-function pointer recovery",
    },
    {
        "id": "get_function_pointers_batch",
        "query": "Scan 50 functions for pointer-valued operands and references.",
        "gold_tools": ["get_function_pointers"],
        "accepted_tools": [["get_function_pointers"]],
        "notes": "Batch function-pointer scan",
    },
    {
        "id": "find_call_paths_route",
        "query": "Find a call path from 0x400100 to 0x401000.",
        "gold_tools": ["find_call_paths"],
        "accepted_tools": [["find_call_paths"]],
        "notes": "Basic call path",
    },
    {
        "id": "find_call_paths_recv_dispatch",
        "query": "How does control flow from recv at 0x5e66000 to dispatch at 0x5e67000?",
        "gold_tools": ["find_call_paths"],
        "accepted_tools": [["find_call_paths"]],
        "notes": "Narrative call-path phrasing",
    },
    {
        "id": "find_call_paths_all",
        "query": "Show all bounded call-graph paths from 0x401000 to 0x402000.",
        "gold_tools": ["find_call_paths"],
        "accepted_tools": [["find_call_paths"]],
        "notes": "All-paths option",
    },
    {
        "id": "get_bytes_raw",
        "query": "Read 32 raw bytes at 0x500000 as hex only.",
        "gold_tools": ["get_bytes"],
        "accepted_tools": [["get_bytes"]],
        "notes": "Hex-only memory read",
    },
    {
        "id": "get_bytes_patch",
        "query": "Dump the opcode bytes at 0x512025c for 16 bytes.",
        "gold_tools": ["get_bytes"],
        "accepted_tools": [["get_bytes"]],
        "notes": "Instruction bytes",
    },
    {
        "id": "search_rc4_find",
        "query": "Find RC4 implementations in this binary.",
        "gold_tools": ["search_rc4"],
        "accepted_tools": [["search_rc4"]],
        "notes": "Crypto scan",
    },
    {
        "id": "search_rc4_cipher",
        "query": "Search for a stream cipher that looks like RC4 key scheduling and PRGA.",
        "gold_tools": ["search_rc4"],
        "accepted_tools": [["search_rc4"]],
        "notes": "Behavioral RC4 wording",
    },
    {
        "id": "get_coverage_lift",
        "query": "What percentage of instructions lifted cleanly versus intrinsic or decode error?",
        "gold_tools": ["get_coverage"],
        "accepted_tools": [["get_coverage"]],
        "notes": "Coverage report",
    },
    {
        "id": "get_coverage_stats",
        "query": "Report IL lift coverage stats for the loaded binary.",
        "gold_tools": ["get_coverage"],
        "accepted_tools": [["get_coverage"]],
        "notes": "Coverage paraphrase",
    },
    {
        "id": "get_asm_range",
        "query": "Disassemble ARM64 instructions from 0x512025c to 0x51202cc.",
        "gold_tools": ["get_asm"],
        "accepted_tools": [["get_asm"]],
        "notes": "Address range disassembly",
    },
    {
        "id": "get_asm_only",
        "query": "Give me asm only for the range 0x401000..0x401040.",
        "gold_tools": ["get_asm"],
        "accepted_tools": [["get_asm"]],
        "notes": "Asm-only phrasing",
    },
    {
        "id": "get_function_at_containing",
        "query": "What function contains address 0x5e611fc?",
        "gold_tools": ["get_function_at"],
        "accepted_tools": [["get_function_at"]],
        "notes": "Containing function lookup",
    },
    {
        "id": "get_function_at_with_asm",
        "query": "Find the function containing 0x5e611fc and include asm in the result.",
        "gold_tools": ["get_function_at"],
        "accepted_tools": [["get_function_at"]],
        "notes": "Inline asm via get_function_at",
    },
    {
        "id": "get_function_at_with_il",
        "query": "Show the function for 0x5e611fc with AeonIL attached.",
        "gold_tools": ["get_function_at"],
        "accepted_tools": [["get_function_at"]],
        "notes": "Inline IL via get_function_at",
    },
    {
        "id": "get_string_cstr",
        "query": "Read the C string at 0x700123.",
        "gold_tools": ["get_string"],
        "accepted_tools": [["get_string"]],
        "notes": "Null-terminated string read",
    },
    {
        "id": "get_string_banner",
        "query": "Show the null-terminated banner string stored at 0x701000.",
        "gold_tools": ["get_string"],
        "accepted_tools": [["get_string"]],
        "notes": "String phrasing",
    },
    {
        "id": "get_data_hex_ascii",
        "query": "Read 64 bytes at 0x500000 and include the ASCII sidecar.",
        "gold_tools": ["get_data"],
        "accepted_tools": [["get_data"]],
        "notes": "Hex plus ASCII read",
    },
    {
        "id": "get_data_blob",
        "query": "Dump the memory blob at 0x500120 as bytes plus printable text.",
        "gold_tools": ["get_data"],
        "accepted_tools": [["get_data"]],
        "notes": "Hex plus ASCII paraphrase",
    },
    {
        "id": "multi_load_then_rc4",
        "query": "Load samples/hello_aarch64.elf and then search it for RC4 code.",
        "gold_tools": ["load_binary", "search_rc4"],
        "accepted_tools": [["load_binary", "search_rc4"]],
        "notes": "Two-step workflow",
    },
    {
        "id": "multi_load_then_reduced",
        "query": "Open samples/hello_aarch64.elf, then show the reduced IL for 0x718.",
        "gold_tools": ["load_binary", "get_reduced_il"],
        "accepted_tools": [["load_binary", "get_reduced_il"]],
        "notes": "Load plus function IR",
    },
    {
        "id": "multi_list_then_cfg",
        "query": "List functions containing recv, then graph control flow for 0x5e611fc.",
        "gold_tools": ["list_functions", "get_function_cfg"],
        "accepted_tools": [["list_functions", "get_function_cfg"]],
        "notes": "Discovery plus graph",
    },
    {
        "id": "ambiguous_function_summary",
        "query": "Explain what the function at 0x5e611fc is doing.",
        "gold_tools": ["get_reduced_il"],
        "accepted_tools": [["get_reduced_il"], ["get_ssa"], ["get_function_at"]],
        "notes": "Ambiguous summary request",
    },
    {
        "id": "ambiguous_data_read",
        "query": "Read memory at 0x500000 for me.",
        "gold_tools": ["get_data"],
        "accepted_tools": [["get_data"], ["get_bytes"]],
        "notes": "Ambiguous raw-data wording",
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate aeon MCP description variants.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Claude CLI model alias for the fallback backend.")
    parser.add_argument(
        "--backend",
        choices=["auto", "anthropic_sdk", "claude_cli"],
        default="auto",
        help="Force an evaluation backend.",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=0.0,
        help="Optional pause between scenarios.",
    )
    return parser.parse_args()


def tool_to_anthropic_schema(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": tool["name"],
        "description": tool["description"],
        "input_schema": tool["inputSchema"],
    }


def unique_in_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def spawn_aeon_mcp_for_tools() -> list[dict[str, Any]]:
    cmd = ["cargo", "run", "-q", "-p", "aeon-frontend", "--bin", "aeon-mcp"]
    proc = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdin is not None
        assert proc.stdout is not None
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
        proc.stdin.flush()
        proc.stdin.close()

        responses = []
        deadline = time.time() + 60
        while len(responses) < 2 and time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            responses.append(json.loads(line))
        stderr = proc.stderr.read()
        if len(responses) < 2:
            raise RuntimeError(f"Failed to fetch tools/list from aeon_mcp. stderr={stderr.strip()}")
        return responses[1]["result"]["tools"]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def apply_rewrites(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rewritten = copy.deepcopy(tools)
    for tool in rewritten:
        name = tool["name"]
        if name not in DESCRIPTION_REWRITES:
            raise KeyError(f"Missing rewritten description for {name}")
        tool["description"] = DESCRIPTION_REWRITES[name]
        properties = tool.get("inputSchema", {}).get("properties", {})
        for param_name, param_desc in PARAM_REWRITES.get(name, {}).items():
            if param_name not in properties:
                raise KeyError(f"Missing property {param_name} on {name}")
            properties[param_name]["description"] = param_desc
    return rewritten


def has_anthropic_sdk() -> bool:
    return importlib.util.find_spec("anthropic") is not None and bool(os.getenv("ANTHROPIC_API_KEY"))


def has_claude_cli() -> bool:
    return shutil.which("claude") is not None


def resolve_backend(requested: str) -> str:
    if requested == "anthropic_sdk":
        if not has_anthropic_sdk():
            raise RuntimeError("anthropic_sdk backend requested but anthropic package or ANTHROPIC_API_KEY is missing")
        return requested
    if requested == "claude_cli":
        if not has_claude_cli():
            raise RuntimeError("claude_cli backend requested but claude CLI is not installed")
        return requested
    if has_anthropic_sdk():
        return "anthropic_sdk"
    if has_claude_cli():
        return "claude_cli"
    raise RuntimeError("No supported backend found. Need anthropic SDK + ANTHROPIC_API_KEY or the claude CLI.")


def normalize_tool_name(name: str) -> str:
    if name.startswith(f"mcp__{SERVER_NAME}__"):
        return name.split(f"mcp__{SERVER_NAME}__", 1)[1]
    return name


def read_call_log(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_claude_cli_scenario(
    scenario: dict[str, Any],
    tools_json: Path,
    model: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aeon-mcp-eval-") as temp_dir:
        temp_path = Path(temp_dir)
        log_path = temp_path / "calls.jsonl"
        mcp_config_path = temp_path / "mcp.json"
        mcp_config = {
            "mcpServers": {
                SERVER_NAME: {
                    "type": "stdio",
                    "command": sys.executable,
                    "args": [str(MOCK_SERVER), "--tools-json", str(tools_json), "--log-file", str(log_path)],
                }
            }
        }
        mcp_config_path.write_text(json.dumps(mcp_config), encoding="utf-8")
        tool_names = json.loads(tools_json.read_text(encoding="utf-8"))["tools"]
        allowed_tools = ",".join(f"mcp__{SERVER_NAME}__{tool['name']}" for tool in tool_names)
        cmd = [
            "claude",
            "-p",
            scenario["query"],
            "--output-format",
            "json",
            "--json-schema",
            json.dumps(RESULT_SCHEMA),
            "--system-prompt",
            SYSTEM_PROMPT,
            "--model",
            model,
            "--tools",
            "",
            "--allowedTools",
            allowed_tools,
            "--mcp-config",
            str(mcp_config_path),
            "--strict-mcp-config",
            "--no-session-persistence",
            "--permission-mode",
            "dontAsk",
        ]
        completed = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()
        calls = read_call_log(log_path)
        called_tools = unique_in_order([normalize_tool_name(item["name"]) for item in calls])
        parsed_result: dict[str, Any] | None = None
        permission_denials: list[dict[str, Any]] = []
        outer: dict[str, Any] | None = None
        if stdout:
            try:
                outer = json.loads(stdout)
                permission_denials = outer.get("permission_denials", []) or []
                structured = outer.get("structured_output")
                if isinstance(structured, dict):
                    parsed_result = structured
                else:
                    result_text = outer.get("result")
                    if isinstance(result_text, str):
                        parsed_result = json.loads(result_text)
            except Exception:
                parsed_result = None
        selected_tools = []
        if isinstance(parsed_result, dict):
            raw_selected = parsed_result.get("selected_tools", [])
            if isinstance(raw_selected, list):
                selected_tools = [normalize_tool_name(str(value)) for value in raw_selected]
        denied_tools = unique_in_order(
            [normalize_tool_name(item.get("tool_name", "")) for item in permission_denials if item.get("tool_name")]
        )
        return {
            "backend": "claude_cli",
            "query": scenario["query"],
            "called_tools": called_tools,
            "selected_tools": unique_in_order(selected_tools),
            "denied_tools": denied_tools,
            "raw_stdout": stdout,
            "raw_stderr": stderr,
            "returncode": completed.returncode,
        }


def run_anthropic_sdk_scenario(
    scenario: dict[str, Any],
    tools: list[dict[str, Any]],
) -> dict[str, Any]:
    import anthropic  # type: ignore

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    response = client.messages.create(
        model=SDK_MODEL,
        max_tokens=256,
        system=SYSTEM_PROMPT,
        tools=[tool_to_anthropic_schema(tool) for tool in tools],
        messages=[{"role": "user", "content": scenario["query"]}],
    )
    called_tools = unique_in_order(
        [block.name for block in response.content if getattr(block, "type", None) == "tool_use"]
    )
    selected_tools = list(called_tools)
    return {
        "backend": "anthropic_sdk",
        "query": scenario["query"],
        "called_tools": called_tools,
        "selected_tools": selected_tools,
        "stop_reason": response.stop_reason,
        "model": response.model,
    }


def evaluate_variant(
    variant_name: str,
    backend: str,
    tools: list[dict[str, Any]],
    tools_json: Path,
    model: str,
    sleep_seconds: float,
) -> dict[str, Any]:
    scenario_results: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        if backend == "anthropic_sdk":
            run = run_anthropic_sdk_scenario(scenario, tools)
        else:
            run = run_claude_cli_scenario(scenario, tools_json, model)
        called_tools = run["called_tools"]
        predicted = called_tools or run.get("denied_tools", []) or run.get("selected_tools", [])
        accepted = scenario["accepted_tools"]
        accepted_match = any(set(predicted) == set(option) for option in accepted)
        exact_primary_match = set(predicted) == set(scenario["gold_tools"])
        scenario_results.append(
            {
                "id": scenario["id"],
                "query": scenario["query"],
                "gold_tools": scenario["gold_tools"],
                "accepted_tools": accepted,
                "notes": scenario["notes"],
                "predicted_tools": predicted,
                "called_tools": called_tools,
                "selected_tools": run.get("selected_tools", []),
                "accepted_match": accepted_match,
                "exact_primary_match": exact_primary_match,
                "backend_details": {
                    key: value
                    for key, value in run.items()
                    if key not in {"query", "called_tools", "selected_tools"}
                },
            }
        )
        if sleep_seconds:
            time.sleep(sleep_seconds)
    summary = summarize_results(scenario_results)
    return {
        "variant": variant_name,
        "summary": summary,
        "scenarios": scenario_results,
    }


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    accepted_matches = sum(1 for item in results if item["accepted_match"])
    exact_primary_matches = sum(1 for item in results if item["exact_primary_match"])
    tool_names = sorted(DESCRIPTION_REWRITES.keys())
    per_tool: dict[str, dict[str, float | int]] = {}
    for tool in tool_names:
        tp = fp = fn = 0
        for item in results:
            gold = set(item["gold_tools"])
            predicted = set(item["predicted_tools"])
            if tool in gold and tool in predicted:
                tp += 1
            elif tool in predicted and tool not in gold:
                fp += 1
            elif tool in gold and tool not in predicted:
                fn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_tool[tool] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }
    return {
        "scenario_count": total,
        "accepted_match_count": accepted_matches,
        "accepted_match_rate": round(accepted_matches / total, 4),
        "exact_primary_match_count": exact_primary_matches,
        "exact_primary_match_rate": round(exact_primary_matches / total, 4),
        "per_tool": per_tool,
    }


def build_recommendations_markdown(
    backend: str,
    backend_note: str,
    current: dict[str, Any],
    rewritten: dict[str, Any],
    original_tools: list[dict[str, Any]],
    rewritten_tools: list[dict[str, Any]],
) -> str:
    current_summary = current["summary"]
    rewritten_summary = rewritten["summary"]
    lines = [
        "# MCP Description Rewrite Recommendations",
        "",
        "## Method",
        "",
        backend_note,
        "",
        f"- Backend: `{backend}`",
        f"- Scenarios: `{current_summary['scenario_count']}`",
        "",
        "Research direction used:",
        "- Shorter descriptions beat longer ones on tool selection more often.",
        "- Lead with an action verb.",
        "- Put format examples in parameter descriptions.",
        "- Clarify close tool pairs with short see-also wording.",
        "",
        "References:",
        "- arXiv 2602.14878: https://arxiv.org/abs/2602.14878",
        "- Anthropic tool-use docs: https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/implement-tool-use",
        "- Anthropic Python SDK docs: https://docs.anthropic.com/en/api/client-sdks",
        "",
        "## Score Summary",
        "",
        "| Variant | Accepted Match | Exact Primary Match |",
        "|---|---:|---:|",
        f"| Current | {current_summary['accepted_match_count']}/{current_summary['scenario_count']} ({current_summary['accepted_match_rate']:.1%}) | {current_summary['exact_primary_match_count']}/{current_summary['scenario_count']} ({current_summary['exact_primary_match_rate']:.1%}) |",
        f"| Rewritten | {rewritten_summary['accepted_match_count']}/{rewritten_summary['scenario_count']} ({rewritten_summary['accepted_match_rate']:.1%}) | {rewritten_summary['exact_primary_match_count']}/{rewritten_summary['scenario_count']} ({rewritten_summary['exact_primary_match_rate']:.1%}) |",
        "",
        "## Per-Tool Delta",
        "",
        "| Tool | Current F1 | Rewritten F1 | Delta |",
        "|---|---:|---:|---:|",
    ]
    for tool in sorted(DESCRIPTION_REWRITES):
        current_f1 = current_summary["per_tool"][tool]["f1"]
        rewritten_f1 = rewritten_summary["per_tool"][tool]["f1"]
        delta = round(float(rewritten_f1) - float(current_f1), 4)
        lines.append(f"| `{tool}` | {current_f1:.4f} | {rewritten_f1:.4f} | {delta:+.4f} |")

    lines.extend(
        [
            "",
            "## Recommended Rewrites",
            "",
            "| Tool | Before | After |",
            "|---|---|---|",
        ]
    )
    rewritten_lookup = {tool["name"]: tool for tool in rewritten_tools}
    for tool in original_tools:
        name = tool["name"]
        lines.append(
            f"| `{name}` | {tool['description']} | {rewritten_lookup[name]['description']} |"
        )

    lines.extend(
        [
            "",
            "## Parameter Changes",
            "",
        ]
    )
    for tool in original_tools:
        name = tool["name"]
        before_props = tool.get("inputSchema", {}).get("properties", {})
        after_props = rewritten_lookup[name].get("inputSchema", {}).get("properties", {})
        changed = []
        for param_name, after in after_props.items():
            before_desc = before_props.get(param_name, {}).get("description")
            after_desc = after.get("description")
            if before_desc != after_desc:
                changed.append(f"- `{name}.{param_name}`: `{before_desc}` -> `{after_desc}`")
        if changed:
            lines.append(f"### `{name}`")
            lines.extend(changed)
            lines.append("")

    lines.extend(
        [
            "## Notes",
            "",
            "- Alias tools remain intentionally explicit, but the canonical tools now read as the default choice for generic requests.",
            "- The biggest description wins should come from the confusing tool families: raw vs reduced vs SSA IR, bytes vs data vs string reads, and global pointer scans vs per-function pointer scans.",
            "- If you later provide `ANTHROPIC_API_KEY`, the same runner can use the Anthropic Python SDK directly instead of the CLI fallback.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    backend = resolve_backend(args.backend)
    original_tools = spawn_aeon_mcp_for_tools()
    rewritten_tools = apply_rewrites(original_tools)

    with tempfile.TemporaryDirectory(prefix="aeon-tool-defs-") as temp_dir:
        temp_path = Path(temp_dir)
        current_tools_json = temp_path / "current_tools.json"
        rewritten_tools_json = temp_path / "rewritten_tools.json"
        current_tools_json.write_text(json.dumps({"tools": original_tools}, indent=2), encoding="utf-8")
        rewritten_tools_json.write_text(json.dumps({"tools": rewritten_tools}, indent=2), encoding="utf-8")

        current_eval = evaluate_variant(
            "current",
            backend,
            original_tools,
            current_tools_json,
            args.model,
            args.sleep_seconds,
        )
        rewritten_eval = evaluate_variant(
            "rewritten",
            backend,
            rewritten_tools,
            rewritten_tools_json,
            args.model,
            args.sleep_seconds,
        )

    backend_note = (
        "Preferred path is the Anthropic Python SDK, but this machine had no `ANTHROPIC_API_KEY` and no installed "
        "`anthropic` package during the run. The live evaluation therefore used the authenticated local `claude` CLI "
        "against a mock MCP server that exposed the tool definitions and logged real tool calls."
        if backend == "claude_cli"
        else "Live evaluation used the Anthropic Python SDK directly."
    )
    results = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_epoch": time.time(),
        "backend": backend,
        "backend_note": backend_note,
        "model": args.model if backend == "claude_cli" else SDK_MODEL,
        "scenario_count": len(SCENARIOS),
        "current": current_eval,
        "rewritten": rewritten_eval,
        "description_rewrites": DESCRIPTION_REWRITES,
        "parameter_rewrites": PARAM_REWRITES,
    }
    RESULTS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    RECOMMENDATIONS_PATH.write_text(
        build_recommendations_markdown(
            backend,
            backend_note,
            current_eval,
            rewritten_eval,
            original_tools,
            rewritten_tools,
        ),
        encoding="utf-8",
    )
    print(f"Wrote {RESULTS_PATH}")
    print(f"Wrote {RECOMMENDATIONS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
