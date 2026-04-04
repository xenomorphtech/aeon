# MCP Description Rewrite Evaluation

## Method

Preferred path is the Anthropic Python SDK, but this machine had no `ANTHROPIC_API_KEY` and no installed `anthropic` package during the run. The live evaluation therefore used the authenticated local `claude` CLI against a mock MCP server that exposed the tool definitions and logged real tool calls.

- Backend: `claude_cli`
- Scenarios: `58`

Research direction used:
- Shorter descriptions beat longer ones on tool selection more often.
- Lead with an action verb.
- Put format examples in parameter descriptions.
- Clarify close tool pairs with short see-also wording.

References:
- arXiv 2602.14878: https://arxiv.org/abs/2602.14878
- Anthropic tool-use docs: https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/implement-tool-use
- Anthropic Python SDK docs: https://docs.anthropic.com/en/api/client-sdks

## Score Summary

| Variant | Accepted Match | Exact Primary Match |
|---|---:|---:|
| Current | 57/58 (98.3%) | 57/58 (98.3%) |
| Rewritten | 56/58 (96.5%) | 56/58 (96.5%) |

## Decision

Do not apply the current rewrite set to `crates/aeon-frontend/src/service.rs`.

- The rewritten set scored worse on the live eval: `56/58` vs `57/58`.
- The regression came from `get_function_at`, which became more attractive on an "explain this function / show reduced IL" query and caused an unnecessary extra tool call.
- Because the delta is negative and small, this is not a clear win. Keep the current shipped descriptions and iterate on the confusing tool family before changing production tool metadata.

## Per-Tool Delta

| Tool | Current F1 | Rewritten F1 | Delta |
|---|---:|---:|---:|
| `add_hypothesis` | 1.0000 | 1.0000 | +0.0000 |
| `define_struct` | 1.0000 | 1.0000 | +0.0000 |
| `find_call_paths` | 1.0000 | 1.0000 | +0.0000 |
| `get_asm` | 1.0000 | 1.0000 | +0.0000 |
| `get_bytes` | 1.0000 | 1.0000 | +0.0000 |
| `get_coverage` | 1.0000 | 1.0000 | +0.0000 |
| `get_data` | 1.0000 | 1.0000 | +0.0000 |
| `get_function_at` | 0.8571 | 0.7500 | -0.1071 |
| `get_function_cfg` | 1.0000 | 1.0000 | +0.0000 |
| `get_function_il` | 1.0000 | 1.0000 | +0.0000 |
| `get_function_pointers` | 1.0000 | 1.0000 | +0.0000 |
| `get_il` | 1.0000 | 1.0000 | +0.0000 |
| `get_reduced_il` | 0.8889 | 0.8889 | +0.0000 |
| `get_ssa` | 1.0000 | 1.0000 | +0.0000 |
| `get_stack_frame` | 1.0000 | 1.0000 | +0.0000 |
| `get_string` | 1.0000 | 1.0000 | +0.0000 |
| `get_xrefs` | 0.8000 | 0.8000 | +0.0000 |
| `list_functions` | 1.0000 | 1.0000 | +0.0000 |
| `load_binary` | 1.0000 | 1.0000 | +0.0000 |
| `rename_symbol` | 1.0000 | 1.0000 | +0.0000 |
| `scan_pointers` | 1.0000 | 1.0000 | +0.0000 |
| `scan_vtables` | 1.0000 | 1.0000 | +0.0000 |
| `search_analysis_names` | 1.0000 | 1.0000 | +0.0000 |
| `search_rc4` | 1.0000 | 1.0000 | +0.0000 |
| `set_analysis_name` | 1.0000 | 1.0000 | +0.0000 |

## Candidate Rewrites Tested

| Tool | Before | After |
|---|---|---|
| `load_binary` | Load an ELF binary for analysis. Must be called before other tools. | Load the ELF at path so other aeon tools can query it. |
| `list_functions` | List functions discovered from .eh_frame unwind tables. Supports pagination and name filtering. | List discovered functions; filter by name or paginate. |
| `set_analysis_name` | Backwards-compatible alias for rename_symbol. Attaches or overwrites a semantic symbol on an address. | Alias of rename_symbol: set a semantic name at addr. |
| `rename_symbol` | Attach or overwrite a semantic symbol name on an address. | Name addr with a semantic symbol. |
| `define_struct` | Attach or overwrite a structure definition on an address. | Attach a struct definition to addr. |
| `add_hypothesis` | Record a semantic hypothesis on an address. Duplicate notes are ignored. | Attach an analyst note to addr. |
| `search_analysis_names` | Search analysis names attached to addresses using a regex pattern. | Find named addresses by regex. |
| `get_il` | Get the lifted AeonIL intermediate language listing for the function containing a given address. | Lift function at addr to raw AeonIL. Use get_reduced_il or get_ssa for cleaner IR. |
| `get_function_il` | Backwards-compatible alias for get_il. | Alias of get_il: lift function at addr to raw AeonIL. |
| `get_reduced_il` | Return block-structured reduced AeonIL for the function containing a given address. | Lift function at addr to reduced IL. Use get_ssa for SSA form. |
| `get_ssa` | Return reduced SSA form for the function containing a given address, optionally optimized. | Lift function at addr to SSA. Use get_reduced_il for non-SSA IR. |
| `get_stack_frame` | Summarize the detected stack frame and visible stack-slot accesses for the function containing a given address. | Show the stack frame and stack-slot accesses for function at addr. |
| `get_function_cfg` | Get the Control Flow Graph for a function. Returns adjacency list, terminal blocks, and reachability from Datalog analysis. | Graph control flow for function at addr. |
| `get_xrefs` | Get cross-references for an address: outgoing calls from the function, and incoming calls from other functions. | List callers and callees for function at addr. |
| `scan_pointers` | Scan non-executable mapped sections for pointer-sized values that reference other locations in the binary, classifying data-to-data and data-to-code edges. | Scan mapped data for internal pointers. Use get_function_pointers for one function. |
| `scan_vtables` | Detect candidate C++ vtables in .rodata/.data-style sections by finding arrays of function pointers and grouping related tables. | Scan mapped data for candidate C++ vtables. |
| `get_function_pointers` | Enumerate pointer-valued operands and resolved code/data references for one function or a paginated slice of functions. | List code and data pointers used by function at addr, or scan many functions. |
| `find_call_paths` | Find shortest and optionally all bounded call-graph paths between two functions using direct calls and vtable-resolved indirect calls. | Find call paths from start_addr to goal_addr. |
| `get_bytes` | Read raw bytes from the binary at a virtual address. Returns hex-encoded string. | Read hex bytes at addr. Use get_data for hex plus ASCII. |
| `search_rc4` | Search for RC4 cipher implementations using Datalog behavioral subgraph isomorphism. Detects KSA (swap+256+mod256) and PRGA (swap+keystream XOR) patterns. | Find RC4 implementations. |
| `get_coverage` | Get IL lift coverage statistics: proper IL vs intrinsic vs nop vs decode errors. | Report IL lift coverage for the loaded binary. |
| `get_asm` | Disassemble ARM64 instructions between two virtual addresses. Returns asm only, without AeonIL. | Disassemble ARM64 from start_addr to stop_addr. |
| `get_function_at` | Find the function containing a given address. Returns function metadata by default, and can optionally attach asm and/or AeonIL listings. | Show the function containing addr; set include_asm or include_il to inline code. |
| `get_string` | Read a null-terminated string at any virtual address (works across all ELF segments, not just .text). | Read a null-terminated string at addr. |
| `get_data` | Read raw bytes at any virtual address (works across all ELF segments). Returns hex + ASCII. | Read bytes plus ASCII at addr. Use get_bytes for hex only. |

## Parameter Changes

### `load_binary`
- `load_binary.path`: `Path to ELF binary` -> `ELF path like samples/hello_aarch64.elf`

### `list_functions`
- `list_functions.limit`: `Max results` -> `Max results like 100`
- `list_functions.name_filter`: `Substring filter on symbol name` -> `Symbol substring like recv`
- `list_functions.offset`: `Start index` -> `Start index like 0`

### `set_analysis_name`
- `set_analysis_name.addr`: `Virtual address in hex` -> `Hex address like 0x5e611fc`
- `set_analysis_name.name`: `Analysis name to assign to the address` -> `Semantic name like packet_dispatch`

### `rename_symbol`
- `rename_symbol.addr`: `Virtual address in hex` -> `Hex address like 0x5e611fc`
- `rename_symbol.name`: `Semantic symbol name to assign to the address` -> `Semantic name like packet_dispatch`

### `define_struct`
- `define_struct.addr`: `Virtual address in hex` -> `Hex address like 0x5e611fc`
- `define_struct.definition`: `Structure definition text` -> `Struct text like Packet { len: u32, data: char* }`

### `add_hypothesis`
- `add_hypothesis.addr`: `Virtual address in hex` -> `Hex address like 0x5e611fc`
- `add_hypothesis.note`: `Hypothesis or analyst note` -> `Analyst note like Likely decrypt loop`

### `search_analysis_names`
- `search_analysis_names.pattern`: `Regex pattern matched against analysis names` -> `Regex like ^rc4_.*$`

### `get_il`
- `get_il.addr`: `Any virtual address in hex, e.g. '0x5e611fc'` -> `Hex address like 0x5e611fc`

### `get_function_il`
- `get_function_il.addr`: `Any virtual address in hex, e.g. '0x5e611fc'` -> `Hex address like 0x5e611fc`

### `get_reduced_il`
- `get_reduced_il.addr`: `Any virtual address in hex, e.g. '0x5e611fc'` -> `Hex address like 0x5e611fc`

### `get_ssa`
- `get_ssa.addr`: `Any virtual address in hex, e.g. '0x5e611fc'` -> `Hex address like 0x5e611fc`
- `get_ssa.optimize`: `Run SSA optimization passes before returning JSON` -> `Run SSA cleanup before returning JSON`

### `get_stack_frame`
- `get_stack_frame.addr`: `Any virtual address in hex, e.g. '0x5e611fc'` -> `Hex address like 0x5e611fc`

### `get_function_cfg`
- `get_function_cfg.addr`: `Function address in hex` -> `Function address like 0x5e611fc`

### `get_xrefs`
- `get_xrefs.addr`: `Function address in hex` -> `Function address like 0x5e611fc`

### `get_function_pointers`
- `get_function_pointers.addr`: `Optional function address in hex; when present, analyzes the containing function` -> `Optional function address like 0x5e611fc`
- `get_function_pointers.limit`: `Max functions to analyze when addr is omitted` -> `Max functions like 50 when addr is omitted`
- `get_function_pointers.offset`: `Start index when scanning multiple functions` -> `Start index like 0`

### `find_call_paths`
- `find_call_paths.goal_addr`: `Goal function address in hex` -> `Goal function address like 0x5e61234`
- `find_call_paths.include_all_paths`: `Include all simple paths up to max_depth` -> `Return all simple paths up to max_depth`
- `find_call_paths.max_depth`: `Maximum call depth to explore` -> `Max call depth like 6`
- `find_call_paths.max_paths`: `Maximum number of paths to return when include_all_paths is true` -> `Max returned paths like 32 when include_all_paths is true`
- `find_call_paths.start_addr`: `Start function address in hex` -> `Start function address like 0x5e611fc`

### `get_bytes`
- `get_bytes.addr`: `Virtual address in hex` -> `Hex address like 0x5e611fc`
- `get_bytes.size`: `Number of bytes` -> `Byte count like 64`

### `get_asm`
- `get_asm.start_addr`: `Start virtual address in hex, e.g. '0x512025c'` -> `Hex start address like 0x512025c`
- `get_asm.stop_addr`: `Stop virtual address in hex (exclusive), e.g. '0x51202cc'` -> `Hex stop address like 0x51202cc`

### `get_function_at`
- `get_function_at.addr`: `Any virtual address in hex, e.g. '0x5e611fc'` -> `Hex address like 0x5e611fc`
- `get_function_at.include_asm`: `Include asm in the returned listing` -> `Attach asm to the result`
- `get_function_at.include_il`: `Include AeonIL in the returned listing` -> `Attach AeonIL to the result`

### `get_string`
- `get_string.addr`: `Virtual address in hex` -> `Hex address like 0x5e611fc`
- `get_string.max_len`: `Max bytes to scan for null terminator` -> `Max bytes to scan like 256`

### `get_data`
- `get_data.addr`: `Virtual address in hex` -> `Hex address like 0x5e611fc`
- `get_data.size`: `Number of bytes to read` -> `Byte count like 64`

## Notes

- Alias tools remain intentionally explicit, but the canonical tools now read as the default choice for generic requests.
- The biggest description wins should come from the confusing tool families: raw vs reduced vs SSA IR, bytes vs data vs string reads, and global pointer scans vs per-function pointer scans.
- If you later provide `ANTHROPIC_API_KEY`, the same runner can use the Anthropic Python SDK directly instead of the CLI fallback.
