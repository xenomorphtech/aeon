# Aeon MCP Tool Description Optimization Analysis

## Overview
Analysis of 31 aeon MCP tools in `/crates/aeon-frontend/src/service.rs` for LLM tool-calling quality improvements based on BFCL+ToolACE principles.

## Current State

### Tool Categories
1. **Binary Loading** (1): load_binary
2. **Function Discovery** (1): list_functions
3. **Semantic Annotation** (4): set_analysis_name, rename_symbol, define_struct, add_hypothesis
4. **Semantic Lookup** (2): search_analysis_names, get_blackboard_entry
5. **IL/SSA Analysis** (4): get_il, get_function_il, get_reduced_il, get_ssa
6. **Function Analysis** (3): get_stack_frame, get_function_cfg, get_function_skeleton
7. **Data Flow Analysis** (1): get_data_flow_slice
8. **Cross-Reference Analysis** (2): get_xrefs, find_call_paths
9. **Binary Scanning** (4): scan_pointers, scan_vtables, get_function_pointers, search_rc4
10. **Binary Inspection** (5): get_bytes, get_data, get_string, get_asm, get_function_at
11. **Datalog Queries** (1): execute_datalog
12. **Coverage** (1): get_coverage
13. **Emulation** (4): emulate_snippet_il, emulate_snippet_native, emulate_snippet, emulate_snippet_native_advanced

## Quality Issues Identified

### 1. **Vague/Incomplete Descriptions**
- `get_il`: "Get the lifted AeonIL intermediate language listing for the function containing a given address."
  - **Issue**: Doesn't explain WHEN to use vs `get_reduced_il` or `get_ssa`
  - **Impact**: LLM can't differentiate between similar tools

- `get_function_skeleton`: "Get a dense summary of function properties for efficient triage..."
  - **Issue**: "Efficient triage" is vague - what properties exactly?

- `add_hypothesis`: "Record a semantic hypothesis on an address."
  - **Issue**: No guidance on format, examples, or use cases

### 2. **Redundant/Confusing Aliases**
- `get_il` vs `get_function_il`: Both aliases, same behavior
  - **Issue**: LLM wastes consideration on two identical tools
  
- `set_analysis_name` vs `rename_symbol`: Nearly identical
  - **Improvement**: Only one should exist or clear differentiation needed

- `emulate_snippet` vs `emulate_snippet_native`: Same tool, different names
  - **Issue**: "emulate_snippet is alias for emulate_snippet_native" - confusing

### 3. **Missing Preconditions and Constraints**
- `get_il` through all analysis tools: No mention that `load_binary` must be called first
  - **Impact**: LLM might not establish proper ordering

- `execute_datalog`: "register" parameter is conditional ("Required for 'defines' and 'flows_to' queries")
  - **Issue**: Not clearly stated which queries require which parameters

- Emulation tools: No guidance on step_limit selection (when to use 100 vs 10000)

### 4. **Missing Use Cases/Examples**
Most tools lack concrete guidance on WHEN to use them:
- When to use `get_data_flow_slice` backward vs forward?
- When to use `scan_pointers` vs `scan_vtables`?
- When to use IL interpretation vs native emulation?

### 5. **Inconsistent Parameter Documentation**
- Some defaults stated in description: `get_bytes`: "Number of bytes", default: 64
- Some only in schema: `list_functions`: limit default 100 only in JSON schema
- Some parameters undefined: `find_call_paths.max_paths`: default 32 but not explained when it matters

### 6. **Unclear Output Formats**
- `scan_pointers`: "classifying data-to-data and data-to-code edges" - what is the output format?
- `get_data_flow_slice`: "slice" - is this a list of instructions? registers? CFG nodes?
- `search_rc4`: "Detects KSA...and PRGA patterns" - what constitutes a match?

### 7. **Missing Performance/Resource Guidance**
- Emulation tools: No guidance on complexity or when execution might timeout
- `scan_pointers`, `scan_vtables`: No mention of scan time/memory for large binaries
- Datalog queries: No guidance on when `limit: 500` is insufficient

## Optimization Opportunities

### High Priority (Affects Tool Selection)

**Issue 1: Remove Tool Aliases**
- Current: `get_il` and `get_function_il` both exist
- Fix: Keep one, remove the alias definition
- Impact: Reduces decision space for LLM by 3 tools

**Issue 2: Clarify Similar Tools**
- Current: `set_analysis_name` vs `rename_symbol` are redundant
- Fix: Consolidate to single tool or document exact difference
- Impact: Eliminates ambiguity in annotation decisions

**Issue 3: Add Use-Case Differentiation**
- Current: No guidance on when to use `get_il` vs `get_reduced_il` vs `get_ssa`
- Fix: Add "Use `get_il` when you need full IL with all details. Use `get_reduced_il` for block structure overview. Use `get_ssa` for data flow analysis."
- Impact: LLM can make intelligent tool selection

### Medium Priority (Affects Tool Effectiveness)

**Issue 4: Document Conditional Parameters**
- Current: `execute_datalog` has undocumented parameter requirements
- Fix: Add to description: "Parameters: query (required), addr (required), register (required for 'defines' and 'flows_to'), limit (optional)"
- Impact: Prevents parameter-missing errors

**Issue 5: Add Execution Guidance**
- Current: Emulation tools lack step_limit guidance
- Fix: "Use step_limit 100-1000 for short snippets, 10000+ for loops. Set conservatively to avoid timeouts."
- Impact: Better parameter choices

**Issue 6: Explain Output Formats**
- Current: `get_data_flow_slice` output unclear
- Fix: "Returns instruction addresses and registers involved in data flow from source to destination."
- Impact: Proper handling of results

### Lower Priority (Improves Description Quality)

**Issue 7: Add Examples**
- Add concrete examples: "`get_bytes` at 0x1000 with size 16 returns 16 bytes of hex string"
- Helps LLM ground understanding

**Issue 8: Cross-Reference Related Tools**
- In descriptions, mention when to use alternative tools
- Example: "For higher-level overview, use `get_function_skeleton`. For detailed analysis, use `get_il`."

**Issue 9: Document Memory/Time Tradeoffs**
- `emulate_snippet_il`: Faster but less accurate
- `emulate_snippet_native`: Slower but full emulation
- Help LLM choose based on time constraints

## Proposed Improvements Summary

| Tool | Issue Type | Current | Proposed | Impact |
|------|-----------|---------|----------|--------|
| get_il | Alias | Keep with get_function_il | Remove get_function_il | Reduce options |
| rename_symbol | Redundant | Keep with set_analysis_name | Clarify difference or consolidate | Reduce ambiguity |
| execute_datalog | Unclear | No param docs | Add param requirements | Prevent errors |
| get_data_flow_slice | Vague | No use case | Add when/why guidance | Better selection |
| emulate_snippet | Confusing | "Alias for native" | Rename or consolidate | Clearer intent |
| All analysis tools | Missing precondition | No load_binary mention | Add dependency note | Establish ordering |
| emulation tools | No guidance | step_limit undocumented | Add tuning advice | Better parameters |

## BFCL+ToolACE Principles Applied

1. **Clarity**: Remove ambiguity in tool selection
2. **Completeness**: Document all preconditions and parameters
3. **Differentiation**: Explain when to use each tool
4. **Consistency**: Standardize description format
5. **Examples**: Ground understanding with concrete cases

## Next Steps

1. Implement high-priority fixes (remove aliases, clarify similar tools)
2. Enhance medium-priority descriptions (add parameters, guidance)
3. Add examples and cross-references
4. Test improved descriptions with LLM function calling

