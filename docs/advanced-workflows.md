# Advanced Aeon Analysis Workflows

Sophisticated patterns for complex binary analysis tasks using aeon's MCP tools.

## Table of Contents

1. [Vulnerability Classification](#vulnerability-classification)
2. [Cryptographic Implementation Analysis](#cryptographic-implementation-analysis)
3. [Reverse Engineering Protocol Handlers](#reverse-engineering-protocol-handlers)
4. [Dynamic Behavior Simulation](#dynamic-behavior-simulation)
5. [Supply Chain Analysis](#supply-chain-analysis)

---

## Vulnerability Classification

**Goal**: Automatically classify and prioritize security issues in binaries.

**Workflow**:
```
1. Enumerate all functions → list_functions()
2. For each function:
   a. Get skeleton → get_function_skeleton()
   b. Look for dangerous patterns (strcpy, sprintf, system, etc.)
   c. Tag with set_analysis_name("vuln_candidate_<pattern>")
3. Search all candidates → search_analysis_names("vuln_candidate_.*")
4. For each candidate:
   a. Map callers → get_xrefs()
   b. Find paths from untrusted input → find_call_paths()
   c. Analyze preconditions → get_il() + examine branches
5. Classify severity:
   - CRITICAL: Reachable from network input, no validation
   - HIGH: Reachable but with validation bypass possibility
   - MEDIUM: Requires specific conditions
   - LOW: Requires significant preconditions
```

**Example: Buffer Overflow Hunter**
```
Phase 1: Scan for strcpy patterns
  → get_function_skeleton() for all functions
  → Filter those with string operations
  → Annotate: set_analysis_name("strcpy_site_0x40xxxx")

Phase 2: Check input sources
  → find_call_paths(start="recv", goal="strcpy_site")
  → If path exists: POTENTIAL VULNERABILITY
  → Analyze path for validation

Phase 3: Verify exploitability
  → get_il(addr="strcpy_site")
  → Check buffer size vs input length
  → emulate_snippet_native() with oversized input
  → If crash/overflow: CONFIRMED VULNERABILITY
```

---

## Cryptographic Implementation Analysis

**Goal**: Characterize cryptographic implementations and identify non-standard variants.

**Workflow**:
```
Phase 1: Identify Crypto Functions
  1. search_rc4() → Find RC4 implementations
  2. scan_pointers() → Find S-boxes, round constants
  3. get_function_skeleton() → Look for crypto patterns
     - Large constants (AES: 0x0102..., DES: 0x98765..., etc.)
     - Loops with 256+ iterations (key schedules)
     - XOR-heavy operations
  4. search_analysis_names() → Find prior annotations

Phase 2: Algorithm Identification
  1. For each candidate:
     a. get_il() → Full instruction listing
     b. Look for characteristic patterns:
        - AES: SubBytes, ShiftRows, MixColumns, AddRoundKey
        - SHA: Logical ops (Ch, Maj), additions mod 2^32
        - RSA: Modular exponentiation with large moduli
  2. Measure IL coverage → get_coverage()
     - >95%: Trust IL-level analysis
     - 75-95%: Supplement with emulation
     - <75%: Heavy obfuscation, use emulate_snippet_native()

Phase 3: Security Assessment
  1. Key storage → scan_pointers() + get_data()
     - Embedded keys: CRITICAL (keys visible in binary)
     - Derived keys: Check derivation function
     - External keys: Verify handling (not logged, memory cleared)
  2. Implementation quality → get_il() inspection
     - Constant-time operations: Look for timing-safe patterns
     - Side-channel resistance: Analyze memory access patterns
     - Standard compliance: Compare against known implementations

Phase 4: Non-standard Variant Detection
  1. Custom parameters:
     a. get_il() on key expansion → Look for non-standard constants
     b. emulate_snippet_native() with known test vectors
     c. Compare output against standard implementations
  2. Modified algorithms:
     a. Analyze round count: get_function_skeleton() → loop detection
     b. Check for weakened operations (fewer rounds, simplified logic)
     c. Test against vectors: emulate_snippet_native() validation
```

**Example: AES Variant Detection**
```
1. Identify AES candidate
   → search_analysis_names("^crypto_.*AES")
   → get_function_skeleton() confirms: 4 args, 256+ bytes stack

2. Extract characteristic constants
   → get_data() at suspected S-box location
   → Compare first 16 bytes against standard AES S-box
   → If mismatch: MODIFIED S-BOX

3. Check key schedule
   → find_call_paths(start="init", goal="key_expansion")
   → get_il() on key expansion function
   → Look for Rcon constants (0x01, 0x02, 0x04, ...)
   → If different: CUSTOM KEY SCHEDULE

4. Validate with emulation
   → emulate_snippet_native() with known test vector
   → Compare against openssl output
   → If match: LIKELY STANDARD AES (with possible obfuscation)
   → If different: CUSTOM VARIANT (requires reverse engineering)

5. Assess security impact
   → If standard: analyze implementation quality (timing, memory)
   → If variant: investigate reason (licensing, performance, security)
```

---

## Reverse Engineering Protocol Handlers

**Goal**: Understand binary communication protocols and message formats.

**Workflow**:
```
Phase 1: Identify Message Processing
  1. Find network I/O:
     → search_analysis_names(".*recv.*|.*read.*")
     → Get xrefs to network functions
  2. Trace message flow:
     → find_call_paths(start="recv", goal="message_processor")
     → Map processing pipeline

Phase 2: Locate Format Parsing
  1. For each processing function:
     a. get_function_skeleton() → Identify loops and branches
     b. get_il() → Examine byte/field extraction patterns
     c. Look for hardcoded offsets (accessing buf[0], buf[4], etc.)
  2. Use data flow analysis:
     → get_data_flow_slice(direction="forward")
     → Track how input bytes transform into decisions

Phase 3: Define Message Structure
  1. Identify offset patterns:
     → Bytes 0-3: Often magic/type (search: 0x12345678 pattern)
     → Bytes 4-7: Often length field (search: comparisons with constants)
     → Remaining: Payload with fields
  2. Use emulation to validate:
     → emulate_snippet_native() with crafted messages
     → Observe which bytes trigger different paths
  3. Define struct:
     → define_struct(addr="...", definition="{
        u32 magic;
        u32 length;
        u8 cmd;
        u8 flags;
        u8 reserved[2];
        u8 payload[256];
     }")

Phase 4: Command Handler Mapping
  1. Locate dispatch table:
     → scan_vtables() or scan_pointers()
     → Look for arrays of function pointers
  2. Map commands to handlers:
     → For each entry: get_function_at()
     → Annotate: set_analysis_name("cmd_handler_<cmd_id>")
  3. Analyze each handler:
     → get_il() to understand behavior
     → emulate_snippet_native() with different payloads
     → Extract response format

Phase 5: State Machine Analysis
  1. Build state graph:
     → get_function_cfg() for each handler
     → Identify state variables (usually at fixed offsets)
  2. Trace transitions:
     → find_call_paths() between handlers
     → Document valid sequences (authentication → data → logout)
  3. Find state confusion bugs:
     → Look for handlers accessible without prior authentication
     → emulate_snippet_native() with invalid transitions
```

**Example: TLS Handshake Handler Reverse Engineering**
```
1. Find ClientHello processor
   → search_analysis_names(".*client.*hello")
   → get_il() to identify parsing

2. Extract message format
   → Observe:
     - First 3 bytes: likely version (0x03 0x03 = TLS 1.2)
     - Next 32 bytes: random nonce
     - Variable length: session ID
   → define_struct() with proper layout

3. Identify supported ciphers
   → get_il() shows loop reading 2-byte cipher codes
   → Collect observed codes: 0x002f (AES-128-SHA), etc.
   → Map to standard names

4. Find ServerHello handler
   → find_call_paths(start="ClientHello_handler", goal="ServerHello_handler")
   → get_il() to understand cipher selection logic

5. Validate with emulation
   → emulate_snippet_native() with valid ClientHello
   → Observe which cipher is selected
   → emulate_snippet_native() with forced unsupported cipher
   → Does it fail gracefully?
```

---

## Dynamic Behavior Simulation

**Goal**: Execute and analyze code behavior without running the full binary.

**Workflow**:
```
Phase 1: Identify Target Code
  1. Find interesting snippet:
     → Search for pattern: encryption loop, decompression, parsing
     → get_function_skeleton() to assess size/complexity
  2. Determine dependencies:
     → get_data_flow_slice(direction="backward")
     → Identify required inputs (what registers/memory needed)

Phase 2: Prepare Simulation Environment
  1. Initialize registers:
     → Identify function parameters and calling convention
     → Set x0-x7 for arguments (or stack if many args)
     → Set sp, lr as appropriate
  2. Prepare memory:
     → Allocate buffers for input data
     → Map data structures needed
     → Set up constants/tables
  3. Set step budget:
     → Estimate instruction count: ~10 per byte processed
     → For safety: budget = estimated * 5

Phase 3: Execute and Observe
  1. Run emulation:
     → emulate_snippet_native(start, end, registers, memory, step_limit)
  2. Analyze results:
     → final_registers: Output values (return value in x0)
     → memory_writes: Side effects, output buffers
     → decoded_strings: Extracted plaintext, error messages
     → stop_reason: Why execution stopped

Phase 4: Validate and Refine
  1. Cross-check outputs:
     → Compare against expected behavior (if known)
     → Try with different inputs
  2. Debug failures:
     → If step_limit hit: Increase budget or reduce range
     → If missing memory: Add to initial_memory map
     → If wrong output: Check input setup, calling convention
  3. Automate validation:
     → Test against multiple known vectors
     → Build confidence in extracted behavior

Phase 5: Extract Behavior Description
  1. Document findings:
     → add_hypothesis(addr="...", note="decrypts_with_key_from_x0")
  2. Create helper:
     → In agent code: Create wrapper showing exactly what was learned
```

**Example: String Decryption Loop Simulation**
```
1. Identify target
   → get_il() shows loop at 0x40xxxx
   → Loop processes each byte: xor with key, add constant, shift

2. Setup environment
   → initial_registers:
     x0: ptr to encrypted string (e.g., 0x7fff8000)
     x1: key value
   → initial_memory:
     0x7fff8000: encrypted_bytes (e.g., "encrypted_string")
   → step_limit: 500

3. Execute
   → result = emulate_snippet_native(0x40xxxx, 0x40xyyy, regs, mem, 500)
   → decoded_strings: ["hello"] ← Success!

4. Validate
   → Try with different key: Different decryption
   → Try with shorter string: Still works
   → Try with invalid key: Garbled output

5. Document
   → set_analysis_name("string_decrypt_xor_key")
   → add_hypothesis(note="simple_xor_with_constant_add_obfuscation")
```

---

## Supply Chain Analysis

**Goal**: Identify third-party code, vendors, and suspicious patterns that indicate compromise.

**Workflow**:
```
Phase 1: Identify Code Sections
  1. Scan for known signatures:
     → search_analysis_names("openssl|boringssl|libcrypto")
     → Look for standard library symbols
  2. Detect obfuscated libraries:
     → get_function_skeleton() for all functions
     → Look for functions with unusual patterns:
       - Many local variables (often library code)
       - Large instruction counts (algorithms)
       - Complex control flow (legitimate business logic)

Phase 2: Extract Version Information
  1. Search for version strings:
     → get_string() at common locations
     → Look for patterns: "1.2.3", "v2.0", etc.
  2. Search for build dates:
     → get_data() in binary info sections
     → Look for timestamp patterns
  3. Use heuristics:
     → get_function_skeleton() → crypto patterns
     → Compare against known library characteristics

Phase 3: Analyze Dependency Graph
  1. Build call graph:
     → execute_datalog(query="call_graph_transitive", addr="main")
     → Map all reachable functions
  2. Identify library boundaries:
     → Functions with consistent naming patterns (lib_*)
     → Isolated call graphs (library doesn't call application)
  3. Find unexpected dependencies:
     → If crypto library calls network: SUSPICIOUS
     → If compression library calls system(): SUSPICIOUS

Phase 4: Detect Supply Chain Compromise
  1. Look for backdoors:
     → find_call_paths(start="trusted_input", goal="system_call")
     → Without validation: POTENTIAL VULNERABILITY
     → Unusual file access patterns
  2. Check for data exfiltration:
     → get_xrefs() for network functions
     → Are they called from libraries unexpectedly?
  3. Verify cryptographic usage:
     → find_call_paths() from network handlers to crypto
     → Does encryption/decryption follow expected patterns?

Phase 5: Build Evidence Report
  1. Document findings:
     → List identified libraries with versions
     → Map dependencies and trust boundaries
     → Note any suspicious patterns
  2. Create analysis summary:
     → Identify high-risk components
     → Flag potential compromises
     → Recommend further investigation
```

**Example: Vendor Library Supply Chain Check**
```
1. Find OpenSSL usage
   → search_analysis_names("EVP_|CRYPTO_|SSL_")
   → Count occurrences across binary

2. Extract version
   → get_string() at .rodata locations
   → Find "OpenSSL 1.1.1a" or similar

3. Check for unusual modifications
   → get_il() on EVP_Encrypt function
   → Compare against known OpenSSL source
   → If modified: investigate why

4. Analyze call patterns
   → find_call_paths(start="network_recv", goal="EVP_Decrypt")
   → Is decryption called for network data? (Normal)
   → get_il() to verify no key extraction or logging

5. Document
   → OpenSSL 1.1.1a (standard version)
   → Used for HTTPS/TLS (expected)
   → No suspicious modifications detected
   → ASSESSMENT: Standard dependency
```

---

## Best Practices for Advanced Workflows

### Performance Optimization
- Use `get_function_skeleton()` before `get_il()` to estimate complexity
- Batch similar operations: multiple `execute_datalog()` calls together
- Cache results: don't re-query the same address
- Use `offset/limit` pagination for large function lists

### Robustness
- Always check `get_coverage()` before trusting IL analysis
- Validate emulation results against multiple test cases
- Use `emulate_snippet_native_advanced()` for complex scenarios
- Combine multiple analysis approaches (IL + emulation + heuristics)

### Documentation
- Use `set_analysis_name()` consistently with patterns
- Document findings incrementally with `add_hypothesis()`
- Create structured output with `define_struct()`
- Build chains of evidence, not assumptions

### Troubleshooting
- If IL lift is poor (<85%): Use `get_asm()` for raw assembly
- If emulation fails: Check `initial_memory` and register initialization
- If paths don't connect: Use `scan_pointers()` for indirect calls
- If functions missing: Check if they're in `.eh_frame` or dynamic code

---

## Common Analysis Recipes

### Recipe: Find All Crypto Key Derivation Points
```
1. search_analysis_names(".*key.*deriv.*")
2. For each result:
   a. get_xrefs() - who calls this?
   b. get_data_flow_slice(direction="backward") - where does key come from?
   c. add_hypothesis() - document key sources
```

### Recipe: Trace Data from Network to Storage
```
1. find_call_paths(start="recv", goal="write_to_file")
2. For each path:
   a. get_il() at each step
   b. Look for transformations (encryption, compression, validation)
   c. Record what modifications happen
```

### Recipe: Identify State Machine Implementation
```
1. get_function_skeleton() for all functions
2. Filter for consistent naming (state_*, handle_*, process_*)
3. get_function_cfg() for each
4. Look for common blocks (error handling, validation)
5. execute_datalog(query="reachability") to understand state transitions
```

---

## Integration with External Tools

### Combining with IDA Pro / Ghidra
- Use aeon for automated pattern detection
- Use IDA/Ghidra for visualization
- Export findings from aeon: `set_analysis_name()`, `add_hypothesis()`
- Import hypotheses: Use aeon results to guide manual analysis

### Combining with AFL / Fuzzing
- Use aeon to identify input handling
- Identify valid message formats with emulation
- Use fuzz harnesses to find crashes at identified locations

### Combining with YARA / Signatures
- Use aeon to extract constants, magic numbers
- Generate YARA rules based on findings
- Use signatures to identify library versions
- Refine rules based on aeon analysis

---

## Next Steps

For more detailed examples and workflow variations, see:
- `docs/analysis-workflows.md` - Foundation workflows
- Specific tool documentation in README.md
- Tool schemas via `GET /tools` in HTTP API

