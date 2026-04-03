# Plan: Datalog Evolution In Aeon

## Executive Summary

aeon should keep Datalog, but not in its current imagined form.

The current codebase has two Datalog programs:

- `AeonAnalysis` in `crates/aeon/src/analysis.rs`, which computes intra-function reachability and terminal nodes from `inst_in_func` and `edge`.
- `Rc4Hunter` in `crates/aeon/src/rc4_search.rs`, which matches one RC4-oriented behavioral pattern over a tiny, ad hoc fact set.

That is enough to prove the direction, but not enough to justify `datalog_plugin.md` as written. The plugin design assumes a richer and more reusable fact database than aeon actually has today, and it assumes that compiling agent-authored `ascent!` code into host shared objects is a reasonable default query mechanism. It is not.

The right next step is:

1. Build a canonical per-function analysis pipeline that produces reduced IL, stack-slot-normalized IL, SSA, use/def, dominance, and solved constants.
2. Persist those results in `AeonEngine` as a reusable fact store.
3. Keep Datalog for recursive graph/dataflow/behavior matching.
4. Use direct SSA/query APIs for micro-slicing, exact def-use traversal, and other local value questions.
5. If arbitrary declarative queries are still desired later, expose a restricted in-process query layer over the persisted fact store, not JIT-compiled Rust loaded with `dlopen`.

## 1. Current Datalog Usage

### What exists today

#### `AeonAnalysis`

`crates/aeon/src/analysis.rs` defines:

```rust
relation inst_in_func(u64, u64);    // (func_addr, inst_addr)
relation edge(u64, u64);            // (src_addr, dst_addr)

relation internal_edge(u64, u64, u64); // (func, src, dst)
relation reachable(u64, u64, u64);     // (func, src, dst)
relation terminal(u64, u64);           // (func, addr)
```

Supported query behavior today:

- `AeonEngine::get_function_details()` populates `inst_in_func` and `edge`, runs the program, and returns:
  - `internal_edges`
  - `terminal_blocks`
  - `reachable_paths_count`
- This is surfaced through `AeonSession::get_function_details()` and `AeonSession::get_function_cfg()`.

This is a control-flow closure only. It is not a general fact database.

#### `Rc4Hunter`

`crates/aeon/src/rc4_search.rs` defines:

```rust
relation byte_load(u64, u64);      // (inst_addr, dest_var)
relation byte_store(u64, u64);     // (inst_addr, value_var)
relation is_xor(u64, u64, u64);    // (inst_addr, src1_var, src2_var)
relation flows_to(u64, u64);       // (producer_var, consumer_inst)
relation in_loop(u64);             // (inst_addr)

relation swap_detected(u64, u64, u64, u64);
relation keystream_xor_detected(u64);
```

Supported query behavior today:

- `search_rc4()` scans candidate functions.
- It does a cheap structural prefilter outside Datalog.
- It then runs `Rc4Hunter`.
- It classifies results as:
  - `RC4_PRGA (swap + keystream XOR)`
  - `RC4_KSA (swap + 256 loop + mod256)`
  - `swap_pattern (unconfirmed)`

### What fact extraction exists today

`rc4_search.rs` has a private `DataflowFacts` extractor that derives:

- `byte_loads`
- `byte_stores`
- `xors`
- `flows_to`
- `in_loop`
- `has_256_bound`
- `has_mod256`

Important limitations:

- Facts are extracted from raw lifted IL, not reduced IL.
- Loop detection is “backward edge => mark linear address interval” rather than CFG loop analysis.
- Dataflow is register-definition tracking via `RegisterEnv`, not SSA.
- `has_256_bound` and `has_mod256` are booleans outside the logic program, so the behavioral proof is split between Datalog and imperative heuristics.
- The extractor is RC4-specific and not reused anywhere else.

### What is missing

Compared with the roadmap and `datalog_plugin.md`, aeon currently lacks:

- A reusable fact database in `AeonEngine`.
- Any Datalog over reduced IL.
- Any Datalog over SSA.
- Any callgraph or interprocedural relations in the Datalog layer.
- Relations for stack slots, constants, comparisons, phi nodes, dominance, or solved values.
- A general query surface such as `execute_datalog`.
- Persistent per-function analysis caching.

`datalog_plugin.md` is notably ahead of reality. It describes input relations such as `def`, `use_of`, `load`, `store`, `is_add`, `is_sub`, `is_and`, `is_shift`, `is_call`, and `has_constant`, but the current code does not build or expose those relations.

### Frontend status

The frontend in `crates/aeon-frontend/src/service.rs` exposes `search_rc4` and CFG/IL tools, but there is no dynamic Datalog tool today. The roadmap’s proposed `execute_datalog(query_string)` does not exist yet.

## 2. What SSA And Reduced IL Change

The `aeon-reduce` side is now rich enough to support a much better fact model:

- `reduce_flags` can rewrite `SetFlags + CondBranch` into direct compare conditions.
- `reduce_stack` can rewrite SP/FP-relative memory into `StackSlot { offset, size }`.
- SSA types already model:
  - versioned variables
  - `Phi`
  - `Compare`
  - `CondSelect`
  - `StackSlot`
  - versioned flag values
- `UseDefMap` already computes def/use chains.
- `DomTree` already computes dominance.
- `SCCP` and `dead_branch` already compute solved constants and executable control flow.

That said, the current “full pipeline” is not actually full. `reduce_and_build_ssa()` in `crates/aeon-reduce/src/ssa/pipeline.rs` claims to do “intra-block reduce -> CFG -> SSA -> optimize”, but it currently:

1. builds a CFG from the input instruction list,
2. builds SSA,
3. optimizes SSA,

and does not call `reduce_block()` or `recognize_stack_frame()`.

That gap matters. If aeon emits facts from the current SSA pipeline as-is, it will miss:

- simplified compare patterns from `reduce_flags`
- stack slot normalization from `reduce_stack`
- literal/materialized constants from `resolve_adrp_add` and `resolve_movk_chains`
- normalized reduced IL forms that make pattern queries robust

## 3. Recommended Architecture

### Recommendation

Use a hybrid model:

- Direct SSA APIs for exact local reasoning:
  - slices
  - def-use walks
  - constant lookup
  - dominance checks
- Datalog for recursive and behavioral questions:
  - reachability
  - constrained path queries
  - loop-carried pattern matching
  - multi-instruction behavioral classification
  - interprocedural “source -> sink without sanitizer” style proofs

### Do not use the current dynamic plugin design as the default

`datalog_plugin.md` proposes:

1. agent writes arbitrary `ascent!` rules
2. aeon writes a Rust template
3. `rustc` compiles a shared object
4. aeon `dlopen`s it
5. facts are shipped as JSON in and results as JSON out

That is the wrong default mechanism now that SSA exists.

Problems with this approach:

- It requires a full Rust toolchain and dependency-path management at query time.
- It recompiles or cache-manages host code for every schema/query variant.
- It serializes a large fact set into JSON for every query.
- It couples the query surface to internal Rust/Ascent syntax.
- It is brittle around schema evolution.
- It is difficult to sandbox correctly.
- It duplicates information that should live persistently in the analysis session.

### What aeon should use instead

Near term:

- Keep Ascent for built-in, compiled analyses and template queries.
- Build a persistent `FactDb` over normalized reduced IL + SSA.
- Expose typed query tools such as:
  - `get_slice(...)`
  - `find_defs(...)`
  - `find_uses(...)`
  - `match_behavior(template, scope, params)`
  - `query_call_paths(...)`

Medium term:

- If arbitrary logic queries are still necessary, implement a restricted in-process query layer over the `FactDb`.
- That layer can still be Datalog-like, but it should consume stable relation names and a safe rule subset.
- If fully dynamic recursive evaluation is required, evaluate an embedded engine or a small internal Datalog IR, not host-side JIT Rust compilation.

Bottom line:

- Datalog is still the right analysis style for behavior matching.
- The JIT plugin design is not the right execution model.

## 4. Canonical Function Analysis Pipeline

aeon should have one canonical per-function normalization pipeline for all higher-level queries:

```text
decode + lift
  -> flatten pair / reduce_block
  -> recognize_stack_frame
  -> CFG
  -> SSA construction
  -> UseDefMap + DomTree
  -> SCCP / dead-branch / copy-prop / DCE / CSE
  -> facts
```

Concretely, aeon needs a new function-level analysis object, for example:

```rust
pub struct FunctionAnalysis {
    pub func_addr: u64,
    pub lifted: Vec<LiftedInst>,
    pub reduced: Vec<ReducedInst>,
    pub cfg: Cfg,
    pub ssa_raw: SsaFunction,
    pub ssa_opt: SsaFunction,
    pub use_def_raw: UseDefMap,
    pub use_def_opt: UseDefMap,
    pub dom_raw: DomTree,
    pub dom_opt: DomTree,
    pub facts: FactDb,
}
```

and `AeonEngine` should cache those analyses:

```rust
pub struct AeonEngine {
    semantic: HashMap<u64, SemanticContext>,
    functions: HashMap<u64, FunctionAnalysis>,
    // optional: interprocedural fact caches
}
```

Today `AeonSession` persists only semantic state in `analysis_state`, and `get_function_details()` creates a fresh `AeonEngine` and discards it immediately. That needs to change if aeon wants reusable Datalog facts.

## 5. Proposed Fact Schema

The schema should be layered. Reduced IL facts are useful for source-faithful evidence and address-accurate pattern matching. SSA facts are the main substrate for precise dataflow.

Implementation note:

- In memory, aeon should intern enums/strings to compact IDs.
- For readability, the schema below uses `String` names for `kind`, `cond`, and `loc_class`.

### 5.1 Core structural relations

```rust
relation func(u64);                                  // func_addr
relation block(u64, u64, u64);                       // block_id, func_addr, block_start_addr
relation stmt(u64, u64, u32);                        // stmt_id, block_id, stmt_index
relation stmt_in_func(u64, u64);                     // stmt_id, func_addr
relation stmt_origin_addr(u64, u64);                 // stmt_id, original_addr
relation stmt_synthetic(u64);                        // stmt_id (phi, synthetic clobber, rewritten branch)

relation block_edge(u64, u64);                       // src_block, dst_block
relation stmt_edge(u64, u64);                        // src_stmt, dst_stmt
relation entry_block(u64, u64);                      // func_addr, block_id

relation dominates(u64, u64);                        // dom_block, block
relation idom(u64, u64);                             // block, immediate_dom
relation back_edge(u64, u64);                        // src_block, dst_block
relation loop_header(u64);                           // block_id
relation loop_member(u64, u64);                      // header_block, member_block
relation loop_stmt(u64);                             // stmt_id

relation call_edge(u64, u64, u64);                   // caller_func, call_stmt, callee_func
relation maybe_call_edge(u64, u64, u64);             // caller_func, call_stmt, callee_func
```

Notes:

- `stmt_origin_addr` is required because current `SsaStmt` has no address field, and behavior-search results need address-level evidence.
- `stmt_synthetic` is needed for phi nodes and synthetic call clobber defs.

### 5.2 Reduced IL relations

These should be emitted after `reduce_block()` and `recognize_stack_frame()`.

```rust
relation ril_stmt_kind(u64, String);                 // stmt_id, assign|store|call|branch|cond_branch|ret|...

relation ril_def_reg(u64, String, u32, u8);          // stmt_id, loc_class, loc_index, width_bits
relation ril_use_reg(u64, String, u32, u8);          // stmt_id, loc_class, loc_index, width_bits
relation ril_const(u64, u64);                        // stmt_id, immediate_value

relation ril_load_size(u64, u8);                     // stmt_id, size_bytes
relation ril_store_size(u64, u8);                    // stmt_id, size_bytes
relation ril_call_target(u64, u64);                  // stmt_id, callee_addr

relation ril_branch_kind(u64, String);               // stmt_id, compare|zero|not_zero|bit_zero|bit_not_zero|flag
relation ril_branch_cond(u64, String);               // stmt_id, eq|ne|lt|...
relation ril_branch_reg_arg(u64, u8, String, u32, u8); // stmt_id, arg_index, loc_class, loc_index, width_bits
relation ril_branch_const_arg(u64, u8, u64);         // stmt_id, arg_index, imm

relation stack_slot(u64, u64, i64, u8);             // slot_id, func_addr, offset, size_bytes
relation ril_reads_slot(u64, u64);                   // stmt_id, slot_id
relation ril_writes_slot(u64, u64);                  // stmt_id, slot_id

relation ril_mem_base_reg(u64, String, u32);         // stmt_id, loc_class, loc_index
relation ril_mem_index_const(u64, i64);              // stmt_id, constant_offset
```

Why this layer matters:

- It preserves original statement addresses.
- It exposes stack slots before SSA has transformed everything.
- It makes direct compare patterns queryable after `reduce_flags`.
- It is a good source for “protocol parser” and “frame layout” queries.

### 5.3 SSA value and statement relations

These should be emitted from SSA after construction. Prefer emitting both raw SSA and optimized SSA, or at least preserve enough provenance to distinguish exact structure from solver-derived facts.

```rust
relation ssa_var(u64, u64, String, u32, u8, u32);    // var_id, func_addr, loc_class, loc_index, width_bits, version
relation ssa_entry_var(u64);                         // var_id (version 0)

relation ssa_stmt_kind(u64, String);                 // stmt_id, assign|store|call|branch|cond_branch|phi|setflags|...
relation ssa_def(u64, u64);                          // stmt_id, var_id
relation ssa_use(u64, u8, u64);                      // stmt_id, arg_index, var_id
relation ssa_use_count(u64, u32);                    // var_id, count

relation ssa_assign_op(u64, String);                 // stmt_id, imm|add|sub|mul|and|or|xor|shl|lsr|asr|ror|load|compare|condselect|...
relation ssa_arg_const(u64, u8, u64);                // stmt_id, arg_index, imm
relation ssa_arg_slot(u64, u8, u64);                 // stmt_id, arg_index, slot_id

relation ssa_load(u64, u64, u8);                     // stmt_id, dst_var, size_bytes
relation ssa_store(u64, u8);                         // stmt_id, size_bytes
relation ssa_call_target(u64, u64);                  // stmt_id, callee_addr

relation ssa_phi(u64, u64);                          // stmt_id, dst_var
relation ssa_phi_in(u64, u64, u64);                  // phi_stmt, pred_block, src_var

relation ssa_branch_kind(u64, String);               // stmt_id, compare|zero|not_zero|bit_zero|bit_not_zero|flag
relation ssa_branch_cond(u64, String);               // stmt_id, eq|ne|lt|...
relation ssa_branch_arg_var(u64, u8, u64);           // stmt_id, arg_index, var_id
relation ssa_branch_arg_const(u64, u8, u64);         // stmt_id, arg_index, imm

relation ssa_exact_const(u64, u64);                  // var_id, imm from direct defining stmt
relation ssa_solved_const(u64, u64);                 // var_id, imm proven by SCCP
relation ssa_executable_block(u64);                  // block_id
relation ssa_executable_edge(u64, u64);              // pred_block, succ_block

relation ssa_call_clobber(u64, u64);                 // call_stmt, var_id
```

Notes:

- `ssa_call_clobber` is necessary because the current SSA builder updates caller-saved register versions after `Call`, but those defs are implicit, not represented as statements.
- `ssa_exact_const` and `ssa_solved_const` should both exist. The first preserves syntax; the second captures propagated meaning.
- `arg_index` should follow a fixed convention:
  - assign/load ops: expression operands in source order
  - store: `0 = address`, `1 = value`
  - branch compare: `0 = lhs`, `1 = rhs`
  - call: `0 = target`

### 5.4 Optional data/rodata relations for behavior matching

For AES, CRC, protocol constants, and parser tables, aeon should add data relations too:

```rust
relation data_symbol(u64, String);                   // addr, symbol
relation data_u32(u64, u32);                         // addr, value
relation data_u64(u64, u64);                         // addr, value
relation table_candidate(u64, u64, u32, u32);       // table_id, base_addr, elem_size, entry_count
relation table_use(u64, u64, u64);                  // stmt_id, table_id, index_var
```

This is the missing bridge for table-driven crypto and parser-dispatch recognition.

## 6. Example Queries

The examples below use the proposed schema and are written in Ascent-style pseudocode.

### 6.1 RC4 PRGA swap + keystream XOR

```rust
relation rc4_swap(u64, u64, u64, u64);
rc4_swap(load_a, load_b, store_a, store_b) <--
    ssa_load(load_a, va, 1),
    ssa_load(load_b, vb, 1),
    ssa_store(store_a, 1),
    ssa_store(store_b, 1),
    ssa_use(store_a, 1, vb),        // arg 1 = stored value
    ssa_use(store_b, 1, va),
    loop_stmt(load_a),
    loop_stmt(store_a),
    if load_a != load_b,
    if store_a != store_b;

relation rc4_prga_xor(u64);
rc4_prga_xor(xor_stmt) <--
    ssa_assign_op(xor_stmt, "xor"),
    ssa_use(xor_stmt, _, key_byte),
    ssa_def(load_stmt, key_byte),
    ssa_load(load_stmt, key_byte, 1),
    loop_stmt(xor_stmt);
```

Compared with the current RC4 detector, this version does not need a private RC4-only extractor and can reuse general SSA facts.

### 6.2 Detect a packet parser that checks a length and then compares a magic

```rust
relation parser_magic_check(u64, u64, u64);
parser_magic_check(func, len_cmp, magic_cmp) <--
    stmt_in_func(len_cmp, func),
    stmt_in_func(magic_cmp, func),

    ril_branch_kind(len_cmp, "compare"),
    ril_branch_cond(len_cmp, "cs"),              // unsigned >=
    ril_branch_const_arg(len_cmp, 1, min_len),
    if min_len >= 4,

    ril_branch_kind(magic_cmp, "compare"),
    ril_branch_cond(magic_cmp, "eq"),
    ril_branch_const_arg(magic_cmp, 1, magic),
    if magic == 0xdeadbeef;
```

This is the kind of query that becomes much cleaner after `reduce_flags`.

### 6.3 Detect loop-carried ARX behavior for custom ciphers

```rust
relation arx_round(u64);
arx_round(func) <--
    stmt_in_func(add_stmt, func),
    stmt_in_func(xor_stmt, func),
    stmt_in_func(ror_stmt, func),

    ssa_assign_op(add_stmt, "add"),
    ssa_assign_op(xor_stmt, "xor"),
    ssa_assign_op(ror_stmt, "ror"),

    ssa_def(add_stmt, v_add),
    ssa_use(xor_stmt, 0, v_add),
    ssa_def(xor_stmt, v_xor),
    ssa_use(ror_stmt, 0, v_xor),

    loop_stmt(add_stmt),
    loop_stmt(xor_stmt),
    loop_stmt(ror_stmt);
```

This is the right generalization path for TEA/XTEA/ChaCha-like recognition.

### 6.4 Detect TEA/XTEA-like delta constants

```rust
relation tea_like(u64);
tea_like(func) <--
    stmt_in_func(add_stmt, func),
    ssa_assign_op(add_stmt, "add"),
    ssa_arg_const(add_stmt, _, 0x9e3779b9),
    loop_stmt(add_stmt);
```

This is not a full TEA proof, but it is a useful seed relation for a larger template.

### 6.5 Detect AES T-table style rounds

```rust
relation aes_ttable_candidate(u64);
aes_ttable_candidate(func) <--
    stmt_in_func(t0_stmt, func),
    stmt_in_func(t1_stmt, func),
    stmt_in_func(t2_stmt, func),
    stmt_in_func(t3_stmt, func),

    table_use(t0_stmt, tab0, idx0),
    table_use(t1_stmt, tab1, idx1),
    table_use(t2_stmt, tab2, idx2),
    table_use(t3_stmt, tab3, idx3),

    table_candidate(tab0, _, 4, 256),
    table_candidate(tab1, _, 4, 256),
    table_candidate(tab2, _, 4, 256),
    table_candidate(tab3, _, 4, 256),

    loop_stmt(t0_stmt),
    loop_stmt(t1_stmt),
    loop_stmt(t2_stmt),
    loop_stmt(t3_stmt);
```

This requires the optional table relations. Without them, AES detection will remain mostly imperative.

### 6.6 Detect field-by-field protocol parsing from a packet pointer

```rust
relation packet_field_load(u64, u64, i64);
packet_field_load(func, stmt, off) <--
    stmt_in_func(stmt, func),
    ssa_load(stmt, dst, size),
    if size == 1 || size == 2 || size == 4 || size == 8,
    ssa_use(stmt, 0, base),
    ssa_def(base_def, base),
    ssa_assign_op(base_def, "add"),
    ssa_arg_const(base_def, 1, off);

relation parser_candidate(u64);
parser_candidate(func) <--
    packet_field_load(func, _, 0),
    packet_field_load(func, _, 2),
    packet_field_load(func, _, 4),
    packet_field_load(func, _, 8);
```

This is intentionally approximate. The point is that aeon can match parser structure once loads, offsets, and compares are normalized.

## 7. How To Expand Fact Extraction

### Step 1: make function normalization canonical

Add a function-level reducer in `aeon-reduce`, not just `reduce_block`.

Something like:

```rust
pub fn normalize_function(instructions: &[(u64, Stmt, Vec<u64>)]) -> NormalizedFunction
```

It should:

- preserve original addresses,
- reduce statements,
- recognize stack frames,
- build CFG from reduced statements,
- build SSA,
- run optimization passes,
- retain both raw and optimized views when useful.

### Step 2: add provenance-aware SSA IDs

The fact layer needs stable IDs for:

- blocks
- statements
- SSA vars
- stack slots

and it needs provenance:

- original statement address
- synthetic/generated status
- source layer: raw reduced IL vs optimized SSA

Today `SsaStmt` has no address/provenance field, so aeon needs either:

- a side map from `stmt_id -> origin_addr`, or
- a new wrapper type that carries `stmt_id` and `origin_addr`.

### Step 3: emit both exact and solved facts

Do not force the entire fact layer to choose between source-faithful syntax and optimized semantics.

Emit:

- exact structural facts from reduced IL / raw SSA
- solved facts from SCCP / dead-branch

Examples:

- `ssa_exact_const(var, value)` from direct `Imm`
- `ssa_solved_const(var, value)` from SCCP
- `ssa_executable_edge(pred, succ)` from SCCP reachability

### Step 4: materialize implicit SSA events

The current SSA builder creates implicit caller-saved clobber defs after `Call` without emitting statements. Fact extraction must not lose that.

Options:

- emit synthetic clobber statements, or
- emit `ssa_call_clobber(call_stmt, var_id)` facts directly

Likewise, entry-version variables need `ssa_entry_var(var_id)` facts because they have no defining statement.

### Step 5: move RC4 onto the shared fact layer

After the shared fact schema exists:

- delete the private `DataflowFacts` path in `rc4_search.rs`
- rewrite RC4 detection to consume shared `FactDb` relations
- keep only RC4-specific rules, not RC4-specific extraction

That is the first proof that the new layer is actually reusable.

## 8. How Datalog Should Be Used Beyond RC4

### Good fits for Datalog

- reachability with exclusions
- loop membership and loop-carried state
- dataflow over def/use and phi joins
- behavioral motif detection
- interprocedural “source reaches sink” proofs
- cross-cutting joins between code, data tables, and semantic annotations

### Less good fits

- one-off local slices over a single SSA var
- exact constant folding and symbolic simplification
- ad hoc UI/listing transformations

Those should use direct Rust APIs over `UseDefMap`, `DomTree`, and the normalized IR.

### Concrete behavioral categories aeon can add

- AES:
  - T-table rounds
  - S-box + MixColumns style transforms
  - key-schedule constants (`Rcon`)
- ARX ciphers:
  - TEA/XTEA
  - ChaCha/Salsa-like quarter rounds
  - custom rotate/add/xor loops
- Hash/update loops:
  - rolling state in loop-carried phis
  - rotate/xor/add constants
- Protocol parsers:
  - length-guarded field extraction
  - magic/version compares
  - tag/dispatch trees
- Decrypt/decode stubs:
  - call -> loop -> XOR/add/sub table lookup -> store decoded bytes

## 9. Integration With `RegisterEnv` And SSA

### `RegisterEnv` should remain a normalization tool, not the final fact substrate

`RegisterEnv` is still useful for:

- ADRP/add resolution
- MOVK chain resolution
- simple intra-block substitution
- pre-SSA def tracking

But it should feed the fact layer indirectly via normalized reduced IL, not act as the persistent representation.

Why:

- it is block-local / forward-only,
- it does not represent join points,
- it does not model phi or dominance,
- it is not a stable session-level fact database.

### SSA should be the main fact substrate

SSA gives aeon what the Datalog layer actually needs:

- explicit versioned defs
- explicit uses
- loop-carried joins through `Phi`
- direct compare operands
- direct stack-slot expressions
- a clean place to attach solved constants and reachability

### Use `UseDefMap` and `DomTree` as fact builders

`UseDefMap` should directly populate:

- `ssa_def`
- `ssa_use`
- `ssa_use_count`

`DomTree` should directly populate:

- `dominates`
- `idom`

SCCP / dead-branch should populate:

- `ssa_solved_const`
- `ssa_executable_block`
- `ssa_executable_edge`

### Blackboard integration

`AeonEngine` already persists semantic context:

- renamed symbols
- struct definitions
- hypotheses

The fact system should join with that state.

Useful relations:

```rust
relation semantic_symbol(u64, String);               // addr, symbol
relation semantic_struct(u64, String);               // addr, definition
```

I would not put free-form `hypothesis` text directly into first-class logic relations yet. That is better treated as annotation until aeon grows typed hypothesis categories.

## 10. Concrete Next Steps

### Phase 1: make facts real

- Add a canonical function normalization pipeline in `aeon-reduce`.
- Cache per-function analyses in `AeonEngine`.
- Emit the core structural, reduced IL, and SSA facts listed above.
- Add provenance IDs for SSA statements.

### Phase 2: migrate existing analyses

- Rebuild `search_rc4()` on top of the shared fact layer.
- Rebuild `get_function_cfg()` on top of cached facts.
- Add reusable loop and reachability helpers on top of the fact DB.

### Phase 3: expose query tools

- Add typed tools for:
  - slices
  - def-use
  - behavior templates
  - constrained reachability
- Do not start with arbitrary JIT Datalog.

### Phase 4: optional restricted declarative query layer

- Add a stable, in-process logic/query surface over the persisted `FactDb`.
- Keep it schema-aware and safe.
- Only revisit arbitrary dynamic rule compilation if there is a concrete need that the restricted layer cannot satisfy.

## Final Recommendation

The right answer is not “replace Datalog because SSA exists.” The right answer is:

- keep Datalog as aeon’s behavioral and recursive query engine,
- move fact extraction onto normalized reduced IL plus SSA,
- stop treating RC4 extraction as a one-off,
- do not use the current JIT shared-library plugin design as the default query path,
- use direct SSA APIs and Datalog together, with each handling the class of problem it is actually good at.
