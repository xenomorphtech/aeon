# API Integration Plan For `aeon-reduce`

This plan focuses on the current API/frontend boundary:

- [roadmap.md](/home/sdancer/aeon/roadmap.md)
- [docs/next-steps.md](/home/sdancer/aeon/docs/next-steps.md)
- [docs/reduction-test-corpus.md](/home/sdancer/aeon/docs/reduction-test-corpus.md)
- [crates/aeon-frontend/src/service.rs](/home/sdancer/aeon/crates/aeon-frontend/src/service.rs)
- [crates/aeon-frontend/src/main.rs](/home/sdancer/aeon/crates/aeon-frontend/src/main.rs)
- [crates/aeon/src/api.rs](/home/sdancer/aeon/crates/aeon/src/api.rs)
- [crates/aeon-reduce/src/pipeline.rs](/home/sdancer/aeon/crates/aeon-reduce/src/pipeline.rs)
- [crates/aeon-reduce/src/reduce_stack.rs](/home/sdancer/aeon/crates/aeon-reduce/src/reduce_stack.rs)
- [crates/aeon-reduce/src/ssa/pipeline.rs](/home/sdancer/aeon/crates/aeon-reduce/src/ssa/pipeline.rs)
- [crates/aeon-reduce/src/ssa/cfg.rs](/home/sdancer/aeon/crates/aeon-reduce/src/ssa/cfg.rs)

## Current State

The integration gap is mostly at the `aeon` API boundary, not in the frontend transport:

- `aeon-frontend` already has the right architecture for new tools. Both MCP and HTTP are thin wrappers over `AeonFrontend::call_tool()` and `tools_list()` in [crates/aeon-frontend/src/service.rs](/home/sdancer/aeon/crates/aeon-frontend/src/service.rs).
- `AeonSession::get_il()` in [crates/aeon/src/api.rs](/home/sdancer/aeon/crates/aeon/src/api.rs) still builds listings by decoding bytes and emitting `format!("{:?}", stmt)` strings through `render_instruction_listing()`.
- `aeon-reduce` already has the core primitives:
  - `reduce_block()` in [crates/aeon-reduce/src/pipeline.rs](/home/sdancer/aeon/crates/aeon-reduce/src/pipeline.rs)
  - `build_ssa()` in [crates/aeon-reduce/src/ssa/construct.rs](/home/sdancer/aeon/crates/aeon-reduce/src/ssa/construct.rs)
  - `optimize_ssa()` and `reduce_and_build_ssa()` in [crates/aeon-reduce/src/ssa/pipeline.rs](/home/sdancer/aeon/crates/aeon-reduce/src/ssa/pipeline.rs)
- Two important reducer gaps remain:
  - `reduce_block()` does not yet call `recognize_stack_frame()`.
  - `reduce_and_build_ssa()` still builds CFG/SSA from raw lifted statements instead of reduced blocks.
- There is one design mismatch to resolve during integration:
  - `reduce_block()` is block-local.
  - `reduce_stack::detect_prologue()` and `recognize_stack_frame()` are function-context-sensitive because prologue detection depends on the start of the function.
- The decode/lift path is duplicated in multiple places:
  - `render_instruction_listing()` in [crates/aeon/src/api.rs](/home/sdancer/aeon/crates/aeon/src/api.rs)
  - `AeonEngine::ingest_function()` in [crates/aeon/src/engine.rs](/home/sdancer/aeon/crates/aeon/src/engine.rs)
  - call/xref/coverage scans in [crates/aeon/src/api.rs](/home/sdancer/aeon/crates/aeon/src/api.rs)

The right move is to productize reduction/SSA in `aeon`, then let `aeon-frontend` expose them through the existing generic tool transport.

## 1. Expose `aeon-reduce` Through Structured MCP/HTTP Tools

### Recommendation

Do not add bespoke HTTP routes. Keep:

- HTTP: `POST /call`
- MCP: `tools/call`

Add new tool names and schemas in [crates/aeon-frontend/src/service.rs](/home/sdancer/aeon/crates/aeon-frontend/src/service.rs), backed by new `AeonSession` methods in [crates/aeon/src/api.rs](/home/sdancer/aeon/crates/aeon/src/api.rs).

This preserves the thin frontend rule from [roadmap.md](/home/sdancer/aeon/roadmap.md).

### Agent-facing tools

Recommended public tools:

1. `get_reduced_il(addr, include_asm=false, include_stack_frame=true, format="compact")`
2. `get_ssa(addr, optimize=true, format="compact")`
3. `get_stack_frame(addr, include_accesses=true)`

Do not expose raw `reduce_block`, `build_ssa`, and `optimize_ssa` as separate top-level tools by default. Those are implementation steps, not the best agent UX.

Mapping:

- `get_reduced_il` -> shared decode stream + `reduce_function_cfg()`
- `get_ssa(optimize=false)` -> reduced CFG + `build_ssa()`
- `get_ssa(optimize=true)` -> reduced CFG + `build_ssa()` + `optimize_ssa()`

If a low-level debug surface is still useful, add it later under explicit dev-only names:

- `build_ssa_raw`
- `optimize_ssa_raw`

### Proposed JSON shapes

#### `get_reduced_il`

Input:

```json
{
  "addr": "0x5e611fc",
  "include_asm": false,
  "include_stack_frame": true,
  "format": "compact"
}
```

Output:

```json
{
  "function": "0x5e611e0",
  "query_addr": "0x5e611fc",
  "artifact": "reduced_il",
  "block_count": 3,
  "instruction_count": 14,
  "reduced_stmt_count": 9,
  "stack_frame": {
    "detected": true,
    "frame_size": 96,
    "has_frame_pointer": true,
    "prologue_end": 3,
    "saved_regs": [
      {"reg": "x29", "offset": 0, "size": 8},
      {"reg": "x30", "offset": 8, "size": 8}
    ]
  },
  "blocks": [
    {
      "id": 0,
      "addr": "0x5e611e0",
      "preds": [],
      "succs": [1, 2],
      "instruction_addrs": ["0x5e611e0", "0x5e611e4", "0x5e611e8"],
      "stmts": [
        {"op": "store", "addr": {"op": "stack_slot", "offset": 0, "size": 8}, "value": {"op": "reg", "name": "x29"}, "size": 8},
        {"op": "cond_branch", "cond": {"op": "compare", "cc": "ne", "lhs": {"op": "reg", "name": "w8"}, "rhs": {"op": "imm", "value": "0x1"}}, "target": {"op": "imm", "value": "0x5e61210"}, "fallthrough": "0x5e611f0"}
      ]
    }
  ]
}
```

#### `get_ssa`

Input:

```json
{
  "addr": "0x5e611fc",
  "optimize": true,
  "format": "compact"
}
```

Output:

```json
{
  "function": "0x5e611e0",
  "query_addr": "0x5e611fc",
  "artifact": "ssa",
  "optimized": true,
  "block_count": 3,
  "metrics": {
    "phi_count": 1,
    "assign_count": 7,
    "stack_slot_count": 2
  },
  "blocks": [
    {
      "id": 0,
      "addr": "0x5e611e0",
      "preds": [],
      "succs": [1, 2],
      "stmts": [
        {"op": "assign", "dst": "gpr0_1", "src": {"op": "imm", "value": "0x1"}},
        {"op": "cond_branch", "cond": {"op": "compare", "cc": "eq", "lhs": {"op": "var", "name": "gpr0_1"}, "rhs": {"op": "imm", "value": "0x1"}}, "target": 1, "fallthrough": 2}
      ]
    }
  ]
}
```

#### `get_stack_frame`

Input:

```json
{
  "addr": "0x5e611fc",
  "include_accesses": true
}
```

Output:

```json
{
  "function": "0x5e611e0",
  "query_addr": "0x5e611fc",
  "artifact": "stack_frame",
  "detected": true,
  "frame_size": 96,
  "has_frame_pointer": true,
  "prologue_end": 3,
  "saved_regs": [
    {"reg": "x29", "offset": 0, "size": 8},
    {"reg": "x30", "offset": 8, "size": 8}
  ],
  "slots": [
    {"offset": -4, "size": 4, "loads": 1, "stores": 2, "block_ids": [1]},
    {"offset": 16, "size": 8, "loads": 2, "stores": 1, "block_ids": [0, 2]}
  ]
}
```

### Frontend changes

Add handlers and schemas in [crates/aeon-frontend/src/service.rs](/home/sdancer/aeon/crates/aeon-frontend/src/service.rs):

- `tool_get_reduced_il()`
- `tool_get_ssa()`
- `tool_get_stack_frame()`

Then register them in:

- `AeonFrontend::call_tool()`
- `tools_list()`

Suggested schema additions:

```rust
tool_schema("get_reduced_il",
    "Return block-structured reduced AeonIL for the function containing the given address.",
    json!({"type": "object", "properties": {
        "addr": {"type": "string", "description": "Any virtual address in hex"},
        "include_asm": {"type": "boolean", "default": false},
        "include_stack_frame": {"type": "boolean", "default": true},
        "format": {"type": "string", "enum": ["compact", "rich"], "default": "compact"}
    }, "required": ["addr"]}));

tool_schema("get_ssa",
    "Return SSA form for the function containing the given address, optionally optimized.",
    json!({"type": "object", "properties": {
        "addr": {"type": "string", "description": "Any virtual address in hex"},
        "optimize": {"type": "boolean", "default": true},
        "format": {"type": "string", "enum": ["compact", "rich"], "default": "compact"}
    }, "required": ["addr"]}));

tool_schema("get_stack_frame",
    "Summarize detected stack-frame layout and stack-slot accesses for the function containing the given address.",
    json!({"type": "object", "properties": {
        "addr": {"type": "string", "description": "Any virtual address in hex"},
        "include_accesses": {"type": "boolean", "default": true}
    }, "required": ["addr"]}));
```

Nothing else in MCP or HTTP needs to change. Both frontends already forward arbitrary tool names and JSON arguments.

Optional but useful for local debugging:

- add `reduced-il`, `ssa`, and `stack-frame` subcommands in [crates/aeon-frontend/src/main.rs](/home/sdancer/aeon/crates/aeon-frontend/src/main.rs)

## 2. New Tool Shapes Most Valuable For Agents

### `get_reduced_il`

This should be the default “read code” surface for agents, not `get_il`.

Why it matters:

- reduced IL removes a large amount of ARM64 noise
- stack slots are much easier to reason about than raw `SP` arithmetic
- compare fusion removes implicit-flag reasoning
- block-level output is cheaper than raw per-instruction dumps

Recommended defaults:

- `format="compact"`
- `include_asm=false`
- `include_stack_frame=true`

### `get_ssa`

This is the right tool for data-flow, copy propagation, constant flow, and future slicing.

Recommended shape:

- one tool
- one `optimize` boolean
- block-oriented output
- block IDs instead of repeating target addresses in CFG links

Do not make agents choose between `build_ssa` and `optimize_ssa` unless they are debugging the pipeline itself.

### `get_stack_frame`

This is worth exposing separately even if `get_reduced_il` already contains stack info.

Why it deserves a dedicated tool:

- it is high-signal and cheap
- many tasks only need local-variable recovery, not full IL
- it creates a stable contract for future slot typing and stack-local promotion

This tool should summarize:

- frame size
- frame-pointer presence
- saved registers
- recognized stack-slot offsets/sizes
- load/store counts per slot

Implementation note:

- detect the prologue once from the entry path
- reuse that `PrologueInfo` to rewrite and summarize stack accesses across all blocks
- do not run prologue detection independently on every basic block

## 3. Unify Ingestion So IL, Reduction, And SSA Share One Decoded Stream

### Recommendation

Add a single session-level function artifact cache in `aeon`, then build IL, reduced IL, SSA, and stack summaries from that shared artifact.

The current duplication is the main integration risk.

### Concrete design

Add a new internal module in `aeon`, for example:

- `crates/aeon/src/function_ir.rs`

Suggested core types:

```rust
pub struct DecodedInstruction {
    pub addr: u64,
    pub word: u32,
    pub asm: String,
    pub stmt: aeonil::Stmt,
    pub edges: Vec<u64>,
    pub valid: bool,
}

pub struct DecodedFunction {
    pub func_addr: u64,
    pub size: u64,
    pub instructions: Vec<DecodedInstruction>,
}

pub struct FunctionArtifacts {
    pub decoded: DecodedFunction,
    pub reduced_cfg: OnceCell<ReducedCfg>,
    pub ssa: OnceCell<SsaFunction>,
    pub optimized_ssa: OnceCell<SsaFunction>,
    pub stack_frame: OnceCell<Option<PrologueInfo>>,
}
```

Store that in `AeonSession`, not in the frontend:

```rust
pub struct AeonSession {
    path: String,
    binary: LoadedBinary,
    analysis_state: RefCell<AeonEngine>,
    function_cache: RefCell<HashMap<u64, FunctionArtifacts>>,
}
```

### Required API refactor in `AeonSession`

Add internal helpers in [crates/aeon/src/api.rs](/home/sdancer/aeon/crates/aeon/src/api.rs):

```rust
fn decode_function(&self, addr: u64) -> Result<DecodedFunction, String>;
fn function_artifacts(&self, addr: u64) -> Result<Ref<'_, FunctionArtifacts>, String>;
fn build_reduced_cfg(decoded: &DecodedFunction) -> ReducedCfg;
```

Then rewrite these APIs to consume the shared artifact:

- `get_il()`
- `get_function_il()`
- new `get_reduced_il()`
- new `get_ssa()`
- new `get_stack_frame()`
- `get_function_details()`

Also add `AeonEngine::ingest_decoded_function(&mut self, decoded: &DecodedFunction)` in [crates/aeon/src/engine.rs](/home/sdancer/aeon/crates/aeon/src/engine.rs) so the current Datalog/CFG detail path does not re-decode the same function again.

### Required reducer changes

#### 1. Split block-local reduction from function-level stack recognition

In [crates/aeon-reduce/src/pipeline.rs](/home/sdancer/aeon/crates/aeon-reduce/src/pipeline.rs):

```rust
pub fn reduce_block_local(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let stmts = flatten_pairs(stmts);
    let stmts = fold_constants(stmts);
    let stmts = resolve_adrp_add(stmts);
    let stmts = resolve_movk_chains(stmts);
    let stmts = fold_constants(stmts);
    let stmts = fuse_flags(stmts);
    let stmts = eliminate_dead_flags(stmts);
    fold_extensions(stmts)
}
```

Then add a function-level wrapper, either in `aeon-reduce` or in the new `function_ir` module in `aeon`:

```rust
pub fn reduce_function_cfg(instructions: &[(u64, Stmt, Vec<u64>)]) -> ReducedCfg {
    let mut cfg = build_cfg(instructions);

    for block in &mut cfg.blocks {
        block.stmts = reduce_block_local(std::mem::take(&mut block.stmts));
    }

    let prologue = cfg
        .blocks
        .get(cfg.entry as usize)
        .and_then(|entry| detect_prologue(&entry.stmts));

    if let Some(prologue) = &prologue {
        for block in &mut cfg.blocks {
            block.stmts = rewrite_stack_accesses(std::mem::take(&mut block.stmts), prologue);
        }
    }

    ReducedCfg::from_cfg(cfg, prologue)
}
```

This is the cleanest integration point because it respects both facts:

- most reduction passes are block-local
- stack-slot recognition is function-level

If the project wants a very small immediate patch first, calling `recognize_stack_frame()` from the existing `reduce_block()` is still useful for the entry block and crate-local tests. It should not be the final API path for whole-function reduction.

#### 2. Make SSA truly reduction-backed

In [crates/aeon-reduce/src/ssa/pipeline.rs](/home/sdancer/aeon/crates/aeon-reduce/src/ssa/pipeline.rs), change `reduce_and_build_ssa()` to consume the function-level reduced CFG instead of raw lifted blocks:

```rust
let reduced = crate::pipeline::reduce_function_cfg(instructions);
let mut ssa_func = build_ssa(&reduced.into_cfg());
optimize_ssa(&mut ssa_func);
```

The key point is that SSA should see:

- block-local simplification
- stack-slot rewrites informed by one shared prologue
- unchanged CFG topology

#### 3. Add a reusable function-level reduction helper

Today the API layer would have to rebuild block structure itself. That logic belongs closer to `aeon-reduce`.

Add a small public helper, for example in a new reducer module:

```rust
pub struct ReducedBlock {
    pub id: BlockId,
    pub addr: u64,
    pub instruction_addrs: Vec<u64>,
    pub stmts: Vec<Stmt>,
    pub predecessors: Vec<BlockId>,
    pub successors: Vec<BlockId>,
}

pub struct ReducedCfg {
    pub entry: BlockId,
    pub blocks: Vec<ReducedBlock>,
    pub stack_frame: Option<PrologueInfo>,
}

pub fn reduce_function_cfg(instructions: &[(u64, Stmt, Vec<u64>)]) -> ReducedCfg;
```

That keeps the block split/reduction policy in one place.

### Provenance recommendation

For the first integration pass, block-level `instruction_addrs` are sufficient.

Do not block rollout on per-statement provenance.

If later needed, add:

```rust
pub struct ReducedStmt {
    pub source_addrs: Vec<u64>,
    pub stmt: Stmt,
}
```

## 4. Token-Efficiency Improvements For IL Output

The current `get_il()` output is expensive because it emits:

- one object per instruction
- full absolute addresses everywhere
- debug strings instead of structured data
- repeated field names

### Recommendation: support two JSON encodings

1. `format="compact"` for agents
2. `format="rich"` for debugging/tests

New reduction/SSA tools should default to `compact`.

### Compact encoding rules

#### Use structured AST, not `Debug`

Do not emit:

```json
{"il":"Assign { dst: X(0), src: Imm(42) }"}
```

Emit:

```json
{"op":"assign","dst":"x0","src":{"op":"imm","value":"0x2a"}}
```

#### Prefer block IDs and relative offsets

For reduced IL and SSA:

- use `id`, `preds`, `succs` for CFG links
- include `addr` once per block
- do not repeat full target addresses inside every control-flow statement unless required

For lifted IL:

- add `function` once
- encode per-instruction `off` relative to function start instead of absolute `addr`

#### Omit optional fields by default

Default off:

- `asm`
- `edges`
- semantic annotations on every statement
- empty operand arrays

Make them opt-in.

#### Keep top-level summaries dense

Add counts that help an agent decide whether to expand:

- `instruction_count`
- `block_count`
- `reduced_stmt_count`
- `phi_count`
- `stack_slot_count`
- `intrinsic_count`

This is cheaper than forcing the model to scan the body to infer complexity.

### Serialization strategy

Do not serialize `aeonil` and SSA enums directly with default serde shape.

That produces Rust-shaped JSON, not agent-shaped JSON.

Recommended approach:

- add an `api_types` or `json` module inside `aeon`
- define explicit serializable view structs/enums there
- convert `aeonil::Expr`, `aeonil::Stmt`, `aeon_reduce::ssa::*`, and `PrologueInfo` into compact JSON views

This keeps `aeon-reduce` independent of frontend concerns and preserves control over field names and hex formatting.

### Backward-compatibility recommendation for `get_il`

Do not silently break the current `get_il()` output shape on day one.

Safer rollout:

1. add `format: "legacy" | "compact" | "rich"` to `get_il`
2. keep `legacy` as the initial default
3. make all new tools (`get_reduced_il`, `get_ssa`, `get_stack_frame`) structured-only
4. switch `get_il` default later after downstream MCP/HTTP consumers move

That gives the project a migration path without forcing every existing client to adapt at once.

## Concrete File-Level Recommendations

### `crates/aeon/src/api.rs`

- add session-level function artifact caching
- add `get_reduced_il()`
- add `get_ssa()`
- add `get_stack_frame()`
- replace `render_instruction_listing()` debug-string output with structured serializer helpers
- stop decoding/lifting directly in every endpoint

### `crates/aeon/src/engine.rs`

- add `ingest_decoded_function()`
- optionally migrate `get_function_details()` to consume shared decoded artifacts instead of raw ECS ingestion from bytes

### `crates/aeon-reduce/src/pipeline.rs`

- split `reduce_block_local()` from function-level `reduce_function_cfg()`
- keep stack-frame detection driven by one shared `PrologueInfo`

### `crates/aeon-reduce/src/ssa/pipeline.rs`

- consume function-level reduced CFG before SSA construction
- keep `optimize_ssa()` separate, but route agent-facing `get_ssa(optimize=true)` through it

### `crates/aeon-frontend/src/service.rs`

- add tool dispatch arms
- add JSON input schemas
- keep HTTP/MCP transport unchanged

### `crates/aeon-frontend/src/main.rs`

- add optional local CLI commands for `reduced-il`, `ssa`, and `stack-frame`

## Recommended Execution Order

1. Land the small reducer patch that wires `recognize_stack_frame()` into the current `reduce_block()` for immediate readability wins.
2. Split stack recognition into the function-level reduction path used by the API.
3. Fix `reduce_and_build_ssa()` so it reduces before SSA.
4. Add shared decoded-function artifacts in `aeon`.
5. Add serializable JSON view types in `aeon`.
6. Expose `get_reduced_il`, `get_ssa`, and `get_stack_frame` in `AeonSession`.
7. Add frontend tool schemas in `aeon-frontend`.
8. Add end-to-end tests that assert JSON shape and stack-slot visibility on the reduction corpus.

## Testing Recommendations

Use [docs/reduction-test-corpus.md](/home/sdancer/aeon/docs/reduction-test-corpus.md) as the fixture source for API-level regression tests.

Add tests at three levels:

- reducer unit tests: already present in `aeon-reduce`
- `aeon` API tests: JSON artifact shape and stack-slot presence
- frontend tests: tool schema registration and `tools/call` / `/call` smoke tests

The key regression assertions should be:

- `get_reduced_il` returns fused compare branches, resolved constants, and `stack_slot`
- `get_ssa(optimize=false)` differs from `get_ssa(optimize=true)` in expected cases
- `get_stack_frame` reports frame size and saved registers for real prologues
- `get_il(format="compact")` never falls back to `Debug` strings
