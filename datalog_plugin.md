# Dynamic Datalog Queries via JIT Compilation

## Overview

Allow the MCP agent to write arbitrary `ascent!` Datalog queries, have aeon compile them into shared libraries on the host, load them, execute against extracted facts, and return results — all within a single `run_datalog` MCP tool call.

## Flow

```
Agent writes Datalog rules (ascent syntax)
  → aeon wraps in .rs template with serde entry point
    → rustc compiles to .so (cdylib)
      → aeon dlopens .so, calls entry point with serialized facts
        → results returned as JSON to agent
```

## Fact Schema

The host extracts a standard set of facts from the lifted IL for a given function (or set of functions). These are serialized as JSON and passed to the compiled query. The query declares which input relations it needs — unused relations are simply ignored.

### Available input relations

Derived from the existing `DataflowFacts` extraction in `rc4_search.rs` and the ECS components:

```rust
// Control flow
relation edge(u64, u64);                  // (src_addr, dst_addr)
relation inst_in_func(u64, u64);          // (func_addr, inst_addr)
relation in_loop(u64);                    // (inst_addr)

// Dataflow
relation def(u64, u64);                   // (inst_addr, reg_canonical_id)
relation use_of(u64, u64);               // (inst_addr, reg_canonical_id)
relation flows_to(u64, u64);             // (producer_inst, consumer_inst)

// Typed instructions
relation byte_load(u64, u64);            // (inst_addr, dest_var)
relation byte_store(u64, u64);           // (inst_addr, value_var)
relation load(u64, u64, u64);            // (inst_addr, dest_var, size)
relation store(u64, u64, u64);           // (inst_addr, value_var, size)
relation is_xor(u64, u64, u64);          // (inst_addr, src1_var, src2_var)
relation is_add(u64, u64, u64);          // (inst_addr, src1_var, src2_var)
relation is_sub(u64, u64, u64);          // (inst_addr, src1_var, src2_var)
relation is_and(u64, u64, u64);          // (inst_addr, src1_var, src2_var)
relation is_shift(u64, u64, u64);        // (inst_addr, src_var, amount_var)
relation is_call(u64, u64);              // (inst_addr, target_addr)
relation is_cmp(u64);                    // (inst_addr) - SetFlags
relation has_constant(u64, u64);         // (inst_addr, immediate_value)

// IL text (for result annotation)
relation il_text(u64, String);           // (inst_addr, debug_repr)
relation asm_text(u64, String);          // (inst_addr, disassembly)
```

### JSON wire format

```json
{
  "edge": [[4194304, 4194308], [4194308, 4194312]],
  "inst_in_func": [[4194300, 4194304], [4194300, 4194308]],
  "byte_load": [[4194316, 4194316]],
  "flows_to": [[4194304, 4194316]],
  ...
}
```

Each relation is a key mapping to an array of tuples. The compiled query deserializes only the relations it declares.

## Generated .rs Template

```rust
use ascent::ascent;
use serde_json::{Value, json};
use std::collections::HashMap;

ascent! {
    pub struct DynQuery;

    // ── Input relations (always declared, populated from JSON) ──
    relation edge(u64, u64);
    relation inst_in_func(u64, u64);
    relation in_loop(u64);
    relation def(u64, u64);
    relation use_of(u64, u64);
    relation flows_to(u64, u64);
    relation byte_load(u64, u64);
    relation byte_store(u64, u64);
    relation load(u64, u64, u64);
    relation store(u64, u64, u64);
    relation is_xor(u64, u64, u64);
    relation is_add(u64, u64, u64);
    relation is_sub(u64, u64, u64);
    relation is_and(u64, u64, u64);
    relation is_shift(u64, u64, u64);
    relation is_call(u64, u64);
    relation is_cmp(u64);
    relation has_constant(u64, u64);

    // ── Agent-provided rules spliced here ──
    {{RULES}}
}

#[no_mangle]
pub extern "C" fn run_query(facts_ptr: *const u8, facts_len: usize) -> *mut u8 {
    let facts_bytes = unsafe { std::slice::from_raw_parts(facts_ptr, facts_len) };
    let facts: HashMap<String, Value> = serde_json::from_slice(facts_bytes).unwrap();

    let mut q = DynQuery::default();

    // Populate input relations from JSON
    macro_rules! populate_2 {
        ($name:ident, $facts:expr) => {
            if let Some(Value::Array(rows)) = $facts.get(stringify!($name)) {
                for row in rows {
                    if let Value::Array(t) = row {
                        q.$name.push((t[0].as_u64().unwrap(), t[1].as_u64().unwrap()));
                    }
                }
            }
        };
    }
    macro_rules! populate_3 {
        ($name:ident, $facts:expr) => {
            if let Some(Value::Array(rows)) = $facts.get(stringify!($name)) {
                for row in rows {
                    if let Value::Array(t) = row {
                        q.$name.push((
                            t[0].as_u64().unwrap(),
                            t[1].as_u64().unwrap(),
                            t[2].as_u64().unwrap(),
                        ));
                    }
                }
            }
        };
    }
    macro_rules! populate_1 {
        ($name:ident, $facts:expr) => {
            if let Some(Value::Array(rows)) = $facts.get(stringify!($name)) {
                for row in rows {
                    q.$name.push((row.as_u64().unwrap(),));
                }
            }
        };
    }

    populate_2!(edge, facts);
    populate_2!(inst_in_func, facts);
    populate_1!(in_loop, facts);
    populate_2!(def, facts);
    populate_2!(use_of, facts);
    populate_2!(flows_to, facts);
    populate_2!(byte_load, facts);
    populate_2!(byte_store, facts);
    populate_3!(load, facts);
    populate_3!(store, facts);
    populate_3!(is_xor, facts);
    populate_3!(is_add, facts);
    populate_3!(is_sub, facts);
    populate_3!(is_and, facts);
    populate_3!(is_shift, facts);
    populate_2!(is_call, facts);
    populate_1!(is_cmp, facts);
    populate_2!(has_constant, facts);

    q.run();

    // ── Collect output relations (agent-declared) ──
    let result = json!({{OUTPUT_COLLECT}});

    let result_bytes = serde_json::to_vec(&result).unwrap();
    let ptr = result_bytes.as_ptr() as *mut u8;
    std::mem::forget(result_bytes);
    ptr
}

// Companion function so the host can free the result
#[no_mangle]
pub extern "C" fn free_result(ptr: *mut u8, len: usize) {
    unsafe { drop(Vec::from_raw_parts(ptr, len, len)); }
}
```

## Template Substitution

The host fills two placeholders:

### `{{RULES}}`

Agent-provided ascent rules, verbatim. Example:

```
relation reachable(u64, u64);
reachable(x, y) <-- edge(x, y);
reachable(x, z) <-- edge(x, y), reachable(y, z);

relation dead_store(u64);
dead_store(inst) <--
    store(inst, _, _),
    !use_of(_, inst);
```

### `{{OUTPUT_COLLECT}}`

Auto-generated from the agent's declared output relations. For each non-input relation the agent declares, emit collection code:

```rust
{
    "reachable": q.reachable.iter().map(|(a,b)| json!([a,b])).collect::<Vec<_>>(),
    "dead_store": q.dead_store.iter().map(|(a,)| json!(a)).collect::<Vec<_>>(),
}
```

The host parses the agent's rules to identify which relations are new (not in the input set) and generates the output collection accordingly.

## Compilation

```bash
rustc --edition 2021 \
      --crate-type cdylib \
      -O \
      --extern ascent=/path/to/libascent.rlib \
      --extern serde_json=/path/to/libserde_json.rlib \
      --extern serde=/path/to/libserde.rlib \
      -L dependency=/path/to/deps \
      /tmp/aeon_query_<hash>.rs \
      -o /tmp/aeon_query_<hash>.so
```

Dependency paths come from `cargo metadata` or are cached at build time. The hash is computed from the rules text so identical queries skip recompilation.

## Host-Side Loader

```rust
use libloading::{Library, Symbol};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

struct CompiledQuery {
    _lib: Library,  // must outlive the symbols
    run: Symbol<extern "C" fn(*const u8, usize) -> *mut u8>,
    free: Symbol<extern "C" fn(*mut u8, usize)>,
}

fn compile_and_load(rules: &str, output_collect: &str) -> Result<CompiledQuery, String> {
    let mut hasher = DefaultHasher::new();
    rules.hash(&mut hasher);
    let hash = hasher.finish();

    let so_path = format!("/tmp/aeon_query_{:x}.so", hash);

    if !std::path::Path::new(&so_path).exists() {
        let rs_source = TEMPLATE
            .replace("{{RULES}}", rules)
            .replace("{{OUTPUT_COLLECT}}", output_collect);

        let rs_path = format!("/tmp/aeon_query_{:x}.rs", hash);
        std::fs::write(&rs_path, &rs_source).map_err(|e| e.to_string())?;

        let status = std::process::Command::new("rustc")
            .args(&[
                "--edition", "2021",
                "--crate-type", "cdylib",
                "-O",
                "-L", "dependency=./target/release/deps",
                &rs_path,
                "-o", &so_path,
            ])
            .status()
            .map_err(|e| e.to_string())?;

        if !status.success() {
            return Err("rustc compilation failed".into());
        }
    }

    unsafe {
        let lib = Library::new(&so_path).map_err(|e| e.to_string())?;
        let run = lib.get(b"run_query").map_err(|e| e.to_string())?;
        let free = lib.get(b"free_result").map_err(|e| e.to_string())?;
        Ok(CompiledQuery { _lib: lib, run, free })
    }
}
```

## MCP Tool: `run_datalog`

### Schema

```json
{
  "name": "run_datalog",
  "description": "Compile and execute a custom Datalog query against a function's extracted facts. Write ascent-syntax rules using the available input relations. New relations you declare become output.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "func_addr": {
        "type": "string",
        "description": "Function address to analyze (hex). Facts are extracted from this function's lifted IL."
      },
      "rules": {
        "type": "string",
        "description": "Ascent Datalog rules. Declare new relations and write rules over the input relations: edge, inst_in_func, in_loop, def, use_of, flows_to, byte_load, byte_store, load, store, is_xor, is_add, is_sub, is_and, is_shift, is_call, is_cmp, has_constant."
      }
    },
    "required": ["func_addr", "rules"]
  }
}
```

### Example call

```json
{
  "name": "run_datalog",
  "arguments": {
    "func_addr": "0x51203d0",
    "rules": "relation reachable(u64, u64);\nreachable(x, y) <-- edge(x, y);\nreachable(x, z) <-- edge(x, y), reachable(y, z);\n\nrelation xor_in_loop(u64);\nxor_in_loop(addr) <-- is_xor(addr, _, _), in_loop(addr);"
  }
}
```

### Example response

```json
{
  "compile_time_ms": 2340,
  "cached": false,
  "results": {
    "reachable": [[85066704, 85066708], [85066704, 85066712], ...],
    "xor_in_loop": [85066738]
  }
}
```

## Caching Strategy

- Key: SHA-256 of the rules text (not the facts)
- `.so` files persist in `/tmp/aeon_query_<hash>.so`
- Same query against different functions reuses the compiled `.so`
- Cache can be cleared with an optional `clear_cache` tool or on process exit

## Implementation Steps

1. **Extend fact extraction** — generalize `rc4_search.rs`'s `extract_dataflow` into a standalone module that produces the full fact schema above (add `def`, `use_of`, `is_add`, `is_sub`, `is_and`, `is_shift`, `is_call`, `is_cmp`, `has_constant`, `load`/`store` with sizes)

2. **Template engine** — store the `.rs` template as a const string in a new `src/datalog_jit.rs` module. Parse agent rules to identify output relations (any `relation` declaration not in the input set). Generate the `{{OUTPUT_COLLECT}}` block.

3. **Compiler shim** — shell out to `rustc` with dependency paths resolved from the build's `target/release/deps`. Add `libloading` to `Cargo.toml`.

4. **Loader + executor** — dlopen, pass serialized facts, collect results, dlclose.

5. **MCP tool** — wire `run_datalog` into `src/mcp.rs` following the existing tool pattern.

6. **Error handling** — return `rustc` stderr on compilation failure so the agent can fix its query and retry.

## Dependencies to Add

```toml
libloading = "0.8"
sha2 = "0.10"       # for cache key hashing
```

## Security Notes

This is a local-only tool — the agent runs on the same host as `rustc`. The compiled code has full process access. This is acceptable for a local RE workstation. Do not expose this over a network without sandboxing (seccomp, nsjail, etc.).
