# Roadmap

aeon is being built as a sensory organ, reasoning sandbox, and execution environment for autonomous AI agents. This roadmap focuses on evolving the current ARM64 analysis core into a deterministic, stateful, token-efficient substrate for software reverse engineering and analysis, without adding human-aimed tooling bloat.

This roadmap is organized as parallel workstreams. Some dependencies exist, but most of these efforts can move forward at the same time.

## Guiding Constraints

- Keep the primary interface machine-native: JSON, MCP, and composable tool calls.
- Prefer deterministic analysis over asking an LLM to mentally simulate machines.
- Make the agent spend tokens on hypotheses, not on scrolling through raw assembly.
- Preserve a thin frontend layer and keep real logic in the core crates.
- Let state compound across iterations so the agent does not repeatedly rediscover the same facts.
- Optimize for validating the behavior and trust boundaries of closed-source software that our systems run.

## Current Baseline

- ARM64 ELF ingestion and function discovery from `.eh_frame`
- AeonIL lifting and CFG/reachability analysis
- RC4 behavioral search
- MCP and HTTP frontends
- Address-level semantic naming via `set_analysis_name`

## Workstream 1: Token-Efficient Program Topology

This workstream helps the agent decide where to look before it pays the cost of reading full IL or assembly.

- Semantic summarization tools in `crates/aeon-frontend/src/mcp.rs` and `crates/aeon-frontend/src/service.rs`
  Add a `get_function_skeleton(addr)` MCP tool that returns dense JSON such as:

  ```json
  {
    "args": 2,
    "calls": ["malloc", "recv"],
    "strings": ["config.json"],
    "loops": 1,
    "crypto_constants": ["RC4_SBOX"]
  }
  ```

- Micro-slicing in `crates/aeon/src/analysis.rs` and `crates/aeon/src/engine.rs`
  Add a `get_data_flow_slice(target_addr, register)` tool so the agent can ask for a backward or forward slice on a single register or value and receive only the small instruction subset that matters.

- Token-dense IL in `crates/aeon/src/il.rs`
  Serialize IL into strictly structured, LLM-friendly formats such as compact JSON or Lisp-like S-expressions rather than debug-oriented text dumps.

- Result
  The agent can triage functions, follow one value, and request deeper detail only when the summary indicates it is worth the tokens.

## Workstream 2: Datalog as the Deterministic Engine

This is the anti-hallucination workstream. LLMs are poor CPU simulators, but they are good at proposing declarative rules. aeon should let the model express a hypothesis as logic and then execute it deterministically.

- Fact extraction in `crates/aeon/src/engine.rs`
  On ingestion, lower the binary into a reusable fact database such as `Instruction(addr, op)`, `CallEdge(src, dst)`, `ReadsMem(addr)`, `Defines(addr, reg)`, and `FlowsTo(src, dst)`.

- Datalog-backed analyses in `crates/aeon/src/analysis.rs`
  Extend the current reachability-focused rule set into a broader relation layer that supports dataflow, callgraph, loop membership, constants, and typed memory operations.

- Query execution in `crates/aeon-frontend/src/mcp.rs` and `crates/aeon-frontend/src/service.rs`
  Expose an MCP tool such as `execute_datalog(query_string)` that accepts agent-authored rules, runs them against the extracted facts, and returns exact result tuples.

- Design input
  `datalog_plugin.md` already sketches the dynamic query path and should become the design seed for this workstream.

- Workflow
  Instead of reading code linearly to understand a behavior, the agent writes a rule like "find all paths from `recv()` to the command dispatcher" or "find all callers that reach the license check without passing through the signature verifier." aeon executes the query and returns exact addresses and relations. The model stays responsible for hypotheses; aeon stays responsible for proof.

## Workstream 3: The Programmatic Blackboard

Autonomous analysis is iterative. The agent needs a place to store semantic understanding so it does not forget context or loop on the same uncertain inference.

- Stateful context in `crates/aeon-frontend/src/service.rs` and `crates/aeon/src/engine.rs`
  Evolve the current `set_analysis_name` support into a mutable knowledge graph attached to the analysis session.

- Mutation tools
  Add tools such as:
  `rename_symbol(addr, "load_plugin_manifest")`
  `define_struct(addr, "NetworkPacket { size: u32, data: char* }")`
  `add_hypothesis(addr, "This looks like a custom stream cipher initialization block")`

- Auto-propagation
  Once the agent renames a symbol or defines a structure, that semantic label should appear automatically in future xrefs, IL responses, slices, summaries, and reports.

- Result
  The agent stops treating each tool call as stateless. It accumulates an epistemic state inside aeon and can iteratively refine it.

## Workstream 4: Active Experimentation

Static analysis eventually hits dead ends: obfuscated control flow, dynamic API resolution, format decoding routines, or string decryption loops. At that point the agent needs bounded experiments, not guesswork.

- Micro-emulation API in `crates/aeon/src/engine.rs`
  Integrate a lightweight emulator such as `unicorn-rs` or an interpreter for AeonIL so aeon can execute small regions in a controlled sandbox.

- Sandbox tool in `crates/aeon-frontend/src/mcp.rs` and `crates/aeon-frontend/src/service.rs`
  Expose `emulate_snippet(start_addr, end_addr, initial_registers={...})` with optional memory initialization and bounded step limits.

- Observable outputs
  Return the final register state, touched memory ranges, branch trace, and decoded strings or buffers produced by the snippet.

- Workflow
  If the agent finds a string decryption loop, it should not need to reverse the arithmetic by hand. It should initialize dummy registers, run the snippet, and inspect the resulting memory directly.

## Workstream 5: Swarm Orchestration

The `survey` crate is well positioned to evolve from a one-off batch utility into a multi-agent orchestrator for a single binary.

- Orchestration in `crates/survey`
  Replace the fixed opcode survey flow with a headless coordinator that launches specialized agent roles against a shared aeon session and blackboard.

- Example roles
  The Scout uses fast heuristics, imports, and `rc4_search.rs` to map the binary quickly.
  The Tracer spends more reasoning budget on specific slices, hypotheses, and Datalog queries.
  The Reporter converts the shared blackboard into a final JSON analysis or capability report.

- Headless pipelines
  `survey` should be able to run unattended from binary input to final artifact: bootstrap aeon, load the binary, fan out specialist passes, merge their state, and emit structured JSON reports without a human orchestrator.

- Result
  aeon stops being a single-agent microscope and becomes a substrate for coordinated autonomous analysis.

## Workstream 6: Evaluation and Benchmarking

An agent framework needs a reproducible way to measure capability and evidence quality, not just a growing tool surface.

- Evaluation models in `crates/aeon-eval`
  Define corpus entries, task specs, expected outcomes, evidence bundles, claims, run metrics, and scored results as versioned machine-readable types.

- Benchmark corpus
  Build a representative set of closed-source software analysis tasks such as configuration loading, packet shape recovery, reachability proofs, decrypted string extraction, custom crypto loop identification, and behavior classification.

- Evidence-first scoring
  Judge runs by whether claims are backed by concrete addresses, query results, slices, emulation traces, or structured artifacts rather than by free-form prose alone.

- Result
  aeon can be optimized against repeatable task completion and evidence quality instead of ad hoc demos.

## Exit Criteria

- An agent can triage a binary without first reading raw assembly.
- The default workflow is summary -> slice -> query -> experiment -> persist state -> report.
- Semantic labels survive across tool calls and improve later responses automatically.
- The highest-value reasoning steps are deterministic queries or experiments, not free-form simulation.
- `survey` can drive the whole loop in a headless pipeline.

## Non-Goals

- Human-first dashboards or rich manual UI layers
- Analyst-oriented workflow scaffolding that duplicates what an autonomous agent can already do
- Forcing the model to inspect entire functions when aeon can answer the narrower question directly
