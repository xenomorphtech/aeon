# Aeon Tool Development Guide

Guide for extending aeon with new analysis tools and capabilities.

## Overview

Aeon's tool system is built on a standardized interface that allows:
- Adding new analysis tools quickly
- Exposing tools through multiple frontends (CLI, MCP, HTTP)
- Maintaining backward compatibility
- Versioning and deprecating tools cleanly

This guide shows how to implement new tools within the aeon framework.

## Architecture

### Tool System Components

```
Tool Implementation
    ↓
Tool Schema Definition (input/output)
    ↓
Frontend Service Layer (service.rs)
    ↓
Multiple Frontends
    ├── CLI (aeon)
    ├── MCP (aeon-mcp)
    ├── HTTP (aeon-http)
    └── SDK (direct calls)
```

### Tool Lifecycle

1. **Design Phase**: Define tool purpose and interface
2. **Core Implementation**: Add to analysis library (crates/aeon)
3. **Service Layer**: Register in service.rs
4. **Schema Definition**: Document JSON input/output
5. **Frontend Integration**: Expose through CLI, MCP, HTTP
6. **Documentation**: Add to analyst guides
7. **Testing**: Unit tests, integration tests, roundtrip tests

## Tool Types

### Tier 1: Core Analysis (Foundation)
- **Scope**: Must-have analysis capabilities
- **Example**: `load_binary`, `list_functions`, `get_il`
- **Stability**: High - rarely changed
- **Documentation**: Complete with examples

### Tier 2: Advanced Analysis (Common)
- **Scope**: Frequently-used specialized capabilities
- **Example**: `get_function_skeleton`, `execute_datalog`
- **Stability**: Medium - may have limitations
- **Documentation**: Complete with workflow context

### Tier 3: Specialized Analysis (Domain-specific)
- **Scope**: Focused capabilities for specific domains
- **Example**: `search_rc4`, `scan_vtables`
- **Stability**: Medium-High
- **Documentation**: Detailed, with use cases

### Tier 4: Performance Features (Advanced)
- **Scope**: Performance optimization or advanced usage
- **Example**: `emulate_snippet_native_advanced`
- **Stability**: Medium - may have edge cases
- **Documentation**: Focus on constraints and limitations

## Implementation Steps

### Step 1: Design the Tool

Define:
1. **Purpose**: What problem does this solve?
2. **Inputs**: What does the user provide?
3. **Outputs**: What does the tool return?
4. **Use Cases**: When should analysts use this?
5. **Constraints**: Any limitations or assumptions?

**Example Design: `find_integer_overflows`**
```
Purpose: Find potential integer overflow vulnerabilities
Inputs: 
  - Optional address to focus on specific function
  - Optional register to track
Outputs:
  - List of potential overflow points
  - Each with: address, operation, operand sizes
Use Cases:
  - Security vulnerability assessment
  - Vulnerability classification workflow
Constraints:
  - Requires IL coverage >80%
  - May have false positives in obfuscated code
```

### Step 2: Implement Core Logic

Add implementation to appropriate crate:

```rust
// In crates/aeon/src/lib.rs or dedicated module

pub struct OverflowFinder {
    // analysis state
}

impl OverflowFinder {
    pub fn new() -> Self {
        Self { /* ... */ }
    }
    
    pub fn find_in_function(&self, addr: u64) -> Vec<OverflowCandidate> {
        // Implementation
    }
}

#[derive(Serialize, Deserialize)]
pub struct OverflowCandidate {
    pub address: u64,
    pub operation: String,
    pub left_bits: usize,
    pub right_bits: usize,
    pub confidence: f32,
}
```

### Step 3: Register Tool in Service

Add to `crates/aeon-frontend/src/service.rs`:

```rust
impl ToolService {
    pub fn tool_find_integer_overflows(&mut self, args: Value) -> Result<Value> {
        // Parse arguments
        let addr: Option<u64> = args["addr"]
            .as_str()
            .and_then(|s| u64::from_str_radix(s, 16).ok());
        
        // Call core implementation
        let finder = OverflowFinder::new();
        let results = match addr {
            Some(a) => finder.find_in_function(a),
            None => self.find_in_all_functions(&finder),
        };
        
        // Format output
        let output = json!({
            "candidates": results.iter().map(|c| json!({
                "address": format!("0x{:x}", c.address),
                "operation": c.operation,
                "left_bits": c.left_bits,
                "right_bits": c.right_bits,
                "confidence": c.confidence,
            })).collect::<Vec<_>>(),
            "total_found": results.len(),
        });
        
        Ok(output)
    }
    
    pub fn call_tool(&mut self, name: &str, args: Value) -> Result<Value> {
        match name {
            // ... existing tools ...
            "find_integer_overflows" => self.tool_find_integer_overflows(args),
            _ => Err(format!("Unknown tool: {}", name).into()),
        }
    }
}
```

### Step 4: Define Tool Schema

Add to tools list for documentation:

```rust
// In tool registration
ToolSchema {
    name: "find_integer_overflows",
    description: "Find potential integer overflow vulnerabilities in a binary",
    parameters: json!({
        "type": "object",
        "properties": {
            "addr": {
                "type": "string",
                "description": "Optional function address (hex, e.g. 0x401234). If omitted, scans all functions."
            }
        }
    }),
    required: vec![],
}
```

### Step 5: Write Tests

Create comprehensive test coverage:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn find_integer_overflows_identifies_mul_overflow() {
        let il = vec![
            // Create test IL with multiplication
        ];
        
        let finder = OverflowFinder::new();
        let results = finder.analyze(&il);
        
        assert!(!results.is_empty());
        assert!(results[0].operation.contains("mul"));
    }
    
    #[test]
    fn find_integer_overflows_with_no_functions() {
        // Test edge case
    }
    
    #[test]
    fn find_integer_overflows_handles_obfuscated_code() {
        // Test with heavily transformed operations
    }
}
```

### Step 6: Add to Documentation

Update relevant documentation files:

**For quick-reference.md:**
```markdown
| Goal | Tools | Example |
|------|-------|---------|
| Find integer overflows | `find_integer_overflows` | `find_integer_overflows(addr="0x401234")` |
```

**For analysis-workflows.md:**
Add new section in "Common Workflows":
```
### Find Integer Overflows

1. list_functions() → scan all functions
2. For each function:
   a. find_integer_overflows(addr="0x...")
   b. Analyze candidate with get_il()
   c. Emulate with large values to verify
3. Result: Confirmed overflow candidates
```

**For ANALYST_GUIDE.md:**
Update integration examples if relevant.

## Integration Patterns

### Pattern 1: Simple Analyzer
**Use When**: Tool analyzes static properties  
**Example**: `get_function_skeleton`, `scan_pointers`

```rust
pub fn analyze(&self, addr: u64) -> AnalysisResult {
    // Single pass analysis
    // Return structured result
}
```

### Pattern 2: Search Tool
**Use When**: Tool finds instances of a pattern  
**Example**: `search_rc4`, `search_analysis_names`

```rust
pub fn search(&self, pattern: &str) -> Vec<Match> {
    // Scan for pattern
    // Return all matches with confidence
}
```

### Pattern 3: Datalog Query
**Use When**: Tool needs graph/reachability analysis  
**Example**: `execute_datalog`, `find_call_paths`

```rust
pub fn query(&self, program: &str, addr: u64) -> QueryResult {
    // Run Datalog program
    // Return facts as JSON
}
```

### Pattern 4: Emulation Tool
**Use When**: Tool executes code dynamically  
**Example**: `emulate_snippet_native`

```rust
pub fn emulate(&self, start: u64, end: u64, state: ExecutionState) -> ExecutionResult {
    // Run code in sandbox
    // Return final state and observations
}
```

## Tool API Design

### Input Design Principles

1. **Use hex strings for addresses**: "0x401234", not 4204084
2. **Support optional parameters**: Make common use case work without args
3. **Use consistent naming**: `addr`, `target_addr`, not `address` or `ptr`
4. **Limit parameter count**: Aim for ≤5 required, ≤3 optional
5. **Document defaults**: Be explicit about what happens if param is omitted

**Good Input Design:**
```json
{
  "addr": "0x401234",        // Required, but optional in schema (has sensible default)
  "include_imports": true,   // Optional, clear meaning
  "limit": 100               // Optional, clear default behavior
}
```

**Poor Input Design:**
```json
{
  "address": 4204084,        // Decimal, confusing
  "f": true,                 // Unclear what "f" means
  "v": 100,                  // Unclear what "v" means
  "foo": "bar",              // Unnecessary parameter
  "callback_func": "...",    // Can't serialize callbacks
}
```

### Output Design Principles

1. **Use consistent structure**: Every result has `type`, `address`, `data`
2. **Use descriptive field names**: `byte_count`, not `bc` or `size`
3. **Include metadata**: Always return count/summary fields
4. **Support partial results**: Handle incomplete analysis gracefully
5. **Be explicit about units**: "bytes", "instructions", "rounds"

**Good Output Design:**
```json
{
  "total_found": 3,
  "candidates": [
    {
      "address": "0x401234",
      "name": "main",
      "confidence": 0.95,
      "details": "..."
    }
  ],
  "analysis_time_ms": 45
}
```

**Poor Output Design:**
```json
{
  "c": 3,           // Unclear abbreviation
  "r": [...]        // What is "r"?
  "d": "..."        // Ambiguous field
}
```

## Backward Compatibility

### Adding New Tools
- No compatibility concerns
- Document in new section of guides

### Modifying Existing Tools
- **Input**: Adding optional parameters is safe
- **Input**: Removing/renaming parameters breaks compatibility
- **Output**: Adding fields is safe
- **Output**: Removing fields breaks consumers

**Migration Strategy:**
```rust
// Old tool (deprecated, still available)
pub fn tool_old_function(&mut self, args: Value) -> Result<Value> {
    // Mark as deprecated in documentation
    // Redirect to new tool with mapping
    self.tool_new_function(args)
}

// New tool
pub fn tool_new_function(&mut self, args: Value) -> Result<Value> {
    // Implementation
}
```

### Versioning Tools
If breaking change is necessary:

```rust
// In call_tool match:
"tool_name_v2" => self.tool_name_v2(args),  // New version
"tool_name" => self.tool_name_v1(args),     // Old version (deprecated)
```

Document in migration guide:
- Why breaking change was needed
- How to update scripts
- Timeline for deprecation

## Testing Strategy

### Unit Tests
Test core logic in isolation:
```rust
#[test]
fn identifies_pattern_in_simple_case() { }

#[test]
fn handles_edge_case_correctly() { }

#[test]
fn returns_empty_on_no_matches() { }
```

### Integration Tests
Test tool through service layer:
```rust
#[test]
fn service_tool_returns_correct_json() {
    let mut service = ToolService::new(/* ... */);
    let result = service.call_tool("find_something", json!({"addr": "0x1000"}));
    assert!(result.is_ok());
    // Verify JSON structure
}
```

### Roundtrip Tests
Test compilation and execution:
```rust
#[test]
fn sample_analyzes_complete_function() {
    // Load sample binary
    // Run tool on function
    // Verify results match expectations
}
```

## Performance Considerations

### Optimization Techniques

1. **Caching Results**
   - Cache expensive computations
   - Invalidate on binary reload
   - Use `Arc<DashMap>` for thread-safe caching

2. **Lazy Evaluation**
   - Don't compute what isn't requested
   - Support pagination with `offset`/`limit`

3. **Batch Operations**
   - Process multiple addresses efficiently
   - Return batch results in single call

4. **Memory Management**
   - Use references instead of cloning
   - Stream results for large datasets
   - Clean up temporary state

### Performance Targets

| Tool Type | Time Budget | Sample Size |
|-----------|------------|-------------|
| Skeleton analysis | <10ms | 100 functions |
| IL lifting | 50-100ms | per function |
| Datalog query | 100-500ms | reachability |
| Emulation | 10-100ms | per 1000 instructions |
| Search | <1ms per item | 10k locations |

## Documentation Standards

### For Analyst Guides

**In quick-reference.md:**
```markdown
| Goal | Tools | Example |
|------|-------|---------|
| {Your goal} | `tool_name` | `tool_name(param="value")` |
```

**In analysis-workflows.md:**
```markdown
### {Workflow Name}
{Goal statement}

Phase 1: {Description}
  → tool_1() → Look for {what}
  
Phase 2: {Description}
  → tool_2() → Verify {what}

Example: {Concrete example}
```

### Tool Description Standards

- **Purpose**: One sentence (what problem does it solve?)
- **Inputs**: List with types and descriptions
- **Outputs**: Structure with field descriptions
- **Use Cases**: 2-3 specific analyst workflows
- **Limitations**: Be explicit about constraints
- **Examples**: Copy-paste ready command

## Code Style Guidelines

### Naming Conventions
```rust
pub fn tool_find_something()  // Tool methods: tool_*
pub struct SomethingFinder    // Analysis types: CamelCase
pub fn find_in_function()     // Helper methods: snake_case
const DEFAULT_LIMIT: usize    // Constants: SCREAMING_SNAKE_CASE
```

### Error Handling
```rust
// Return meaningful error messages
Err(format!(
    "IL coverage {:.1}% < 85% minimum for analysis. Use get_asm() instead.",
    coverage * 100.0
))?

// Don't silently fail
// Don't use generic "Error occurred"
```

### Documentation Comments
```rust
/// Finds integer overflow vulnerabilities in a function.
///
/// Analyzes arithmetic operations for potential overflows by examining
/// operand sizes and operation types. Requires IL lift coverage >80%.
///
/// # Arguments
/// * `addr` - Function address to analyze
///
/// # Returns
/// Vector of potential overflow candidates with confidence scores
pub fn find_integer_overflows(&self, addr: u64) -> Vec<Candidate> {
```

## Common Pitfalls

### Pitfall 1: Ignoring IL Coverage
```rust
// ❌ Wrong: Uses IL without checking coverage
let cfg = self.get_cfg(addr)?;  // May be incomplete!

// ✅ Right: Checks coverage first
if self.get_coverage()? < 0.85 {
    return Err("IL coverage too low".into());
}
let cfg = self.get_cfg(addr)?;
```

### Pitfall 2: Infinite Recursion in Graph Analysis
```rust
// ❌ Wrong: No recursion limit
fn analyze_reachable(&self, addr: u64) -> Vec<u64> {
    let mut visited = Vec::new();
    self.dfs(addr, &mut visited);  // May infinite loop on cycles
    visited
}

// ✅ Right: Tracks visited nodes
fn dfs(&self, addr: u64, visited: &mut HashSet<u64>) {
    if visited.contains(&addr) { return; }
    visited.insert(addr);
    // Continue recursion
}
```

### Pitfall 3: Non-deterministic Results
```rust
// ❌ Wrong: HashMap iteration order is non-deterministic
let results: Vec<_> = self.results.iter().collect();

// ✅ Right: Sort for consistent output
let mut results: Vec<_> = self.results.iter().collect();
results.sort_by_key(|r| r.address);
```

### Pitfall 4: Missing Bounds on Expensive Operations
```rust
// ❌ Wrong: May process millions of items
pub fn analyze_all(&self) -> Result<Vec<Result>> {
    let results = self.list_functions()?  // Could be 10k+ functions
        .iter()
        .map(|f| self.analyze_function(f))
        .collect();
    Ok(results)
}

// ✅ Right: Has pagination
pub fn analyze_all(&self, offset: usize, limit: usize) -> Result<Vec<Result>> {
    let results = self.list_functions(offset, limit)?
        .iter()
        .map(|f| self.analyze_function(f))
        .collect();
    Ok(results)
}
```

## Extension Examples

### Example 1: Simple Analyzer

Implement a tool to find functions with specific characteristics:

```rust
pub struct FunctionFilter {
    session: Arc<BinarySession>,
}

impl FunctionFilter {
    pub fn new(session: Arc<BinarySession>) -> Self {
        Self { session }
    }
    
    pub fn find_large_functions(&self, min_instructions: usize) -> Result<Vec<FunctionInfo>> {
        let mut results = Vec::new();
        let funcs = self.session.list_functions(0, 10000)?;
        
        for func in funcs {
            let skeleton = self.session.get_function_skeleton(&func.address)?;
            if skeleton.instruction_count >= min_instructions {
                results.push(FunctionInfo {
                    address: func.address,
                    name: func.name,
                    instruction_count: skeleton.instruction_count,
                });
            }
        }
        
        Ok(results)
    }
}
```

### Example 2: Pattern Search

Implement a tool to find instances of a pattern:

```rust
pub struct PatternFinder {
    session: Arc<BinarySession>,
}

impl PatternFinder {
    pub fn find_string_references(&self, pattern: &str) -> Result<Vec<StringRef>> {
        let mut results = Vec::new();
        let binary = self.session.binary();
        
        for addr in binary.data_section() {
            if let Ok(s) = binary.read_string(addr) {
                if s.contains(pattern) {
                    results.push(StringRef {
                        address: addr,
                        string: s,
                        xrefs: self.session.get_xrefs(addr)?,
                    });
                }
            }
        }
        
        Ok(results)
    }
}
```

## Next Steps

1. **Choose a tool to implement** based on analyst needs
2. **Follow the implementation steps** from Step 1-6
3. **Test thoroughly** with unit, integration, and roundtrip tests
4. **Document** in analyst guides and quick-reference
5. **Gather feedback** from analysts using the tool
6. **Iterate** based on real-world usage patterns

## Resources

- **Architecture**: [../README.md](../README.md) § Design Principles
- **Testing Examples**: crates/aeon/src/lib.rs tests
- **Service Layer**: crates/aeon-frontend/src/service.rs
- **Tool Schemas**: crates/aeon-frontend/src/tools.rs
- **Analyst Guides**: [ANALYST_GUIDE.md](ANALYST_GUIDE.md)

---

**Last Updated**: 2026-04-20  
**Status**: Complete  
**Tool System**: Stable (all tools backward compatible)
