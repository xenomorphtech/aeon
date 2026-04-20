# Aeon Quick Start - 10 Minute Guide

Get up and running with aeon in 10 minutes. By the end of this guide, you'll analyze a real binary.

## Prerequisites (2 minutes)

### Install Rust (if needed)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Clone & Build Aeon
```bash
cd /path/to/aeon
cargo build --release
```

**Result**: `target/release/aeon` binary ready to use

## Get a Sample Binary (1 minute)

Aeon comes with a sample ARM64 binary for testing:

```bash
ls -lh samples/hello_aarch64.elf
# Result: Small test binary (~100KB)
```

Or use your own ARM64 ELF binary if you have one.

## Step 1: Load the Binary (1 minute)

```bash
aeon load-binary --path samples/hello_aarch64.elf
```

**Output**: Binary loaded, analysis session ready

**What it means**: Aeon has parsed the binary, discovered functions from .eh_frame, and prepared to answer questions.

## Step 2: List Functions (1 minute)

```bash
aeon list-functions --limit 10
```

**Output** (example):
```
0x7d8     _start
0x800     main
0x824     printf
0x844     strlen
...
```

**What it means**: These are the functions found in the binary. We can analyze any of them.

## Step 3: Analyze a Function (2 minutes)

Pick one function and get a quick overview:

```bash
aeon get-function-skeleton --addr 0x800
```

**Output** (example):
```json
{
  "address": "0x800",
  "name": "main",
  "instruction_count": 45,
  "arg_count": 2,
  "calls": ["printf", "strlen"],
  "strings": ["Hello", "World"],
  "loops": 1,
  "crypto_patterns": [],
  "stack_usage": 32
}
```

**What it means**:
- **instruction_count**: 45 instructions (small function)
- **calls**: Calls printf and strlen
- **strings**: Contains string literals "Hello" and "World"
- **loops**: Has 1 loop

## Step 4: View the Code (2 minutes)

Get the detailed IL (intermediate language) representation:

```bash
aeon get-il --addr 0x800
```

**Output** (example):
```
stmt: assign x0 = imm(0x1000)           # Load address
stmt: call printf                        # Call printf
stmt: assign x0 = add(x0, imm(1))       # Increment x0
stmt: ret                                 # Return
```

**What it means**: This is the code in a standardized format. Each statement represents one operation.

## Step 5: Find References (1 minute)

See where this function is called:

```bash
aeon get-xrefs --addr 0x800
```

**Output** (example):
```json
{
  "incoming_calls": ["0x7d8"],      # _start calls main
  "outgoing_calls": ["0x824", "0x844"],  # main calls printf, strlen
  "data_references": ["0x2000"]     # References data at 0x2000
}
```

## What You've Accomplished

✅ Loaded a binary  
✅ Discovered its functions  
✅ Analyzed function structure  
✅ Viewed the code  
✅ Found function calls  

**Total time**: ~10 minutes  
**Skills learned**: Basic aeon workflow

## Next Steps

### Option 1: Analyze More Functions
```bash
# Find interesting functions
aeon list-functions | head -20

# Analyze each
aeon get-function-skeleton --addr 0x824
aeon get-function-skeleton --addr 0x844

# Pick one and dive deeper
aeon get-il --addr 0x844
```

### Option 2: Search for Patterns
```bash
# Find functions with loops
aeon list-functions | while read addr; do
  skeleton=$(aeon get-function-skeleton --addr $addr)
  if echo $skeleton | grep -q '"loops": [1-9]'; then
    echo "LOOP: $addr"
  fi
done
```

### Option 3: Learn a Workflow
Pick a task from [docs/ANALYST_GUIDE.md](ANALYST_GUIDE.md):
- Security researcher → [advanced-workflows.md](advanced-workflows.md) § Vulnerability Classification
- Reverse engineer → [analysis-workflows.md](analysis-workflows.md) § How to Analyze an Unknown Function
- Cryptographer → [advanced-workflows.md](advanced-workflows.md) § Cryptographic Implementation Analysis

## Common First Questions

### Q: How do I see assembly code?
```bash
aeon get-asm --start-addr 0x800 --stop-addr 0x900
```

### Q: How do I search for specific functions?
```bash
# If you know the name
aeon list-functions | grep printf

# If you know part of the name
aeon list-functions | grep -i crypto
```

### Q: How do I understand what a function does?
Follow the workflow:
1. `get-function-skeleton` - Quick overview
2. `get-il` - Detailed view
3. `get-xrefs` - Who calls it?
4. `get-data-flow-slice` - Where does input come from?
5. `add-hypothesis` - Document what you learned

**Example**:
```bash
# Get overview
aeon get-function-skeleton --addr 0x824

# Detailed view
aeon get-il --addr 0x824

# Who calls it?
aeon get-xrefs --addr 0x824

# Document finding
aeon set-analysis-name --addr 0x824 --name "my_understanding_of_this_function"
```

### Q: Where's the documentation?
- **Quick commands**: [quick-reference.md](quick-reference.md)
- **Workflows**: [analysis-workflows.md](analysis-workflows.md)
- **Advanced**: [advanced-workflows.md](advanced-workflows.md)
- **Errors**: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **Navigation**: [docs/README.md](docs/README.md)

### Q: Can I use aeon with my own scripts?
Yes! Use the HTTP API:

```python
import requests
import json

API = "http://127.0.0.1:8787"

# Start server in another terminal:
# aeon-http 127.0.0.1:8787

# Load binary
requests.post(f"{API}/call", json={
    "name": "load_binary",
    "arguments": {"path": "my_binary.elf"}
})

# List functions
response = requests.post(f"{API}/call", json={
    "name": "list_functions",
    "arguments": {"offset": 0, "limit": 10}
})

print(json.dumps(response.json(), indent=2))
```

See [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Integration Examples for more.

## Troubleshooting

### "Error: Binary not loaded"
**Solution**: Run `aeon load-binary --path <binary>` first

### "Error: Function not found at 0x..."
**Solution**: Use `list-functions` to see valid addresses

### "Error: IL coverage only 42%"
**Solution**: Use `get-asm` instead of `get-il` for this function

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for complete error guide.

## Key Concepts

### Address Format
- Always in **hex**: `0x401234`, not `4204084`
- Use leading zeros: `0x401234`, not `0x1234`

### Tools Return JSON
- All tools return structured JSON
- Parse with `jq` for command-line processing
- Fields include metadata and results

### Analysis Session
- One binary per session
- Named findings persist across queries
- Use HTTP API for persistent sessions

### Performance
- `get-function-skeleton`: <10ms (quick overview)
- `get-il`: 50-100ms (detailed analysis)
- Large binaries: Use pagination (`--offset` and `--limit`)

## Video Walkthrough (Text)

```bash
# 1. Start fresh
aeon load-binary --path samples/hello_aarch64.elf

# 2. What's in this binary?
aeon list-functions --limit 5

# 3. What does main do?
aeon get-function-skeleton --addr 0x800

# 4. Show me the code
aeon get-il --addr 0x800

# 5. Who calls main?
aeon get-xrefs --addr 0x800

# 6. Analyze caller
aeon get-function-skeleton --addr 0x7d8

# 7. Name this function
aeon set-analysis-name --addr 0x7d8 --name "entry_point"

# 8. Note about it
aeon add-hypothesis --addr 0x7d8 --note "Program entry from OS, sets up stack and calls main"

# Done! You've analyzed a real binary
```

## Where to Go Next

**Time Available** | **Next Step**
---|---
5 minutes | [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Quick Command Reference
15 minutes | Pick one workflow from [analysis-workflows.md](analysis-workflows.md)
30 minutes | Follow complete workflow for your domain
1 hour | Try on your own binary

## Summary

**You now know**:
- ✅ How to load a binary
- ✅ How to list functions
- ✅ How to analyze a function
- ✅ How to view code
- ✅ How to find references
- ✅ How to document findings

**Tools you used**:
- `load-binary` - Load binary for analysis
- `list-functions` - Discover functions
- `get-function-skeleton` - Quick overview
- `get-il` - Detailed view
- `get-xrefs` - Find references
- `set-analysis-name` - Name a function
- `add-hypothesis` - Document findings

**Tools available** (see [quick-reference.md](quick-reference.md)):
- 15+ additional tools for specialized analysis
- [advanced-workflows.md](advanced-workflows.md) shows how to combine them

---

**Next**: Pick [one workflow](analysis-workflows.md) matching your interests and follow it completely. You'll have real analysis skills in 1-2 hours.

**Questions?** → [TROUBLESHOOTING.md](TROUBLESHOOTING.md) § FAQ
