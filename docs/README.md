# Aeon Documentation

Complete documentation suite for ARM64 ELF binary analysis using aeon MCP tools.

## Overview

This directory contains guides, workflows, and references for using aeon's analysis tools. Choose your starting point based on your role and experience level.

## Quick Navigation

### 👤 For Different Roles

**First-Time Users**
→ Start with [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Getting Started

**Security Researchers**
→ Go to [advanced-workflows.md](advanced-workflows.md) § Vulnerability Classification

**Reverse Engineers**
→ Go to [analysis-workflows.md](analysis-workflows.md) § How to Analyze an Unknown Function

**Integration Engineers**
→ Go to [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Integration Examples

**Tool Developers**
→ Go to [../README.md](../README.md) § Design Principles and Workspace Layout

### 🎯 For Different Tasks

| Task | Document | Section |
|------|----------|---------|
| Quick reference for all tools | [quick-reference.md](quick-reference.md) | Tool Categories table |
| Find a specific workflow pattern | [analysis-workflows.md](analysis-workflows.md) | Common Workflows section |
| Learn advanced techniques | [advanced-workflows.md](advanced-workflows.md) | Table of Contents |
| Get help with errors | [quick-reference.md](quick-reference.md) | Debugging Tips |
| Integrate aeon into scripts | [ANALYST_GUIDE.md](ANALYST_GUIDE.md) | Integration Examples |

## Documentation Files

### [ANALYST_GUIDE.md](ANALYST_GUIDE.md) - **START HERE**
**Purpose**: Navigation hub and integration guide  
**Audience**: All users  
**Length**: 343 lines  
**Contains**:
- Getting started instructions
- Navigation by task, goal, and workflow stage
- Quick command reference
- Performance tips
- Troubleshooting guide
- Python/Bash integration examples
- Resource index linking all docs

**When to use**: 
- First time using aeon
- Need to find a specific document
- Want command examples
- Building scripts or integrations

---

### [quick-reference.md](quick-reference.md) - **CHEAT SHEET**
**Purpose**: Compact reference for all tools and patterns  
**Audience**: Active analysts and tool users  
**Length**: 327 lines  
**Contains**:
- Tool categories with common patterns (tables)
- Copy-paste ready workflow templates (8 templates)
- Debugging tips with solutions
- Tool aliases and backward compatibility
- Performance tips (caching, batching)
- Output field reference (JSON examples)
- Integration examples (Python HTTP API, Bash CLI)
- Commonly used patterns

**Organization**:
- Binary Loading & Exploration
- Code Analysis
- Cross-References & Call Graphs
- Data & Constants
- Annotation & Documentation
- Emulation & Execution
- Specialized Detection

**When to use**:
- Need a command quickly
- Want a complete workflow template
- Debugging analysis issues
- Learning tool options

---

### [analysis-workflows.md](analysis-workflows.md) - **FOUNDATIONS**
**Purpose**: Step-by-step practical workflows for common analysis tasks  
**Audience**: Security analysts, reverse engineers  
**Length**: 432 lines  
**Contains**: 8 complete workflows with examples:
1. Quick-Start: 10-Minute Binary Survey
2. Vulnerability Hunting: Buffer Overflows
3. Crypto Algorithm Detection
4. Data Structure Recovery
5. Call Graph Analysis & Dependency Mapping
6. Obfuscation Detection & Deobfuscation
7. Integration with External Tools
8. Best Practices for Analysis

Each workflow includes:
- Clear goal statement
- Multi-phase approach with examples
- Specific tools to use
- Expected outputs
- Validation steps

**When to use**:
- Learning by example
- Following a structured analysis approach
- Understanding typical workflows
- Need step-by-step guidance

---

### [advanced-workflows.md](advanced-workflows.md) - **EXPERT PATTERNS**
**Purpose**: Sophisticated analysis techniques for complex scenarios  
**Audience**: Expert analysts, security researchers  
**Length**: 495 lines  
**Contains**: 5 advanced analysis domains:

---

### [TOOL_DEVELOPMENT.md](TOOL_DEVELOPMENT.md) - **DEVELOPER GUIDE**
**Purpose**: Reference for implementing new analysis tools  
**Audience**: Tool developers, system architects  
**Length**: 696 lines  
**Contains**:
- Tool architecture and lifecycle (7 steps)
- 4 tool tiers with stability guarantees
- Implementation steps (design, code, register, test)
- Integration patterns (analyzer, search, datalog, emulation)
- API design principles (input/output)
- Backward compatibility strategies
- Testing strategy (unit, integration, roundtrip)
- Code style guidelines
- Common pitfalls with corrections
- Extension examples with complete code

**Key Sections**:
- Architecture Components
- Step-by-Step Implementation Guide
- Tool Types & Tiers
- API Design Principles
- Backward Compatibility
- Testing Strategy
- Common Pitfalls
- Extension Examples

**When to use**:
- Planning a new tool
- Understanding aeon's tool system
- Learning best practices
- Avoiding common mistakes
- Implementing integration patterns

---

### [advanced-workflows.md](advanced-workflows.md) - **EXPERT PATTERNS** (continued)
**Contains**: 5 advanced analysis domains:

1. **Vulnerability Classification**
   - Automated severity assessment
   - Reachability analysis
   - Exploitation path detection

2. **Cryptographic Implementation Analysis**
   - Algorithm identification (AES, SHA, RSA, etc.)
   - Non-standard variant detection
   - Security assessment
   - Side-channel resistance analysis

3. **Reverse Engineering Protocol Handlers**
   - Message format discovery
   - Command handler mapping
   - State machine analysis
   - Format validation

4. **Dynamic Behavior Simulation**
   - Code execution without running full binary
   - Behavior extraction
   - Validation and refinement
   - String decryption example

5. **Supply Chain Analysis**
   - Third-party code identification
   - Version extraction
   - Dependency mapping
   - Compromise detection

Each domain includes:
- 5-phase workflow with detailed methodology
- Concrete example with step-by-step walkthrough
- Best practices and robustness tips
- Troubleshooting guidance

**When to use**:
- Advanced security analysis
- Detecting compromised libraries
- Analyzing obfuscated code
- Learning sophisticated techniques

---

## Document Comparison

| Aspect | ANALYST_GUIDE | quick-reference | analysis-workflows | advanced-workflows | TOOL_DEVELOPMENT |
|--------|---------------|-----------------|-------------------|-------------------|------------------|
| **Focus** | Navigation & integration | Commands & quick lookup | Practical step-by-step | Sophisticated techniques | Tool implementation |
| **Audience** | All users | Active analysts | Learners & practitioners | Expert analysts | Tool developers |
| **Example code** | Python/Bash scripts | Copy-paste templates | Full workflows | Domain examples | Rust implementation |
| **Depth** | Breadth (all areas) | Shallow (command reference) | Medium (detailed steps) | Deep (expert patterns) | Implementation details |
| **Search usage** | "How do I..." | "What's the command for..." | "How do I solve..." | "Advanced technique..." | "How do I build..." |

## Workflow Coverage

### By Analyst Type

**Security Auditor**:
1. [ANALYST_GUIDE.md](ANALYST_GUIDE.md) - overview
2. [advanced-workflows.md](advanced-workflows.md) § Vulnerability Classification
3. [quick-reference.md](quick-reference.md) § Debugging Tips

**Malware Analyst**:
1. [analysis-workflows.md](analysis-workflows.md) § Obfuscation Detection
2. [advanced-workflows.md](advanced-workflows.md) § Dynamic Behavior Simulation
3. [quick-reference.md](quick-reference.md) § Common Workflows

**Reverse Engineer**:
1. [analysis-workflows.md](analysis-workflows.md) § How to Analyze an Unknown Function
2. [advanced-workflows.md](advanced-workflows.md) § Reverse Engineering Protocol Handlers
3. [quick-reference.md](quick-reference.md) § Tool Categories

**Cryptographer**:
1. [advanced-workflows.md](advanced-workflows.md) § Cryptographic Implementation Analysis
2. [analysis-workflows.md](analysis-workflows.md) § Crypto Algorithm Detection
3. [quick-reference.md](quick-reference.md) § Specialized Detection

**Integrator**:
1. [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Integration Examples
2. [quick-reference.md](quick-reference.md) § Integration Examples
3. [../README.md](../README.md) § Interfaces (API details)

## Learning Path

### Beginner (Weeks 1-2)
1. Read [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Getting Started
2. Try one workflow from [analysis-workflows.md](analysis-workflows.md) on your own binary
3. Keep [quick-reference.md](quick-reference.md) open as reference
4. Practice annotation (`set-analysis-name`, `add-hypothesis`)

### Intermediate (Weeks 3-4)
1. Complete 3-4 workflows from [analysis-workflows.md](analysis-workflows.md)
2. Read [advanced-workflows.md](advanced-workflows.md) domain that matches your focus
3. Combine tools in new ways based on patterns
4. Document your analysis process

### Advanced (Week 5+)
1. Implement custom workflows from [advanced-workflows.md](advanced-workflows.md)
2. Develop reusable analysis scripts using [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Integration Examples
3. Contribute new workflow patterns
4. Mentor others through workflows

## Tool Reference

Each document cross-references the same set of tools. Here's how they're covered:

| Tool | quick-ref | analysis-workflows | advanced-workflows |
|------|-----------|-------------------|-------------------|
| load_binary | ✅ | - | - |
| list_functions | ✅ | ✅ | ✅ |
| get_function_skeleton | ✅ | ✅ | ✅ |
| get_il | ✅ | ✅ | ✅ |
| get_asm | ✅ | ✅ | ✅ |
| get_xrefs | ✅ | ✅ | ✅ |
| find_call_paths | ✅ | ✅ | ✅ |
| execute_datalog | ✅ | ✅ | ✅ |
| emulate_snippet | ✅ | ✅ | ✅ |
| scan_pointers | ✅ | ✅ | ✅ |
| scan_vtables | ✅ | ✅ | ✅ |
| set_analysis_name | ✅ | ✅ | ✅ |
| add_hypothesis | ✅ | ✅ | ✅ |
| define_struct | ✅ | ✅ | ✅ |
| search_rc4 | ✅ | ✅ | ✅ |

See [../README.md](../README.md) for complete tool descriptions and JSON schemas.

## Common Questions

### "Where should I start?"
→ [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Getting Started

### "I need a quick command reference"
→ [quick-reference.md](quick-reference.md) § Tool Categories (tables)

### "I want to learn by example"
→ [analysis-workflows.md](analysis-workflows.md) § Table of Contents (pick your topic)

### "I need expert-level technique"
→ [advanced-workflows.md](advanced-workflows.md) § Table of Contents (pick your domain)

### "I'm getting an error"
→ [quick-reference.md](quick-reference.md) § Debugging Tips (solution table)

### "How do I integrate aeon into my scripts?"
→ [ANALYST_GUIDE.md](ANALYST_GUIDE.md) § Integration Examples

### "What's the complete tool API?"
→ [../README.md](../README.md) § Interfaces (CLI, MCP, HTTP)

## Documentation Statistics

| Document | Lines | Primary Content | Secondary Content |
|----------|-------|-----------------|-------------------|
| ANALYST_GUIDE.md | 343 | Navigation & integration | 15+ tools, 5 code examples |
| quick-reference.md | 327 | Commands & patterns | 15+ tools, 20+ snippets |
| analysis-workflows.md | 432 | 8 practical workflows | 15+ tools, 8 examples |
| advanced-workflows.md | 495 | 5 expert domains | 15+ tools, 5 examples |
| TOOL_DEVELOPMENT.md | 696 | Implementation guide | 4 patterns, 2 code examples |
| docs/README.md | 339 | Documentation index | Navigation & comparison |
| **TOTAL** | **2632** | **6 comprehensive guides** | **40+ examples & 15+ tools** |

## Contribution Guidelines

### Adding New Workflows

1. Choose appropriate document:
   - **Practical, common task**: [analysis-workflows.md](analysis-workflows.md)
   - **Sophisticated, expert-level**: [advanced-workflows.md](advanced-workflows.md)

2. Follow the pattern:
   - Clear goal statement
   - Multi-phase approach
   - Specific tools with examples
   - Expected outputs

3. Include validation step showing how to verify results

### Adding Examples

1. For commands: Update [quick-reference.md](quick-reference.md)
2. For patterns: Add to [analysis-workflows.md](analysis-workflows.md) § Common Patterns
3. For techniques: Add to [advanced-workflows.md](advanced-workflows.md) § Common Recipes

### Updating Documentation

Keep all documents in sync:
- Tool name changes: Update all 4 docs
- Tool removal/deprecation: Mark clearly and explain alternatives
- New tools: Add to tables in each document

## Related Documentation

- **Architecture & Design**: [../README.md](../README.md)
- **Workspace Layout**: [../README.md](../README.md) § Workspace Layout
- **Build & Install**: [../README.md](../README.md) § Build
- **Interfaces**: [../README.md](../README.md) § Interfaces (CLI, MCP, HTTP)

## Version & Status

- **Last Updated**: 2026-04-20
- **Documentation Version**: 1.0
- **Tool Coverage**: All stable tools (Tier 1-3)
- **Status**: ✅ Complete for current tool set

---

## Quick Links

**For Analysts:**
- **Start here**: [ANALYST_GUIDE.md](ANALYST_GUIDE.md)
- **Command reference**: [quick-reference.md](quick-reference.md)
- **Learn by example**: [analysis-workflows.md](analysis-workflows.md)
- **Advanced techniques**: [advanced-workflows.md](advanced-workflows.md)

**For Developers:**
- **Build a tool**: [TOOL_DEVELOPMENT.md](TOOL_DEVELOPMENT.md)
- **Architecture**: [../README.md](../README.md)
- **This index**: [README.md](README.md)

**Got a question?** Check the [Common Questions](#common-questions) section above.
