# Aeon Deployment & Installation Guide

Complete guide for building, installing, and deploying aeon in various environments.

## Quick Start (5 minutes)

### Prerequisites
- Rust 1.75+ (`rustup` recommended)
- 2GB+ free disk space
- Linux/macOS (primary development targets)

### Build & Install
```bash
# Clone repository
git clone https://github.com/anthropics/aeon.git
cd aeon

# Build release binary
cargo build --release

# Run first test
./target/release/aeon load-binary --path samples/hello_aarch64.elf
```

**Result**: Ready to use in ~3-5 minutes

---

## Installation Methods

### Method 1: Local Development (Recommended for Analysts)

```bash
# Clone and build
git clone https://github.com/anthropics/aeon.git
cd aeon
cargo build --release

# Add to PATH
export PATH="$PATH:$(pwd)/target/release"

# Or symlink
ln -s $(pwd)/target/release/aeon /usr/local/bin/aeon
```

**Pros**: Easy to update, access to source, customizable  
**Cons**: Build time (2-3 minutes), requires Rust  
**Best For**: Developers, custom analysis, frequent updates

---

### Method 2: System Installation (For Production)

```bash
# Build release binaries
cargo build --release

# Copy binaries to system locations
sudo cp target/release/aeon /usr/local/bin/
sudo cp target/release/aeon-mcp /usr/local/bin/
sudo cp target/release/aeon-http /usr/local/bin/

# Verify installation
which aeon
aeon load-binary --help
```

**Pros**: Available system-wide, no rebuild needed  
**Cons**: Manual updates, requires sudo  
**Best For**: System administrators, production servers

---

### Method 3: Docker Container (For Isolation)

Create `Dockerfile`:
```dockerfile
FROM rust:1.75

WORKDIR /workspace
RUN git clone https://github.com/anthropics/aeon.git .
RUN cargo build --release

ENV PATH="/workspace/target/release:${PATH}"

ENTRYPOINT ["aeon"]
```

Build and use:
```bash
# Build image
docker build -t aeon:latest .

# Run analysis
docker run -v /path/to/binary:/data aeon load-binary --path /data/binary.elf
docker run -v /path/to/binary:/data aeon list-functions
```

**Pros**: Complete isolation, reproducible, no local Rust needed  
**Cons**: Slower startup, requires Docker  
**Best For**: CI/CD pipelines, containers, sandboxed analysis

---

## Running Aeon

### CLI Mode (Single Query)

```bash
# Load binary and get results
aeon load-binary --path binary.elf
aeon list-functions --limit 10
aeon get-il --addr 0x401234
```

**Use When**: One-off analysis, simple queries  
**Performance**: Fast startup, slow for many queries

---

### HTTP API Mode (Persistent Session)

**Terminal 1 (Start server)**:
```bash
# Start HTTP API server
aeon-http 127.0.0.1:8787

# Output:
# Listening on http://127.0.0.1:8787
```

**Terminal 2 (Run analysis)**:
```bash
# Load binary (persistent)
curl -X POST http://127.0.0.1:8787/call \
  -H 'Content-Type: application/json' \
  -d '{"name":"load_binary","arguments":{"path":"binary.elf"}}'

# List functions (reuses loaded binary)
curl -X POST http://127.0.0.1:8787/call \
  -H 'Content-Type: application/json' \
  -d '{"name":"list_functions","arguments":{"limit":10}}'
```

**Use When**: Multiple queries, persistent analysis session  
**Performance**: Slower first query, fast subsequent queries

---

## Testing Before Deployment

```bash
# Run test suite before deployment
cargo test --all

# Run specific important tests
cargo test --test integration_tests

# Verify binary works
./target/release/aeon load-binary --path samples/hello_aarch64.elf
./target/release/aeon list-functions
```

---

## Troubleshooting Installation

### Issue: "aeon: command not found"

**Solution**:
```bash
# Check PATH
echo $PATH

# Add directory to PATH
export PATH="$PATH:/path/to/aeon/target/release"

# Or verify binary exists
ls -la /path/to/aeon/target/release/aeon
```

---

### Issue: "error: linker 'cc' not found"

**Solution** (Ubuntu/Debian):
```bash
sudo apt-get install build-essential
```

**Solution** (macOS):
```bash
xcode-select --install
```

---

### Issue: "Cargo not found"

**Solution**:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

---

## System Requirements

### Minimum
- CPU: 2 cores
- RAM: 2GB
- Disk: 2GB (includes build artifacts)
- OS: Linux, macOS

### Recommended
- CPU: 4+ cores
- RAM: 8GB+
- Disk: 10GB+ (SSD recommended)
- OS: Ubuntu 20.04+, macOS 11+, Fedora 35+

### For Large Binaries (>100MB)
- CPU: 8+ cores
- RAM: 16GB+
- Disk: 50GB+ SSD

---

## Maintenance & Updates

### Check for Updates
```bash
cd /path/to/aeon
git fetch origin
git log --oneline origin/main | head -5
```

### Update to Latest
```bash
cd /path/to/aeon
git pull origin main
cargo build --release
```

---

## Next Steps

**After Installation**:
1. Read [docs/QUICKSTART.md](QUICKSTART.md) for first analysis
2. Follow [docs/ANALYST_GUIDE.md](ANALYST_GUIDE.md) for your workflow
3. Reference [docs/PERFORMANCE_GUIDE.md](PERFORMANCE_GUIDE.md) for optimization

---

**Deployment Guide Date**: April 20, 2026  
**Status**: Complete  
**Applicable To**: aeon 1.0+
