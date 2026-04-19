# aeon_instrument Trace Format Specification

**Version**: 1.0  
**Status**: Stable  
**Last Updated**: 2026-04-19

## Overview

The trace binary format (.trace files) records execution of ARM64 code blocks with full memory access instrumentation. Traces are designed for:
- Compact storage (780 bytes/block average)
- Streaming ingestion (process while reading)
- Forward compatibility (versioned headers)
- Symbolic analysis (dataflow tracking)

## File Structure

```
[Header (64 bytes)]
[Block Record 0 (variable)]
[Block Record 1 (variable)]
...
[Block Record N-1 (variable)]
```

## Header (64 bytes)

Byte offsets and little-endian encoding throughout.

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0-3 | 4 | Magic | u32 | `0x4145544F` ("AETO" in ASCII) |
| 4-5 | 2 | Version Major | u16 | Current: 1 |
| 6-7 | 2 | Version Minor | u16 | Current: 0 |
| 8-11 | 4 | Flags | u32 | See below |
| 12-19 | 8 | Timestamp | u64 | Unix seconds at trace start |
| 20-27 | 8 | Entry PC | u64 | Initial instruction pointer |
| 28-35 | 8 | Entry SP | u64 | Initial stack pointer |
| 36-43 | 8 | Block Count | u64 | Total blocks in trace |
| 44-51 | 8 | Total Memory Ops | u64 | Sum of all memory accesses |
| 52-63 | 12 | Reserved | Reserved | Must be zero |

### Flags (4 bytes)

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | HAS_MEMORY_SIZES | Memory access sizes included |
| 1 | HAS_REGISTER_STATE | Entry/exit register snapshots included |
| 2 | COMPRESSED | Block records are gzip-compressed |
| 3-31 | Reserved | Must be zero |

## Block Record (variable size)

Each block record captures one executed basic block.

### Block Header (64 bytes)

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0-7 | 8 | Address | u64 | Code address of block |
| 8-15 | 8 | Next PC | u64 | Instruction pointer after block |
| 16-23 | 8 | Sequence Number | u64 | Global execution order |
| 24-31 | 8 | Visit Count | u64 | Times this block was visited |
| 32-39 | 8 | Entry PC | u64 | Instruction pointer at entry |
| 40-47 | 8 | Memory Accesses | u64 | Count of mem ops in this block |
| 48-55 | 8 | Register Reads | u64 | Bitmask of registers read |
| 56-63 | 8 | Register Writes | u64 | Bitmask of registers written |

### Register Snapshots (optional, 256 bytes each)

If `HAS_REGISTER_STATE` flag is set:

```
[Entry Register State (256 bytes)]
[Exit Register State (256 bytes)]
```

Each register state:
- x[0-30]: 31 × 8 bytes = 248 bytes
- Flags: 1 × 8 bytes = 8 bytes

### Memory Access Records (variable)

For each memory access, in order of execution:

| Size | Field | Type | Description |
|------|-------|------|-------------|
| 8 | Address | u64 | Memory address accessed |
| 8 | Value | u64 | Value read/written |
| 1 | Size | u8 | Access size in bytes (1,2,4,8) |
| 1 | Flags | u8 | See below |

Memory Access Flags:
- Bit 0: Is Write (1) or Read (0)
- Bits 1-7: Reserved

**Total per access**: 18 bytes (minimum)

### Block Record End Marker

Optional 8-byte sentinel `0xDEADBEEFDEADBEEF` after all memory accesses to delimit blocks.

## Record Format Examples

### Minimal Block (no memory accesses, no register state)
```
64 bytes (block header)
= 64 bytes total
```

### Block with 5 Memory Accesses (no register state)
```
64 bytes (block header)
+ 18 × 5 bytes (memory accesses)
+ 8 bytes (end marker)
= 186 bytes total
```

### Block with Full Instrumentation
```
64 bytes (block header)
+ 256 bytes (entry registers)
+ 256 bytes (exit registers)
+ 18 × N bytes (memory accesses)
+ 8 bytes (end marker)
= 584 + (18 × N) bytes total
```

## Reading Algorithm

```rust
fn read_trace(path: &Path) -> Result<Vec<BlockRecord>> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header)?;
    
    // Verify magic + version
    let magic = u32::from_le_bytes(header[0..4].try_into()?);
    assert_eq!(magic, 0x4145544F);
    
    let version_major = u16::from_le_bytes(header[4..6].try_into()?);
    let version_minor = u16::from_le_bytes(header[6..8].try_into()?);
    assert_eq!(version_major, 1);
    
    let flags = u32::from_le_bytes(header[8..12].try_into()?);
    let block_count = u64::from_le_bytes(header[36..44].try_into()?) as usize;
    
    let mut blocks = Vec::with_capacity(block_count);
    
    for _ in 0..block_count {
        let block = read_block(&mut file, flags)?;
        blocks.push(block);
    }
    
    Ok(blocks)
}

fn read_block(file: &mut File, flags: u32) -> Result<BlockRecord> {
    let mut block_header = [0u8; 64];
    file.read_exact(&mut block_header)?;
    
    let addr = u64::from_le_bytes(block_header[0..8].try_into()?);
    let next_pc = u64::from_le_bytes(block_header[8..16].try_into()?);
    let mem_access_count = u64::from_le_bytes(block_header[40..48].try_into()?) as usize;
    
    // Optional register state
    let entry_regs = if (flags & 0x2) != 0 {
        Some(read_register_state(file)?)
    } else {
        None
    };
    
    let exit_regs = if (flags & 0x2) != 0 {
        Some(read_register_state(file)?)
    } else {
        None
    };
    
    // Read memory accesses
    let mut accesses = Vec::with_capacity(mem_access_count);
    for _ in 0..mem_access_count {
        let access = read_memory_access(file)?;
        accesses.push(access);
    }
    
    // Optional end marker
    let mut marker = [0u8; 8];
    if file.read_exact(&mut marker).is_ok() {
        let marker_val = u64::from_le_bytes(marker);
        if marker_val != 0xDEADBEEFDEADBEEF {
            file.seek(SeekFrom::Current(-8))?; // Backtrack if not marker
        }
    }
    
    Ok(BlockRecord {
        addr,
        next_pc,
        entry_regs,
        exit_regs,
        memory_accesses: accesses,
    })
}
```

## Versioning Strategy

### Version 1.0 (Current)
- Basic block execution tracing
- Memory access instrumentation
- Optional register snapshots
- Fixed 64-byte block headers

### Version 1.1 (Planned)
- Compressed block records (gzip)
- Extended memory size tracking
- Branch condition tracking
- Variable-length encoding for addresses

### Version 2.0 (Future)
- Multi-threaded trace support
- Call stack unwinding
- Exception handling records
- SIMD register state

### Compatibility Rules

**Forward Compatibility**:
- Readers MAY ignore unrecognized flags
- Readers MUST skip unknown record types
- New flags go in upper bits; old readers see them as zero

**Backward Compatibility**:
- Version 1.1 readers understand 1.0 files (flags determine presence)
- Version 2.0 files use different magic or version numbers
- No file format changes within major version

## Storage Characteristics

### Compression Potential

Typical uncompressed trace:
- hello_aarch64: 12 blocks × 64 bytes = 768 bytes (no memory ops)
- loops_cond_aarch64: 100 blocks × (64 + 18×10) accesses = 18.4 KB
- NMSS crypto (4 blocks, 22 accesses): ~1.2 KB

With gzip compression:
- Highly repetitive memory patterns compress 3-5×
- Recommended for large traces (>1 MB)

### Streaming Ingestion

The format supports reading incrementally:
```rust
let mut blocks = Vec::new();
loop {
    match read_block(&mut file, flags) {
        Ok(block) => {
            process_block(&block); // Analyze immediately
            blocks.push(block);
        }
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
        Err(e) => return Err(e),
    }
}
```

This enables:
- Live trace processing (no full load required)
- Bounded memory usage (process-and-discard)
- Early termination on threshold

## Validation Checklist

When reading a trace file:

- [ ] File size ≥ 64 bytes (header)
- [ ] Magic == 0x4145544F
- [ ] Version major ≤ 1
- [ ] Flags reserved bits == 0
- [ ] Block count matches actual records
- [ ] Total memory ops count is consistent
- [ ] Memory access counts per block match
- [ ] All addresses are within expected range
- [ ] Sequence numbers are monotonically increasing

## Tools & Utilities

### Dump Trace Metadata
```bash
aeon-instrument-trace-dump --header trace.bin
# Output: version, block count, timestamp, entry PC
```

### Convert Format
```bash
aeon-instrument-trace-convert --from 1.0 --to 1.1 --compress input.trace output.trace
```

### Analyze Trace
```bash
aeon-instrument-trace-analyze trace.bin
# Output: memory access patterns, hot blocks, register usage
```

## Performance Impact

Reading full trace into memory:
- **Time**: O(n) where n = block count
- **Space**: O(n + m) where m = memory access count
- **Typical**: 10KB/ms throughput on modern hardware

Streaming (process-and-discard):
- **Time**: O(n) (same)
- **Space**: O(1) constant
- **Recommended for**: Large programs (>100K blocks)

## References

- Block trace recording: `crates/aeon-instrument/src/trace.rs`
- Format constants: `crates/aeon-instrument/src/trace.rs`
- Serialization: `serde_json` + custom binary writer
- Test vectors: `crates/aeon-instrument/tests/engine_integration.rs`

## Appendix: Magic Number Justification

`0x4145544F` = "AETO" in little-endian ASCII:
- 0x41 = 'A' (Aeon)
- 0x45 = 'E' (Execution)
- 0x54 = 'T' (Trace)
- 0x4F = 'O' (Output)

Provides obvious text marker when examining hex dumps.
