// Execution and dataflow tracing
//
// Records every block entry, register state transition, and memory
// read/write during instrumented execution. The trace is the raw
// material for symbolic folding.
//
// TraceWriter provides buffered disk-backed writing using bincode.
// File format: [4-byte magic "AETR"][4-byte LE version 1]
//   then repeated: [4-byte LE length][bincode BlockTrace of that length]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use aeon_jit::JitContext;
use serde::{Deserialize, Serialize};

/// A single memory access observed during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccess {
    pub addr: u64,
    pub size: u8,
    pub value: u64,
    pub is_write: bool,
    /// Block address where this access occurred.
    pub block_addr: u64,
    /// Sequential index within the trace.
    pub seq: u64,
}

/// Register state snapshot at a block boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegSnapshot {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub flags: u64,
}

impl From<&JitContext> for RegSnapshot {
    fn from(ctx: &JitContext) -> Self {
        Self {
            x: ctx.x,
            sp: ctx.sp,
            pc: ctx.pc,
            flags: ctx.flags,
        }
    }
}

/// A traced block execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTrace {
    pub addr: u64,
    pub entry_regs: RegSnapshot,
    pub exit_regs: RegSnapshot,
    pub memory_accesses: Vec<MemoryAccess>,
    pub next_pc: u64,
    /// How many times this block has been visited.
    pub visit_count: u64,
    pub seq: u64,
}

/// Full execution trace — append-only log.
///
/// When disk-backed tracing is enabled, in-memory blocks can be drained
/// periodically to bound RAM. The `block_visits` map and aggregate counters
/// survive drains so the engine's limit checks remain accurate.
#[derive(Debug, Default)]
pub struct TraceLog {
    pub blocks: Vec<BlockTrace>,
    pub total_memory_reads: u64,
    pub total_memory_writes: u64,
    next_seq: u64,
    /// Persistent visit count per block address — survives drain_blocks().
    block_visits: BTreeMap<u64, u64>,
}

impl TraceLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_block(&mut self, trace: BlockTrace) {
        self.total_memory_reads +=
            trace.memory_accesses.iter().filter(|a| !a.is_write).count() as u64;
        self.total_memory_writes +=
            trace.memory_accesses.iter().filter(|a| a.is_write).count() as u64;
        *self.block_visits.entry(trace.addr).or_insert(0) += 1;
        self.blocks.push(trace);
        self.next_seq += 1;
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Persistent visit count for a block address (survives drains).
    pub fn block_visit_count(&self, addr: u64) -> u64 {
        self.block_visits.get(&addr).copied().unwrap_or(0)
    }

    /// Drain in-memory blocks, returning them for external use.
    /// Counters, sequence numbers, and visit counts are preserved.
    pub fn drain_blocks(&mut self) -> Vec<BlockTrace> {
        std::mem::take(&mut self.blocks)
    }

    /// All unique block addresses visited (across full lifetime, not just in-memory).
    pub fn unique_blocks(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.block_visits.keys().copied().collect();
        addrs.sort();
        addrs
    }

    /// Visit count per block address (across full lifetime).
    pub fn visit_counts(&self) -> BTreeMap<u64, u64> {
        self.block_visits.clone()
    }

    /// Extract the trace for a specific block address (in-memory blocks only).
    pub fn traces_for_block(&self, addr: u64) -> Vec<&BlockTrace> {
        self.blocks.iter().filter(|b| b.addr == addr).collect()
    }
}

// ── Disk-backed trace writer ────────────────────────────────────────

const TRACE_MAGIC: &[u8; 4] = b"AETR";
const TRACE_VERSION: u32 = 1;

/// Default BufWriter capacity: 8 MB.
const DEFAULT_BUF_CAPACITY: usize = 8 * 1024 * 1024;

/// Buffered disk-backed trace writer.
///
/// Writes length-prefixed bincode-serialized `BlockTrace` entries.
/// The file is appendable across flushes within a single session.
pub struct TraceWriter {
    writer: BufWriter<File>,
    path: PathBuf,
    bytes_written: u64,
    entries_written: u64,
}

impl TraceWriter {
    /// Create a new trace file at `path`, writing the file header.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::create(&path)?;
        let mut writer = BufWriter::with_capacity(DEFAULT_BUF_CAPACITY, file);

        // File header: magic + version
        writer.write_all(TRACE_MAGIC)?;
        writer.write_all(&TRACE_VERSION.to_le_bytes())?;

        Ok(Self {
            writer,
            path,
            bytes_written: 8,
            entries_written: 0,
        })
    }

    /// Write a single block trace entry (length-prefixed bincode).
    pub fn write_block(&mut self, trace: &BlockTrace) -> io::Result<()> {
        let encoded =
            bincode::serialize(trace).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let len = encoded.len() as u32;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&encoded)?;
        self.bytes_written += 4 + encoded.len() as u64;
        self.entries_written += 1;
        Ok(())
    }

    /// Write a batch of block traces.
    pub fn write_blocks(&mut self, traces: &[BlockTrace]) -> io::Result<()> {
        for trace in traces {
            self.write_block(trace)?;
        }
        Ok(())
    }

    /// Flush the internal buffer to disk.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn entries_written(&self) -> u64 {
        self.entries_written
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Read a trace file back into a Vec of BlockTrace entries.
pub fn read_trace_file(path: impl AsRef<Path>) -> io::Result<Vec<BlockTrace>> {
    use std::io::Read;
    let mut file = File::open(path)?;

    // Verify header
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != TRACE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad trace magic",
        ));
    }
    let mut ver = [0u8; 4];
    file.read_exact(&mut ver)?;
    let version = u32::from_le_bytes(ver);
    if version != TRACE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported trace version {}", version),
        ));
    }

    // Read length-prefixed entries
    let mut entries = Vec::new();
    let mut len_buf = [0u8; 4];
    loop {
        match file.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)?;
        let trace: BlockTrace =
            bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        entries.push(trace);
    }

    Ok(entries)
}
