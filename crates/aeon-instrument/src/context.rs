// Live execution context: registers + memory accessor
//
// MemoryProvider trait abstracts where memory comes from:
//   - SnapshotMemory: flat byte buffer (from core dump / memory dump)
//   - MappedElf: ELF segments mapped at their load addresses
//   - ProxyMemory: reads forwarded to a remote debugger / agent
//
// LiveContext holds the ARM64 register state and a boxed MemoryProvider.
// It converts to/from aeon_jit::JitContext for execution.

use aeon::elf::LoadedBinary;
use aeon_jit::JitContext;
use std::collections::BTreeMap;

/// Trait for providing memory to the instrumentation engine.
pub trait MemoryProvider: Send {
    /// Read `size` bytes from virtual address `addr`.
    /// Returns None if the address is unmapped.
    fn read(&self, addr: u64, size: usize) -> Option<Vec<u8>>;

    /// Write bytes to virtual address. Optional — returns false if unsupported.
    fn write(&mut self, _addr: u64, _data: &[u8]) -> bool {
        false
    }
}

/// Flat memory snapshot.
pub struct SnapshotMemory {
    pub regions: BTreeMap<u64, Vec<u8>>,
}

impl SnapshotMemory {
    pub fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
        }
    }

    pub fn add_region(&mut self, base: u64, data: Vec<u8>) {
        self.regions.insert(base, data);
    }
}

impl MemoryProvider for SnapshotMemory {
    fn read(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        for (&base, data) in &self.regions {
            let end = base + data.len() as u64;
            if addr >= base && addr + size as u64 <= end {
                let offset = (addr - base) as usize;
                return Some(data[offset..offset + size].to_vec());
            }
        }
        None
    }

    fn write(&mut self, addr: u64, new_data: &[u8]) -> bool {
        for (&base, data) in self.regions.iter_mut() {
            let end = base + data.len() as u64;
            if addr >= base && addr + new_data.len() as u64 <= end {
                let offset = (addr - base) as usize;
                data[offset..offset + new_data.len()].copy_from_slice(new_data);
                return true;
            }
        }
        false
    }
}

/// Memory provider backed by an ELF binary's LOAD segments.
///
/// Maps the ELF's LOAD segments so the JIT can read instructions and data
/// at their original virtual addresses.
pub struct ElfMemory {
    binary: LoadedBinary,
}

impl ElfMemory {
    /// Create an ElfMemory from an ELF file path.
    pub fn from_elf(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let binary = aeon::elf::load_elf(path)?;
        Ok(Self { binary })
    }

    /// Create an ElfMemory from an already-loaded binary.
    pub fn from_loaded(binary: LoadedBinary) -> Self {
        Self { binary }
    }

    /// Access the underlying LoadedBinary.
    pub fn binary(&self) -> &LoadedBinary {
        &self.binary
    }
}

impl MemoryProvider for ElfMemory {
    fn read(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        let data = self.binary.read_vaddr(addr, size)?;
        if data.len() == size {
            Some(data.to_vec())
        } else {
            None
        }
    }
}

/// Live execution context — ARM64 state + memory.
pub struct LiveContext {
    pub regs: JitContext,
    pub memory: Box<dyn MemoryProvider>,
}

impl LiveContext {
    pub fn new(memory: Box<dyn MemoryProvider>) -> Self {
        Self {
            regs: JitContext::default(),
            memory,
        }
    }

    pub fn pc(&self) -> u64 {
        self.regs.pc
    }

    pub fn set_pc(&mut self, pc: u64) {
        self.regs.pc = pc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SnapshotMemory: read ──────────────────────────────────────

    #[test]
    fn read_within_single_region() {
        let mut mem = SnapshotMemory::new();
        mem.add_region(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let data = mem.read(0x1000, 4).unwrap();
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn read_at_offset_within_region() {
        let mut mem = SnapshotMemory::new();
        mem.add_region(0x1000, vec![0x00, 0x11, 0x22, 0x33, 0x44]);
        let data = mem.read(0x1002, 2).unwrap();
        assert_eq!(data, vec![0x22, 0x33]);
    }

    #[test]
    fn read_returns_none_for_unmapped() {
        let mem = SnapshotMemory::new();
        assert!(mem.read(0x1000, 1).is_none());
    }

    #[test]
    fn read_returns_none_past_region_end() {
        let mut mem = SnapshotMemory::new();
        mem.add_region(0x1000, vec![0xAA, 0xBB]);
        // Reading 4 bytes starting at 0x1000 overflows the 2-byte region
        assert!(mem.read(0x1000, 4).is_none());
    }

    #[test]
    fn read_returns_none_before_region_start() {
        let mut mem = SnapshotMemory::new();
        mem.add_region(0x1000, vec![0xAA, 0xBB]);
        assert!(mem.read(0x0FFF, 1).is_none());
    }

    #[test]
    fn read_across_regions_fails() {
        let mut mem = SnapshotMemory::new();
        // Two adjacent regions: [0x1000..0x1002] and [0x1002..0x1004]
        mem.add_region(0x1000, vec![0xAA, 0xBB]);
        mem.add_region(0x1002, vec![0xCC, 0xDD]);
        // Reading 4 bytes from 0x1000 spans both — should fail (no cross-region reads)
        assert!(mem.read(0x1000, 4).is_none());
    }

    #[test]
    fn read_from_correct_region_among_multiple() {
        let mut mem = SnapshotMemory::new();
        mem.add_region(0x1000, vec![0x11; 16]);
        mem.add_region(0x2000, vec![0x22; 16]);
        let data = mem.read(0x2004, 4).unwrap();
        assert_eq!(data, vec![0x22, 0x22, 0x22, 0x22]);
    }

    // ── SnapshotMemory: write ─────────────────────────────────────

    #[test]
    fn write_within_region() {
        let mut mem = SnapshotMemory::new();
        mem.add_region(0x1000, vec![0x00; 8]);
        assert!(mem.write(0x1002, &[0xFF, 0xEE]));
        let data = mem.read(0x1000, 8).unwrap();
        assert_eq!(data, vec![0x00, 0x00, 0xFF, 0xEE, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn write_returns_false_for_unmapped() {
        let mut mem = SnapshotMemory::new();
        assert!(!mem.write(0x1000, &[0xFF]));
    }

    #[test]
    fn write_returns_false_past_region_end() {
        let mut mem = SnapshotMemory::new();
        mem.add_region(0x1000, vec![0x00; 2]);
        assert!(!mem.write(0x1000, &[0xFF; 4]));
    }

    #[test]
    fn write_then_read_roundtrip() {
        let mut mem = SnapshotMemory::new();
        mem.add_region(0x1000, vec![0x00; 16]);
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert!(mem.write(0x1004, &payload));
        let readback = mem.read(0x1004, 4).unwrap();
        assert_eq!(readback, payload);
    }

    // ── LiveContext ───────────────────────────────────────────────

    #[test]
    fn live_context_pc_get_set() {
        let mem = SnapshotMemory::new();
        let mut ctx = LiveContext::new(Box::new(mem));
        assert_eq!(ctx.pc(), 0);
        ctx.set_pc(0x400000);
        assert_eq!(ctx.pc(), 0x400000);
    }

    #[test]
    fn live_context_reads_through_memory_provider() {
        let mut mem = SnapshotMemory::new();
        mem.add_region(0x1000, vec![0x42; 4]);
        let ctx = LiveContext::new(Box::new(mem));
        let data = ctx.memory.read(0x1000, 4).unwrap();
        assert_eq!(data, vec![0x42; 4]);
    }
}
