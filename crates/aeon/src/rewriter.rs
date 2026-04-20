use std::collections::BTreeMap;
use std::sync::Arc;

/// Represents a code region to be rewritten
#[derive(Debug, Clone)]
pub struct CodeRegion {
    /// Start address of the original code
    pub start_addr: u64,
    /// End address of the original code (exclusive)
    pub end_addr: u64,
    /// Original code bytes
    pub original_bytes: Vec<u8>,
}

impl CodeRegion {
    pub fn new(start_addr: u64, end_addr: u64, original_bytes: Vec<u8>) -> Self {
        Self {
            start_addr,
            end_addr,
            original_bytes,
        }
    }

    pub fn size(&self) -> u64 {
        self.end_addr - self.start_addr
    }
}

/// Memory protection flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProt {
    /// Read-only
    Read,
    /// Read-Write
    ReadWrite,
    /// Read-Write-Execute
    ReadWriteExecute,
}

/// Shadow memory entry tracking
#[derive(Debug, Clone)]
pub struct ShadowMemoryEntry {
    /// Shadow memory base address
    pub shadow_addr: u64,
    /// Original code region
    pub original_region: CodeRegion,
    /// Current memory protection of shadow
    pub protection: MemoryProt,
}

/// Manages shadow memory for code rewriting
pub struct ShadowMemory {
    /// Map from original code start address to shadow entry
    entries: BTreeMap<u64, ShadowMemoryEntry>,
    /// Next available shadow memory address
    next_shadow_addr: u64,
    /// Shadow memory base (must be RWX capable)
    shadow_base: u64,
    /// Maximum shadow memory size
    max_shadow_size: u64,
}

impl ShadowMemory {
    const DEFAULT_SHADOW_BASE: u64 = 0x100000000;
    const DEFAULT_MAX_SIZE: u64 = 0x10000000; // 256 MB

    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_shadow_addr: Self::DEFAULT_SHADOW_BASE,
            shadow_base: Self::DEFAULT_SHADOW_BASE,
            max_shadow_size: Self::DEFAULT_MAX_SIZE,
        }
    }

    pub fn with_base(shadow_base: u64, max_size: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            next_shadow_addr: shadow_base,
            shadow_base,
            max_shadow_size: max_size,
        }
    }

    /// Allocate shadow memory for a code region
    pub fn allocate(&mut self, region: CodeRegion) -> Result<ShadowMemoryEntry, String> {
        let size = region.size() as usize;

        // Check if we have space
        if self.next_shadow_addr + size as u64 > self.shadow_base + self.max_shadow_size {
            return Err("Shadow memory exhausted".to_string());
        }

        // Check if original region already has a shadow
        if self.entries.contains_key(&region.start_addr) {
            return Err(format!(
                "Code region {:#x} already has a shadow allocation",
                region.start_addr
            ));
        }

        let shadow_addr = self.next_shadow_addr;
        self.next_shadow_addr += size as u64;

        let entry = ShadowMemoryEntry {
            shadow_addr,
            original_region: region,
            protection: MemoryProt::ReadWriteExecute,
        };

        self.entries.insert(entry.original_region.start_addr, entry.clone());
        Ok(entry)
    }

    /// Get shadow entry for original address
    pub fn get_shadow(&self, original_addr: u64) -> Option<&ShadowMemoryEntry> {
        self.entries.get(&original_addr)
    }

    /// Get all shadow entries
    pub fn entries(&self) -> impl Iterator<Item = &ShadowMemoryEntry> {
        self.entries.values()
    }

    /// Update protection for a shadow region
    pub fn set_protection(&mut self, original_addr: u64, prot: MemoryProt) -> Result<(), String> {
        if let Some(entry) = self.entries.get_mut(&original_addr) {
            entry.protection = prot;
            Ok(())
        } else {
            Err(format!(
                "No shadow entry for original address {:#x}",
                original_addr
            ))
        }
    }

    /// Get current shadow memory usage
    pub fn used_size(&self) -> u64 {
        self.next_shadow_addr - self.shadow_base
    }

    /// Get total available shadow memory
    pub fn available_size(&self) -> u64 {
        self.max_shadow_size - self.used_size()
    }
}

/// PC redirection entry
#[derive(Debug, Clone)]
pub struct RedirectionEntry {
    /// Original code address
    pub original_addr: u64,
    /// Shadow code address to redirect to
    pub shadow_addr: u64,
    /// Whether this redirection is active
    pub active: bool,
}

/// Manages PC redirection for code execution
pub struct PCRedirector {
    redirections: BTreeMap<u64, RedirectionEntry>,
}

impl PCRedirector {
    pub fn new() -> Self {
        Self {
            redirections: BTreeMap::new(),
        }
    }

    /// Register a PC redirection
    pub fn register_redirect(&mut self, original_addr: u64, shadow_addr: u64) {
        self.redirections.insert(
            original_addr,
            RedirectionEntry {
                original_addr,
                shadow_addr,
                active: true,
            },
        );
    }

    /// Get redirect target for an address, if registered
    pub fn get_redirect(&self, addr: u64) -> Option<u64> {
        self.redirections
            .get(&addr)
            .filter(|e| e.active)
            .map(|e| e.shadow_addr)
    }

    /// Disable a redirection
    pub fn disable(&mut self, addr: u64) -> Result<(), String> {
        if let Some(entry) = self.redirections.get_mut(&addr) {
            entry.active = false;
            Ok(())
        } else {
            Err(format!("No redirection registered for {:#x}", addr))
        }
    }

    /// Get all redirections
    pub fn redirections(&self) -> impl Iterator<Item = &RedirectionEntry> {
        self.redirections.values()
    }
}

/// Core rewriter for dynamic code instrumentation
pub struct CoreRewriter {
    shadow_memory: ShadowMemory,
    pc_redirector: PCRedirector,
}

impl CoreRewriter {
    pub fn new() -> Self {
        Self {
            shadow_memory: ShadowMemory::new(),
            pc_redirector: PCRedirector::new(),
        }
    }

    pub fn with_shadow_config(shadow_base: u64, max_size: u64) -> Self {
        Self {
            shadow_memory: ShadowMemory::with_base(shadow_base, max_size),
            pc_redirector: PCRedirector::new(),
        }
    }

    /// Register a code region for rewriting
    pub fn register_region(&mut self, region: CodeRegion) -> Result<u64, String> {
        let shadow_entry = self.shadow_memory.allocate(region.clone())?;
        let shadow_addr = shadow_entry.shadow_addr;

        // Register PC redirection from original to shadow
        self.pc_redirector
            .register_redirect(region.start_addr, shadow_addr);

        Ok(shadow_addr)
    }

    /// Get shadow address for original code address
    pub fn get_shadow_addr(&self, original_addr: u64) -> Option<u64> {
        self.shadow_memory
            .get_shadow(original_addr)
            .map(|e| e.shadow_addr)
    }

    /// Copy rewritten code to shadow memory
    /// In Phase 1, this is a simple copy. Later phases will insert instrumentation.
    pub fn copy_code(&self, original_addr: u64, rewritten_bytes: &[u8]) -> Result<(), String> {
        let shadow_entry = self
            .shadow_memory
            .get_shadow(original_addr)
            .ok_or_else(|| format!("No shadow allocation for {:#x}", original_addr))?;

        // Validate size matches
        if rewritten_bytes.len() != shadow_entry.original_region.original_bytes.len() {
            return Err(format!(
                "Rewritten code size ({}) doesn't match original ({})",
                rewritten_bytes.len(),
                shadow_entry.original_region.original_bytes.len()
            ));
        }

        // In Phase 1, we just track that the code exists
        // In Phase 2-3, this will actually write to memory (requires unsafe/mmap)
        Ok(())
    }

    /// Protect original code region as read-only
    pub fn protect_original(&mut self, original_addr: u64) -> Result<(), String> {
        // In Phase 1, we just track the intent
        // In Phase 2-3, this will use mprotect/VirtualProtect
        Ok(())
    }

    /// Redirect PC to shadow code
    pub fn redirect_pc(&self, original_addr: u64) -> Option<u64> {
        self.pc_redirector.get_redirect(original_addr)
    }

    /// Get shadow memory info
    pub fn shadow_info(&self) -> (u64, u64, u64) {
        (
            self.shadow_memory.shadow_base,
            self.shadow_memory.used_size(),
            self.shadow_memory.available_size(),
        )
    }

    /// Get all registered regions and their shadows
    pub fn regions(&self) -> Vec<(u64, u64, u64)> {
        self.shadow_memory
            .entries()
            .map(|e| (e.original_region.start_addr, e.shadow_addr, e.original_region.size()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_memory_allocation() {
        let mut shadow = ShadowMemory::new();
        let region = CodeRegion::new(0x1000, 0x2000, vec![0; 0x1000]);

        let entry = shadow.allocate(region).unwrap();
        assert_eq!(entry.shadow_addr, ShadowMemory::DEFAULT_SHADOW_BASE);
        assert_eq!(entry.original_region.start_addr, 0x1000);
    }

    #[test]
    fn test_shadow_memory_multiple_regions() {
        let mut shadow = ShadowMemory::new();
        let region1 = CodeRegion::new(0x1000, 0x2000, vec![0; 0x1000]);
        let region2 = CodeRegion::new(0x3000, 0x4000, vec![0; 0x1000]);

        let entry1 = shadow.allocate(region1).unwrap();
        let entry2 = shadow.allocate(region2).unwrap();

        assert_eq!(entry1.shadow_addr, ShadowMemory::DEFAULT_SHADOW_BASE);
        assert_eq!(
            entry2.shadow_addr,
            ShadowMemory::DEFAULT_SHADOW_BASE + 0x1000
        );
    }

    #[test]
    fn test_pc_redirector() {
        let mut redirector = PCRedirector::new();
        redirector.register_redirect(0x1000, 0x100000000);

        assert_eq!(redirector.get_redirect(0x1000), Some(0x100000000));
        assert_eq!(redirector.get_redirect(0x2000), None);
    }

    #[test]
    fn test_core_rewriter() {
        let mut rewriter = CoreRewriter::new();
        let region = CodeRegion::new(0x1000, 0x2000, vec![0; 0x1000]);

        let shadow_addr = rewriter.register_region(region).unwrap();
        assert!(rewriter.get_shadow_addr(0x1000).is_some());
        assert_eq!(rewriter.redirect_pc(0x1000), Some(shadow_addr));
    }

    #[test]
    fn test_protection_levels() {
        let mut shadow = ShadowMemory::new();
        let region = CodeRegion::new(0x1000, 0x2000, vec![0; 0x1000]);

        let entry = shadow.allocate(region).unwrap();
        assert_eq!(entry.protection, MemoryProt::ReadWriteExecute);

        shadow
            .set_protection(0x1000, MemoryProt::Read)
            .unwrap();
        let entry = shadow.get_shadow(0x1000).unwrap();
        assert_eq!(entry.protection, MemoryProt::Read);
    }
}
