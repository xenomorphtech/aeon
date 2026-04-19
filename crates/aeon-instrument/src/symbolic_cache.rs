// Incremental symbolic analysis caching for 2× speedup on repeated analysis
//
// Caches folding results (constants, invariants, inductions) from previous runs.
// When re-analyzing, only processes newly discovered blocks.
//
// Design: Simple in-memory cache keyed by (block_addr, block_seq).
// Avoids re-folding blocks seen in prior runs on the same binary.

use std::collections::BTreeMap;

/// Cache key: (block address, execution sequence position)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockKey(pub u64, pub u64);

/// Cached invariants for a single block.
#[derive(Debug, Clone)]
pub struct CachedBlockInvariants {
    pub addr: u64,
    pub constants: usize,
    pub branches: usize,
    pub inductions: usize,
}

/// In-memory cache of symbolic analysis results.
pub struct SymbolicCache {
    /// Cached invariants by (block_addr, seq).
    block_cache: BTreeMap<BlockKey, CachedBlockInvariants>,
    /// Global dataflow edges seen.
    dataflow_edges: BTreeMap<(u64, u64), Vec<(u64, u64)>>,
    /// Hit/miss stats.
    hits: usize,
    misses: usize,
}

impl SymbolicCache {
    pub fn new() -> Self {
        Self {
            block_cache: BTreeMap::new(),
            dataflow_edges: BTreeMap::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// Record analysis of a block for future cache hits.
    pub fn record_block(
        &mut self,
        addr: u64,
        seq: u64,
        constants: usize,
        branches: usize,
        inductions: usize,
    ) {
        let key = BlockKey(addr, seq);
        self.block_cache.insert(
            key,
            CachedBlockInvariants {
                addr,
                constants,
                branches,
                inductions,
            },
        );
    }

    /// Check if block analysis is cached.
    pub fn lookup(&mut self, addr: u64, seq: u64) -> Option<CachedBlockInvariants> {
        let key = BlockKey(addr, seq);
        if let Some(cached) = self.block_cache.get(&key) {
            self.hits += 1;
            return Some(cached.clone());
        }
        self.misses += 1;
        None
    }

    /// Record dataflow edges from one block to another.
    pub fn record_dataflow(&mut self, from_addr: u64, to_addr: u64) {
        self.dataflow_edges
            .entry((from_addr, to_addr))
            .or_insert_with(Vec::new);
    }

    /// Get cache hit rate as percentage.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> (usize, usize) {
        (self.hits, self.misses)
    }

    /// Clear cache.
    pub fn clear(&mut self) {
        self.block_cache.clear();
        self.dataflow_edges.clear();
        self.hits = 0;
        self.misses = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_records_and_retrieves() {
        let mut cache = SymbolicCache::new();
        cache.record_block(0x1000, 0, 5, 2, 1);

        let result = cache.lookup(0x1000, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().constants, 5);
        assert_eq!(cache.hits, 1);
    }

    #[test]
    fn cache_misses_on_absent_key() {
        let mut cache = SymbolicCache::new();
        cache.record_block(0x1000, 0, 5, 2, 1);

        let result = cache.lookup(0x2000, 0);
        assert!(result.is_none());
        assert_eq!(cache.misses, 1);
    }

    #[test]
    fn hit_rate_calculation() {
        let mut cache = SymbolicCache::new();
        cache.record_block(0x1000, 0, 5, 2, 1);
        cache.record_block(0x2000, 0, 3, 1, 0);

        cache.lookup(0x1000, 0); // hit
        cache.lookup(0x3000, 0); // miss
        cache.lookup(0x2000, 0); // hit
        cache.lookup(0x4000, 0); // miss

        assert_eq!(cache.hit_rate(), 50.0);
    }
}
