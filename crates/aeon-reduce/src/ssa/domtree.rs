//! Dominator tree -- computes the immediate-dominator tree using the
//! Cooper-Harvey-Kennedy iterative algorithm.  Used by SSA passes that
//! need dominance queries (e.g. dead-branch elimination, code motion).

use super::construct::SsaFunction;
use super::types::BlockId;
use std::collections::{HashMap, HashSet};

/// Dominator tree for an SSA function.
pub struct DomTree {
    idom: HashMap<BlockId, BlockId>,
    children: HashMap<BlockId, Vec<BlockId>>,
    rpo: Vec<BlockId>,
}

/// Intersect two nodes in the dominator tree, walking up by RPO number
/// until they meet.  This is the core of the CHK algorithm.
fn intersect(
    idom: &HashMap<BlockId, BlockId>,
    rpo_order: &HashMap<BlockId, usize>,
    mut a: BlockId,
    mut b: BlockId,
) -> BlockId {
    while a != b {
        while rpo_order[&a] > rpo_order[&b] {
            a = idom[&a];
        }
        while rpo_order[&b] > rpo_order[&a] {
            b = idom[&b];
        }
    }
    a
}

impl DomTree {
    /// Build dominator tree for the given SsaFunction using the
    /// Cooper-Harvey-Kennedy iterative algorithm.
    pub fn build(func: &SsaFunction) -> Self {
        if func.blocks.is_empty() {
            return DomTree {
                idom: HashMap::new(),
                children: HashMap::new(),
                rpo: Vec::new(),
            };
        }

        // Build adjacency for DFS: block_id -> successors
        let mut succ_map: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for block in &func.blocks {
            succ_map.insert(block.id, block.successors.clone());
        }

        // 1. Compute reverse postorder (RPO) via DFS from entry
        let rpo = Self::compute_rpo(func.entry, &succ_map, func.blocks.len());

        // Map block -> RPO index (lower index = earlier in RPO)
        let rpo_order: HashMap<BlockId, usize> =
            rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

        // Build predecessor map
        let mut pred_map: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for block in &func.blocks {
            pred_map.entry(block.id).or_default();
            for &succ in &block.successors {
                pred_map.entry(succ).or_default().push(block.id);
            }
        }

        // 2. Initialize idom[entry] = entry
        let entry = func.entry;
        let mut idom: HashMap<BlockId, BlockId> = HashMap::new();
        idom.insert(entry, entry);

        // 3. Iterate until fixed point
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == entry {
                    continue;
                }
                let preds = pred_map.get(&b).cloned().unwrap_or_default();

                // Find first processed predecessor
                let mut new_idom = None;
                for &p in &preds {
                    if idom.contains_key(&p) {
                        new_idom = Some(p);
                        break;
                    }
                }

                let mut new_idom = match new_idom {
                    Some(n) => n,
                    None => continue, // unreachable block
                };

                // Intersect with other processed predecessors
                for &p in &preds {
                    if p == new_idom {
                        continue;
                    }
                    if idom.contains_key(&p) {
                        new_idom = intersect(&idom, &rpo_order, new_idom, p);
                    }
                }

                if idom.get(&b) != Some(&new_idom) {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }

        // 4. Build children map from idom
        let mut children: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (&block, &parent) in &idom {
            if block != parent {
                children.entry(parent).or_default().push(block);
            }
        }
        // Sort children for deterministic iteration
        for v in children.values_mut() {
            v.sort();
        }

        DomTree {
            idom,
            children,
            rpo,
        }
    }

    /// Compute reverse postorder via iterative DFS.
    fn compute_rpo(
        entry: BlockId,
        succ_map: &HashMap<BlockId, Vec<BlockId>>,
        _num_blocks: usize,
    ) -> Vec<BlockId> {
        let mut visited: HashSet<BlockId> = HashSet::new();
        let mut postorder: Vec<BlockId> = Vec::new();
        // Iterative DFS using an explicit stack.
        // Stack entries: (block, index_into_successors)
        let mut stack: Vec<(BlockId, usize)> = Vec::new();

        visited.insert(entry);
        stack.push((entry, 0));

        while let Some((block, idx)) = stack.last_mut() {
            let succs = succ_map.get(block).cloned().unwrap_or_default();
            if *idx < succs.len() {
                let next = succs[*idx];
                *idx += 1;
                if visited.insert(next) {
                    stack.push((next, 0));
                }
            } else {
                postorder.push(*block);
                stack.pop();
            }
        }

        postorder.reverse();
        postorder
    }

    /// Does block `a` dominate block `b`? (reflexive: a dominates a)
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        let mut current = b;
        loop {
            if current == a {
                return true;
            }
            match self.idom.get(&current) {
                Some(&parent) if parent != current => current = parent,
                _ => return false,
            }
        }
    }

    /// Reverse postorder iterator.
    pub fn rpo_iter(&self) -> impl Iterator<Item = BlockId> + '_ {
        self.rpo.iter().copied()
    }

    /// Immediate dominator of `block`. Returns `None` for the entry block.
    pub fn idom(&self, block: BlockId) -> Option<BlockId> {
        self.idom.get(&block).copied().filter(|&p| p != block)
    }

    /// Children in the dominator tree.
    pub fn dom_children(&self, block: BlockId) -> &[BlockId] {
        self.children
            .get(&block)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::construct::{SsaBlock, SsaFunction};

    /// Helper: build an SsaFunction from a list of (block_id, successors).
    /// The entry is always block 0.
    fn make_func(blocks: &[(BlockId, Vec<BlockId>)]) -> SsaFunction {
        let mut ssa_blocks = Vec::new();
        // Compute predecessors
        let mut pred_map: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for &(id, _) in blocks {
            pred_map.entry(id).or_default();
        }
        for &(id, ref succs) in blocks {
            for &s in succs {
                pred_map.entry(s).or_default().push(id);
            }
        }
        for &(id, ref succs) in blocks {
            ssa_blocks.push(SsaBlock {
                id,
                addr: id as u64 * 4,
                stmts: Vec::new(),
                successors: succs.clone(),
                predecessors: pred_map.get(&id).cloned().unwrap_or_default(),
            });
        }
        SsaFunction {
            entry: blocks[0].0,
            blocks: ssa_blocks,
        }
    }

    #[test]
    fn dom_straight_line() {
        // A(0) -> B(1) -> C(2)
        let func = make_func(&[(0, vec![1]), (1, vec![2]), (2, vec![])]);
        let dt = DomTree::build(&func);

        assert!(dt.dominates(0, 0));
        assert!(dt.dominates(0, 1));
        assert!(dt.dominates(0, 2));
        assert!(dt.dominates(1, 2));
        assert!(!dt.dominates(2, 1));
        assert!(!dt.dominates(1, 0));

        assert_eq!(dt.idom(0), None);
        assert_eq!(dt.idom(1), Some(0));
        assert_eq!(dt.idom(2), Some(1));
    }

    #[test]
    fn dom_diamond() {
        //     A(0)
        //    / \
        //  B(1) C(2)
        //    \ /
        //    D(3)
        let func = make_func(&[(0, vec![1, 2]), (1, vec![3]), (2, vec![3]), (3, vec![])]);
        let dt = DomTree::build(&func);

        // A dominates everything
        assert!(dt.dominates(0, 0));
        assert!(dt.dominates(0, 1));
        assert!(dt.dominates(0, 2));
        assert!(dt.dominates(0, 3));

        // B does NOT dominate D (C is an alternative path)
        assert!(!dt.dominates(1, 3));
        // C does NOT dominate D
        assert!(!dt.dominates(2, 3));

        // D's idom should be A
        assert_eq!(dt.idom(3), Some(0));
    }

    #[test]
    fn dom_loop() {
        // A(0) -> B(1) -> A(0)  (back edge)
        //         B(1) -> C(2)
        let func = make_func(&[(0, vec![1]), (1, vec![0, 2]), (2, vec![])]);
        let dt = DomTree::build(&func);

        assert!(dt.dominates(0, 1));
        assert!(dt.dominates(0, 2));
        // In a loop, entry still dominates the loop body
        assert!(!dt.dominates(1, 0));
    }

    #[test]
    fn dom_self() {
        // Every block dominates itself
        let func = make_func(&[(0, vec![1, 2]), (1, vec![3]), (2, vec![3]), (3, vec![])]);
        let dt = DomTree::build(&func);

        for block in &func.blocks {
            assert!(
                dt.dominates(block.id, block.id),
                "block {} should dominate itself",
                block.id
            );
        }
    }

    #[test]
    fn dom_rpo_order() {
        let func = make_func(&[(0, vec![1, 2]), (1, vec![3]), (2, vec![3]), (3, vec![])]);
        let dt = DomTree::build(&func);

        let rpo: Vec<BlockId> = dt.rpo_iter().collect();
        // RPO should contain all blocks
        let mut sorted = rpo.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3]);

        // Entry should be first
        assert_eq!(rpo[0], 0);
    }

    #[test]
    fn dom_children() {
        // A(0) -> B(1) -> C(2)
        let func = make_func(&[(0, vec![1]), (1, vec![2]), (2, vec![])]);
        let dt = DomTree::build(&func);

        assert_eq!(dt.dom_children(0), &[1]);
        assert_eq!(dt.dom_children(1), &[2]);
        assert!(dt.dom_children(2).is_empty());
    }
}
