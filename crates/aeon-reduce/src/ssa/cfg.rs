//! Control-flow graph construction -- splits a linear sequence of AeonIL
//! `Stmt` nodes into basic blocks connected by edges derived from branch
//! and conditional-branch statements.  Provides predecessor/successor queries.

use std::collections::{HashMap, HashSet};
use super::types::*;
use aeonil::Stmt;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    pub addr: u64,
    pub stmts: Vec<Stmt>, // original (pre-SSA) statements
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
}

#[derive(Debug, Clone)]
pub struct Cfg {
    pub entry: BlockId,
    pub blocks: Vec<BasicBlock>,
    pub block_map: HashMap<u64, BlockId>, // addr -> block id
}

/// Build a CFG from a flat instruction list.
/// Input: `(address, statement, edge_targets)` triples sorted by address.
///
/// `edge_targets` for each instruction specifies the addresses this instruction
/// can transfer control to.  For a sequential instruction this is just
/// `[next_addr]`; for a branch it lists the taken target (and fallthrough for
/// conditional branches); for `Ret` it is empty.
pub fn build_cfg(instructions: &[(u64, Stmt, Vec<u64>)]) -> Cfg {
    if instructions.is_empty() {
        return Cfg {
            entry: 0,
            blocks: Vec::new(),
            block_map: HashMap::new(),
        };
    }

    // Build an address -> index map for quick lookup
    let addr_to_idx: HashMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, (addr, _, _))| (*addr, i))
        .collect();

    // 1. Identify block leaders
    let mut leaders: HashSet<usize> = HashSet::new();

    // First instruction is always a leader (entry point)
    leaders.insert(0);

    for (i, (_addr, _stmt, edges)) in instructions.iter().enumerate() {
        let next_addr = if i + 1 < instructions.len() {
            Some(instructions[i + 1].0)
        } else {
            None
        };

        // Determine if this instruction is a terminator:
        // - no edges (ret/trap)
        // - multiple edges (conditional branch)
        // - single edge that goes somewhere other than the next instruction (unconditional branch)
        let is_terminator = edges.is_empty()
            || edges.len() > 1
            || (edges.len() == 1 && next_addr.map_or(true, |na| edges[0] != na));

        if is_terminator {
            // All edge targets become leaders (branch targets)
            for target_addr in edges {
                if let Some(&target_idx) = addr_to_idx.get(target_addr) {
                    leaders.insert(target_idx);
                }
            }
            // The instruction after a terminator is also a leader
            if i + 1 < instructions.len() {
                leaders.insert(i + 1);
            }
        }
    }

    // 2. Sort leaders to get block boundaries
    let mut leader_list: Vec<usize> = leaders.into_iter().collect();
    leader_list.sort();

    // Map: leader index -> block id
    let mut leader_to_block: HashMap<usize, BlockId> = HashMap::new();
    for (block_id, &leader_idx) in leader_list.iter().enumerate() {
        leader_to_block.insert(leader_idx, block_id as BlockId);
    }

    // 3. Build basic blocks
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let num_leaders = leader_list.len();

    for (bi, &leader_idx) in leader_list.iter().enumerate() {
        let block_id = bi as BlockId;
        let block_addr = instructions[leader_idx].0;

        // Determine the range of instructions in this block
        let end_idx = if bi + 1 < num_leaders {
            leader_list[bi + 1]
        } else {
            instructions.len()
        };

        let stmts: Vec<Stmt> = instructions[leader_idx..end_idx]
            .iter()
            .map(|(_, stmt, _)| stmt.clone())
            .collect();

        // Successors come from the last instruction's edges
        let last_idx = end_idx - 1;
        let last_edges = &instructions[last_idx].2;
        let mut successors: Vec<BlockId> = Vec::new();
        for target_addr in last_edges {
            if let Some(&target_idx) = addr_to_idx.get(target_addr) {
                if let Some(&target_block) = leader_to_block.get(&target_idx) {
                    if !successors.contains(&target_block) {
                        successors.push(target_block);
                    }
                }
            }
            // Edges to addresses outside the instruction list are ignored
        }

        blocks.push(BasicBlock {
            id: block_id,
            addr: block_addr,
            stmts,
            successors,
            predecessors: Vec::new(), // filled below
        });
    }

    // 4. Build predecessor edges (reverse of successors)
    // Collect all (pred, succ) pairs first to avoid borrow issues
    let edges: Vec<(BlockId, BlockId)> = blocks
        .iter()
        .flat_map(|b| b.successors.iter().map(move |&s| (b.id, s)))
        .collect();
    for (pred, succ) in edges {
        blocks[succ as usize].predecessors.push(pred);
    }

    // Build addr -> block_id map
    let block_map: HashMap<u64, BlockId> = blocks
        .iter()
        .map(|b| (b.addr, b.id))
        .collect();

    Cfg {
        entry: 0,
        blocks,
        block_map,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aeonil::{Expr, Reg, Condition, BranchCond};

    /// Helper: make a simple assign statement (X(dst) = Imm(val))
    fn assign(dst: u8, val: u64) -> Stmt {
        Stmt::Assign {
            dst: Reg::X(dst),
            src: Expr::Imm(val),
        }
    }

    #[test]
    fn cfg_straight_line() {
        // 3 sequential assigns, each flows to the next; last has no successor
        // outside the function.
        let instrs = vec![
            (0x1000u64, assign(0, 1), vec![0x1004]),
            (0x1004, assign(1, 2), vec![0x1008]),
            (0x1008, assign(2, 3), vec![]),
        ];
        let cfg = build_cfg(&instrs);
        // All in one block since edges only go to the next instruction
        // and the last has empty edges (terminal).
        // Actually the last has empty edges, making 0x1008 a terminator,
        // but 0x1004 -> 0x1008 is sequential so no split there.
        // 0x1000 -> 0x1004 is sequential. But 0x1004's edge is 0x1008
        // which equals instructions[2].0, so no leader insertion from edges.
        // However, 0x1008 has empty edges (terminal), so i+1 would be OOB.
        // So the only leader is index 0. One block.
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.blocks[0].stmts.len(), 3);
        assert!(cfg.blocks[0].successors.is_empty());
        assert!(cfg.blocks[0].predecessors.is_empty());
    }

    #[test]
    fn cfg_diamond() {
        // Block A (0x100): cond branch to B (0x108) or C (0x10c)
        // Block B (0x108): branch to D (0x110)
        // Block C (0x10c): branch to D (0x110)
        // Block D (0x110): ret
        let cond_branch = Stmt::CondBranch {
            cond: BranchCond::Flag(Condition::EQ),
            target: Expr::Imm(0x108),
            fallthrough: 0x10c,
        };
        let branch_to_d = Stmt::Branch {
            target: Expr::Imm(0x110),
        };
        let instrs = vec![
            (0x100, assign(0, 0), vec![0x104]),
            (0x104, cond_branch, vec![0x108, 0x10c]),
            (0x108, branch_to_d.clone(), vec![0x110]),
            (0x10c, branch_to_d, vec![0x110]),
            (0x110, Stmt::Ret, vec![]),
        ];
        let cfg = build_cfg(&instrs);
        assert_eq!(cfg.blocks.len(), 4);

        // Block A = block 0: addr=0x100, successors=[B, C]
        let a = &cfg.blocks[0];
        assert_eq!(a.addr, 0x100);
        assert_eq!(a.stmts.len(), 2); // assign + cond_branch
        assert_eq!(a.successors.len(), 2);

        // Block B = block 1: addr=0x108, successors=[D]
        let b = &cfg.blocks[1];
        assert_eq!(b.addr, 0x108);
        assert_eq!(b.successors, vec![cfg.block_map[&0x110]]);
        assert!(b.predecessors.contains(&a.id));

        // Block C = block 2: addr=0x10c, successors=[D]
        let c = &cfg.blocks[2];
        assert_eq!(c.addr, 0x10c);
        assert_eq!(c.successors, vec![cfg.block_map[&0x110]]);
        assert!(c.predecessors.contains(&a.id));

        // Block D = block 3: addr=0x110, predecessors=[B, C]
        let d = &cfg.blocks[3];
        assert_eq!(d.addr, 0x110);
        assert!(d.successors.is_empty());
        assert_eq!(d.predecessors.len(), 2);
        assert!(d.predecessors.contains(&b.id));
        assert!(d.predecessors.contains(&c.id));
    }

    #[test]
    fn cfg_loop() {
        // Block A (0x200): header with assign + cond branch back to A or to B
        // Block B (0x208): ret
        //
        // The cond_branch at 0x204 targets 0x200 (back-edge) and 0x208.
        // Since nothing branches to 0x204 and the assign at 0x200 is
        // sequential, both instructions belong to block A.
        let cond_branch = Stmt::CondBranch {
            cond: BranchCond::Flag(Condition::NE),
            target: Expr::Imm(0x200),
            fallthrough: 0x208,
        };
        let instrs = vec![
            (0x200, assign(0, 1), vec![0x204]),
            (0x204, cond_branch, vec![0x200, 0x208]),
            (0x208, Stmt::Ret, vec![]),
        ];
        let cfg = build_cfg(&instrs);
        // A = {0x200: assign, 0x204: cond_branch}, B = {0x208: ret}
        assert_eq!(cfg.blocks.len(), 2);

        // A = block 0: contains both instructions, self-loop + exit to B
        let a = &cfg.blocks[0];
        assert_eq!(a.addr, 0x200);
        assert_eq!(a.stmts.len(), 2);
        assert!(a.successors.contains(&a.id)); // self-loop
        assert!(a.predecessors.contains(&a.id)); // back-edge

        // B = block 1
        let b = &cfg.blocks[1];
        assert_eq!(b.addr, 0x208);
        assert!(b.successors.is_empty());
        assert!(b.predecessors.contains(&a.id));
    }

    #[test]
    fn cfg_loop_with_separate_header() {
        // Here we ensure a loop where the header and latch are distinct blocks.
        // Block A (0x200): assign, branch to B
        // Block B (0x204): assign, cond branch to C (0x208) or back to B (0x204)
        // Block C (0x208): ret
        //
        // The back-edge targets 0x204, which is ALSO a target from A, so 0x204
        // is a leader and gets its own block.
        let cond_branch = Stmt::CondBranch {
            cond: BranchCond::Flag(Condition::NE),
            target: Expr::Imm(0x204),
            fallthrough: 0x208,
        };
        let instrs = vec![
            (0x200, assign(0, 1), vec![0x204]),        // branch to 0x204
            (0x204, assign(1, 2), vec![0x208]),        // sequential to 0x208 (body)
            (0x208, cond_branch, vec![0x204, 0x20c]),  // back to 0x204 or exit to 0x20c
            (0x20c, Stmt::Ret, vec![]),
        ];
        let cfg = build_cfg(&instrs);
        // Terminators: instr 0 has edge [0x204] where 0x204 != next(0x204)?
        // Actually instr 0 edge=[0x204], next=0x204 => NOT a terminator.
        // instr 2 has edges=[0x204, 0x20c] => IS a terminator (multiple edges).
        // So 0x204 and 0x20c are leaders from instr 2's edges.
        // instr 3 is after terminator => leader at idx 3.
        // Leaders: {0, 1(=0x204), 3(=0x20c)}
        assert_eq!(cfg.blocks.len(), 3);

        let a = &cfg.blocks[0];
        assert_eq!(a.addr, 0x200);
        assert_eq!(a.stmts.len(), 1);
        assert_eq!(a.successors, vec![cfg.block_map[&0x204]]);

        let b = &cfg.blocks[1];
        assert_eq!(b.addr, 0x204);
        assert_eq!(b.stmts.len(), 2); // assign + cond_branch
        assert!(b.successors.contains(&b.id)); // self-loop back to 0x204
        assert!(b.predecessors.contains(&a.id));
        assert!(b.predecessors.contains(&b.id)); // back-edge

        let c = &cfg.blocks[2];
        assert_eq!(c.addr, 0x20c);
        assert!(c.successors.is_empty());
        assert!(c.predecessors.contains(&b.id));
    }

    #[test]
    fn cfg_multi_exit() {
        // Block A (0x300): cond branch to B (0x308) or falls through to next
        // Block A-tail (0x304): ret
        // Block B (0x308): ret
        let cond_branch = Stmt::CondBranch {
            cond: BranchCond::Flag(Condition::EQ),
            target: Expr::Imm(0x308),
            fallthrough: 0x304,
        };
        let instrs = vec![
            (0x300, cond_branch, vec![0x308, 0x304]),
            (0x304, Stmt::Ret, vec![]),
            (0x308, Stmt::Ret, vec![]),
        ];
        let cfg = build_cfg(&instrs);
        assert_eq!(cfg.blocks.len(), 3);

        // Both block 1 (0x304) and block 2 (0x308) are terminal
        let b1 = &cfg.blocks[1];
        assert_eq!(b1.addr, 0x304);
        assert!(b1.successors.is_empty());

        let b2 = &cfg.blocks[2];
        assert_eq!(b2.addr, 0x308);
        assert!(b2.successors.is_empty());

        // Both are successors of block 0
        let a = &cfg.blocks[0];
        assert_eq!(a.successors.len(), 2);
        assert!(a.successors.contains(&b1.id));
        assert!(a.successors.contains(&b2.id));
    }

    #[test]
    fn cfg_empty_input() {
        let cfg = build_cfg(&[]);
        assert!(cfg.blocks.is_empty());
    }
}
