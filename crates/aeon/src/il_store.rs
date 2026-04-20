use std::collections::BTreeMap;
use serde_json::{json, Value};
use crate::il::{Expr, Stmt};
use crate::function_ir::DecodedInstruction;

/// Abstraction level for IL representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ILLevel {
    /// Low-Level IL (raw instruction lifted)
    LLIL,
    /// Mid-Level IL (simplified, optimized)
    MLIL,
    /// High-Level IL (further abstraction)
    HLIL,
}

/// IL representation at a specific abstraction level
#[derive(Debug, Clone)]
pub struct ILRepresentation {
    pub level: ILLevel,
    pub stmts: Vec<Stmt>,
    pub raw_asm: String,
}

/// Per-instruction IL storage
#[derive(Debug, Clone)]
pub struct InstructionIL {
    pub addr: u64,
    pub raw_asm: String,
    pub llil: Vec<Stmt>,
    pub mlil: Option<Vec<Stmt>>,
    pub hlil: Option<Vec<Stmt>>,
}

impl InstructionIL {
    pub fn new(addr: u64, raw_asm: String, llil: Vec<Stmt>) -> Self {
        Self {
            addr,
            raw_asm,
            llil,
            mlil: None,
            hlil: None,
        }
    }

    pub fn get(&self, level: ILLevel) -> Option<&[Stmt]> {
        match level {
            ILLevel::LLIL => Some(&self.llil),
            ILLevel::MLIL => self.mlil.as_ref().map(|v| v.as_slice()),
            ILLevel::HLIL => self.hlil.as_ref().map(|v| v.as_slice()),
        }
    }

    pub fn set(&mut self, level: ILLevel, stmts: Vec<Stmt>) {
        match level {
            ILLevel::LLIL => self.llil = stmts,
            ILLevel::MLIL => self.mlil = Some(stmts),
            ILLevel::HLIL => self.hlil = Some(stmts),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "addr": format!("0x{:x}", self.addr),
            "asm": self.raw_asm,
            "llil": self.llil.iter().map(|s| format!("{:?}", s)).collect::<Vec<_>>(),
            "mlil": self.mlil.as_ref().map(|stmts| {
                stmts.iter().map(|s| format!("{:?}", s)).collect::<Vec<_>>()
            }),
            "hlil": self.hlil.as_ref().map(|stmts| {
                stmts.iter().map(|s| format!("{:?}", s)).collect::<Vec<_>>()
            }),
        })
    }
}

/// Storage for IL representations of code regions
pub struct ILStore {
    /// Map from instruction address to IL representation
    instructions: BTreeMap<u64, InstructionIL>,
    /// Whether MLIL/HLIL optimization has been performed
    optimized: bool,
}

impl ILStore {
    pub fn new() -> Self {
        Self {
            instructions: BTreeMap::new(),
            optimized: false,
        }
    }

    /// Store IL for an instruction
    pub fn store_instruction(&mut self, insn: InstructionIL) {
        self.instructions.insert(insn.addr, insn);
    }

    /// Store IL from decoded instructions
    pub fn store_from_decoded(&mut self, instructions: Vec<DecodedInstruction>) {
        for insn in instructions {
            let mut il = InstructionIL::new(insn.addr, insn.asm, vec![insn.stmt]);
            self.instructions.insert(insn.addr, il);
        }
    }

    /// Get IL representation at specific level
    pub fn get(&self, addr: u64, level: ILLevel) -> Option<Vec<Stmt>> {
        self.instructions.get(&addr).and_then(|il| {
            il.get(level).map(|stmts| stmts.to_vec())
        })
    }

    /// Query IL for an address range
    pub fn query_range(&self, start: u64, end: u64, level: ILLevel) -> Vec<(u64, Vec<Stmt>)> {
        self.instructions
            .range(start..end)
            .filter_map(|(addr, il)| {
                il.get(level).map(|stmts| (*addr, stmts.to_vec()))
            })
            .collect()
    }

    /// Set IL at specific level for optimization
    pub fn set_level(&mut self, addr: u64, level: ILLevel, stmts: Vec<Stmt>) -> Result<(), String> {
        self.instructions
            .get_mut(&addr)
            .ok_or_else(|| format!("No instruction at {:#x}", addr))?
            .set(level, stmts);
        Ok(())
    }

    /// Mark as optimized
    pub fn mark_optimized(&mut self) {
        self.optimized = true;
    }

    /// Get all stored instructions
    pub fn all_instructions(&self) -> impl Iterator<Item = (&u64, &InstructionIL)> {
        self.instructions.iter()
    }

    /// Get instruction by address
    pub fn get_instruction(&self, addr: u64) -> Option<&InstructionIL> {
        self.instructions.get(&addr)
    }

    /// Export as JSON for inspection
    pub fn to_json(&self, level: ILLevel) -> Value {
        let instructions: Vec<_> = self.instructions
            .iter()
            .filter_map(|(_, insn)| {
                insn.get(level).map(|_| insn.to_json())
            })
            .collect();

        json!({
            "level": format!("{:?}", level),
            "optimized": self.optimized,
            "instruction_count": instructions.len(),
            "instructions": instructions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_il_storage() {
        let mut insn = InstructionIL::new(0x1000, "mov x0, x1".to_string(), vec![]);
        assert_eq!(insn.addr, 0x1000);
        assert!(insn.get(ILLevel::LLIL).is_some());
    }

    #[test]
    fn test_il_store_basic() {
        let mut store = ILStore::new();
        let insn = InstructionIL::new(0x1000, "mov x0, x1".to_string(), vec![Stmt::Nop]);
        store.store_instruction(insn);

        assert!(store.get(0x1000, ILLevel::LLIL).is_some());
    }

    #[test]
    fn test_il_store_multi_level() {
        let mut store = ILStore::new();
        let mut insn = InstructionIL::new(0x1000, "add x0, x0, #1".to_string(), vec![Stmt::Nop]);
        insn.set(ILLevel::MLIL, vec![Stmt::Nop]);
        store.store_instruction(insn);

        assert!(store.get(0x1000, ILLevel::LLIL).is_some());
        assert!(store.get(0x1000, ILLevel::MLIL).is_some());
    }

    #[test]
    fn test_il_store_range_query() {
        let mut store = ILStore::new();
        for i in 0..5 {
            let insn = InstructionIL::new(0x1000 + i * 4, format!("insn_{}", i), vec![Stmt::Nop]);
            store.store_instruction(insn);
        }

        let results = store.query_range(0x1000, 0x1010, ILLevel::LLIL);
        assert!(results.len() >= 3);
    }

    #[test]
    fn test_il_store_optimization_marking() {
        let mut store = ILStore::new();
        assert!(!store.optimized);
        store.mark_optimized();
        assert!(store.optimized);
    }
}
