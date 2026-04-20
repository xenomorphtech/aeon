use std::collections::BTreeMap;
use serde_json::{json, Value};
use crate::il_store::{ILLevel, ILStore};
use crate::il::Stmt;

/// Control flow decision from hook execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFlow {
    /// Continue normal execution
    Continue,
    /// Skip current instruction
    Skip,
    /// Redirect PC to address
    Redirect(u64),
    /// Stop execution
    Stop,
}

impl ControlFlow {
    pub fn to_json(&self) -> Value {
        match self {
            ControlFlow::Continue => json!("continue"),
            ControlFlow::Skip => json!("skip"),
            ControlFlow::Redirect(addr) => json!({ "redirect": format!("0x{:x}", addr) }),
            ControlFlow::Stop => json!("stop"),
        }
    }
}

/// Sandboxed register context for hooks (isolated from native state)
#[derive(Debug, Clone)]
pub struct RegisterContext {
    /// Registers x0-x30 (64-bit)
    x_regs: [u64; 31],
    /// Stack pointer (x31)
    sp: u64,
    /// Program counter
    pc: u64,
    /// Condition flags (N, Z, C, V)
    flags: u8,
}

impl RegisterContext {
    pub fn new() -> Self {
        Self {
            x_regs: [0u64; 31],
            sp: 0,
            pc: 0,
            flags: 0,
        }
    }

    /// Get register by name (x0-x30, sp, pc)
    pub fn get(&self, name: &str) -> Option<u64> {
        match name {
            "sp" => Some(self.sp),
            "pc" => Some(self.pc),
            name if name.starts_with("x") => {
                if let Ok(idx) = name[1..].parse::<usize>() {
                    if idx < 31 {
                        Some(self.x_regs[idx])
                    } else if idx == 31 {
                        Some(self.sp)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Set register by name
    pub fn set(&mut self, name: &str, value: u64) -> Result<(), String> {
        match name {
            "sp" => {
                self.sp = value;
                Ok(())
            }
            "pc" => {
                self.pc = value;
                Ok(())
            }
            name if name.starts_with("x") => {
                if let Ok(idx) = name[1..].parse::<usize>() {
                    if idx < 31 {
                        self.x_regs[idx] = value;
                        Ok(())
                    } else if idx == 31 {
                        self.sp = value;
                        Ok(())
                    } else {
                        Err(format!("Invalid register: {}", name))
                    }
                } else {
                    Err(format!("Invalid register: {}", name))
                }
            }
            _ => Err(format!("Unknown register: {}", name)),
        }
    }

    /// Get flag bits
    pub fn get_flags(&self) -> u8 {
        self.flags
    }

    /// Set flag bits
    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    pub fn to_json(&self) -> Value {
        let mut regs = BTreeMap::new();
        for i in 0..31 {
            regs.insert(format!("x{}", i), json!(self.x_regs[i]));
        }
        regs.insert("sp".to_string(), json!(self.sp));
        regs.insert("pc".to_string(), json!(self.pc));

        json!({
            "registers": regs,
            "flags": format!("0x{:02x}", self.flags),
        })
    }
}

/// Sandboxed memory context for hooks
#[derive(Debug, Clone)]
pub struct MemoryContext {
    /// Tracked memory writes (addr -> value)
    writes: BTreeMap<u64, Vec<u8>>,
    /// Tracked memory reads
    reads: Vec<(u64, usize)>,
}

impl MemoryContext {
    pub fn new() -> Self {
        Self {
            writes: BTreeMap::new(),
            reads: Vec::new(),
        }
    }

    /// Record memory write
    pub fn write(&mut self, addr: u64, data: Vec<u8>) {
        self.writes.insert(addr, data);
    }

    /// Record memory read
    pub fn read(&mut self, addr: u64, size: usize) {
        self.reads.push((addr, size));
    }

    /// Get all writes
    pub fn writes(&self) -> &BTreeMap<u64, Vec<u8>> {
        &self.writes
    }

    /// Get all reads
    pub fn reads(&self) -> &[(u64, usize)] {
        &self.reads
    }

    pub fn to_json(&self) -> Value {
        json!({
            "writes": self.writes.iter().map(|(addr, data)| {
                json!({
                    "addr": format!("0x{:x}", addr),
                    "size": data.len(),
                    "data": format!("{:02x?}", data),
                })
            }).collect::<Vec<_>>(),
            "reads": self.reads.iter().map(|(addr, size)| {
                json!({
                    "addr": format!("0x{:x}", addr),
                    "size": size,
                })
            }).collect::<Vec<_>>(),
        })
    }
}

/// Execution context available to hooks
pub struct HookContext {
    /// Current instruction address
    pub insn_addr: u64,
    /// Sandboxed register state
    pub registers: RegisterContext,
    /// Sandboxed memory state
    pub memory: MemoryContext,
    /// IL store for code inspection
    il_store: Option<std::sync::Arc<ILStore>>,
}

impl HookContext {
    pub fn new(insn_addr: u64) -> Self {
        Self {
            insn_addr,
            registers: RegisterContext::new(),
            memory: MemoryContext::new(),
            il_store: None,
        }
    }

    /// Set initial register state
    pub fn set_registers(&mut self, regs: BTreeMap<String, u64>) {
        for (name, value) in regs {
            let _ = self.registers.set(&name, value);
        }
    }

    /// Query IL at current instruction
    pub fn query_il(&self, level: ILLevel) -> Option<Vec<Stmt>> {
        self.il_store.as_ref().and_then(|store| {
            store.get(self.insn_addr, level)
        })
    }

    /// Query IL as JSON (for inspection)
    pub fn query_il_json(&self, level: ILLevel) -> Option<Value> {
        self.il_store.as_ref().and_then(|store| {
            store.get_instruction(self.insn_addr).map(|insn| insn.to_json())
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "addr": format!("0x{:x}", self.insn_addr),
            "registers": self.registers.to_json(),
            "memory": self.memory.to_json(),
        })
    }
}

/// Hook trait for user-defined instrumentation
pub trait InstrumentationHook: Send + Sync {
    /// Called before instruction execution
    fn on_instruction(&mut self, ctx: &mut HookContext) -> ControlFlow {
        ControlFlow::Continue
    }

    /// Called on memory load
    fn on_memory_load(&mut self, ctx: &mut HookContext, addr: u64, size: u8) -> ControlFlow {
        ControlFlow::Continue
    }

    /// Called on memory store
    fn on_memory_store(&mut self, ctx: &mut HookContext, addr: u64, data: &[u8]) -> ControlFlow {
        ControlFlow::Continue
    }

    /// Called on indirect branch/call
    fn on_indirect_branch(&mut self, ctx: &mut HookContext, target: u64) -> ControlFlow {
        ControlFlow::Continue
    }

    /// Called on block entry
    fn on_block_enter(&mut self, ctx: &mut HookContext) -> ControlFlow {
        ControlFlow::Continue
    }

    /// Called on block exit
    fn on_block_exit(&mut self, ctx: &mut HookContext) -> ControlFlow {
        ControlFlow::Continue
    }
}

/// Hook engine for executing instrumentation
pub struct HookEngine {
    hooks: Vec<Box<dyn InstrumentationHook>>,
}

impl HookEngine {
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Register a hook
    pub fn register_hook(&mut self, hook: Box<dyn InstrumentationHook>) {
        self.hooks.push(hook);
    }

    /// Execute all hooks for instruction
    pub fn execute_instruction(&mut self, mut ctx: HookContext) -> (HookContext, ControlFlow) {
        let mut control_flow = ControlFlow::Continue;

        for hook in &mut self.hooks {
            match hook.on_instruction(&mut ctx) {
                ControlFlow::Continue => {}
                flow => {
                    control_flow = flow;
                    break;
                }
            }
        }

        (ctx, control_flow)
    }

    /// Execute all hooks for memory load
    pub fn execute_memory_load(
        &mut self,
        mut ctx: HookContext,
        addr: u64,
        size: u8,
    ) -> (HookContext, ControlFlow) {
        let mut control_flow = ControlFlow::Continue;
        ctx.memory.read(addr, size as usize);

        for hook in &mut self.hooks {
            match hook.on_memory_load(&mut ctx, addr, size) {
                ControlFlow::Continue => {}
                flow => {
                    control_flow = flow;
                    break;
                }
            }
        }

        (ctx, control_flow)
    }

    /// Execute all hooks for memory store
    pub fn execute_memory_store(
        &mut self,
        mut ctx: HookContext,
        addr: u64,
        data: &[u8],
    ) -> (HookContext, ControlFlow) {
        let mut control_flow = ControlFlow::Continue;
        ctx.memory.write(addr, data.to_vec());

        for hook in &mut self.hooks {
            match hook.on_memory_store(&mut ctx, addr, data) {
                ControlFlow::Continue => {}
                flow => {
                    control_flow = flow;
                    break;
                }
            }
        }

        (ctx, control_flow)
    }

    /// Get number of registered hooks
    pub fn hook_count(&self) -> usize {
        self.hooks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHook;

    impl InstrumentationHook for TestHook {
        fn on_instruction(&mut self, ctx: &mut HookContext) -> ControlFlow {
            ctx.registers.set("x0", 42).unwrap();
            ControlFlow::Continue
        }
    }

    #[test]
    fn test_register_context_get_set() {
        let mut ctx = RegisterContext::new();
        ctx.set("x0", 123).unwrap();
        assert_eq!(ctx.get("x0"), Some(123));
    }

    #[test]
    fn test_register_context_sp() {
        let mut ctx = RegisterContext::new();
        ctx.set("sp", 0x1000).unwrap();
        assert_eq!(ctx.get("sp"), Some(0x1000));
    }

    #[test]
    fn test_memory_context_tracking() {
        let mut mem = MemoryContext::new();
        mem.write(0x1000, vec![1, 2, 3, 4]);
        mem.read(0x2000, 8);

        assert_eq!(mem.writes().len(), 1);
        assert_eq!(mem.reads().len(), 1);
    }

    #[test]
    fn test_hook_context_creation() {
        let ctx = HookContext::new(0x1000);
        assert_eq!(ctx.insn_addr, 0x1000);
    }

    #[test]
    fn test_hook_engine_register() {
        let mut engine = HookEngine::new();
        engine.register_hook(Box::new(TestHook));
        assert_eq!(engine.hook_count(), 1);
    }

    #[test]
    fn test_hook_execution_modifies_context() {
        let mut engine = HookEngine::new();
        engine.register_hook(Box::new(TestHook));

        let ctx = HookContext::new(0x1000);
        let (ctx, _) = engine.execute_instruction(ctx);

        assert_eq!(ctx.registers.get("x0"), Some(42));
    }

    #[test]
    fn test_control_flow_enum() {
        assert_eq!(ControlFlow::Continue, ControlFlow::Continue);
        assert_eq!(ControlFlow::Skip, ControlFlow::Skip);
        assert!(ControlFlow::Redirect(0x1000) != ControlFlow::Continue);
    }
}
