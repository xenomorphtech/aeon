use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use serde_json::{json, Value};

use crate::hook_engine::{HookContext, ControlFlow, InstrumentationHook, HookEngine};
use crate::rewriter::{CodeRegion, CoreRewriter};
use crate::il_store::{ILStore, ILLevel};

/// Simplified hook handler for common patterns
pub struct SimpleHook<F>
where
    F: Fn(&mut HookContext) -> ControlFlow + Send + Sync,
{
    handler: F,
}

impl<F> SimpleHook<F>
where
    F: Fn(&mut HookContext) -> ControlFlow + Send + Sync,
{
    pub fn new(handler: F) -> Box<Self> {
        Box::new(Self { handler })
    }
}

impl<F> InstrumentationHook for SimpleHook<F>
where
    F: Fn(&mut HookContext) -> ControlFlow + Send + Sync,
{
    fn on_instruction(&mut self, ctx: &mut HookContext) -> ControlFlow {
        (self.handler)(ctx)
    }
}

/// Instruction tracer hook - logs all instruction execution
pub struct InstructionTracer {
    trace: Arc<Mutex<Vec<Value>>>,
}

impl InstructionTracer {
    pub fn new() -> Self {
        Self {
            trace: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_trace(&self) -> Vec<Value> {
        self.trace.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.trace.lock().unwrap().clear();
    }
}

impl InstrumentationHook for InstructionTracer {
    fn on_instruction(&mut self, ctx: &mut HookContext) -> ControlFlow {
        let entry = json!({
            "type": "instruction",
            "addr": format!("0x{:x}", ctx.insn_addr),
            "state": ctx.to_json(),
        });
        self.trace.lock().unwrap().push(entry);
        ControlFlow::Continue
    }
}

/// Memory tracer hook - logs memory accesses
pub struct MemoryTracer {
    trace: Arc<Mutex<Vec<Value>>>,
}

impl MemoryTracer {
    pub fn new() -> Self {
        Self {
            trace: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_trace(&self) -> Vec<Value> {
        self.trace.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.trace.lock().unwrap().clear();
    }
}

impl InstrumentationHook for MemoryTracer {
    fn on_memory_load(&mut self, ctx: &mut HookContext, addr: u64, size: u8) -> ControlFlow {
        let entry = json!({
            "type": "memory_load",
            "addr": format!("0x{:x}", addr),
            "size": size,
            "pc": format!("0x{:x}", ctx.insn_addr),
        });
        self.trace.lock().unwrap().push(entry);
        ControlFlow::Continue
    }

    fn on_memory_store(&mut self, ctx: &mut HookContext, addr: u64, data: &[u8]) -> ControlFlow {
        let entry = json!({
            "type": "memory_store",
            "addr": format!("0x{:x}", addr),
            "size": data.len(),
            "pc": format!("0x{:x}", ctx.insn_addr),
        });
        self.trace.lock().unwrap().push(entry);
        ControlFlow::Continue
    }
}

/// Register tracer hook - logs register changes
pub struct RegisterTracer {
    trace: Arc<Mutex<Vec<Value>>>,
    watches: BTreeMap<String, u64>,
}

impl RegisterTracer {
    pub fn new() -> Self {
        Self {
            trace: Arc::new(Mutex::new(Vec::new())),
            watches: BTreeMap::new(),
        }
    }

    /// Watch specific register for changes
    pub fn watch(&mut self, reg: &str) {
        self.watches.insert(reg.to_string(), 0);
    }

    pub fn get_trace(&self) -> Vec<Value> {
        self.trace.lock().unwrap().clone()
    }
}

impl InstrumentationHook for RegisterTracer {
    fn on_instruction(&mut self, ctx: &mut HookContext) -> ControlFlow {
        for (reg_name, last_value) in &mut self.watches {
            if let Some(current_value) = ctx.registers.get(reg_name) {
                if current_value != *last_value {
                    let entry = json!({
                        "type": "register_change",
                        "register": reg_name,
                        "old_value": format!("0x{:x}", last_value),
                        "new_value": format!("0x{:x}", current_value),
                        "pc": format!("0x{:x}", ctx.insn_addr),
                    });
                    self.trace.lock().unwrap().push(entry);
                    *last_value = current_value;
                }
            }
        }
        ControlFlow::Continue
    }
}

/// Branch tracer hook - logs branch/call sites
pub struct BranchTracer {
    trace: Arc<Mutex<Vec<Value>>>,
}

impl BranchTracer {
    pub fn new() -> Self {
        Self {
            trace: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_trace(&self) -> Vec<Value> {
        self.trace.lock().unwrap().clone()
    }
}

impl InstrumentationHook for BranchTracer {
    fn on_indirect_branch(&mut self, ctx: &mut HookContext, target: u64) -> ControlFlow {
        let entry = json!({
            "type": "indirect_branch",
            "from": format!("0x{:x}", ctx.insn_addr),
            "to": format!("0x{:x}", target),
        });
        self.trace.lock().unwrap().push(entry);
        ControlFlow::Continue
    }
}

/// Instrumentation builder for fluent API
pub struct InstrumentationBuilder {
    rewriter: CoreRewriter,
    hook_engine: HookEngine,
    il_store: ILStore,
}

impl InstrumentationBuilder {
    pub fn new() -> Self {
        Self {
            rewriter: CoreRewriter::new(),
            hook_engine: HookEngine::new(),
            il_store: ILStore::new(),
        }
    }

    /// Register code region for instrumentation
    pub fn register_region(mut self, region: CodeRegion) -> Result<Self, String> {
        self.rewriter.register_region(region)?;
        Ok(self)
    }

    /// Add instruction tracer
    pub fn with_instruction_trace(mut self) -> Self {
        self.hook_engine
            .register_hook(Box::new(InstructionTracer::new()));
        self
    }

    /// Add memory tracer
    pub fn with_memory_trace(mut self) -> Self {
        self.hook_engine
            .register_hook(Box::new(MemoryTracer::new()));
        self
    }

    /// Add register tracer
    pub fn with_register_trace(mut self, registers: Vec<String>) -> Self {
        let mut tracer = RegisterTracer::new();
        for reg in registers {
            tracer.watch(&reg);
        }
        self.hook_engine
            .register_hook(Box::new(tracer));
        self
    }

    /// Add branch tracer
    pub fn with_branch_trace(mut self) -> Self {
        self.hook_engine
            .register_hook(Box::new(BranchTracer::new()));
        self
    }

    /// Add custom hook
    pub fn with_hook(mut self, hook: Box<dyn InstrumentationHook>) -> Self {
        self.hook_engine.register_hook(hook);
        self
    }

    /// Build the instrumentation
    pub fn build(self) -> Instrumentation {
        Instrumentation {
            rewriter: self.rewriter,
            hook_engine: self.hook_engine,
            il_store: self.il_store,
        }
    }
}

/// Complete instrumentation system
pub struct Instrumentation {
    rewriter: CoreRewriter,
    hook_engine: HookEngine,
    il_store: ILStore,
}

impl Instrumentation {
    /// Execute instrumentation on code with initial register state
    pub fn execute(
        &mut self,
        code_addr: u64,
        initial_registers: BTreeMap<String, u64>,
    ) -> (Value, ControlFlow) {
        let mut ctx = HookContext::new(code_addr);
        ctx.set_registers(initial_registers);

        let (ctx, control_flow) = self.hook_engine.execute_instruction(ctx);
        (ctx.to_json(), control_flow)
    }

    /// Get rewriter info
    pub fn rewriter_info(&self) -> Value {
        let (shadow_base, used, available) = self.rewriter.shadow_info();
        let regions = self.rewriter.regions();

        json!({
            "shadow_base": format!("0x{:x}", shadow_base),
            "used_size": used,
            "available_size": available,
            "regions": regions.iter().map(|(orig, shadow, size)| {
                json!({
                    "original": format!("0x{:x}", orig),
                    "shadow": format!("0x{:x}", shadow),
                    "size": size,
                })
            }).collect::<Vec<_>>(),
        })
    }

    /// Get hook count
    pub fn hook_count(&self) -> usize {
        self.hook_engine.hook_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_hook_creation() {
        let _hook = SimpleHook::new(|_ctx| ControlFlow::Continue);
    }

    #[test]
    fn test_instruction_tracer() {
        let tracer = InstructionTracer::new();
        assert_eq!(tracer.get_trace().len(), 0);
    }

    #[test]
    fn test_instrumentation_builder() {
        let region = CodeRegion::new(0x1000, 0x2000, vec![0; 0x1000]);
        let instr = InstrumentationBuilder::new()
            .register_region(region)
            .unwrap()
            .with_instruction_trace()
            .with_memory_trace()
            .with_register_trace(vec!["x0".to_string(), "x1".to_string()])
            .with_branch_trace()
            .build();

        assert_eq!(instr.hook_count(), 4);
    }

    #[test]
    fn test_instrumentation_execute() {
        let region = CodeRegion::new(0x1000, 0x2000, vec![0; 0x1000]);
        let mut instr = InstrumentationBuilder::new()
            .register_region(region)
            .unwrap()
            .build();

        let mut regs = BTreeMap::new();
        regs.insert("x0".to_string(), 42);

        let (state, flow) = instr.execute(0x1000, regs);
        assert_eq!(flow, ControlFlow::Continue);
        assert!(state.is_object());
    }
}
