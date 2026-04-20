//! Custom callback system for user-defined analysis hooks
//!
//! Enables extending the instrumentation engine with custom analysis functions
//! at key execution points: block entry/exit, memory access, register state changes.

/// Event fired when a block is about to execute.
#[derive(Debug, Clone)]
pub struct BlockEntryEvent {
    pub block_addr: u64,
    pub block_size: u32,
}

/// Event fired when a block completes execution.
#[derive(Debug, Clone)]
pub struct BlockExitEvent {
    pub block_addr: u64,
    pub exit_reason: BlockExitReason,
}

/// Reason the block exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockExitReason {
    Fallthrough,
    Branch(u64),
    Call(u64),
    Return,
    Halt,
}

/// Event fired when memory is accessed.
#[derive(Debug, Clone)]
pub struct MemoryAccessEvent {
    pub addr: u64,
    pub size: u8,
    pub value: u64,
    pub is_write: bool,
    pub block_addr: u64,
}

/// Event fired when a register is written.
#[derive(Debug, Clone)]
pub struct RegisterWriteEvent {
    pub reg_index: u8,
    pub value: u64,
    pub block_addr: u64,
}

/// Trait for custom analysis callbacks.
/// Implement this to inject custom analysis at execution points.
pub trait ExecutionCallback: Send + Sync {
    /// Called when a block is about to execute.
    fn on_block_entry(&self, _event: &BlockEntryEvent) {}

    /// Called when a block completes execution.
    fn on_block_exit(&self, _event: &BlockExitEvent) {}

    /// Called when memory is accessed.
    fn on_memory_access(&self, _event: &MemoryAccessEvent) {}

    /// Called when a register is written.
    fn on_register_write(&self, _event: &RegisterWriteEvent) {}
}

/// Registry for execution callbacks.
pub struct CallbackRegistry {
    callbacks: Vec<Box<dyn ExecutionCallback>>,
}

impl CallbackRegistry {
    /// Create a new empty callback registry.
    pub fn new() -> Self {
        Self {
            callbacks: Vec::new(),
        }
    }

    /// Register a callback to be invoked at execution points.
    pub fn register(&mut self, callback: Box<dyn ExecutionCallback>) {
        self.callbacks.push(callback);
    }

    /// Clear all registered callbacks.
    pub fn clear(&mut self) {
        self.callbacks.clear();
    }

    /// Fire block entry event to all registered callbacks.
    pub fn fire_block_entry(&self, event: &BlockEntryEvent) {
        for cb in &self.callbacks {
            cb.on_block_entry(event);
        }
    }

    /// Fire block exit event to all registered callbacks.
    pub fn fire_block_exit(&self, event: &BlockExitEvent) {
        for cb in &self.callbacks {
            cb.on_block_exit(event);
        }
    }

    /// Fire memory access event to all registered callbacks.
    pub fn fire_memory_access(&self, event: &MemoryAccessEvent) {
        for cb in &self.callbacks {
            cb.on_memory_access(event);
        }
    }

    /// Fire register write event to all registered callbacks.
    pub fn fire_register_write(&self, event: &RegisterWriteEvent) {
        for cb in &self.callbacks {
            cb.on_register_write(event);
        }
    }
}

impl Default for CallbackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCallback;

    impl ExecutionCallback for TestCallback {
        fn on_block_entry(&self, event: &BlockEntryEvent) {
            assert!(event.block_addr > 0);
        }
    }

    #[test]
    fn test_callback_registry_creation() {
        let mut registry = CallbackRegistry::new();
        let callback = Box::new(TestCallback);
        registry.register(callback);

        assert_eq!(registry.callbacks.len(), 1);
    }

    #[test]
    fn test_callback_events() {
        let registry = CallbackRegistry::new();

        let event = BlockEntryEvent {
            block_addr: 0x1000,
            block_size: 32,
        };
        registry.fire_block_entry(&event);

        let mem_event = MemoryAccessEvent {
            addr: 0x2000,
            size: 8,
            value: 42,
            is_write: true,
            block_addr: 0x1000,
        };
        registry.fire_memory_access(&mem_event);
    }
}
