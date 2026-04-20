//! Integration test for custom execution callbacks

use aeon_instrument::callbacks::{BlockEntryEvent, ExecutionCallback};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct CountingCallback {
    count: Arc<AtomicUsize>,
}

impl ExecutionCallback for CountingCallback {
    fn on_block_entry(&self, _event: &BlockEntryEvent) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test_callback_execution() {
    let count = Arc::new(AtomicUsize::new(0));
    let callback = Box::new(CountingCallback { count: count.clone() });

    let mut registry = aeon_instrument::callbacks::CallbackRegistry::new();
    registry.register(callback);

    let event = BlockEntryEvent {
        block_addr: 0x1000,
        block_size: 32,
    };
    registry.fire_block_entry(&event);

    assert_eq!(count.load(Ordering::SeqCst), 1);
}
