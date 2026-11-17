# aeon-jit Test Parallelization Bug Analysis

## Root Cause Identified

The crate uses **static mutable state** for callback tracking in tests:

```rust
static READ_COUNT: AtomicUsize = AtomicUsize::new(0);
static WRITE_COUNT: AtomicUsize = AtomicUsize::new(0);
static BRIDGE_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_READ_ADDR: AtomicU64 = AtomicU64::new(0);
static LAST_WRITE_ADDR: AtomicU64 = AtomicU64::new(0);
static LAST_WRITE_VALUE: AtomicU64 = AtomicU64::new(0);
static LAST_TRANSLATE_TARGET: AtomicU64 = AtomicU64::new(0);
static LAST_BRIDGE_TARGET: AtomicU64 = AtomicU64::new(0);
static LAST_BRIDGE_CTX_X30: AtomicU64 = AtomicU64::new(0);
```

## Problem Pattern

When tests run in parallel:
1. Test A starts and registers `test_branch_bridge_capture_x30` callback
2. Test B starts and registers a different callback
3. Test A expects BRIDGE_COUNT = 1, but gets value from Test B's executions
4. Test A asserts fail: expected 4100 (or 8192), got 0

## Affected Tests (10 failures)

All tests that:
- Set callback functions
- Execute compiled blocks
- Check counter values
- Run in parallel mode

Specifically:
- `flag_cond_*` tests (7 failures) - use callbacks, check flag values
- `executes_checksum_loop_block_with_post_index_load` - uses callbacks
- `unresolved_branch_bridge_sees_flushed_x30` - uses bridge callback
- `compiles_and_executes_a_basic_block` - uses both read/write callbacks

## Solutions

### Option 1: Test Isolation (Recommended)
Add test setup/teardown to reset all static state:

```rust
#[cfg(test)]
mod tests {
    fn reset_test_statics() {
        READ_COUNT.store(0, Ordering::SeqCst);
        WRITE_COUNT.store(0, Ordering::SeqCst);
        BRIDGE_COUNT.store(0, Ordering::SeqCst);
        LAST_READ_ADDR.store(0, Ordering::SeqCst);
        LAST_WRITE_ADDR.store(0, Ordering::SeqCst);
        LAST_WRITE_VALUE.store(0, Ordering::SeqCst);
        LAST_TRANSLATE_TARGET.store(0, Ordering::SeqCst);
        LAST_BRIDGE_TARGET.store(0, Ordering::SeqCst);
        LAST_BRIDGE_CTX_X30.store(0, Ordering::SeqCst);
    }
    
    #[test]
    fn some_test() {
        reset_test_statics();  // Add to every test using callbacks
        // ... test code ...
    }
}
```

**Pros**: Simple, minimal changes, works immediately
**Cons**: Manual boilerplate in every test

### Option 2: Test Fixture Macro
Create a macro to standardize test setup:

```rust
macro_rules! jit_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            reset_test_statics();
            $body
        }
    };
}

jit_test!(my_test, {
    // test code
});
```

**Pros**: DRY, single source of reset logic
**Cons**: Requires macro boilerplate

### Option 3: Use thread-local Storage
Replace statics with thread-local vars (more invasive):

```rust
thread_local! {
    static READ_COUNT: Cell<usize> = Cell::new(0);
    // ... etc ...
}
```

**Pros**: True isolation per thread
**Cons**: Major refactor, test code becomes harder to read

### Option 4: Single-threaded Test Suite (Current Workaround)
Document and enforce `--test-threads=1`:

```bash
# In Cargo.toml:
[profile.test]
# Force serial execution to avoid state collisions
```

**Pros**: No code changes
**Cons**: Defeats purpose of parallel tests, slower CI

---

## Recommendation

**Immediate Fix**: Add `reset_test_statics()` call to every test using callbacks (1-line addition to 10 tests).

**Long-term Fix**: Implement test fixture macro for better maintainability.

**CI Integration**: Update CI to run tests serially until fix is in place:
```bash
cargo test -p aeon-jit -- --test-threads=1
```

---

## Verification

After fix, verify with:
```bash
# Should pass
cargo test -p aeon-jit -- --test-threads=4

# Should pass
cargo test -p aeon-jit -- --test-threads=1
```
