# Goal State

Date: 2026-04-09

Primary goal:
- Obtain one real cert token from the live app while the dynamic JIT tracing path stays stable and does not kill the target process.

What is already working:
- Exact-PC dynamic diversion works.
- Native resume trampoline works.
- Native outgoing branch bridge works.
- Per-thread dynamic claims/runtime state exist.
- Raw JIT dump loading for disassembly is implemented in Aeon code.
- Several bad ART helper paths are now skipped or bailed instead of being bridged blindly.
- Root-thread `art_quick_invoke_stub` resume corruption was fixed.

Current live stage:
- The system is past the original exception-handler, LR, and first-helper failures.
- Recent runs reach late native/JIT continuation paths before failing.
- We still do not get a token back; recent `/call` outputs are empty.
- The process now survives further than before, but still dies later in the native/JIT handoff chain.

Latest concrete blocker:
- After the new `art_quick_to_interpreter_bridge` skip-helper bailout, a continuation stays in-corridor and reaches the `0x9cf80ae0 -> 0x9cf80b54` path before the process exits.

Practical summary:
- The debugging state is now late-stage stabilization, not initial bring-up.
- Each fix is moving the live failure site forward.
- The remaining task is to stabilize the post-bail continuation path enough to return one token without dying.
