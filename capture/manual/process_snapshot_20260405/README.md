# NMSS Process Memory Snapshot — 2026-04-05

Full process memory snapshot of AION2 (com.netmarble.thered) captured at the exact moment execution enters the JIT cert computation corridor.

## What This Is

A frozen process state captured via Frida page-trap: the JIT cert corridor was flipped to read-only (`r--`), and when execution hit the first instruction, the exception handler dumped the entire process memory before restoring permissions and letting the computation proceed.

This gives you the **initial state** of the cert hash computation — every register, every heap object, every mapped region — at the moment the JIT token generation begins.

## Contents

| File | Description |
|------|-------------|
| `before_manifest.json` | Registers (x0-x30, sp, pc), memory map (4056 regions), metadata at fault point |
| `after_manifest.json` | Same structure, captured after the cert call completed |
| `memdump/` | 3084 per-region binary files, named by hex base address |
| `memdump.tar.gz` | Compressed archive of the above (323MB, 1.8GB uncompressed) |

## Key Parameters

- **Faulting PC**: `0x9b616de0` (inside memfd:jit-cache execute alias)
- **Thread ID**: 4329
- **JIT base**: `0x9b5fe000` (memfd:jit-cache r-xs, ~512KB)
- **Heap arena**: `~0x12c00000` (transient token record area)
- **Architecture**: AArch64
- **Region count**: 4056 mapped regions, 3084 dumped (regions >50MB skipped)

## Register State at Fault

```
pc  = 0x9b616de0    sp  = 0x75acdad540
x0  = 0x762083ca88  x1  = 0x134020a8
x2  = 0x0           x3  = 0xb400007831a17620
```

(Full register set in before_manifest.json)

## How to Use

### Offline Replay (Unicorn/ARM device)
1. Parse `before_manifest.json` for registers and region list
2. For each region: mmap at original VA, load the `.bin` file from `memdump/`
3. Set registers from manifest
4. Jump to `faulting_pc` (0x9b616de0)
5. The cert computation should execute using only the mapped memory state

### IL Analysis (aeon)
1. Lift the JIT code at 0x9b5fe000 to aeon IL
2. Use the snapshot as a concrete memory backing store
3. Execute blocks from faulting_pc — classify memory reads as concrete (in snapshot) vs symbolic (unmapped)
4. Track which output bytes depend on known vs unknown state

## Context

- The cert function is a **custom JIT-implemented transform** in ART's jit-cache (no standard MD5/SHA/AES constants)
- Caller chain: `libUnreal.so -> JIT corridor (token assembly) -> libart.so (string materialization)`
- Full execution path analysis: `capture/manual/CERT_EXECUTION_PATH_2026-04-05.md` (258-block Stalker trace)
- Detection mechanism analysis: `capture/manual/NMSS_DETECTION_PATH_2026-04-05.md`

## Capture Method

Captured using `frida/jit_trace_gate.js` page-trap with `doFullProcessSnapshot()` — reads `/proc/PID/maps`, dumps all readable regions via `Memory.readByteArray()`, captures register context from exception handler. Snapshot taken via xerda-server (custom Frida) on Android emulator.
