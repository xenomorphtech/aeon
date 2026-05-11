# Frida capture spec — full state for `live_cert_eval` offline replay

**Owner:** cert-harness drafts; **executor:** trace-claude3 (owns device 5558).
**Goal:** produce a snapshot that `scripts/snapshot_to_page_cache.py manifest`
can ingest end-to-end, so `live_cert_eval --offline-cache` can drive the cert
function to completion on the host.

The synthetic single-region boot test already works (`blocks=1, stop=symbolic_branch`);
the missing inputs are the **non-corridor regions**, the **real register file at hash
entry**, and the **TPIDR_EL0** (TLS) pointer.

---

## EASIEST PATH (cert-session-key-injection, conf 0.8)

The cert call site is **`corridor + 0x26f364`** with `bl 0x134f30`. Just before
that BL, the callee-saved register **`x21` points at a freshly-allocated buffer
that is the COMPLETE cert input**. The buffer is filled by the chain
`0x26f200 (parent) → 0xbe00c → 0xbcaf0 (std::map<int, _SymbolInfo>::__insert_node_at)
→ 0xbc270 (data copy)`. At auth-time the std::map is populated; at cert-time the
map is looked up and the result is copied into `x21`'s allocation.

**Downstream pipeline is deterministic given the buffer at `x21`.** No need to
model the std::map, the auth handler, or to track every XOR aggregation source
across `caller_input`. The harness just needs:

1. The bytes at `*x21` at the moment of the `bl 0x134f30` (or equivalently at
   `0x134f30` entry — `x21` is callee-saved, so it survives the call).
2. The corridor code itself (already covered by P0 region #1).
3. libnmsssa.so r-xp + r--p + rw-p (already P0 region #2–4) for the SHA-256
   constants / CRC32 table / any other static lookup the stages read.

What this **supersedes**:
- Section 1 region 7's "dump caller_input[0x4070..0x4088] etc." is no longer
  load-bearing — those XOR sources are reachable from offsets *within* the
  buffer at `x21`, which we dump in full.
- Section 1 region 8's "manager singleton + post-auth check" is still useful
  as a snapshot-validity sanity check (auth_key non-zero → snapshot is
  post-auth, see `manager_singleton_resolution.md`) but the manager itself
  doesn't need to be present at runtime if `x21`'s buffer already carries
  the session/auth state.
- The "scramble constant" search (7a) is moot if it's also already baked
  into the `x21` buffer at cert-time.

**Hook P concretely.** At `Interceptor.attach(corridor.base.add(0x134f30), …)`:
```js
onEnter(args) {
    const x21 = this.context.x21;
    // length is whatever was alloc'd at the parent (0x26f200 region) — start
    // with 64 KB to cover any plausible allocation; trim on host based on
    // observed end-of-data.
    out.x21_addr = x21.toString();
    out.x21_buffer_64KB_hex = Memory.readByteArray(x21, 65536).toHex?.();
    // Continue with full reg/region dump as before.
}
```

The buffer at `x21` is what the converter should treat as the **primary cert
input region** in the manifest: tag it `"file_path": "[anon:x21_cert_input]"`
so the harness's namespace logic classifies it as a volatile region (per
`is_stable_cache_region`). All offset reads the cascade does — including
`+0x70..+0x88`, `+0x4070..+0x4088`, etc. — resolve inside this allocation.

The rest of this document still applies for register state, system regs,
verification, and trigger timing; the change here narrows the *primary data*
to one allocation.

---

## UPDATE 2026-05-11 — cascade structure (supersedes earlier single-hash assumption)

Per facts `cert-real-hash-algorithm`, `cert-two-hash-cascade`,
`cert-stage5-hash2-analysis`, and the CRC32 correction (arm64-runner cycles
152, 159, plus the 0x4e3118 → table_nmcrc reclassification):

**Pipeline table (cert-pipeline-table REVISED — SHA-256 reclassification):**

| Stage | Function       | Address (corridor-rel) | Role                                                  |
|-------|----------------|------------------------|-------------------------------------------------------|
| 0     | PREPROC_A      | 0x1475a8               | **SHA-256** of buffer; output formatted as ASCII hex  |
| 1     | CRC32-1        | 0x14b87c               | reflected CRC32, **custom seed 0x7da213f4**           |
| 2     | xxHash64       | 0x14ff50               | byte-verified PRIMEs (PRIME1 0x9E3779B185EBCA87 etc.) |
| 3     | PREPROC_A      | 0x1475a8 (re-entrant)  | **SHA-256** again over post-xxHash buffer state       |
| 4     | CRC32-2        | 0x14b87c (re-entrant)  | second CRC32 pass                                     |
| 5     | HASH2          | 0x135658               | **SHA-256** (was "custom"; reclassified)              |
| 6     | HASH2          | 0x135658 (re-entrant)  | **SHA-256** — **final cert shaped here**              |

**The whole cascade is well-known primitives.** SHA-256 ×5 interleaved with
CRC32 ×2 and xxHash64 ×1. The earlier "custom obfuscated HASH2" and
"hex-encoding PREPROC_A" readings were partial: PREPROC_A's externally-visible
form is hex chars but the underlying hash is SHA-256; HASH2's lack of
identifiable constants in byte scans was because OLLVM reconstructs the SHA-256
K[i] and H[0..7] tables via `movz`/`movk` immediate pairs rather than loading
them from rodata. The 24-byte cert at `x0+0x70` is therefore *the first 24
bytes of a SHA-256 digest*, hex-encoded externally to 48 characters.

**Dataflow correction — cert input is NOT the challenge** (per
cert-pipeline-dataflow). The 24 bytes that stages 5/6 SHA-256-hash are NOT
the raw challenge bytes; they are an **XOR aggregation of session/device
state pulled from multiple offsets of the caller's input**:

```
buffer[0x70..0x88]
  = caller_input[0x70..0x88]
    XOR caller_input[0x4070..0x4088]
    XOR ...                          // additional 0x4000-stride slices
    XOR 0x1D                         // single-byte constant
    XOR scramble                     // per-call scramble value
```

The challenge contributes only via xxHash64 (stage 2): its 64-bit hash output
is written somewhere in the buffer that *later* gets folded into the XOR
aggregation, but only as one term out of several. This explains why different
challenges produce different certs (xxHash output term differs) while
different session/device states *also* produce different certs (other XOR
terms differ).

**For the harness:** the 16449-byte buffer at `x22` alone is **not** sufficient
input. The capture must also include any caller-side memory the XOR aggregation
reads from — concretely, the bytes at `caller_input + 0x4070..(+0x4088)` and
any further 0x4000-stride slices. If `caller_input` and the 16449-byte buffer
are aliased (i.e., `caller_input == x22`), then offset 0x4070 lies *outside*
the 16449-byte buffer's nominal 16449 = 0x4041 length — meaning the actual
allocation is larger than the documented length, and the dump must extend
through at least `x22 + 0x8000` to be safe. The spec's region rule for the
16449 buffer (Section 1, region 7) is updated below to reflect this.

**Per-stage execution cycle** the orchestrator runs before each stage call:
```c
memcpy(buffer + 0x4000, aux, 65);  // copy aux into buffer at 0x4000
memset(aux, 0, 65);                 // zero aux
blr stage;                          // call stage function
// — stage may write output back into aux or buffer; orchestrator copies onward
```

Implications:
- The 65-byte `aux` is **reused** across stages; outputs are **overwritten,
  not concatenated**. So capturing the aux buffer at any one boundary only
  shows the most-recent stage's intermediate state. To validate stage-by-
  stage, hook each stage's entry/exit individually (one trace; multiple
  intermediate dumps).
- `buffer + 0x4000` is the staging slot. The orchestrator's `w20`
  (chunk-divisor) and `w3` (stage sequence) almost certainly drive these
  offsets and the per-stage parameters.

**Symbolic-execution risk and the shim path:**
PREPROC_A is 4474 insns × 25% negated-logic × 2 invocations; HASH2 is 22862
insns × 21% negated-logic × 2 invocations. Naive emulation budget is in the
hundreds of thousands of blocks. The right move is to **shim both functions
with native SHA-256**:

1. (Cheap, slow) raise `--max-blocks` to 65536+ and let the symbolic engine
   grind. Realistic for offline batch jobs, not for interactive iteration.
2. (Recommended) add two corridor-side function shims to `live_cert_eval.rs`,
   mirroring the existing `LIBC_*_OFFSET` libc shims:
   - `CORRIDOR_PREPROC_A_OFFSET = 0x1475a8` — read the call's `(src, len, dst)`
     args from registers, compute SHA-256 over `src[0..len]` using the `sha2`
     crate, write 32 raw bytes to `dst` (or 64 ASCII hex chars, depending on
     observed callee convention), set return registers, jump to `lr`.
   - `CORRIDOR_HASH2_OFFSET = 0x135658` — same shape; SHA-256 of the input
     buffer with whatever specific layout the disassembly fixes (e.g., reads
     24 bytes at `x0+0x70`, writes 32 bytes at `x0+0x20` per cert-output-
     write-address).
   Together these skip ~55000 obfuscated instructions across the cascade and
   cut wall-clock from minutes to seconds.
3. Confirm exact arg conventions before implementing the shim. Static analysis
   has not been definitive on which register is src/dst/len for PREPROC_A
   (cert-stage0-preprocess-a recorded `x0, w1, w2, x3, w4` but didn't isolate
   the hex direction). A 10-line Frida probe at PREPROC_A entry — log all
   args + dump bytes before/after across one full call — would lock the
   signature.

**CRC32 stage detail:** `0x14b87c` uses reflected CRC32 (polynomial
`0xEDB88320`) with **custom seed `0x7da213f4`** (cycle-162). The table is
unchanged:

**CRC32 stage detail:** `0x14b87c` uses reflected CRC32 (polynomial
`0xEDB88320`) with **custom seed `0x7da213f4`** (cycle-162). The table is
unchanged:
- `libnmsssa.so + 0x4e3118` is a **GOT slot** (in the dynamic linker's
  R_AARCH64_GLOB_DAT / R_AARCH64_RELATIVE relocation domain), populated at
  load time to point at the actual table.
- `libnmsssa.so + 0x4e4010` is **`table_nmcrc`** — 1024 bytes
  (256 × `u32`) of the standard reflected CRC32 lookup table
  (polynomial `0xEDB88320`). Used by PREPROC_B only.
- Both addresses live in libnmsssa.so's R/RO mappings; the GOT slot is in
  `.data.rel.ro` (RW pre-RELRO, R after) and the table is in `.rodata`.
- The existing P0 rule "libnmsssa.so r--p AND rw-p fully dumped" already
  covers these. Verification (Section 6) confirms the GOT slot is resolved
  and the table bytes match the reference.

- `0x150ca0` — **small validator entry** (outer wrapper; the natural-fire hook target)
- `0x14ff50` — **xxHash64 main**. PRIMEs byte-verified (PRIME1=`0x9E3779B185EBCA87`,
  PRIME2=`0xC2B2AE3D27D4EB4F`, PRIME4=`0x85EBCA77C2B2AE63`).
- `0x1503ec` — **hybrid finalize + format**: front half is xxHash finalize/avalanche,
  back half is printf `%x`/`%X` expansion. The previously-reported "printf
  misidentification" (cycle 137 `cert-chain-misidentified-printf`) was *partial*
  — it was right that there's printf-like code, wrong that it's *only* printf.
- `0x135658` — **secondary hash** (91 KB / 22862 insns / 77 loops / 10 MULs /
  239 RORs). OLLVM-obfuscated. Constants don't match standard MD5 `K[i]` — this
  is a custom transform. **The final cert is shaped by `0x135658`, not by xxHash64
  alone.** This is why raw xxh64 over the 16449-byte buffer does not reproduce
  `0xbba6dcddaedd96d7` (the recorded `xxh64_hash`) under any seed — and even if
  it did, the *cert* is the post-0x135658 result, not the xxHash output.
- `0x100068` — LZ4 + manual ELF loader (not a hash; ignore).

**Buffer convention through the cascade** (per cert-two-hash-cascade and
cert-stage5-hash2-analysis):
- `buffer[0x20..0x40]` — 32 bytes — carries the xxHash output INTO `0x135658`
  and the post-secondary output OUT of `0x135658`. This is the `cert_struct`
  output area referenced by `cert-output-write-address` (write at `+0x1505dc`).
- At HASH2 entry, **x0 + 0x70..(+0x88)** is the 24-byte region HASH2 reads —
  matches the 24-byte / 48-hex-char cert hypothesis. (User-reported range
  was `0x70..0x84`; if 24 bytes is the load-bearing fact, end-exclusive must
  be 0x88. Confirm at runtime by capturing x0 and dumping a 0x100-byte
  window from it.) **`x0` at HASH2 entry is potentially a different pointer
  than `cert_struct`** — the spec captures `x0` at hook N entry so we can
  reconcile both views on the host.
- HASH2 has **no standard hash constants** — they are runtime-reconstructed
  via heavy OLLVM obfuscation (≈21% negated-logic ops). All required constant
  tables sit in libnmsssa.so's `.data.rel.ro` / BSS after the loader's
  constructors have run, so the snapshot must include those mappings (already
  covered by P0 region #4). The emu's symbolic engine will get stressed by
  the obfuscation pattern (see verification section).

**Implications for this spec:**
1. The corridor dump must cover **both** `+0x135658` and `+0x14ff50`. Both are
   within the 320 KB corridor (0x135658 < 0x14ff50 < 0x150000), so the existing
   P0 corridor dump (full 0x50000) already satisfies this — no region change.
2. Add two new hooks to the trigger plan: **N at `+0x135658` entry** (capture
   `buffer[0x20..0x40]` = xxHash output going in) and **O at `+0x135658` exit**
   (capture `buffer[0x20..0x40]` = secondary output, which is the cert).
3. Post-capture verification: the harness must reach `+0x135658` and run it to
   completion before any cert comparison. Stopping at `+0x1505dc` (xxhash
   output write) is **not sufficient** — that's the input to HASH2, not the cert.
4. Hook priority for natural-fire detection (per cert-real-hash-algorithm):
   `0x150ca0 > 0x14ff50 > 0x1503ec > 0x100068`. Hook `0x150ca0` first to confirm
   the cert flow fires at all, then layer the snapshot dump on `0x14ff50` and
   the cert-output capture on `0x135658` exit.

Sections below reference both stages where relevant.

---

## 0. Outputs (must match the converter's `manifest` mode contract)

Write under `/data/local/tmp/cert_harness_snapshot_<timestamp>/`, then `adb pull`:

```
manifest.json                 # registers, sysregs, region list (schema below)
maps.txt                      # raw /proc/<pid>/maps copy
memdump/<base_hex>.bin        # one file per dumped region, named by region.base
proc_fdinfo/                  # optional; not consumed by converter, useful for forensics
```

`manifest.json` schema (compatible with `process_snapshot_20260405/before_manifest.json`
and `trampoline_proc_memdump_5558/manifest.json` shapes — converter accepts either):

```jsonc
{
  "label": "cert_hash_entry_<challenge>",
  "timestamp": "<ISO-8601 UTC>",
  "pid": 12345,
  "thread_id": 12346,
  "arch": "arm64",
  "pointer_size": 8,
  "trigger": {                      // for human auditability; ignored by converter
    "hook_addr": "0x...",           // absolute PC of 0x150ca0 entry hook
    "hook_offset": "0x150ca0",      // corridor-relative
    "challenge": "AABBCCDDEEFF0011",
    "natural_fire": true
  },
  "registers": {                    // hex strings, "0x..."
    "pc":  "...", "sp": "...",
    "x0": "...", "x1": "...", ..., "x30": "...",
    "nzcv": "0",                    // top-level inside `registers` per harness load_state_json
    "simd": {                       // optional but recommended; LE-hex u128 per qN
      "q0":  "00..", ..., "q31": ".."
    }
  },
  "system_registers": {             // critical; harness uses TPIDR_EL0 for TLS reads
    "tpidr_el0": "0x..."
  },
  "regions": [                      // see Section 1 for the dump set
    {
      "base":      "0x9d164000",
      "end":       "0x9d1b4000",
      "size":      327680,
      "perms":     "r-xp",
      "offset":    "0x0",
      "file_path": "/memfd:jit-cache (deleted)",
      "dumped":    true,
      "dump_file": "9d164000.bin",
      "dump_size": 327680,
      "skip_reason": null
    },
    ...
  ]
}
```

---

## 1. Memory regions to dump (in priority order)

For each region, dump the *entire* region; the converter slices into 4 KB pages.
Anything >50 MB can be skipped (`skip_reason: "too large"`) unless explicitly listed.

### P0 — Required for code execution

1. **JIT corridor (full 0x50000 = 320 KB)** — `nmsscr.dec` r-xp region containing
   the cert function. The current `cert_trace/jit_live_corridor_9d164000.bin` is
   only 64 KB and **does not include the xxhash entry at `+0x14ff50` nor the
   output writer at `+0x1505dc`**. Required range: `corridor_base..corridor_base+0x50000`.
   Find by: largest r-xp range whose first segment file-offset=0 is bigger than
   `XXH64_STAGE_OFFSET` (`+0x14ff50`).

2. **`libnmsssa.so` r-xp** (text) — entire range. The cert function trampolines
   out of the corridor into `libnmsssa.so` for the inner SHA256 cascade
   (`actual_compute` at `corridor+0x16d36c` → libnmsssa internals) and well512
   primitives. Without text, the lifter halts on the first BL out of corridor.

3. **`libnmsssa.so` r--p** (rodata) — needed for D04/D09 bootstrap constants if
   they are baked in, plus the well512 default state and challenge_hash32 lookup
   table.

4. **`libnmsssa.so` rw-p** (BSS / .data) — the **manager singleton** lives here.
   Required offsets known so far:
   - `libnmsssa_base + 0x3c0600`  → WELL512 state (128 bytes)
   - `libnmsssa_base + 0x3c6d78`  → WELL512 index (u32)
   - `libnmsssa_base + 0x3c6b50`  → fptr cell for `getCertValue`

5. **`libc.so` r-xp** — for `memcpy`/`memset`/`strchr`/`snprintf*` shims that the
   harness intercepts (offsets listed at the top of `live_cert_eval.rs`). The
   converter doesn't need the full text — only pages actually touched — but
   simplest: dump the whole `r-xp` range.

6. **linker/`ld-android.so` r-xp** — only if the dispatch chain crosses through
   PLT veneers we haven't enumerated yet. Lower priority; cheap to include.

### P1 — Required for input data

7. **The 16449-byte xxhash input buffer at `x22`** (allocated via
   `mov w0,#0x4041` at `corridor+0x134fec`) — but **capture more than 16449
   bytes**. Per cert-pipeline-dataflow, the cascade reads
   `caller_input[0x4070..0x4088]`, which is past the nominal 16449-byte
   length (0x4041). Treat the documented 16449 length as a lower bound, not
   the allocation size. **Dump the entire enclosing anonymous heap region**
   (typically a 64 KB scudo primary slab — already cheap). The Hook P probe
   must capture caller-input bytes at the following offsets at minimum:
   - `[0x70..0x88]` — first XOR aggregation source
   - `[0x4070..0x4088]` — second XOR aggregation source (past nominal length)
   - `[0x2010..0x2018]` — challenge embedding (per cert-xxhash-input-source)
   - any further `0x4000`-stride slices, if the disassembly of the XOR-
     aggregation loop reveals more terms. Trace-claude3 should dump the
     entire region containing `x22` (not a fixed-size slice) so all possible
     XOR sources are present in the snapshot.

   Streaming context layout (`x0` to xxHash, 0x70 bytes): state[4]@+0x00,
   output[4]@+0x20, streaming-buf@+0x40, buf_len@+0x60, total_len@+0x68.

7a. **Scramble constant** — the per-call value XORed into the aggregation.
    Currently unidentified; could be a register value preserved across the
    cascade, a global in libnmsssa.so's BSS, or a derived value from
    session_key. Hook P should additionally dump:
    - All callee-saved registers verbatim (already captured via reg dump).
    - If the orchestrator at 0x134f30 sets up the scramble in a known
      register (e.g., x19 before the first stage call), record its value
      separately in `expected_cert.json.orchestrator_entry.scramble_candidates`
      alongside x19..x28. The host-side verifier can then test each as the
      XOR constant.

8. **Manager singleton + SSO heap** — resolved via fixed offset in
   libnmsssa.so. Per cert-session-state-origin:
   ```
   singleton_ptr = *(u64*) (libnmsssa_base + 0x122fb8)
   session_key   = (char*) (singleton_ptr + 0x210)    // SSO std::string
   auth_key      = (??*)   (singleton_ptr + 0x388)    // ZERO until post-auth
   challenge_sso = (char*) (singleton_ptr + 0xCE8)    // SSO std::string
   ```
   The `+0x122fb8` slot is in libnmsssa.so's `.data.rel.ro` (populated at
   load time by the dynamic linker) and is captured automatically as part of
   region #4 (libnmsssa rw-p). The singleton itself lives in a heap region
   — dump the enclosing scudo slab.

   **CRITICAL: the snapshot must be taken POST-AUTH (T+8.9 s after process
   start, after the server-handshake HTTP 200 response).** Pre-auth,
   `singleton+0x388` is zero and `singleton+0x210` may be empty or contain
   stale bootstrap data — the cert function won't produce a valid cert.
   This is why every prior pre-auth sweep in cert-emu failed.

   Sanity check the snapshot post-capture:
   ```python
   singleton = struct.unpack('<Q', read_at(libnmss + 0x122fb8, 8))[0]
   auth_key  = read_at(singleton + 0x388, 32)
   assert any(b != 0 for b in auth_key), "snapshot is pre-auth (auth_key=0)"
   ```
   If `auth_key` is all zero, the capture timing missed the auth window —
   discard and retry after the next observed HTTP 200 to the auth endpoint.

9. **Stack region** — dump from `sp - 0x8000` to `sp + 0x8000` rounded to page
   boundaries (or the entire `[stack:<tid>]` mapping if small). Holds saved
   x19-x29, x30, and frame-local input pointers.

10. **TLS region** — dump the full `[anon:stack_and_tls:<tid>]` mapping (typically
    a few pages around `TPIDR_EL0`). Bionic pthread struct + slots
    (errno, dlerror, locale, etc.) are referenced by libc shims.

### P2 — Nice to have (don't block on these)

11. **ART JIT cache** (memfd:jit-cache, the cert corridor's source) — if the cert
    flow re-enters ART for any string materialization. Usually unnecessary if
    we patch the return-art-string capture inside the harness.

12. **`[anon:.bss]` regions adjacent to libnmsssa.so** — Android splits BSS into
    a separate anonymous segment named after the lib; the manager singleton's
    static pointer cell may live here.

13. **`det_buf` region** — if used by the cert function. Per prior captures, it
    sits in libnmsssa's BSS or a fixed heap arena. Optional; the cert path
    seen so far doesn't touch it.

### Region size budget

A complete P0+P1 dump should be **under 50 MB compressed**:
- corridor 0.3 MB · libnmsssa text+rodata+bss ≈ 5–10 MB · libc text ≈ 1 MB ·
  16449 buffer 64 KB · singleton arena 64 KB · stack 64 KB · TLS 16–32 KB

Skip the 384 MB `[anon:dalvik-main space (region space)]` and the 50 MB+ ART
boot.oat regions.

---

## 2. Register state at the hook PC

Capture verbatim from the Frida `Interceptor.attach`'s `context` object inside
`onEnter`. The `context` exposes `x0..x28`, `fp` (= x29), `lr` (= x30), `sp`, `pc`,
and `nzcv`. Names must match the harness's `load_state_json` lowercase keys:

```js
const regs = {};
for (let i = 0; i <= 28; i++) regs[`x${i}`] = '0x' + ctx[`x${i}`].toString(16);
regs.x29 = '0x' + ctx.fp.toString(16);
regs.x30 = '0x' + ctx.lr.toString(16);
regs.sp  = '0x' + ctx.sp.toString(16);
regs.pc  = '0x' + ctx.pc.toString(16);
regs.nzcv = '0x' + (ctx.nzcv || 0).toString(16);
```

**Required:** x0..x30, sp, pc, nzcv.
**Recommended:** q0..q31 (SIMD/FP). Frida's `context` does not expose SIMD on
arm64 directly; capture via inline assembly stub OR accept the harness's
inferred defaults (zero). Note: the cert path so far has **not** required SIMD
registers, but capturing them removes one source of divergence.

`x29` and `x30` are sometimes given as `fp` and `lr`; the converter normalizes.

---

## 3. System registers

The harness `load_state_json` accepts a top-level `system_registers` (or `sysregs`)
object. The one that matters today:

- **`tpidr_el0`** — thread-local storage pointer. Many libc/Bionic shims do
  `ldr xN, [tpidr_el0 + offset]` to fetch errno, the pthread struct, locale, etc.
  Without it the emu reads zero from TLS and faults symbolically.

  Frida cannot read TPIDR_EL0 directly from user space. Two options:
  - **(a) infer** at capture time: a Bionic pthread struct sits at TPIDR_EL0 and
    contains a self-pointer at offset 0; on Android arm64 the convention is also
    that the TLS region's base = TPIDR_EL0. The capture script should record
    the address of the `[anon:stack_and_tls:<tid>]` region containing `sp` and
    set `tpidr_el0` to that region's base. The harness already does this
    inference at runtime if `tpidr_el0` is absent — but recording the captured
    value reduces guesswork.
  - **(b) trampoline read**: insert a one-shot `mrs xN, tpidr_el0` via
    `Memory.patchCode` + `NativeCallback` at a known PC and read xN from
    `context`. Heavyweight; use only if (a) fails.

- `nzcv` — already captured in `registers` (top-level inside the registers
  object). Usually doesn't matter at function entry but record it for parity.

Other sysregs (`TTBR0_EL1`, `MAIR_EL1`, `SCTLR_EL1`) — kernel-only, not needed.

---

## 4. Trigger logic

**Primary hook (natural fire):** `Interceptor.attach(corridor_base + 0x150ca0, ...)`

Per the user's note, `0x150ca0` is the natural-fire entry to the cert function
(was misidentified as printf in `cert-chain-misidentified-printf` from cycle 137;
revisited by arm64-runner's recent facts that put the cert output write at
`+0x1505dc`, which sits inside the `0x150ca0` function). Hooking it passively
catches the cert call when the game's own auth flow drives it.

**Secondary hook (xxhash entry):** `Interceptor.attach(corridor_base + 0x14ff50, ...)`

Captures the *inner* state where the streaming context (`x0`) and the
input-buffer pointer/length (`x1`/`x2`) are concrete. Use this as the **primary
snapshot point** — it's downstream of any setup the 0x150ca0 wrapper does, so
all the registers needed for emu reproduction are concrete and meaningful here.

**The PRIMARY snapshot point is `0x134f30` (orchestrator entry).** Per
cycle-162 (`cert-runtime-table-0x4e3118` REVISED), the inputs the harness is
still missing to drive the full cascade live are:

- **(a) caller's input to orchestrator `0x134f30`** — the raw arguments the
  game passes in. At entry to the orchestrator, all of these are concrete in
  registers / on the stack and have not yet been transformed by any stage.
- **(b) mode args `w20` (chunk-divisor) and `w3` (stage sequence)** — these
  determine how the orchestrator dispatches stages. Without them concrete,
  the harness can't decide whether to run a given stage and the cascade
  diverges immediately.
- **(c) accumulated aux 65-byte buffer state across stages** — the `x3`
  pointer (paired with `w4 = 65` in the call signature documented in
  `cert-stage0-preprocess-a`) carries state from one stage to the next.
  Its **initial** contents at `0x134f30` entry are what the harness needs;
  the mid-pipeline contents are reconstructed by the emu as it runs.

Hooking at `0x14ff50` (xxhash entry) is *insufficient* because by then
stages 0–1 have already mutated the 16449-byte buffer and the 65-byte aux
buffer; capturing the post-PREPROC_A/B state means we can no longer
independently emulate PREPROC_A and PREPROC_B for verification.

**Capture timing is critical** (cert-session-state-origin): the manager
singleton must have `+0x388` (auth_key) populated, which only happens after
the server-handshake HTTP 200 at T+8.9 s post-process-start. A capture that
fires before then will have all-zero auth_key and the cert function won't
produce a valid output. The recommended pattern is:

1. Spawn or attach to the live process at T=0.
2. Optionally hook the HTTP response handler or `singleton+0x388` write
   site as a tripwire — once it goes non-zero, the post-auth window is open.
3. Wait at least one full cert call to confirm the manager is stable
   (alternatively: hook `0x150ca0` and only enable Hook P after the first
   `0x150ca0` natural fire — by which point the manager is definitely
   post-auth, since stage 5/6 can't have run otherwise).
4. Arm Hook P (`0x134f30`); on next natural fire, take the snapshot.

**Recommended flow (revised):**
0. **Hook P — `0x134f30` entry (PRIMARY, post-auth only)**: full state
   dump *before any stage runs*. Capture full registers (including `x20`,
   `w3`, `x22`, the x3 aux-buffer pointer, x0 16449-buffer pointer),
   `nzcv`, `sp`, `pc`; dump regions per Section 1; ALSO dump the 65-byte
   aux buffer at `x3` verbatim into `expected_cert.json` as `aux65_initial`
   so the host-side verifier can compare the harness's per-stage aux state
   against any future Hook-B sample. This is the snapshot the converter
   ingests.
1. **Hook A — `0x150ca0` entry** (secondary): tiny recorder; just
   timestamp + `x0/x1/x2/x22` for natural-fire confirmation and challenge
   tagging.
2. **Hook B — `0x14ff50` entry** (verification only — not the primary
   snapshot): record `cert_struct` pointer + the 32-byte slot at
   `cert_struct+0x20..+0x40` (which should be the xxhash *input* at this
   point) for the harness's mid-cascade cross-check.
3. **Hook M — `0x1505dc`**: capture the 32-byte block written at
   `cert_struct+0x20..+0x40` (the xxHash output, which is the *input* to
   `0x135658`). This is the **intermediate** value, not the cert. Useful as a
   cross-check that the emu reproduces the same xxHash output before HASH2.
4. **Hook N — `0x135658` entry**: read `cert_struct+0x20..+0x40` and record
   it as `hash2_input` (should equal what Hook M observed).
5. **Hook O — `0x135658` exit (onLeave)**: read `cert_struct+0x20..+0x40` and
   record it as `hash2_output`. **This is the cert.**

Write to `expected_cert.json`:
```json
{
  "challenge": "...",
  "orchestrator_entry": {
    "pc":  "0x134f30",
    "w20": "0x...",                  // chunk-divisor (mode arg)
    "w3":  "0x...",                  // stage sequence (mode arg)
    "x0_16449buf_addr":  "0x...",
    "x3_aux65_addr":     "0x...",
    "x22":               "0x...",
    "aux65_initial_hex": "<130-hex of the 65 bytes at x3 BEFORE any stage>"
  },
  "cert_struct_addr": "0x...",
  "hash2_x0_at_entry": "0x...",
  "xxhash_output_32B_via_certstruct":   "<64-hex Hook M @ +0x1505dc onLeave>",
  "hash2_input_32B_certstruct":         "<64-hex Hook N entry, certstruct view>",
  "hash2_input_24B_at_x0plus0x70":      "<48-hex Hook N entry, HASH2 actual read range>",
  "hash2_x0_window_256B_entry_hex":     "<512-hex full window for forensics>",
  "hash2_output_32B_certstruct":        "<64-hex Hook O exit, certstruct view>",
  "hash2_output_24B_at_x0plus0x70":     "<48-hex Hook O exit — THE CERT>",
  "hash2_x0_window_256B_exit_hex":      "<512-hex full window for forensics>"
}
```

The 24-byte field at `x0+0x70` on Hook O exit is the cert per
cert-stage5-hash2-analysis. The 32-byte field at `cert_struct+0x20..+0x40` is
also recorded as a cross-check; if the two views disagree, the host-side
verification step will catch it.

The 32-byte cert struct's first 24 bytes are conventionally the cert (matches
the 48-hex-char shape of the recorded `derive_*.json` outputs); record the full
32B too for forensics and for any future change to the cert's published length.

---

## 5. Pseudocode skeleton (Frida JS)

```js
'use strict';

const PACKAGE = 'com.netmarble.thered';
const OUT_DIR = '/data/local/tmp/cert_harness_snapshot';

function findCorridor() {
    // pick largest r-xp range under /data/data/<pkg>/files whose
    // file-offset-0 segment is bigger than XXH64_STAGE_OFFSET (0x14ff50)
    const XXH64_STAGE_OFFSET = 0x14ff50;
    const buckets = {};
    Process.enumerateRanges('r-x').forEach(r => {
        if (!r.file) return;
        const p = r.file.path || '';
        if (p.indexOf(`/data/data/${PACKAGE}/files/`) === -1) return;
        const e = buckets[p] || (buckets[p] = { total: 0, base0: null, base0Size: 0 });
        e.total += r.size;
        if (r.file.offset === 0) { e.base0 = r.base; e.base0Size = r.size; }
    });
    let best = null;
    for (const p in buckets) {
        const e = buckets[p];
        if (e.base0Size > XXH64_STAGE_OFFSET && (!best || e.total > best.total))
            best = { path: p, base: e.base0, size: e.total };
    }
    return best;
}

function findLibnmsssa() {
    return Process.findModuleByName('libnmsssa.so');
}

function readMaps() {
    return new File('/proc/self/maps', 'r').readText();   // or read /proc/<pid>/maps from shell side
}

function dumpRegion(base, size, outDir) {
    const buf = Memory.readByteArray(base, size);
    File.writeAllBytes(`${outDir}/memdump/${base.toString(16)}.bin`, buf);
}

function snapshotRegisters(ctx) {
    const regs = {};
    for (let i = 0; i <= 28; i++) regs[`x${i}`] = '0x' + ctx[`x${i}`].toString(16);
    regs.x29 = '0x' + ctx.fp.toString(16);
    regs.x30 = '0x' + ctx.lr.toString(16);
    regs.sp  = '0x' + ctx.sp.toString(16);
    regs.pc  = '0x' + ctx.pc.toString(16);
    regs.nzcv = '0x' + (ctx.nzcv || 0).toString(16);
    return regs;
}

function pickRegionsToDump(corridor, libnmss) {
    // returns [{base,end,perms,offset,path,size}] from /proc/self/maps,
    // FILTERED to the P0+P1 set described above.
    const wanted = [];
    Process.enumerateRanges('---').forEach(r => {
        const p = (r.file && r.file.path) || '';
        const include = (
            // P0: corridor (covers 0x14ff50/0x1505dc)
            (r.base.equals(corridor.base) && r.size >= corridor.size) ||
            // P0: libnmsssa text/rodata/bss
            (p.indexOf('libnmsssa.so') >= 0) ||
            // P0: libc text
            (p.indexOf('/system/lib64/libc.so') >= 0 && r.protection.indexOf('x') >= 0) ||
            // P1: stack + tls
            (p.indexOf('[stack') >= 0) || (p.indexOf('[anon:stack_and_tls:') >= 0) ||
            // P1: bss adjacent to libnmsssa
            (p.indexOf('[anon:.bss]') >= 0)
        );
        if (include && r.protection.startsWith('r')) wanted.push(/* descriptor */);
    });
    return wanted;
}

function captureAtHashEntry(corridor, libnmss) {
    const HOOK = corridor.base.add(0x14ff50);

    Interceptor.attach(HOOK, {
        onEnter(args) {
            const t0 = Date.now();
            const regs = snapshotRegisters(this.context);

            // Sanity: challenge should be at (x22 + 0x2010) — log first 8 bytes.
            const x22 = this.context.x22;
            const challengeWindow = Memory.readByteArray(x22.add(0x2010), 16);

            // Dump regions
            const regions = pickRegionsToDump(corridor, libnmss);
            // Also dump the 16449-byte buffer's containing region:
            // resolve x22 to its containing range and add if not already in `regions`.
            // ... (omitted for brevity)

            const sysregs = {
                // TPIDR_EL0 inference: pick the [anon:stack_and_tls:<tid>] region
                // containing `sp` and use its base.
                tpidr_el0: inferTpidr(this.context.sp)
            };

            const manifest = {
                label: 'cert_hash_entry',
                timestamp: new Date().toISOString(),
                pid: Process.id,
                thread_id: Process.getCurrentThreadId(),
                arch: 'arm64',
                pointer_size: 8,
                trigger: {
                    hook_addr: HOOK.toString(),
                    hook_offset: '0x14ff50',
                    natural_fire: true
                },
                registers: regs,
                system_registers: sysregs,
                regions: regions.map(r => ({
                    base:      '0x' + r.base.toString(16),
                    end:       '0x' + r.end.toString(16),
                    size:      r.size,
                    perms:     r.perms,
                    offset:    '0x' + r.offset.toString(16),
                    file_path: r.path,
                    dumped:    true,
                    dump_file: r.base.toString(16) + '.bin',
                    dump_size: r.size
                }))
            };

            const outDir = `${OUT_DIR}_${t0}`;
            File.mkdir(outDir);
            File.mkdir(`${outDir}/memdump`);
            // dump every region
            regions.forEach(r => dumpRegion(r.base, r.size, outDir));
            File.writeAllText(`${outDir}/manifest.json`, JSON.stringify(manifest, null, 2));
            File.writeAllText(`${outDir}/maps.txt`, readMaps());

            send({ ok: true, outDir, hook: HOOK.toString() });
        }
    });
}

function captureCertOutput(corridor) {
    // Three-hook cascade capture; tracks the cert struct through xxHash → HASH2.
    // The cert_struct address is the same across all three hooks; one possible
    // way to obtain it is to read x1 (or whichever reg the caller passes as
    // the output struct ptr) at 0x14ff50 entry and stash it in onEnter/state.
    let certStruct = null;
    const out = { xxhash_output_32B: null, hash2_input_32B: null, hash2_output_32B: null };

    // Hook M — xxHash output write (intermediate, not cert)
    Interceptor.attach(corridor.base.add(0x1505dc), {
        onLeave() {
            if (certStruct) {
                out.xxhash_output_32B =
                    Memory.readByteArray(certStruct.add(0x20), 32);
            }
        }
    });

    // Hook N — HASH2 entry: capture x0 + 24B at x0+0x70 (HASH2's actual read
    // range per cert-stage5-hash2-analysis), AND the cert_struct view, so we
    // can reconcile on the host. Also dump 0x100 bytes around x0 for context.
    Interceptor.attach(corridor.base.add(0x135658), {
        onEnter(args) {
            const x0 = this.context.x0;
            out.hash2_x0_at_entry = x0.toString();
            out.hash2_x0_window_256B_entry =
                Memory.readByteArray(x0, 0x100);
            out.hash2_input_24B_entry =
                Memory.readByteArray(x0.add(0x70), 24);
            if (certStruct) {
                out.hash2_input_32B_certstruct =
                    Memory.readByteArray(certStruct.add(0x20), 32);
            }
            this.hash2_x0 = x0;
        },
        onLeave() {
            const x0 = this.hash2_x0;
            out.hash2_x0_window_256B_exit =
                Memory.readByteArray(x0, 0x100);
            out.hash2_output_24B_exit =
                Memory.readByteArray(x0.add(0x70), 24);
            if (certStruct) {
                out.hash2_output_32B_certstruct =
                    Memory.readByteArray(certStruct.add(0x20), 32);
            }
            emitExpectedCert(out);
        }
    });
    // certStruct is captured at the 0x14ff50 onEnter callback (Hook B) and
    // hoisted into this scope; omitted here for brevity.
}

// --- main ---
const corridor = findCorridor();
const libnmss  = findLibnmsssa();
if (!corridor) throw new Error('corridor not found');
captureAtHashEntry(corridor, libnmss);
captureCertOutput(corridor);
```

---

## 6. Post-capture verification (host side)

After `adb pull`, run on the host:

```bash
SNAP=/path/to/cert_harness_snapshot_<ts>

# 1. challenge sanity: byte 0x2010 of the 16449 buffer should be the challenge
python3 -c "
import json, struct
m = json.load(open('$SNAP/manifest.json'))
x22 = int(m['registers']['x22'], 16)
buf_region = next(r for r in m['regions']
                  if int(r['base'],16) <= x22 < int(r['end'],16))
data = open(f'$SNAP/memdump/{buf_region[\"dump_file\"]}', 'rb').read()
off = x22 - int(buf_region['base'], 16)
print('challenge bytes at +0x2010:', data[off+0x2010:off+0x2018].hex())
"

# 2. session_key + auth_key sanity: resolve mgr via libnmsssa+0x122fb8 and
#    confirm we are POST-AUTH (auth_key at mgr+0x388 must be non-zero).
python3 - << 'PY'
import json, struct, glob, os
m = json.load(open('$SNAP/manifest.json'))
libnmss = [r for r in m['regions'] if 'libnmsssa.so' in (r.get('file_path') or '')]
if not libnmss:
    raise SystemExit('libnmsssa.so NOT in regions list — capture incomplete')
base = min(int(r['base'], 16) for r in libnmss)

def read_at(va, n):
    # Walk every dumped region (not just libnmss) — singleton ptr aims at heap.
    for r in m['regions']:
        rb, re_ = int(r['base'], 16), int(r['end'], 16)
        if rb <= va < re_ and r.get('dumped'):
            data = open(f"$SNAP/memdump/{r['dump_file']}", 'rb').read()
            return data[va - rb : va - rb + n]
    return None

# Resolve singleton
slot = read_at(base + 0x122fb8, 8)
if slot is None:
    raise SystemExit('mgr GOT slot at libnmsssa+0x122fb8 not in dumped pages')
singleton = struct.unpack('<Q', slot)[0]
print(f'manager singleton @ 0x{singleton:x}')

session_key = read_at(singleton + 0x210, 32)   # SSO inline or pointer
auth_key    = read_at(singleton + 0x388, 32)
if session_key is None or auth_key is None:
    raise SystemExit('singleton offsets not in dumped pages — dump enclosing slab')

print('session_key bytes:', session_key[:32].hex())
if all(b == 0 for b in auth_key):
    raise SystemExit('AUTH_KEY IS ZERO — snapshot is PRE-AUTH; retry after server HTTP 200')
print('auth_key bytes:', auth_key.hex(), '(non-zero => post-auth)')
PY

# 2b. CRC32 table sanity: PREPROC_B uses standard reflected CRC32 with a
# CUSTOM SEED 0x7da213f4 (NOT the conventional 0xFFFFFFFF). Confirm
# libnmsssa+0x4e4010 holds the table and the GOT slot at +0x4e3118 has been
# resolved to point at it. PREPROC_A does NOT use this table.
python3 - << 'PY'
import json, struct, glob, os
m = json.load(open('$SNAP/manifest.json'))
# Find libnmsssa.so region(s); collect them with their base addresses
libnmss = [r for r in m['regions']
           if 'libnmsssa.so' in (r.get('file_path') or '')]
if not libnmss:
    print('libnmsssa.so NOT in regions list — capture is incomplete')
    raise SystemExit(1)

# Find module base (lowest base of any libnmsssa.so mapping)
base = min(int(r['base'], 16) for r in libnmss)
print(f'libnmsssa.so base = 0x{base:x}')

def read_at(va, n):
    for r in libnmss:
        rb, re_ = int(r['base'], 16), int(r['end'], 16)
        if rb <= va < re_:
            off = va - rb
            data = open(f"$SNAP/memdump/{r['dump_file']}", 'rb').read()
            return data[off:off+n]
    return None

# Generate the reference reflected CRC32 table
def crc32_table(poly=0xEDB88320):
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (poly if (c & 1) else 0)
        t.append(c & 0xffffffff)
    return t

got_slot   = read_at(base + 0x4e3118, 8)
table_head = read_at(base + 0x4e4010, 1024)

if got_slot is None or table_head is None:
    print('GOT slot or table not in dumped pages')
    raise SystemExit(1)

got_ptr = struct.unpack('<Q', got_slot)[0]
expected = base + 0x4e4010
print(f'GOT slot 0x4e3118 -> 0x{got_ptr:x}; expected 0x{expected:x}  '
      f'{"OK" if got_ptr == expected else "MISMATCH"}')

ref = crc32_table()
actual = list(struct.unpack('<256I', table_head))
if actual == ref:
    print('table_nmcrc @ 0x4e4010 = standard reflected CRC32  OK')
else:
    # find first diff for diagnostics
    bad = next(i for i,(a,b) in enumerate(zip(actual,ref)) if a!=b)
    print(f'table mismatch at index {bad}: got 0x{actual[bad]:08x} '
          f'expected 0x{ref[bad]:08x}')
PY

# 3. convert
python3 /home/sdancer/aeon-ollvm-codex1/scripts/snapshot_to_page_cache.py \
    --out /tmp/cert_harness_live1 \
    --serial cert-live-snapshot-<ts> \
    --challenge "$(jq -r .trigger.challenge $SNAP/manifest.json)" \
    manifest \
    --manifest $SNAP/manifest.json \
    --memdump-dir $SNAP/memdump \
    --maps $SNAP/maps.txt

# 4. boot the harness
target/release/live_cert_eval \
    --state-json /tmp/cert_harness_live1/state.json \
    --maps-file /tmp/cert_harness_live1/maps.txt \
    --adb-serial cert-live-snapshot-<ts> \
    --offline-cache \
    --page-cache-dir /tmp/cert_harness_live1/page_cache \
    --challenge "$(jq -r .trigger.challenge $SNAP/manifest.json)" \
    --max-blocks 4096 \
    --missing-memory symbolic \
    --report-out /tmp/cert_harness_live1_report.json
```

A successful run should advance `blocks >> 1`, traverse **`+0x14ff50` (xxHash) →
`+0x1505dc` (xxHash output write) → `+0x135658` (secondary hash, the heavy 22862-
insn function with 77 loops)** to completion, and produce a final 32-byte cert
struct that matches the `hash2_output_32B` field of `expected_cert.json`.

Three cross-check milestones (in order):
- After block traversal reaches the write at `+0x1505dc`, the emu's
  `cert_struct+0x20..+0x40` should match `xxhash_output_32B_via_certstruct`
  from Hook M. If this matches but the final cert doesn't, the bug is in HASH2
  emulation, not in the input pipeline.
- At HASH2 entry (`+0x135658`), the emu's `x0 + 0x70..(+0x88)` should match
  `hash2_input_24B_at_x0plus0x70` from Hook N. Two distinct possibilities if
  this disagrees: (a) the captured `cert_struct` is *not* the same pointer
  HASH2 receives in `x0`, or (b) HASH2 reads a different offset than 0x70.
  The Hook N forensic window (`hash2_x0_window_256B_entry_hex`) lets us locate
  the actual cert-input bytes inside the 256-byte window.
- After block traversal returns from `+0x135658`, the emu's `x0 + 0x70..(+0x88)`
  should match `hash2_output_24B_at_x0plus0x70` from Hook O — **this 24-byte
  window is the cert** (48 hex chars).

Because `0x135658` is 91 KB / 22862 insns / 77 loops, expect `--max-blocks` of
**at least 8192** for the harness invocation to complete the cascade. Memory
churn during that traversal is the main risk; budget time accordingly.

**Obfuscation stress on the emu.** Per cert-stage5-hash2-analysis, HASH2 has
≈21% negated-logic ops and runtime-reconstructed constants. Two practical
consequences for the harness:
1. The lifter must handle a high density of `EOR x, y, ~z` / `MVN` patterns
   without spurious symbolic-branch escapes. If the emu halts mid-HASH2 with
   `stop_reason: symbolic_branch` and the deps point inside the corridor
   (rather than at a missing memory address), the obfuscation is the cause,
   not missing input data. Try `--missing-memory symbolic` even when all
   regions are present — it lets the engine push through obfuscation-
   constructed values rather than treating any unresolved read as fatal.
2. Many constants HASH2 uses are read from libnmsssa.so's `.data.rel.ro` after
   RELRO relocation. If the snapshot region #3 (libnmsssa.so r--p) is missing,
   the constants will appear symbolic and the cert will diverge from
   `hash2_output_24B_at_x0plus0x70`. The capture **must** include the entire
   libnmsssa.so r--p and rw-p mappings — not just text.

---

## 7. Open questions for trace-claude3

- Is `0x150ca0` natural-fire reliable on the current AION2 build, or has the
  cert flow shifted again? Confirm by passive `Interceptor.attach` and a
  one-minute idle observation before doing the full dump.
- Is `x22` always the orchestrator pointer for the 16449-byte buffer, or only
  on some code paths? If variable, the spec needs to enumerate candidate
  registers (`x19`/`x20`/`x21`/`x22`) and scan all for the `(x + 0x2010 ==
  current_challenge_bytes)` invariant.
- `TPIDR_EL0` value: if the inferred-from-stack approach fails, schedule a
  one-shot inline `mrs` capture from a known PC and bake the result into the
  manifest under `system_registers.tpidr_el0`.

---

## 8. Naming

The capture script that implements this spec should live at
`/home/sdancer/aeon-trace/frida/full_state_capture_5558.py` (mirroring the
`<purpose>_<device>.py` naming used by other Frida scripts in that tree).
