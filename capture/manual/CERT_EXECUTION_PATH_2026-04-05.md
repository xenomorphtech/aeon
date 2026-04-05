# Cert Execution Path Summary (2026-04-05)

## Inputs

- Live cert call traced successfully through the armed Stalker relay.
- Live JIT execute alias: `0x9b5fe000`
- Successful cert trace start block: `0x9b612670`
- Traced block heads: `258`
- JIT image analyzed: `capture/manual/jit_exec_alias_0x9b5fe000.bin`

## High-Level Conclusion

The traced cert corridor does **not** look like a standalone hash compression routine. The hot blocks are dominated by:

- object/tag checks against runtime type tables
- virtual dispatch through method slots
- temporary object allocation/lookup
- bounds and state handling
- printable-character sanitization
- lock/flag handoff and cleanup

I also searched the live JIT dump for common embedded crypto constants:

- MD5 IVs
- SHA-1 IVs
- early SHA-256 round constants
- AES S-box prefix
- base64 alphabet

None of those were present in the current JIT image. The current traced corridor therefore looks like a **cert builder / formatter / dispatcher path around crypto state**, not the raw crypto primitive itself.

## Interpreted Path

### 1. Entry dispatch and object validation

Start block: `0x9b612670`

This block is a repeated "typed object -> slot call" ladder:

- load object tag from `[x1]`
- compare against runtime type cell at `0x76ace14c34`-style globals
- on mismatch, call the slow-path validator via `[x19 + 1528]`
- on match, load a method/object slot and call through `[x0 + 24]`

The block does this multiple times in sequence:

- slot `+984`
- slot `+768`
- slot `+768` again
- if nonzero, branch into a deeper helper chain

This is consistent with:

- validating the current cert context object
- extracting nested fields or helper interfaces
- selecting the next stage dynamically

### 2. Builder object allocation and setup

Hot block: `0x9b619a50`

This block:

- preserves `x1..x4` into `x22..x25`
- allocates or acquires a temporary object through the runtime allocator path
- dispatches through slot `+984`
- then calls another helper object via slot `+592`

This looks like construction of an intermediate builder/context object used by later cert formatting steps.

### 3. Multi-step field extraction and gated processing

Hot block: `0x9b617a20`

This is a larger coordinator block. It:

- pulls multiple nested objects through slot calls
- checks a count/length field at `[x0 + 8]`
- fetches further fields through slots `+224`, `+264`, `+736`, `+248`, `+192`, `+304`, `+1096`, and `[obj+128]->...`
- uses atomic/ordered loads (`ldar`) and a state flag word
- conditionally toggles bit flags in a local state register

This does not look like arithmetic hashing. It looks like:

- walking structured input pieces
- deciding which subfields participate
- staging values for emission into the final cert buffer

### 4. Range and length normalization

Hot block: `0x9b61c8f0`

This block operates on what looks like a slice/string/buffer descriptor:

- compare requested length/index `w2` against `[x1 + 24]`
- reject negative/top-bit-set values
- write `[x1 + 32] = w2`
- clamp `[x1 + 28]` to `-1` if needed

This is a classic bounds-update helper, not a hash round.

### 5. Character sanitization / printable coercion

Hot block: `0x9b61ccc0`

This is the clearest semantic helper in the traced set.

It:

- loops while `w22 < w21`
- fetches a character-ish value through slot `+232`
- checks whether it is in `(0x1f, 0x7f)`
- if outside printable ASCII, substitutes `0x3f` (`'?'`)
- forwards the chosen byte/value through slot `+1008`
- accumulates the returned size/count into `w22`

This strongly suggests:

- escaping or sanitizing emitted cert characters
- or converting internal values into a printable token representation

It is **not** characteristic of a raw digest compression loop.

### 6. Lock/flag release and cleanup

Hot block: `0x9b61d500`

This block:

- calls through `[x19 + 896]`
- reads a byte from `[x21 + 0x10f]` with `ldarb`
- clears it with `stlrb wzr, [x21 + 0x10f]`
- calls through `[x19 + 904]`
- returns the saved byte in `x0`

This is a small synchronization/ownership handoff helper, likely cleanup after a builder or queue object is processed.

### 7. Return-side helper

Hot block: `0x9b616790`

This is mostly a function epilogue. The meaningful work happens just before it:

- a helper call via a literal-loaded object
- `str w23, [x21 + 12]`
- return `x21`

This looks like a small result/update helper that stores a status/count into an object before returning.

## Important Non-Code Markers

Two traced addresses are not real logic bodies:

- `0x9b613e40`
- `0x9b6142f0`

Both land in UDF/literal-pool islands. The executable helpers begin immediately after them:

- real helper starts near `0x9b613e60`
- real helper starts near `0x9b614310`

So these PCs are best interpreted as block-boundary markers inside generated code, not standalone algorithm steps.

## Current Best Assessment

The successful cert trace is entering a **flattened generated builder pipeline** that:

1. validates the current cert context object
2. acquires helper/builder objects
3. walks nested structured fields
4. normalizes indices and lengths
5. coerces output into printable ASCII
6. commits the result and releases state

The actual hash primitive is likely:

- hidden behind one of the virtual slot calls in this corridor, or
- executed outside this hot printable/builder corridor and only its result is consumed here

Based on the current traced blocks alone, the cert path we captured is **closer to token assembly than to the raw hash core**.

## Internal Caller Follow-up

I followed the two strongest internal caller PCs reached from the later deep trace:

- `0x9b60c7c8`
- `0x9b614848`

These do **not** look like exits into `libUnreal.so` or the deleted `nmcore` image.

### `0x9b60c7c8`

This site sits inside a local numeric-processing block, not at a `blr` handoff. The surrounding code:

- first dispatches through slot `+248`
- then reads a structure with a length/count at `[x0 + 8]`
- performs float loads from offsets like:
  - `+60`
  - `+12`
  - `+64`
  - `+32`
  - `+20`
  - `+36`
  - `+56`
  - `+24`
- compares and combines those fields with `fadd` / `fcmp`

So this block looks like local record/vector-style arithmetic or scoring logic, not an external crypto-library call.

### `0x9b614848`

This site is still inside a JIT object-dispatch helper. The surrounding code:

- checks a flag byte at `[x21 + 73]`
- dispatches through slot `+288`
- reads another nested field at `[w1 + 132]`
- dispatches through slot `+288` again

So this is another internal object-walking helper, not the external digest boundary.

### Implication

The deeper follow-up strengthens the same conclusion:

- the current reproducible cert path is still staying inside the generated JIT subsystem
- the interesting work may be a custom JIT-implemented transform rather than a call out to a standard digest implementation

## Slot Return Follow-up

I instrumented the post-call return sites for two deeper slot dispatches:

- `0x9b612768` for the chain starting at `0x9b612754`
- `0x9b617da4` for the chain starting at `0x9b617d98`

### `0x9b617d98` return values

This site fired heavily on a valid cert call.

Observed return values in `x0` were small scalars:

- `0`
- `1`
- `2`
- `3`

Those values were not readable pointers and immediately faulted on dereference. That strongly suggests this slot returns a compact enum/status/classification code rather than an object pointer.

The companion registers were more object-like:

- `x1` / `x2` repeatedly held heap-like addresses such as:
  - `0x6f62c528`
  - `0x6f62c540`
  - `0x6f62c558`
  - `0x71618fe8`
- `lr` was stable at `0x9b626d1c`, still inside the JIT image

So the useful data flow at this point is:

- structured state is still carried in the object-like arguments (`x1`, `x2`)
- the slot call at `0x9b617d98` collapses that state to a tiny code in `x0`

### `0x9b612754` return values

This return site did **not** fire on the current reproducible cert path, so it is either session-dependent or on a sibling path not taken by the warm valid-token flow used here.

### Implication

This is more evidence against a conventional raw digest API boundary:

- the hot deep slot at `0x9b617d98` is returning tiny classification/state values
- the real payload still appears to live in JIT-managed object arguments, not in a direct hash-buffer pointer or external library return value

So the next decoding step should follow the object-bearing arguments around this site, especially the `x1` / `x2` values, rather than chasing external-library call edges.

## x1 / x2 Object Dump Follow-up

I then dumped the live `x1` / `x2` objects in-context at `0x9b617da4`.

The interesting repeated object addresses were:

- `0x6f62c528`
- `0x6f62c540`
- `0x6f62c558`
- `0x71618fe8`

All of them live in anonymous `rw-` heap mappings, but their contents look like string/object payloads related to TLS and certificate validation, not challenge or token bytes.

### `0x6f62c528`

This object contains string fragments including:

- `TLSv1`
- `TLSv1.1`
- `TLSv1.2`
- `This protocol does not support input`

### `0x6f62c540`

This overlaps the same string table region and includes:

- `TLSv1.1`
- `TLSv1.2`
- `This protocol does not support input`
- `Timeout ...`

### `0x6f62c558`

This also overlaps the same region and includes:

- `TLSv1.2`
- `This protocol does not support input`
- `Timeout too large.`

### `0x71618fe8`

This object contains:

- `TLSv1.3`
- `com.android.org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi`

### Implication

These are not challenge/token carriers.

Instead, the hot `0x9b617d98` slot appears to be classifying or selecting among pre-existing TLS / certificate-provider related objects and collapsing that selection to a tiny code in `x0`.

So this path is even further from a raw digest-buffer producer than initially suspected. The interesting data flow at this point is not the challenge bytes themselves, but:

- object/handle selection
- provider/protocol classification
- later printable-token assembly in the surrounding JIT pipeline

## Best Next Targets

If we want the real crypto primitive rather than the builder path, the next highest-value targets are the slot call sites that feed data into the printable/sanitizing stage:

- `0x9b612754` / slot chain from the entry ladder
- `0x9b617d98` / slot `+304`
- `0x9b617e00` and `0x9b617e80` / nested `[obj+128]` chains
- `0x9b61ccd8` / the source producing the character/value before ASCII clamping

Those are better candidates than the already-traced builder helpers if the goal is to isolate the underlying hash or digest producer.

## Differential Token-Buffer Dump Follow-up

I switched from object tracing to a differential writable-memory scan around the final token string.

For a valid cert call with challenge `1122334455667788`, the returned token was:

- `55D15DC554B3587FF81A9576D57003F764951294D7B8502B`

Writable-memory hits for that token showed two distinct storage patterns:

- transient heap records in the large anonymous `rw-` arena at `0x12c00000`
- a later stable copy at `0x77019b03a0`

### Transient heap record layout

The transient copies landed at:

- `0x12dca540`
- `0x12dca5a0`
- `0x12dca600`

The same pattern repeated on the next valid cert call with challenge `8899AABBCCDDEEFF`, whose token was:

- `EFE61364337E826920BD441CF2C69AA017AFF94424139E0A`

The new transient copy then appeared at:

- `0x12dca660`

The spacing is a regular `0x60` bytes per record. Each record has the same local shape:

- token ASCII at `record + 0x00`
- challenge ASCII at `record - 0x20`
- pointer/length metadata just before that

For example, the later valid call with challenge `1234567890ABCDEF` produced token:

- `B21650E95EBE475363D646DCA08EBA84D8CF47AB6A4B959A`

and the matching transient record looked like:

- metadata/header write at `0x12dca6f0`
- challenge at `0x12dca700`
- token at `0x12dca720`

So the token is not first materialized at the small stable copy. It first appears inside a structured heap record in the large `0x12c00000` arena.

### Stable later copy

Across different valid tokens, the only stable writable address was:

- `0x77019b03a0`

That region sits next to certificate/TLS text such as:

- `http://www.digicert.com/CPS`
- `Java_com_epicgam...`

Watching `0x77019b03a0` during a cert call produced only a read, not a write. So this is a downstream consumer/cached copy, not the first producer.

### First write-side hit

I then watched the transient heap page `0x12dca000..0x12dcb000` during a valid cert call.

The first write hit was:

- write PC: `0x76bfd4a764`
- LR: `0x76bfd447e8`
- destination: `0x12dca6f0`
- `x2 = 0x6f3df760`
- `x3 = 0x20`

Kernel mapping shows that `0x76bfd4a764` is inside:

- `/apex/com.android.art/lib64/libart.so`
- execute mapping `76bfcc6000-76bfe34000`

So the first observed write into the token record is not coming directly from the game JIT block. It is coming from an ART runtime helper that writes the record header/metadata immediately before the challenge/token ASCII payload.

### Implication

This gives a much cleaner boundary:

- the small stable token copy at `0x77019b03a0` is too late
- the large `0x12c00000` heap arena is the first useful token-bearing structure
- the first observed write into that structure is already in `libart.so`

That means the next reverse step should work backward from the ART-side write helper into its caller chain, or keep watching the transient arena with a lighter stack/caller capture, rather than continuing to chase downstream TLS/provider objects like the `0x9b617d98` classification path.

## Direct libart Write-Site Hook Follow-up

The heap-page watch was still unstable, so I switched to a direct hook on the already-identified ART write leaf instead of using `MemoryAccessMonitor`.

The correct hook target is:

- `libart.so + 0x54a764`
- live address in this run: `0x76bfd4a764`

This is the same write PC previously observed when the transient token record was being built in the large `0x12c00000` heap arena.

### Live hit

With the direct hook armed, a valid cert call for challenge `1122334455667788` returned:

- `FC54718D35F9BB69563700FCAB21B7F8AF25A597616A26D4`

The `libart` write-site hook fired exactly once:

- `pc = 0x76bfd4a764`
- `lr = 0x76bfd447e8`
- `x0 = 0xb4000077d19580a0`
- `x1 = 0xb400007831a5b2d0`
- `x2 = 0x6f3df760`
- `x3 = 0x28`
- `x4 = 0x7`

### Raw caller chain above the write leaf

Short fuzzy backtrace captured at the hook:

1. `0x76bfd447e8`
2. `0x795e3d4b90`
3. `0x795e3a7ab8`
4. `0x76bfd447e8`
5. `0x76bfca2f70`
6. `0x76b44b1fac`
7. `0x76b44a432c`
8. `0x6faa5b90`

Mapped modules:

- `0x76bfd447e8` -> `libart.so`
- `0x795e3d4b90` -> `libc.so`
- `0x795e3a7ab8` -> `libc.so`
- `0x76bfca2f70` -> `libart.so`
- `0x76b44b1fac` -> `libjavacore.so`
- `0x76b44a432c` -> `libjavacore.so`
- `0x6faa5b90` -> `boot-core-libart.oat`

### Implication

This is the cleanest recovered caller chain so far above the token-record write site, and it is entirely inside the Android runtime stack:

- `libart.so`
- `libc.so`
- `libjavacore.so`
- boot OAT code

There are no game-native or JIT frames in this captured slice.

That strongly suggests this particular write is already late in the pipeline: a runtime-managed string/object copy or materialization step after the cert value has been converted into its printable ASCII form.

So the actual digest or custom transform still happens earlier, before control reaches this ART-managed write path.

## Low-Overhead Stalker Follow-up

I then tried to diff two valid cert calls by stalking the cert thread directly instead of using the heavy page-trap relay.

### 1. Stalking the `Java.performNow()` cert thread

I added a low-overhead relay that:

- runs `NmssSa.getCertValue(challenge)` directly inside `Java.performNow()`
- stalks that exact thread during the call
- counts basic-block heads in interesting executable mappings (`jit-cache`, deleted app images, `libUnreal.so`, `libnmsssa.so`, etc.)

Result on valid calls:

- challenge `1122334455667788` -> token `FDBCEF462DFE0E28266A2685C2C84EBB000AB2CB369CB47E`
- challenge `A1B2C3D4E5F60718` -> token `2A27E4DE6774D402223A3EB3320F2573B143D5E642E782F8`

But the trace saw:

- `threadId = 23219`
- `blockCount = 0`
- `pcHits = {}`

So the direct cert-call thread did not execute any blocks in the expected native/JIT mappings during the traced window.

### 2. Stalking the worker thread from native handoff hooks

I then added a second relay keyed off the stable native handoff sites already present in the capture agent:

- `nmsscr_base + 0x209dc4`
- `nmsscr_base + 0x20b548`

The idea was:

- arm tracing
- call `getCertValue()`
- when one of those native hooks fires, start stalking that actual worker thread

Result on the same two valid cert calls:

- both calls still returned valid tokens
- neither native hook fired
- `workerThreadId = null`
- `startHook = null`
- `hookHits = []`
- `blockCount = 0`

### Implication

This is strong negative evidence:

- the current valid cert path in this live session is **not** traversing the previously assumed native handoff points
- and it is **not** executing inside the expected JIT/native executable ranges on the direct `Java.performNow()` cert thread either

So the earlier JIT corridor and page-trap observations do not currently line up with the reproducible warm valid-token path being exercised now.

At this point, the missing step is not “trace harder inside the same corridor,” but first re-identify the actual execution boundary for the present cert path:

- either the current path is offloading to a different native/JIT thread we are not yet hooking
- or the current path has moved to a different Java / ART / deleted-image route than the one previously traced
