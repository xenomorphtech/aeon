# NMSS Detection Path 2026-04-05

## Scope

Passive mapping of the `code 5` / `kMyself` alert path in the current NMSS stack.
This note is about understanding how the detection signal is produced and surfaced, not about changing behavior.

## Main result

The Java side does **not** synthesize the runtime string:

`Security Alert(code : 5)\n[kMyself]`

Instead:

1. Native code emits a Java callback `DetectCallBack(int code, String details, boolean exitFlag)`.
2. `NmssSa.DetectCallBack(...)` decides whether to show a dialog.
3. `NmssSa.AlertMsg(...)` just stores the three values into fields and posts a UI runnable.
4. The dialog runnable uses `m_strMsg` directly as the alert body.
5. If `m_bAppExit` is true, the dialog OK handler finishes the activity and kills the process.

That means both `code = 5` and the visible details string are already decided before `AlertMsg(...)`.

## Java chain

### Entry

`GameActivity` initializes NMSS with:

- `NmssSa.getInstObj().init(activity, null)`

Decoded from:

- `/tmp/nmss_apktool/smali/com/epicgames/unreal/GameActivity.smali`

This is only the early app-side init. The engine bridge can be attached later:

- `SecurityUnrealBridge.<init>()` installs `new SecurityUnrealBridge$1()` via `NmssSa.setDetectCallBack(...)`
- `SecurityUnityBridge.<init>()` does the same for the Unity bridge

Decoded from:

- `/tmp/nmss_apktool/smali_classes3/nmss/app/SecurityUnrealBridge.smali`
- `/tmp/nmss_apktool/smali_classes3/nmss/app/SecurityUnityBridge.smali`

In this APK, there are no decoded Java-side call sites instantiating `SecurityUnrealBridge`, so that bridge is likely created from engine/native-side code rather than the ordinary `GameActivity` boot path.

### `NmssSa.DetectCallBack(int, String, boolean)`

Decoded from:

- `/tmp/nmss_apktool/smali_classes3/nmss/app/NmssSa.smali`

Behavior:

1. If `m_detectCallBack != null`, call `InitCallbackStrings()`.
2. Look up an optional custom message by detection code from `m_lCustomMessages`.
3. Look up `"default"` in `m_lCustomMessages`.
4. Check whether the detection code is suppressed in `m_lMessagesOff`.
5. If `code > 0 && exitFlag`, append either the custom message or default message to `details` using `"\n"`.
6. If the code is not suppressed and either `details` is non-empty or `exitFlag` is true, call `AlertMsg(code, details, exitFlag)`.
7. If `m_detectCallBack != null`, call `onDetectNotify(code, "")`.

Important consequence:

- The engine callback only receives `(code, "")`.
- The dialog text comes from the internal `details` string passed into `AlertMsg(...)`, not from the engine bridge.

### `NmssSa.AlertMsg(int, String, boolean)`

Decoded from:

- `/tmp/nmss_apktool/smali_classes3/nmss/app/NmssSa.smali`

Behavior:

1. If static `m_bShowMsg` is already true, return.
2. Set `m_bShowMsg = true`.
3. Store:
   - `m_bAppExit = exitFlag`
   - `m_nCode = code`
   - `m_strMsg = details`
4. Post `NmssSa$1` onto the UI thread.

This method does **not** prepend `"Security Alert"` and does **not** format `code 5`.

### Dialog runnable

Decoded from:

- `/tmp/nmss_apktool/smali_classes3/nmss/app/NmssSa$1.smali`

Behavior:

1. Create `AlertDialog.Builder(activity)`.
2. Call `setMessage(m_strMsg)`.
3. Make it non-cancelable.
4. Add an OK button.
5. Show the dialog.

Again: the displayed text is `m_strMsg` as-is.

### Dialog OK handler

Decoded from:

- `/tmp/nmss_apktool/smali_classes3/nmss/app/NmssSa$1$1.smali`

Behavior:

1. If `m_bAppExit` is true:
   - `moveTaskToBack(true)`
   - `finish()`
   - `Process.killProcess(Process.myPid())`
2. Reset `m_bShowMsg = false`

This matches the passive runtime observation that `m_bAppExit` is the field that turns the alert into process termination.

### Engine callback subclasses

Decoded from:

- `/tmp/nmss_apktool/smali_classes3/nmss/app/NmssSa$DetectCallBack.smali`
- `/tmp/nmss_apktool/smali_classes3/nmss/app/SecurityUnrealBridge$1.smali`
- `/tmp/nmss_apktool/smali_classes3/nmss/app/SecurityUnityBridge$1.smali`

Behavior:

- `NmssSa$DetectCallBack` is an abstract Java callback with:
  - `InitCallbackStrings()`
  - `onDetectNotify(int, String)`
- Unreal bridge forwards `(code, details)` into native `iiiliIIiiIli(int, String)`.
- Unity bridge forwards `(code, details)` into a Unity JSON message.

But `NmssSa.DetectCallBack(...)` calls them with an empty details string:

- `onDetectNotify(code, "")`

So those bridges are notification-only. They are not the source of the UI text.

## Native chain

Binary:

- `/home/sdancer/games/nmss/bins/e6c48d89_libnmsssa.so`

### JNI callback bridge

`0x13f9d0`

- Builds the Java callback name `"DetectCallBack"`
- Builds the Java signature `"(ILjava/lang/String;Z)V"`
- Passes the callback to `0x14173c`

The callback strings are visible in `.rodata` around:

- `0x31ba4b` -> `DetectCallBack`
- `0x31ba5a` -> `(ILjava/lang/String;Z)V`

This helper does one more important thing before the JNI dispatch:

- if `w2 & 1` is set, it runs a short side path that includes `mov w1, #5`
- that side path calls `0x128eb4`, `0x12aee8`, and `0xe2eec`

That does not prove it is the single origin of detection code `5`, but it is one of the tightest native sites where literal `5` is prepared adjacent to the Java callback emit.

### Other registered Java callback helpers

`0x13fb8c`

- if `w0 == 1`, builds:
  - `SetApkInfoCallBack`
  - `()V`
- otherwise builds:
  - `SetProcessInfoCallBack`
  - `()V`
- then calls the same JNI dispatcher `0x14173c`

`0x13fdfc`

- builds:
  - `TDThreadWait`
  - `(I)V`
- then calls sibling JNI helper `0x141d68`

The relevant `.rodata` strings are contiguous:

- `0x31ba72` -> `SetApkInfoCallBack`
- `0x31ba85` -> `()V`
- `0x31ba89` -> `SetProcessInfoCallBack`
- `0x31baa0` -> `TDThreadWait`
- `0x31baab` -> `(I)V`

### Common Java dispatcher

`0x14173c`

This is the common JNI dispatcher used by:

- `0x13f9d0` for `DetectCallBack`
- `0x13fb8c` for `SetApkInfoCallBack` / `SetProcessInfoCallBack`

High-level behavior:

1. Resolve the target Java method on the callback object.
2. Convert the native string payload into a `jstring`.
3. Call the Java method with:
   - `code`
   - `details`
   - `exitFlag`
4. Release temporary JNI/local resources.

### `nmssDetect`

`0x14148c` (`Java_nmss_app_NmssSa_nmssDetect`)

High-level behavior:

1. If the incoming flag is set, do pre-work via `0x122fb8`.
2. Call `0x128150`.
3. In the alternate path, load a callback slot from `[ctx + 0x3a8]`.
4. Call that slot indirectly with:
   - `w0 = detectType-ish input`
   - `x1 = temporary string object`
   - `w2 = 0`

So `nmssDetect` itself does not call Java directly; it routes through a context callback.

### Context construction

`0x1242b4`

Called from `nmssNativeInit_ext`.

It builds a large detection/report context and stores several fields, including callback slots:

- `[ctx + 0x3a8]`
- `[ctx + 0x3b0]`
- `[ctx + 0x300]`
- `[ctx + 0x380]`

The slot mapping is now concrete from the caller setup in `nmssNativeInit_ext`:

- `nmssNativeInit_ext` at `0x13ea84..0x13eaa8` passes stack arguments into `0x1242b4`
- `0x1242b4` later stores them with:
  - `[ctx + 0x3a8] = 0x13f9d0` -> `DetectCallBack(int, String, boolean)`
  - `[ctx + 0x3b0] = 0x13fb8c` -> `SetApkInfoCallBack` / `SetProcessInfoCallBack`
  - `[ctx + 0x300] = caller int argument`
  - `[ctx + 0x380] = caller pointer argument`

So the callback slot used by `nmssDetect` is no longer inferred: `[ctx + 0x3a8]` is the native helper that emits Java `DetectCallBack(...)`.

This function also contains one of the strongest `code 5` signals currently isolated:

- `0x1244b4: cmp w9, #0x5`

That comparison happens before the callback/report registration branch and is likely part of the classification threshold or mode-selection logic for the detection/report context.

## What is known about `code 5`

### Definite facts

1. Java does not compute it.
2. `AlertMsg(...)` only stores it.
3. `NmssSa.DetectCallBack(...)` only uses it for:
   - custom-message lookup
   - message suppression lookup
   - deciding whether to call `AlertMsg(...)`
4. The integer must therefore come from native code before Java callback dispatch.

### Strong native candidates

- `0x1244b4: cmp w9, #0x5` inside context builder `0x1242b4`
- `0x17eabc` and nearby branches compare against `#5`
- multiple internal helpers return literal `5` as a classification result

The strongest reduced path so far is:

- `0x17d62c`
  - early exit: if `[ctx + 0x318] == 0`, return `5`
- `0x17ea60`
  - calls `0x17d62c`
  - immediately does `cmp w0, #0x5`
  - special-cases both `0` and `5`
  - if its callback returns `0` and the classifier result was `5`, it propagates `5` out

That means `17d62c -> 17ea60` is currently the tightest statically reduced native path where a final-looking `5` classification is produced and preserved.

### Current best interpretation

`code 5` is a native classification result that is later forwarded through `DetectCallBack(code, details, exitFlag)`. The single root assignment has not been reduced to one final basic block yet, but it is clearly upstream of Java and downstream of the native detection/report logic.

## What is known about `kMyself`

### Definite facts

1. It does not appear in decoded Java/smali from the XAPK.
2. It does not appear in the `NmssSa` Java logic.
3. The Java dialog uses `m_strMsg` directly, so if the runtime string contains `[kMyself]`, that text was already present in the native `details` payload.
4. It does not appear as cleartext in `libnmsssa.so` string tables either.
5. `"Security Alert"` also does not appear as cleartext in decoded Java/smali or in `libnmsssa.so`.

### Current best interpretation

`kMyself` is most likely:

- produced by the native detection engine as a detail string, or
- decrypted from an internal string table before the Java callback is issued

It is **not** added by `AlertMsg(...)`.

## Best current end-to-end chain

1. `GameActivity -> NmssSa.init(activity, null)`
2. optional later engine bridge registration via `SecurityUnrealBridge.<init>() -> NmssSa.setDetectCallBack(...)`
3. `nmssNativeInit_ext (0x13e34c)`
4. context build in `0x1242b4`
5. callback slot registration:
   - `[ctx + 0x3a8] = 0x13f9d0`
   - `[ctx + 0x3b0] = 0x13fb8c`
6. detection entry `nmssDetect (0x14148c)`
7. core detect/report path `0x128150`
8. native classification loop candidate `0x17d62c -> 0x17ea60`
9. indirect detect callback from `[ctx + 0x3a8]`
10. native callback builder `0x13f9d0`
11. JNI dispatcher `0x14173c`
12. Java `NmssSa.DetectCallBack(code, details, exitFlag)`
13. Java `NmssSa.AlertMsg(code, details, exitFlag)`
14. UI runnable `NmssSa$1.run()`
15. OK handler `NmssSa$1$1.onClick()`
16. if `m_bAppExit == true`, finish + kill process

## Reduced `0x128150` caller tree

The `0x17d62c -> 0x17ea60` path explains where the native classifier preserves `code 5`, but it does **not** yet explain where the visible details string comes from.

The tree is now reduced enough to separate two different native branches:

### 1. Init/config branch: tag parser from `0x1242b4`

The function at `0x12cfd0` is reached from the context constructor:

- `0x124508: add x0, sp, #0x68`
- `0x124510: ldr x1, [ctx + 0x380]`
- `0x124518: bl 0x12cfd0`

`0x12cfd0` is the function containing the tag comparisons previously observed around `0x12d480..0x12de40`:

- `[ENV]`
- `GT`
- `SU`
- `CU`
- `DFLU`
- `HTST`
- `SHDM`
- `DMSG`
- `DFSC`
- `DFSP`
- `DFVM`
- `DFMS`
- `DFAI`
- `DFHS`

Important assignments in that parser:

- `0x12d804` -> store parsed value at `[state + 0x30]`
- `0x12d8f0` -> store parsed value at `[state + 0x48]`
- `0x12d9dc` -> store parsed value at `[state + 0x60]`
- `0x12dae0` -> store parsed value at `[state + 0x78]`
- `0x12dbcc` -> store parsed value at `[state + 0x18]`
- `0x12dcd8` -> store derived integer at `[state + 0x110]`
- `0x12ddbc` -> the `DMSG` branch stores a parsed string at `[state + 0x90]`

This is still important, but the surrounding call site matters: it is run from context construction, using the path/pointer in `[ctx + 0x380]`. So the `DMSG` branch is best interpreted as **init-time config/message ingestion**, not the final live `kMyself` string emitter inside the detection loop.

### 2. Live detect/report branch: `0x12aa40 -> 0x128f30`

Inside the main detect path `0x128150`, the repeated stable handoff is:

- `0x12b1fc: bl 0x12aa40`
- `0x12b200: ldr x1, [ctx + 0x380]`
- `0x12b204: ldr x3, [ctx + 0x3a8]`
- `0x12b208: add x21, ctx, #0x70`
- `0x12b214: bl 0x128f30`

and then a second retry:

- `0x12b220: bl 0x12aa40`
- `0x12b224: ldr x1, [ctx + 0x380]`
- `0x12b228: ldr x3, [ctx + 0x3a8]`
- `0x12b230: mov x2, x21`
- `0x12b234: bl 0x128f30`

`0x12aa40` is not the classifier. It refreshes/tears down transient state and immediately formats runtime strings from:

- `[ctx + 0x388]`
- `[ctx + 0x304]`

using the rodata mini-format at `0x31b7a5` (`%d%s%d%s%d` suffix inside the larger `%d%s%d%s%d%s%d%s%d` blob).

The same field pair is reused again in sibling runtime formatters:

- `0x123530`
- `0x1236d4`
- `0x12b93c`
- `0x129844`

Those blocks all read:

- `ctx->0x388`
- `ctx->0x304`

and build `%d/%s`-style strings from them.

### What `0x128f30` actually does

`0x128f30` takes:

- `x0 = context-ish object`
- `x1 = pointer passed in from caller`
- `x2 = string object` (`ctx + 0x70` in the `0x128150` call path)
- `x3 = callback slot` (`[ctx + 0x3a8]`)

It then builds a composite message from a mix of shared/global runtime state and the current context:

- reads and resets `[shared + 0x468]`
- later reuses `[shared + 0x388]`
- later reuses `[shared + 0x304]`
- appends a fixed `"-"` separator
- formats a final tail using `0x31b73c` (`"%d%s%s"`)
- emits the result through `0x8db90`

The callback emission site is exact:

- `0x129404: mov w0, #0x64`
- `0x129408: add x1, sp, #0x90`
- `0x12940c: mov w2, #1`
- `0x129410: mov x3, x22`
- `0x129414: bl 0x8db90`

So the reduced conclusion is:

- `0x17d62c` / `0x17ea60` explain the **classification value** (`5`)
- `0x12cfd0` explains the **init-time message/config tag ingestion** (`DMSG` and related keys)
- the best current candidate for the **live details-string feeder** is the runtime formatter path centered on `0x12aa40` and `0x128f30`, driven by `ctx->0x388` and `ctx->0x304`

### Practical implication

The native block feeding the visible `kMyself` details string is now more likely to be:

1. a writer into `ctx->0x388`, or
2. the shared transient text source in `[shared + 0x468]`

than the classifier block `0x17d62c` itself.

Current known writers worth reducing next:

- `0x82d78` -> write to `[... + 0x388]`
- `0x130678` -> write to `[... + 0x388]`
- `0x18c85c` -> write to `[... + 0x388]`
- `0x1f899c` -> write to `[... + 0x388]`
- `0x20b0b4` / `0x20e31c` -> write to `[... + 0x468]`

## Reduction of the live string writers

The next reduction step shows that the writer blocks themselves do **not** synthesize `kMyself`.

### `0x18c85c`: `ctx->0x388` is loaded from a cursor stream

The block around `0x18c830` is a generic "pop one 8-byte entry from stream" case:

- check remaining count at `[x20 + 0x18]`
- if needed, decrement by 8
- read the current slot from `[x20]`
- advance the cursor with `str x9, [x20]`
- load the pointed 8-byte value with `ldr x8, [x8]`
- store it to the runtime context with:
  - `0x18c85c: str x8, [x19 + 0x388]`

This is the same decoding pattern used for many sibling fields in the same dispatcher:

- `0x18bfe4` -> `[ctx + 0x278]`
- `0x18c46c` -> `[ctx + 0x298]`
- `0x18c020` -> `[ctx + 0x378]`
- `0x18c0fc` -> `[ctx + 0xb50]`
- many others nearby

So `0x18c85c` is only a **field assignment from a pre-existing parsed stream**, not the string origin.

### `0x20b0b4` / `0x20e31c`: `0x468` is a clone-and-swap slot

These two blocks are also not the origin. They perform:

1. refresh a handle object with `0x1e03c4`
2. release the previous object in `0x468` with `0x227368`
3. deep-clone an existing heap object with `0x2272a8`
4. store the clone back into `0x468`

The exact pattern:

- `0x20b094: bl 0x1e03c4`
- `0x20b0a0: bl 0x227368`
- `0x20b0b0: bl 0x2272a8`
- `0x20b0b4: str x0, [x19 + 0x468]`

and similarly:

- `0x20e2f8: bl 0x1e03c4`
- `0x20e308: bl 0x227368`
- `0x20e318: bl 0x2272a8`
- `0x20e31c: str x0, [x19 + 0x468]`

Helper roles:

- `0x227368` is a virtual-release / destroy helper for a heap object
- `0x2272a8` allocates a new wrapper and clones the source object via its vtable callback at `[src->vtable + 0x10]`
- `0x1e03c4` refreshes a handle-like object in-place: free old, allocate new, optionally bind source data

So `0x468` is a **transient owned copy** of some already-existing object. It is not where the string is composed.

### First real upstream source for the `0x468` path

The actual source enters one layer earlier at `0x20b33c`:

- `0x20b340: ldr x0, [ctx + 0x510]`
- `0x20b35c: bl 0x1d6da0`
- then store outputs into the runtime subobject at `[ctx->a8 + ...]`:
  - `0x20b36c: str x8, [obj + 0x278]`
  - `0x20b370: str x0, [obj + 0x280]`
  - `0x20b378: str x8, [obj + 0x298]`

That is the first concrete point where the live backing data for the later `0x468` clone path enters the object.

`0x1d6da0` itself is a typed parser/selector:

- starts from `x0`
- immediately loads a descriptor at `[x0 + 0x1f0]`
- switches on `[*descriptor + 0x24]`
- fills multiple outputs through its pointer arguments

Observed callers:

- `0x206534`
- `0x20b35c`
- `0x20e7ac`

So the `0x468` string source is no longer a mystery writer block; it is downstream of `0x1d6da0` parsing a descriptor under `[ctx + 0x510]`.

### Current best interpretation of string origin

At this point the best reduced model is:

1. `0x1d6da0` parses a typed payload/descriptor from `[ctx + 0x510]`
2. it fills the live object backing fields:
   - `0x278`
   - `0x280`
   - `0x298`
3. later blocks like `0x20b0b4` / `0x20e31c` clone from those parsed backing objects into transient owned slots like `0x468`
4. the formatter path around `0x12aa40` / `0x128f30` consumes:
   - `ctx->0x388`
   - `ctx->0x304`
   - transient shared text in `0x468`

So the likely `kMyself` origin has moved one more step upstream:

- not the `0x468` clone sites
- not the `0x388` assignment itself
- but the typed payload parser rooted at `0x1d6da0` and the decoded cursor/descriptor state it populates

### Next reduction targets

The highest-value next passive targets are now:

- `0x1d6da0` case arms for the descriptor type at `[desc + 0x24]`
- the producer of `[ctx + 0x510]`
- the specific case that populates the object later stored at `[obj + 0x298]`

## Reduction of `0x1d6da0` and `ctx->0x510`

The next reduction step changes the answer in one important way:

- the `0x1d6da0` switch does **not** directly fill the value later stored at `obj + 0x298`
- `obj + 0x298` is populated by the separate `x5` output path, which runs **before** the descriptor switch

### `0x1d6da0` output split

At entry:

- `x20 = out1`
- `x19 = out2`
- `x23 = out3`
- `x24 = out4`
- `x25 = out5`
- `x27 = [ctx510 + 0x1f0]` descriptor

The `x25` path is handled first, before any `switch(desc->type)` logic:

- `0x1d6de4: cbz x5, ...`
- `0x1d6e00: str xzr, [x25]`
- `0x1d6e04: ldr w8, [ctx510 + 0x1e8]`
- `0x1d6e14: bl 0x28d358`
- `0x1d6e2c: bl 0x28d768`
- `0x1d6e30: str x0, [x25]`

The two helper calls are now reduced enough to characterize:

- `0x28d358`
  - takes a counted object plus a key pointer/value
  - returns an integer index
  - either by binary-search-like helper logic when metadata is present, or by linear scan fallback
- `0x28d768`
  - takes a counted array object and an index
  - returns `array[index]` if the index is in range, else `0`

So the fifth output is looked up from the `ctx510 + 0x1e8` field through a straightforward:

- key -> index (`0x28d358`)
- index -> object pointer (`0x28d768`)

path, not through the descriptor switch.

Only after that does the function dispatch on:

- `0x1d6e48: ldr w8, [desc + 0x24]`

and select table-driven outputs for the other result slots.

### What the `0x1d6da0` switch actually fills

The main descriptor switch maps `[desc + 0x24]` to an internal index, then uses table lookups rooted at:

- `0x3c8000 + 0xa28`, accessed via:
  - `0x1d6ff8: [table + 0xe0]` -> stored to `*out1`
  - `0x1d7068: [table + 0x20]` -> stored to `*out2`
  - `0x1d7090: [table + 0x80]` -> stored to `*out4`
- plus a code table at:
  - `0x3c3000 + 0x3ac`, stored to `*out3`

So the switch is still important, but it feeds:

- `obj + 0x278`
- `obj + 0x280`
- optionally `obj + 0x288`
- optionally `obj + 0x290`

It does **not** explain `obj + 0x298`.

### Consequence for the `0x20b35c` call site

The `0x20b35c` caller passes:

- `x1 = sp + 0x10`
- `x2 = sp + 0x8`
- `x3 = 0`
- `x4 = 0`
- `x5 = sp`
- `w6 = 0`

and after return stores:

- `[sp + 0x10]` -> `obj + 0x278`
- `[sp + 0x8]` -> `obj + 0x280`
- `[sp]` -> `obj + 0x298`

Therefore:

- `obj + 0x298` is exactly the pre-switch `x5` lookup result
- it is **not** chosen by any `desc->type` case arm

That means the live `kMyself` candidate at `obj + 0x298` is now best explained as:

- a resource/object lookup keyed by `ctx510->0x1e8`
- not by the `0x1d6da0` descriptor switch tables

### Producer and updater of `ctx->0x510`

`ctx->0x510` is a swappable `0x280`-byte state object.

Stable clone/update chain:

- `0x1e4138`
  - allocates `0x280` bytes
  - copies the old object
  - clones/retains nested members
  - this is the real object constructor/clone

Replacement/update path:

- `0x1fd0c8: ldr x0, [ctx + 0x510]`
- `0x1fd0d0: bl 0x1e4138`
  - clone the current `0x510` object
- `0x1fd0dc: ldr x0, [ctx + 0x510]`
- `0x1fd0e0: bl 0x1e4364`
  - release the old object
- `0x1fd0e4: str x23, [ctx + 0x510]`
  - install the new object
- `0x1fd0f0: bl 0x1e44b8`
  - validate/configure the new object after swap

Temporary override path:

- `0x1f6b40: ldr x27, [ctx + 0x510]`
- `0x1f6b68: str x8, [ctx + 0x510]`
- later restored by:
  - `0x1f6ba8: str x27, [ctx + 0x510]`

So the `0x510` object is not a one-off parser scratch buffer. It is a persistent live state object that is cloned, swapped, validated, and temporarily overridden.

### `0x1e44b8` does not explain `obj + 0x298`

The post-swap validator at `0x1e44b8` was the last remaining possibility for a hidden string-selection side path, but the reduction does not support that:

- it keys off `[ctx510 + 0]` values around:
  - `0x300..0x306`
  - `0xfefd..0xfeff`
  - `0x100`
- it sizes a scratch/output buffer at:
  - `[out + 0x150]`
  - `[out + 0x158]`
- it picks a callback from:
  - `[ctx + 0x530]`, else `[ctx + 0x770] + 0x198`
- and calls that callback with:
  - `x0 = ctx`
  - `x1 = out + 0x158`
  - `x2 = &len`

What it does **not** do is read or derive `ctx510->0x1e8`.

So `0x1e44b8` sits alongside the `0x1e8` path as configuration/validation, but it does not explain the `obj + 0x298` object that later carries the details string.

### The stronger `kMyself` lead: `ctx510->0x1e8`

The resource-key field used by the `x5` lookup is `ctx510->0x1e8`.

Observed writers:

- `0x18c650: str x8, [ctx510 + 0x1e8]`
  - this is the dynamic stream-fed assignment inside the large decoder
- `0x1d47c4: str x11, [obj + 0x1e8]`
  - default/template seed during object setup
- `0x1d4cdc: str x8, [dst + 0x1e8]`
  - copy during object clone

Additional runtime mutator:

- `0x20c640: str w8, [ctx510 + 0x1e8]`
  - this is not a template/clone write
  - it runs after an import/unpack path rooted at `0x20c2bc`
  - the value comes from `[x21 + 0x10]`
  - if that side object is present and has type `1`, the code loads:
    - `0x20c638: ldr x8, [x8 + 0x8]`
    - `0x20c63c: ldrb w8, [x8]`
    - `0x20c640: str w8, [x20 + 0x1e8]`
  - otherwise it stores `0`

So `ctx510->0x1e8` can be overwritten late by a separate importer path, not just by the original decoder at `0x18c650`.

That means the likely hidden-string origin is now:

1. some dynamic feed that sets or rewrites `ctx510->0x1e8`
2. `0x1d6da0` pre-switch lookup resolving that key into the `x5` object via `0x28d358 -> 0x28d768`
3. caller storing that resolved object into `obj + 0x298`

### Practical reduction result

The answer to “which `0x1d6da0` case fills `obj + 0x298`?” is now:

- none of the descriptor case arms do
- `obj + 0x298` comes from the separate pre-switch `ctx510->0x1e8` lookup

So the right next passive targets are no longer the switch table itself. They are:

- the dynamic writer to `ctx510->0x1e8` at `0x18c650`
- the late importer/mutator at `0x20c640` and its source object at `[x21 + 0x10]`
- the upstream source feeding that dynamic writer's cursor/stream
- the table/root object behind the `0x28d358 -> 0x28d768` key-to-object lookup

## Reduction of the late importer feeding `0x20c640`

The post-clone write at `0x20c640` turned out to have two distinct call paths, and only one of them is a plausible origin for a new selector value.

### `0x1fd368` is only a round-trip of the current `ctx->0x510`

The caller at `0x1fd368` does:

- `0x1fd2f4: bl 0x20bfe4`
  - query/measure the current `ctx->0x510`
- allocate a buffer of that size
- `0x1fd350: bl 0x20bfe4`
  - serialize the current `ctx->0x510` into that buffer
- `0x1fd368: bl 0x20c2bc`
  - deserialize/import that same buffer back into a fresh object

So this path is a **self round-trip** of the already-existing `ctx->0x510` state. It can preserve or normalize the selector, but it cannot be the original source of a new `kMyself` selector.

### `0x202c34` is the real fresh importer

The second caller is the one that matters:

- `0x202bd4: bl 0x24eb68`
  - parse/build a fresh variable-length buffer in `x25`
- `0x202c0c: bl 0x24f1cc`
  - compute/validate a sub-slice within that fresh buffer
- `0x202c34: bl 0x20c2bc`
  - import that sub-slice into the typed object consumed by `0x20c640`

This is the first path in the current reduction that clearly introduces **new imported content** instead of round-tripping existing `ctx->0x510` state.

### What `0x20c2bc` actually does with that imported record

At entry:

- source object pointer is passed indirectly on the stack
- `0x20c2cc: ldr x8, [x1]`
- `0x20c2ec: bl 0x214a7c`

`0x214a7c` is a generic typed extractor. It does not build the object itself; it asks `0x214b50` to extract a typed view and returns the result pointer as `x21`.

Then `0x20c2bc` imports fields from `x21` into the new `ctx->0x510` object:

- `x21 + 0x18` -> copied into `ctx510 + 0x50`
- `x21 + 0x20` -> copied into `ctx510 + 0x158`
- `x21 + 0x30` -> `ctx510 + 0x1e0`
- `x21 + 0x38` -> `ctx510 + 0x1d8`
- `x21 + 0x48` -> copied into `ctx510 + 0x180`
- `x21 + 0x50` -> `ctx510 + 0x1c8`
- `x21 + 0x58` -> string/object into `ctx510 + 0x218`
- `x21 + 0x78` -> string/object into `ctx510 + 0x1a0`
- `x21 + 0x80` -> string/object into `ctx510 + 0x1a8`
- `x21 + 0x88` -> string/object into `ctx510 + 0x258`

The selector-relevant field is:

- `x21 + 0x10`

If that side field is present and has type `1`, then:

- `0x20c638: ldr x8, [x8, #0x8]`
- `0x20c63c: ldrb w8, [x8]`
- `0x20c640: str w8, [x20, #0x1e8]`

So the late selector is exactly the **first byte of a type-1 imported field at `x21 + 0x10`**.

### Practical consequence

The `kMyself` selector source is now best explained as:

1. a fresh imported record enters through the `0x202bd4 -> 0x202c34` path
2. `0x214a7c / 0x214b50` extract a typed object view from that imported sub-buffer
3. the object field at `x21 + 0x10` supplies a one-byte selector
4. `0x20c640` writes that byte into `ctx510->0x1e8`
5. `0x1d6da0` later resolves that key into the object stored at `obj + 0x298`

So the current best passive source for the selector behind `kMyself` is **not** the old decoder arm at `0x18c650`. It is the imported typed record feeding `x21 + 0x10` on the `0x202c34` path.

## Schema behind `0x214a7c / 0x214b50`

The descriptor passed into `0x214a7c` from the live importer path is not anonymous after relocation reduction. The `.data.rel.ro` object at `0x3947e0` resolves to an `SSL_SESSION_ASN1` schema.

Resolved relocation/name targets from that descriptor include:

- `SSL_SESSION_ASN1`
- `version`
- `ssl_version`
- `cipher`
- `session_id`
- `master_key`
- `key_arg`
- `time`
- `timeout`
- `peer`
- `session_id_context`
- `verify_result`
- `tlsext_hostname`
- `psk_identity_hint`
- `psk_identity`
- `tlsext_tick_lifetime_hint`
- `tlsext_tick`
- `comp_id`
- `srp_username`

So the `0x202c34 -> 0x20c2bc -> 0x214a7c` path is importing a typed SSL session record, not a free-form anti-tamper message object.

### What `x21 + 0x10` most likely represents

The imported object layout observed in `0x20c2bc` lines up with the beginning of that `SSL_SESSION_ASN1` schema:

- `x21 + 0x4`
  - scalar field consistent with `version`
- `x21 + 0x8`
  - nested short byte object, used to rebuild a two-byte value at `ctx510 + 0x1f8`
  - consistent with `ssl_version`
- `x21 + 0x10`
  - next imported field in order
  - handled as a small type-1 object whose first payload byte is copied to `ctx510 + 0x1e8`
  - most likely corresponds to `cipher`
- `x21 + 0x18`
  - length-prefixed blob, consistent with `session_id`
- `x21 + 0x20`
  - length-prefixed blob capped at `0x20`, consistent with `master_key`
- `x21 + 0x30`
  - scalar time-like field
- `x21 + 0x38`
  - scalar timeout-like field
- later fields match the rest of the SSL session schema (`peer`, `session_id_context`, `verify_result`, `tlsext_hostname`, `psk_identity*`, `srp_username`)

So the best current interpretation is:

- `x21 + 0x10` is not a `kMyself` text fragment
- it is the imported SSL session `cipher` field, or at least a cipher-related small encoded field immediately following `version` and `ssl_version`
- `0x20c640` copies only its first byte into `ctx510->0x1e8`

### Consequence for the `kMyself` hunt

This is the strongest sign so far that the `0x202c34 -> 0x20c640` path is part of TLS session/protocol classification rather than the origin of the visible `[kMyself]` details string.

That also matches the earlier dynamic observations where downstream objects carried:

- `TLSv1`
- `TLSv1.1`
- `TLSv1.2`
- `TLSv1.3`
- certificate/provider strings from Android/BC

So this importer path is now better understood as:

- SSL/TLS session metadata import
- followed by lookup/classification

rather than the direct source of the anti-tamper detail text.

## Open items

1. Whether `0x17d62c` is the exact final source of the `5` that reaches `0x13f9d0`, or only one upstream producer of that class
2. Whether the `cipher`-like byte copied from the `SSL_SESSION_ASN1` import into `ctx510->0x1e8` is only a TLS classifier input, or whether it also gates some later detail-string selection indirectly
3. Which path, if any, still feeds the actual visible `[kMyself]` detail text rather than TLS/session metadata
4. Whether the visible prefix `Security Alert(code : 5)` is built by native code directly or loaded from packed config before callback dispatch

## Final Summary

The passive end-to-end chain is now reduced enough to describe cleanly.

### End-to-end chain

1. App/engine initialization registers the native-to-Java detection callback path.
   Key addresses:
   - `0x1242b4` builds the native detection context and installs callback slots
   - `[ctx + 0x3a8] = 0x13f9d0` native `DetectCallBack(int, String, boolean)` bridge
   - `[ctx + 0x3b0] = 0x13fb8c` adjacent Java callback helper
   - `0x14173c` is the Java bridge stage that reaches `NmssSa.DetectCallBack(...)`

2. Native detection logic produces the numeric classification before Java sees anything.
   Key addresses:
   - `0x128150` is the central native detection/report subtree
   - `0x17d62c` has the strongest reduced early `return 5` path found so far
   - `0x17ea60` immediately checks that result, special-cases `0` and `5`, and propagates `5`

3. The visible alert text is already decided on the native side.
   Java does not build the message body.
   Java side:
   - `NmssSa.DetectCallBack(int, String, boolean)` decides whether to surface the alert
   - `NmssSa.AlertMsg(int, String, boolean)` only stores:
     - `m_nCode = code`
     - `m_strMsg = details`
     - `m_bAppExit = exitFlag`
   - the dialog uses `m_strMsg` directly
   - if `m_bAppExit` is true, the OK handler finishes the activity and kills the process

4. The best native message/detail formatting corridor remains the runtime formatter path around:
   - `0x12b1fc -> 0x12aa40`
   - `0x12b214 -> 0x128f30`
   These blocks consume live context/state fields such as:
   - `ctx + 0x388`
   - `ctx + 0x304`
   - shared/transient text slot `0x468`

5. The obvious field writers are not the real string origin.
   Reduced non-origin writers:
   - `0x18c85c` writes `ctx + 0x388` from an already-decoded cursor stream
   - `0x20b0b4` and `0x20e31c` clone/swap the transient `0x468` object slot

6. The object later associated with the message path is populated through `0x1d6da0`, but not by its descriptor switch.
   Key addresses:
   - `0x20b33c` calls `0x1d6da0`
   - `0x20b36c` stores results into `obj + 0x278`, `obj + 0x280`, and `obj + 0x298`
   - `0x1d6da0` loads descriptor `[ctx510 + 0x1f0]`
   - `obj + 0x298` comes from the pre-switch `x5` path, not from any `desc->type` case arm
   - pre-switch path:
     - `0x1d6e04` loads `ctx510 + 0x1e8`
     - `0x1d6e18` calls `0x28d358` (key -> index lookup)
     - `0x1d6e2c` calls `0x28d768` (index -> object fetch)
     - `0x1d6e30` stores the resolved object to `*x25`

7. `ctx + 0x510` is a persistent live state object, not scratch parser state.
   Key addresses:
   - `0x1e4138` clones/builds the `0x280`-byte `ctx + 0x510` object
   - `0x1fd0e4` swaps the new object into `[ctx + 0x510]`
   - `0x1fd0f0` calls `0x1e44b8` to validate/configure it
   - `0x1e44b8` does not explain the message selector; it is a sibling config/validation path

8. The lookup key at `ctx510 + 0x1e8` is touched by more than one path.
   Key addresses:
   - `0x18c650` writes `ctx510 + 0x1e8` from a decoder stream
   - `0x20c640` later rewrites `ctx510 + 0x1e8` from an imported object field

9. That later importer path is now understood and is not the direct `kMyself` origin.
   Key addresses:
   - `0x202bd4 -> 0x202c34` builds/parses a fresh sub-buffer
   - `0x20c2bc` imports that sub-buffer into a typed object
   - `0x214a7c / 0x214b50` decode the schema behind that imported object
   - the schema resolves to `SSL_SESSION_ASN1`
   - named fields include:
     - `version`
     - `ssl_version`
     - `cipher`
     - `session_id`
     - `master_key`
     - `time`
     - `timeout`
     - `peer`
     - `verify_result`
     - `tlsext_hostname`
     - `psk_identity_hint`
     - `psk_identity`
     - `srp_username`
   - `0x20c638/0x20c63c/0x20c640` copy the first byte of imported field `x21 + 0x10` into `ctx510 + 0x1e8`
   - that field most likely corresponds to `cipher`, so this branch is best classified as TLS/session metadata import and classification, not the direct source of `[kMyself]`

10. Current conclusion.
    - `code 5` is a native classification result computed before Java callback dispatch
    - `[kMyself]` is already present in the native `details` payload before Java
    - Java only transports and displays it
    - the `SSL_SESSION_ASN1` importer branch is not the direct source of the visible detail text
    - the best remaining native source for the actual `[kMyself]` message content is still the formatter/report path around:
      - `0x12aa40`
      - `0x128f30`

### Key address list

- `0x1242b4` context builder / callback slot install
- `0x128150` native detection/report subtree
- `0x128f30` native formatter/report helper
- `0x12aa40` native formatter/report helper
- `0x13f9d0` native `DetectCallBack` bridge
- `0x13fb8c` adjacent Java callback helper
- `0x14173c` Java bridge stage
- `0x17d62c` strongest reduced `code 5` producer
- `0x17ea60` `code 5` propagation / special-case handling
- `0x18c650` early dynamic write to `ctx510 + 0x1e8`
- `0x18c85c` stream-fed write to `ctx + 0x388`
- `0x1d6da0` typed parser/selector for `ctx + 0x510`
- `0x1e4138` clone/build `ctx + 0x510`
- `0x1e44b8` post-swap validator/configurator
- `0x1fd0e4` install new `ctx + 0x510`
- `0x20b0b4` clone/swap transient `0x468`
- `0x20b33c` caller that fills `obj + 0x278/0x280/0x298`
- `0x20c2bc` importer of typed sub-records
- `0x20c640` late write to `ctx510 + 0x1e8`
- `0x20e31c` clone/swap transient `0x468`
- `0x202c34` fresh importer path
- `0x214a7c` typed extractor wrapper
- `0x214b50` schema-driven decoder
- `0x28d358` key -> index lookup
- `0x28d768` index -> object fetch
