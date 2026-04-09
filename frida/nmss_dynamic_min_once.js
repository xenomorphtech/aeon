'use strict';

(function () {
    var READY_CHALLENGE = '6BA4D60738580083';
    var TARGET_CHALLENGE = READY_CHALLENGE;
    var DYNAMIC_LIB = '/data/local/tmp/libaeon_instrument.so';
    var RESULT_PATH = '/data/user/0/com.netmarble.thered/files/nmss_dynamic_min_once.json';
    var ART_HOOK_LOG_PATH = '/data/user/0/com.netmarble.thered/files/nmss_dynamic_min_art_hooks.log';
    var ENABLE_ART_DIAG_HOOKS = false;
    var ENABLE_BLOCK_TRACE_STUB = true;
    var STOP_AFTER_FIRST_RUN = true;
    var PREPARE_RETRY_MS = 1000;
    var PREPARE_MAX_WAIT_MS = 45000;
    var ACTIVE_EXEC_SIZE = 0x50000;
    var PAGE_SIZE = 0x1000;
    var TRACE_RING_ENTRY_SIZE = 32;
    var TRACE_MIN_RING_CAPACITY = 0x10000;
    var TRACE_MAX_RING_CAPACITY = 0x100000;
    var TRACE_COUNTER_SLOTS = 0x10000;
    var TRACE_CODE_PAGES = 1;
    var TRACE_STUB_HEX =
        'ea0300aa69030010290140f92b0d0a8b6cfd5fc88c0500916cfd0dc8adffff35' +
        'ce020010ce0140f9cffd5fc8f0050091d0fd0dc8adffff3551020010310240f9' +
        'f101118a21020010210040f92214118b481680d2010000d44a0400f9400800f9' +
        '010080d2410c00f94ffc9fc8c0035fd600000000000000000000000000000000' +
        '00000000000000000000000000000000';
    var TRACE_STUB_OFFSETS = {
        counters: 0x70,
        seq: 0x78,
        ringMask: 0x80,
        ringBase: 0x88,
        size: 0x90,
    };
    var PTR_MASK = ptr('0x00FFFFFFFFFFFFFF');
    var PAGE_MASK = ptr('0xFFFFFFFFFFFFF000');
    var AEON_SCRATCH_STAGE = 0x18;
    var AEON_SCRATCH_LAST_TARGET = 0x20;
    var AEON_SCRATCH_TAIL_MODE = 0x28;
    var AEON_SCRATCH_SAVED_X30 = 0x10;
    var AEON_SCRATCH_DBG_OUTGOING_X30 = 0x120;
    var AEON_SCRATCH_DBG_POST_CALL_X30 = 0x128;
    var AEON_SCRATCH_DBG_RESUME_TARGET = 0x130;
    var AEON_SCRATCH_DBG_CTX_PC = 0x138;

    var state = {
        currentBase: null,
        currentSize: 0,
        currentFile: null,
        activePage: null,
        passthroughPages: {},
        traceActive: false,
        traceThreadId: null,
        cachedTpidr: ptr(0),
        steppedTrapCounts: {},
        dynamic: {
            loaded: false,
            loadError: null,
            lastLoadStage: null,
            handle: null,
            libPath: null,
            sourceBase: 0,
            sourceSize: 0,
            maxSteps: 50000,
            runtime: null,
            exports: {},
            bridgeGlobals: {},
            nativeBranchTranslate: null,
            nativeBranchBridge: null,
            threadClaims: {},
            pendingThreads: {},
            runs: [],
            lastRun: null,
            resumeTrampoline: null,
            resumeBrkImm: 0,
            resumeBrkWord: 0,
            trace: null,
            sourceCache: {},
        },
        artHooks: {
            installed: false,
            hooks: {},
            events: [],
        },
        session: {
            preflight: null,
            range: null,
            load: null,
        },
        crashSaved: false,
    };

    var libc = Process.getModuleByName('libc.so');
    var openFn = new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int', 'int']);
    var readFn = new NativeFunction(libc.getExportByName('read'), 'int', ['int', 'pointer', 'int']);
    var writeFn = new NativeFunction(libc.getExportByName('write'), 'int', ['int', 'pointer', 'int']);
    var closeFn = new NativeFunction(libc.getExportByName('close'), 'int', ['int']);
    var mkdirFn = new NativeFunction(libc.getExportByName('mkdir'), 'int', ['pointer', 'int']);

    function emit(obj) {
        console.log(JSON.stringify(obj));
    }

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function threadKey(threadId) {
        return String(threadId);
    }

    function hasClaim(map, threadId) {
        if (threadId === null || threadId === undefined) return false;
        return Object.prototype.hasOwnProperty.call(map || {}, threadKey(threadId));
    }

    function getClaim(map, threadId) {
        if (threadId === null || threadId === undefined) return null;
        var key = threadKey(threadId);
        if (!map || !Object.prototype.hasOwnProperty.call(map, key)) return null;
        return map[key];
    }

    function ensureClaim(map, threadId, meta) {
        var key = threadKey(threadId);
        if (!map[key]) {
            map[key] = Object.assign({
                thread_id: threadId,
                claimed_at: (new Date()).toISOString(),
            }, meta || {});
        }
        return map[key];
    }

    function pushLimited(list, item, maxItems) {
        list.push(item);
        while (list.length > maxItems) list.shift();
    }

    function currentThreadIdMaybe() {
        try { return Process.getCurrentThreadId(); } catch (e) { return null; }
    }

    function u64Number(value) {
        if (value === null || value === undefined) return 0;
        try { return parseInt(ptr(value).toString(), 16); } catch (e) {}
        if (typeof value === 'number') return value;
        if (typeof value === 'string') {
            if (value.indexOf('0x') === 0 || value.indexOf('0X') === 0) return parseInt(value, 16);
            var n = parseInt(value, 10);
            return isNaN(n) ? 0 : n;
        }
        return 0;
    }

    function normalizeWordPtr(value) {
        if (value === null || value === undefined) return ptr(0);
        try { return ptr(value); } catch (e) {}
        if (typeof value === 'number') return ptr('0x' + value.toString(16));
        if (typeof value === 'string') {
            if (value.indexOf('0x') === 0 || value.indexOf('0X') === 0) return ptr(value);
            var n = parseInt(value, 10);
            if (!isNaN(n)) return ptr('0x' + n.toString(16));
        }
        return ptr(0);
    }

    function writeWordExact(addr, value) {
        ptr(addr).writePointer(normalizeWordPtr(value));
    }

    function readWordExact(addr) {
        return ptr(addr).readPointer();
    }

    function writeU64Num(addr, value) {
        var hi = Math.floor(value / 0x100000000);
        var lo = value >>> 0;
        ptr(addr).writeU64(uint64('0x' + hi.toString(16) + ('00000000' + lo.toString(16)).slice(-8)));
    }

    function readU64Num(addr) {
        return parseInt(ptr(addr).readU64().toString(), 10);
    }

    function hexToBytes(hex) {
        var clean = String(hex || '').replace(/^0x/i, '');
        if ((clean.length & 1) !== 0) clean = '0' + clean;
        var out = new Uint8Array(clean.length / 2);
        for (var i = 0; i < out.length; i++) {
            out[i] = parseInt(clean.substr(i * 2, 2), 16) & 0xff;
        }
        return out;
    }

    function alignUp(value, alignment) {
        if (alignment <= 0) return value;
        return Math.ceil(value / alignment) * alignment;
    }

    function nextPow2(value) {
        var n = 1;
        while (n < value) n <<= 1;
        return n;
    }

    function untagPtr(value) {
        try {
            return ptr(value).and(PTR_MASK);
        } catch (e) {
            return ptr(0);
        }
    }

    function pageBaseFor(value) {
        return untagPtr(value).and(PAGE_MASK);
    }

    function mkdirp(path) {
        mkdirFn(Memory.allocUtf8String(path), 0x1ff);
    }

    function writeTextFile(path, text) {
        var fd = openFn(Memory.allocUtf8String(path), 0x241, 0x1a4);
        if (fd < 0) return false;
        try {
            var buf = Memory.allocUtf8String(text);
            writeFn(fd, buf, text.length);
            return true;
        } finally {
            closeFn(fd);
        }
    }

    function appendTextFile(path, text) {
        var fd = openFn(Memory.allocUtf8String(path), 0x441, 0x1a4);
        if (fd < 0) return false;
        try {
            var buf = Memory.allocUtf8String(text);
            writeFn(fd, buf, text.length);
            return true;
        } finally {
            closeFn(fd);
        }
    }

    function saveResult(obj) {
        writeTextFile(RESULT_PATH, JSON.stringify(obj, null, 2));
    }

    function buildPartialResult(status) {
        return {
            pid: Process.id,
            status: status || 'partial',
            ready_challenge: READY_CHALLENGE,
            target_challenge: TARGET_CHALLENGE,
            dynamic_lib: DYNAMIC_LIB,
            stop_after_first_run: STOP_AFTER_FIRST_RUN,
            preflight: state.session.preflight,
            range: state.session.range,
            load: state.session.load,
            dynamic_last_run: state.dynamic.lastRun,
            dynamic_runs: state.dynamic.runs.slice(-8),
            coverage: dynamicTraceStatusSummary(128, 2048),
            art_hook_events: state.artHooks.events.slice(-64),
        };
    }

    function contextSnapshot(cpuCtx) {
        if (!cpuCtx) return null;
        var out = {
            pc: fmtPtr(cpuCtx.pc),
            sp: fmtPtr(cpuCtx.sp),
            fp: fmtPtr(cpuCtx.fp),
            lr: fmtPtr(cpuCtx.lr),
        };
        for (var i = 0; i <= 8; i++) {
            out['x' + i] = fmtPtr(cpuCtx['x' + i]);
        }
        out.x19 = fmtPtr(cpuCtx.x19);
        out.x20 = fmtPtr(cpuCtx.x20);
        out.x21 = fmtPtr(cpuCtx.x21);
        out.x22 = fmtPtr(cpuCtx.x22);
        out.x23 = fmtPtr(cpuCtx.x23);
        out.x24 = fmtPtr(cpuCtx.x24);
        out.x28 = fmtPtr(cpuCtx.x28);
        return out;
    }

    function saveCrashResult(status, details, threadId) {
        if (state.crashSaved) return;
        state.crashSaved = true;
        var result = buildPartialResult(status || 'crash');
        var crash = {
            thread_id: threadId === undefined ? null : threadId,
            type: details && details.type ? details.type : null,
            address: details && details.address ? fmtPtr(details.address) : null,
            memory_operation: details && details.memory ? details.memory.operation || null : null,
            memory_address: details && details.memory ? fmtPtr(details.memory.address) : null,
            context: contextSnapshot(details ? details.context : null),
        };
        if (state.dynamic.loaded) {
            try {
                crash.bridge_state = dynamicBridgeState(threadId);
            } catch (e) {
                crash.bridge_state_error = String(e);
            }
        }
        result.crash = crash;
        saveResult(result);
        emit({ type: 'crash_snapshot', data: crash });
    }

    function artHookThreadAllowed(threadId) {
        if (threadId === null || threadId === undefined) return false;
        if (state.traceThreadId !== null && state.traceThreadId !== undefined) {
            return threadId === state.traceThreadId;
        }
        return false;
    }

    function logArtHook(label, fields) {
        var event = Object.assign({
            ts: (new Date()).toISOString(),
            label: label,
        }, fields || {});
        pushLimited(state.artHooks.events, event, 256);
        emit({ type: 'art_hook', data: event });
        appendTextFile(ART_HOOK_LOG_PATH, JSON.stringify(event) + '\n');
    }

    function installArtHooks() {
        if (!ENABLE_ART_DIAG_HOOKS) return false;
        if (state.artHooks.installed) return true;
        var libart = null;
        try {
            libart = Process.findModuleByName('libart.so');
        } catch (e) {
            return false;
        }
        if (!libart) return false;

        function addHook(name, offset, handlers) {
            var addr = libart.base.add(offset);
            state.artHooks.hooks[name] = Interceptor.attach(addr, {
                onEnter: function (args) {
                    var tid = currentThreadIdMaybe();
                    this.__nmss_tid = tid;
                    if (!artHookThreadAllowed(tid)) return;
                    if (handlers.onEnter) handlers.onEnter.call(this, args, tid, addr);
                },
                onLeave: function (retval) {
                    var tid = this.__nmss_tid;
                    if (!artHookThreadAllowed(tid)) return;
                    if (handlers.onLeave) handlers.onLeave.call(this, retval, tid, addr);
                }
            });
        }

        addHook('art_quick_update_inline_cache', 0x224bf0, {
            onEnter: function (args, tid, addr) {
                this.__entry_lr = normalizeWordPtr(this.context.lr);
                logArtHook('art_quick_update_inline_cache.enter', {
                    thread_id: tid,
                    pc: fmtPtr(addr),
                    lr: fmtPtr(this.context.lr),
                    sp: fmtPtr(this.context.sp),
                    x0: fmtPtr(this.context.x0),
                    x8: fmtPtr(this.context.x8),
                    x19: fmtPtr(this.context.x19),
                    x20: fmtPtr(this.context.x20),
                });
            },
            onLeave: function (retval, tid, addr) {
                var entryLr = this.__entry_lr;
                var retrapped = false;
                if (entryLr && !entryLr.isNull() && isInsideTrappedJit(entryLr)) {
                    retrapped = retrapPage(pageBaseFor(entryLr));
                }
                logArtHook('art_quick_update_inline_cache.leave', {
                    thread_id: tid,
                    pc: fmtPtr(addr),
                    lr: fmtPtr(this.context.lr),
                    entry_lr: fmtPtr(entryLr),
                    sp: fmtPtr(this.context.sp),
                    x0: fmtPtr(this.context.x0),
                    x8: fmtPtr(this.context.x8),
                    x19: fmtPtr(this.context.x19),
                    x20: fmtPtr(this.context.x20),
                    retrapped_return_page: retrapped,
                });
            }
        });

        addHook('art_quick_test_suspend', 0x221c80, {
            onEnter: function (args, tid, addr) {
                logArtHook('art_quick_test_suspend.enter', {
                    thread_id: tid,
                    pc: fmtPtr(addr),
                    lr: fmtPtr(this.context.lr),
                    sp: fmtPtr(this.context.sp),
                    x19: fmtPtr(this.context.x19),
                    x20: fmtPtr(this.context.x20),
                    x30: fmtPtr(this.context.lr),
                });
            }
        });

        addHook('RunCheckpointFunction', 0x6770bc, {
            onEnter: function (args, tid, addr) {
                logArtHook('RunCheckpointFunction.enter', {
                    thread_id: tid,
                    pc: fmtPtr(addr),
                    lr: fmtPtr(this.context.lr),
                    sp: fmtPtr(this.context.sp),
                    x0: fmtPtr(this.context.x0),
                    x19: fmtPtr(this.context.x19),
                });
            }
        });

        addHook('MarkCodeClosure::Run', 0x41b084, {
            onEnter: function (args, tid, addr) {
                logArtHook('MarkCodeClosure.Run.enter', {
                    thread_id: tid,
                    pc: fmtPtr(addr),
                    lr: fmtPtr(this.context.lr),
                    sp: fmtPtr(this.context.sp),
                    x0: fmtPtr(this.context.x0),
                    x19: fmtPtr(this.context.x19),
                });
            }
        });

        addHook('GetOatQuickMethodHeader', 0x2847e0, {
            onEnter: function (args, tid, addr) {
                logArtHook('GetOatQuickMethodHeader.enter', {
                    thread_id: tid,
                    pc: fmtPtr(addr),
                    lr: fmtPtr(this.context.lr),
                    sp: fmtPtr(this.context.sp),
                    x0: fmtPtr(this.context.x0),
                    x1: fmtPtr(this.context.x1),
                    x2: fmtPtr(this.context.x2),
                });
            }
        });

        addHook('FindOatMethodFor', 0x284c90, {
            onEnter: function (args, tid, addr) {
                logArtHook('FindOatMethodFor.enter', {
                    thread_id: tid,
                    pc: fmtPtr(addr),
                    lr: fmtPtr(this.context.lr),
                    sp: fmtPtr(this.context.sp),
                    x0: fmtPtr(this.context.x0),
                    x1: fmtPtr(this.context.x1),
                    x2: fmtPtr(this.context.x2),
                });
            }
        });

        state.artHooks.installed = true;
        return true;
    }

    function filePathFor(range) {
        try {
            return range && range.file && range.file.path ? String(range.file.path) : null;
        } catch (e) {
            return null;
        }
    }

    function enumerateExecRanges() {
        var out = [];
        var seen = {};
        ['r-x', '--x'].forEach(function (prot) {
            try {
                Process.enumerateRanges(prot).forEach(function (range) {
                    if ((range.protection || prot).indexOf('w') !== -1) return;
                    var key = range.base.toString() + ':' + range.size.toString();
                    if (seen[key]) return;
                    seen[key] = true;
                    out.push(range);
                });
            } catch (e) {}
        });
        return out;
    }

    function findExecRangeFor(addr) {
        var p = ptr(addr);
        var ranges = enumerateExecRanges();
        for (var i = 0; i < ranges.length; i++) {
            var r = ranges[i];
            if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) return r;
        }
        return null;
    }

    function isTrapCandidate(range) {
        var path = filePathFor(range) || '';
        if (path.indexOf('jit-cache') >= 0) return true;
        if (path.indexOf('/data/data/com.netmarble.thered/files/') >= 0 && path.indexOf('(deleted)') >= 0) return true;
        return false;
    }

    function scoreTrapCandidate(range) {
        var score = 0;
        var path = filePathFor(range) || '';
        if (path.indexOf('/memfd:jit-cache') >= 0) score += 1000;
        if (path.indexOf('/data/data/com.netmarble.thered/files/') >= 0) score += 500;
        if (path.indexOf('(deleted)') >= 0) score += 100;
        score += Math.min(range.size >>> 12, 0xffff);
        return score;
    }

    function chooseTrapRange() {
        var best = null;
        enumerateExecRanges().forEach(function (range) {
            if (!isTrapCandidate(range)) return;
            if (best === null || scoreTrapCandidate(range) > scoreTrapCandidate(best)) {
                best = range;
            }
        });
        return best;
    }

    function installForRange(range) {
        if (!range) throw new Error('no trap range');
        state.currentBase = range.base;
        state.currentSize = Math.min(range.size, ACTIVE_EXEC_SIZE);
        state.currentFile = filePathFor(range);
        state.activePage = null;
        state.passthroughPages = {};
        return {
            base: state.currentBase.toString(),
            size: state.currentSize,
            file: state.currentFile,
        };
    }

    function trackedPageKey(pageBase) {
        return pageBase ? pageBase.toString() : '0x0';
    }

    function restoreExecProtection() {
        if (!state.currentBase || !state.currentSize) return true;
        Memory.protect(state.currentBase, state.currentSize, 'r-x');
        state.activePage = null;
        state.passthroughPages = {};
        return true;
    }

    function ensureTrapProtection() {
        if (!state.currentBase || !state.currentSize) return false;
        Memory.protect(state.currentBase, state.currentSize, 'r--');
        state.activePage = null;
        state.passthroughPages = {};
        return true;
    }

    function activatePage(pageBase) {
        if (!pageBase || pageBase.isNull()) return false;
        if (state.activePage && !state.activePage.equals(pageBase)) {
            var previousKey = trackedPageKey(state.activePage);
            if (!state.passthroughPages[previousKey]) {
                Memory.protect(state.activePage, PAGE_SIZE, 'r--');
            }
        }
        Memory.protect(pageBase, PAGE_SIZE, 'r-x');
        state.activePage = pageBase;
        return true;
    }

    function allowPassthroughPage(pageBase) {
        if (!pageBase || pageBase.isNull()) return false;
        Memory.protect(pageBase, PAGE_SIZE, 'r-x');
        state.passthroughPages[trackedPageKey(pageBase)] = true;
        return true;
    }

    function retrapPage(pageBase) {
        if (!pageBase || pageBase.isNull()) return false;
        Memory.protect(pageBase, PAGE_SIZE, 'r--');
        delete state.passthroughPages[trackedPageKey(pageBase)];
        if (state.activePage && state.activePage.equals(pageBase)) {
            state.activePage = null;
        }
        return true;
    }

    function isInsideTrappedJit(addr) {
        if (!state.currentBase || !state.currentSize || addr === null || addr === undefined) return false;
        var p = untagPtr(addr);
        return p.compare(state.currentBase) >= 0 && p.compare(state.currentBase.add(state.currentSize)) < 0;
    }

    function isTargetTrapException(details) {
        if (!state.traceActive) return false;
        if (!details || details.type !== 'access-violation') return false;
        if (!details.memory || details.memory.operation !== 'execute') return false;
        if (details.memory.address && isInsideTrappedJit(details.memory.address)) return true;
        if (details.address && isInsideTrappedJit(details.address)) return true;
        if (details.context && isInsideTrappedJit(details.context.pc)) return true;
        return false;
    }

    function translatedFindGlobalExport(name) {
        if (typeof Module.getGlobalExportByName === 'function') {
            try { return Module.getGlobalExportByName(name); } catch (e) {}
        }
        try { return Module.findExportByName(null, name); } catch (e) {}
        return null;
    }

    function translatedGetLibdl() {
        if (translatedGetLibdl._cache) return translatedGetLibdl._cache;
        var dlopenPtr = translatedFindGlobalExport('dlopen');
        var dlsymPtr = translatedFindGlobalExport('dlsym');
        var dlerrorPtr = translatedFindGlobalExport('dlerror');
        if (!dlopenPtr || !dlsymPtr || !dlerrorPtr) {
            throw new Error('dlopen exports not found');
        }
        translatedGetLibdl._cache = {
            dlopen: new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']),
            dlsym: new NativeFunction(dlsymPtr, 'pointer', ['pointer', 'pointer']),
            dlerror: new NativeFunction(dlerrorPtr, 'pointer', []),
        };
        return translatedGetLibdl._cache;
    }

    function translatedResolveSymbol(handle, symbol) {
        var dl = translatedGetLibdl();
        var sym = dl.dlsym(handle, Memory.allocUtf8String(symbol));
        return sym && !sym.isNull() ? sym : null;
    }

    function dynamicTraceRingCapacity(counterSlots) {
        var target = Math.max(TRACE_MIN_RING_CAPACITY, counterSlots * 4);
        return Math.min(TRACE_MAX_RING_CAPACITY, nextPow2(target));
    }

    function dynamicResetTrace() {
        var trace = state.dynamic.trace;
        if (!trace || !trace.dataBase || trace.dataBase.isNull()) return false;
        trace.dataBase.writeByteArray(new Uint8Array(trace.dataSize));
        state.dynamic.sourceCache = {};
        return true;
    }

    function dynamicEnsureTrace() {
        if (state.dynamic.trace && state.dynamic.trace.dataBase && !state.dynamic.trace.dataBase.isNull()) return state.dynamic.trace;
        var counterSlots = TRACE_COUNTER_SLOTS;
        var ringCapacity = dynamicTraceRingCapacity(counterSlots);
        var ringBytes = ringCapacity * TRACE_RING_ENTRY_SIZE;
        var counterBytes = alignUp(counterSlots * 8, 8);
        var dataBytes = alignUp(counterBytes + 8 + ringBytes, PAGE_SIZE);
        var codeBytes = TRACE_CODE_PAGES * PAGE_SIZE;
        var slabSize = codeBytes + dataBytes;
        var slabBase = Memory.alloc(slabSize);
        slabBase.writeByteArray(new Uint8Array(slabSize));
        var codeBase = slabBase;
        var dataBase = slabBase.add(codeBytes);
        var countersBase = dataBase;
        var seqBase = countersBase.add(counterBytes);
        var ringBase = seqBase.add(8);
        Memory.protect(codeBase, codeBytes, 'rwx');
        Memory.protect(dataBase, dataBytes, 'rw-');
        Memory.patchCode(codeBase, TRACE_STUB_OFFSETS.size, function (code) {
            code.writeByteArray(hexToBytes(TRACE_STUB_HEX));
            writeWordExact(code.add(TRACE_STUB_OFFSETS.counters), countersBase);
            writeWordExact(code.add(TRACE_STUB_OFFSETS.seq), seqBase);
            writeWordExact(code.add(TRACE_STUB_OFFSETS.ringMask), ptr('0x' + (ringCapacity - 1).toString(16)));
            writeWordExact(code.add(TRACE_STUB_OFFSETS.ringBase), ringBase);
        });
        Memory.protect(codeBase, codeBytes, 'r-x');
        state.dynamic.trace = {
            slabBase: slabBase,
            slabSize: slabSize,
            codeBase: codeBase,
            codeSize: codeBytes,
            dataBase: dataBase,
            dataSize: dataBytes,
            stubBase: codeBase,
            countersBase: countersBase,
            counterSlots: counterSlots,
            seqBase: seqBase,
            ringBase: ringBase,
            ringCapacity: ringCapacity,
            ringMask: ringCapacity - 1,
            ringEntrySize: TRACE_RING_ENTRY_SIZE,
        };
        dynamicResetTrace();
        return state.dynamic.trace;
    }

    function translatedOffsetX(index) { return index * 8; }
    function translatedOffsetSp() { return 31 * 8; }
    function translatedOffsetPc() { return translatedOffsetSp() + 8; }
    function translatedOffsetFlags() { return translatedOffsetPc() + 8; }
    function translatedOffsetSimd() { return translatedOffsetFlags() + 8; }
    function translatedOffsetTpidr() { return translatedOffsetSimd() + (32 * 16); }

    function translatedJitContextSize() {
        return (31 * 8) + 8 + 8 + 8 + (32 * 16) + 8;
    }

    function readTpidrEl0() {
        if (readTpidrEl0._fn) return readTpidrEl0._fn();
        var code = Memory.alloc(Process.pageSize);
        code.writeU32(0xD53BD040);
        code.add(4).writeU32(0xD65F03C0);
        Memory.protect(code, Process.pageSize, 'r-x');
        readTpidrEl0._fn = new NativeFunction(code, 'pointer', []);
        return readTpidrEl0._fn();
    }

    function primeTpidrEl0() {
        try {
            state.cachedTpidr = readTpidrEl0();
        } catch (e) {
            state.cachedTpidr = ptr(0);
        }
        return state.cachedTpidr;
    }

    function translatedSeedContext(ctxPtr, cpuCtx) {
        for (var i = 0; i <= 28; i++) {
            writeWordExact(ctxPtr.add(translatedOffsetX(i)), cpuCtx['x' + i]);
        }
        writeWordExact(ctxPtr.add(translatedOffsetX(29)), cpuCtx.fp);
        writeWordExact(ctxPtr.add(translatedOffsetX(30)), cpuCtx.lr);
        writeWordExact(ctxPtr.add(translatedOffsetSp()), cpuCtx.sp);
        writeWordExact(ctxPtr.add(translatedOffsetPc()), cpuCtx.pc);
        writeU64Num(ctxPtr.add(translatedOffsetFlags()), cpuCtx.nzcv ? parseInt(String(cpuCtx.nzcv), 10) || 0 : 0);
        var simdBase = ctxPtr.add(translatedOffsetSimd());
        for (var q = 0; q <= 31; q++) {
            var dst = simdBase.add(q * 16);
            try {
                var qval = cpuCtx['q' + q];
                if (qval instanceof ArrayBuffer) {
                    dst.writeByteArray(new Uint8Array(qval));
                    continue;
                }
                if (qval && qval.buffer instanceof ArrayBuffer && qval.byteLength !== undefined) {
                    dst.writeByteArray(new Uint8Array(qval.buffer, qval.byteOffset || 0, Math.min(16, qval.byteLength)));
                    continue;
                }
            } catch (e) {}
            dst.writeByteArray(new Uint8Array(16));
        }
        var tpidr = state.cachedTpidr;
        if (!tpidr || tpidr.isNull()) {
            try {
                tpidr = readTpidrEl0();
                state.cachedTpidr = tpidr;
            } catch (e) {
                tpidr = ptr(0);
            }
        }
        writeWordExact(ctxPtr.add(translatedOffsetTpidr()), tpidr);
    }

    function translatedApplyContext(ctxPtr, cpuCtx, nextPc) {
        for (var i = 0; i <= 28; i++) {
            cpuCtx['x' + i] = readWordExact(ctxPtr.add(translatedOffsetX(i)));
        }
        cpuCtx.fp = readWordExact(ctxPtr.add(translatedOffsetX(29)));
        cpuCtx.lr = readWordExact(ctxPtr.add(translatedOffsetX(30)));
        cpuCtx.sp = readWordExact(ctxPtr.add(translatedOffsetSp()));
        cpuCtx.pc = normalizeWordPtr(nextPc);
        try { cpuCtx.nzcv = readU64Num(ctxPtr.add(translatedOffsetFlags())); } catch (e) {}
    }

    function dynamicResolveExport(handle, symbol, retType, argTypes) {
        var sym = translatedResolveSymbol(handle, symbol);
        if (!sym) throw new Error('missing dynamic export: ' + symbol);
        return new NativeFunction(sym, retType, argTypes);
    }

    function aarch64BrkWord(imm) {
        return (0xd4200000 | ((Number(imm) & 0xffff) << 5)) >>> 0;
    }

    function dynamicLoad(libPath) {
        var d = state.dynamic;
        d.lastLoadStage = 'resolve_libdl';
        var dl = translatedGetLibdl();
        d.lastLoadStage = 'dlopen';
        var handle = dl.dlopen(Memory.allocUtf8String(libPath), 2);
        if (handle.isNull()) {
            var errPtr = dl.dlerror();
            var errMsg = errPtr && !errPtr.isNull() ? (errPtr.readUtf8String() || '<null>') : '<unknown>';
            throw new Error('dlopen failed: ' + libPath + ' err=' + errMsg);
        }
        d.lastLoadStage = 'resolve_exports';
        d.exports = {
            create: dynamicResolveExport(handle, 'aeon_dyn_runtime_create', 'pointer', ['uint64', 'uint64']),
            destroy: dynamicResolveExport(handle, 'aeon_dyn_runtime_destroy', 'void', ['pointer']),
            setMaxSteps: dynamicResolveExport(handle, 'aeon_dyn_runtime_set_max_steps', 'void', ['pointer', 'uint64']),
            setCodeRange: dynamicResolveExport(handle, 'aeon_dyn_runtime_set_code_range', 'void', ['pointer', 'uint64', 'uint64']),
            clearCodeRange: dynamicResolveExport(handle, 'aeon_dyn_runtime_clear_code_range', 'void', ['pointer']),
            setMemRead: dynamicResolveExport(handle, 'aeon_dyn_runtime_set_memory_read_callback', 'void', ['pointer', 'pointer']),
            setMemWrite: dynamicResolveExport(handle, 'aeon_dyn_runtime_set_memory_write_callback', 'void', ['pointer', 'pointer']),
            setBranchTranslate: dynamicResolveExport(handle, 'aeon_dyn_runtime_set_branch_translate_callback', 'void', ['pointer', 'pointer']),
            setBranchBridge: dynamicResolveExport(handle, 'aeon_dyn_runtime_set_branch_bridge_callback', 'void', ['pointer', 'pointer']),
            setBlockEnter: dynamicResolveExport(handle, 'aeon_dyn_runtime_set_block_enter_callback', 'void', ['pointer', 'pointer']),
            compiledBlocks: dynamicResolveExport(handle, 'aeon_dyn_runtime_compiled_blocks', 'uint64', ['pointer']),
            lookupBlockSource: dynamicResolveExport(handle, 'aeon_dyn_runtime_lookup_block_source', 'uint64', ['pointer', 'uint64']),
            resultSize: dynamicResolveExport(handle, 'aeon_dyn_runtime_result_size', 'uint64', []),
            bridgeScratchSize: dynamicResolveExport(handle, 'aeon_dyn_runtime_bridge_scratch_size', 'uint64', []),
            resumeHandoffSize: dynamicResolveExport(handle, 'aeon_dyn_runtime_resume_handoff_size', 'uint64', []),
            resumeTrampolineBrkImm: dynamicResolveExport(handle, 'aeon_dyn_runtime_resume_trampoline_brk_imm', 'uint32', []),
        };
        d.nativeBranchTranslate = translatedResolveSymbol(handle, 'aeon_dyn_runtime_branch_translate');
        if (!d.nativeBranchTranslate || d.nativeBranchTranslate.isNull()) {
            throw new Error('missing dynamic export: aeon_dyn_runtime_branch_translate');
        }
        d.nativeBranchBridge = translatedResolveSymbol(handle, 'aeon_dyn_runtime_branch_bridge');
        if (!d.nativeBranchBridge || d.nativeBranchBridge.isNull()) {
            throw new Error('missing dynamic export: aeon_dyn_runtime_branch_bridge');
        }
        d.bridgeGlobals = {
            stage: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_stage'),
            lastTarget: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_last_target'),
            savedX30: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_saved_x30'),
            tailMode: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_tail_mode'),
            outgoingX30: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_outgoing_x30'),
            postCallX30: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_post_call_x30'),
            resumeTarget: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_resume_target'),
            ctxPc: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_ctx_pc'),
            ctx: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_ctx'),
            hostSp: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_host_sp'),
            codeStart: translatedResolveSymbol(handle, 'aeon_dyn_code_range_start'),
            codeEnd: translatedResolveSymbol(handle, 'aeon_dyn_code_range_end'),
        };
        d.resumeTrampoline = translatedResolveSymbol(handle, 'aeon_dyn_runtime_resume_trampoline');
        if (!d.resumeTrampoline || d.resumeTrampoline.isNull()) {
            throw new Error('missing dynamic export: aeon_dyn_runtime_resume_trampoline');
        }
        d.resumeBrkImm = Number(d.exports.resumeTrampolineBrkImm()) & 0xffff;
        d.resumeBrkWord = aarch64BrkWord(d.resumeBrkImm);
        d.libPath = libPath;
        d.handle = handle;
        d.loaded = true;
        d.loadError = null;
        d.lastLoadStage = 'done';
        dynamicEnsureTrace();
        return {
            loaded: true,
            lib_path: libPath,
            resume_trampoline: d.resumeTrampoline.toString(),
            resume_brk_imm: '0x' + d.resumeBrkImm.toString(16),
        };
    }

    function dynamicBridgeScratchSize() {
        var d = state.dynamic;
        if (d.exports && d.exports.bridgeScratchSize) {
            try { return u64Number(d.exports.bridgeScratchSize()); } catch (e) {}
        }
        return 0x140;
    }

    function dynamicResumeHandoffSize() {
        var d = state.dynamic;
        if (d.exports && d.exports.resumeHandoffSize) {
            try { return u64Number(d.exports.resumeHandoffSize()); } catch (e) {}
        }
        return 0x30;
    }

    function dynamicReadU64Symbol(sym) {
        if (!sym || sym.isNull()) return null;
        try { return readWordExact(sym).toString(); } catch (e) { return null; }
    }

    function dynamicBridgeScratchState(threadId) {
        var d = state.dynamic;
        if (threadId === null || threadId === undefined) return null;
        var pending = d.pendingThreads ? d.pendingThreads[String(threadId)] : null;
        if (!pending || !pending.ctxPtr || pending.ctxPtr.isNull()) return null;
        try {
            var scratchSize = dynamicBridgeScratchSize();
            var scratchBase = pending.ctxPtr.sub(scratchSize);
            return {
                scratch_base: scratchBase.toString(),
                thread_stage: readWordExact(scratchBase.add(AEON_SCRATCH_STAGE)).toString(),
                thread_last_target: readWordExact(scratchBase.add(AEON_SCRATCH_LAST_TARGET)).toString(),
                thread_tail_mode: readWordExact(scratchBase.add(AEON_SCRATCH_TAIL_MODE)).toString(),
                thread_saved_x30: readWordExact(scratchBase.add(AEON_SCRATCH_SAVED_X30)).toString(),
                thread_outgoing_x30: readWordExact(scratchBase.add(AEON_SCRATCH_DBG_OUTGOING_X30)).toString(),
                thread_post_call_x30: readWordExact(scratchBase.add(AEON_SCRATCH_DBG_POST_CALL_X30)).toString(),
                thread_resume_target: readWordExact(scratchBase.add(AEON_SCRATCH_DBG_RESUME_TARGET)).toString(),
                thread_ctx_pc: readWordExact(scratchBase.add(AEON_SCRATCH_DBG_CTX_PC)).toString(),
            };
        } catch (e) {
            return { scratch_error: String(e) };
        }
    }

    function dynamicBridgeState(threadId) {
        var d = state.dynamic;
        var g = d.bridgeGlobals || {};
        var out = {
            stage: dynamicReadU64Symbol(g.stage),
            last_target: dynamicReadU64Symbol(g.lastTarget),
            saved_x30: dynamicReadU64Symbol(g.savedX30),
            tail_mode: dynamicReadU64Symbol(g.tailMode),
            outgoing_x30: dynamicReadU64Symbol(g.outgoingX30),
            post_call_x30: dynamicReadU64Symbol(g.postCallX30),
            resume_target: dynamicReadU64Symbol(g.resumeTarget),
            ctx_pc: dynamicReadU64Symbol(g.ctxPc),
            ctx: dynamicReadU64Symbol(g.ctx),
            host_sp: dynamicReadU64Symbol(g.hostSp),
            code_start: dynamicReadU64Symbol(g.codeStart),
            code_end: dynamicReadU64Symbol(g.codeEnd),
        };
        var scratch = dynamicBridgeScratchState(threadId);
        if (scratch) {
            Object.keys(scratch).forEach(function (key) {
                out[key] = scratch[key];
            });
        }
        return out;
    }

    function dynamicPtrInCurrentCodeRange(value) {
        if (!value || !state.currentBase || !state.currentSize) return false;
        try {
            var p = normalizeWordPtr(value);
            if (p.isNull()) return false;
            var start = state.currentBase;
            var end = state.currentBase.add(state.currentSize);
            return p.compare(start) >= 0 && p.compare(end) < 0;
        } catch (e) {
            return false;
        }
    }

    function dynamicLooksCodeAligned(value) {
        if (value === null || value === undefined) return false;
        var s = String(value).toLowerCase();
        if (s === '0x0' || s === '0') return false;
        return /[048c]$/i.test(s);
    }

    function dynamicHasExecutableRange(value) {
        if (!value) return false;
        try {
            var p = normalizeWordPtr(value);
            if (p.isNull()) return false;
            var range = Process.findRangeByAddress(p);
            if (!range) return false;
            var prot = range.protection || range.prot || '';
            return prot.indexOf('x') !== -1;
        } catch (e) {
            return false;
        }
    }

    function dynamicIsNonCallableExternalTarget(value) {
        if (!value) return false;
        if (dynamicPtrInCurrentCodeRange(value)) return false;
        if (!dynamicLooksCodeAligned(value)) return true;
        return !dynamicHasExecutableRange(value);
    }

    function dynamicResolveBailResumePc(bridgeState) {
        if (!bridgeState) return null;
        var candidates = [
            bridgeState.thread_resume_target,
            bridgeState.resume_target,
            bridgeState.thread_ctx_pc,
            bridgeState.ctx_pc,
        ];
        for (var i = 0; i < candidates.length; i++) {
            var candidate = candidates[i];
            if (!candidate || candidate === '0x0') continue;
            if (dynamicPtrInCurrentCodeRange(candidate)) {
                return normalizeWordPtr(candidate);
            }
            if (dynamicHasExecutableRange(candidate)) {
                return normalizeWordPtr(candidate);
            }
        }
        return null;
    }

    function dynamicDisableClaim(threadId, reason, target, resumePc) {
        var claim = getClaim(state.dynamic.threadClaims, threadId);
        if (!claim) return;
        claim.disabled = true;
        claim.disabled_at = (new Date()).toISOString();
        claim.disabled_reason = reason || 'disabled';
        claim.disabled_target = target || null;
        claim.disabled_resume = resumePc ? fmtPtr(resumePc) : null;
    }

    function dynamicMaybeBailNonCallableExecute(details, threadId, bridgeState) {
        var d = state.dynamic;
        if (threadId === null || threadId === undefined) return false;
        var pending = d.pendingThreads[String(threadId)];
        if (!pending || !pending.ctxPtr || pending.ctxPtr.isNull()) return false;
        if (!bridgeState) return false;
        var target = bridgeState.thread_last_target || bridgeState.last_target;
        if (!target || !dynamicIsNonCallableExternalTarget(target)) return false;
        var resumePc = dynamicResolveBailResumePc(bridgeState);
        if (!resumePc || resumePc.isNull()) return false;
        translatedApplyContext(pending.ctxPtr, details.context, resumePc);
        delete d.pendingThreads[String(threadId)];
        dynamicDisableClaim(threadId, 'non-callable-target', target, resumePc);
        ensureTrapProtection();
        if (dynamicPtrInCurrentCodeRange(resumePc)) {
            activatePage(pageBaseFor(resumePc));
        }
        d.lastRun = {
            stop: 'non_callable_target',
            thread_id: threadId,
            target: target,
            resume_pc: fmtPtr(resumePc),
            bridge_ctx_pc: bridgeState.thread_ctx_pc || bridgeState.ctx_pc || null,
        };
        pushLimited(d.runs, d.lastRun, 32);
        return true;
    }

    function readU32Maybe(addr) {
        try { return ptr(addr).readU32(); } catch (e) { return null; }
    }

    function isAarch64BrkWord(word) {
        if (word === null || word === undefined) return false;
        return ((word >>> 0) & 0xffe0001f) === 0xd4200000;
    }

    function deletedAppModuleInfo(addr) {
        try {
            var p = normalizeWordPtr(addr);
            if (p.isNull()) return null;
            var range = Process.findRangeByAddress(p);
            if (!range) return null;
            var path = filePathFor(range) || '';
            if (path.indexOf('/data/data/com.netmarble.thered/files/') === -1) return null;
            if (path.indexOf('(deleted)') === -1) return null;
            return {
                path: path,
                base: range.base,
                offset: '0x' + u64Number(p.sub(range.base)).toString(16),
            };
        } catch (e) {
            return null;
        }
    }

    function maybeStepDeletedModuleTrap(details) {
        if (!details || !details.context) return false;
        if (details.type === 'access-violation') return false;
        var pc = normalizeWordPtr(details.context.pc);
        if (!pc || pc.isNull()) return false;
        var info = deletedAppModuleInfo(pc);
        if (!info) return false;
        var word = readU32Maybe(pc);
        if (!isAarch64BrkWord(word)) return false;
        var key = pc.toString();
        var count = state.steppedTrapCounts[key] || 0;
        if (count >= 8) return false;
        state.steppedTrapCounts[key] = count + 1;
        details.context.pc = pc.add(4);
        emit({
            type: 'stepped_deleted_brk',
            data: {
                pc: pc.toString(),
                word: '0x' + (word >>> 0).toString(16),
                count: state.steppedTrapCounts[key],
                module_path: info.path,
                module_offset: info.offset,
                thread_id: details.threadId === undefined ? null : details.threadId,
                trap_type: details.type || null,
            },
        });
        return true;
    }

    function dynamicEnsureRuntime(threadId) {
        var d = state.dynamic;
        var nullPtr = ptr(0);
        var claim = ensureClaim(d.threadClaims, threadId, {
            first_pc: null,
            runtime: null,
            sourceBase: 0,
            sourceSize: 0,
        });
        if (!d.loaded || !d.exports.create) throw new Error('dynamic runtime not loaded');
        var base = state.currentBase ? u64Number(state.currentBase) : 0;
        var size = state.currentSize || 0;
        if (!base || !size) throw new Error('dynamic runtime has no current JIT window');
        var trace = dynamicEnsureTrace();
        if (claim.runtime && claim.sourceBase === base && claim.sourceSize === size) {
            d.runtime = claim.runtime;
            d.sourceBase = base;
            d.sourceSize = size;
            d.exports.setMaxSteps(claim.runtime, d.maxSteps);
            d.exports.setCodeRange(claim.runtime, base, base + size);
            d.exports.setMemRead(claim.runtime, nullPtr);
            d.exports.setMemWrite(claim.runtime, nullPtr);
            d.exports.setBranchTranslate(claim.runtime, d.nativeBranchTranslate);
            d.exports.setBranchBridge(claim.runtime, d.nativeBranchBridge);
            d.exports.setBlockEnter(claim.runtime, ENABLE_BLOCK_TRACE_STUB ? trace.stubBase : nullPtr);
            return claim;
        }
        if (claim.runtime && d.exports.destroy) {
            try { d.exports.destroy(claim.runtime); } catch (e) {}
            claim.runtime = null;
        }
        var runtime = d.exports.create(base, size);
        if (!runtime || runtime.isNull()) throw new Error('aeon_dyn_runtime_create failed');
        claim.runtime = runtime;
        claim.sourceBase = base;
        claim.sourceSize = size;
        d.runtime = runtime;
        d.sourceBase = base;
        d.sourceSize = size;
        d.exports.setMaxSteps(runtime, d.maxSteps);
        d.exports.setCodeRange(runtime, base, base + size);
        d.exports.setMemRead(runtime, nullPtr);
        d.exports.setMemWrite(runtime, nullPtr);
        d.exports.setBranchTranslate(runtime, d.nativeBranchTranslate);
        d.exports.setBranchBridge(runtime, d.nativeBranchBridge);
        d.exports.setBlockEnter(runtime, ENABLE_BLOCK_TRACE_STUB ? trace.stubBase : nullPtr);
        return claim;
    }

    function dynamicParseResult(resultPtr) {
        return {
            stop_code: resultPtr.readU32(),
            start_pc: readU64Num(resultPtr.add(8)),
            final_pc: readU64Num(resultPtr.add(16)),
            steps: readU64Num(resultPtr.add(24)),
            compiled_blocks: readU64Num(resultPtr.add(32)),
            info_pc: readU64Num(resultPtr.add(40)),
        };
    }

    function dynamicFindResumeTrap(details) {
        var d = state.dynamic;
        if (!details || !details.context) return null;
        var threadId = details.threadId;
        if (threadId === null || threadId === undefined) {
            threadId = currentThreadIdMaybe();
        }
        if (threadId === null || threadId === undefined) return null;
        var pending = d.pendingThreads[String(threadId)];
        if (!pending || !d.resumeBrkWord) return null;
        var pc = ptr(details.context.pc);
        try {
            if (pc.readU32() === d.resumeBrkWord) {
                return { threadId: threadId, pending: pending, trapPc: pc };
            }
        } catch (e) {}
        try {
            var prev = pc.sub(4);
            if (prev.readU32() === d.resumeBrkWord) {
                return { threadId: threadId, pending: pending, trapPc: prev };
            }
        } catch (e) {}
        return null;
    }

    function dynamicArmResumeFromContext(cpuCtx, threadId) {
        var d = state.dynamic;
        var startPc = u64Number(cpuCtx.pc);
        var claim = dynamicEnsureRuntime(threadId);
        claim.first_pc = claim.first_pc || ('0x' + startPc.toString(16));
        var scratchSize = dynamicBridgeScratchSize();
        var allocSize = scratchSize + translatedJitContextSize();
        var ctxAlloc = Memory.alloc(allocSize);
        var ctxPtr = ctxAlloc.add(scratchSize);
        translatedSeedContext(ctxPtr, cpuCtx);
        var resultSize = d.exports.resultSize ? u64Number(d.exports.resultSize()) : 48;
        var resultPtr = Memory.alloc(resultSize);
        resultPtr.writeByteArray(new Uint8Array(resultSize));
        var handoffSize = dynamicResumeHandoffSize();
        var handoffPtr = Memory.alloc(handoffSize);
        handoffPtr.writeByteArray(new Uint8Array(handoffSize));
        writeWordExact(handoffPtr.add(0x00), claim.runtime);
        writeWordExact(handoffPtr.add(0x08), ctxPtr);
        writeWordExact(handoffPtr.add(0x10), resultPtr);
        writeWordExact(handoffPtr.add(0x18), cpuCtx.x0);
        writeWordExact(handoffPtr.add(0x20), cpuCtx.pc);
        writeWordExact(handoffPtr.add(0x28), cpuCtx.lr);
        d.pendingThreads[String(threadId)] = {
            startPc: startPc,
            ctxAlloc: ctxAlloc,
            ctxPtr: ctxPtr,
            resultPtr: resultPtr,
            resultSize: resultSize,
            handoffPtr: handoffPtr,
            runtime: claim.runtime,
        };
        cpuCtx.x0 = handoffPtr;
        cpuCtx.pc = d.resumeTrampoline;
        return {
            armed: true,
            start_pc: '0x' + startPc.toString(16),
            thread_id: threadId,
        };
    }

    function dynamicCurrentRuntime() {
        var claim = getClaim(state.dynamic.threadClaims, state.traceThreadId);
        if (claim && claim.runtime) return claim.runtime;
        var keys = Object.keys(state.dynamic.threadClaims || {});
        for (var i = 0; i < keys.length; i++) {
            var candidate = state.dynamic.threadClaims[keys[i]];
            if (candidate && candidate.runtime) return candidate.runtime;
        }
        return null;
    }

    function dynamicLookupSourceForBlockId(runtime, blockId) {
        var d = state.dynamic;
        var key = String(blockId);
        if (Object.prototype.hasOwnProperty.call(d.sourceCache, key)) {
            return d.sourceCache[key];
        }
        var value = 0;
        try {
            value = runtime && d.exports.lookupBlockSource ? u64Number(d.exports.lookupBlockSource(runtime, blockId)) : 0;
        } catch (e) {
            value = 0;
        }
        d.sourceCache[key] = value;
        return value;
    }

    function dynamicRecentTraceEvents(limit) {
        var trace = state.dynamic.trace;
        var runtime = dynamicCurrentRuntime();
        if (!trace) return [];
        var totalHits = readU64Num(trace.seqBase);
        var validEvents = Math.min(totalHits, trace.ringCapacity);
        var keep = Math.max(0, parseInt(limit || 0, 10));
        var out = [];
        if (keep <= 0 || validEvents <= 0) return out;
        var startSeq = Math.max(0, totalHits - Math.min(validEvents, keep));
        for (var seq = startSeq; seq < totalHits; seq++) {
            var idx = seq & trace.ringMask;
            var entry = trace.ringBase.add(idx * trace.ringEntrySize);
            var entrySeq = readU64Num(entry);
            if (entrySeq !== seq) continue;
            var blockId = readU64Num(entry.add(8));
            var sourcePc = dynamicLookupSourceForBlockId(runtime, blockId);
            out.push({
                seq: entrySeq,
                block_id: '0x' + blockId.toString(16),
                source_block: sourcePc ? ('0x' + sourcePc.toString(16)) : null,
                thread_id: readU64Num(entry.add(16)),
            });
        }
        return out;
    }

    function dynamicTraceStatusSummary(maxCounters, maxEvents) {
        var trace = state.dynamic.trace;
        var runtime = dynamicCurrentRuntime();
        if (!trace) return { installed: false };
        var compiledBlocks = 0;
        try {
            compiledBlocks = runtime && state.dynamic.exports.compiledBlocks
                ? u64Number(state.dynamic.exports.compiledBlocks(runtime))
                : 0;
        } catch (e) {
            compiledBlocks = 0;
        }
        var inspectCount = Math.min(compiledBlocks || trace.counterSlots, trace.counterSlots);
        var counters = [];
        var hitBlocks = 0;
        for (var blockId = 0; blockId < inspectCount; blockId++) {
            var hits = readU64Num(trace.countersBase.add(blockId * 8));
            if (hits !== 0) hitBlocks++;
            if (hits === 0) continue;
            var sourcePc = dynamicLookupSourceForBlockId(runtime, blockId);
            counters.push({
                block_id: '0x' + blockId.toString(16),
                source_block: sourcePc ? ('0x' + sourcePc.toString(16)) : null,
                hits: hits,
            });
        }
        counters.sort(function (a, b) { return b.hits - a.hits; });
        var totalHits = readU64Num(trace.seqBase);
        return {
            installed: true,
            slab_base: trace.slabBase.toString(),
            counters_base: trace.countersBase.toString(),
            seq_base: trace.seqBase.toString(),
            ring_base: trace.ringBase.toString(),
            ring_capacity: trace.ringCapacity,
            counter_slots: trace.counterSlots,
            compiled_blocks: compiledBlocks,
            overflow_possible: compiledBlocks > trace.counterSlots,
            total_hits: totalHits,
            hit_blocks: hitBlocks,
            top_blocks: counters.slice(0, Math.max(0, parseInt(maxCounters || 64, 10))),
            events: dynamicRecentTraceEvents(maxEvents || 128),
        };
    }

    function dynamicFinishResumeTrap(details, trap) {
        var d = state.dynamic;
        var raw = dynamicParseResult(trap.pending.resultPtr);
        translatedApplyContext(trap.pending.ctxPtr, details.context, raw.final_pc);
        var stopCode = raw.stop_code;
        var stopName = 'unknown';
        if (stopCode === 0) stopName = 'halted';
        else if (stopCode === 1) stopName = 'max_steps';
        else if (stopCode === 2) stopName = 'code_range_exit';
        else if (stopCode === 3) stopName = 'lift_error';
        else if (stopCode === 0xffffffff) stopName = 'invalid_argument';
        var result = {
            start_pc: '0x' + trap.pending.startPc.toString(16),
            final_pc: '0x' + raw.final_pc.toString(16),
            steps: Number(raw.steps),
            compiled_blocks: Number(raw.compiled_blocks),
            stop_code: Number(stopCode),
            stop: stopName,
            info_pc: raw.info_pc ? ('0x' + raw.info_pc.toString(16)) : null,
            handoff: stopCode === 2,
            recent_blocks: dynamicRecentTraceEvents(Math.min(Number(raw.steps) + 4, 64)),
        };
        delete d.pendingThreads[String(trap.threadId)];
        d.lastRun = result;
        pushLimited(d.runs, result, 32);
        if (STOP_AFTER_FIRST_RUN) {
            state.traceActive = false;
            restoreExecProtection();
            result.trace_disarmed = true;
            saveResult(buildPartialResult('stopped_after_first_run'));
            emit({
                type: 'partial_final',
                ok: true,
                stop: result.stop,
                final_pc: result.final_pc,
                compiled_blocks: result.compiled_blocks,
                steps: result.steps,
            });
            return result;
        }
        ensureTrapProtection();
        var finalPcNum = raw.final_pc;
        var currentBaseNum = state.currentBase ? u64Number(state.currentBase) : 0;
        var currentSizeNum = state.currentSize || 0;
        if (finalPcNum && currentBaseNum &&
            finalPcNum >= currentBaseNum &&
            finalPcNum < (currentBaseNum + currentSizeNum)) {
            activatePage(pageBaseFor(ptr('0x' + finalPcNum.toString(16))));
        }
        return result;
    }

    function nmssJavaString(value) {
        return Java.use('java.lang.String').$new(String(value || ''));
    }

    function nmssResolveCurrentActivity() {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var thread = ActivityThread.currentActivityThread();
        if (!thread) return null;
        try {
            var activities = thread.mActivities.value;
            var iter = activities.values().iterator();
            var fallback = null;
            while (iter.hasNext()) {
                var record = iter.next();
                var activity = record.activity.value;
                if (!activity) continue;
                if (fallback === null) fallback = activity;
                try {
                    if (!record.paused.value) return activity;
                } catch (e) {
                    return activity;
                }
            }
            return fallback;
        } catch (e) {
            try {
                return ActivityThread.currentApplication();
            } catch (inner) {
                return null;
            }
        }
    }

    function nmssResolveHandles() {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var activity = null;
        var app = null;
        var loader = null;
        var factory = null;
        try { activity = nmssResolveCurrentActivity(); } catch (e) {}
        try { app = ActivityThread.currentApplication(); } catch (e) {}
        try { if (activity) loader = activity.getClassLoader(); } catch (e) {}
        try { if (!loader && app) loader = app.getClassLoader(); } catch (e) {}
        try { if (loader) factory = Java.ClassFactory.get(loader); } catch (e) {}
        return {
            activity: activity,
            app: app,
            loader: loader,
            NmssSa: factory ? factory.use('nmss.app.NmssSa') : Java.use('nmss.app.NmssSa'),
        };
    }

    function nmssInvokeReflective(instance, name, args) {
        var cls = instance.getClass();
        var methods = cls.getDeclaredMethods();
        var objectArgs = [];
        args = args || [];
        for (var i = 0; i < args.length; i++) {
            objectArgs.push(typeof args[i] === 'string' ? nmssJavaString(args[i]) : args[i]);
        }
        for (var m = 0; m < methods.length; m++) {
            var method = methods[m];
            try {
                if (method.getName() !== name) continue;
                var types = method.getParameterTypes();
                if (types.length !== objectArgs.length) continue;
                method.setAccessible(true);
                return method.invoke(instance, Java.array('java.lang.Object', objectArgs));
            } catch (e) {}
        }
        throw new Error('method not found: ' + name + '/' + args.length);
    }

    function nmssInvokeMethod(instance, name, args) {
        args = args || [];
        try {
            if (args.length === 0 && typeof instance[name] === 'function') return instance[name]();
            if (args.length === 1 && typeof instance[name] === 'function') return instance[name](args[0]);
        } catch (e) {}
        return nmssInvokeReflective(instance, name, args);
    }

    function nmssRunOnMainThread(action) {
        var Handler = Java.use('android.os.Handler');
        var Looper = Java.use('android.os.Looper');
        var CountDownLatch = Java.use('java.util.concurrent.CountDownLatch');
        var TimeUnit = Java.use('java.util.concurrent.TimeUnit');
        var latch = CountDownLatch.$new(1);
        var result = { ok: false, error: null, value: null };
        function runAction() {
            try {
                result.value = action();
                result.ok = true;
            } catch (e) {
                result.error = String(e);
            } finally {
                latch.countDown();
            }
        }
        try {
            var RunnableClass = Java.registerClass({
                name: 'com.aeon.NmssDynamicMin' + Date.now() + '_' + Math.floor(Math.random() * 100000),
                implements: [Java.use('java.lang.Runnable')],
                methods: {
                    run: runAction
                }
            });
            Handler.$new(Looper.getMainLooper()).post(RunnableClass.$new());
        } catch (postErr) {
            try {
                Java.scheduleOnMainThread(runAction);
            } catch (scheduleErr) {
                return {
                    ok: false,
                    error: 'main_thread_post_failed: ' + String(postErr) + ' / ' + String(scheduleErr),
                    value: null
                };
            }
        }
        var ok = latch.await(20, TimeUnit.SECONDS.value);
        if (!ok) return { ok: false, error: 'timeout_20s', value: null };
        return result;
    }

    function prepareNmss(certChallenge, readyChallenge) {
        if (typeof Java === 'undefined') {
            return { ok: false, error: 'java_undefined' };
        }
        if (!Java.available) {
            return { ok: false, error: 'java_unavailable' };
        }
        var outer = null;
        Java.performNow(function () {
            outer = nmssRunOnMainThread(function () {
                var threadId = null;
                try { threadId = Process.getCurrentThreadId(); } catch (e) {}
                var handles = nmssResolveHandles();
                var inst = handles.NmssSa.getInstObj();
                if (!inst) {
                    return {
                        ok: false,
                        error: 'NO_INSTANCE',
                        challenge: certChallenge,
                        ready_challenge: readyChallenge,
                        activity_class: handles.activity ? String(handles.activity.getClass().getName()) : null,
                        thread_id: threadId,
                    };
                }
                nmssInvokeMethod(inst, 'onResume', []);
                nmssInvokeMethod(inst, 'run', [readyChallenge]);
                var cert = nmssInvokeMethod(inst, 'getCertValue', [certChallenge]);
                var token = cert ? cert.toString() : '';
                return {
                    ok: token.length > 0,
                    error: token.length > 0 ? null : 'empty_cert',
                    challenge: certChallenge,
                    ready_challenge: readyChallenge,
                    token: token,
                    activity_class: handles.activity ? String(handles.activity.getClass().getName()) : null,
                    thread_id: threadId,
                };
            });
        });
        if (!outer || !outer.ok) {
            return {
                ok: false,
                error: outer ? outer.error : 'prepare_failed',
                challenge: certChallenge,
                ready_challenge: readyChallenge,
            };
        }
        return outer.value;
    }

    function sleepMs(ms) {
        var start = Date.now();
        while ((Date.now() - start) < ms) {}
    }

    function waitForPreparedNmss(certChallenge, readyChallenge) {
        var started = Date.now();
        var attempts = 0;
        var last = null;
        while ((Date.now() - started) <= PREPARE_MAX_WAIT_MS) {
            attempts++;
            last = prepareNmss(certChallenge, readyChallenge);
            if (last && last.ok && last.token) {
                last.wait_attempts = attempts;
                last.wait_elapsed_ms = Date.now() - started;
                return last;
            }
            sleepMs(PREPARE_RETRY_MS);
        }
        if (last && typeof last === 'object') {
            last.wait_attempts = attempts;
            last.wait_elapsed_ms = Date.now() - started;
        }
        return last || {
            ok: false,
            error: 'prepare_timeout',
            challenge: certChallenge,
            ready_challenge: readyChallenge,
            wait_attempts: attempts,
            wait_elapsed_ms: Date.now() - started,
        };
    }

    if (!globalThis.__nmssDynamicMinExceptionHandlerInstalled) {
        Process.setExceptionHandler(function (details) {
            var threadId = details.threadId;
            if (threadId === null || threadId === undefined) {
                threadId = currentThreadIdMaybe();
            }
            if (maybeStepDeletedModuleTrap(details)) {
                return true;
            }
            var dynamicResumeTrap = dynamicFindResumeTrap(details);
            if (dynamicResumeTrap) {
                dynamicFinishResumeTrap(details, dynamicResumeTrap);
                return true;
            }
            if (!isTargetTrapException(details)) {
                if (state.dynamic.loaded && artHookThreadAllowed(threadId)) {
                    saveCrashResult('unhandled_exception_after_dynamic_jump', details, threadId);
                }
                if (state.dynamic.loaded && details && details.context &&
                    details.type === 'access-violation' &&
                    details.memory && details.memory.operation === 'execute') {
                    try {
                        var bailoutBridge = dynamicBridgeState(threadId);
                        if (dynamicMaybeBailNonCallableExecute(details, threadId, bailoutBridge)) {
                            return true;
                        }
                        if (getClaim(state.dynamic.threadClaims, threadId) || getClaim(state.dynamic.pendingThreads, threadId)) {
                            saveCrashResult('execute_fault_after_external_jump', details, threadId);
                        }
                    } catch (e) {}
                }
                return false;
            }
            var pageBase = details.context ? pageBaseFor(details.context.pc) : pageBaseFor(details.address);
            if (state.traceThreadId !== null &&
                state.traceThreadId !== undefined &&
                threadId !== state.traceThreadId) {
                allowPassthroughPage(pageBase);
                return true;
            }
            dynamicArmResumeFromContext(details.context, threadId);
            return true;
        });
        globalThis.__nmssDynamicMinExceptionHandlerInstalled = true;
    }

    function main() {
        var result = {
            pid: Process.id,
            ready_challenge: READY_CHALLENGE,
            target_challenge: TARGET_CHALLENGE,
            dynamic_lib: DYNAMIC_LIB,
            art_diag_hooks_enabled: ENABLE_ART_DIAG_HOOKS,
            block_trace_stub_enabled: ENABLE_BLOCK_TRACE_STUB,
            stop_after_first_run: STOP_AFTER_FIRST_RUN,
        };

        emit({ type: 'stage', stage: 'preflight' });
        var preflight = waitForPreparedNmss(READY_CHALLENGE, READY_CHALLENGE);
        state.session.preflight = preflight;
        result.preflight = preflight;
        emit({ type: 'preflight', data: preflight });
        if (!preflight || !preflight.ok || !preflight.token) {
            result.status = 'preflight_failed';
            saveResult(result);
            emit({ type: 'final', ok: false, stage: 'preflight', result: result });
            return;
        }

        emit({ type: 'stage', stage: 'dynamic_load' });
        var rangeInfo = installForRange(chooseTrapRange());
        state.session.range = rangeInfo;
        result.range = rangeInfo;
        result.cached_tpidr = fmtPtr(primeTpidrEl0());
        var loadInfo = dynamicLoad(DYNAMIC_LIB);
        state.session.load = loadInfo;
        result.load = loadInfo;
        emit({ type: 'load', data: loadInfo });
        writeTextFile(ART_HOOK_LOG_PATH, '');
        installArtHooks();

        state.traceThreadId = preflight.thread_id || null;
        state.traceActive = true;
        dynamicResetTrace();
        ensureTrapProtection();

        emit({ type: 'stage', stage: 'traced_call', thread_id: state.traceThreadId });
        var tracedCall = prepareNmss(TARGET_CHALLENGE, READY_CHALLENGE);
        result.traced_call = tracedCall;
        emit({ type: 'traced_call', data: tracedCall });

        state.traceActive = false;
        restoreExecProtection();

        result.dynamic_last_run = state.dynamic.lastRun;
        result.dynamic_runs = state.dynamic.runs.slice(-8);
        result.coverage = dynamicTraceStatusSummary(128, 2048);
        result.status = 'ok';
        saveResult(result);
        emit({ type: 'final', ok: true, result: result });
    }

    setImmediate(function () {
        try {
            main();
        } catch (e) {
            var failure = {
                status: 'error',
                error: String(e),
                stack: e && e.stack ? String(e.stack) : null,
            };
            saveResult(failure);
            emit({ type: 'fatal', error: String(e), stack: e && e.stack ? String(e.stack) : null });
        }
    });
})();
