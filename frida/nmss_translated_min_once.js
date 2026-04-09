'use strict';

(function () {
    var READY_CHALLENGE = '6BA4D60738580083';
    var TARGET_CHALLENGE = READY_CHALLENGE;
    var TRANSLATED_ELF = '/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.elf';
    var TRANSLATED_MAP = '/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.map.json.compact.blockmap.jsonl';
    var RESULT_PATH = '/data/local/tmp/aeon_capture/nmss_translated_min_once.json';
    var ACTIVE_EXEC_SIZE = 0x50000;
    var PAGE_SIZE = 0x1000;
    var TRACE_RING_ENTRY_SIZE = 32;
    var TRACE_MIN_RING_CAPACITY = 0x10000;
    var TRACE_MAX_RING_CAPACITY = 0x100000;
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

    var state = {
        currentBase: null,
        currentSize: 0,
        currentFile: null,
        activePage: null,
        passthroughPages: {},
        traceActive: false,
        traceThreadId: null,
        cachedTpidr: ptr(0),
        translated: {
            loaded: false,
            loadError: null,
            handle: null,
            elfPath: null,
            mapPath: null,
            sourceBase: 0,
            sourceSize: 0,
            maxSteps: 50000,
            blockMap: {},
            blockIdMap: {},
            trapBlockMap: {},
            blockCache: {},
            entryFnCache: {},
            helperAddrs: {},
            helperCallbacks: {},
            trace: null,
            lastRun: null,
            lastCoverage: null,
        },
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

    function readTextFile(path) {
        var fd = openFn(Memory.allocUtf8String(path), 0, 0);
        if (fd < 0) return null;
        var chunks = [];
        var chunkSize = 0x4000;
        try {
            while (true) {
                var buf = Memory.alloc(chunkSize);
                var n = readFn(fd, buf, chunkSize);
                if (n <= 0) break;
                chunks.push(buf.readUtf8String(n) || '');
                if (n < chunkSize) break;
            }
        } finally {
            closeFn(fd);
        }
        return chunks.join('');
    }

    function saveResult(obj) {
        mkdirp('/data/local/tmp/aeon_capture');
        writeTextFile(RESULT_PATH, JSON.stringify(obj, null, 2));
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

    function translatedTraceBlockIds() {
        var seen = {};
        var ids = [];
        Object.keys(state.translated.blockIdMap).forEach(function (key) {
            var id = u64Number(key);
            if (seen[id]) return;
            seen[id] = true;
            ids.push(id);
        });
        ids.sort(function (a, b) { return a - b; });
        return ids;
    }

    function translatedTraceRingCapacity(blockCount) {
        var target = Math.max(TRACE_MIN_RING_CAPACITY, blockCount * 16);
        return Math.min(TRACE_MAX_RING_CAPACITY, nextPow2(target));
    }

    function translatedResetTrace() {
        var trace = state.translated.trace;
        if (!trace || !trace.dataBase || trace.dataBase.isNull()) return false;
        trace.dataBase.writeByteArray(new Uint8Array(trace.dataSize));
        return true;
    }

    function translatedEnsureTrace() {
        var blockIds = translatedTraceBlockIds();
        if (blockIds.length === 0) throw new Error('no translated blocks');
        var maxBlockId = blockIds[blockIds.length - 1];
        var counterSlots = maxBlockId + 1;
        var ringCapacity = translatedTraceRingCapacity(blockIds.length);
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
        state.translated.trace = {
            slabBase: slabBase,
            slabSize: slabSize,
            codeBase: codeBase,
            codeSize: codeBytes,
            dataBase: dataBase,
            dataSize: dataBytes,
            stubBase: codeBase,
            countersBase: countersBase,
            counterSlots: counterSlots,
            blockIds: blockIds,
            maxBlockId: maxBlockId,
            seqBase: seqBase,
            ringBase: ringBase,
            ringCapacity: ringCapacity,
            ringMask: ringCapacity - 1,
            ringEntrySize: TRACE_RING_ENTRY_SIZE,
        };
        translatedResetTrace();
    }

    function translatedTraceStatusSummary(maxCounters, maxEvents) {
        var trace = state.translated.trace;
        if (!trace) return { installed: false };
        var counters = [];
        var hitBlocks = 0;
        trace.blockIds.forEach(function (blockId) {
            var hits = readU64Num(trace.countersBase.add(blockId * 8));
            if (hits !== 0) hitBlocks++;
            if (hits === 0) return;
            counters.push({
                block_id: '0x' + blockId.toString(16),
                source_block: state.translated.blockIdMap['0x' + blockId.toString(16)] || null,
                hits: hits,
            });
        });
        counters.sort(function (a, b) { return b.hits - a.hits; });
        var totalHits = readU64Num(trace.seqBase);
        var validEvents = Math.min(totalHits, trace.ringCapacity);
        var events = [];
        var keepEvents = Math.max(0, parseInt(maxEvents || 0, 10));
        if (keepEvents > 0 && validEvents > 0) {
            var startSeq = Math.max(0, totalHits - Math.min(validEvents, keepEvents));
            for (var seq = startSeq; seq < totalHits; seq++) {
                var idx = seq & trace.ringMask;
                var entry = trace.ringBase.add(idx * trace.ringEntrySize);
                var entrySeq = readU64Num(entry);
                if (entrySeq !== seq) continue;
                var blockId = readU64Num(entry.add(8));
                events.push({
                    seq: entrySeq,
                    block_id: '0x' + blockId.toString(16),
                    source_block: state.translated.blockIdMap['0x' + blockId.toString(16)] || null,
                    thread_id: readU64Num(entry.add(16)),
                });
            }
        }
        return {
            installed: true,
            slab_base: trace.slabBase.toString(),
            counters_base: trace.countersBase.toString(),
            seq_base: trace.seqBase.toString(),
            ring_base: trace.ringBase.toString(),
            ring_capacity: trace.ringCapacity,
            total_hits: totalHits,
            hit_blocks: hitBlocks,
            top_blocks: counters.slice(0, Math.max(0, parseInt(maxCounters || 64, 10))),
            events: events,
        };
    }

    function translatedParseMap(text) {
        var blockMap = {};
        var blockIdMap = {};
        var trapBlockMap = {};
        var meta = null;
        String(text || '').split(/\r?\n/).forEach(function (line) {
            line = line.trim();
            if (!line) return;
            var entry = JSON.parse(line);
            if (entry.t === 'meta') {
                meta = entry;
            } else if (entry.t === 'b') {
                blockMap[String(entry.src).toLowerCase()] = entry.sym;
            } else if (entry.t === 'i') {
                blockIdMap[String(entry.id).toLowerCase()] = String(entry.src).toLowerCase();
            } else if (entry.t === 't') {
                trapBlockMap[String(entry.src).toLowerCase()] = { kind: entry.kind, imm: entry.imm };
            }
        });
        if (meta === null) throw new Error('missing translated meta');
        return {
            raw: meta,
            blockMap: blockMap,
            blockIdMap: blockIdMap,
            trapBlockMap: trapBlockMap,
            sourceBase: u64Number(meta.base),
            sourceSize: meta.source_size || ((meta.instruction_limit || 0) * 4),
        };
    }

    function translatedRebaseSourceAddr(runtimeAddr) {
        var currentBase = state.currentBase ? u64Number(state.currentBase) : 0;
        if (!currentBase || !state.translated.sourceBase) return runtimeAddr;
        var runtime = u64Number(runtimeAddr);
        if (runtime < currentBase || runtime >= (currentBase + state.currentSize)) return runtime;
        return state.translated.sourceBase + (runtime - currentBase);
    }

    function translatedUnrebaseTarget(sourceAddr) {
        var currentBase = state.currentBase ? u64Number(state.currentBase) : 0;
        if (!currentBase || !state.translated.sourceBase) return sourceAddr;
        var source = u64Number(sourceAddr);
        if (source < state.translated.sourceBase || source >= (state.translated.sourceBase + state.currentSize)) return source;
        return currentBase + (source - state.translated.sourceBase);
    }

    function translatedLookupBlockPtr(runtimeAddr) {
        var sourceAddr = translatedRebaseSourceAddr(runtimeAddr);
        var key = '0x' + sourceAddr.toString(16);
        var symbol = state.translated.blockMap[key.toLowerCase()];
        if (!symbol) return null;
        if (state.translated.blockCache[symbol]) return state.translated.blockCache[symbol];
        var sym = translatedResolveSymbol(state.translated.handle, symbol);
        if (!sym) return null;
        state.translated.blockCache[symbol] = sym;
        return sym;
    }

    function translatedLookupTrapInfo(runtimeAddr) {
        var sourceAddr = translatedRebaseSourceAddr(runtimeAddr);
        return state.translated.trapBlockMap[('0x' + sourceAddr.toString(16)).toLowerCase()] || null;
    }

    function translatedLookupBlockSymbol(runtimeAddr) {
        var sourceAddr = translatedRebaseSourceAddr(runtimeAddr);
        return state.translated.blockMap[('0x' + sourceAddr.toString(16)).toLowerCase()] || null;
    }

    function translatedSnapshotCpu(cpuCtx) {
        if (!cpuCtx) return null;
        var snap = {};
        [
            'x0', 'x1', 'x2', 'x3', 'x4', 'x5',
            'x8', 'x15', 'x16', 'x17', 'x19', 'x20',
        ].forEach(function (name) {
            try { snap[name] = fmtPtr(cpuCtx[name]); } catch (e) {}
        });
        try { snap.fp = fmtPtr(cpuCtx.fp); } catch (e) {}
        try { snap.lr = fmtPtr(cpuCtx.lr); } catch (e) {}
        try { snap.sp = fmtPtr(cpuCtx.sp); } catch (e) {}
        try { snap.pc = fmtPtr(cpuCtx.pc); } catch (e) {}
        try { snap.nzcv = String(cpuCtx.nzcv); } catch (e) {}
        return snap;
    }

    function translatedSnapshotJitContext(ctxPtr) {
        if (!ctxPtr || ctxPtr.isNull()) return null;
        var snap = {};
        [0, 1, 2, 3, 4, 5, 8, 15, 16, 17, 19, 20].forEach(function (index) {
            try { snap['x' + index] = fmtPtr(readWordExact(ctxPtr.add(translatedOffsetX(index)))); } catch (e) {}
        });
        try { snap.fp = fmtPtr(readWordExact(ctxPtr.add(translatedOffsetX(29)))); } catch (e) {}
        try { snap.lr = fmtPtr(readWordExact(ctxPtr.add(translatedOffsetX(30)))); } catch (e) {}
        try { snap.sp = fmtPtr(readWordExact(ctxPtr.add(translatedOffsetSp()))); } catch (e) {}
        try { snap.pc = fmtPtr(readWordExact(ctxPtr.add(translatedOffsetPc()))); } catch (e) {}
        try { snap.flags = readU64Num(ctxPtr.add(translatedOffsetFlags())); } catch (e) {}
        try { snap.tpidr = fmtPtr(readWordExact(ctxPtr.add(translatedOffsetTpidr()))); } catch (e) {}
        return snap;
    }

    function translatedEntryFunction(entryPtr) {
        var key = entryPtr.toString();
        if (state.translated.entryFnCache[key]) return state.translated.entryFnCache[key];
        var fn = new NativeFunction(entryPtr, 'uint64', ['pointer']);
        state.translated.entryFnCache[key] = fn;
        return fn;
    }

    function translatedAddrInSourceWindow(runtimeAddr) {
        var currentBase = state.currentBase ? u64Number(state.currentBase) : 0;
        var runtime = u64Number(runtimeAddr);
        return !!currentBase && runtime >= currentBase && runtime < (currentBase + state.currentSize);
    }

    function translatedGapLooksLikeTrapPadding(runtimeStart, runtimeEnd) {
        for (var addr = runtimeStart; addr < runtimeEnd; addr += 4) {
            if (translatedLookupTrapInfo(addr)) continue;
            try {
                if (ptr(addr).readU32() === 0) continue;
            } catch (e) {}
            return false;
        }
        return true;
    }

    function translatedFindNearbyBlock(runtimeAddr, maxSkipBytes) {
        if (!translatedAddrInSourceWindow(runtimeAddr)) return null;
        var runtime = u64Number(runtimeAddr);
        var maxSkip = maxSkipBytes || 0x80;
        for (var delta = 4; delta <= maxSkip; delta += 4) {
            var candidate = runtime + delta;
            if (!translatedAddrInSourceWindow(candidate)) break;
            var entryPtr = translatedLookupBlockPtr(candidate);
            if (entryPtr && translatedGapLooksLikeTrapPadding(runtime, candidate)) {
                return {
                    runtimeAddr: candidate,
                    entryPtr: entryPtr,
                    skippedBytes: delta,
                };
            }
        }
        return null;
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

    function translatedPatchHelper(addr, callback) {
        if (!addr || addr.isNull() || !callback || callback.isNull()) return;
        Memory.patchCode(addr, 16, function (code) {
            var writer = new Arm64Writer(code, { pc: addr });
            writer.putLdrRegAddress('x16', callback);
            writer.putBrReg('x16');
            writer.flush();
        });
    }

    function translatedInstallHooks() {
        // Leave the generated helper stubs intact. In particular, the memory-read
        // helper preserves x0, which the translated blocks immediately reuse as the
        // load address.
        translatedPatchHelper(state.translated.helperAddrs.blockEnter, state.translated.trace.stubBase);
    }

    function translatedLoad() {
        var text = readTextFile(TRANSLATED_MAP);
        if (text === null) throw new Error('failed to read translated map');
        var parsed = translatedParseMap(text);
        var dl = translatedGetLibdl();
        var handle = dl.dlopen(Memory.allocUtf8String(TRANSLATED_ELF), 2);
        if (handle.isNull()) {
            var errPtr = dl.dlerror();
            var errMsg = errPtr && !errPtr.isNull() ? (errPtr.readUtf8String() || '<null>') : '<unknown>';
            throw new Error('dlopen failed: ' + errMsg);
        }
        state.translated.handle = handle;
        state.translated.loaded = true;
        state.translated.elfPath = TRANSLATED_ELF;
        state.translated.mapPath = TRANSLATED_MAP;
        state.translated.sourceBase = parsed.sourceBase;
        state.translated.sourceSize = parsed.sourceSize;
        state.translated.blockMap = parsed.blockMap;
        state.translated.blockIdMap = parsed.blockIdMap;
        state.translated.trapBlockMap = parsed.trapBlockMap;
        state.translated.blockCache = {};
        state.translated.entryFnCache = {};
        translatedEnsureTrace();
        state.translated.helperAddrs = {
            memRead: parsed.raw.memory_read_hook ? translatedResolveSymbol(handle, parsed.raw.memory_read_hook.symbol) : null,
            trap: parsed.raw.trap_hook ? translatedResolveSymbol(handle, parsed.raw.trap_hook.symbol) : null,
            translate: parsed.raw.branch_translate_hook ? translatedResolveSymbol(handle, parsed.raw.branch_translate_hook.symbol) : null,
            bridge: parsed.raw.branch_bridge_hook ? translatedResolveSymbol(handle, parsed.raw.branch_bridge_hook.symbol) : null,
            unknown: parsed.raw.unknown_block_hook ? translatedResolveSymbol(handle, parsed.raw.unknown_block_hook.symbol) : null,
            blockEnter: parsed.raw.block_enter_hook ? translatedResolveSymbol(handle, parsed.raw.block_enter_hook.symbol) : null,
        };
        translatedInstallHooks();
        return {
            loaded: true,
            blocks: Object.keys(state.translated.blockMap).length,
            block_ids: Object.keys(state.translated.blockIdMap).length,
            source_base: '0x' + state.translated.sourceBase.toString(16),
            source_size: state.translated.sourceSize,
        };
    }

    function translatedRunFromContext(cpuCtx) {
        var ctxPtr = Memory.alloc(translatedJitContextSize());
        translatedSeedContext(ctxPtr, cpuCtx);
        var current = u64Number(cpuCtx.pc);
        var startPc = current;
        var steps = 0;
        var trapExit = null;
        var skips = [];
        while (current && steps < state.translated.maxSteps) {
            var trapInfo = translatedLookupTrapInfo(current);
            if (trapInfo) {
                trapExit = {
                    pc: '0x' + current.toString(16),
                    kind: trapInfo.kind || 'unknown',
                    imm: trapInfo.imm || null,
                };
                break;
            }
            var entryPtr = translatedLookupBlockPtr(current);
            if (!entryPtr) {
                var nearby = translatedFindNearbyBlock(current, 0x80);
                if (!nearby) break;
                skips.push({
                    from: '0x' + current.toString(16),
                    to: '0x' + nearby.runtimeAddr.toString(16),
                    skipped_bytes: nearby.skippedBytes,
                });
                current = nearby.runtimeAddr;
                entryPtr = nearby.entryPtr;
            }
            var sourceCurrent = translatedRebaseSourceAddr(current);
            var entrySymbol = translatedLookupBlockSymbol(current);
            var entry = translatedEntryFunction(entryPtr);
            var next = 0;
            try {
                next = u64Number(entry(ctxPtr));
            } catch (e) {
                state.translated.lastRun = {
                    start_pc: '0x' + startPc.toString(16),
                    final_pc: fmtPtr(cpuCtx.pc),
                    steps: steps,
                    trap_exit: trapExit,
                    unresolved: false,
                    skips: skips,
                    error: {
                        message: String(e),
                        stack: e && e.stack ? String(e.stack) : null,
                        runtime_pc: '0x' + current.toString(16),
                        source_pc: '0x' + sourceCurrent.toString(16),
                        entry_symbol: entrySymbol,
                        entry_ptr: fmtPtr(entryPtr),
                        cpu_before: translatedSnapshotCpu(cpuCtx),
                        ctx_seeded: translatedSnapshotJitContext(ctxPtr),
                    },
                };
                return state.translated.lastRun;
            }
            steps++;
            if (!next) {
                current = next;
                break;
            }
            current = translatedUnrebaseTarget(next);
            if (!translatedLookupBlockPtr(current) && !translatedLookupTrapInfo(current)) break;
        }
        translatedApplyContext(ctxPtr, cpuCtx, current);
        state.translated.lastRun = {
            start_pc: '0x' + startPc.toString(16),
            final_pc: fmtPtr(cpuCtx.pc),
            steps: steps,
            trap_exit: trapExit,
            unresolved: current ? !translatedLookupBlockPtr(current) : false,
            skips: skips,
        };
        return state.translated.lastRun;
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
        var RunnableClass = Java.registerClass({
            name: 'com.aeon.MinTranslated' + Date.now() + '_' + Math.floor(Math.random() * 100000),
            implements: [Java.use('java.lang.Runnable')],
            methods: {
                run: function () {
                    try {
                        result.value = action();
                        result.ok = true;
                    } catch (e) {
                        result.error = String(e);
                    } finally {
                        latch.countDown();
                    }
                }
            }
        });
        Handler.$new(Looper.getMainLooper()).post(RunnableClass.$new());
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

    if (!globalThis.__nmssTranslatedMinExceptionHandlerInstalled) {
        Process.setExceptionHandler(function (details) {
            if (!isTargetTrapException(details)) {
                return false;
            }
            var threadId = details.threadId;
            if (threadId === null || threadId === undefined) {
                try { threadId = Process.getCurrentThreadId(); } catch (e) {}
            }
            var pageBase = details.context ? pageBaseFor(details.context.pc) : pageBaseFor(details.address);
            if (state.traceThreadId !== null &&
                state.traceThreadId !== undefined &&
                threadId !== state.traceThreadId) {
                allowPassthroughPage(pageBase);
                return true;
            }
            var translatedResult = translatedRunFromContext(details.context);
            if (translatedResult && translatedResult.error) {
                emit({ type: 'translated_error', data: translatedResult.error });
                state.traceActive = false;
                restoreExecProtection();
                return true;
            }
            var translatedPage = details.context ? pageBaseFor(details.context.pc) : null;
            var shouldResumeOriginal = false;
            if (translatedResult && translatedResult.trap_exit) {
                shouldResumeOriginal = true;
            } else if (translatedResult && translatedResult.unresolved && details.context) {
                var currentPcNum = u64Number(details.context.pc);
                var currentBaseNum = state.currentBase ? u64Number(state.currentBase) : 0;
                shouldResumeOriginal = !!currentBaseNum &&
                    currentPcNum >= currentBaseNum &&
                    currentPcNum < (currentBaseNum + state.currentSize);
            }
            if (shouldResumeOriginal && translatedPage) {
                activatePage(translatedPage);
            }
            return true;
        });
        globalThis.__nmssTranslatedMinExceptionHandlerInstalled = true;
    }

    function main() {
        var result = {
            pid: Process.id,
            ready_challenge: READY_CHALLENGE,
            target_challenge: TARGET_CHALLENGE,
        };

        emit({ type: 'stage', stage: 'preflight' });
        var preflight = prepareNmss(READY_CHALLENGE, READY_CHALLENGE);
        result.preflight = preflight;
        emit({ type: 'preflight', data: preflight });
        if (!preflight || !preflight.ok || !preflight.token) {
            result.status = 'preflight_failed';
            saveResult(result);
            emit({ type: 'final', ok: false, stage: 'preflight', result: result });
            return;
        }

        emit({ type: 'stage', stage: 'translated_load' });
        var rangeInfo = installForRange(chooseTrapRange());
        result.range = rangeInfo;
        result.cached_tpidr = fmtPtr(primeTpidrEl0());
        var loadInfo = translatedLoad();
        result.load = loadInfo;
        emit({ type: 'load', data: loadInfo });

        state.traceThreadId = preflight.thread_id || null;
        state.traceActive = true;
        translatedResetTrace();
        ensureTrapProtection();

        emit({ type: 'stage', stage: 'traced_call', thread_id: state.traceThreadId });
        var tracedCall = prepareNmss(TARGET_CHALLENGE, READY_CHALLENGE);
        result.traced_call = tracedCall;
        emit({ type: 'traced_call', data: tracedCall });

        state.traceActive = false;
        restoreExecProtection();

        var coverage = translatedTraceStatusSummary(128, 2048);
        result.coverage = coverage;
        result.last_run = state.translated.lastRun;
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
