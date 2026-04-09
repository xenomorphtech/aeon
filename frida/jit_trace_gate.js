// Page-trap probe for the live cert corridor in jit-cache.
// Tracks hot pages/PCs/edges and can scan the hottest pages for likely
// AArch64 function entry prologues inside the same Frida session.

'use strict';

(function () {
    if (globalThis.__jitGateTrace && globalThis.__jitGateTrace.installed) {
        console.log('[CAPTURE] [GATE] relay already installed');
        return;
    }

    var state = globalThis.__jitGateTrace = {
        installed: true,
        maxEvents: 256,
        seq: 0,
        drops: 0,
        events: [],
        failures: [],
        hooks: {},
        currentBase: null,
        currentSize: 0,
        currentFile: null,
        activePage: null,
        pageHits: {},
        pcHits: {},
        edgeHits: {},
        threadHits: {},
        trapCounts: {},
        protections: [],
        trapSnapshots: [],
        trapSnapshotSeq: 0,
        exceptions: [],
        fixedTraceArm: null,
        fixedTrace: null,
        stalker: {
            active: false,
            armed: false,
            pendingThreadId: null,
            threadId: null,
            startedAt: null,
            startReason: null,
            maxEvents: 1024,
            drops: 0,
            events: [],
            pcHits: {},
            threadHits: {},
            blockCount: 0,
        },
        postResume: {
            active: false,
            threadId: null,
            startPc: null,
            startedAt: null,
            stopReason: null,
            reason: null,
            events: [],
            drops: 0,
            maxEvents: 128,
            blockCount: 0,
        },
        nativeChain: {
            hooksInstalled: false,
            hooks: {},
            resumedThreads: {},
        },
        memdump: {
            armed: false,
            captured: false,
            before: null,
            after: null,
        },
        freeze: {
            armed: false,
            triggered: false,
            challenge: null,
            info: null,
        },
        translated: {
            armed: false,
            minPc: null,
            elfPath: null,
            mapPath: null,
            loaded: false,
            loadError: null,
            handle: null,
            moduleName: null,
            sourceBase: 0,
            sourceSize: 0,
            maxSteps: 4096,
            activeThreadId: null,
            activeChallenge: null,
            activeCall: null,
            claimedThreads: {},
            helperAddrs: {},
            helperCallbacks: {},
            blockMap: {},
            blockIdMap: {},
            trapBlockMap: {},
            blockCache: {},
            runs: [],
            recentBlocks: [],
            lastRun: null,
            lastLoadStage: null,
            logReads: false,
            logTraps: true,
            logBlocks: true,
        },
        dynamic: {
            armed: false,
            loaded: false,
            loadError: null,
            minPc: null,
            libPath: null,
            handle: null,
            runtime: null,
            sourceBase: 0,
            sourceSize: 0,
            maxSteps: 4096,
            nativeBranchBridge: null,
            bridgeGlobals: {},
            activeThreadId: null,
            activeChallenge: null,
            activeCall: null,
            threadClaims: {},
            exports: {},
            callbacks: {},
            runs: [],
            recentBlocks: [],
            lastRun: null,
            lastLoadStage: null,
            pendingThreads: {},
            resumeTrampoline: null,
            resumeBrkImm: 0,
            resumeBrkWord: 0,
            logReads: false,
            logBlocks: true,
            logWrites: false,
        },
    };

    var PTR_MASK = ptr('0x00FFFFFFFFFFFFFF');
    var PAGE_MASK = ptr('0xFFFFFFFFFFFFF000');
    var EXEC_PROTECTIONS = ['r-x', '--x'];
    var ACTIVE_EXEC_SIZE = 0x50000;
    var PAGE_SIZE = 0x1000;
    var AEON_SCRATCH_STAGE = 0x18;
    var AEON_SCRATCH_LAST_TARGET = 0x20;
    var AEON_SCRATCH_TAIL_MODE = 0x28;
    var AEON_SCRATCH_SAVED_X30 = 0x10;
    var AEON_SCRATCH_DBG_OUTGOING_X30 = 0x120;
    var AEON_SCRATCH_DBG_POST_CALL_X30 = 0x128;
    var AEON_SCRATCH_DBG_RESUME_TARGET = 0x130;
    var AEON_SCRATCH_DBG_CTX_PC = 0x138;
    var STALKER_REPEAT_SAMPLE = 256;
    var MEMDUMP_MAX_REGION = 50 * 1024 * 1024;
    var MEMDUMP_DEVICE_DIR = '/data/local/tmp/aeon_capture/memdump';
    var TRAP_WINDOW_DEVICE_DIR = '/data/local/tmp/aeon_capture/trap_windows';
    var FREEZE_STATUS_PATH = '/data/local/tmp/aeon_capture/freeze.json';
    var MEMDUMP_CHUNK = 0x10000;
    var originalCallCertExport = null;

    function parseJsonMaybe(value) {
        if (typeof value !== 'string') return value;
        try {
            return JSON.parse(value);
        } catch (e) {
            return value;
        }
    }

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function nowMillis() {
        return (new Date()).getTime();
    }

    function describeAddr(value) {
        try {
            var p = normalizeWordPtr(value);
            var out = { addr: p.toString() };
            try {
                var mod = Process.findModuleByAddress(p);
                if (mod) {
                    out.module = mod.name || null;
                    out.offset = '0x' + u64Number(p.sub(mod.base)).toString(16);
                }
            } catch (e) {}
            try {
                out.symbol = DebugSymbol.fromAddress(p).toString();
            } catch (e) {}
            return out;
        } catch (e) {
            return { addr: String(value), error: String(e) };
        }
    }

    function threadKey(threadId) {
        return String(threadId);
    }

    function claimedThreadIds(map) {
        return Object.keys(map || {});
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

    function bytesToHex(bytes) {
        if (!bytes) return null;
        var view = new Uint8Array(bytes);
        var out = [];
        for (var i = 0; i < view.length; i++) {
            var h = view[i].toString(16);
            out.push(h.length === 1 ? '0' + h : h);
        }
        return out.join('');
    }

    function sha256Hex(bytesLike) {
        if (!bytesLike) return null;
        var bytes = bytesLike instanceof Uint8Array ? bytesLike : new Uint8Array(bytesLike);
        var K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];
        function rotr(x, n) {
            return ((x >>> n) | (x << (32 - n))) >>> 0;
        }
        var bitLen = bytes.length * 8;
        var paddedLen = bytes.length + 1;
        while ((paddedLen % 64) !== 56) paddedLen++;
        paddedLen += 8;
        var msg = new Uint8Array(paddedLen);
        msg.set(bytes);
        msg[bytes.length] = 0x80;
        var dv = new DataView(msg.buffer);
        var hi = Math.floor(bitLen / 0x100000000);
        var lo = bitLen >>> 0;
        dv.setUint32(paddedLen - 8, hi >>> 0, false);
        dv.setUint32(paddedLen - 4, lo, false);
        var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        var h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
        var w = new Uint32Array(64);
        for (var offset = 0; offset < paddedLen; offset += 64) {
            for (var i = 0; i < 16; i++) {
                w[i] = dv.getUint32(offset + i * 4, false);
            }
            for (var j = 16; j < 64; j++) {
                var s0 = (rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3)) >>> 0;
                var s1 = (rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10)) >>> 0;
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
            }
            var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (var t = 0; t < 64; t++) {
                var S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
                var ch = ((e & f) ^ ((~e) & g)) >>> 0;
                var temp1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
                var S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
                var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
                var temp2 = (S0 + maj) >>> 0;
                h = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }
            h0 = (h0 + a) >>> 0;
            h1 = (h1 + b) >>> 0;
            h2 = (h2 + c) >>> 0;
            h3 = (h3 + d) >>> 0;
            h4 = (h4 + e) >>> 0;
            h5 = (h5 + f) >>> 0;
            h6 = (h6 + g) >>> 0;
            h7 = (h7 + h) >>> 0;
        }
        function hex32(x) {
            return ('00000000' + (x >>> 0).toString(16)).slice(-8);
        }
        return hex32(h0) + hex32(h1) + hex32(h2) + hex32(h3) +
               hex32(h4) + hex32(h5) + hex32(h6) + hex32(h7);
    }

    function readUtf8Maybe(addr, maxLen) {
        try { return ptr(addr).readUtf8String(maxLen); } catch (e) { return null; }
    }

    function exceptionBacktrace(context, limit) {
        try {
            return Thread.backtrace(context, Backtracer.ACCURATE)
                .slice(0, limit || 10)
                .map(function (addr) {
                    try {
                        return DebugSymbol.fromAddress(addr).toString();
                    } catch (e) {
                        return ptr(addr).toString();
                    }
                });
        } catch (e) {
            return ['<bt-error:' + String(e) + '>'];
        }
    }

    function readBytesMaybe(addr, size) {
        try { return bytesToHex(ptr(addr).readByteArray(size)); } catch (e) { return null; }
    }

    function readSsoLike(addr) {
        var p = ptr(addr);
        var out = {
            addr: p.toString(),
            raw32: readBytesMaybe(p, 32),
            cstr: readUtf8Maybe(p, 64),
        };
        try {
            out.ptr = p.readPointer().toString();
            out.ptr_cstr = readUtf8Maybe(out.ptr, 64);
        } catch (e) {}
        return out;
    }

    function memdumpGetLibc() {
        if (memdumpGetLibc._cache) return memdumpGetLibc._cache;
        var libc = Process.getModuleByName('libc.so');
        memdumpGetLibc._cache = {
            open: new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int', 'int']),
            write: new NativeFunction(libc.getExportByName('write'), 'long', ['int', 'pointer', 'long']),
            read: new NativeFunction(libc.getExportByName('read'), 'long', ['int', 'pointer', 'long']),
            close: new NativeFunction(libc.getExportByName('close'), 'int', ['int']),
            mkdir: new NativeFunction(libc.getExportByName('mkdir'), 'int', ['pointer', 'int']),
            kill: new NativeFunction(libc.getExportByName('kill'), 'int', ['int', 'int']),
        };
        return memdumpGetLibc._cache;
    }

    function memdumpMkdir(path) {
        var lc = memdumpGetLibc();
        lc.mkdir(Memory.allocUtf8String(path), 0x1ff);
    }

    function memdumpOpenWrite(path) {
        var lc = memdumpGetLibc();
        return lc.open(Memory.allocUtf8String(path), 0x241, 0x1a4);
    }

    function readTextFile(path) {
        var lc = memdumpGetLibc();
        var fd = lc.open(Memory.allocUtf8String(path), 0, 0);
        if (fd < 0) return null;
        var chunkSize = 0x4000;
        var chunks = [];
        try {
            while (true) {
                var buf = Memory.alloc(chunkSize);
                var n = lc.read(fd, buf, chunkSize);
                if (n <= 0) break;
                chunks.push(buf.readUtf8String(n) || '');
                if (n < chunkSize) break;
            }
        } finally {
            lc.close(fd);
        }
        if (chunks.length === 0) return '';
        return chunks.join('');
    }

    function translatedFindGlobalExport(name) {
        if (typeof Module.getGlobalExportByName === 'function') {
            try { return Module.getGlobalExportByName(name); } catch (e) {}
        }
        if (typeof Module.findExportByName === 'function') {
            try { return Module.findExportByName(null, name); } catch (e) {}
        }
        return null;
    }

    function translatedGetLibdl() {
        if (translatedGetLibdl._cache) return translatedGetLibdl._cache;
        var dlopenPtr = translatedFindGlobalExport('dlopen');
        var dlsymPtr = translatedFindGlobalExport('dlsym');
        var dlerrorPtr = translatedFindGlobalExport('dlerror');
        if (!dlopenPtr || !dlsymPtr || !dlerrorPtr) {
            throw new Error('dlopen/dlsym/dlerror exports not found');
        }
        translatedGetLibdl._cache = {
            dlopen: new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']),
            dlsym: new NativeFunction(dlsymPtr, 'pointer', ['pointer', 'pointer']),
            dlerror: new NativeFunction(dlerrorPtr, 'pointer', []),
        };
        return translatedGetLibdl._cache;
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

    function writeU64Num(addr, value) {
        var hi = Math.floor(value / 0x100000000);
        var lo = value >>> 0;
        ptr(addr).writeU64(uint64('0x' + hi.toString(16) + ('00000000' + lo.toString(16)).slice(-8)));
    }

    function readU64Num(addr) {
        return parseInt(ptr(addr).readU64().toString(), 10);
    }

    function normalizeWordPtr(value) {
        if (value === null || value === undefined) return ptr(0);
        try { return ptr(value); } catch (e) {}
        if (typeof value === 'number') {
            return ptr('0x' + value.toString(16));
        }
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

    function hexToBytes(hex) {
        if (!hex) return new Uint8Array(0);
        var clean = String(hex).replace(/^0x/i, '');
        if ((clean.length & 1) !== 0) clean = '0' + clean;
        var out = new Uint8Array(clean.length / 2);
        for (var i = 0; i < out.length; i++) {
            out[i] = parseInt(clean.substr(i * 2, 2), 16) & 0xff;
        }
        return out;
    }

    function bytesToArrayBuffer(bytes) {
        var out = new Uint8Array(bytes.length);
        out.set(bytes);
        return out.buffer;
    }

    function translatedJitContextSize() {
        return (31 * 8) + 8 + 8 + 8 + (32 * 16) + 8;
    }

    function dynamicBridgeScratchSize() {
        var d = state.dynamic;
        if (d.exports && d.exports.bridgeScratchSize) {
            try {
                return u64Number(d.exports.bridgeScratchSize());
            } catch (e) {}
        }
        return 0x120;
    }

    function dynamicResumeHandoffSize() {
        var d = state.dynamic;
        if (d.exports && d.exports.resumeHandoffSize) {
            try {
                return u64Number(d.exports.resumeHandoffSize());
            } catch (e) {}
        }
        return 0x28;
    }

    function translatedOffsetX(index) { return index * 8; }
    function translatedOffsetSp() { return 31 * 8; }
    function translatedOffsetPc() { return translatedOffsetSp() + 8; }
    function translatedOffsetFlags() { return translatedOffsetPc() + 8; }
    function translatedOffsetSimd() { return translatedOffsetFlags() + 8; }
    function translatedOffsetTpidr() { return translatedOffsetSimd() + (32 * 16); }

    function readTpidrEl0() {
        if (readTpidrEl0._fn) return readTpidrEl0._fn();
        var code = Memory.alloc(Process.pageSize);
        code.writeU32(0xD53BD040);
        code.add(4).writeU32(0xD65F03C0);
        Memory.protect(code, Process.pageSize, 'r-x');
        readTpidrEl0._fn = new NativeFunction(code, 'pointer', []);
        return readTpidrEl0._fn();
    }

    function translatedParseMap(text) {
        text = String(text || '');
        var trimmed = text.trim();
        if (trimmed.length === 0) throw new Error('empty translated map');
        if (trimmed[0] !== '{') {
            return translatedParseMapJsonl(text);
        }
        var data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            return translatedParseMapJsonl(text);
        }
        var blockMap = {};
        var blockIdMap = {};
        var trapBlockMap = {};
        if (data.block_map && typeof data.block_map === 'object') {
            Object.keys(data.block_map).forEach(function (key) {
                blockMap[String(key).toLowerCase()] = data.block_map[key];
            });
        } else {
            (data.blocks || []).forEach(function (entry) {
                blockMap[String(entry.source_block).toLowerCase()] = entry.symbol;
            });
        }
        if (data.block_id_map && typeof data.block_id_map === 'object') {
            Object.keys(data.block_id_map).forEach(function (key) {
                blockIdMap[String(key).toLowerCase()] = String(data.block_id_map[key]).toLowerCase();
            });
        }
        if (data.trap_block_map && typeof data.trap_block_map === 'object') {
            Object.keys(data.trap_block_map).forEach(function (key) {
                trapBlockMap[String(key).toLowerCase()] = data.trap_block_map[key];
            });
        }
        return {
            raw: data,
            blockMap: blockMap,
            blockIdMap: blockIdMap,
            trapBlockMap: trapBlockMap,
            sourceBase: u64Number(data.base),
            sourceSize: ((data.instruction_limit || 0) * 4),
        };
    }

    function translatedParseMapJsonl(text) {
        var blockMap = {};
        var blockIdMap = {};
        var trapBlockMap = {};
        var meta = null;
        var lines = String(text || '').split(/\r?\n/);
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (!line) continue;
            var entry = JSON.parse(line);
            if (entry.t === 'meta') {
                meta = entry;
            } else if (entry.t === 'b') {
                blockMap[String(entry.src).toLowerCase()] = entry.sym;
            } else if (entry.t === 'i') {
                blockIdMap[String(entry.id).toLowerCase()] = String(entry.src).toLowerCase();
            } else if (entry.t === 't') {
                trapBlockMap[String(entry.src).toLowerCase()] = {
                    kind: entry.kind,
                    imm: entry.imm,
                };
            }
        }
        if (meta === null) throw new Error('compact jsonl map missing meta record');
        return {
            raw: meta,
            blockMap: blockMap,
            blockIdMap: blockIdMap,
            trapBlockMap: trapBlockMap,
            sourceBase: u64Number(meta.base),
            sourceSize: meta.source_size || ((meta.instruction_limit || 0) * 4),
        };
    }

    function translatedResolveSymbol(handle, symbol) {
        var dl = translatedGetLibdl();
        var sym = dl.dlsym(handle, Memory.allocUtf8String(symbol));
        return sym && !sym.isNull() ? sym : null;
    }

    function translatedRebaseSourceAddr(runtimeAddr) {
        var currentBase = state.currentBase ? u64Number(state.currentBase) : 0;
        if (!currentBase || !state.translated.sourceBase) return runtimeAddr;
        var runtime = u64Number(runtimeAddr);
        var size = state.currentSize || 0;
        if (!size) return runtime;
        if (runtime < currentBase || runtime >= (currentBase + size)) return runtime;
        return state.translated.sourceBase + (runtime - currentBase);
    }

    function translatedUnrebaseTarget(sourceAddr) {
        var currentBase = state.currentBase ? u64Number(state.currentBase) : 0;
        if (!currentBase || !state.translated.sourceBase) return sourceAddr;
        var source = u64Number(sourceAddr);
        var size = state.currentSize || 0;
        if (!size) return source;
        if (source < state.translated.sourceBase || source >= (state.translated.sourceBase + size)) return source;
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
        var key = '0x' + sourceAddr.toString(16);
        return state.translated.trapBlockMap[key.toLowerCase()] || null;
    }

    function aarch64BrkWord(imm) {
        return (0xd4200000 | ((Number(imm) & 0xffff) << 5)) >>> 0;
    }

    function translatedAddrInSourceWindow(runtimeAddr) {
        var currentBase = state.currentBase ? u64Number(state.currentBase) : 0;
        var size = state.currentSize || 0;
        var runtime = u64Number(runtimeAddr);
        return !!currentBase && !!size && runtime >= currentBase && runtime < (currentBase + size);
    }

    function translatedFindNearbyBlock(runtimeAddr, maxSkipBytes) {
        if (!translatedAddrInSourceWindow(runtimeAddr)) return null;
        var runtime = u64Number(runtimeAddr);
        var maxSkip = maxSkipBytes || 0x40;
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

    function translatedGapLooksLikeTrapPadding(runtimeStart, runtimeEnd) {
        for (var addr = runtimeStart; addr < runtimeEnd; addr += 4) {
            var trapInfo = translatedLookupTrapInfo(addr);
            if (trapInfo) continue;
            try {
                if (ptr(addr).readU32() === 0) continue;
            } catch (e) {}
            return false;
        }
        return true;
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
                if (qval !== undefined && qval !== null) {
                    if (qval instanceof ArrayBuffer) {
                        dst.writeByteArray(new Uint8Array(qval));
                        continue;
                    }
                    if (qval && qval.buffer instanceof ArrayBuffer && qval.byteLength !== undefined) {
                        dst.writeByteArray(new Uint8Array(qval.buffer, qval.byteOffset || 0, Math.min(16, qval.byteLength)));
                        continue;
                    }
                }
            } catch (e) {}
            dst.writeByteArray(new Uint8Array(16));
        }
        writeWordExact(ctxPtr.add(translatedOffsetTpidr()), readTpidrEl0());
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
        var simdBase = ctxPtr.add(translatedOffsetSimd());
        for (var q = 0; q <= 31; q++) {
            try {
                cpuCtx['q' + q] = bytesToArrayBuffer(new Uint8Array(simdBase.add(q * 16).readByteArray(16)));
            } catch (e) {}
        }
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
        var t = state.translated;
        if (t.helperCallbacks.translate) return;
        t.helperCallbacks.translate = new NativeCallback(function (sourceTarget) {
            return sourceTarget;
        }, 'uint64', ['uint64']);
        t.helperCallbacks.bridge = new NativeCallback(function (ctx, sourceTarget) {
            return sourceTarget;
        }, 'uint64', ['pointer', 'uint64']);
        t.helperCallbacks.unknown = new NativeCallback(function (sourceTarget) {
            console.log('[CAPTURE] [GATE] translated unknown block target=' + ptr(sourceTarget));
        }, 'void', ['uint64']);
        t.helperCallbacks.memRead = new NativeCallback(function (addr) {
            if (t.logReads) console.log('[CAPTURE] [GATE] translated read addr=' + ptr(addr));
        }, 'void', ['uint64']);
        t.helperCallbacks.trap = new NativeCallback(function (blockAddr, kindCode, imm) {
            if (t.logTraps) console.log('[CAPTURE] [GATE] translated trap block=' + ptr(blockAddr) + ' kind=' + kindCode + ' imm=0x' + Number(imm).toString(16));
        }, 'void', ['uint64', 'uint64', 'uint64']);
        t.helperCallbacks.blockEnter = new NativeCallback(function (blockId) {
            var blockIdNum = u64Number(blockId);
            var blockIdKey = '0x' + blockIdNum.toString(16);
            var sourceBlock = t.blockIdMap[blockIdKey.toLowerCase()] || null;
            var record = {
                block_id: blockIdKey,
                source_block: sourceBlock,
            };
            pushLimited(t.recentBlocks, record, 128);
            if (t.logBlocks) {
                console.log('[CAPTURE] [GATE] translated block id=' + blockIdKey +
                    (sourceBlock ? ' source=' + sourceBlock : ' source=<unknown>'));
            }
        }, 'void', ['uint64']);
        translatedPatchHelper(t.helperAddrs.translate, t.helperCallbacks.translate);
        translatedPatchHelper(t.helperAddrs.bridge, t.helperCallbacks.bridge);
        translatedPatchHelper(t.helperAddrs.unknown, t.helperCallbacks.unknown);
        translatedPatchHelper(t.helperAddrs.memRead, t.helperCallbacks.memRead);
        translatedPatchHelper(t.helperAddrs.trap, t.helperCallbacks.trap);
        translatedPatchHelper(t.helperAddrs.blockEnter, t.helperCallbacks.blockEnter);
    }

    function translatedLoad(elfPath, mapPath) {
        console.log('[CAPTURE] [GATE] translated load stage=read_map map=' + mapPath);
        state.translated.lastLoadStage = 'read_map';
        var text = readTextFile(mapPath);
        if (text === null) throw new Error('failed to read map: ' + mapPath);
        console.log('[CAPTURE] [GATE] translated load stage=parse_map');
        state.translated.lastLoadStage = 'parse_map';
        var parsed = translatedParseMap(text);
        console.log('[CAPTURE] [GATE] translated load stage=resolve_libdl');
        state.translated.lastLoadStage = 'resolve_libdl';
        var dl = translatedGetLibdl();
        console.log('[CAPTURE] [GATE] translated load stage=dlopen elf=' + elfPath);
        state.translated.lastLoadStage = 'dlopen';
        var handle = dl.dlopen(Memory.allocUtf8String(elfPath), 2);
        if (handle.isNull()) {
            var errPtr = dl.dlerror();
            var errMsg = errPtr && !errPtr.isNull() ? (errPtr.readUtf8String() || '<null>') : '<unknown>';
            throw new Error('dlopen failed: ' + elfPath + ' err=' + errMsg);
        }
        console.log('[CAPTURE] [GATE] translated load stage=populate_state');
        state.translated.lastLoadStage = 'populate_state';
        state.translated.elfPath = elfPath;
        state.translated.mapPath = mapPath;
        state.translated.handle = handle;
        state.translated.moduleName = elfPath.split('/').slice(-1)[0];
        state.translated.blockMap = parsed.blockMap;
        state.translated.blockIdMap = parsed.blockIdMap;
        state.translated.trapBlockMap = parsed.trapBlockMap || {};
        state.translated.blockCache = {};
        state.translated.recentBlocks = [];
        state.translated.sourceBase = parsed.sourceBase;
        state.translated.sourceSize = parsed.sourceSize;
        console.log('[CAPTURE] [GATE] translated load stage=resolve_hooks');
        state.translated.lastLoadStage = 'resolve_hooks';
        state.translated.helperAddrs = {
            memRead: parsed.raw.memory_read_hook ? translatedResolveSymbol(handle, parsed.raw.memory_read_hook.symbol) : null,
            trap: parsed.raw.trap_hook ? translatedResolveSymbol(handle, parsed.raw.trap_hook.symbol) : null,
            translate: parsed.raw.branch_translate_hook ? translatedResolveSymbol(handle, parsed.raw.branch_translate_hook.symbol) : null,
            bridge: parsed.raw.branch_bridge_hook ? translatedResolveSymbol(handle, parsed.raw.branch_bridge_hook.symbol) : null,
            unknown: parsed.raw.unknown_block_hook ? translatedResolveSymbol(handle, parsed.raw.unknown_block_hook.symbol) : null,
            blockEnter: parsed.raw.block_enter_hook ? translatedResolveSymbol(handle, parsed.raw.block_enter_hook.symbol) : null,
        };
        console.log('[CAPTURE] [GATE] translated load stage=install_hooks');
        state.translated.lastLoadStage = 'install_hooks';
        translatedInstallHooks();
        console.log('[CAPTURE] [GATE] translated load stage=done');
        state.translated.lastLoadStage = 'done';
        state.translated.loaded = true;
        state.translated.loadError = null;
        return {
            loaded: true,
            elfPath: elfPath,
            mapPath: mapPath,
            sourceBase: '0x' + state.translated.sourceBase.toString(16),
            sourceSize: state.translated.sourceSize,
            blocks: Object.keys(state.translated.blockMap).length,
            blockIds: Object.keys(state.translated.blockIdMap).length,
        };
    }

    function translatedRunFromContext(cpuCtx) {
        var startPc = u64Number(cpuCtx.pc);
        var ctxPtr = Memory.alloc(translatedJitContextSize());
        translatedSeedContext(ctxPtr, cpuCtx);
        var current = startPc;
        var steps = 0;
        var path = [];
        var skips = [];
        var trapExit = null;
        while (current && steps < state.translated.maxSteps) {
            var trapInfo = translatedLookupTrapInfo(current);
            if (trapInfo) {
                trapExit = {
                    pc: '0x' + current.toString(16),
                    kind: trapInfo.kind || 'unknown',
                    imm: trapInfo.imm || null,
                };
                console.log('[CAPTURE] [GATE] translated handoff trap-only block=' +
                            ptr(current) + ' kind=' + trapExit.kind +
                            (trapExit.imm ? ' imm=' + trapExit.imm : ''));
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
                console.log('[CAPTURE] [GATE] translated skip filler from=' +
                            ptr(current) + ' to=' + ptr(nearby.runtimeAddr) +
                            ' skipped=0x' + nearby.skippedBytes.toString(16));
                current = nearby.runtimeAddr;
                entryPtr = nearby.entryPtr;
            }
            path.push('0x' + current.toString(16));
            var entry = new NativeFunction(entryPtr, 'uint64', ['pointer']);
            var next = u64Number(entry(ctxPtr));
            steps++;
            if (!next) {
                current = next;
                break;
            }
            current = translatedUnrebaseTarget(next);
            var maybeNext = translatedLookupBlockPtr(current);
            if (!maybeNext) break;
        }
        translatedApplyContext(ctxPtr, cpuCtx, current);
        var result = {
            startPc: '0x' + startPc.toString(16),
            finalPc: '0x' + u64Number(cpuCtx.pc).toString(16),
            steps: steps,
            path: path,
            skips: skips,
            trap_exit: trapExit,
            unresolved: current ? !translatedLookupBlockPtr(current) : false,
            recent_blocks: state.translated.recentBlocks.slice(-Math.min(steps + 4, 32)),
        };
        state.translated.lastRun = result;
        pushLimited(state.translated.runs, result, 32);
        console.log('[CAPTURE] [GATE] translated dispatch start=' + result.startPc +
                    ' steps=' + steps +
                    ' final=' + result.finalPc +
                    ' unresolved=' + result.unresolved);
        return result;
    }

    function dynamicDestroyThreadClaims(claims) {
        var d = state.dynamic;
        var map = claims || {};
        Object.keys(map).forEach(function (key) {
            var claim = map[key];
            if (claim && claim.runtime && d.exports && d.exports.destroy) {
                try {
                    d.exports.destroy(claim.runtime);
                } catch (e) {
                    noteFailure('dynamic destroy runtime[' + key + ']', e);
                }
            }
        });
    }

    function dynamicDestroyRuntime() {
        var d = state.dynamic;
        dynamicDestroyThreadClaims(d.threadClaims);
        d.runtime = null;
        d.sourceBase = 0;
        d.sourceSize = 0;
        d.recentBlocks = [];
        d.threadClaims = {};
        d.pendingThreads = {};
        d.bridgeGlobals = {};
    }

    function dynamicResolveExport(handle, symbol, retType, argTypes) {
        var sym = translatedResolveSymbol(handle, symbol);
        if (!sym) throw new Error('missing dynamic export: ' + symbol);
        return new NativeFunction(sym, retType, argTypes);
    }

    function dynamicLoad(libPath) {
        var d = state.dynamic;
        console.log('[CAPTURE] [GATE] dynamic load stage=resolve_libdl');
        d.lastLoadStage = 'resolve_libdl';
        var dl = translatedGetLibdl();
        console.log('[CAPTURE] [GATE] dynamic load stage=dlopen so=' + libPath);
        d.lastLoadStage = 'dlopen';
        var handle = dl.dlopen(Memory.allocUtf8String(libPath), 2);
        if (handle.isNull()) {
            var errPtr = dl.dlerror();
            var errMsg = errPtr && !errPtr.isNull() ? (errPtr.readUtf8String() || '<null>') : '<unknown>';
            throw new Error('dlopen failed: ' + libPath + ' err=' + errMsg);
        }
        console.log('[CAPTURE] [GATE] dynamic load stage=resolve_exports');
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
            runOut: dynamicResolveExport(handle, 'aeon_dyn_runtime_run_out', 'uint32', ['pointer', 'pointer', 'pointer']),
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
            argX0: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_arg_x0'),
            argX1: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_arg_x1'),
            argX18: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_arg_x18'),
            argX19: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_arg_x19'),
            argX21: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_arg_x21'),
            argX28: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_arg_x28'),
            argSp: translatedResolveSymbol(handle, 'aeon_dyn_branch_bridge_arg_sp'),
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
        console.log('[CAPTURE] [GATE] dynamic load stage=done');
        return {
            loaded: true,
            libPath: libPath,
        };
    }

    function dynamicReadU64Symbol(sym) {
        if (!sym || sym.isNull()) return null;
        try {
            return readWordExact(sym).toString();
        } catch (e) {
            return null;
        }
    }

    function dynamicBridgeScratchState(threadId) {
        var d = state.dynamic;
        if (threadId === null || threadId === undefined) return null;
        var pending = d.pendingThreads ? d.pendingThreads[String(threadId)] : null;
        if (!pending || !pending.ctxPtr || pending.ctxPtr.isNull()) return null;
        try {
            var scratchSize = d.exports && d.exports.bridgeScratchSize ? Number(d.exports.bridgeScratchSize()) : 0;
            if (!scratchSize) return null;
            var scratchBase = pending.ctxPtr.sub(scratchSize);
            return {
                scratch_base: scratchBase.toString(),
                thread_stage_addr: scratchBase.add(AEON_SCRATCH_STAGE).toString(),
                thread_stage: readWordExact(scratchBase.add(AEON_SCRATCH_STAGE)).toString(),
                thread_last_target_addr: scratchBase.add(AEON_SCRATCH_LAST_TARGET).toString(),
                thread_last_target: readWordExact(scratchBase.add(AEON_SCRATCH_LAST_TARGET)).toString(),
                thread_tail_mode_addr: scratchBase.add(AEON_SCRATCH_TAIL_MODE).toString(),
                thread_tail_mode: readWordExact(scratchBase.add(AEON_SCRATCH_TAIL_MODE)).toString(),
                thread_saved_x30_addr: scratchBase.add(AEON_SCRATCH_SAVED_X30).toString(),
                thread_saved_x30: readWordExact(scratchBase.add(AEON_SCRATCH_SAVED_X30)).toString(),
                thread_outgoing_x30_addr: scratchBase.add(AEON_SCRATCH_DBG_OUTGOING_X30).toString(),
                thread_outgoing_x30: readWordExact(scratchBase.add(AEON_SCRATCH_DBG_OUTGOING_X30)).toString(),
                thread_post_call_x30_addr: scratchBase.add(AEON_SCRATCH_DBG_POST_CALL_X30).toString(),
                thread_post_call_x30: readWordExact(scratchBase.add(AEON_SCRATCH_DBG_POST_CALL_X30)).toString(),
                thread_resume_target_addr: scratchBase.add(AEON_SCRATCH_DBG_RESUME_TARGET).toString(),
                thread_resume_target: readWordExact(scratchBase.add(AEON_SCRATCH_DBG_RESUME_TARGET)).toString(),
                thread_ctx_pc_addr: scratchBase.add(AEON_SCRATCH_DBG_CTX_PC).toString(),
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
            stage_addr: g.stage ? g.stage.toString() : null,
            stage: dynamicReadU64Symbol(g.stage),
            last_target_addr: g.lastTarget ? g.lastTarget.toString() : null,
            last_target: dynamicReadU64Symbol(g.lastTarget),
            saved_x30_addr: g.savedX30 ? g.savedX30.toString() : null,
            saved_x30: dynamicReadU64Symbol(g.savedX30),
            tail_mode_addr: g.tailMode ? g.tailMode.toString() : null,
            tail_mode: dynamicReadU64Symbol(g.tailMode),
            arg_x0_addr: g.argX0 ? g.argX0.toString() : null,
            arg_x0: dynamicReadU64Symbol(g.argX0),
            arg_x1_addr: g.argX1 ? g.argX1.toString() : null,
            arg_x1: dynamicReadU64Symbol(g.argX1),
            arg_x18_addr: g.argX18 ? g.argX18.toString() : null,
            arg_x18: dynamicReadU64Symbol(g.argX18),
            arg_x19_addr: g.argX19 ? g.argX19.toString() : null,
            arg_x19: dynamicReadU64Symbol(g.argX19),
            arg_x21_addr: g.argX21 ? g.argX21.toString() : null,
            arg_x21: dynamicReadU64Symbol(g.argX21),
            arg_x28_addr: g.argX28 ? g.argX28.toString() : null,
            arg_x28: dynamicReadU64Symbol(g.argX28),
            arg_sp_addr: g.argSp ? g.argSp.toString() : null,
            arg_sp: dynamicReadU64Symbol(g.argSp),
            outgoing_x30_addr: g.outgoingX30 ? g.outgoingX30.toString() : null,
            outgoing_x30: dynamicReadU64Symbol(g.outgoingX30),
            post_call_x30_addr: g.postCallX30 ? g.postCallX30.toString() : null,
            post_call_x30: dynamicReadU64Symbol(g.postCallX30),
            resume_target_addr: g.resumeTarget ? g.resumeTarget.toString() : null,
            resume_target: dynamicReadU64Symbol(g.resumeTarget),
            ctx_pc_addr: g.ctxPc ? g.ctxPc.toString() : null,
            ctx_pc: dynamicReadU64Symbol(g.ctxPc),
            ctx_addr: g.ctx ? g.ctx.toString() : null,
            ctx: dynamicReadU64Symbol(g.ctx),
            host_sp_addr: g.hostSp ? g.hostSp.toString() : null,
            host_sp: dynamicReadU64Symbol(g.hostSp),
            code_start_addr: g.codeStart ? g.codeStart.toString() : null,
            code_start: dynamicReadU64Symbol(g.codeStart),
            code_end_addr: g.codeEnd ? g.codeEnd.toString() : null,
            code_end: dynamicReadU64Symbol(g.codeEnd),
        };
        var scratch = dynamicBridgeScratchState(threadId);
        if (scratch) {
            Object.keys(scratch).forEach(function (k) {
                out[k] = scratch[k];
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

    function dynamicModuleOffset(value) {
        try {
            var p = normalizeWordPtr(value);
            if (p.isNull()) return null;
            var mod = Process.findModuleByAddress(p);
            if (!mod) return null;
            return {
                module: mod.name || null,
                offset: u64Number(p.sub(mod.base)),
            };
        } catch (e) {
            return null;
        }
    }

    function readWordMaybe(addr) {
        try {
            return readWordExact(addr).toString();
        } catch (e) {
            return null;
        }
    }

    function readU16Maybe(addr) {
        try {
            return ptr(addr).readU16();
        } catch (e) {
            return null;
        }
    }

    function dynamicInspectResumeFrame(ctxPtr, finalPc, threadId) {
        var info = dynamicModuleOffset(finalPc);
        if (!info || info.module !== 'libart.so') return null;
        var fp = readWordExact(ctxPtr.add(translatedOffsetX(29)));
        var sp = readWordExact(ctxPtr.add(translatedOffsetSp()));
        var lr = readWordExact(ctxPtr.add(translatedOffsetX(30)));
        var x4 = readWordExact(ctxPtr.add(translatedOffsetX(4)));
        var x5 = readWordExact(ctxPtr.add(translatedOffsetX(5)));
        var x22 = readWordExact(ctxPtr.add(translatedOffsetX(22)));
        var x24 = readWordExact(ctxPtr.add(translatedOffsetX(24)));
        var out = {
            thread: threadId,
            final_pc: fmtPtr(finalPc),
            module: info.module,
            module_offset: '0x' + info.offset.toString(16),
            fp: fp.toString(),
            sp: sp.toString(),
            lr: lr.toString(),
            x4: x4.toString(),
            x5: x5.toString(),
        };
        if (info.offset === 0x218968 || info.offset === 0x218bec) {
            out.kind = (info.offset === 0x218968) ? 'art_quick_invoke_stub_epilogue' : 'art_quick_invoke_static_stub_epilogue';
            out.frame_x4 = readWordMaybe(fp.add(0));
            out.frame_x5 = readWordMaybe(fp.add(8));
            out.frame_x19 = readWordMaybe(fp.add(16));
            out.frame_x20 = readWordMaybe(fp.add(24));
            out.frame_fp = readWordMaybe(fp.add(32));
            out.frame_lr = readWordMaybe(fp.add(40));
            out.frame_x5_cstr = out.frame_x5 ? readUtf8Maybe(ptr(out.frame_x5), 32) : null;
            out.ret_target = out.frame_lr;
        } else if (info.offset === 0x212524) {
            out.kind = 'NterpCommonInvokeInstance_resume';
            out.x22 = x22.toString();
            out.x24 = x24.toString();
            out.nterp_word_6 = readU16Maybe(x22.add(6));
            out.nterp_word_8 = readU16Maybe(x22.add(8));
            out.nterp_dispatch_base = x24.toString();
        } else {
            return null;
        }
        console.log('[CAPTURE] [GATE] native-resume frame ' + JSON.stringify(out));
        return out;
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
        console.log('[CAPTURE] [GATE] dynamic bailout thread=' + threadId +
            ' target=' + target +
            ' resume=' + resumePc +
            ' ctx_pc=' + (bridgeState.thread_ctx_pc || bridgeState.ctx_pc || '<none>'));
        translatedApplyContext(pending.ctxPtr, details.context, resumePc);
        delete d.pendingThreads[String(threadId)];
        dynamicDisableClaim(threadId, 'non-callable-target', target, resumePc);
        var currentRange = (state.currentBase && state.currentSize)
            ? (findExecRangeFor(state.currentBase) || chooseTrapRange())
            : null;
        if (currentRange) {
            ensureTrapProtection(currentRange);
        }
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

    function dynamicInstallCallbacks() {
        var d = state.dynamic;
        if (d.callbacks.blockEnter) return;
        d.callbacks.memRead = new NativeCallback(function (addr) {
            if (d.logReads) console.log('[CAPTURE] [GATE] dynamic read addr=' + ptr(addr));
        }, 'void', ['uint64']);
        d.callbacks.memWrite = new NativeCallback(function (addr, size, value) {
            if (d.logWrites) {
                console.log('[CAPTURE] [GATE] dynamic write addr=' + ptr(addr) +
                    ' size=' + Number(size) + ' value=0x' + u64Number(value).toString(16));
            }
        }, 'void', ['uint64', 'uint8', 'uint64']);
        d.callbacks.blockEnter = new NativeCallback(function (blockId) {
            var blockIdNum = u64Number(blockId);
            var sourceNum = 0;
            try {
                if (d.exports.lookupBlockSource) {
                    Object.keys(d.threadClaims || {}).some(function (key) {
                        var claim = d.threadClaims[key];
                        if (!claim || !claim.runtime) return false;
                        var candidate = u64Number(d.exports.lookupBlockSource(claim.runtime, blockIdNum));
                        if (candidate) {
                            sourceNum = candidate;
                            return true;
                        }
                        return false;
                    });
                }
            } catch (e) {}
            var record = {
                block_id: '0x' + blockIdNum.toString(16),
                source_block: sourceNum ? ('0x' + sourceNum.toString(16)) : null,
            };
            pushLimited(d.recentBlocks, record, 128);
            if (d.logBlocks) {
                console.log('[CAPTURE] [GATE] dynamic block id=' + record.block_id +
                    (record.source_block ? ' source=' + record.source_block : ' source=<unknown>'));
            }
        }, 'void', ['uint64']);
    }

    function dynamicEnsureRuntime(threadId) {
        var d = state.dynamic;
        var nullPtr = ptr(0);
        var key = threadKey(threadId);
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
        if (claim.runtime && claim.sourceBase === base && claim.sourceSize === size) {
            d.runtime = claim.runtime;
            d.sourceBase = base;
            d.sourceSize = size;
            console.log('[CAPTURE] [GATE] dynamic runtime reuse thread=' + key +
                ' base=0x' + base.toString(16) +
                ' size=0x' + size.toString(16) +
                ' maxSteps=' + d.maxSteps);
            d.exports.setMaxSteps(claim.runtime, d.maxSteps);
            d.exports.setCodeRange(claim.runtime, base, base + size);
            return claim;
        }
        if (claim.runtime && d.exports && d.exports.destroy) {
            try {
                d.exports.destroy(claim.runtime);
            } catch (e) {
                noteFailure('dynamic destroy runtime[' + key + ']', e);
            }
            claim.runtime = null;
        }
        console.log('[CAPTURE] [GATE] dynamic runtime create begin thread=' + key +
            ' base=0x' + base.toString(16) +
            ' size=0x' + size.toString(16) +
            ' maxSteps=' + d.maxSteps);
        dynamicInstallCallbacks();
        console.log('[CAPTURE] [GATE] dynamic runtime callbacks installed');
        var runtime = d.exports.create(base, size);
        if (!runtime || runtime.isNull()) throw new Error('aeon_dyn_runtime_create failed');
        console.log('[CAPTURE] [GATE] dynamic runtime create ok ptr=' + runtime);
        claim.runtime = runtime;
        claim.sourceBase = base;
        claim.sourceSize = size;
        d.runtime = runtime;
        d.sourceBase = base;
        d.sourceSize = size;
        d.exports.setMaxSteps(runtime, d.maxSteps);
        console.log('[CAPTURE] [GATE] dynamic runtime setMaxSteps ok');
        d.exports.setCodeRange(runtime, base, base + size);
        console.log('[CAPTURE] [GATE] dynamic runtime setCodeRange ok');
        d.exports.setMemRead(runtime, d.logReads ? d.callbacks.memRead : nullPtr);
        console.log('[CAPTURE] [GATE] dynamic runtime setMemRead ' + (d.logReads ? 'callback' : 'null'));
        d.exports.setMemWrite(runtime, d.logWrites ? d.callbacks.memWrite : nullPtr);
        console.log('[CAPTURE] [GATE] dynamic runtime setMemWrite ' + (d.logWrites ? 'callback' : 'null'));
        d.exports.setBranchTranslate(runtime, d.nativeBranchTranslate);
        console.log('[CAPTURE] [GATE] dynamic runtime setBranchTranslate native=' + d.nativeBranchTranslate);
        d.exports.setBranchBridge(runtime, d.nativeBranchBridge);
        console.log('[CAPTURE] [GATE] dynamic runtime setBranchBridge native=' + d.nativeBranchBridge);
        d.exports.setBlockEnter(runtime, nullPtr);
        console.log('[CAPTURE] [GATE] dynamic runtime setBlockEnter null');
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

    function dynamicIsZeroTrapCandidate(cpuCtx) {
        if (!cpuCtx || !cpuCtx.pc) return false;
        try {
            return ptr(cpuCtx.pc).readU32() === 0;
        } catch (e) {
            return false;
        }
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
        console.log('[CAPTURE] [GATE] dynamic dispatch enter start=0x' + startPc.toString(16));
        var claim = dynamicEnsureRuntime(threadId);
        claim.first_pc = claim.first_pc || ('0x' + startPc.toString(16));
        console.log('[CAPTURE] [GATE] dynamic dispatch runtime-ready thread=' + threadKey(threadId) +
            ' ptr=' + claim.runtime);
        var scratchSize = dynamicBridgeScratchSize();
        var allocSize = scratchSize + translatedJitContextSize();
        var ctxAlloc = Memory.alloc(allocSize);
        var ctxPtr = ctxAlloc.add(scratchSize);
        console.log('[CAPTURE] [GATE] dynamic dispatch alloc ctx alloc=0x' +
            allocSize.toString(16) + ' scratch=0x' + scratchSize.toString(16) +
            ' ctx=' + ctxPtr + ' base=' + ctxAlloc);
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
        console.log('[CAPTURE] [GATE] dynamic dispatch handoff runtime=' + normalizeWordPtr(claim.runtime) +
            ' ctx=' + normalizeWordPtr(ctxPtr) +
            ' result=' + normalizeWordPtr(resultPtr) +
            ' orig_x0=' + normalizeWordPtr(cpuCtx.x0) +
            ' orig_pc=' + normalizeWordPtr(cpuCtx.pc) +
            ' orig_x30=' + normalizeWordPtr(cpuCtx.lr));
        console.log('[CAPTURE] [GATE] dynamic dispatch set regs begin x0=' + handoffPtr +
            ' pc=' + d.resumeTrampoline);
        cpuCtx.x0 = handoffPtr;
        console.log('[CAPTURE] [GATE] dynamic dispatch set x0 ok');
        cpuCtx.pc = d.resumeTrampoline;
        console.log('[CAPTURE] [GATE] dynamic dispatch set pc ok');
        console.log('[CAPTURE] [GATE] dynamic dispatch armed trampoline=' + d.resumeTrampoline +
            ' brkImm=0x' + d.resumeBrkImm.toString(16) +
            ' thread=' + threadId +
            ' resultSize=0x' + resultSize.toString(16) +
            ' bridgeStage=' + (dynamicBridgeState().stage || '<null>'));
        return {
            armed: true,
            startPc: '0x' + startPc.toString(16),
            thread_id: threadId,
        };
    }

    function dynamicFinishResumeTrap(details, trap) {
        var d = state.dynamic;
        var raw = dynamicParseResult(trap.pending.resultPtr);
        console.log('[CAPTURE] [GATE] dynamic resume trap parsed raw start=0x' +
            raw.start_pc.toString(16) + ' final=0x' + raw.final_pc.toString(16) +
            ' steps=' + raw.steps + ' compiled=' + raw.compiled_blocks +
            ' info=0x' + raw.info_pc.toString(16));
        translatedApplyContext(trap.pending.ctxPtr, details.context, raw.final_pc);
        var stopCode = raw.stop_code;
        var stopName = 'unknown';
        if (stopCode === 0) stopName = 'halted';
        else if (stopCode === 1) stopName = 'max_steps';
        else if (stopCode === 2) stopName = 'code_range_exit';
        else if (stopCode === 3) stopName = 'lift_error';
        else if (stopCode === 0xffffffff) stopName = 'invalid_argument';
        var result = {
            startPc: '0x' + trap.pending.startPc.toString(16),
            finalPc: '0x' + raw.final_pc.toString(16),
            steps: Number(raw.steps),
            compiled_blocks: Number(raw.compiled_blocks),
            stop_code: Number(stopCode),
            stop: stopName,
            info_pc: raw.info_pc ? ('0x' + raw.info_pc.toString(16)) : null,
            handoff: stopCode === 2,
            recent_blocks: d.recentBlocks.slice(-Math.min(Number(raw.steps) + 4, 32)),
        };
        delete d.pendingThreads[String(trap.threadId)];
        d.lastRun = result;
        pushLimited(d.runs, result, 32);
        var currentRange = (state.currentBase && state.currentSize)
            ? (findExecRangeFor(state.currentBase) || chooseTrapRange())
            : null;
        if (currentRange) {
            ensureTrapProtection(currentRange);
        }
        var finalPcNum = raw.final_pc;
        var currentBaseNum = state.currentBase ? u64Number(state.currentBase) : 0;
        var currentSizeNum = state.currentSize || 0;
        if (finalPcNum && currentBaseNum &&
            finalPcNum >= currentBaseNum &&
            finalPcNum < (currentBaseNum + currentSizeNum)) {
            activatePage(pageBaseFor(ptr('0x' + finalPcNum.toString(16))));
        } else if (stopCode === 2 && finalPcNum) {
            try {
                dynamicInspectResumeFrame(trap.pending.ctxPtr, ptr('0x' + finalPcNum.toString(16)), trap.threadId);
            } catch (e) {
                noteFailure('dynamic inspect resume frame', e);
            }
            installNativeChainHooks();
            rememberNativeResume(trap.threadId, ptr('0x' + finalPcNum.toString(16)), {
                start_pc: result.startPc,
                stop: result.stop,
                steps: result.steps,
            });
        }
        console.log('[CAPTURE] [GATE] dynamic resume trap final=' + result.finalPc +
            ' steps=' + result.steps +
            ' stop=' + result.stop);
        return result;
    }

    function memdumpWriteFile(path, addr, size) {
        var lc = memdumpGetLibc();
        var fd = memdumpOpenWrite(path);
        if (fd < 0) return false;
        var p = ptr(addr);
        var written = 0;
        while (written < size) {
            var chunk = Math.min(MEMDUMP_CHUNK, size - written);
            try {
                var n = lc.write(fd, p.add(written), chunk);
                if (n <= 0) break;
                written += n;
            } catch (e) {
                break;
            }
        }
        lc.close(fd);
        return written;
    }

    function memdumpWriteStr(path, str) {
        var lc = memdumpGetLibc();
        var fd = memdumpOpenWrite(path);
        if (fd < 0) return false;
        var buf = Memory.allocUtf8String(str);
        lc.write(fd, buf, str.length);
        lc.close(fd);
        return true;
    }

    function snapshotTrapWindow(range) {
        if (!state.currentBase || !state.currentSize) return null;
        try {
            memdumpMkdir('/data/local/tmp/aeon_capture');
            memdumpMkdir(TRAP_WINDOW_DEVICE_DIR);
            var seq = ++state.trapSnapshotSeq;
            var baseHex = fmtPtr(state.currentBase).replace(/^0x/, '');
            var stamp = (new Date()).toISOString().replace(/[^0-9]/g, '').slice(0, 17);
            var stem = 'pid' + Process.id +
                '_base_' + baseHex +
                '_size_' + state.currentSize.toString(16) +
                '_seq_' + seq +
                '_ts_' + stamp;
            var binPath = TRAP_WINDOW_DEVICE_DIR + '/' + stem + '.bin';
            var metaPath = TRAP_WINDOW_DEVICE_DIR + '/' + stem + '.json';
            var bytes = state.currentBase.readByteArray(state.currentSize);
            var sha256 = sha256Hex(bytes);
            var written = memdumpWriteFile(binPath, state.currentBase, state.currentSize);
            var meta = {
                pid: Process.id,
                timestamp: (new Date()).toISOString(),
                base: fmtPtr(state.currentBase),
                size: state.currentSize,
                file: filePathFor(range),
                sha256: sha256,
                bytes_written: written,
                path: binPath,
            };
            memdumpWriteStr(metaPath, JSON.stringify(meta, null, 2));
            state.trapSnapshots.push(meta);
            if (state.trapSnapshots.length > 32) {
                state.trapSnapshots.shift();
            }
            return meta;
        } catch (e) {
            noteFailure('snapshot trap window ' + fmtPtr(state.currentBase), e);
            return null;
        }
    }

    function writeFreezeStatus(status) {
        memdumpMkdir('/data/local/tmp/aeon_capture');
        memdumpWriteStr(FREEZE_STATUS_PATH, JSON.stringify(status, null, 2));
    }

    function memdumpReadMaps() {
        var lc = memdumpGetLibc();
        var fd = lc.open(Memory.allocUtf8String('/proc/self/maps'), 0, 0);
        if (fd < 0) return [];
        var buf = Memory.alloc(0x100000);
        var total = 0;
        while (true) {
            var n = lc.read(fd, buf.add(total), 0x100000 - total);
            if (n <= 0) break;
            total += n;
            if (total >= 0x100000) break;
        }
        lc.close(fd);
        if (total === 0) return [];
        var text = buf.readUtf8String(total);
        var lines = text.split('\n');
        var regions = [];
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (!line) continue;
            var m = line.match(/^([0-9a-f]+)-([0-9a-f]+)\s+([rwxsp-]{4})\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)/);
            if (!m) continue;
            var start = uint64('0x' + m[1]);
            var end = uint64('0x' + m[2]);
            var size = end.sub(start).toNumber();
            regions.push({
                base: '0x' + m[1],
                end: '0x' + m[2],
                size: size,
                perms: m[3],
                offset: '0x' + m[4],
                file_path: m[5] || '',
            });
        }
        return regions;
    }

    function captureRegs(ctx) {
        var regs = { pc: fmtPtr(ctx.pc), sp: fmtPtr(ctx.sp) };
        for (var i = 0; i <= 28; i++) {
            regs['x' + i] = fmtPtr(ctx['x' + i]);
        }
        regs.x29 = fmtPtr(ctx.fp);
        regs.x30 = fmtPtr(ctx.lr);
        try {
            regs.nzcv = '' + ctx.nzcv;
        } catch (e) {}
        var simd = {};
        var hasSIMD = false;
        for (var q = 0; q <= 31; q++) {
            try {
                var val = ctx['q' + q];
                if (val !== undefined && val !== null) {
                    if (val instanceof ArrayBuffer || (val.byteLength !== undefined)) {
                        var u8 = new Uint8Array(val);
                        var hex = '';
                        for (var b = 0; b < u8.length; b++) {
                            var h = u8[b].toString(16);
                            hex += h.length === 1 ? '0' + h : h;
                        }
                        simd['q' + q] = hex;
                    } else {
                        simd['q' + q] = val.toString();
                    }
                    hasSIMD = true;
                }
            } catch (e) {}
        }
        if (!hasSIMD) {
            for (var d = 0; d <= 31; d++) {
                try {
                    var dval = ctx['d' + d];
                    if (dval !== undefined && dval !== null) {
                        if (dval instanceof ArrayBuffer || (dval.byteLength !== undefined)) {
                            var du8 = new Uint8Array(dval);
                            var dhex = '';
                            for (var db = 0; db < du8.length; db++) {
                                var dh = du8[db].toString(16);
                                dhex += dh.length === 1 ? '0' + dh : dh;
                            }
                            simd['d' + d] = dhex;
                        } else {
                            simd['d' + d] = dval.toString();
                        }
                        hasSIMD = true;
                    }
                } catch (e) {}
            }
        }
        if (hasSIMD) regs.simd = simd;
        return regs;
    }

    function shouldDumpRegion(region) {
        var perms = region.perms;
        if (perms[0] !== 'r') return { dump: false, reason: 'not readable' };
        if (region.size > MEMDUMP_MAX_REGION) {
            var fp = region.file_path || '';
            if (fp.indexOf('jit-cache') >= 0) {
                return { dump: true, reason: 'jit-cache (override size limit)' };
            }
            return { dump: false, reason: 'too large (' + (region.size / (1024 * 1024)).toFixed(1) + 'MB)' };
        }
        if (region.size === 0) return { dump: false, reason: 'zero size' };
        return { dump: true, reason: null };
    }

    function regionFileName(base) {
        return base.replace('0x', '') + '.bin';
    }

    function doFullProcessSnapshot(label, ctx, threadId) {
        var t0 = Date.now();
        var subdir = MEMDUMP_DEVICE_DIR + '/' + label;
        console.log('[CAPTURE] [GATE] memdump START ' + label + ' -> ' + subdir);
        memdumpMkdir('/data/local/tmp/aeon_capture');
        memdumpMkdir(MEMDUMP_DEVICE_DIR);
        memdumpMkdir(subdir);

        var maps = memdumpReadMaps();
        console.log('[CAPTURE] [GATE] memdump maps: ' + maps.length + ' regions');

        var regs = ctx ? captureRegs(ctx) : null;
        var manifest = {
            label: label,
            timestamp: (new Date()).toISOString(),
            pid: Process.id,
            arch: Process.arch,
            pointer_size: Process.pointerSize,
            faulting_pc: ctx ? fmtPtr(ctx.pc) : null,
            thread_id: threadId || null,
            registers: regs,
            regions: [],
            summary: { total: 0, dumped: 0, skipped: 0, bytes: 0, errors: 0 },
        };

        for (var i = 0; i < maps.length; i++) {
            var region = maps[i];
            var decision = shouldDumpRegion(region);
            var entry = {
                base: region.base,
                end: region.end,
                size: region.size,
                perms: region.perms,
                offset: region.offset,
                file_path: region.file_path,
                dumped: false,
                dump_file: null,
                dump_size: 0,
                skip_reason: decision.reason,
            };
            manifest.summary.total++;

            if (decision.dump) {
                var fname = regionFileName(region.base);
                var fpath = subdir + '/' + fname;
                try {
                    var written = memdumpWriteFile(fpath, region.base, region.size);
                    if (written > 0) {
                        entry.dumped = true;
                        entry.dump_file = fname;
                        entry.dump_size = written;
                        manifest.summary.dumped++;
                        manifest.summary.bytes += written;
                    } else {
                        entry.skip_reason = 'write returned 0';
                        manifest.summary.errors++;
                    }
                } catch (e) {
                    entry.skip_reason = 'error: ' + String(e);
                    manifest.summary.errors++;
                }
            } else {
                manifest.summary.skipped++;
            }
            manifest.regions.push(entry);
        }

        var elapsed = Date.now() - t0;
        manifest.summary.elapsed_ms = elapsed;
        var manifestPath = MEMDUMP_DEVICE_DIR + '/' + label + '_manifest.json';
        memdumpWriteStr(manifestPath, JSON.stringify(manifest, null, 2));

        console.log('[CAPTURE] [GATE] memdump DONE ' + label +
                     ' regions=' + manifest.summary.dumped + '/' + manifest.summary.total +
                     ' bytes=' + (manifest.summary.bytes / (1024 * 1024)).toFixed(1) + 'MB' +
                     ' errors=' + manifest.summary.errors +
                     ' elapsed=' + elapsed + 'ms');
        return manifest;
    }

    function pushEvent(event) {
        if (state.events.length >= state.maxEvents) {
            state.events.shift();
            state.drops++;
        }
        state.events.push(event);
    }

    function record(label, ctx, extra) {
        var event = {
            seq: ++state.seq,
            label: label,
            pc: fmtPtr(ctx.pc),
            lr: fmtPtr(ctx.lr),
            x0: fmtPtr(ctx.x0),
            x1: fmtPtr(ctx.x1),
            x8: fmtPtr(ctx.x8),
            x21: fmtPtr(ctx.x21),
            x22: fmtPtr(ctx.x22),
            x25: fmtPtr(ctx.x25),
            x27: fmtPtr(ctx.x27),
        };
        if (extra) {
            Object.keys(extra).forEach(function (key) {
                event[key] = extra[key];
            });
        }
        pushEvent(event);
    }

    function noteFailure(label, error) {
        var stack = null;
        try { stack = error && error.stack ? String(error.stack) : null; } catch (e) {}
        state.failures.push({
            label: label,
            error: String(error),
            stack: stack,
        });
        if (state.failures.length > 32) {
            state.failures.shift();
        }
        console.log('[CAPTURE] [GATE] ' + label + ' failed: ' + error + (stack ? (' stack=' + stack) : ''));
    }

    function untagPtr(value) {
        try {
            return ptr(value).and(PTR_MASK);
        } catch (e) {
            return ptr('0');
        }
    }

    function pageBaseFor(value) {
        try {
            return untagPtr(value).and(PAGE_MASK);
        } catch (e) {
            return ptr('0');
        }
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
        EXEC_PROTECTIONS.forEach(function (prot) {
            try {
                Process.enumerateRanges(prot).forEach(function (range) {
                    var protection = range.protection || prot;
                    if (protection.indexOf('w') !== -1) return;
                    var key = range.base.toString() + ':' + range.size.toString();
                    if (seen[key]) return;
                    seen[key] = true;
                    out.push(range);
                });
            } catch (e) {
                noteFailure('enumerate exec ranges ' + prot, e);
            }
        });
        return out;
    }

    function findExecRangeFor(addr) {
        var p = ptr(addr);
        var ranges = enumerateExecRanges();
        for (var i = 0; i < ranges.length; i++) {
            var r = ranges[i];
            if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) {
                return r;
            }
        }
        return null;
    }

    function isTrapCandidate(range) {
        var path = filePathFor(range);
        if (!path) return false;
        if (path.indexOf('jit-cache') >= 0) return true;
        if (path.indexOf('/data/data/com.netmarble.thered/files/') >= 0 &&
            path.indexOf('(deleted)') >= 0) {
            return true;
        }
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

    function pushException(event) {
        state.exceptions.push(event);
        if (state.exceptions.length > 32) {
            state.exceptions.shift();
        }
    }

    function bumpTrapCount(addr) {
        var key = addr ? String(addr) : 'null';
        var count = (state.trapCounts[key] || 0) + 1;
        state.trapCounts[key] = count;
        return count;
    }

    function bumpMapCount(map, key) {
        var count = (map[key] || 0) + 1;
        map[key] = count;
        return count;
    }

    function sortedMapEntries(map, label, limit) {
        var maxItems = parseInt(limit || 16, 10);
        if (!(maxItems > 0)) maxItems = 16;
        return Object.keys(map)
            .map(function (key) {
                var item = { hits: map[key] };
                item[label] = key;
                return item;
            })
            .sort(function (a, b) { return b.hits - a.hits; })
            .slice(0, maxItems);
    }

    function pushLimited(list, item, maxItems, onDrop) {
        if (list.length >= maxItems) {
            list.shift();
            if (typeof onDrop === 'function') onDrop();
        }
        list.push(item);
    }

    function currentThreadIdMaybe() {
        try {
            return Process.getCurrentThreadId();
        } catch (e) {
            return null;
        }
    }

    function threadNameMaybe(threadId) {
        if (threadId === null || threadId === undefined) return null;
        try {
            var text = readTextFile('/proc/self/task/' + threadId + '/comm');
            if (text === null || text === undefined) return null;
            text = String(text).trim();
            return text.length > 0 ? text : null;
        } catch (e) {
            return null;
        }
    }

    function isBackgroundArtThreadName(name) {
        if (!name) return false;
        return name === 'Profile Saver' ||
               name === 'HeapTaskDaemon' ||
               name === 'ReferenceQueueD' ||
               name.indexOf('CrashSight') === 0 ||
               name.indexOf('Jit thread pool') === 0;
    }

    function clearStalkerData() {
        state.stalker.drops = 0;
        state.stalker.events = [];
        state.stalker.pcHits = {};
        state.stalker.threadHits = {};
        state.stalker.blockCount = 0;
    }

    function clearPostResumeTraceData() {
        state.postResume.events = [];
        state.postResume.drops = 0;
        state.postResume.blockCount = 0;
    }

    function clearNativeChainResumes() {
        state.nativeChain.resumedThreads = {};
    }

    function pruneNativeChainResumes() {
        var now = nowMillis();
        Object.keys(state.nativeChain.resumedThreads).forEach(function (key) {
            var item = state.nativeChain.resumedThreads[key];
            if (!item || (item.expires_at_ms && item.expires_at_ms < now)) {
                delete state.nativeChain.resumedThreads[key];
            }
        });
    }

    function rememberNativeResume(threadId, finalPc, extra) {
        if (threadId === null || threadId === undefined) return;
        pruneNativeChainResumes();
        state.nativeChain.resumedThreads[String(threadId)] = Object.assign({
            thread_id: threadId,
            final_pc: fmtPtr(finalPc),
            remembered_at: (new Date()).toISOString(),
            expires_at_ms: nowMillis() + 15000,
        }, extra || {});
    }

    function nativeResumeForThread(threadId) {
        pruneNativeChainResumes();
        if (threadId === null || threadId === undefined) return null;
        return state.nativeChain.resumedThreads[String(threadId)] || null;
    }

    function logNativeChain(label, threadId, fields) {
        var parts = ['[CAPTURE] [GATE] native-chain', label, 'thread=' + threadId];
        Object.keys(fields || {}).forEach(function (key) {
            parts.push(key + '=' + fields[key]);
        });
        console.log(parts.join(' '));
    }

    function installNativeChainHooks() {
        if (state.nativeChain.hooksInstalled) return true;
        var libart = null;
        try {
            libart = Process.findModuleByName('libart.so');
        } catch (e) {
            noteFailure('native-chain libart lookup', e);
            return false;
        }
        if (!libart) return false;

        function addHook(name, offset, onEnter) {
            var addr = libart.base.add(offset);
            state.nativeChain.hooks[name] = Interceptor.attach(addr, {
                onEnter: function (args) {
                    var tid = currentThreadIdMaybe();
                    var resume = nativeResumeForThread(tid);
                    if (!resume) return;
                    try {
                        onEnter.call(this, args, tid, addr, resume);
                    } catch (e) {
                        noteFailure('native-chain hook ' + name, e);
                    }
                }
            });
        }

        addHook('art_quick_test_suspend', 0x221c80, function (args, tid, addr, resume) {
            logNativeChain('art_quick_test_suspend', tid, {
                pc: fmtPtr(addr),
                x30: fmtPtr(this.context.lr),
                x19: fmtPtr(this.context.x19),
                sp: fmtPtr(this.context.sp),
                resumed_from: resume.final_pc,
            });
        });

        addHook('art_quick_invoke_epilogue', 0x218968, function (args, tid, addr, resume) {
            var sp = ptr(this.context.sp);
            var savedX30 = readWordExact(sp.add(32));
            var retKind = readBytesMaybe(this.context.x5, 1);
            logNativeChain('art_quick_invoke_epilogue', tid, {
                pc: fmtPtr(addr),
                live_x30: fmtPtr(this.context.lr),
                saved_x30: fmtPtr(savedX30),
                x0: fmtPtr(this.context.x0),
                x4: fmtPtr(this.context.x4),
                x5: fmtPtr(this.context.x5),
                ret_kind: retKind || '<null>',
                resumed_from: resume.final_pc,
            });
        });

        addHook('art_quick_invoke_ret_x0', 0x218998, function (args, tid, addr, resume) {
            logNativeChain('art_quick_invoke_ret_x0', tid, {
                pc: fmtPtr(addr),
                x30: fmtPtr(this.context.lr),
                x0: fmtPtr(this.context.x0),
                resumed_from: resume.final_pc,
            });
        });

        addHook('art_quick_invoke_ret_d0', 0x2189a0, function (args, tid, addr, resume) {
            logNativeChain('art_quick_invoke_ret_d0', tid, {
                pc: fmtPtr(addr),
                x30: fmtPtr(this.context.lr),
                resumed_from: resume.final_pc,
            });
        });

        addHook('art_quick_invoke_ret_s0', 0x2189a8, function (args, tid, addr, resume) {
            logNativeChain('art_quick_invoke_ret_s0', tid, {
                pc: fmtPtr(addr),
                x30: fmtPtr(this.context.lr),
                resumed_from: resume.final_pc,
            });
        });

        state.nativeChain.hooksInstalled = true;
        console.log('[CAPTURE] [GATE] native-chain hooks installed libart=' + fmtPtr(libart.base));
        return true;
    }

    function stopPostResumeTrace(reason) {
        if (!state.postResume.active || state.postResume.threadId === null || state.postResume.threadId === undefined) {
            return false;
        }
        try {
            Stalker.unfollow(state.postResume.threadId);
            Stalker.garbageCollect();
            console.log('[CAPTURE] [GATE] post-resume stop thread=' + state.postResume.threadId +
                        ' reason=' + (reason || 'unspecified'));
        } catch (e) {
            noteFailure('post-resume stop thread=' + state.postResume.threadId, e);
        }
        state.postResume.active = false;
        state.postResume.threadId = null;
        state.postResume.startPc = null;
        state.postResume.startedAt = null;
        state.postResume.stopReason = reason || null;
        state.postResume.reason = null;
        return true;
    }

    function onPostResumePc(threadId, pc, context) {
        var info = describeAddr(pc);
        var lrInfo = describeAddr(context.lr);
        var last = state.postResume.events.length ? state.postResume.events[state.postResume.events.length - 1] : null;
        if (last && last.pc === info.addr && last.lr === lrInfo.addr) {
            last.count = (last.count || 1) + 1;
            return;
        }
        pushLimited(state.postResume.events, {
            seq: ++state.seq,
            threadId: threadId,
            pc: info.addr,
            module: info.module || null,
            offset: info.offset || null,
            symbol: info.symbol || null,
            lr: lrInfo.addr,
            lr_symbol: lrInfo.symbol || null,
            lr_module: lrInfo.module || null,
            count: 1,
        }, state.postResume.maxEvents, function () {
            state.postResume.drops++;
        });
        console.log('[CAPTURE] [GATE] post-resume pc=' + info.addr +
                    (info.module ? ' ' + info.module + '+' + info.offset : '') +
                    (info.symbol ? ' sym=' + info.symbol : '') +
                    ' lr=' + lrInfo.addr +
                    (lrInfo.symbol ? ' lr_sym=' + lrInfo.symbol : '') +
                    ' thread=' + threadId);
    }

    function startPostResumeTrace(threadId, startPc, reason) {
        if (threadId === null || threadId === undefined) return false;
        if (state.postResume.active) {
            console.log('[CAPTURE] [GATE] post-resume keep thread=' + state.postResume.threadId +
                        ' start=' + (state.postResume.startPc || '<none>') +
                        ' ignore_thread=' + threadId +
                        ' reason=' + (reason || 'unspecified'));
            return false;
        }
        clearPostResumeTraceData();
        state.postResume.active = true;
        state.postResume.threadId = threadId;
        state.postResume.startPc = fmtPtr(startPc);
        state.postResume.startedAt = (new Date()).toISOString();
        state.postResume.stopReason = null;
        state.postResume.reason = reason || null;
        try {
            Stalker.follow(threadId, {
                transform: function (iterator) {
                    var instruction = iterator.next();
                    if (instruction === null) return;
                    var blockHead = ptr(instruction.address);
                    state.postResume.blockCount++;
                    iterator.putCallout((function (capturedPc) {
                        return function (context) {
                            onPostResumePc(threadId, capturedPc, context);
                        };
                    })(blockHead));
                    iterator.keep();
                    instruction = iterator.next();
                    while (instruction !== null) {
                        iterator.keep();
                        instruction = iterator.next();
                    }
                }
            });
            var startInfo = describeAddr(startPc);
            console.log('[CAPTURE] [GATE] post-resume start thread=' + threadId +
                        ' start=' + startInfo.addr +
                        (startInfo.module ? ' ' + startInfo.module + '+' + startInfo.offset : '') +
                        (startInfo.symbol ? ' sym=' + startInfo.symbol : '') +
                        ' reason=' + (reason || 'unspecified'));
            return true;
        } catch (e) {
            noteFailure('post-resume follow thread=' + threadId, e);
            state.postResume.active = false;
            state.postResume.threadId = null;
            state.postResume.startPc = null;
            state.postResume.startedAt = null;
            state.postResume.stopReason = String(e);
            return false;
        }
    }

    function restoreExecProtection() {
        if (!state.currentBase || !state.currentSize) return true;
        try {
            Memory.protect(state.currentBase, state.currentSize, 'r-x');
            state.activePage = null;
            return true;
        } catch (e) {
            noteFailure('restore exec protection ' + fmtPtr(state.currentBase), e);
            return false;
        }
    }

    function reassertTrapProtectionIfArmed() {
        if (!state.currentBase || !state.currentSize) return false;
        if (!(state.translated.armed || state.dynamic.armed || state.stalker.armed ||
              state.freeze.armed || state.memdump.armed || state.fixedTraceArm)) {
            return false;
        }
        var currentRange = findExecRangeFor(state.currentBase) || chooseTrapRange();
        if (!currentRange) return false;
        ensureTrapProtection(currentRange);
        return true;
    }

    function stopStalker(reason) {
        if (!state.stalker.active || state.stalker.threadId === null || state.stalker.threadId === undefined) {
            state.stalker.pendingThreadId = null;
            return false;
        }
        try {
            Stalker.unfollow(state.stalker.threadId);
            Stalker.garbageCollect();
            console.log('[CAPTURE] [GATE] stalker stop thread=' + state.stalker.threadId + ' reason=' + (reason || 'unspecified'));
        } catch (e) {
            noteFailure('stalker stop thread=' + state.stalker.threadId, e);
        }
        state.stalker.active = false;
        state.stalker.pendingThreadId = null;
        state.stalker.threadId = null;
        state.stalker.startedAt = null;
        state.stalker.startReason = reason || null;
        return true;
    }

    function onStalkerPc(threadId, pc, context) {
        if (!isInsideTrappedJit(pc)) return;
        var pcKey = fmtPtr(pc);
        var threadKey = String(threadId);
        var hitCount = bumpMapCount(state.stalker.pcHits, pcKey);
        state.stalker.threadHits[threadKey] = bumpMapCount(state.stalker.threadHits, threadKey);
        if (hitCount === 1 || (STALKER_REPEAT_SAMPLE > 0 && (hitCount % STALKER_REPEAT_SAMPLE) === 0)) {
            pushLimited(state.stalker.events, {
                seq: ++state.seq,
                threadId: threadId,
                pc: pcKey,
                lr: fmtPtr(context.lr),
                sp: fmtPtr(context.sp),
                x0: fmtPtr(context.x0),
                x1: fmtPtr(context.x1),
                x8: fmtPtr(context.x8),
                count: hitCount,
            }, state.stalker.maxEvents, function () {
                state.stalker.drops++;
            });
            console.log('[CAPTURE] [GATE] stalker pc=' + pcKey +
                        ' thread=' + threadId +
                        ' lr=' + fmtPtr(context.lr) +
                        ' count=' + hitCount);
        }
    }

    function startStalkerForThread(threadId, reason) {
        if (threadId === null || threadId === undefined) return false;
        if (state.stalker.active && state.stalker.threadId === threadId) return true;
        stopStalker('switch');
        clearStalkerData();
        state.stalker.active = true;
        state.stalker.armed = false;
        state.stalker.pendingThreadId = null;
        state.stalker.threadId = threadId;
        state.stalker.startedAt = (new Date()).toISOString();
        state.stalker.startReason = reason || null;
        try {
            Stalker.follow(threadId, {
                transform: function (iterator) {
                    var instruction = iterator.next();
                    if (instruction === null) {
                        return;
                    }
                    var blockHead = ptr(instruction.address);
                    if (isInsideTrappedJit(blockHead)) {
                        state.stalker.blockCount++;
                        iterator.putCallout((function (capturedPc) {
                            return function (context) {
                                onStalkerPc(threadId, capturedPc, context);
                            };
                        })(blockHead));
                    }
                    iterator.keep();
                    instruction = iterator.next();
                    while (instruction !== null) {
                        iterator.keep();
                        instruction = iterator.next();
                    }
                }
            });
            console.log('[CAPTURE] [GATE] stalker start thread=' + threadId + ' reason=' + (reason || 'unspecified'));
            return true;
        } catch (e) {
            noteFailure('stalker follow thread=' + threadId, e);
            state.stalker.active = false;
            state.stalker.threadId = null;
            state.stalker.startedAt = null;
            state.stalker.startReason = null;
            return false;
        }
    }

    function scheduleStalkerForThread(threadId, reason) {
        if (threadId === null || threadId === undefined) return;
        if (!state.stalker.armed) return;
        if (state.stalker.active && state.stalker.threadId === threadId) return;
        if (state.stalker.pendingThreadId === threadId) return;
        state.stalker.pendingThreadId = threadId;
        setTimeout(function () {
            if (state.stalker.pendingThreadId !== threadId) return;
            state.stalker.pendingThreadId = null;
            startStalkerForThread(threadId, reason);
        }, 0);
    }

    function isInsideTrappedJit(addr) {
        if (!state.currentBase || !state.currentSize || addr === null || addr === undefined) return false;
        try {
            var p = untagPtr(addr);
            return p.compare(state.currentBase) >= 0 &&
                   p.compare(state.currentBase.add(state.currentSize)) < 0;
        } catch (e) {
            return false;
        }
    }

    function isTargetTrapException(details) {
        if (!details || details.type !== 'access-violation') return false;
        var memoryOp = details.memory ? details.memory.operation : null;
        if (memoryOp !== 'execute') return false;
        if (details.memory && isInsideTrappedJit(details.memory.address)) return true;
        if (details.address && isInsideTrappedJit(details.address)) return true;
        if (details.context && isInsideTrappedJit(details.context.pc)) return true;
        return false;
    }

    function activatePage(pageBase) {
        try {
            if (!pageBase || pageBase.equals(ptr('0'))) return false;
            if (state.activePage && !state.activePage.equals(pageBase)) {
                Memory.protect(state.activePage, PAGE_SIZE, 'r--');
            }
            Memory.protect(pageBase, PAGE_SIZE, 'r-x');
            state.activePage = pageBase;
            return true;
        } catch (e) {
            noteFailure('activate page ' + fmtPtr(pageBase), e);
            return false;
        }
    }

    function ensureTrapProtection(range) {
        try {
            var ok = Memory.protect(state.currentBase, state.currentSize, 'r--');
            var snapshot = snapshotTrapWindow(range);
            var event = {
                base: fmtPtr(state.currentBase),
                size: '0x' + state.currentSize.toString(16),
                file: filePathFor(range),
                protection: 'r--',
                ok: !!ok,
            };
            if (snapshot) {
                event.sha256 = snapshot.sha256;
                event.dump_path = snapshot.path;
                event.dump_written = snapshot.bytes_written;
            }
            state.protections.push(event);
            if (state.protections.length > 32) {
                state.protections.shift();
            }
            console.log('[CAPTURE] [GATE] protect jit ' + event.base +
                        ' size=' + event.size +
                        ' -> ' + event.protection +
                        ' ok=' + event.ok +
                        (event.sha256 ? (' sha256=' + event.sha256 + ' dump=' + event.dump_path) : ''));
            return ok;
        } catch (e) {
            noteFailure('protect jit ' + fmtPtr(range.base), e);
            return false;
        }
    }

    function describeCurrentRange() {
        if (!state.currentBase || !state.currentSize) return null;
        return {
            base: state.currentBase.toString(),
            size: state.currentSize,
            protection: state.stalker.armed ? 'r--' : 'r-x',
            file: state.currentFile,
        };
    }

    function topThreadIds(limit) {
        var maxThreads = parseInt(limit || 3, 10);
        if (!(maxThreads > 0)) maxThreads = 3;
        var ids = [];
        sortedMapEntries(state.threadHits, 'thread', maxThreads * 2 + 2).forEach(function (entry) {
            var tid = parseInt(entry.thread, 10);
            if (!(tid > 0)) return;
            if (ids.indexOf(tid) !== -1) return;
            ids.push(tid);
        });
        if (ids.length === 0 && state.stalker.threadId) {
            ids.push(parseInt(state.stalker.threadId, 10));
        }
        return ids.slice(0, maxThreads);
    }

    function selectedThreadIds(jsonThreads) {
        var requested = parseJsonMaybe(jsonThreads);
        var threadIds = [];
        if (Array.isArray(requested)) {
            requested.forEach(function (tid) {
                var threadId = parseInt(tid, 10);
                if (!(threadId > 0)) return;
                if (threadIds.indexOf(threadId) !== -1) return;
                threadIds.push(threadId);
            });
        }
        if (threadIds.length === 0) {
            threadIds = topThreadIds(3);
        }
        return threadIds;
    }

    function callCertValue(challenge) {
        if (typeof originalCallCertExport === 'function') {
            try {
                return originalCallCertExport(challenge) || '';
            } catch (e) {
                return 'ERR:' + e;
            }
        }
        var token = null;
        Java.performNow(function () {
            var r = null;
            try {
                var inst = Java.use('nmss.app.NmssSa').getInstObj();
                if (!inst) {
                    r = 'NO_INSTANCE';
                } else {
                    r = inst.getCertValue(challenge);
                    if (r) r = r.toString();
                }
            } catch (inner) {
                r = 'ERR:' + inner;
            }
            token = r || '';
        });
        return token;
    }

    function noHotThreadsTrace(challenge) {
        return {
            status: 'done',
            challenge: challenge,
            token: null,
            followed: [],
            blockCount: 0,
            pcHits: {},
            top: [],
            range: describeCurrentRange(),
            hotThreads: globalThis.__jitGateTraceTopThreads(8),
            error: 'no hot threads',
        };
    }

    function runFixedThreadTraceCore(challenge, threadIds) {
        if (!threadIds || threadIds.length === 0) {
            return noHotThreadsTrace(challenge);
        }

        var pcHits = {};
        var blockCount = 0;
        var token = null;
        var error = null;
        var followed = [];
        var previouslyArmed = !!state.stalker.armed;

        stopStalker('fixed trace');
        state.stalker.armed = false;
        state.stalker.pendingThreadId = null;
        restoreExecProtection();

        try {
            threadIds.forEach(function (tid) {
                var threadId = parseInt(tid, 10);
                if (!(threadId > 0)) return;
                followed.push(threadId);
                Stalker.follow(threadId, {
                    transform: function (iterator) {
                        var instruction = iterator.next();
                        if (instruction === null) {
                            return;
                        }
                        var blockHead = ptr(instruction.address);
                        if (isInsideTrappedJit(blockHead)) {
                            blockCount++;
                            iterator.putCallout((function (capturedPc) {
                                return function () {
                                    bumpMapCount(pcHits, capturedPc.toString());
                                };
                            })(blockHead));
                        }
                        iterator.keep();
                        instruction = iterator.next();
                        while (instruction !== null) {
                            iterator.keep();
                            instruction = iterator.next();
                        }
                    }
                });
            });
            token = callCertValue(challenge);
        } catch (e) {
            error = String(e);
        } finally {
            followed.forEach(function (threadId) {
                try { Stalker.unfollow(threadId); } catch (e) {}
            });
            try { Stalker.garbageCollect(); } catch (e) {}
            if (previouslyArmed && state.currentBase && state.currentSize) {
                state.stalker.armed = true;
                ensureTrapProtection(findExecRangeFor(state.currentBase) || chooseTrapRange());
            } else {
                restoreExecProtection();
            }
        }

        return {
            status: 'done',
            challenge: challenge,
            token: token,
            followed: followed,
            blockCount: blockCount,
            pcHits: pcHits,
            top: sortedMapEntries(pcHits, 'pc', 40),
            range: describeCurrentRange(),
            hotThreads: globalThis.__jitGateTraceTopThreads(8),
            error: error,
        };
    }

    function installForRange(range) {
        if (!range) return;
        restoreExecProtection();
        var maxSize = Math.min(range.size, ACTIVE_EXEC_SIZE);
        if (maxSize <= 0) {
            noteFailure('install corridor ' + fmtPtr(range.base), 'range too small');
            return;
        }
        var corridorBase = range.base;
        var corridorSize = maxSize;
        if (state.currentBase &&
            state.currentBase.equals(corridorBase) &&
            state.currentSize === corridorSize) {
            return;
        }
        state.currentBase = corridorBase;
        state.currentSize = corridorSize;
        state.currentFile = filePathFor(range);
        state.activePage = null;
        state.pageHits = {};
        state.pcHits = {};
        state.edgeHits = {};
        state.threadHits = {};
        state.trapCounts = {};
        stopStalker('corridor changed');
        clearStalkerData();
        if (state.stalker.armed) {
            ensureTrapProtection(range);
        }
        console.log('[CAPTURE] [GATE] installing for exec range base=' + range.base +
                    ' corridor=' + state.currentBase +
                    ' trap_size=0x' + state.currentSize.toString(16) +
                    ' file=' + (state.currentFile || ''));
    }

    globalThis.__jitGateTraceClear = function () {
        state.seq = 0;
        state.drops = 0;
        state.events.length = 0;
        state.pageHits = {};
        state.pcHits = {};
        state.edgeHits = {};
        state.threadHits = {};
        state.trapCounts = {};
        state.exceptions.length = 0;
        state.fixedTraceArm = null;
        state.fixedTrace = null;
        stopStalker('clear');
        clearStalkerData();
        state.activePage = null;
        if (state.currentBase && state.currentSize) {
            try {
                Memory.protect(state.currentBase, state.currentSize, state.stalker.armed ? 'r--' : 'r-x');
            } catch (e) {
                noteFailure('reset trap protection ' + fmtPtr(state.currentBase), e);
            }
        }
        return 'OK';
    };

    globalThis.__jitGateTraceTopPages = function (limit) {
        return sortedMapEntries(state.pageHits, 'page', limit || 8);
    };

    globalThis.__jitGateTraceTopThreads = function (limit) {
        return sortedMapEntries(state.threadHits, 'thread', limit || 8);
    };

    globalThis.__jitGateTraceTopEdges = function (limit) {
        return sortedMapEntries(state.edgeHits, 'edge', limit || 12);
    };

    globalThis.__jitGateHotThreads = function (limit) {
        return JSON.stringify(topThreadIds(limit || 3));
    };

    globalThis.__jitGateTraceScanHotPages = function (limit, minHits, pattern) {
        var maxPages = parseInt(limit || 8, 10);
        var minCount = parseInt(minHits || 1, 10);
        var matchPattern = pattern || 'fd 7b ?? a9';
        if (!(maxPages > 0)) maxPages = 8;
        if (!(minCount > 0)) minCount = 1;
        return JSON.stringify(globalThis.__jitGateTraceTopPages(maxPages)
            .filter(function (entry) { return entry.hits >= minCount; })
            .map(function (entry) {
                var pageBase = ptr(entry.page);
                var matches = [];
                try {
                    matches = Memory.scanSync(pageBase, PAGE_SIZE, matchPattern).map(function (hit) {
                        return {
                            address: hit.address.toString(),
                            page: entry.page,
                            hits: entry.hits,
                            bytes16: readBytesMaybe(hit.address, 16),
                        };
                    });
                } catch (e) {
                    matches.push({
                        page: entry.page,
                        hits: entry.hits,
                        error: String(e),
                    });
                }
                return {
                    page: entry.page,
                    hits: entry.hits,
                    matches: matches,
                };
            }));
    };

    globalThis.__jitGateTraceDump = function () {
        return JSON.stringify({
            currentBase: state.currentBase ? state.currentBase.toString() : null,
            currentSize: state.currentSize,
            currentFile: state.currentFile,
            activePage: state.activePage ? state.activePage.toString() : null,
            pageHits: state.pageHits,
            pcHits: state.pcHits,
            edgeHits: state.edgeHits,
            threadHits: state.threadHits,
            topPages: globalThis.__jitGateTraceTopPages(12),
            topThreads: globalThis.__jitGateTraceTopThreads(12),
            topEdges: globalThis.__jitGateTraceTopEdges(16),
            drops: state.drops,
            events: state.events,
            failures: state.failures,
            protections: state.protections,
            exceptions: state.exceptions,
            fixedTraceArm: state.fixedTraceArm,
            fixedTrace: state.fixedTrace,
            stalker: {
                active: state.stalker.active,
                armed: state.stalker.armed,
                pendingThreadId: state.stalker.pendingThreadId,
                threadId: state.stalker.threadId,
                startedAt: state.stalker.startedAt,
                startReason: state.stalker.startReason,
                blockCount: state.stalker.blockCount,
                drops: state.stalker.drops,
                events: state.stalker.events,
                pcHits: state.stalker.pcHits,
                threadHits: state.stalker.threadHits,
            },
        });
    };

    globalThis.__jitGateFixedThreadTraceRun = function (challenge, jsonThreads) {
        state.fixedTraceArm = null;
        state.fixedTrace = runFixedThreadTraceCore(challenge, selectedThreadIds(jsonThreads));
        return JSON.stringify(state.fixedTrace);
    };

    globalThis.__jitGateFixedThreadTraceArm = function (jsonThreads) {
        var threadIds = selectedThreadIds(jsonThreads);
        state.fixedTraceArm = {
            status: threadIds.length > 0 ? 'armed' : 'empty',
            armedAt: (new Date()).toISOString(),
            requested: threadIds,
            hotThreads: globalThis.__jitGateTraceTopThreads(8),
            range: describeCurrentRange(),
        };
        state.fixedTrace = null;
        return JSON.stringify(state.fixedTraceArm);
    };

    globalThis.__jitGateFixedThreadTraceStatus = function () {
        return JSON.stringify({
            armed: state.fixedTraceArm,
            trace: state.fixedTrace,
        });
    };

    globalThis.__jitGateFixedThreadTraceClear = function () {
        state.fixedTraceArm = null;
        state.fixedTrace = null;
        return 'OK';
    };

    globalThis.__jitGateStalkerDump = function () {
        return JSON.stringify({
            active: state.stalker.active,
            armed: state.stalker.armed,
            pendingThreadId: state.stalker.pendingThreadId,
            threadId: state.stalker.threadId,
            startedAt: state.stalker.startedAt,
            startReason: state.stalker.startReason,
            blockCount: state.stalker.blockCount,
            drops: state.stalker.drops,
            events: state.stalker.events,
            pcHits: state.stalker.pcHits,
            threadHits: state.stalker.threadHits,
        });
    };

    globalThis.__jitGateStalkerTopPcs = function (limit) {
        var maxPcs = parseInt(limit || 16, 10);
        if (!(maxPcs > 0)) maxPcs = 16;
        return Object.keys(state.stalker.pcHits)
            .map(function (pc) {
                return { pc: pc, hits: state.stalker.pcHits[pc] };
            })
            .sort(function (a, b) { return b.hits - a.hits; })
            .slice(0, maxPcs);
    };

    globalThis.__jitGateStalkerStop = function (reason) {
        stopStalker(reason || 'manual');
        state.stalker.armed = false;
        state.stalker.pendingThreadId = null;
        restoreExecProtection();
        return 'OK';
    };

    globalThis.__jitGateStalkerArm = function () {
        stopStalker('rearm');
        clearStalkerData();
        state.stalker.armed = true;
        if (!state.currentBase) {
            installForRange(chooseTrapRange());
        }
        if (state.currentBase && state.currentSize) {
            var currentRange = findExecRangeFor(state.currentBase) || chooseTrapRange();
            ensureTrapProtection(currentRange);
        }
        return 'ARMED';
    };

    globalThis.__jitGateStalkerDisarm = function () {
        stopStalker('manual disarm');
        state.stalker.armed = false;
        state.stalker.pendingThreadId = null;
        restoreExecProtection();
        return 'DISARMED';
    };

    globalThis.__jitGateMemdumpArm = function () {
        state.memdump.armed = true;
        state.memdump.captured = false;
        state.memdump.before = null;
        state.memdump.after = null;
        if (!state.currentBase) {
            installForRange(chooseTrapRange());
        }
        if (state.currentBase && state.currentSize) {
            var currentRange = findExecRangeFor(state.currentBase) || chooseTrapRange();
            ensureTrapProtection(currentRange);
        }
        console.log('[CAPTURE] [GATE] memdump ARMED');
        return JSON.stringify({
            status: 'armed',
            corridor: state.currentBase ? state.currentBase.toString() : null,
            corridorSize: state.currentSize,
        });
    };

    globalThis.__jitGateMemdumpAfter = function () {
        if (!state.memdump.captured || !state.memdump.before) {
            return JSON.stringify({ error: 'no before snapshot captured yet' });
        }
        try {
            state.memdump.after = doFullProcessSnapshot('after', null, null);
        } catch (e) {
            noteFailure('memdump after snapshot', e);
            state.memdump.after = { error: String(e) };
        }
        return JSON.stringify({
            status: 'done',
            before_regions: state.memdump.before.summary || null,
            after_regions: state.memdump.after.summary || null,
        });
    };

    globalThis.__jitGateMemdumpStatus = function () {
        return JSON.stringify({
            armed: state.memdump.armed,
            captured: state.memdump.captured,
            before: state.memdump.before ? {
                label: state.memdump.before.label,
                timestamp: state.memdump.before.timestamp,
                faulting_pc: state.memdump.before.faulting_pc,
                thread_id: state.memdump.before.thread_id,
                summary: state.memdump.before.summary,
            } : null,
            after: state.memdump.after ? {
                label: state.memdump.after.label,
                timestamp: state.memdump.after.timestamp,
                summary: state.memdump.after.summary,
            } : null,
            device_dir: MEMDUMP_DEVICE_DIR,
        });
    };

    globalThis.__jitGateFreezeArm = function (challenge, minPcHex) {
        state.freeze.armed = true;
        state.freeze.triggered = false;
        state.freeze.challenge = challenge || null;
        state.freeze.minPc = minPcHex ? ptr(minPcHex) : null;
        state.freeze.info = null;
        if (!state.currentBase) {
            installForRange(chooseTrapRange());
        }
        if (state.currentBase && state.currentSize) {
            var currentRange = findExecRangeFor(state.currentBase) || chooseTrapRange();
            ensureTrapProtection(currentRange);
        }
        var status = {
            status: 'armed',
            timestamp: (new Date()).toISOString(),
            pid: Process.id,
            challenge: state.freeze.challenge,
            corridor: state.currentBase ? state.currentBase.toString() : null,
            corridorSize: state.currentSize,
            freeze_status_path: FREEZE_STATUS_PATH,
        };
        writeFreezeStatus(status);
        console.log('[CAPTURE] [GATE] freeze ARMED challenge=' + (state.freeze.challenge || '<none>'));
        return JSON.stringify(status);
    };

    globalThis.__jitGateFreezeClear = function () {
        state.freeze.armed = false;
        state.freeze.triggered = false;
        state.freeze.challenge = null;
        state.freeze.info = null;
        var status = {
            status: 'disarmed',
            timestamp: (new Date()).toISOString(),
            pid: Process.id,
            freeze_status_path: FREEZE_STATUS_PATH,
        };
        writeFreezeStatus(status);
        console.log('[CAPTURE] [GATE] freeze DISARMED');
        return JSON.stringify(status);
    };

    globalThis.__jitGateFreezeStatus = function () {
        return JSON.stringify({
            armed: state.freeze.armed,
            triggered: state.freeze.triggered,
            challenge: state.freeze.challenge,
            info: state.freeze.info,
            freeze_status_path: FREEZE_STATUS_PATH,
        });
    };

    globalThis.__jitGateTranslatedLoad = function (elfPath, mapPath) {
        try {
            var result = translatedLoad(String(elfPath), String(mapPath));
            console.log('[CAPTURE] [GATE] translated LOAD elf=' + elfPath + ' map=' + mapPath + ' blocks=' + result.blocks);
            return JSON.stringify(result);
        } catch (e) {
            state.translated.loaded = false;
            state.translated.loadError = String(e) + ' stage=' + (state.translated.lastLoadStage || '<unknown>');
            noteFailure('translated load', e);
            return JSON.stringify({
                loaded: false,
                error: String(e),
                stage: state.translated.lastLoadStage || null,
                stack: e && e.stack ? String(e.stack) : null,
            });
        }
    };

    globalThis.__jitGateTranslatedArm = function (elfPath, mapPath, minPcHex, maxSteps) {
        if (elfPath && mapPath) {
            globalThis.__jitGateTranslatedLoad(elfPath, mapPath);
        }
        state.translated.armed = true;
        state.translated.minPc = minPcHex ? ptr(minPcHex) : null;
        state.translated.activeThreadId = null;
        state.translated.activeChallenge = null;
        state.translated.activeCall = null;
        state.translated.claimedThreads = {};
        if (maxSteps !== undefined && maxSteps !== null) {
            var parsedSteps = parseInt(maxSteps, 10);
            if (parsedSteps > 0) state.translated.maxSteps = parsedSteps;
        }
        if (!state.currentBase) {
            installForRange(chooseTrapRange());
        }
        reassertTrapProtectionIfArmed();
        var status = {
            armed: state.translated.armed,
            loaded: state.translated.loaded,
            load_error: state.translated.loadError,
            min_pc: state.translated.minPc ? state.translated.minPc.toString() : null,
            elf_path: state.translated.elfPath,
            map_path: state.translated.mapPath,
            source_base: state.translated.sourceBase ? ('0x' + state.translated.sourceBase.toString(16)) : null,
            source_size: state.translated.sourceSize,
            current_corridor: state.currentBase ? state.currentBase.toString() : null,
            current_corridor_size: state.currentSize,
            max_steps: state.translated.maxSteps,
            active_thread_id: state.translated.activeThreadId,
            active_challenge: state.translated.activeChallenge,
            active_call: state.translated.activeCall,
            claimed_thread_ids: claimedThreadIds(state.translated.claimedThreads),
            recent_blocks: state.translated.recentBlocks,
        };
        console.log('[CAPTURE] [GATE] translated ARM loaded=' + state.translated.loaded +
                    ' minPc=' + (status.min_pc || '<none>') +
                    ' current=' + (status.current_corridor || '<none>'));
        return JSON.stringify(status);
    };

    globalThis.__jitGateTranslatedClear = function () {
        state.translated.armed = false;
        state.translated.minPc = null;
        state.translated.activeThreadId = null;
        state.translated.activeChallenge = null;
        state.translated.activeCall = null;
        state.translated.claimedThreads = {};
        restoreExecProtection();
        console.log('[CAPTURE] [GATE] translated DISARMED');
        return JSON.stringify({ armed: false });
    };

    globalThis.__jitGateTranslatedStatus = function () {
        return JSON.stringify({
            armed: state.translated.armed,
            loaded: state.translated.loaded,
            load_error: state.translated.loadError,
            load_stage: state.translated.lastLoadStage,
            min_pc: state.translated.minPc ? state.translated.minPc.toString() : null,
            elf_path: state.translated.elfPath,
            map_path: state.translated.mapPath,
            source_base: state.translated.sourceBase ? ('0x' + state.translated.sourceBase.toString(16)) : null,
            source_size: state.translated.sourceSize,
            max_steps: state.translated.maxSteps,
            active_thread_id: state.translated.activeThreadId,
            active_challenge: state.translated.activeChallenge,
            active_call: state.translated.activeCall,
            claimed_thread_ids: claimedThreadIds(state.translated.claimedThreads),
            last_run: state.translated.lastRun,
            recent_runs: state.translated.runs,
            recent_blocks: state.translated.recentBlocks,
        });
    };

    globalThis.__jitGateDynamicLoad = function (libPath) {
        try {
            var result = dynamicLoad(String(libPath));
            console.log('[CAPTURE] [GATE] dynamic LOAD so=' + libPath);
            return JSON.stringify(result);
        } catch (e) {
            state.dynamic.loaded = false;
            state.dynamic.loadError = String(e) + ' stage=' + (state.dynamic.lastLoadStage || '<unknown>');
            noteFailure('dynamic load', e);
            return JSON.stringify({
                loaded: false,
                error: String(e),
                stage: state.dynamic.lastLoadStage || null,
                stack: e && e.stack ? String(e.stack) : null,
            });
        }
    };

    globalThis.__jitGateDynamicArm = function (libPath, minPcHex, maxSteps) {
        if (libPath) {
            globalThis.__jitGateDynamicLoad(libPath);
        }
        state.dynamic.armed = true;
        state.dynamic.minPc = minPcHex ? ptr(minPcHex) : null;
        state.dynamic.activeThreadId = null;
        state.dynamic.activeChallenge = null;
        state.dynamic.activeCall = null;
        state.dynamic.threadClaims = {};
        if (maxSteps !== undefined && maxSteps !== null) {
            var parsedSteps = parseInt(maxSteps, 10);
            if (parsedSteps > 0) state.dynamic.maxSteps = parsedSteps;
        }
        if (!state.currentBase) {
            installForRange(chooseTrapRange());
        }
        reassertTrapProtectionIfArmed();
        var status = {
            armed: state.dynamic.armed,
            loaded: state.dynamic.loaded,
            load_error: state.dynamic.loadError,
            min_pc: state.dynamic.minPc ? state.dynamic.minPc.toString() : null,
            lib_path: state.dynamic.libPath,
            source_base: state.dynamic.sourceBase ? ('0x' + state.dynamic.sourceBase.toString(16)) : null,
            source_size: state.dynamic.sourceSize,
            current_corridor: state.currentBase ? state.currentBase.toString() : null,
            current_corridor_size: state.currentSize,
            max_steps: state.dynamic.maxSteps,
            active_thread_id: state.dynamic.activeThreadId,
            active_challenge: state.dynamic.activeChallenge,
            active_call: state.dynamic.activeCall,
            claimed_thread_ids: claimedThreadIds(state.dynamic.threadClaims),
            recent_blocks: state.dynamic.recentBlocks,
        };
        console.log('[CAPTURE] [GATE] dynamic ARM loaded=' + state.dynamic.loaded +
                    ' minPc=' + (status.min_pc || '<none>') +
                    ' current=' + (status.current_corridor || '<none>'));
        return JSON.stringify(status);
    };

    globalThis.__jitGateDynamicClear = function () {
        state.dynamic.armed = false;
        state.dynamic.minPc = null;
        state.dynamic.activeThreadId = null;
        state.dynamic.activeChallenge = null;
        state.dynamic.activeCall = null;
        state.dynamic.threadClaims = {};
        state.dynamic.pendingThreads = {};
        dynamicDestroyRuntime();
        restoreExecProtection();
        console.log('[CAPTURE] [GATE] dynamic DISARMED');
        return JSON.stringify({ armed: false });
    };

    globalThis.__jitGateDynamicStatus = function () {
        return JSON.stringify({
            armed: state.dynamic.armed,
            loaded: state.dynamic.loaded,
            load_error: state.dynamic.loadError,
            load_stage: state.dynamic.lastLoadStage,
            min_pc: state.dynamic.minPc ? state.dynamic.minPc.toString() : null,
            lib_path: state.dynamic.libPath,
            source_base: state.dynamic.sourceBase ? ('0x' + state.dynamic.sourceBase.toString(16)) : null,
            source_size: state.dynamic.sourceSize,
            max_steps: state.dynamic.maxSteps,
            active_thread_id: state.dynamic.activeThreadId,
            active_challenge: state.dynamic.activeChallenge,
            active_call: state.dynamic.activeCall,
            claimed_thread_ids: claimedThreadIds(state.dynamic.threadClaims),
            pending_thread_ids: Object.keys(state.dynamic.pendingThreads || {}),
            resume_trampoline: state.dynamic.resumeTrampoline ? state.dynamic.resumeTrampoline.toString() : null,
            resume_brk_imm: state.dynamic.resumeBrkImm ? ('0x' + state.dynamic.resumeBrkImm.toString(16)) : null,
            bridge: dynamicBridgeState(),
            last_run: state.dynamic.lastRun,
            recent_runs: state.dynamic.runs,
            recent_blocks: state.dynamic.recentBlocks,
        });
    };

    if (typeof rpc !== 'undefined' && rpc && rpc.exports) {
        rpc.exports.jitGateTranslatedLoad = function (elfPath, mapPath) {
            return globalThis.__jitGateTranslatedLoad(String(elfPath), String(mapPath));
        };
        rpc.exports.jitGateTranslatedArm = function (elfPath, mapPath, minPcHex, maxSteps) {
            return globalThis.__jitGateTranslatedArm(
                elfPath !== undefined && elfPath !== null ? String(elfPath) : undefined,
                mapPath !== undefined && mapPath !== null ? String(mapPath) : undefined,
                minPcHex !== undefined && minPcHex !== null ? String(minPcHex) : undefined,
                maxSteps
            );
        };
        rpc.exports.jitGateTranslatedClear = function () {
            return globalThis.__jitGateTranslatedClear();
        };
        rpc.exports.jitGateTranslatedStatus = function () {
            return globalThis.__jitGateTranslatedStatus();
        };
        rpc.exports.jitGateDynamicLoad = function (libPath) {
            return globalThis.__jitGateDynamicLoad(String(libPath));
        };
        rpc.exports.jitGateDynamicArm = function (libPath, minPcHex, maxSteps) {
            return globalThis.__jitGateDynamicArm(
                libPath !== undefined && libPath !== null ? String(libPath) : undefined,
                minPcHex !== undefined && minPcHex !== null ? String(minPcHex) : undefined,
                maxSteps
            );
        };
        rpc.exports.jitGateDynamicClear = function () {
            return globalThis.__jitGateDynamicClear();
        };
        rpc.exports.jitGateDynamicStatus = function () {
            return globalThis.__jitGateDynamicStatus();
        };
    }

    globalThis.__jitGateMemdumpListFiles = function () {
        var lc = memdumpGetLibc();
        var opendir = new NativeFunction(
            Process.getModuleByName('libc.so').getExportByName('opendir'),
            'pointer', ['pointer']);
        var readdir = new NativeFunction(
            Process.getModuleByName('libc.so').getExportByName('readdir'),
            'pointer', ['pointer']);
        var closedir = new NativeFunction(
            Process.getModuleByName('libc.so').getExportByName('closedir'),
            'int', ['pointer']);
        var dir = opendir(Memory.allocUtf8String(MEMDUMP_DEVICE_DIR));
        if (dir.isNull()) return JSON.stringify([]);
        var files = [];
        while (true) {
            var ent = readdir(dir);
            if (ent.isNull()) break;
            var name = ent.add(19).readUtf8String();
            if (name === '.' || name === '..') continue;
            files.push(name);
        }
        closedir(dir);
        files.sort();
        return JSON.stringify(files);
    };

    if (!globalThis.__jitGateTraceExceptionHandlerInstalled) {
        Process.setExceptionHandler(function (details) {
            var event = {
                type: details.type || null,
                address: details.address ? fmtPtr(details.address) : null,
                memory: details.memory ? {
                    operation: details.memory.operation || null,
                    address: details.memory.address ? fmtPtr(details.memory.address) : null,
                } : null,
                pc: details.context ? fmtPtr(details.context.pc) : null,
                lr: details.context ? fmtPtr(details.context.lr) : null,
                matched_trap: false,
            };
            var threadId = details.threadId;
            if (threadId === null || threadId === undefined) {
                threadId = currentThreadIdMaybe();
            }
            var dynamicResumeTrap = dynamicFindResumeTrap(details);
            if (dynamicResumeTrap) {
                event.matched_trap = true;
                event.dynamic_resume = true;
                event.threadId = dynamicResumeTrap.threadId;
                pushException(event);
                console.log('[CAPTURE] [GATE] dynamic resume trap type=' + event.type +
                            ' pc=' + event.pc +
                            ' lr=' + event.lr +
                            ' thread=' + dynamicResumeTrap.threadId);
                try {
                    dynamicFinishResumeTrap(details, dynamicResumeTrap);
                    return true;
                } catch (e) {
                    noteFailure('dynamic resume trap', e);
                    console.log('[CAPTURE] [GATE] dynamic resume trap ERROR pc=' + event.pc +
                                ' err=' + String(e));
                    return false;
                }
            }
            if (!isTargetTrapException(details)) {
                if (state.dynamic && state.dynamic.armed && details.context &&
                    event.type === 'access-violation' &&
                    event.memory && event.memory.operation === 'execute') {
                    try {
                        var bailoutBridge = dynamicBridgeState(threadId);
                        if (dynamicMaybeBailNonCallableExecute(details, threadId, bailoutBridge)) {
                            event.matched_trap = true;
                            event.dynamic_bailout = true;
                            event.threadId = threadId;
                            pushException(event);
                            return true;
                        }
                    } catch (e) {
                        noteFailure('dynamic bailout', e);
                    }
                }
                event.matched_trap = false;
                pushException(event);
                var passLine = '[CAPTURE] [GATE] pass exception type=' + event.type +
                    ' address=' + event.address +
                    ' pc=' + event.pc +
                    ' lr=' + event.lr;
                if (event.memory) {
                    passLine += ' memop=' + (event.memory.operation || '<none>') +
                        ' memaddr=' + (event.memory.address || '<none>');
                }
                if (state.dynamic && state.dynamic.armed) {
                    passLine += ' bridge=' + JSON.stringify(dynamicBridgeState(threadId));
                }
                if (state.postResume && state.postResume.active && state.postResume.threadId === threadId) {
                    passLine += ' post_resume=' + JSON.stringify({
                        start_pc: state.postResume.startPc,
                        block_count: state.postResume.blockCount,
                        drops: state.postResume.drops,
                        events: state.postResume.events.slice(-12),
                    });
                    stopPostResumeTrace('fault');
                }
                if (details.context && event.type === 'access-violation') {
                    passLine += ' bt=' + JSON.stringify(exceptionBacktrace(details.context, 10));
                }
                console.log(passLine);
                return false;
            }
            event.matched_trap = true;
            var pageBase = details.context ? pageBaseFor(details.context.pc) : pageBaseFor(details.address);
            var pageKey = pageBase ? pageBase.toString() : '0x0';
            var pcKey = event.pc || '0x0';
            var lrKey = event.lr || '0x0';
            var edgeKey = lrKey + '->' + pcKey;
            var trapCount = bumpTrapCount(pcKey);
            state.pageHits[pageKey] = bumpMapCount(state.pageHits, pageKey);
            state.pcHits[pcKey] = bumpMapCount(state.pcHits, pcKey);
            state.edgeHits[edgeKey] = bumpMapCount(state.edgeHits, edgeKey);
            if (threadId !== null && threadId !== undefined) {
                state.threadHits[String(threadId)] = bumpMapCount(state.threadHits, String(threadId));
                event.threadId = threadId;
                scheduleStalkerForThread(threadId, pcKey);
            }
            event.page = pageKey;
            event.edge = edgeKey;
            event.count = trapCount;
            pushException(event);
            if (!(state.dynamic.armed || state.translated.armed) &&
                (trapCount <= 4 || (trapCount % 1024) === 0)) {
                console.log('[CAPTURE] [GATE] trapped execute fault type=' + event.type +
                            ' address=' + event.address +
                            ' pc=' + event.pc +
                            ' lr=' + event.lr +
                            ' thread=' + (threadId === null || threadId === undefined ? 'unknown' : threadId) +
                            ' page=' + event.page +
                            ' edge=' + event.edge +
                            ' count=' + trapCount);
            }
            if (state.memdump.armed && !state.memdump.captured) {
                state.memdump.captured = true;
                state.memdump.armed = false;
                console.log('[CAPTURE] [GATE] memdump TRIGGERED on fault pc=' + event.pc + ' thread=' + threadId);
                try {
                    state.memdump.before = doFullProcessSnapshot('before', details.context, threadId);
                } catch (e) {
                    noteFailure('memdump before snapshot', e);
                    state.memdump.before = { error: String(e) };
                }
            }
            if (state.dynamic.armed && state.dynamic.loaded && state.dynamic.activeCall &&
                (!state.dynamic.minPc || (details.context && ptr(details.context.pc).compare(state.dynamic.minPc) >= 0))) {
                try {
                    var dynThreadName = threadNameMaybe(threadId);
                    var existingDynamicClaim = getClaim(state.dynamic.threadClaims, threadId);
                    if (existingDynamicClaim && existingDynamicClaim.disabled) {
                        console.log('[CAPTURE] [GATE] dynamic skip disabled thread=' + threadId +
                            ' name=' + (dynThreadName || '<unknown>') +
                            ' pc=' + event.pc +
                            ' reason=' + (existingDynamicClaim.disabled_reason || 'disabled'));
                        if (!activatePage(pageBase)) {
                            return false;
                        }
                        return true;
                    }
                    if (dynamicIsZeroTrapCandidate(details.context)) {
                        console.log('[CAPTURE] [GATE] dynamic ignore zero/trap candidate pc=' + event.pc +
                                    ' thread=' + threadId +
                                    (hasClaim(state.dynamic.threadClaims, threadId) ? ' claimed=true' : ' claimed=false'));
                        if (!activatePage(pageBase)) {
                            return false;
                        }
                        return true;
                    }
                    if (!hasClaim(state.dynamic.threadClaims, threadId) &&
                        isBackgroundArtThreadName(dynThreadName)) {
                        console.log('[CAPTURE] [GATE] dynamic skip background thread=' + threadId +
                            ' name=' + dynThreadName +
                            ' pc=' + event.pc);
                        if (!activatePage(pageBase)) {
                            return false;
                        }
                        return true;
                    }
                    if (!hasClaim(state.dynamic.threadClaims, threadId)) {
                        ensureClaim(state.dynamic.threadClaims, threadId, {
                            first_pc: event.pc,
                            challenge: state.dynamic.activeCall ? (state.dynamic.activeCall.challenge || null) : null,
                            thread_name: dynThreadName,
                        });
                        console.log('[CAPTURE] [GATE] dynamic claimed thread=' + threadId +
                            ' name=' + (dynThreadName || '<unknown>') +
                            ' pc=' + event.pc +
                            ' challenge=' + (state.dynamic.activeCall ? (state.dynamic.activeCall.challenge || '<none>') : '<none>'));
                    }
                    if (state.dynamic.pendingThreads &&
                        Object.prototype.hasOwnProperty.call(state.dynamic.pendingThreads, String(threadId))) {
                        console.log('[CAPTURE] [GATE] dynamic skip pending thread=' + threadId +
                            ' pc=' + event.pc +
                            ' stage=' + (dynamicBridgeState(threadId).stage || '<null>'));
                        if (!activatePage(pageBase)) {
                            return false;
                        }
                        return true;
                    }
                    dynamicArmResumeFromContext(details.context, threadId);
                    return true;
                } catch (e) {
                    noteFailure('dynamic dispatch', e);
                    console.log('[CAPTURE] [GATE] dynamic dispatch ERROR pc=' + event.pc + ' err=' + String(e));
                    return false;
                }
            }
            if (state.translated.armed && state.translated.loaded &&
                state.translated.activeCall &&
                (!state.translated.minPc || (details.context && ptr(details.context.pc).compare(state.translated.minPc) >= 0))) {
                try {
                    if (!hasClaim(state.translated.claimedThreads, threadId)) {
                        ensureClaim(state.translated.claimedThreads, threadId, {
                            first_pc: event.pc,
                            challenge: state.translated.activeCall.challenge || null,
                        });
                        console.log('[CAPTURE] [GATE] translated claimed thread=' + threadId +
                            ' pc=' + event.pc +
                            ' challenge=' + (state.translated.activeCall.challenge || '<none>'));
                    }
                    var translatedResult = translatedRunFromContext(details.context);
                    var translatedPage = details.context ? pageBaseFor(details.context.pc) : null;
                    var shouldResumeOriginal = false;
                    if (translatedResult && translatedResult.trap_exit) {
                        shouldResumeOriginal = true;
                    } else if (translatedResult && translatedResult.unresolved && details.context) {
                        var currentPcNum = u64Number(details.context.pc);
                        var currentBaseNum = state.currentBase ? u64Number(state.currentBase) : 0;
                        var currentSizeNum = state.currentSize || 0;
                        shouldResumeOriginal = !!currentBaseNum &&
                            currentPcNum >= currentBaseNum &&
                            currentPcNum < (currentBaseNum + currentSizeNum);
                    }
                    if (shouldResumeOriginal && translatedPage) {
                        activatePage(translatedPage);
                    }
                    return true;
                } catch (e) {
                    noteFailure('translated dispatch', e);
                    console.log('[CAPTURE] [GATE] translated dispatch ERROR pc=' + event.pc + ' err=' + String(e));
                    return false;
                }
            }
            if (state.freeze.armed && !state.freeze.triggered &&
                (!state.freeze.minPc || (details.context && ptr(details.context.pc).compare(state.freeze.minPc) >= 0))) {
                state.freeze.armed = false;
                state.freeze.triggered = true;
                state.freeze.info = {
                    status: 'triggered',
                    timestamp: (new Date()).toISOString(),
                    pid: Process.id,
                    thread_id: threadId || null,
                    challenge: state.freeze.challenge,
                    type: event.type,
                    address: event.address,
                    pc: event.pc,
                    lr: event.lr,
                    registers: details.context ? captureRegs(details.context) : null,
                    page: event.page,
                    edge: event.edge,
                    trap_count: trapCount,
                    freeze_status_path: FREEZE_STATUS_PATH,
                };
                writeFreezeStatus(state.freeze.info);
                console.log('[CAPTURE] [GATE] FREEZE TRIGGERED pid=' + Process.id +
                            ' thread=' + (threadId === null || threadId === undefined ? 'unknown' : threadId) +
                            ' pc=' + event.pc +
                            ' challenge=' + (state.freeze.challenge || '<none>') +
                            ' status=' + FREEZE_STATUS_PATH);
                try {
                    memdumpGetLibc().kill(Process.id, 19);
                } catch (e) {
                    noteFailure('freeze SIGSTOP', e);
                    state.freeze.triggered = false;
                    state.freeze.armed = true;
                    state.freeze.info = {
                        status: 'error',
                        timestamp: (new Date()).toISOString(),
                        pid: Process.id,
                        thread_id: threadId || null,
                        pc: event.pc,
                        error: String(e),
                        freeze_status_path: FREEZE_STATUS_PATH,
                    };
                    writeFreezeStatus(state.freeze.info);
                }
                return true;
            }
            if (!activatePage(pageBase)) {
                return false;
            }
            return true;
        });
        globalThis.__jitGateTraceExceptionHandlerInstalled = true;
        console.log('[CAPTURE] [GATE] installed exception handler');
    }

    if (typeof maybeAdoptJit === 'function') {
        var origMaybeAdoptJit = maybeAdoptJit;
        maybeAdoptJit = function (target, source) {
            var mod = origMaybeAdoptJit(target, source);
            if (mod && mod.base) {
                var range = findExecRangeFor(mod.base);
                if (range !== null && isTrapCandidate(range)) {
                    installForRange(range);
                }
            }
            return mod;
        };
        console.log('[CAPTURE] [GATE] wrapped maybeAdoptJit');
    }

    if (typeof rpc !== 'undefined' && rpc && rpc.exports && typeof rpc.exports.callCert === 'function' &&
        !globalThis.__jitGateWrappedCallCert) {
        originalCallCertExport = rpc.exports.callCert;
        function runCallWithTranslatedScope(challenge, fn) {
            var useTranslatedScope = state.translated.armed && state.translated.loaded;
            var useDynamicScope = state.dynamic.armed && state.dynamic.loaded;
            var priorThreadId = state.translated.activeThreadId;
            var priorChallenge = state.translated.activeChallenge;
            var priorTranslatedCall = state.translated.activeCall;
            var priorTranslatedClaims = state.translated.claimedThreads;
            var priorDynamicThreadId = state.dynamic.activeThreadId;
            var priorDynamicChallenge = state.dynamic.activeChallenge;
            var priorDynamicCall = state.dynamic.activeCall;
            var priorDynamicThreadClaims = state.dynamic.threadClaims;
            var priorPendingThreads = state.dynamic.pendingThreads;
            var scopeStartedAt = (new Date()).toISOString();
            var rootThreadId = currentThreadIdMaybe();
            var protectedTranslatedRange = false;
            if (useTranslatedScope) {
                state.translated.activeThreadId = rootThreadId;
                state.translated.activeChallenge = challenge || null;
                state.translated.activeCall = {
                    challenge: challenge || null,
                    root_thread_id: rootThreadId,
                    started_at: scopeStartedAt,
                };
                state.translated.claimedThreads = {};
                if (rootThreadId !== null && rootThreadId !== undefined) {
                    ensureClaim(state.translated.claimedThreads, rootThreadId, {
                        first_pc: null,
                        challenge: challenge || null,
                        seeded_by: 'call_scope',
                    });
                }
                if (state.currentBase && state.currentSize) {
                    var currentRange = findExecRangeFor(state.currentBase) || chooseTrapRange();
                    if (currentRange) {
                        ensureTrapProtection(currentRange);
                        protectedTranslatedRange = true;
                    }
                }
                console.log('[CAPTURE] [GATE] translated call scope root_thread=' +
                            (rootThreadId === null || rootThreadId === undefined ? 'unknown' : rootThreadId) +
                            ' mode=claim-many' +
                            ' challenge=' + (challenge || '<none>'));
            }
            if (useDynamicScope) {
                state.dynamic.activeThreadId = null;
                state.dynamic.activeChallenge = challenge || null;
                state.dynamic.activeCall = {
                    challenge: challenge || null,
                    root_thread_id: rootThreadId,
                    started_at: scopeStartedAt,
                };
                state.dynamic.threadClaims = {};
                state.dynamic.pendingThreads = {};
                if (rootThreadId !== null && rootThreadId !== undefined) {
                    ensureClaim(state.dynamic.threadClaims, rootThreadId, {
                        first_pc: null,
                        challenge: challenge || null,
                        seeded_by: 'call_scope',
                        runtime: null,
                        sourceBase: 0,
                        sourceSize: 0,
                    });
                }
                if (!protectedTranslatedRange && state.currentBase && state.currentSize) {
                    var currentDynamicRange = findExecRangeFor(state.currentBase) || chooseTrapRange();
                    if (currentDynamicRange) {
                        ensureTrapProtection(currentDynamicRange);
                        protectedTranslatedRange = true;
                    }
                }
                console.log('[CAPTURE] [GATE] dynamic call scope root_thread=' +
                            (rootThreadId === null || rootThreadId === undefined ? 'unknown' : rootThreadId) +
                            ' mode=claim-many' +
                            ' challenge=' + (challenge || '<none>'));
            }
            try {
                return fn();
            } finally {
                var scopeDynamicClaims = state.dynamic.threadClaims;
                if (useTranslatedScope) {
                    state.translated.activeThreadId = priorThreadId;
                    state.translated.activeChallenge = priorChallenge;
                    state.translated.activeCall = priorTranslatedCall;
                    state.translated.claimedThreads = priorTranslatedClaims;
                    if (protectedTranslatedRange) {
                        if (!reassertTrapProtectionIfArmed()) {
                            restoreExecProtection();
                        }
                    }
                    console.log('[CAPTURE] [GATE] translated call scope clear challenge=' + (challenge || '<none>'));
                }
                if (useDynamicScope) {
                    state.dynamic.activeThreadId = priorDynamicThreadId;
                    state.dynamic.activeChallenge = priorDynamicChallenge;
                    state.dynamic.activeCall = priorDynamicCall;
                    state.dynamic.threadClaims = priorDynamicThreadClaims;
                    state.dynamic.pendingThreads = priorPendingThreads;
                    dynamicDestroyThreadClaims(scopeDynamicClaims);
                    clearNativeChainResumes();
                    stopPostResumeTrace('call scope clear');
                    if (!useTranslatedScope && protectedTranslatedRange) {
                        if (!reassertTrapProtectionIfArmed()) {
                            restoreExecProtection();
                        }
                    }
                    console.log('[CAPTURE] [GATE] dynamic call scope clear challenge=' + (challenge || '<none>'));
                }
            }
        }
        rpc.exports.callCert = function (challenge) {
            var memdumpPending = state.memdump.armed || state.memdump.captured;
            if (!state.fixedTraceArm && !memdumpPending) {
                var plainToken = runCallWithTranslatedScope(challenge, function () {
                    return originalCallCertExport(challenge);
                });
                if (state.memdump.captured && !state.memdump.after) {
                    console.log('[CAPTURE] [GATE] memdump after-snapshot (plain call path)');
                    try {
                        state.memdump.after = doFullProcessSnapshot('after', null, null);
                    } catch (e) {
                        noteFailure('memdump after snapshot', e);
                    }
                }
                return plainToken;
            }
            if (!state.fixedTraceArm) {
                var mdToken = runCallWithTranslatedScope(challenge, function () {
                    return originalCallCertExport(challenge);
                });
                if (state.memdump.captured && !state.memdump.after) {
                    console.log('[CAPTURE] [GATE] memdump after-snapshot (memdump path)');
                    try {
                        state.memdump.after = doFullProcessSnapshot('after', null, null);
                    } catch (e) {
                        noteFailure('memdump after snapshot', e);
                    }
                }
                return mdToken;
            }
            var armed = state.fixedTraceArm;
            state.fixedTraceArm = null;
            state.fixedTrace = {
                status: 'running',
                challenge: challenge,
                token: null,
                followed: armed.requested || [],
                blockCount: 0,
                pcHits: {},
                top: [],
                range: describeCurrentRange(),
                hotThreads: globalThis.__jitGateTraceTopThreads(8),
                armedAt: armed.armedAt,
                startedAt: (new Date()).toISOString(),
                error: null,
            };
            try {
                var result = runFixedThreadTraceCore(challenge, armed.requested || []);
                result.armedAt = armed.armedAt;
                result.startedAt = state.fixedTrace.startedAt;
                result.finishedAt = (new Date()).toISOString();
                state.fixedTrace = result;
                return result.token || '';
            } catch (e) {
                state.fixedTrace.error = String(e);
                state.fixedTrace.finishedAt = (new Date()).toISOString();
                return '';
            }
        };
        globalThis.__jitGateWrappedCallCert = true;
        console.log('[CAPTURE] [GATE] wrapped rpc.exports.callCert');
    }

    setTimeout(function () {
        if (typeof jitMod !== 'undefined' && jitMod && jitMod.base) {
            var initialRange = findExecRangeFor(jitMod.base);
            if (initialRange !== null && isTrapCandidate(initialRange)) {
                installForRange(initialRange);
                return;
            }
        }
        if (!state.currentBase) {
            installForRange(chooseTrapRange());
        }
    }, 0);
})();
