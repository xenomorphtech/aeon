'use strict';

(function () {
    if (globalThis.__jitPostJitRenderTrace && globalThis.__jitPostJitRenderTrace.installed) {
        console.log('[CAPTURE] [POSTJIT] relay already installed');
        return;
    }

    var MAX_BLOCK_TRACE = 32768;
    var MAX_EXIT_EVENTS = 8192;
    var DEFAULT_CHALLENGE = 'AABBCCDDEEFF0011';
    var PTR_MASK = ptr('0x00FFFFFFFFFFFFFF');
    var SSO_SIZE = 24;
    var SSO_SAMPLE_LIMIT = 96;
    var MEMCPY_SAMPLE_LIMIT = 0x400;
    var FREEZE_STATUS_PATH = '/data/data/com.netmarble.thered/files/postjit_exit_freeze.json';
    var HOT_EXIT_OFFSETS = [
        0x5fec0,
        0x5ff00,
        0x5f710,
        0xc0ab0,
        0xc2914,
        0xc291c,
        0xc292c,
        0xc2938,
        0x170d04,
        0x2489f0,
        0x248a08,
        0x24b490,
        0x2708a8,
        0x2708c4,
        0x2708c8,
        0x2708dc,
        0x2728f0,
        0x2a76dc,
        0x2a8e30
    ];

    var state = globalThis.__jitPostJitRenderTrace = {
        installed: true,
        last: null,
        locationCache: {},
        currentRun: null,
        hotExitHookKeys: {},
        memcpyHooksInstalled: false,
        memcpyHookListeners: [],
    };

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function parseJsonMaybe(value) {
        if (typeof value !== 'string') return value;
        try {
            return JSON.parse(value);
        } catch (e) {
            return value;
        }
    }

    function untagPtr(value) {
        try {
            return ptr(value).and(PTR_MASK);
        } catch (e) {
            return ptr('0');
        }
    }

    function samePtr(left, right) {
        try {
            return ptr(left).equals(ptr(right));
        } catch (e) {
            return false;
        }
    }

    function candidatePtrs(value) {
        var out = [];
        try {
            var original = ptr(value);
            out.push(original);
            var untagged = untagPtr(original);
            if (!samePtr(original, untagged)) out.push(untagged);
        } catch (e) {}
        return out;
    }

    function isoNow() {
        return (new Date()).toISOString();
    }

    function filePathFor(range) {
        try {
            return range && range.file && range.file.path ? String(range.file.path) : null;
        } catch (e) {
            return null;
        }
    }

    function resetLocationCache() {
        state.locationCache = {};
    }

    function resolveLocation(addr) {
        var key = fmt(addr);
        var cached = state.locationCache[key];
        if (cached) return cached;

        var p = ptr(addr);
        var out = {
            pc: key,
            module: null,
            file: null,
            base: null,
            offset: null,
            protection: null,
        };

        try {
            var mod = Process.findModuleByAddress(p);
            if (mod !== null) {
                out.module = mod.name || null;
                out.file = mod.path || mod.name || null;
                out.base = fmt(mod.base);
                out.offset = fmt(p.sub(mod.base));
                state.locationCache[key] = out;
                return out;
            }
        } catch (e) {}

        try {
            if (typeof Process.findRangeByAddress === 'function') {
                var range = Process.findRangeByAddress(p);
                if (range !== null) {
                    out.file = filePathFor(range);
                    out.base = fmt(range.base);
                    out.offset = fmt(p.sub(range.base));
                    out.protection = range.protection || null;
                    state.locationCache[key] = out;
                    return out;
                }
            }
        } catch (e) {}

        state.locationCache[key] = out;
        return out;
    }

    function bump(map, key) {
        var next = (map[key] || 0) + 1;
        map[key] = next;
        return next;
    }

    function sortedTop(map, limit, keyName) {
        var max = parseInt(limit || 32, 10);
        if (!(max > 0)) max = 32;
        var label = keyName || 'key';
        return Object.keys(map)
            .map(function (key) {
                var item = { hits: map[key] };
                item[label] = key;
                return item;
            })
            .sort(function (a, b) { return b.hits - a.hits; })
            .slice(0, max);
    }

    function asciiToPattern(s) {
        var out = [];
        for (var i = 0; i < s.length; i++) {
            var h = s.charCodeAt(i).toString(16);
            out.push(h.length === 1 ? '0' + h : h);
        }
        return out.join(' ');
    }

    function hexToPattern(hex) {
        var clean = String(hex || '').replace(/[^0-9a-fA-F]/g, '');
        if ((clean.length & 1) !== 0 || clean.length === 0) return null;
        var out = [];
        for (var i = 0; i < clean.length; i += 2) {
            out.push(clean.slice(i, i + 2));
        }
        return out.join(' ');
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

    function encodeUtf16LeHex(text) {
        var s = String(text || '');
        var out = [];
        for (var i = 0; i < s.length; i++) {
            var code = s.charCodeAt(i);
            out.push((code & 0xff).toString(16).padStart(2, '0'));
            out.push(((code >>> 8) & 0xff).toString(16).padStart(2, '0'));
        }
        return out.join('');
    }

    function containsHex(haystackHex, needleHex) {
        if (!haystackHex || !needleHex) return false;
        return String(haystackHex).toLowerCase().indexOf(String(needleHex).toLowerCase()) >= 0;
    }

    function qwordsFromBytes(bytes) {
        if (!bytes) return [];
        try {
            var view = new DataView(bytes);
            var out = [];
            for (var off = 0; off + 8 <= bytes.byteLength; off += 8) {
                var lo = view.getUint32(off, true);
                var hi = view.getUint32(off + 4, true);
                var hex = hi.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0');
                out.push('0x' + hex);
            }
            return out;
        } catch (e) {
            return [];
        }
    }

    function asciiMaybe(bytes) {
        if (!bytes) return null;
        try {
            var view = new Uint8Array(bytes);
            var chars = [];
            for (var i = 0; i < view.length; i++) {
                if (view[i] === 0) break;
                chars.push(String.fromCharCode(view[i]));
            }
            return chars.join('');
        } catch (e) {
            return null;
        }
    }

    function utf16LeMaybe(bytes) {
        if (!bytes) return null;
        try {
            var view = new Uint8Array(bytes);
            var chars = [];
            for (var i = 0; i + 1 < view.length; i += 2) {
                var code = view[i] | (view[i + 1] << 8);
                if (code === 0) break;
                chars.push(String.fromCharCode(code));
            }
            return chars.join('');
        } catch (e) {
            return null;
        }
    }

    function looksHex48(text) {
        return !!(text && /^[0-9A-Fa-f]{48}$/.test(text));
    }

    function rangeInfoForAddress(addr) {
        try {
            var p = untagPtr(addr);
            var range = Process.findRangeByAddress(p);
            if (range === null) return null;
            return {
                base: fmt(range.base),
                size: range.size,
                protection: range.protection || null,
                file: filePathFor(range),
            };
        } catch (e) {
            return null;
        }
    }

    function readByteArrayMaybe(addr, size) {
        var ptrs = candidatePtrs(addr);
        for (var i = 0; i < ptrs.length; i++) {
            var p = ptrs[i];
            if (p.isNull()) continue;
            try {
                if (typeof p.readVolatile === 'function') {
                    return p.readVolatile(size);
                }
            } catch (e) {}
            try {
                return Memory.readByteArray(p, size);
            } catch (e) {}
        }
        return null;
    }

    function readSsoSlot(addr) {
        var base = untagPtr(addr);
        var raw = readByteArrayMaybe(base, SSO_SIZE);
        if (raw === null) {
            return {
                addr: fmt(base),
                error: 'unreadable',
            };
        }

        var view = new Uint8Array(raw);
        var out = {
            addr: fmt(base),
            raw_hex: bytesToHex(raw),
            raw_qwords: qwordsFromBytes(raw),
        };

        try {
            var tag = view[0];
            if ((tag & 1) === 0) {
                var shortLen = tag >>> 1;
                var shortBytes = view.slice(1, 1 + Math.min(shortLen, 22));
                out.kind = 'short';
                out.len = shortLen;
                out.data_hex = bytesToHex(shortBytes);
                out.text = asciiMaybe(shortBytes);
                out.hex48 = looksHex48(out.text);
                return out;
            }

            var sizeValue = Memory.readU64(base.add(8));
            var size = typeof sizeValue === 'number' ? sizeValue :
                (sizeValue && typeof sizeValue.toNumber === 'function' ? sizeValue.toNumber() : parseInt(String(sizeValue), 10));
            var dataPtr = untagPtr(Memory.readPointer(base.add(16)));
            out.kind = 'long';
            out.len = size;
            out.ptr = fmt(dataPtr);
            if (size > 0 && size <= 0x1000 && !dataPtr.isNull()) {
                var sampleSize = Math.min(size, SSO_SAMPLE_LIMIT);
                var sample = readByteArrayMaybe(dataPtr, sampleSize);
                out.data_hex = bytesToHex(sample);
                out.text = asciiMaybe(sample);
                out.hex48 = looksHex48(out.text);
            }
            return out;
        } catch (e) {
            out.error = String(e);
            return out;
        }
    }

    function pointerCandidatesFromSlot(slot) {
        if (!slot || !Array.isArray(slot.raw_qwords)) return [];
        var seen = {};
        var out = [];
        slot.raw_qwords.forEach(function (item) {
            try {
                var candidate = untagPtr(ptr(item));
                if (!isLikelyPointer(candidate)) return;
                var key = fmt(candidate);
                if (seen[key]) return;
                seen[key] = true;
                out.push(candidate);
            } catch (e) {}
        });
        return out;
    }

    function probePointerValue(addr, expectedToken) {
        var p = untagPtr(addr);
        var out = {
            addr: fmt(p),
            range: rangeInfoForAddress(p),
        };
        if (!isLikelyPointer(p)) {
            out.error = 'not-pointer';
            return out;
        }

        var raw = readByteArrayMaybe(p, SSO_SAMPLE_LIMIT);
        if (raw === null) {
            out.error = 'unreadable';
            return out;
        }

        out.sample_hex = bytesToHex(raw);
        out.sample_qwords = qwordsFromBytes(raw);
        out.sample_ascii = asciiMaybe(raw);
        out.sample_utf16le = utf16LeMaybe(raw);
        if (looksHex48(out.sample_ascii)) {
            out.tokenCandidate = out.sample_ascii.toUpperCase();
        } else if (looksHex48(out.sample_utf16le)) {
            out.tokenCandidate = out.sample_utf16le.toUpperCase();
        }
        if (/^[0-9A-Fa-f]{48}$/.test(String(expectedToken || '')) && out.sample_hex) {
            out.encodingMatch = detectTokenEncoding(out.sample_hex, expectedToken);
            if (out.tokenCandidate) {
                out.matchesExpected = out.tokenCandidate === String(expectedToken).toUpperCase();
            }
        }
        out.slot_probe = readSsoSlot(p);
        return out;
    }

    function probeOutputObject(objAddr, expectedToken) {
        var obj = untagPtr(objAddr);
        var out = {
            object: fmt(obj),
        };
        if (obj.isNull()) {
            out.error = 'null';
            return out;
        }
        try {
            if (obj.compare(ptr('0x1000')) < 0) {
                out.error = 'low-address';
                return out;
            }
        } catch (e) {}
        var slot68 = readSsoSlot(obj.add(0x68));
        out.slot68 = slot68;
        if (slot68 && slot68.text && looksHex48(slot68.text)) {
            out.tokenCandidate = slot68.text.toUpperCase();
            if (/^[0-9A-Fa-f]{48}$/.test(String(expectedToken || ''))) {
                out.matchesExpected = out.tokenCandidate === String(expectedToken).toUpperCase();
            }
        }
        var candidates = pointerCandidatesFromSlot(slot68);
        if (candidates.length > 0) {
            out.slot68_pointer_probes = candidates.slice(0, 4).map(function (candidate) {
                return probePointerValue(candidate, expectedToken);
            });
        }
        return out;
    }

    function probeSsoAt(addr, expectedToken) {
        var base = untagPtr(addr);
        var slot = readSsoSlot(base);
        var out = {
            addr: fmt(base),
            slot: slot,
        };
        if (slot && slot.text && looksHex48(slot.text)) {
            out.tokenCandidate = slot.text.toUpperCase();
            if (/^[0-9A-Fa-f]{48}$/.test(String(expectedToken || ''))) {
                out.matchesExpected = out.tokenCandidate === String(expectedToken).toUpperCase();
            }
        }
        return out;
    }

    function isLikelyPointer(value) {
        try {
            var p = untagPtr(value);
            return !p.isNull() && p.compare(ptr('0x1000')) >= 0;
        } catch (e) {
            return false;
        }
    }

    function memdumpGetLibc() {
        if (memdumpGetLibc._cache) return memdumpGetLibc._cache;
        var libc = Process.getModuleByName('libc.so');
        memdumpGetLibc._cache = {
            open: new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int', 'int']),
            write: new NativeFunction(libc.getExportByName('write'), 'long', ['int', 'pointer', 'long']),
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

    function memdumpWriteStr(path, str) {
        var lc = memdumpGetLibc();
        var fd = memdumpOpenWrite(path);
        if (fd < 0) return false;
        var buf = Memory.allocUtf8String(str);
        lc.write(fd, buf, str.length);
        lc.close(fd);
        return true;
    }

    function writeFreezeStatus(status) {
        memdumpWriteStr(FREEZE_STATUS_PATH, JSON.stringify(status, null, 2));
    }

    function captureRegs(context) {
        var regs = {
            pc: fmt(context.pc),
            sp: fmt(context.sp),
            lr: fmt(context.lr),
            fp: fmt(context.fp),
        };
        for (var i = 0; i <= 28; i++) {
            regs['x' + i] = fmt(context['x' + i]);
        }
        return regs;
    }

    function memcpySampleInfo(name, ptrValue, size) {
        var n = parseInt(size || 0, 10);
        if (!(n > 0) || !isLikelyPointer(ptrValue)) {
            return {
                role: name,
                addr: fmt(untagPtr(ptrValue)),
                size: n,
                sample_hex: null,
            };
        }
        var limit = Math.min(n, MEMCPY_SAMPLE_LIMIT);
        var raw = readByteArrayMaybe(ptrValue, limit);
        return {
            role: name,
            addr: fmt(untagPtr(ptrValue)),
            size: n,
            sample_hex: bytesToHex(raw),
            sample_ascii: asciiMaybe(raw),
        };
    }

    function detectTokenEncoding(sampleHex, expectedToken) {
        var token = String(expectedToken || '').toUpperCase();
        if (!/^[0-9A-F]{48}$/.test(token) || !sampleHex) return null;
        var upperHex = bytesToHex(Memory.allocUtf8String(token).readByteArray(token.length));
        var lower = token.toLowerCase();
        var lowerHex = bytesToHex(Memory.allocUtf8String(lower).readByteArray(lower.length));
        var utf16Upper = encodeUtf16LeHex(token);
        var utf16Lower = encodeUtf16LeHex(lower);
        if (containsHex(sampleHex, upperHex)) return 'utf8-upper';
        if (containsHex(sampleHex, lowerHex)) return 'utf8-lower';
        if (containsHex(sampleHex, utf16Upper)) return 'utf16le-upper';
        if (containsHex(sampleHex, utf16Lower)) return 'utf16le-lower';
        return null;
    }

    function noteMemcpyMatch(run, event) {
        if (!run) return;
        if (!run.memcpyMatches) run.memcpyMatches = [];
        if (run.memcpyMatches.length >= 64) {
            run.memcpyMatchDrops = (run.memcpyMatchDrops || 0) + 1;
            return;
        }
        run.memcpyMatches.push(event);
    }

    function installMemcpyHooks() {
        if (state.memcpyHooksInstalled) return;
        var libc = Process.getModuleByName('libc.so');
        ['memcpy', 'memmove', '__memcpy_chk'].forEach(function (name) {
            var addr = null;
            try { addr = libc.getExportByName(name); } catch (e) {}
            if (!addr) return;
            try {
                var listener = Interceptor.attach(addr, {
                    onEnter: function (args) {
                        this.run = state.currentRun;
                        if (!this.run || !this.run.captureMemcpy) return;
                        this.name = name;
                        this.dst = args[0];
                        this.src = args[1];
                        this.size = (name === '__memcpy_chk') ? args[2].toInt32() : args[2].toInt32();
                        this.pc = this.context.pc;
                        this.lr = this.context.lr;
                    },
                    onLeave: function () {
                        var run = this.run;
                        if (!run || !run.captureMemcpy) return;
                        var expected = String(run.expectedToken || '');
                        if (!/^[0-9A-Fa-f]{48}$/.test(expected)) return;
                        var srcInfo = memcpySampleInfo('src', this.src, this.size);
                        var dstInfo = memcpySampleInfo('dst', this.dst, this.size);
                        var srcEnc = detectTokenEncoding(srcInfo.sample_hex, expected);
                        var dstEnc = detectTokenEncoding(dstInfo.sample_hex, expected);
                        if (!srcEnc && !dstEnc) return;
                        noteMemcpyMatch(run, {
                            kind: 'memcpy-hit',
                            func: this.name,
                            threadId: Process.getCurrentThreadId(),
                            pc: fmt(this.pc),
                            lr: fmt(this.lr),
                            size: this.size,
                            src: srcInfo,
                            dst: dstInfo,
                            src_match: srcEnc,
                            dst_match: dstEnc,
                        });
                    }
                });
                state.memcpyHookListeners.push(listener);
            } catch (e) {}
        });
        state.memcpyHooksInstalled = true;
    }

    function uninstallMemcpyHooks() {
        state.memcpyHookListeners.forEach(function (listener) {
            try { listener.detach(); } catch (e) {}
        });
        state.memcpyHookListeners = [];
        state.memcpyHooksInstalled = false;
        if (state.currentRun) {
            state.currentRun.captureMemcpy = false;
        }
        try { Interceptor.flush(); } catch (e) {}
    }

    function hexWindow(addr, radius) {
        var base = ptr(addr).sub(radius);
        var result = {
            base: fmt(base),
        };
        try {
            result.hex = bytesToHex(Memory.readByteArray(base, radius * 2));
        } catch (e) {
            result.error = String(e);
        }
        try {
            if (typeof hexdump === 'function') {
                result.dump = hexdump(base, { length: radius * 2, ansi: false });
            }
        } catch (e) {
            result.dump_error = String(e);
        }
        return result;
    }

    function enumerateExecRanges() {
        var out = [];
        var seen = {};
        ['r-x', '--x', 'rwx', '-wx'].forEach(function (prot) {
            try {
                Process.enumerateRanges(prot).forEach(function (range) {
                    var key = range.base.toString() + ':' + range.size.toString();
                    if (seen[key]) return;
                    seen[key] = true;
                    out.push(range);
                });
            } catch (e) {}
        });
        return out;
    }

    function isJitRange(range) {
        var path = filePathFor(range) || '';
        if (!path) return false;
        if (path.indexOf('jit-cache') >= 0) return true;
        if (path.indexOf('/data/data/com.netmarble.thered/files/') >= 0 &&
            path.indexOf('(deleted)') >= 0) {
            return true;
        }
        return false;
    }

    function chooseJitRanges() {
        return enumerateExecRanges().filter(isJitRange);
    }

    function chooseDeletedJitBases(jitRanges) {
        var grouped = {};
        (jitRanges || []).forEach(function (range) {
            var path = filePathFor(range) || '';
            if (path.indexOf('/data/data/com.netmarble.thered/files/') < 0) return;
            if (path.indexOf('(deleted)') < 0) return;
            if (!grouped[path]) {
                grouped[path] = {
                    path: path,
                    base: range.base,
                    end: range.base.add(range.size),
                };
            } else {
                if (range.base.compare(grouped[path].base) < 0) {
                    grouped[path].base = range.base;
                }
                var end = range.base.add(range.size);
                if (end.compare(grouped[path].end) > 0) {
                    grouped[path].end = end;
                }
            }
        });
        return Object.keys(grouped).map(function (path) {
            var item = grouped[path];
            return {
                path: path,
                base: item.base,
                size: Number(item.end.sub(item.base)),
            };
        });
    }

    function enumerateWritableRanges() {
        var out = [];
        var seen = {};
        ['rw-', 'rwx'].forEach(function (prot) {
            try {
                Process.enumerateRanges(prot).forEach(function (range) {
                    var key = range.base.toString() + ':' + range.size.toString();
                    if (seen[key]) return;
                    seen[key] = true;
                    out.push(range);
                });
            } catch (e) {}
        });
        return out;
    }

    function isHeapLikeRange(range) {
        var path = filePathFor(range) || '';
        if (!path) return true;
        if (path.indexOf('jit-cache') >= 0) return false;
        if (path.indexOf('[stack') >= 0) return false;
        if (path.indexOf('stack_and_tls') >= 0) return false;
        if (path.indexOf('/apex/') === 0) return false;
        if (path.indexOf('/system/') === 0) return false;
        if (path.indexOf('/vendor/') === 0) return false;
        if (path.indexOf('/product/') === 0) return false;
        if (path.indexOf('.so') >= 0) return false;
        if (path.indexOf('.apk') >= 0) return false;
        if (path.indexOf('.oat') >= 0) return false;
        if (path.indexOf('.art') >= 0) return false;
        if (path.indexOf('.vdex') >= 0) return false;
        if (path.indexOf('/data/app/') >= 0) return false;
        return true;
    }

    function chooseHeapRanges() {
        return enumerateWritableRanges().filter(isHeapLikeRange);
    }

    function insideAny(addr, ranges) {
        var p = ptr(addr);
        for (var i = 0; i < ranges.length; i++) {
            var r = ranges[i];
            if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) {
                return true;
            }
        }
        return false;
    }

    function describeRanges(ranges) {
        return ranges.map(function (range) {
            return {
                base: fmt(range.base),
                size: range.size,
                protection: range.protection,
                file: filePathFor(range),
            };
        });
    }

    function renderLocation(event) {
        if (event.module) return event.module + '+' + event.offset;
        if (event.file) return event.file + '+' + event.offset;
        return event.pc;
    }

    function compressFlow(blockTrace, limit) {
        var max = parseInt(limit || 128, 10);
        if (!(max > 0)) max = 128;
        var out = [];
        var lastKey = null;
        for (var i = 0; i < blockTrace.length; i++) {
            var event = blockTrace[i];
            var key = renderLocation(event);
            if (key === lastKey) continue;
            out.push({
                seq: event.seq,
                pc: event.pc,
                module: event.module,
                file: event.file,
                offset: event.offset,
            });
            lastKey = key;
            if (out.length >= max) break;
        }
        return out;
    }

    function compressModuleFlow(blockTrace, limit) {
        var max = parseInt(limit || 64, 10);
        if (!(max > 0)) max = 64;
        var out = [];
        var current = null;

        blockTrace.forEach(function (event) {
            var name = event.module || event.file || '[unknown]';
            if (current && current.name === name) {
                current.blocks++;
                current.lastSeq = event.seq;
                current.lastPc = event.pc;
                return;
            }
            if (out.length >= max) return;
            current = {
                name: name,
                module: event.module,
                file: event.file,
                firstSeq: event.seq,
                lastSeq: event.seq,
                firstPc: event.pc,
                lastPc: event.pc,
                blocks: 1,
            };
            out.push(current);
        });

        return out;
    }

    function createThreadState(threadId) {
        return {
            threadId: threadId,
            seenJit: false,
            lastWasJit: false,
            jitHitCount: 0,
            lastJitPc: null,
            lastJitOffset: null,
            traceStarted: false,
            traceStartedAt: null,
            startPc: null,
            startLr: null,
            blockCount: 0,
            blockTraceDrops: 0,
            blockTrace: [],
            pcHits: {},
            moduleHits: {},
            exitCount: 0,
            lastOutsidePc: null,
            lastOutsideOffset: null,
            lastOutsideModule: null,
            lastOutsideFile: null,
            enterX8: null,
        };
    }

    function normalizeOptions(options) {
        var input = parseJsonMaybe(options) || {};
        var out = {
            freezeOnExit: !!input.freeze_on_exit,
            freezeExitOffsets: null,
            captureMemcpy: input.capture_memcpy !== false,
            disableHeapSearch: !!input.disable_heap_search,
            captureHotProbes: input.capture_hot_probes !== false,
        };
        if (Array.isArray(input.freeze_exit_offsets) && input.freeze_exit_offsets.length > 0) {
            out.freezeExitOffsets = input.freeze_exit_offsets.map(function (item) {
                return String(item).toLowerCase();
            });
        }
        return out;
    }

    function createRun(challenge, jitRanges, options) {
        var opts = normalizeOptions(options);
        return {
            challenge: String(challenge),
            startedAt: isoNow(),
            endedAt: null,
            token: null,
            error: null,
            expectedToken: null,
            jitRanges: describeRanges(jitRanges),
            callThreadId: null,
            followed: [],
            seq: 0,
            globalJitSeen: false,
            lastJitThreadId: null,
            freezeOnExit: opts.freezeOnExit,
            freezeExitOffsets: opts.freezeExitOffsets,
            freezeTriggered: false,
            freezeInfo: null,
            freezeStatusPath: FREEZE_STATUS_PATH,
            captureMemcpy: opts.captureMemcpy,
            disableHeapSearch: opts.disableHeapSearch,
            captureHotProbes: opts.captureHotProbes,
            memcpyMatches: [],
            memcpyMatchDrops: 0,
            heapSearch: null,
            exitEvents: [],
            exitEventDrops: 0,
            transitionEvents: [],
            transitionEventDrops: 0,
            hotExitEvents: [],
            hotExitEventDrops: 0,
            threads: {},
            failures: [],
        };
    }

    function getThreadState(run, threadId) {
        var key = String(threadId);
        var existing = run.threads[key];
        if (existing) return existing;
        var created = createThreadState(threadId);
        run.threads[key] = created;
        return created;
    }

    function pushExitEvent(run, event) {
        if (run.exitEvents.length >= MAX_EXIT_EVENTS) {
            run.exitEventDrops++;
            return;
        }
        run.exitEvents.push(event);
    }

    function pushTransitionEvent(run, event) {
        if (run.transitionEvents.length >= MAX_EXIT_EVENTS) {
            run.transitionEventDrops++;
            return;
        }
        run.transitionEvents.push(event);
    }

    function pushHotExitEvent(run, event) {
        if (run.hotExitEvents.length >= MAX_EXIT_EVENTS) {
            run.hotExitEventDrops++;
            return;
        }
        run.hotExitEvents.push(event);
    }

    function contextReg(context, regName) {
        var name = String(regName || '').trim().toLowerCase();
        if (!name) return null;
        if (name === 'lr' || name === 'x30') return context.lr;
        if (name === 'sp') return context.sp;
        if (name === 'pc') return context.pc;
        var m = name.match(/^[wx](\d+)$/);
        if (m) {
            return context['x' + m[1]];
        }
        return context[name] || null;
    }

    function deriveBranchTarget(context, instruction) {
        if (!instruction) return null;
        var mnemonic = String(instruction.mnemonic || '').toLowerCase();
        var opStr = String(instruction.opStr || '').trim();
        if (mnemonic === 'ret') {
            return contextReg(context, opStr || 'lr');
        }
        if (mnemonic === 'br' || mnemonic === 'blr') {
            return contextReg(context, opStr);
        }
        if (mnemonic === 'b' || mnemonic === 'bl') {
            if (/^0x[0-9a-f]+$/i.test(opStr)) {
                try { return ptr(opStr); } catch (e) {}
            }
        }
        return null;
    }

    function ensureHotExitHooks(jitRanges) {
        var bases = chooseDeletedJitBases(jitRanges);
        bases.forEach(function (item) {
            HOT_EXIT_OFFSETS.forEach(function (offset) {
                if (!(offset >= 0 && offset < item.size)) return;
                var addr = item.base.add(offset);
                var key = addr.toString();
                if (state.hotExitHookKeys[key]) return;
                try {
                    Instruction.parse(addr);
                } catch (e) {
                    return;
                }
                try {
                    Interceptor.attach(addr, {
                        onEnter: function () {
                            var run = state.currentRun;
                            if (!run) return;
                            var instruction = null;
                            try {
                                instruction = Instruction.parse(addr);
                            } catch (e) {}
                            var target = deriveBranchTarget(this.context, instruction);
                            if (target === null) return;
                            if (insideAny(target, run.jitRangesRaw || [])) return;
                            var threadId = Process.getCurrentThreadId();
                            var loc = resolveLocation(target);
                            var event = {
                                seq: ++run.seq,
                                threadId: threadId,
                                hookPc: fmt(addr),
                                hookOffset: '0x' + offset.toString(16),
                                instruction: instruction ? instruction.toString() : null,
                                target: fmt(target),
                                targetModule: loc.module,
                                targetFile: loc.file,
                                targetOffset: loc.offset,
                                lr: fmt(this.context.lr),
                                x0: fmt(this.context.x0),
                                x1: fmt(this.context.x1),
                                x2: fmt(this.context.x2),
                                x8: fmt(this.context.x8),
                            };
                            if (run.captureHotProbes) {
                                event.x8_probe = probeOutputObject(this.context.x8, run.expectedToken);
                                event.x19_obj68 = probeOutputObject(this.context.x19, run.expectedToken);
                            }
                            pushHotExitEvent(run, event);
                            triggerFreezeFromHotHook(run, event, this.context);
                            if (run.freezeOnExit || run.freezeTriggered || run.disableHeapSearch) return;
                            if (run.heapSearch === null) {
                                maybeSearchHeaps(run, threadId, loc, this.context);
                            }
                        }
                    });
                    state.hotExitHookKeys[key] = true;
                } catch (e) {}
            });
        });
    }

    function onBlock(run, threadId, pc, context, jitRanges) {
        var thread = getThreadState(run, threadId);
        var loc = resolveLocation(pc);

        if (insideAny(pc, jitRanges)) {
            var enterX8 = untagPtr(context.x8);
            if (!thread.lastWasJit) {
                pushTransitionEvent(run, {
                    seq: ++run.seq,
                    direction: 'enter-jit',
                    threadId: threadId,
                    from_pc: thread.lastOutsidePc,
                    from_module: thread.lastOutsideModule,
                    from_file: thread.lastOutsideFile,
                    from_offset: thread.lastOutsideOffset,
                    to_jit_pc: loc.pc,
                    to_jit_offset: loc.offset,
                    enter_x8: fmt(enterX8),
                    enter_x8_probe: probeOutputObject(enterX8, run.expectedToken),
                    lr: fmt(context.lr),
                    sp: fmt(context.sp),
                    x0: fmt(context.x0),
                    x1: fmt(context.x1),
                    x2: fmt(context.x2),
                    x8: fmt(context.x8),
                });
            }
            if (isLikelyPointer(enterX8)) {
                thread.enterX8 = fmt(enterX8);
            }
            thread.seenJit = true;
            thread.lastWasJit = true;
            thread.jitHitCount++;
            thread.lastJitPc = loc.pc;
            thread.lastJitOffset = loc.offset;
            run.globalJitSeen = true;
            run.lastJitThreadId = threadId;
            return;
        }

        if (!thread.seenJit || !thread.lastWasJit) {
            thread.lastOutsidePc = loc.pc;
            thread.lastOutsideOffset = loc.offset;
            thread.lastOutsideModule = loc.module;
            thread.lastOutsideFile = loc.file;
            return;
        }
        thread.lastWasJit = false;

        if (!thread.traceStarted) {
            thread.traceStarted = true;
            thread.traceStartedAt = isoNow();
            thread.startPc = loc.pc;
            thread.startLr = fmt(context.lr);
            maybeSearchHeaps(run, threadId, loc, context);
        }

        pushTransitionEvent(run, {
            seq: ++run.seq,
            direction: 'leave-jit',
            threadId: threadId,
            from_jit_pc: thread.lastJitPc,
            from_jit_offset: thread.lastJitOffset,
            to_pc: loc.pc,
            to_module: loc.module,
            to_file: loc.file,
            to_offset: loc.offset,
            saved_enter_x8: thread.enterX8,
            saved_enter_x8_probe: probeOutputObject(thread.enterX8, run.expectedToken),
            current_x8: fmt(untagPtr(context.x8)),
            current_x8_probe: probeOutputObject(context.x8, run.expectedToken),
            lr: fmt(context.lr),
            sp: fmt(context.sp),
            x0: fmt(context.x0),
            x1: fmt(context.x1),
            x2: fmt(context.x2),
            x8: fmt(context.x8),
        });

        var moduleKey = loc.module || loc.file || '[unknown]';
        var pcKey = loc.pc;
        var hit = bump(thread.pcHits, pcKey);
        bump(thread.moduleHits, moduleKey);
        thread.blockCount++;
        thread.exitCount++;

        var event = {
            seq: ++run.seq,
            threadId: threadId,
            callThread: threadId === run.callThreadId,
            from_jit_pc: thread.lastJitPc,
            from_jit_offset: thread.lastJitOffset,
            pc: pcKey,
            module: loc.module,
            file: loc.file,
            offset: loc.offset,
            saved_enter_x8: thread.enterX8,
            saved_enter_x8_probe: probeOutputObject(thread.enterX8, run.expectedToken),
            current_x8: fmt(untagPtr(context.x8)),
            current_x8_probe: probeOutputObject(context.x8, run.expectedToken),
            lr: fmt(context.lr),
            sp: fmt(context.sp),
            x0: fmt(context.x0),
            x1: fmt(context.x1),
            x2: fmt(context.x2),
            x8: fmt(context.x8),
            hit: hit,
        };

        pushExitEvent(run, event);
        thread.lastOutsidePc = loc.pc;
        thread.lastOutsideOffset = loc.offset;
        thread.lastOutsideModule = loc.module;
        thread.lastOutsideFile = loc.file;
        triggerFreeze(run, event, context);

        if (thread.blockTrace.length >= MAX_BLOCK_TRACE) {
            thread.blockTraceDrops++;
            return;
        }
        thread.blockTrace.push(event);
    }

    function buildThreadSummary(thread) {
        return {
            threadId: thread.threadId,
            seenJit: thread.seenJit,
            jitHitCount: thread.jitHitCount,
            lastJitPc: thread.lastJitPc,
            lastJitOffset: thread.lastJitOffset,
            traceStarted: thread.traceStarted,
            traceStartedAt: thread.traceStartedAt,
            startPc: thread.startPc,
            startLr: thread.startLr,
            blockCount: thread.blockCount,
            blockTraceDrops: thread.blockTraceDrops,
            exitCount: thread.exitCount,
        };
    }

    function shouldFreezeForExit(run, event) {
        if (!run || !run.freezeOnExit || run.freezeTriggered) return false;
        if (event.callThread) return false;
        if (run.freezeExitOffsets && run.freezeExitOffsets.length > 0) {
            return run.freezeExitOffsets.indexOf(String(event.from_jit_offset || '').toLowerCase()) >= 0;
        }
        return true;
    }

    function shouldFreezeForHotHook(run, event) {
        if (!run || !run.freezeOnExit || run.freezeTriggered) return false;
        if (run.freezeExitOffsets && run.freezeExitOffsets.length > 0) {
            return run.freezeExitOffsets.indexOf(String(event.hookOffset || '').toLowerCase()) >= 0;
        }
        return true;
    }

    function triggerFreeze(run, event, context) {
        if (!shouldFreezeForExit(run, event)) return;
        run.freezeTriggered = true;
        run.freezeInfo = {
            status: 'triggered',
            timestamp: isoNow(),
            pid: Process.id,
            thread_id: event.threadId,
            challenge: run.challenge,
            token: run.token,
            expectedToken: run.expectedToken,
            freeze_status_path: FREEZE_STATUS_PATH,
            event: event,
            registers: captureRegs(context),
            probes: {
                saved_enter_x8: probeOutputObject(event.saved_enter_x8, run.expectedToken),
                current_x8: probeOutputObject(context.x8, run.expectedToken),
                x19_obj68: probeOutputObject(context.x19, run.expectedToken),
                x19_objc8: probeSsoAt(untagPtr(context.x19).add(0xc8), run.expectedToken),
                x0_objc8: probeSsoAt(untagPtr(context.x0).add(0xc8), run.expectedToken),
                sp_plus_0x50: probeSsoAt(ptr(context.sp).add(0x50), run.expectedToken),
                sp_plus_0x590: probeSsoAt(ptr(context.sp).add(0x590), run.expectedToken),
            },
            memcpy_matches: run.memcpyMatches.slice(),
            memcpy_match_drops: run.memcpyMatchDrops,
        };
        writeFreezeStatus(run.freezeInfo);
        try {
            memdumpGetLibc().kill(Process.id, 19);
        } catch (e) {
            run.freezeInfo = {
                status: 'error',
                timestamp: isoNow(),
                error: String(e),
                challenge: run.challenge,
                freeze_status_path: FREEZE_STATUS_PATH,
            };
            writeFreezeStatus(run.freezeInfo);
        }
    }

    function triggerFreezeFromHotHook(run, event, context) {
        if (!shouldFreezeForHotHook(run, event)) return;
        run.freezeTriggered = true;
        run.freezeInfo = {
            status: 'triggered',
            timestamp: isoNow(),
            pid: Process.id,
            thread_id: event.threadId,
            challenge: run.challenge,
            token: run.token,
            expectedToken: run.expectedToken,
            freeze_status_path: FREEZE_STATUS_PATH,
            event: event,
            registers: captureRegs(context),
            probes: {
                current_x8: probeOutputObject(context.x8, run.expectedToken),
                x19_obj68: probeOutputObject(context.x19, run.expectedToken),
                x19_objc8: probeSsoAt(untagPtr(context.x19).add(0xc8), run.expectedToken),
                x0_objc8: probeSsoAt(untagPtr(context.x0).add(0xc8), run.expectedToken),
                sp_plus_0x50: probeSsoAt(ptr(context.sp).add(0x50), run.expectedToken),
                sp_plus_0x590: probeSsoAt(ptr(context.sp).add(0x590), run.expectedToken),
            },
            memcpy_matches: run.memcpyMatches.slice(),
            memcpy_match_drops: run.memcpyMatchDrops,
        };
        writeFreezeStatus(run.freezeInfo);
        try {
            memdumpGetLibc().kill(Process.id, 19);
        } catch (e) {
            run.freezeInfo = {
                status: 'error',
                timestamp: isoNow(),
                error: String(e),
                challenge: run.challenge,
                freeze_status_path: FREEZE_STATUS_PATH,
            };
            writeFreezeStatus(run.freezeInfo);
        }
    }

    function selectTraceThread(run) {
        var all = Object.keys(run.threads).map(function (key) { return run.threads[key]; });
        var traced = all.filter(function (thread) { return thread.traceStarted; });
        if (traced.length > 0) {
            traced.sort(function (a, b) { return b.blockCount - a.blockCount; });
            return traced[0];
        }
        var seen = all.filter(function (thread) { return thread.seenJit; });
        if (seen.length > 0) {
            seen.sort(function (a, b) { return b.jitHitCount - a.jitHitCount; });
            return seen[0];
        }
        return null;
    }

    function scanPatternsInRanges(ranges, defs, maxHits) {
        var limit = parseInt(maxHits || 64, 10);
        if (!(limit > 0)) limit = 64;
        var hits = [];
        for (var i = 0; i < ranges.length; i++) {
            var range = ranges[i];
            for (var j = 0; j < defs.length; j++) {
                var def = defs[j];
                if (hits.length >= limit) return hits;
                try {
                    var matches = Memory.scanSync(range.base, range.size, def.pattern);
                    for (var k = 0; k < matches.length; k++) {
                        if (hits.length >= limit) return hits;
                        var m = matches[k];
                        hits.push({
                            kind: def.kind,
                            addr: fmt(m.address),
                            size: m.size,
                            range_base: fmt(range.base),
                            range_size: range.size,
                            protection: range.protection,
                            file: filePathFor(range),
                            window: hexWindow(m.address, Math.min(64, def.windowRadius)),
                        });
                    }
                } catch (e) {}
            }
        }
        return hits;
    }

    function maybeSearchHeaps(run, threadId, loc, context) {
        if (run.heapSearch !== null) return;
        var expected = String(run.expectedToken || '');
        if (!/^[0-9A-Fa-f]{48}$/.test(expected)) {
            run.heapSearch = {
                triggered: false,
                reason: 'expected token unavailable',
            };
            return;
        }

        var upper = expected.toUpperCase();
        var lower = expected.toLowerCase();
        var defs = [{
            kind: 'ascii-upper',
            pattern: asciiToPattern(upper),
            windowRadius: upper.length + 32,
        }];
        if (lower !== upper) {
            defs.push({
                kind: 'ascii-lower',
                pattern: asciiToPattern(lower),
                windowRadius: lower.length + 32,
            });
        }
        var rawPattern = hexToPattern(expected);
        if (rawPattern !== null) {
            defs.push({
                kind: 'raw-bytes',
                pattern: rawPattern,
                windowRadius: (expected.length / 2) + 32,
            });
        }

        var ranges = chooseHeapRanges();
        var hits = scanPatternsInRanges(ranges, defs, 64);
        run.heapSearch = {
            triggered: true,
            expectedToken: upper,
            triggeredAt: isoNow(),
            triggerThreadId: threadId,
            triggerPc: loc.pc,
            triggerModule: loc.module,
            triggerFile: loc.file,
            triggerOffset: loc.offset,
            triggerLr: fmt(context.lr),
            heapRangeCount: ranges.length,
            heapRanges: describeRanges(ranges),
            hits: hits,
        };
    }

    function buildSummary(run) {
        var selected = selectTraceThread(run);
        var allThreads = Object.keys(run.threads).map(function (key) { return run.threads[key]; });
        var perThread = allThreads
            .map(buildThreadSummary)
            .sort(function (a, b) {
                if (b.blockCount !== a.blockCount) return b.blockCount - a.blockCount;
                return b.jitHitCount - a.jitHitCount;
            });

        var traceThreads = perThread.filter(function (thread) { return thread.traceStarted; }).map(function (thread) {
            return thread.threadId;
        });
        var seenJit = run.globalJitSeen;

        if (run.callThreadId !== null) {
            var callThread = run.threads[String(run.callThreadId)];
            if (callThread && callThread.traceStarted) {
                selected = callThread;
                traceThreads = [run.callThreadId];
            }
        }

        var stopReason = 'call-complete-before-jit';
        if (traceThreads.length > 0) {
            stopReason = 'call-complete';
        } else if (seenJit) {
            stopReason = 'call-complete-without-postjit-block';
        }

        return {
            ok: !run.error,
            challenge: run.challenge,
            token: run.token,
            expectedToken: run.expectedToken,
            startedAt: run.startedAt,
            endedAt: run.endedAt,
            callThreadId: run.callThreadId,
            followed: run.followed,
            jitRanges: run.jitRanges,
            lastJitThreadId: run.lastJitThreadId,
            freezeOnExit: run.freezeOnExit,
            freezeTriggered: run.freezeTriggered,
            freezeInfo: run.freezeInfo,
            freezeStatusPath: run.freezeStatusPath,
            memcpyMatchCount: run.memcpyMatches.length,
            memcpyMatchDrops: run.memcpyMatchDrops,
            memcpyMatches: run.memcpyMatches,
            heapSearch: run.heapSearch,
            transitionEventCount: run.transitionEvents.length,
            transitionEventDrops: run.transitionEventDrops,
            transitionEvents: run.transitionEvents,
            hotExitEventCount: run.hotExitEvents.length,
            hotExitEventDrops: run.hotExitEventDrops,
            hotExitEvents: run.hotExitEvents,
            exitEventCount: run.exitEvents.length,
            exitEventDrops: run.exitEventDrops,
            exitEvents: run.exitEvents,
            selectedThread: selected ? selected.threadId : null,
            traceThreads: traceThreads,
            seenJit: seenJit,
            stopReason: stopReason,
            blockCount: selected ? selected.blockCount : 0,
            blockTraceDrops: selected ? selected.blockTraceDrops : 0,
            traceStartedAt: selected ? selected.traceStartedAt : null,
            startPc: selected ? selected.startPc : null,
            startLr: selected ? selected.startLr : null,
            lastJitPc: selected ? selected.lastJitPc : null,
            lastJitOffset: selected ? selected.lastJitOffset : null,
            moduleFlow: selected ? compressModuleFlow(selected.blockTrace, 96) : [],
            flow: selected ? compressFlow(selected.blockTrace, 256) : [],
            pcTop: selected ? sortedTop(selected.pcHits, 64, 'pc') : [],
            moduleTop: selected ? sortedTop(selected.moduleHits, 32, 'module') : [],
            perThread: perThread,
            error: run.error,
            failures: run.failures.slice(),
            blockTrace: selected ? selected.blockTrace : [],
        };
    }

    function enumerateTraceThreadIds() {
        var seen = {};
        var out = [];
        try {
            Process.enumerateThreads().forEach(function (thread) {
                var tid = parseInt(thread.id, 10);
                if (!(tid > 0)) return;
                if (seen[tid]) return;
                seen[tid] = true;
                out.push(tid);
            });
        } catch (e) {}
        return out;
    }

    function callCertValueAcrossThreads(challenge, run, jitRanges) {
        var followed = [];
        try {
            Java.performNow(function () {
                run.callThreadId = Process.getCurrentThreadId();
                var threadIds = enumerateTraceThreadIds();
                run.followed = threadIds.slice();

                threadIds.forEach(function (tid) {
                    followed.push(tid);
                    Stalker.follow(tid, {
                        transform: function (iterator) {
                            var instruction = iterator.next();
                            if (instruction === null) {
                                return;
                            }

                            var blockHead = ptr(instruction.address);
                            (function (capturedPc, threadId) {
                                iterator.putCallout(function (context) {
                                    onBlock(run, threadId, capturedPc, context, jitRanges);
                                });
                            })(blockHead, tid);

                            iterator.keep();
                            instruction = iterator.next();
                            while (instruction !== null) {
                                iterator.keep();
                                instruction = iterator.next();
                            }
                        }
                    });
                });

                var result = null;
                try {
                    var inst = Java.use('nmss.app.NmssSa').getInstObj();
                    if (!inst) {
                        result = 'NO_INSTANCE';
                    } else {
                        result = inst.getCertValue(challenge);
                        if (result) result = result.toString();
                    }
                } catch (inner) {
                    result = 'ERR:' + inner;
                }
                run.token = String(result || '');
            });
        } finally {
            followed.forEach(function (tid) {
                try { Stalker.unfollow(tid); } catch (e) {
                    run.failures.push({ where: 'unfollow:' + tid, error: String(e) });
                }
            });
            try { Stalker.garbageCollect(); } catch (e) {
                run.failures.push({ where: 'garbageCollect', error: String(e) });
            }
        }
    }

    globalThis.__jitPostJitRenderTraceRun = function (challenge, expectedToken, options) {
        var targetChallenge = String(challenge || DEFAULT_CHALLENGE);
        if (!/^[0-9A-Fa-f]{16}$/.test(targetChallenge)) {
            return JSON.stringify({
                ok: false,
                error: 'challenge must be 16 hex chars',
                challenge: targetChallenge,
            });
        }

        resetLocationCache();
        installMemcpyHooks();

        var jitRanges = chooseJitRanges();
        if (jitRanges.length === 0) {
            return JSON.stringify({
                ok: false,
                error: 'jit exec ranges not found',
            });
        }

        var run = createRun(targetChallenge, jitRanges, options);
        run.jitRangesRaw = jitRanges;
        if (/^[0-9A-Fa-f]{48}$/.test(String(expectedToken || ''))) {
            run.expectedToken = String(expectedToken).toUpperCase();
        }
        ensureHotExitHooks(jitRanges);
        state.currentRun = run;
        try {
            callCertValueAcrossThreads(targetChallenge, run, jitRanges);
        } catch (e) {
            run.error = String(e);
        } finally {
            state.currentRun = null;
        }

        run.endedAt = isoNow();
        state.last = buildSummary(run);
        return JSON.stringify(state.last);
    };

    globalThis.__jitPostJitRenderFreezeRun = function (challenge, expectedToken, options) {
        var parsed = parseJsonMaybe(options) || {};
        parsed.freeze_on_exit = true;
        if (!Array.isArray(parsed.freeze_exit_offsets) || parsed.freeze_exit_offsets.length === 0) {
            parsed.freeze_exit_offsets = ['0x5f710'];
        }
        if (parsed.capture_memcpy === undefined) parsed.capture_memcpy = true;
        return globalThis.__jitPostJitRenderTraceRun(challenge, expectedToken, JSON.stringify(parsed));
    };

    globalThis.__jitPostJitRenderFreezeArm = function (challenge, expectedToken, options) {
        var targetChallenge = String(challenge || DEFAULT_CHALLENGE);
        if (!/^[0-9A-Fa-f]{16}$/.test(targetChallenge)) {
            return JSON.stringify({
                ok: false,
                error: 'challenge must be 16 hex chars',
                challenge: targetChallenge,
            });
        }

        resetLocationCache();
        installMemcpyHooks();

        var jitRanges = chooseJitRanges();
        if (jitRanges.length === 0) {
            return JSON.stringify({
                ok: false,
                error: 'jit exec ranges not found',
            });
        }

        var parsed = parseJsonMaybe(options) || {};
        parsed.freeze_on_exit = true;
        if (!Array.isArray(parsed.freeze_exit_offsets) || parsed.freeze_exit_offsets.length === 0) {
            parsed.freeze_exit_offsets = ['0x5f710'];
        }
        if (parsed.capture_memcpy === undefined) parsed.capture_memcpy = true;

        var run = createRun(targetChallenge, jitRanges, JSON.stringify(parsed));
        run.jitRangesRaw = jitRanges;
        if (/^[0-9A-Fa-f]{48}$/.test(String(expectedToken || ''))) {
            run.expectedToken = String(expectedToken).toUpperCase();
        }
        ensureHotExitHooks(jitRanges);
        state.currentRun = run;
        run.freezeInfo = {
            status: 'armed',
            timestamp: isoNow(),
            pid: Process.id,
            challenge: run.challenge,
            expectedToken: run.expectedToken,
            freeze_status_path: FREEZE_STATUS_PATH,
            freeze_exit_offsets: run.freezeExitOffsets,
            capture_memcpy: run.captureMemcpy,
        };
        writeFreezeStatus(run.freezeInfo);
        state.last = {
            ok: true,
            armed: true,
            challenge: run.challenge,
            expectedToken: run.expectedToken,
            freezeStatusPath: FREEZE_STATUS_PATH,
            freezeExitOffsets: run.freezeExitOffsets,
            captureMemcpy: run.captureMemcpy,
            jitRanges: run.jitRanges,
        };
        return JSON.stringify(state.last);
    };

    globalThis.__jitPostJitRenderDisarm = function () {
        var active = state.currentRun;
        state.currentRun = null;
        return JSON.stringify({
            ok: true,
            disarmed: true,
            hadActiveRun: !!active,
            challenge: active ? active.challenge : null,
            freezeTriggered: active ? active.freezeTriggered : false,
        });
    };

    globalThis.__jitPostJitRenderHotArm = function (challenge, expectedToken, options) {
        var targetChallenge = String(challenge || DEFAULT_CHALLENGE);
        if (!/^[0-9A-Fa-f]{16}$/.test(targetChallenge)) {
            return JSON.stringify({
                ok: false,
                error: 'challenge must be 16 hex chars',
                challenge: targetChallenge,
            });
        }

        resetLocationCache();
        installMemcpyHooks();

        var jitRanges = chooseJitRanges();
        if (jitRanges.length === 0) {
            return JSON.stringify({
                ok: false,
                error: 'jit exec ranges not found',
            });
        }

        var parsed = parseJsonMaybe(options) || {};
        parsed.freeze_on_exit = false;
        if (parsed.capture_memcpy === undefined) parsed.capture_memcpy = true;
        if (parsed.disable_heap_search === undefined) parsed.disable_heap_search = true;
        if (parsed.capture_hot_probes === undefined) parsed.capture_hot_probes = true;

        var run = createRun(targetChallenge, jitRanges, JSON.stringify(parsed));
        run.jitRangesRaw = jitRanges;
        if (/^[0-9A-Fa-f]{48}$/.test(String(expectedToken || ''))) {
            run.expectedToken = String(expectedToken).toUpperCase();
        }
        ensureHotExitHooks(jitRanges);
        state.currentRun = run;
        state.last = {
            ok: true,
            armed: true,
            mode: 'hot-only',
            challenge: run.challenge,
            expectedToken: run.expectedToken,
            captureMemcpy: run.captureMemcpy,
            disableHeapSearch: run.disableHeapSearch,
            captureHotProbes: run.captureHotProbes,
            jitRanges: run.jitRanges,
        };
        return JSON.stringify(state.last);
    };

    globalThis.__jitPostJitRenderMemcpyArm = function (challenge, expectedToken, options) {
        var targetChallenge = String(challenge || DEFAULT_CHALLENGE);
        if (!/^[0-9A-Fa-f]{16}$/.test(targetChallenge)) {
            return JSON.stringify({
                ok: false,
                error: 'challenge must be 16 hex chars',
                challenge: targetChallenge,
            });
        }

        resetLocationCache();
        installMemcpyHooks();

        var jitRanges = chooseJitRanges();
        var parsed = parseJsonMaybe(options) || {};
        parsed.freeze_on_exit = false;
        parsed.capture_memcpy = true;
        parsed.disable_heap_search = true;
        parsed.capture_hot_probes = false;

        var run = createRun(targetChallenge, jitRanges, JSON.stringify(parsed));
        run.jitRangesRaw = jitRanges;
        if (/^[0-9A-Fa-f]{48}$/.test(String(expectedToken || ''))) {
            run.expectedToken = String(expectedToken).toUpperCase();
        }
        state.currentRun = run;
        state.last = {
            ok: true,
            armed: true,
            mode: 'memcpy-only',
            challenge: run.challenge,
            expectedToken: run.expectedToken,
            captureMemcpy: run.captureMemcpy,
        };
        return JSON.stringify(state.last);
    };

    globalThis.__jitPostJitRenderMemcpyUnhook = function () {
        uninstallMemcpyHooks();
        return JSON.stringify({
            ok: true,
            memcpyHooksInstalled: state.memcpyHooksInstalled,
            listenerCount: state.memcpyHookListeners.length,
            currentRunCaptureMemcpy: state.currentRun ? state.currentRun.captureMemcpy : null,
        });
    };

    globalThis.__jitPostJitRenderTraceDump = function () {
        if (state.currentRun) {
            state.last = buildSummary(state.currentRun);
        }
        return JSON.stringify(state.last);
    };
})();
