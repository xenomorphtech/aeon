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
    };

    var PTR_MASK = ptr('0x00FFFFFFFFFFFFFF');
    var PAGE_MASK = ptr('0xFFFFFFFFFFFFF000');
    var EXEC_PROTECTIONS = ['r-x', '--x'];
    var ACTIVE_EXEC_SIZE = 0x50000;
    var CERT_CORRIDOR_START = 0x12000;
    var CERT_CORRIDOR_END = 0x20000;
    var PAGE_SIZE = 0x1000;
    var STALKER_REPEAT_SAMPLE = 256;
    var MEMDUMP_MAX_REGION = 50 * 1024 * 1024;
    var MEMDUMP_DEVICE_DIR = '/data/local/tmp/aeon_capture/memdump';
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

    function readUtf8Maybe(addr, maxLen) {
        try { return Memory.readUtf8String(ptr(addr), maxLen); } catch (e) { return null; }
    }

    function readBytesMaybe(addr, size) {
        try { return bytesToHex(Memory.readByteArray(ptr(addr), size)); } catch (e) { return null; }
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
        state.failures.push({
            label: label,
            error: String(error),
        });
        if (state.failures.length > 32) {
            state.failures.shift();
        }
        console.log('[CAPTURE] [GATE] ' + label + ' failed: ' + error);
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

    function clearStalkerData() {
        state.stalker.drops = 0;
        state.stalker.events = [];
        state.stalker.pcHits = {};
        state.stalker.threadHits = {};
        state.stalker.blockCount = 0;
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
            var event = {
                base: fmtPtr(state.currentBase),
                size: '0x' + state.currentSize.toString(16),
                file: filePathFor(range),
                protection: 'r--',
                ok: !!ok,
            };
            state.protections.push(event);
            if (state.protections.length > 32) {
                state.protections.shift();
            }
            console.log('[CAPTURE] [GATE] protect jit ' + event.base + ' size=' + event.size + ' -> ' + event.protection + ' ok=' + event.ok);
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
        if (maxSize <= CERT_CORRIDOR_START) {
            noteFailure('install corridor ' + fmtPtr(range.base), 'range too small');
            return;
        }
        var corridorBase = range.base.add(CERT_CORRIDOR_START);
        var corridorSize = Math.min(maxSize, CERT_CORRIDOR_END) - CERT_CORRIDOR_START;
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
            if (!isTargetTrapException(details)) {
                event.matched_trap = false;
                pushException(event);
                console.log('[CAPTURE] [GATE] pass exception type=' + event.type +
                            ' address=' + event.address +
                            ' pc=' + event.pc +
                            ' lr=' + event.lr);
                return false;
            }
            event.matched_trap = true;
            var pageBase = details.context ? pageBaseFor(details.context.pc) : pageBaseFor(details.address);
            var pageKey = pageBase ? pageBase.toString() : '0x0';
            var pcKey = event.pc || '0x0';
            var lrKey = event.lr || '0x0';
            var edgeKey = lrKey + '->' + pcKey;
            var threadId = details.threadId;
            if (threadId === null || threadId === undefined) {
                threadId = currentThreadIdMaybe();
            }
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
            if (trapCount <= 4 || (trapCount % 1024) === 0) {
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
        rpc.exports.callCert = function (challenge) {
            var memdumpPending = state.memdump.armed || state.memdump.captured;
            if (!state.fixedTraceArm && !memdumpPending) {
                var plainToken = originalCallCertExport(challenge);
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
                var mdToken = originalCallCertExport(challenge);
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
