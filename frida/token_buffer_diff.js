// Helpers for locating and tracking the cert token buffer in writable memory.

'use strict';

(function () {
    if (globalThis.__tokenBufferDiff && globalThis.__tokenBufferDiff.installed) {
        console.log('[CAPTURE] [TOKDIFF] relay already installed');
        return;
    }

    var state = globalThis.__tokenBufferDiff = {
        installed: true,
        watch: {
            enabled: false,
            base: null,
            size: 0,
            events: [],
            seq: 0,
            drops: 0,
            maxEvents: 64,
        },
    };

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function filePathFor(range) {
        try {
            return range && range.file && range.file.path ? String(range.file.path) : null;
        } catch (e) {
            return null;
        }
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

    function hexWindow(addr, radius) {
        var base = ptr(addr).sub(radius);
        var result = {
            base: base.toString(),
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

    function asciiToPattern(s) {
        var out = [];
        for (var i = 0; i < s.length; i++) {
            var h = s.charCodeAt(i).toString(16);
            out.push(h.length === 1 ? '0' + h : h);
        }
        return out.join(' ');
    }

    function writableRanges() {
        var out = [];
        var seen = {};
        ['rw-', 'rwx'].forEach(function (prot) {
            try {
                Process.enumerateRanges(prot).forEach(function (range) {
                    var key = range.base.toString() + ':' + range.size;
                    if (seen[key]) return;
                    seen[key] = true;
                    out.push(range);
                });
            } catch (e) {}
        });
        return out;
    }

    function scanToken(token, limit) {
        var pattern = asciiToPattern(token);
        var hits = [];
        writableRanges().forEach(function (range) {
            if (hits.length >= limit) return;
            try {
                var matches = Memory.scanSync(range.base, range.size, pattern);
                matches.forEach(function (m) {
                    if (hits.length >= limit) return;
                    hits.push({
                        addr: m.address.toString(),
                        size: m.size,
                        range_base: range.base.toString(),
                        range_size: range.size,
                        protection: range.protection,
                        file: filePathFor(range),
                        window: hexWindow(m.address, Math.min(64, token.length + 32)),
                    });
                });
            } catch (e) {}
        });
        return hits;
    }

    function snapshotAddrs(addrs, radius) {
        return addrs.map(function (addr) {
            return {
                addr: fmt(addr),
                snapshot: hexWindow(addr, radius),
            };
        });
    }

    function pushWatchEvent(event) {
        if (state.watch.events.length >= state.watch.maxEvents) {
            state.watch.events.shift();
            state.watch.drops++;
        }
        state.watch.events.push(event);
    }

    function disableWatch() {
        if (!state.watch.enabled) return 'OK';
        try {
            MemoryAccessMonitor.disable();
        } catch (e) {}
        state.watch.enabled = false;
        return 'OK';
    }

    function safeBacktrace(context) {
        try {
            return Thread.backtrace(context, Backtracer.FUZZY).slice(0, 6).map(function (addr) {
                return fmt(addr);
            });
        } catch (e) {
            return [{ error: String(e) }];
        }
    }

    globalThis.__tokenWritableHits = function (token, limit) {
        var maxHits = typeof limit === 'number' && limit > 0 ? limit : 32;
        return JSON.stringify({
            token: token,
            hits: scanToken(token, maxHits),
        });
    };

    globalThis.__tokenSnapshot = function (jsonAddrs, radius) {
        var addrs = jsonAddrs;
        if (typeof jsonAddrs === 'string') {
            addrs = JSON.parse(jsonAddrs);
        }
        var r = typeof radius === 'number' && radius > 0 ? radius : 96;
        return JSON.stringify({
            snapshots: snapshotAddrs(addrs, r),
        });
    };

    globalThis.__tokenWatchEnable = function (addr, size) {
        disableWatch();
        state.watch.events.length = 0;
        state.watch.seq = 0;
        state.watch.drops = 0;
        state.watch.base = fmt(addr);
        state.watch.size = size >>> 0;
        try {
            MemoryAccessMonitor.enable([{ base: ptr(addr), size: size >>> 0 }], {
                onAccess: function (details) {
                    var isWrite = details.operation === 'write';
                    if (!isWrite) return;
                    pushWatchEvent({
                        seq: ++state.watch.seq,
                        operation: details.operation,
                        from: fmt(details.from),
                        address: fmt(details.address),
                        rangeIndex: details.rangeIndex,
                        pageIndex: details.pageIndex,
                        pagesCompleted: details.pagesCompleted,
                        pagesTotal: details.pagesTotal,
                        context: {
                            pc: fmt(details.context.pc),
                            lr: fmt(details.context.lr),
                            x0: fmt(details.context.x0),
                            x1: fmt(details.context.x1),
                            x2: fmt(details.context.x2),
                            x3: fmt(details.context.x3),
                            x4: fmt(details.context.x4),
                        },
                        backtrace: safeBacktrace(details.context),
                    });
                    try {
                        MemoryAccessMonitor.disable();
                    } catch (e) {}
                    state.watch.enabled = false;
                }
            });
            state.watch.enabled = true;
            return 'OK';
        } catch (e) {
            state.watch.enabled = false;
            return 'ERR:' + e;
        }
    };

    globalThis.__tokenWatchDump = function () {
        return JSON.stringify({
            enabled: state.watch.enabled,
            base: state.watch.base,
            size: state.watch.size,
            drops: state.watch.drops,
            events: state.watch.events,
        });
    };

    globalThis.__tokenWatchDisable = function () {
        return disableWatch();
    };
})();
