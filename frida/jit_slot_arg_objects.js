// Dump the x1/x2 object arguments seen at the hot slot-return site 0x9b617da4.
// This captures the heap objects in-context during the cert call.

'use strict';

(function () {
    if (globalThis.__jitSlotArgObjects && globalThis.__jitSlotArgObjects.installed) {
        console.log('[CAPTURE] [SLOTARG] relay already installed');
        return;
    }

    var state = globalThis.__jitSlotArgObjects = {
        installed: true,
        maxEvents: 64,
        seq: 0,
        drops: 0,
        events: [],
        failures: [],
        count: 0,
        seenKeys: {},
    };

    var TARGET = ptr('0x9b617da4');
    var HIGHLIGHT = {
        '0x6f62c528': true,
        '0x6f62c540': true,
        '0x6f62c558': true,
    };
    var CHALLENGE_ASCII = '6BA4D60738580083';

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

    function findRange(addr) {
        var p = ptr(addr);
        var prots = ['r-x', '--x', 'r--', 'rw-', 'rwx'];
        var seen = {};
        for (var i = 0; i < prots.length; i++) {
            try {
                var rs = Process.enumerateRanges(prots[i]);
                for (var j = 0; j < rs.length; j++) {
                    var r = rs[j];
                    var key = r.base.toString() + ':' + r.size;
                    if (seen[key]) continue;
                    seen[key] = true;
                    if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) {
                        return r;
                    }
                }
            } catch (e) {}
        }
        return null;
    }

    function rp(addr) {
        try { return Memory.readPointer(ptr(addr)).toString(); } catch (e) { return 'ERR:' + e; }
    }

    function hd(addr, n) {
        try { return hexdump(ptr(addr), { length: n, ansi: false }); } catch (e) { return 'ERR:' + e; }
    }

    function utf8(addr, n) {
        try { return Memory.readUtf8String(ptr(addr), n); } catch (e) { return null; }
    }

    function desc(addr) {
        try {
            var p = ptr(addr);
            var r = findRange(p);
            var dump = hd(p, 128);
            var ascii = utf8(p, 128);
            return {
                addr: p.toString(),
                range_base: r ? r.base.toString() : null,
                range_size: r ? r.size : null,
                protection: r ? r.protection : null,
                file: filePathFor(r),
                p0: rp(p),
                p8: rp(p.add(8)),
                p16: rp(p.add(16)),
                p24: rp(p.add(24)),
                p32: rp(p.add(32)),
                p40: rp(p.add(40)),
                dump: dump,
                ascii: ascii,
                has_challenge_ascii: ascii ? ascii.indexOf(CHALLENGE_ASCII) >= 0 : false,
                highlighted: !!HIGHLIGHT[p.toString()],
            };
        } catch (e) {
            return { addr: String(addr), error: String(e) };
        }
    }

    function pushEvent(event) {
        if (state.events.length >= state.maxEvents) {
            state.events.shift();
            state.drops++;
        }
        state.events.push(event);
    }

    function noteFailure(label, error) {
        state.failures.push({
            label: label,
            error: String(error),
        });
        if (state.failures.length > 32) state.failures.shift();
        console.log('[CAPTURE] [SLOTARG] ' + label + ' failed: ' + error);
    }

    function shouldLog(key) {
        state.count++;
        if (!state.seenKeys[key]) {
            state.seenKeys[key] = true;
            return true;
        }
        return state.count <= 8 || (state.count % 64) === 0;
    }

    console.log('[CAPTURE] [SLOTARG] hooking ' + TARGET);

    try {
        Interceptor.attach(TARGET, {
            onEnter: function () {
                var x1 = fmt(this.context.x1);
                var x2 = fmt(this.context.x2);
                var key = x1 + '|' + x2;
                if (!shouldLog(key)) return;
                pushEvent({
                    seq: ++state.seq,
                    count: state.count,
                    pc: fmt(this.context.pc),
                    lr: fmt(this.context.lr),
                    x0: fmt(this.context.x0),
                    x1: desc(this.context.x1),
                    x2: desc(this.context.x2),
                    x3: fmt(this.context.x3),
                    x4: fmt(this.context.x4),
                });
            }
        });
    } catch (e) {
        noteFailure('hook ' + TARGET, e);
    }

    globalThis.__jitSlotArgObjectsClear = function () {
        state.seq = 0;
        state.drops = 0;
        state.events.length = 0;
        state.failures.length = 0;
        state.count = 0;
        state.seenKeys = {};
        return 'OK';
    };

    globalThis.__jitSlotArgObjectsDump = function () {
        return JSON.stringify({
            drops: state.drops,
            count: state.count,
            events: state.events,
            failures: state.failures,
        });
    };
})();
