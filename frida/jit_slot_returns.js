// Capture slot dispatch return values for two key cert-path sites.
// Hooks the post-call return instructions so x0 is the callee's return value.

'use strict';

(function () {
    if (globalThis.__jitSlotReturns && globalThis.__jitSlotReturns.installed) {
        console.log('[CAPTURE] [SLOTRET] relay already installed');
        return;
    }

    var state = globalThis.__jitSlotReturns = {
        installed: true,
        maxEvents: 128,
        seq: 0,
        drops: 0,
        events: [],
        failures: [],
        counts: {},
    };

    var TARGETS = [
        {
            label: 'ret_612754',
            addr: ptr('0x9b612768'),
        },
        {
            label: 'ret_617d98',
            addr: ptr('0x9b617da4'),
        },
    ];

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

    function desc(addr) {
        try {
            var p = ptr(addr);
            var r = findRange(p);
            return {
                addr: p.toString(),
                range_base: r ? r.base.toString() : null,
                range_size: r ? r.size : null,
                protection: r ? r.protection : null,
                file: filePathFor(r),
            };
        } catch (e) {
            return { addr: String(addr), error: String(e) };
        }
    }

    function rp(addr) {
        try { return Memory.readPointer(ptr(addr)).toString(); } catch (e) { return 'ERR:' + e; }
    }

    function hd(addr, n) {
        try { return hexdump(ptr(addr), { length: n, ansi: false }); } catch (e) { return 'ERR:' + e; }
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
        console.log('[CAPTURE] [SLOTRET] ' + label + ' failed: ' + error);
    }

    function bump(label) {
        var count = (state.counts[label] || 0) + 1;
        state.counts[label] = count;
        return count;
    }

    function shouldLog(count) {
        return count <= 8 || (count % 64) === 0;
    }

    function sampleValue(v) {
        return {
            desc: desc(v),
            p0: rp(v),
            p8: rp(ptr(v).add(8)),
            p16: rp(ptr(v).add(16)),
            p24: rp(ptr(v).add(24)),
            dump: hd(v, 64),
        };
    }

    function attachTarget(spec) {
        try {
            Interceptor.attach(spec.addr, {
                onEnter: function () {
                    var count = bump(spec.label);
                    if (!shouldLog(count)) return;
                    var retv = ptr(this.context.x0);
                    pushEvent({
                        seq: ++state.seq,
                        label: spec.label,
                        count: count,
                        pc: fmt(this.context.pc),
                        lr: fmt(this.context.lr),
                        x0: sampleValue(retv),
                        x1: fmt(this.context.x1),
                        x2: fmt(this.context.x2),
                        x3: fmt(this.context.x3),
                        x4: fmt(this.context.x4),
                    });
                }
            });
            console.log('[CAPTURE] [SLOTRET] hooked ' + spec.label + '@' + spec.addr);
        } catch (e) {
            noteFailure('hook ' + spec.label + '@' + spec.addr, e);
        }
    }

    globalThis.__jitSlotReturnsClear = function () {
        state.seq = 0;
        state.drops = 0;
        state.events.length = 0;
        state.failures.length = 0;
        state.counts = {};
        return 'OK';
    };

    globalThis.__jitSlotReturnsDump = function () {
        return JSON.stringify({
            drops: state.drops,
            counts: state.counts,
            events: state.events,
            failures: state.failures,
        });
    };

    TARGETS.forEach(attachTarget);
})();
