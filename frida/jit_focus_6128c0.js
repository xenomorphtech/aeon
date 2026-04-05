// Focused hook for the live jit-cache target at base + 0x148c0.
// Logs entry registers, dumps bytes at x1, and logs onLeave separately.

'use strict';

(function () {
    if (globalThis.__jitFocus6128c0 && globalThis.__jitFocus6128c0.installed) {
        console.log('[CAPTURE] [FOCUS6128C0] relay already installed');
        return;
    }

    var state = globalThis.__jitFocus6128c0 = {
        installed: true,
        target: null,
        seenX1: {},
        counts: {},
        failures: [],
    };

    var EXEC_PROTECTIONS = ['r-x', '--x'];
    var TARGET_OFFSET = 0x148c0;
    var BUFFER_DUMP_SIZE = 64;

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function bytesHex(addr, size) {
        try {
            var view = new Uint8Array(Memory.readByteArray(ptr(addr), size));
            var out = [];
            for (var i = 0; i < view.length; i++) {
                var h = view[i].toString(16);
                out.push(h.length === 1 ? '0' + h : h);
            }
            return out.join('');
        } catch (e) {
            return null;
        }
    }

    function asciiMaybe(addr, size) {
        try { return Memory.readUtf8String(ptr(addr), size); } catch (e) { return null; }
    }

    function noteFailure(where, error) {
        state.failures.push({ where: where, error: String(error) });
        if (state.failures.length > 32) state.failures.shift();
        console.log('[CAPTURE] [FOCUS6128C0] ' + where + ' failed: ' + error);
    }

    function bump(kind) {
        var count = (state.counts[kind] || 0) + 1;
        state.counts[kind] = count;
        return count;
    }

    function chooseJitExecRange() {
        var best = null;
        var seen = {};
        EXEC_PROTECTIONS.forEach(function (prot) {
            try {
                Process.enumerateRanges(prot).forEach(function (range) {
                    var protection = range.protection || prot;
                    if (protection.indexOf('w') !== -1) return;
                    var key = range.base.toString() + ':' + range.size.toString();
                    if (seen[key]) return;
                    seen[key] = true;
                    var path = range && range.file && range.file.path ? String(range.file.path) : '';
                    if (path.indexOf('/memfd:jit-cache') < 0) return;
                    if (best === null || range.size > best.size) best = range;
                });
            } catch (e) {
                noteFailure('enumerate ' + prot, e);
            }
        });
        return best;
    }

    function shouldLog(kind, count) {
        if (count <= 16) return true;
        return (count % 256) === 0;
    }

    var range = chooseJitExecRange();
    if (!range) {
        noteFailure('install', 'jit-cache execute range not found');
        return;
    }

    var target = range.base.add(TARGET_OFFSET);
    state.target = target.toString();
    console.log('[CAPTURE] [FOCUS6128C0] base=' + range.base + ' target=' + target);

    try {
        Interceptor.attach(target, {
            onEnter: function () {
                var count = bump('enter');
                this.enterCount = count;
                this.x1 = this.context.x1;
                this.x1Key = fmt(this.context.x1);
                this.dumpHex = bytesHex(this.x1, BUFFER_DUMP_SIZE);
                this.dumpAscii = asciiMaybe(this.x1, BUFFER_DUMP_SIZE);
                var isNewX1 = !state.seenX1[this.x1Key];
                state.seenX1[this.x1Key] = true;
                if (!shouldLog('enter', count) && !isNewX1) return;
                console.log('[CAPTURE] [FOCUS6128C0] ' + JSON.stringify({
                    kind: 'enter',
                    count: count,
                    addr: target.toString(),
                    x0: fmt(this.context.x0),
                    x1: this.x1Key,
                    x8: fmt(this.context.x8),
                    x21: fmt(this.context.x21),
                    x22: fmt(this.context.x22),
                    lr: fmt(this.context.lr),
                    pc: fmt(this.context.pc),
                    x1_new: isNewX1,
                    x1_bytes64: this.dumpHex,
                    x1_ascii: this.dumpAscii,
                }));
            },
            onLeave: function (retval) {
                var count = bump('leave');
                if (!shouldLog('leave', count)) return;
                console.log('[CAPTURE] [FOCUS6128C0] ' + JSON.stringify({
                    kind: 'leave',
                    count: count,
                    addr: target.toString(),
                    retval: fmt(retval),
                    x0_after: fmt(this.context.x0),
                    x1: this.x1Key || fmt(this.context.x1),
                    x1_bytes64: this.dumpHex || bytesHex(this.context.x1, BUFFER_DUMP_SIZE),
                    lr: fmt(this.context.lr),
                    pc: fmt(this.context.pc),
                }));
            }
        });
    } catch (e) {
        noteFailure('attach ' + target, e);
    }
})();
