// Focused absolute hook for the current live PC 0x9b6128c0.
// Dumps x1 bytes on entry and logs returns separately.

'use strict';

(function () {
    if (globalThis.__jitFocusAbs6128c0 && globalThis.__jitFocusAbs6128c0.installed) {
        console.log('[CAPTURE] [ABS6128C0] relay already installed');
        return;
    }

    var state = globalThis.__jitFocusAbs6128c0 = {
        installed: true,
        target: '0x9b6128c0',
        counts: {},
        seenX1: {},
        failures: [],
    };

    var TARGET = ptr(state.target);
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

    function bump(kind) {
        var count = (state.counts[kind] || 0) + 1;
        state.counts[kind] = count;
        return count;
    }

    function shouldLog(kind, count) {
        if (count <= 16) return true;
        return (count % 256) === 0;
    }

    function noteFailure(where, error) {
        state.failures.push({ where: where, error: String(error) });
        if (state.failures.length > 32) state.failures.shift();
        console.log('[CAPTURE] [ABS6128C0] ' + where + ' failed: ' + error);
    }

    console.log('[CAPTURE] [ABS6128C0] target=' + TARGET);

    try {
        Interceptor.attach(TARGET, {
            onEnter: function () {
                var count = bump('enter');
                this.x1 = this.context.x1;
                this.x1Key = fmt(this.x1);
                this.dumpHex = bytesHex(this.x1, BUFFER_DUMP_SIZE);
                this.dumpAscii = asciiMaybe(this.x1, BUFFER_DUMP_SIZE);
                var isNewX1 = !state.seenX1[this.x1Key];
                state.seenX1[this.x1Key] = true;
                if (!shouldLog('enter', count) && !isNewX1) return;
                console.log('[CAPTURE] [ABS6128C0] ' + JSON.stringify({
                    kind: 'enter',
                    count: count,
                    addr: TARGET.toString(),
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
                console.log('[CAPTURE] [ABS6128C0] ' + JSON.stringify({
                    kind: 'leave',
                    count: count,
                    addr: TARGET.toString(),
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
        noteFailure('attach ' + TARGET, e);
    }
})();
