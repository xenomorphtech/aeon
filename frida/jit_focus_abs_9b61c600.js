// Focused absolute hook for the current live PC 0x9b61c600.
// Dumps bytes at x1 on entry and logs returns separately.

'use strict';

(function () {
    if (globalThis.__jitFocusAbs61c600 && globalThis.__jitFocusAbs61c600.installed) {
        console.log('[CAPTURE] [ABS61C600] relay already installed');
        return;
    }

    var state = globalThis.__jitFocusAbs61c600 = {
        installed: true,
        target: '0x9b61c600',
        counts: {},
        seenX1: {},
        failures: [],
    };

    var TARGET = ptr(state.target);
    var MIN_DUMP_SIZE = 64;
    var MAX_DUMP_SIZE = 256;

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function dumpSizeFrom(ctx) {
        try {
            var size = Number(ptr(ctx.x0)) >>> 0;
            if (size < MIN_DUMP_SIZE) return MIN_DUMP_SIZE;
            if (size > MAX_DUMP_SIZE) return MAX_DUMP_SIZE;
            return size;
        } catch (e) {
            return MIN_DUMP_SIZE;
        }
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

    function shouldLog(kind, count, isNewX1) {
        if (kind === 'enter' && isNewX1) return true;
        if (count <= 16) return true;
        return (count % 256) === 0;
    }

    function noteFailure(where, error) {
        state.failures.push({ where: where, error: String(error) });
        if (state.failures.length > 32) state.failures.shift();
        console.log('[CAPTURE] [ABS61C600] ' + where + ' failed: ' + error);
    }

    console.log('[CAPTURE] [ABS61C600] target=' + TARGET);

    try {
        Interceptor.attach(TARGET, {
            onEnter: function () {
                var count = bump('enter');
                this.dumpSize = dumpSizeFrom(this.context);
                this.x0In = fmt(this.context.x0);
                this.x1 = this.context.x1;
                this.x1Key = fmt(this.x1);
                this.dumpHex = bytesHex(this.x1, this.dumpSize);
                this.dumpAscii = asciiMaybe(this.x1, Math.min(this.dumpSize, 128));
                var isNewX1 = !state.seenX1[this.x1Key];
                state.seenX1[this.x1Key] = true;
                if (!shouldLog('enter', count, isNewX1)) return;
                console.log('[CAPTURE] [ABS61C600] ' + JSON.stringify({
                    kind: 'enter',
                    count: count,
                    addr: TARGET.toString(),
                    x0: this.x0In,
                    x1: this.x1Key,
                    x8: fmt(this.context.x8),
                    x21: fmt(this.context.x21),
                    x22: fmt(this.context.x22),
                    lr: fmt(this.context.lr),
                    pc: fmt(this.context.pc),
                    x1_new: isNewX1,
                    dump_size: this.dumpSize,
                    x1_bytes: this.dumpHex,
                    x1_ascii: this.dumpAscii,
                }));
            },
            onLeave: function (retval) {
                var count = bump('leave');
                if (!shouldLog('leave', count, false)) return;
                console.log('[CAPTURE] [ABS61C600] ' + JSON.stringify({
                    kind: 'leave',
                    count: count,
                    addr: TARGET.toString(),
                    retval: fmt(retval),
                    x0_in: this.x0In || null,
                    x0_after: fmt(this.context.x0),
                    x1: this.x1Key || fmt(this.context.x1),
                    dump_size: this.dumpSize || MIN_DUMP_SIZE,
                    x1_bytes: this.dumpHex || bytesHex(this.context.x1, this.dumpSize || MIN_DUMP_SIZE),
                    lr: fmt(this.context.lr),
                    pc: fmt(this.context.pc),
                }));
            }
        });
    } catch (e) {
        noteFailure('attach ' + TARGET, e);
    }
})();
