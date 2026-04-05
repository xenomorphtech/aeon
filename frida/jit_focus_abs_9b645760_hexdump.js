// Focused absolute hook for the current relocated 0x9b645760 helper.
// This is the live-session analog of the earlier 0x9b61c600 site.

'use strict';

(function () {
    if (globalThis.__jitFocusAbs645760Hex && globalThis.__jitFocusAbs645760Hex.installed) {
        console.log('[CAPTURE] [ABS645760HEX] relay already installed');
        return;
    }

    var state = globalThis.__jitFocusAbs645760Hex = {
        installed: true,
        counts: {},
        seenX1: {},
    };

    var TARGET = ptr('0x9b645760');

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function bump(kind) {
        var count = (state.counts[kind] || 0) + 1;
        state.counts[kind] = count;
        return count;
    }

    function shouldLog(kind, count, isNewX1) {
        if (kind === 'enter' && isNewX1) return true;
        if (count <= 8) return true;
        return (count % 256) === 0;
    }

    function dumpSizeFrom(ctx) {
        try {
            var size = Number(ptr(ctx.x0)) >>> 0;
            if (size < 64) return 64;
            if (size > 128) return 128;
            return size;
        } catch (e) {
            return 64;
        }
    }

    function hexdumpMaybe(addr, size) {
        try {
            return hexdump(ptr(addr), { length: size, ansi: false });
        } catch (e) {
            return null;
        }
    }

    globalThis.__jitFocusAbs645760HexDump = function () {
        return JSON.stringify({
            target: TARGET.toString(),
            counts: state.counts,
        });
    };

    console.log('[CAPTURE] [ABS645760HEX] target=' + TARGET);

    Interceptor.attach(TARGET, {
        onEnter: function () {
            var count = bump('enter');
            this.x0In = fmt(this.context.x0);
            this.x1Key = fmt(this.context.x1);
            this.x2In = fmt(this.context.x2);
            this.dumpSize = dumpSizeFrom(this.context);
            this.dump = hexdumpMaybe(this.context.x1, this.dumpSize);
            var isNewX1 = !state.seenX1[this.x1Key];
            state.seenX1[this.x1Key] = true;
            if (!shouldLog('enter', count, isNewX1)) return;
            console.log('[CAPTURE] [ABS645760HEX] ' + JSON.stringify({
                kind: 'enter',
                count: count,
                addr: TARGET.toString(),
                x0: this.x0In,
                x1: this.x1Key,
                x2: this.x2In,
                x8: fmt(this.context.x8),
                x21: fmt(this.context.x21),
                x22: fmt(this.context.x22),
                lr: fmt(this.context.lr),
                pc: fmt(this.context.pc),
                x1_new: isNewX1,
                dump_size: this.dumpSize,
                x1_hexdump: this.dump,
            }));
        },
        onLeave: function (retval) {
            var count = bump('leave');
            if (!shouldLog('leave', count, false)) return;
            console.log('[CAPTURE] [ABS645760HEX] ' + JSON.stringify({
                kind: 'leave',
                count: count,
                addr: TARGET.toString(),
                retval: fmt(retval),
                x0_in: this.x0In || null,
                x1: this.x1Key || fmt(this.context.x1),
                x2_in: this.x2In || null,
                x0_after: fmt(this.context.x0),
                lr: fmt(this.context.lr),
                pc: fmt(this.context.pc),
            }));
        }
    });
})();
