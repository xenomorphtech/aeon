// Focused absolute hook for 0x9b6156f0 using Frida's hexdump() helper.
// Tracks enter/leave counts to detect non-returning or tail-call behavior.

'use strict';

(function () {
    if (globalThis.__jitFocusAbs6156f0Hex && globalThis.__jitFocusAbs6156f0Hex.installed) {
        console.log('[CAPTURE] [ABS6156F0HEX] relay already installed');
        return;
    }

    var state = globalThis.__jitFocusAbs6156f0Hex = {
        installed: true,
        counts: {},
        seenPtr: {},
    };

    var TARGET = ptr('0x9b6156f0');

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function bump(kind) {
        var count = (state.counts[kind] || 0) + 1;
        state.counts[kind] = count;
        return count;
    }

    function shouldLog(kind, count, isNewPtr) {
        if (kind === 'enter' && isNewPtr) return true;
        if (count <= 8) return true;
        return (count % 256) === 0;
    }

    function dumpSizeFromPtr(ptrValue) {
        var p = fmt(ptrValue);
        if (p === '0x1' || p === '0x0') return 32;
        return 128;
    }

    function hexdumpMaybe(addr, size) {
        try {
            return hexdump(ptr(addr), { length: size, ansi: false });
        } catch (e) {
            return null;
        }
    }

    globalThis.__jitFocusAbs6156f0HexDump = function () {
        return JSON.stringify({
            target: TARGET.toString(),
            enter_count: state.counts.enter || 0,
            leave_count: state.counts.leave || 0,
        });
    };

    console.log('[CAPTURE] [ABS6156F0HEX] target=' + TARGET);

    Interceptor.attach(TARGET, {
        onEnter: function () {
            var count = bump('enter');
            this.x0In = fmt(this.context.x0);
            this.x1In = fmt(this.context.x1);
            this.primaryPtr = this.x0In !== '0x0' ? this.context.x0 : this.context.x1;
            this.primaryKey = fmt(this.primaryPtr);
            this.dumpSize = dumpSizeFromPtr(this.primaryPtr);
            this.dump = hexdumpMaybe(this.primaryPtr, this.dumpSize);
            var isNewPtr = !state.seenPtr[this.primaryKey];
            state.seenPtr[this.primaryKey] = true;
            if (!shouldLog('enter', count, isNewPtr)) return;
            console.log('[CAPTURE] [ABS6156F0HEX] ' + JSON.stringify({
                kind: 'enter',
                count: count,
                addr: TARGET.toString(),
                x0: this.x0In,
                x1: this.x1In,
                x8: fmt(this.context.x8),
                x21: fmt(this.context.x21),
                x22: fmt(this.context.x22),
                lr: fmt(this.context.lr),
                pc: fmt(this.context.pc),
                ptr_new: isNewPtr,
                dump_ptr: this.primaryKey,
                dump_size: this.dumpSize,
                ptr_hexdump: this.dump,
                enter_count: state.counts.enter || 0,
                leave_count: state.counts.leave || 0,
            }));
        },
        onLeave: function (retval) {
            var count = bump('leave');
            if (!shouldLog('leave', count, false)) return;
            console.log('[CAPTURE] [ABS6156F0HEX] ' + JSON.stringify({
                kind: 'leave',
                count: count,
                addr: TARGET.toString(),
                retval: fmt(retval),
                x0_in: this.x0In || null,
                x0_after: fmt(this.context.x0),
                x1_in: this.x1In || null,
                lr: fmt(this.context.lr),
                pc: fmt(this.context.pc),
                enter_count: state.counts.enter || 0,
                leave_count: state.counts.leave || 0,
            }));
        }
    });
})();
