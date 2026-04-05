// Focused hook for the tail-call target resolved from 0x9b61c600.

'use strict';

(function () {
    if (globalThis.__jitTail796f718000 && globalThis.__jitTail796f718000.installed) {
        console.log('[CAPTURE] [TAIL796F718000] relay already installed');
        return;
    }

    var state = globalThis.__jitTail796f718000 = {
        installed: true,
        counts: {},
        seen: {},
    };

    var TARGET = ptr('0x796f718000');

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function bump(kind) {
        var count = (state.counts[kind] || 0) + 1;
        state.counts[kind] = count;
        return count;
    }

    function shouldLog(kind, count, isNewSig) {
        if (kind === 'enter' && isNewSig) return true;
        if (count <= 8) return true;
        return (count % 128) === 0;
    }

    function looksPtr(value) {
        var s = fmt(value);
        if (!s.startsWith('0x')) return false;
        try {
            var n = ptr(value);
            return !n.equals(ptr('0')) && n.compare(ptr('0x10000')) > 0;
        } catch (e) {
            return false;
        }
    }

    function hexdumpMaybe(value, size) {
        try {
            return hexdump(ptr(value), { length: size, ansi: false });
        } catch (e) {
            return null;
        }
    }

    globalThis.__jitTail796f718000Dump = function () {
        return JSON.stringify({
            target: TARGET.toString(),
            enter_count: state.counts.enter || 0,
            leave_count: state.counts.leave || 0,
        });
    };

    console.log('[CAPTURE] [TAIL796F718000] target=' + TARGET);

    Interceptor.attach(TARGET, {
        onEnter: function () {
            var count = bump('enter');
            var sig = [fmt(this.context.x0), fmt(this.context.x1), fmt(this.context.x2), fmt(this.context.x17)].join('|');
            var isNewSig = !state.seen[sig];
            state.seen[sig] = true;
            this.x0In = fmt(this.context.x0);
            this.x1In = fmt(this.context.x1);
            this.x2In = fmt(this.context.x2);
            if (!shouldLog('enter', count, isNewSig)) return;
            console.log('[CAPTURE] [TAIL796F718000] ' + JSON.stringify({
                kind: 'enter',
                count: count,
                addr: TARGET.toString(),
                x0: this.x0In,
                x1: this.x1In,
                x2: this.x2In,
                x3: fmt(this.context.x3),
                x8: fmt(this.context.x8),
                x17: fmt(this.context.x17),
                x21: fmt(this.context.x21),
                x22: fmt(this.context.x22),
                lr: fmt(this.context.lr),
                pc: fmt(this.context.pc),
                sig_new: isNewSig,
                x0_dump: looksPtr(this.context.x0) ? hexdumpMaybe(this.context.x0, 64) : null,
                x1_dump: looksPtr(this.context.x1) ? hexdumpMaybe(this.context.x1, 64) : null,
                x2_dump: looksPtr(this.context.x2) ? hexdumpMaybe(this.context.x2, 64) : null,
                enter_count: state.counts.enter || 0,
                leave_count: state.counts.leave || 0,
            }));
        },
        onLeave: function (retval) {
            var count = bump('leave');
            if (!shouldLog('leave', count, false)) return;
            console.log('[CAPTURE] [TAIL796F718000] ' + JSON.stringify({
                kind: 'leave',
                count: count,
                addr: TARGET.toString(),
                retval: fmt(retval),
                x0_in: this.x0In || null,
                x1_in: this.x1In || null,
                x2_in: this.x2In || null,
                x0_after: fmt(this.context.x0),
                lr: fmt(this.context.lr),
                pc: fmt(this.context.pc),
                enter_count: state.counts.enter || 0,
                leave_count: state.counts.leave || 0,
            }));
        }
    });
})();
