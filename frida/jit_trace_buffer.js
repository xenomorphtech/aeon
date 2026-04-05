// Buffered runtime trace helper loaded through /relay.
// Records a capped hit sequence into a global ring buffer for /eval queries.

'use strict';

(function () {
    if (globalThis.__jitTraceBuffer && globalThis.__jitTraceBuffer.installed) {
        console.log('[CAPTURE] [TRACE_BUF] relay already installed');
        return;
    }

    var state = globalThis.__jitTraceBuffer = {
        installed: true,
        hooks: {},
        currentBase: null,
        events: [],
        maxEvents: 256,
        seq: 0,
        drops: 0,
        failures: [],
    };

    var POINTS = [
        { label: 'cert_entry', offset: 0x10828c },
        { label: 'helper_152dc0', offset: 0x152dc0 },
        { label: 'hash_dispatch', offset: 0x1627d8 },
        { label: 'resume_point', offset: 0x1629a8 },
        { label: 'helper_1702c8', offset: 0x1702c8 },
        { label: 'helper_chain', offset: 0x177740 },
        { label: 'decision_point', offset: 0x1777f0 },
        { label: 'hash_entry', offset: 0x177ebc },
        { label: 'helper_1ad668', offset: 0x1ad668 },
    ];

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
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
            x26: fmtPtr(ctx.x26),
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
        console.log('[CAPTURE] [TRACE_BUF] ' + label + ' failed: ' + error);
    }

    function attachPoint(mod, point) {
        var addr = mod.base.add(point.offset);
        var key = addr.toString();
        if (state.hooks[key]) return;
        try {
            Interceptor.attach(addr, {
                onEnter: function () {
                    var extra = {
                        offset: '0x' + point.offset.toString(16),
                    };
                    if (point.label === 'decision_point') {
                        try {
                            extra.flag = ptr(this.context.x21).add(0xc).readU32();
                        } catch (e) {
                            extra.flag_error = String(e);
                        }
                    }
                    record(point.label + '@' + addr, this.context, extra);
                }
            });
            state.hooks[key] = true;
            console.log('[CAPTURE] [TRACE_BUF] hooked ' + point.label + '@' + addr);
        } catch (e) {
            noteFailure('hook ' + point.label + '@' + addr, e);
        }
    }

    function installForMod(mod) {
        if (!mod || !mod.base) return;
        if (state.currentBase && state.currentBase.equals(mod.base)) return;
        state.currentBase = mod.base;
        console.log('[CAPTURE] [TRACE_BUF] installing for jit base=' + mod.base + ' size=0x' + mod.size.toString(16));
        POINTS.forEach(function (point) {
            attachPoint(mod, point);
        });
    }

    globalThis.__jitTraceBufferClear = function () {
        state.events.length = 0;
        state.seq = 0;
        state.drops = 0;
        return 'OK';
    };

    globalThis.__jitTraceBufferDump = function () {
        return JSON.stringify({
            currentBase: state.currentBase ? state.currentBase.toString() : null,
            maxEvents: state.maxEvents,
            drops: state.drops,
            events: state.events,
            failures: state.failures,
        });
    };

    if (typeof nmsscr_base !== 'undefined' && nmsscr_base !== null && typeof BLR_X8_OFFSET !== 'undefined') {
        try {
            var handoff = nmsscr_base.add(BLR_X8_OFFSET);
            Interceptor.attach(handoff, {
                onEnter: function () {
                    record('nmss_blr_x8@' + handoff, this.context, {
                        target: fmtPtr(this.context.x8),
                    });
                }
            });
            console.log('[CAPTURE] [TRACE_BUF] hooked native handoff @' + handoff);
        } catch (e) {
            noteFailure('native handoff', e);
        }
    }

    if (typeof maybeAdoptJit === 'function') {
        var origMaybeAdoptJit = maybeAdoptJit;
        maybeAdoptJit = function (target, source) {
            var mod = origMaybeAdoptJit(target, source);
            if (mod) installForMod(mod);
            return mod;
        };
        console.log('[CAPTURE] [TRACE_BUF] wrapped maybeAdoptJit');
    }

    if (typeof jitMod !== 'undefined' && jitMod) {
        installForMod(jitMod);
    } else {
        console.log('[CAPTURE] [TRACE_BUF] waiting for jit adoption');
    }
})();
