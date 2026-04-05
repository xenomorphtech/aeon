// Runtime trace helper loaded through /relay.
// Hooks the native handoff plus selected JIT offsets and logs the hit sequence.

'use strict';

(function () {
    if (globalThis.__jitTraceRelay && globalThis.__jitTraceRelay.installed) {
        console.log('[CAPTURE] [TRACE] relay already installed');
        return;
    }

    var state = globalThis.__jitTraceRelay = {
        installed: true,
        hooks: {},
        currentBase: null,
        sequence: 0,
    };

    var POINTS = [
        { label: 'cert_entry', offset: 0x10828c },
        { label: 'hash_dispatch', offset: 0x1627d8 },
        { label: 'resume_point', offset: 0x1629a8 },
        { label: 'helper_chain', offset: 0x177740 },
        { label: 'decision_point', offset: 0x1777f0 },
        { label: 'hash_entry', offset: 0x177ebc },
        { label: 'helper_1702c8', offset: 0x1702c8 },
        { label: 'helper_152dc0', offset: 0x152dc0 },
        { label: 'helper_1ad668', offset: 0x1ad668 },
    ];

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function log(msg) {
        console.log('[CAPTURE] [TRACE] ' + msg);
    }

    function logContext(label, ctx) {
        var parts = [
            '#' + (++state.sequence),
            label,
            'pc=' + fmtPtr(ctx.pc),
            'lr=' + fmtPtr(ctx.lr),
            'x0=' + fmtPtr(ctx.x0),
            'x1=' + fmtPtr(ctx.x1),
            'x8=' + fmtPtr(ctx.x8),
            'x21=' + fmtPtr(ctx.x21),
        ];
        log(parts.join(' '));
    }

    function attachPoint(mod, point) {
        var addr = mod.base.add(point.offset);
        var key = addr.toString();
        if (state.hooks[key]) return;
        try {
            Interceptor.attach(addr, {
                onEnter: function () {
                    logContext(point.label + '@' + addr, this.context);
                    if (point.label === 'decision_point') {
                        try {
                            var flag = ptr(this.context.x21).add(0xc).readU32();
                            log('decision_point flag=' + flag + ' x21=' + fmtPtr(this.context.x21));
                        } catch (e) {
                            log('decision_point flag read failed: ' + e);
                        }
                    }
                }
            });
            state.hooks[key] = true;
            log('hooked ' + point.label + '@' + addr);
        } catch (e) {
            log('hook failed ' + point.label + '@' + addr + ' ' + e);
        }
    }

    function installForMod(mod) {
        if (!mod || !mod.base) {
            log('install skipped: no jit module');
            return;
        }
        if (state.currentBase && state.currentBase.equals(mod.base)) return;
        state.currentBase = mod.base;
        log('installing for jit base=' + mod.base + ' size=0x' + mod.size.toString(16));
        POINTS.forEach(function (point) {
            attachPoint(mod, point);
        });
    }

    if (typeof nmsscr_base !== 'undefined' && nmsscr_base !== null && typeof BLR_X8_OFFSET !== 'undefined') {
        try {
            var handoff = nmsscr_base.add(BLR_X8_OFFSET);
            Interceptor.attach(handoff, {
                onEnter: function () {
                    logContext('nmss_blr_x8@' + handoff, this.context);
                    log('nmss_blr_x8 target=' + fmtPtr(this.context.x8));
                }
            });
            log('hooked native handoff @' + handoff);
        } catch (e) {
            log('native handoff hook failed: ' + e);
        }
    }

    if (typeof maybeAdoptJit === 'function') {
        var origMaybeAdoptJit = maybeAdoptJit;
        maybeAdoptJit = function (target, source) {
            var mod = origMaybeAdoptJit(target, source);
            if (mod) installForMod(mod);
            return mod;
        };
        log('wrapped maybeAdoptJit');
    }

    if (typeof jitMod !== 'undefined' && jitMod) {
        installForMod(jitMod);
    } else {
        log('waiting for jit adoption');
    }
})();
