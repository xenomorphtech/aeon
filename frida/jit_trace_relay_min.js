// Minimal runtime trace helper loaded through /relay.
// Keeps hooks to the safest handoff / entry sites only.

'use strict';

(function () {
    if (globalThis.__jitTraceRelayMin && globalThis.__jitTraceRelayMin.installed) {
        console.log('[CAPTURE] [TRACE_MIN] relay already installed');
        return;
    }

    var state = globalThis.__jitTraceRelayMin = {
        installed: true,
        hooks: {},
        currentBase: null,
        seq: 0,
    };

    var POINTS = [
        { label: 'cert_entry', offset: 0x10828c },
        { label: 'hash_dispatch', offset: 0x1627d8 },
        { label: 'hash_entry', offset: 0x177ebc },
    ];

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function log(msg) {
        console.log('[CAPTURE] [TRACE_MIN] ' + msg);
    }

    function logCtx(label, ctx) {
        log(
            '#' + (++state.seq) + ' ' + label +
            ' pc=' + fmtPtr(ctx.pc) +
            ' lr=' + fmtPtr(ctx.lr) +
            ' x0=' + fmtPtr(ctx.x0) +
            ' x1=' + fmtPtr(ctx.x1) +
            ' x8=' + fmtPtr(ctx.x8)
        );
    }

    function attachPoint(mod, point) {
        var addr = mod.base.add(point.offset);
        var key = addr.toString();
        if (state.hooks[key]) return;
        try {
            Interceptor.attach(addr, {
                onEnter: function () {
                    logCtx(point.label + '@' + addr, this.context);
                }
            });
            state.hooks[key] = true;
            log('hooked ' + point.label + '@' + addr);
        } catch (e) {
            log('hook failed ' + point.label + '@' + addr + ' ' + e);
        }
    }

    function installForMod(mod) {
        if (!mod || !mod.base) return;
        if (state.currentBase && state.currentBase.equals(mod.base)) return;
        state.currentBase = mod.base;
        log('installing for jit base=' + mod.base + ' size=0x' + mod.size.toString(16));
        POINTS.forEach(function (point) { attachPoint(mod, point); });
    }

    if (typeof nmsscr_base !== 'undefined' && nmsscr_base !== null && typeof BLR_X8_OFFSET !== 'undefined') {
        try {
            var handoff = nmsscr_base.add(BLR_X8_OFFSET);
            Interceptor.attach(handoff, {
                onEnter: function () {
                    logCtx('nmss_blr_x8@' + handoff, this.context);
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
