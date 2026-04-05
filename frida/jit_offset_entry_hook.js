// Hook exact hot entry PCs relative to the live jit-cache execute base.

'use strict';

(function () {
    if (globalThis.__jitOffsetEntryHook && globalThis.__jitOffsetEntryHook.installed) {
        console.log('[CAPTURE] [ENTHOOK] relay already installed');
        return;
    }

    var state = globalThis.__jitOffsetEntryHook = {
        installed: true,
        hits: {},
        failures: [],
        hooks: [],
    };

    var EXEC_PROTECTIONS = ['r-x', '--x'];
    var TARGETS = [
        { label: 'pc_6128c0', offset: 0x148c0 },
        { label: 'pc_6156f0', offset: 0x176f0 },
        { label: 'pc_61c600', offset: 0x1e600 },
        { label: 'pc_61d260', offset: 0x1f260 },
        { label: 'pc_61d350', offset: 0x1f350 },
        { label: 'pc_61d530', offset: 0x1f530 },
    ];

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function noteFailure(where, error) {
        state.failures.push({ where: where, error: String(error) });
        if (state.failures.length > 32) state.failures.shift();
        console.log('[CAPTURE] [ENTHOOK] ' + where + ' failed: ' + error);
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

    function logHit(kind, label, addr, ctx, extra) {
        var key = label + '@' + addr;
        var count = (state.hits[key] || 0) + 1;
        state.hits[key] = count;
        if (count > 4 && (count % 256) !== 0) return;
        var payload = {
            kind: kind,
            label: label,
            addr: addr.toString(),
            count: count,
            x0: fmt(ctx.x0),
            x1: fmt(ctx.x1),
            x8: fmt(ctx.x8),
            x21: fmt(ctx.x21),
            x22: fmt(ctx.x22),
            lr: fmt(ctx.lr),
            pc: fmt(ctx.pc),
        };
        if (extra) {
            Object.keys(extra).forEach(function (k) { payload[k] = extra[k]; });
        }
        console.log('[CAPTURE] [ENTHOOK] ' + JSON.stringify(payload));
    }

    var range = chooseJitExecRange();
    if (!range) {
        noteFailure('install', 'jit-cache execute range not found');
        return;
    }
    console.log('[CAPTURE] [ENTHOOK] base=' + range.base + ' file=' + (range.file && range.file.path ? range.file.path : ''));

    TARGETS.forEach(function (target) {
        var addr = range.base.add(target.offset);
        try {
            Interceptor.attach(addr, {
                onEnter: function () {
                    this.label = target.label;
                    this.addr = addr;
                    logHit('enter', target.label, addr, this.context, {});
                },
                onLeave: function (retval) {
                    logHit('leave', this.label || target.label, this.addr || addr, this.context, {
                        retval: fmt(retval),
                        x0_after: fmt(this.context.x0),
                    });
                }
            });
            state.hooks.push({ label: target.label, addr: addr.toString() });
            console.log('[CAPTURE] [ENTHOOK] attached ' + target.label + '@' + addr);
        } catch (e) {
            noteFailure('attach ' + target.label + '@' + addr, e);
        }
    });
})();
