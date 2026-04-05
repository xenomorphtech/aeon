// Session-local hook helper for current hot JIT pages.
// Scans selected pages for AArch64 frame prologues and attaches direct
// enter/leave hooks, logging compact snapshots into the capture server log.

'use strict';

(function () {
    if (globalThis.__jitHotpageHook && globalThis.__jitHotpageHook.installed) {
        console.log('[CAPTURE] [HOTHOOK] relay already installed');
        return;
    }

    var state = globalThis.__jitHotpageHook = {
        installed: true,
        pages: [
            '0x9b61b000',
            '0x9b61c000',
            '0x9b615000',
            '0x9b613000',
            '0x9b612000',
            '0x9b619000',
            '0x9b617000',
        ],
        hooks: [],
        hits: {},
        failures: [],
    };

    var REGS = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'sp', 'pc', 'lr'];

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function bytes16(addr) {
        try {
            var view = new Uint8Array(Memory.readByteArray(ptr(addr), 16));
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

    function snap(ctx) {
        var out = {};
        REGS.forEach(function (reg) {
            try { out[reg] = fmt(ctx[reg]); } catch (e) {}
        });
        return out;
    }

    function noteFailure(where, error) {
        state.failures.push({ where: where, error: String(error) });
        if (state.failures.length > 32) state.failures.shift();
        console.log('[CAPTURE] [HOTHOOK] ' + where + ' failed: ' + error);
    }

    function logHit(kind, addr, ctx, extra) {
        var key = addr.toString();
        var count = (state.hits[key] || 0) + 1;
        state.hits[key] = count;
        if (count > 4 && (count % 256) !== 0) return;
        var payload = {
            kind: kind,
            addr: key,
            count: count,
            x0: fmt(ctx.x0),
            x1: fmt(ctx.x1),
            x8: fmt(ctx.x8),
            x19: fmt(ctx.x19),
            x20: fmt(ctx.x20),
            x21: fmt(ctx.x21),
            x22: fmt(ctx.x22),
            x29: fmt(ctx.x29),
            lr: fmt(ctx.lr),
            pc: fmt(ctx.pc),
        };
        if (extra) {
            Object.keys(extra).forEach(function (k) { payload[k] = extra[k]; });
        }
        console.log('[CAPTURE] [HOTHOOK] ' + JSON.stringify(payload));
    }

    function attach(addr) {
        try {
            Interceptor.attach(addr, {
                onEnter: function () {
                    this.addr = addr;
                    logHit('enter', addr, this.context, { regs: snap(this.context) });
                },
                onLeave: function (retval) {
                    logHit('leave', this.addr || addr, this.context, {
                        retval: fmt(retval),
                        x0_after: fmt(this.context.x0),
                    });
                }
            });
            state.hooks.push(addr.toString());
            console.log('[CAPTURE] [HOTHOOK] attached ' + addr + ' bytes16=' + bytes16(addr));
        } catch (e) {
            noteFailure('attach ' + addr, e);
        }
    }

    state.pages.forEach(function (page) {
        try {
            var matches = Memory.scanSync(ptr(page), 0x1000, 'fd 7b ?? a9');
            console.log('[CAPTURE] [HOTHOOK] page ' + page + ' matches=' + matches.length);
            matches.forEach(function (hit) {
                attach(hit.address);
            });
        } catch (e) {
            noteFailure('scan ' + page, e);
        }
    });
})();
