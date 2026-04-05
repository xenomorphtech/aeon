// Hook prologue candidates on hot cert-corridor pages relative to the live
// jit-cache execute base, so session rebasing does not matter.

'use strict';

(function () {
    if (globalThis.__jitOffsetHotHook && globalThis.__jitOffsetHotHook.installed) {
        console.log('[CAPTURE] [OFFHOOK] relay already installed');
        return;
    }

    var state = globalThis.__jitOffsetHotHook = {
        installed: true,
        hooks: [],
        hits: {},
        failures: [],
    };

    var EXEC_PROTECTIONS = ['r-x', '--x'];
    var PAGE_OFFSETS = [
        0x13000,
        0x14000,
        0x15000,
        0x17000,
        0x19000,
        0x1b000,
        0x1d000,
        0x1e000,
        0x1f000,
    ];

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

    function noteFailure(where, error) {
        state.failures.push({ where: where, error: String(error) });
        if (state.failures.length > 32) state.failures.shift();
        console.log('[CAPTURE] [OFFHOOK] ' + where + ' failed: ' + error);
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
            x21: fmt(ctx.x21),
            x22: fmt(ctx.x22),
            lr: fmt(ctx.lr),
            pc: fmt(ctx.pc),
        };
        if (extra) {
            Object.keys(extra).forEach(function (k) { payload[k] = extra[k]; });
        }
        console.log('[CAPTURE] [OFFHOOK] ' + JSON.stringify(payload));
    }

    function attach(addr) {
        try {
            Interceptor.attach(addr, {
                onEnter: function () {
                    this.addr = addr;
                    logHit('enter', addr, this.context, {});
                },
                onLeave: function (retval) {
                    logHit('leave', this.addr || addr, this.context, {
                        retval: fmt(retval),
                        x0_after: fmt(this.context.x0),
                    });
                }
            });
            state.hooks.push(addr.toString());
            console.log('[CAPTURE] [OFFHOOK] attached ' + addr + ' bytes16=' + bytes16(addr));
        } catch (e) {
            noteFailure('attach ' + addr, e);
        }
    }

    var range = chooseJitExecRange();
    if (!range) {
        noteFailure('install', 'jit-cache execute range not found');
        return;
    }
    console.log('[CAPTURE] [OFFHOOK] base=' + range.base + ' file=' + (range.file && range.file.path ? range.file.path : ''));

    PAGE_OFFSETS.forEach(function (offset) {
        var page = range.base.add(offset);
        try {
            var matches = Memory.scanSync(page, 0x1000, 'fd 7b ?? a9');
            console.log('[CAPTURE] [OFFHOOK] page=' + page + ' off=0x' + offset.toString(16) + ' matches=' + matches.length);
            matches.forEach(function (hit) {
                attach(hit.address);
            });
        } catch (e) {
            noteFailure('scan ' + page, e);
        }
    });
})();
