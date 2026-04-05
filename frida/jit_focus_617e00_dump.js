// Focused in-context dump for 0x9b617e00.

'use strict';

(function () {
    if (globalThis.__jitFocus617e00Dump && globalThis.__jitFocus617e00Dump.installed) {
        console.log('[CAPTURE] [617E00DUMP] relay already installed');
        return;
    }

    var state = globalThis.__jitFocus617e00Dump = {
        installed: true,
        count: 0,
    };

    var TARGET = ptr('0x9b617e00');

    function fmt(v) {
        try { return ptr(v).toString(); } catch (e) { return String(v); }
    }

    function filePath(r) {
        try { return r && r.file && r.file.path ? String(r.file.path) : null; } catch (e) { return null; }
    }

    function findRange(addr) {
        var p = ptr(addr);
        var prots = ['r-x', '--x', 'r--', 'rw-', 'rwx'];
        var seen = {};
        for (var i = 0; i < prots.length; i++) {
            try {
                var rs = Process.enumerateRanges(prots[i]);
                for (var j = 0; j < rs.length; j++) {
                    var r = rs[j];
                    var key = r.base.toString() + ':' + r.size;
                    if (seen[key]) continue;
                    seen[key] = true;
                    if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) return r;
                }
            } catch (e) {}
        }
        return null;
    }

    function desc(addr) {
        try {
            var p = ptr(addr);
            var r = findRange(p);
            return {
                addr: p.toString(),
                range_base: r ? r.base.toString() : null,
                range_size: r ? r.size : null,
                protection: r ? r.protection : null,
                file: filePath(r),
            };
        } catch (e) {
            return { addr: String(addr), error: String(e) };
        }
    }

    function rp(addr) {
        try { return Memory.readPointer(ptr(addr)).toString(); } catch (e) { return 'ERR:' + e; }
    }

    function hd(addr, n) {
        try { return hexdump(ptr(addr), { length: n, ansi: false }); } catch (e) { return 'ERR:' + e; }
    }

    console.log('[CAPTURE] [617E00DUMP] hooking ' + TARGET);

    Interceptor.attach(TARGET, {
        onEnter: function () {
            state.count++;
            if (state.count > 4) return;
            var x0 = ptr(this.context.x0);
            var x1 = ptr(this.context.x1);
            var x0p128 = rp(x0.add(128));
            var x0p128p240 = (function () {
                try {
                    var q = Memory.readPointer(x0.add(128));
                    return Memory.readPointer(q.add(240)).toString();
                } catch (e) {
                    return 'ERR:' + e;
                }
            })();
            console.log('[CAPTURE] [617E00DUMP] ' + JSON.stringify({
                count: state.count,
                pc: fmt(this.context.pc),
                lr: fmt(this.context.lr),
                x0: desc(x0),
                x1: desc(x1),
                x0_p0: rp(x0),
                x0_p8: rp(x0.add(8)),
                x0_p16: rp(x0.add(16)),
                x0_p24: rp(x0.add(24)),
                x0_p128: x0p128,
                x0_p128_p240: x0p128p240,
                x0_dump: hd(x0, 64),
                x1_dump: hd(x1, 64),
            }));
        }
    });
})();
