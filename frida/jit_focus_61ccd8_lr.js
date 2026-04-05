// Focused hook for 0x9b61ccd8 to capture the caller LR and map it.

'use strict';

(function () {
    if (globalThis.__jitFocus61ccd8Lr && globalThis.__jitFocus61ccd8Lr.installed) {
        console.log('[CAPTURE] [61CCD8LR] relay already installed');
        return;
    }

    var state = globalThis.__jitFocus61ccd8Lr = {
        installed: true,
        maxEvents: 64,
        seq: 0,
        drops: 0,
        events: [],
        failures: [],
    };

    var TARGET = ptr('0x9b61ccd8');

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function filePathFor(range) {
        try {
            return range && range.file && range.file.path ? String(range.file.path) : null;
        } catch (e) {
            return null;
        }
    }

    function findRangeFor(addr) {
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
                    if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) {
                        return r;
                    }
                }
            } catch (e) {}
        }
        return null;
    }

    function describeAddr(addr) {
        var p = ptr(addr);
        var mod = null;
        try { mod = Process.findModuleByAddress(p); } catch (e) {}
        var range = findRangeFor(p);
        return {
            addr: p.toString(),
            module: mod ? mod.name : null,
            module_base: mod ? mod.base.toString() : null,
            file: filePathFor(range),
            range_base: range ? range.base.toString() : null,
            range_size: range ? range.size : null,
            protection: range ? range.protection : null,
        };
    }

    function pushEvent(event) {
        if (state.events.length >= state.maxEvents) {
            state.events.shift();
            state.drops++;
        }
        state.events.push(event);
    }

    function noteFailure(label, error) {
        state.failures.push({
            label: label,
            error: String(error),
        });
        if (state.failures.length > 16) state.failures.shift();
        console.log('[CAPTURE] [61CCD8LR] ' + label + ' failed: ' + error);
    }

    console.log('[CAPTURE] [61CCD8LR] hooking ' + TARGET);

    try {
        Interceptor.attach(TARGET, {
            onEnter: function () {
                pushEvent({
                    seq: ++state.seq,
                    pc: fmtPtr(this.context.pc),
                    lr: fmtPtr(this.context.lr),
                    lr_desc: describeAddr(this.context.lr),
                    x0: fmtPtr(this.context.x0),
                    x1: fmtPtr(this.context.x1),
                    x2: fmtPtr(this.context.x2),
                    x3: fmtPtr(this.context.x3),
                    x4: fmtPtr(this.context.x4),
                });
            }
        });
    } catch (e) {
        noteFailure('hook ' + TARGET, e);
    }

    globalThis.__jitFocus61ccd8LrClear = function () {
        state.seq = 0;
        state.drops = 0;
        state.events.length = 0;
        state.failures.length = 0;
        return 'OK';
    };

    globalThis.__jitFocus61ccd8LrDump = function () {
        return JSON.stringify({
            drops: state.drops,
            events: state.events,
            failures: state.failures,
        });
    };
})();
