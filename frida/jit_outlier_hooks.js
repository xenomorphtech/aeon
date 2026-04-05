// Direct hooks for cert-corridor PCs in the live jit-cache image.
// Finds the executable /memfd:jit-cache mapping and attaches at selected
// offsets relative to that base. Exposes a ring buffer via /eval.

'use strict';

(function () {
    if (globalThis.__jitOutlierHooks && globalThis.__jitOutlierHooks.installed) {
        console.log('[CAPTURE] [OUTLIER] relay already installed');
        return;
    }

    var state = globalThis.__jitOutlierHooks = {
        installed: true,
        base: null,
        file: null,
        maxEvents: 512,
        seq: 0,
        drops: 0,
        events: [],
        failures: [],
        hooks: {},
    };

    var TARGETS = [
        { label: 'pc_9b610b10', offset: 0x12b10 },
        { label: 'pc_9b611dd0', offset: 0x13dd0 },
    ];
    var EXEC_PROTECTIONS = ['r-x', '--x'];
    var REGS = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'sp', 'pc', 'lr'];

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function snapshotRegs(ctx) {
        var out = {};
        REGS.forEach(function (reg) {
            try { out[reg] = fmtPtr(ctx[reg]); } catch (e) {}
        });
        return out;
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
        if (state.failures.length > 32) {
            state.failures.shift();
        }
        console.log('[CAPTURE] [OUTLIER] ' + label + ' failed: ' + error);
    }

    function filePathFor(range) {
        try {
            return range && range.file && range.file.path ? String(range.file.path) : null;
        } catch (e) {
            return null;
        }
    }

    function enumerateExecRanges() {
        var out = [];
        var seen = {};
        EXEC_PROTECTIONS.forEach(function (prot) {
            try {
                Process.enumerateRanges(prot).forEach(function (range) {
                    var protection = range.protection || prot;
                    if (protection.indexOf('w') !== -1) return;
                    var key = range.base.toString() + ':' + range.size.toString();
                    if (seen[key]) return;
                    seen[key] = true;
                    out.push(range);
                });
            } catch (e) {
                noteFailure('enumerate exec ranges ' + prot, e);
            }
        });
        return out;
    }

    function chooseJitExecRange() {
        var best = null;
        enumerateExecRanges().forEach(function (range) {
            var path = filePathFor(range);
            if (!path || path.indexOf('/memfd:jit-cache') < 0) return;
            if (best === null || range.size > best.size) {
                best = range;
            }
        });
        return best;
    }

    function record(kind, label, ctx, extra) {
        var event = {
            seq: ++state.seq,
            kind: kind,
            label: label,
            regs: snapshotRegs(ctx),
        };
        if (extra) {
            Object.keys(extra).forEach(function (key) {
                event[key] = extra[key];
            });
        }
        pushEvent(event);
    }

    function attachTarget(base, target) {
        var addr = base.add(target.offset);
        var key = addr.toString();
        if (state.hooks[key]) return;
        try {
            Interceptor.attach(addr, {
                onEnter: function () {
                    this.callId = ++state.seq;
                    record('enter', target.label, this.context, {
                        call_id: this.callId,
                        addr: addr.toString(),
                        offset: '0x' + target.offset.toString(16),
                    });
                },
                onLeave: function (retval) {
                    record('leave', target.label, this.context, {
                        call_id: this.callId,
                        addr: addr.toString(),
                        offset: '0x' + target.offset.toString(16),
                        retval: fmtPtr(retval),
                        x0_after: this.context ? fmtPtr(this.context.x0) : null,
                    });
                }
            });
            state.hooks[key] = true;
            console.log('[CAPTURE] [OUTLIER] hooked ' + target.label + '@' + addr);
        } catch (e) {
            noteFailure('hook ' + target.label + '@' + addr, e);
        }
    }

    function install() {
        var range = chooseJitExecRange();
        if (!range) {
            noteFailure('install', 'jit-cache execute range not found');
            return;
        }
        state.base = range.base.toString();
        state.file = filePathFor(range);
        console.log('[CAPTURE] [OUTLIER] install base=' + state.base + ' file=' + state.file);
        TARGETS.forEach(function (target) {
            attachTarget(range.base, target);
        });
    }

    globalThis.__jitOutlierClear = function () {
        state.seq = 0;
        state.drops = 0;
        state.events.length = 0;
        return 'OK';
    };

    globalThis.__jitOutlierDump = function () {
        return JSON.stringify({
            base: state.base,
            file: state.file,
            drops: state.drops,
            events: state.events,
            failures: state.failures,
        });
    };

    setTimeout(install, 0);
})();
