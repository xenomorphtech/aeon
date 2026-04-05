// Absolute indirect-call hooks for the current live cert trace session.

'use strict';

(function () {
    if (globalThis.__jitAbsCallTargets && globalThis.__jitAbsCallTargets.installed) {
        console.log('[CAPTURE] [ABSCT] relay already installed');
        return;
    }

    var state = globalThis.__jitAbsCallTargets = {
        installed: true,
        maxEvents: 256,
        seq: 0,
        drops: 0,
        events: [],
        failures: [],
        hooks: {},
        calleeHooks: {},
        calleeCounts: {},
    };

    var TARGETS = [
        { label: 'abs_617e10_blr', addr: ptr('0x9b617e10') },
        { label: 'abs_617e90_blr', addr: ptr('0x9b617e90') },
        { label: 'abs_61cce0_blr', addr: ptr('0x9b61cce0') },
    ];
    var SAMPLE = 64;

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

    function readBytesMaybe(addr, size) {
        try {
            var bytes = Memory.readByteArray(ptr(addr), size);
            var view = new Uint8Array(bytes);
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
        console.log('[CAPTURE] [ABSCT] ' + label + ' failed: ' + error);
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

    function shouldLog(count) {
        return count <= 8 || (count % SAMPLE) === 0;
    }

    function isJitDesc(desc) {
        return !!(desc && desc.file && desc.file.indexOf('/memfd:jit-cache') >= 0);
    }

    function attachCallee(addr, sourceLabel, desc) {
        var key = ptr(addr).toString();
        if (state.calleeHooks[key]) return;
        try {
            Interceptor.attach(ptr(addr), {
                onEnter: function () {
                    var count = (state.calleeCounts[key] || 0) + 1;
                    state.calleeCounts[key] = count;
                    this.deepCount = count;
                    if (!shouldLog(count)) return;
                    pushEvent({
                        seq: ++state.seq,
                        kind: 'callee_enter',
                        source: sourceLabel,
                        target: key,
                        target_desc: desc,
                        count: count,
                        pc: fmtPtr(this.context.pc),
                        lr: fmtPtr(this.context.lr),
                        x0: fmtPtr(this.context.x0),
                        x1: fmtPtr(this.context.x1),
                        x2: fmtPtr(this.context.x2),
                        x3: fmtPtr(this.context.x3),
                        x4: fmtPtr(this.context.x4),
                        x0_bytes: readBytesMaybe(this.context.x0, 32),
                        x1_bytes: readBytesMaybe(this.context.x1, 32),
                    });
                },
                onLeave: function (retval) {
                    if (!shouldLog(this.deepCount || 0)) return;
                    pushEvent({
                        seq: ++state.seq,
                        kind: 'callee_leave',
                        source: sourceLabel,
                        target: key,
                        target_desc: desc,
                        count: this.deepCount || null,
                        retval: fmtPtr(retval),
                        x0_after: fmtPtr(this.context.x0),
                    });
                }
            });
            state.calleeHooks[key] = true;
            console.log('[CAPTURE] [ABSCT] hooked callee from ' + sourceLabel + ' -> ' + key);
        } catch (e) {
            noteFailure('hook callee ' + key + ' from ' + sourceLabel, e);
        }
    }

    function attachSite(spec) {
        var key = spec.addr.toString();
        if (state.hooks[key]) return;
        try {
            Interceptor.attach(spec.addr, {
                onEnter: function () {
                    var target = ptr(this.context.x30);
                    var desc = describeAddr(target);
                    pushEvent({
                        seq: ++state.seq,
                        kind: 'site',
                        label: spec.label,
                        addr: key,
                        pc: fmtPtr(this.context.pc),
                        lr: fmtPtr(this.context.lr),
                        x0: fmtPtr(this.context.x0),
                        x1: fmtPtr(this.context.x1),
                        x2: fmtPtr(this.context.x2),
                        x3: fmtPtr(this.context.x3),
                        x4: fmtPtr(this.context.x4),
                        x30: fmtPtr(this.context.x30),
                        target_desc: desc,
                        x0_bytes: readBytesMaybe(this.context.x0, 32),
                        x1_bytes: readBytesMaybe(this.context.x1, 32),
                    });
                    if (desc && !isJitDesc(desc)) {
                        attachCallee(target, spec.label, desc);
                    }
                }
            });
            state.hooks[key] = true;
            console.log('[CAPTURE] [ABSCT] hooked site ' + spec.label + '@' + key);
        } catch (e) {
            noteFailure('hook site ' + spec.label + '@' + key, e);
        }
    }

    globalThis.__jitAbsCallClear = function () {
        state.seq = 0;
        state.drops = 0;
        state.events.length = 0;
        state.failures.length = 0;
        return 'OK';
    };

    globalThis.__jitAbsCallDump = function () {
        return JSON.stringify({
            drops: state.drops,
            events: state.events,
            failures: state.failures,
            callee_counts: state.calleeCounts,
        });
    };

    TARGETS.forEach(attachSite);
})();
