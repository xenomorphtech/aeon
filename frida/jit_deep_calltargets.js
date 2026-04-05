// Hooks the actual indirect call instructions for selected deep cert sites.
// This captures x30 after the object slot load, which is the real callee.

'use strict';

(function () {
    if (globalThis.__jitDeepCallTargets && globalThis.__jitDeepCallTargets.installed) {
        console.log('[CAPTURE] [DCALL] relay already installed');
        return;
    }

    var state = globalThis.__jitDeepCallTargets = {
        installed: true,
        base: null,
        file: null,
        maxEvents: 512,
        seq: 0,
        drops: 0,
        events: [],
        failures: [],
        hooks: {},
        calleeHooks: {},
        calleeCounts: {},
    };

    var TARGETS = [
        { label: 'jit_617e10_blr', offset: 0x19e10 },
        { label: 'jit_617e90_blr', offset: 0x19e90 },
        { label: 'jit_61cce0_blr', offset: 0x1ece0 },
    ];
    var EXEC_PROTECTIONS = ['r-x', '--x'];
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
        console.log('[CAPTURE] [DCALL] ' + label + ' failed: ' + error);
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
            if (best === null || range.size > best.size) best = range;
        });
        return best;
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
        if (!addr) return null;
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
            console.log('[CAPTURE] [DCALL] hooked callee from ' + sourceLabel + ' -> ' + key);
        } catch (e) {
            noteFailure('hook callee ' + key + ' from ' + sourceLabel, e);
        }
    }

    function attachSite(base, spec) {
        var addr = base.add(spec.offset);
        var key = addr.toString();
        if (state.hooks[key]) return;
        try {
            Interceptor.attach(addr, {
                onEnter: function () {
                    var target = ptr(this.context.x30);
                    var desc = describeAddr(target);
                    pushEvent({
                        seq: ++state.seq,
                        kind: 'site',
                        label: spec.label,
                        addr: key,
                        offset: '0x' + spec.offset.toString(16),
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
            console.log('[CAPTURE] [DCALL] hooked site ' + spec.label + '@' + key);
        } catch (e) {
            noteFailure('hook site ' + spec.label + '@' + key, e);
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
        console.log('[CAPTURE] [DCALL] install base=' + state.base + ' file=' + state.file);
        TARGETS.forEach(function (spec) {
            attachSite(range.base, spec);
        });
    }

    globalThis.__jitDeepCallClear = function () {
        state.seq = 0;
        state.drops = 0;
        state.events.length = 0;
        state.failures.length = 0;
        return 'OK';
    };

    globalThis.__jitDeepCallDump = function () {
        return JSON.stringify({
            base: state.base,
            file: state.file,
            drops: state.drops,
            events: state.events,
            failures: state.failures,
            callee_counts: state.calleeCounts,
        });
    };

    setTimeout(install, 0);
})();
