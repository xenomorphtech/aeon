// Deep target hooks for the cert builder corridor.
// Hooks selected indirect-call producer sites inside the live jit-cache
// execute alias and records their resolved call targets. If a resolved
// target lands outside jit-cache, attach a second-level hook there.

'use strict';

(function () {
    if (globalThis.__jitDeepTargets && globalThis.__jitDeepTargets.installed) {
        console.log('[CAPTURE] [DEEP] relay already installed');
        return;
    }

    var state = globalThis.__jitDeepTargets = {
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
        {
            label: 'jit_617e00',
            offset: 0x19e00,
            resolveTarget: function (ctx) {
                var obj128 = readPtrMaybe(ptr(ctx.x0).add(128));
                var slot240 = obj128 ? readPtrMaybe(obj128.add(240)) : null;
                var target = slot240 ? readPtrMaybe(slot240.add(24)) : null;
                return {
                    root: fmtPtr(ctx.x0),
                    obj128: fmtMaybe(obj128),
                    slot240: fmtMaybe(slot240),
                    target: fmtMaybe(target),
                    targetPtr: target,
                };
            }
        },
        {
            label: 'jit_617e80',
            offset: 0x19e80,
            resolveTarget: function (ctx) {
                var obj128 = readPtrMaybe(ptr(ctx.x0).add(128));
                var slot240 = obj128 ? readPtrMaybe(obj128.add(240)) : null;
                var target = slot240 ? readPtrMaybe(slot240.add(24)) : null;
                return {
                    root: fmtPtr(ctx.x0),
                    obj128: fmtMaybe(obj128),
                    slot240: fmtMaybe(slot240),
                    target: fmtMaybe(target),
                    targetPtr: target,
                };
            }
        },
        {
            label: 'jit_61ccd8',
            offset: 0x1ecd8,
            resolveTarget: function (ctx) {
                var slot232 = readPtrMaybe(ptr(ctx.x0).add(232));
                var target = slot232 ? readPtrMaybe(slot232.add(24)) : null;
                return {
                    root: fmtPtr(ctx.x0),
                    slot232: fmtMaybe(slot232),
                    target: fmtMaybe(target),
                    targetPtr: target,
                };
            }
        },
    ];
    var EXEC_PROTECTIONS = ['r-x', '--x'];
    var EXTERNAL_SAMPLE = 64;

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function fmtMaybe(value) {
        return value ? fmtPtr(value) : null;
    }

    function readPtrMaybe(addr) {
        try { return Memory.readPointer(ptr(addr)); } catch (e) { return null; }
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

    function filePathFor(range) {
        try {
            return range && range.file && range.file.path ? String(range.file.path) : null;
        } catch (e) {
            return null;
        }
    }

    function findRangeFor(addr) {
        var p = ptr(addr);
        var seen = {};
        for (var i = 0; i < EXEC_PROTECTIONS.length; i++) {
            var prot = EXEC_PROTECTIONS[i];
            try {
                var ranges = Process.enumerateRanges(prot);
                for (var j = 0; j < ranges.length; j++) {
                    var range = ranges[j];
                    var key = range.base.toString() + ':' + range.size;
                    if (seen[key]) continue;
                    seen[key] = true;
                    if (p.compare(range.base) >= 0 && p.compare(range.base.add(range.size)) < 0) {
                        return range;
                    }
                }
            } catch (e) {}
        }
        try {
            var all = Process.enumerateRanges('r--');
            for (var k = 0; k < all.length; k++) {
                var r = all[k];
                if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) {
                    return r;
                }
            }
        } catch (e) {}
        return null;
    }

    function describeAddr(addr) {
        if (!addr) return null;
        var p = ptr(addr);
        var range = findRangeFor(p);
        var mod = null;
        try { mod = Process.findModuleByAddress(p); } catch (e) {}
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
        if (state.failures.length > 32) {
            state.failures.shift();
        }
        console.log('[CAPTURE] [DEEP] ' + label + ' failed: ' + error);
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

    function isJitTarget(desc) {
        if (!desc) return false;
        return !!(desc.file && desc.file.indexOf('/memfd:jit-cache') >= 0);
    }

    function shouldLog(count) {
        return count <= 8 || (count % EXTERNAL_SAMPLE) === 0;
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
                        x5: fmtPtr(this.context.x5),
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
            console.log('[CAPTURE] [DEEP] hooked callee from ' + sourceLabel + ' -> ' + key);
        } catch (e) {
            noteFailure('hook callee ' + key + ' from ' + sourceLabel, e);
        }
    }

    function attachTarget(base, spec) {
        var addr = base.add(spec.offset);
        var key = addr.toString();
        if (state.hooks[key]) return;
        try {
            Interceptor.attach(addr, {
                onEnter: function () {
                    var info = spec.resolveTarget(this.context);
                    var desc = describeAddr(info.targetPtr);
                    pushEvent({
                        seq: ++state.seq,
                        kind: 'site',
                        label: spec.label,
                        addr: addr.toString(),
                        offset: '0x' + spec.offset.toString(16),
                        pc: fmtPtr(this.context.pc),
                        lr: fmtPtr(this.context.lr),
                        x0: fmtPtr(this.context.x0),
                        x1: fmtPtr(this.context.x1),
                        x2: fmtPtr(this.context.x2),
                        x3: fmtPtr(this.context.x3),
                        x4: fmtPtr(this.context.x4),
                        resolved: {
                            root: info.root || null,
                            obj128: info.obj128 || null,
                            slot240: info.slot240 || null,
                            slot232: info.slot232 || null,
                            target: info.target || null,
                            target_desc: desc,
                        }
                    });
                    if (info.targetPtr && desc && !isJitTarget(desc)) {
                        attachCallee(info.targetPtr, spec.label, desc);
                    }
                }
            });
            state.hooks[key] = true;
            console.log('[CAPTURE] [DEEP] hooked site ' + spec.label + '@' + addr);
        } catch (e) {
            noteFailure('hook site ' + spec.label + '@' + addr, e);
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
        console.log('[CAPTURE] [DEEP] install base=' + state.base + ' file=' + state.file);
        TARGETS.forEach(function (spec) {
            attachTarget(range.base, spec);
        });
    }

    globalThis.__jitDeepClear = function () {
        state.seq = 0;
        state.drops = 0;
        state.events.length = 0;
        state.failures.length = 0;
        return 'OK';
    };

    globalThis.__jitDeepDump = function () {
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
