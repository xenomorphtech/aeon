// Cert-call stalker keyed off the first native handoff site hit in libUnreal.
// This avoids guessing the worker thread from the RPC or Java thread.

'use strict';

(function () {
    if (globalThis.__jitNativeThreadStalker && globalThis.__jitNativeThreadStalker.installed) {
        console.log('[CAPTURE] [JNATIVE] relay already installed');
        return;
    }

    var RESOLVE_ENCODER_OFFSET = 0x209dc4;
    var BLR_X8_OFFSET = 0x20b548;

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function filePathFor(range) {
        try {
            return range && range.file && range.file.path ? String(range.file.path) : null;
        } catch (e) {
            return null;
        }
    }

    function isInterestingExecRange(range) {
        var path = filePathFor(range) || '';
        if (!path) return true;
        if (path.indexOf('jit-cache') >= 0) return true;
        if (path.indexOf('com.netmarble.thered') >= 0) return true;
        if (path.indexOf('libUnreal.so') >= 0) return true;
        if (path.indexOf('(deleted)') >= 0) return true;
        if (path.indexOf('/data/app/') >= 0) return true;
        if (path.indexOf('/data/data/com.netmarble.thered/') >= 0) return true;
        if (path.indexOf('/apex/') === 0) return false;
        if (path.indexOf('/system/') === 0) return false;
        return true;
    }

    function chooseTraceRanges() {
        var out = [];
        var prots = ['r-x', '--x', 'rwx', '-wx'];
        for (var i = 0; i < prots.length; i++) {
            try {
                Process.enumerateRanges(prots[i]).forEach(function (r) {
                    if (isInterestingExecRange(r)) out.push(r);
                });
            } catch (e) {}
        }
        return out;
    }

    function insideAny(addr, ranges) {
        if (!ranges || ranges.length === 0) return false;
        var p = ptr(addr);
        for (var i = 0; i < ranges.length; i++) {
            var r = ranges[i];
            if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) return true;
        }
        return false;
    }

    function describeRanges(ranges) {
        return ranges.map(function (r) {
            return {
                base: r.base.toString(),
                size: r.size,
                protection: r.protection,
                file: filePathFor(r),
            };
        });
    }

    function bump(map, key) {
        var v = (map[key] || 0) + 1;
        map[key] = v;
        return v;
    }

    function sortedTop(map, limit) {
        var max = parseInt(limit || 32, 10);
        if (!(max > 0)) max = 32;
        return Object.keys(map)
            .map(function (k) { return { pc: k, hits: map[k] }; })
            .sort(function (a, b) { return b.hits - a.hits; })
            .slice(0, max);
    }

    var unrealBase = null;
    try {
        if (typeof nmsscr_base !== 'undefined' && nmsscr_base) {
            unrealBase = ptr(nmsscr_base);
        }
    } catch (e) {}
    if (unrealBase === null) {
        unrealBase = Process.getModuleByName('libUnreal.so').base;
    }
    var state = globalThis.__jitNativeThreadStalker = {
        installed: true,
        active: false,
        ranges: [],
        challenge: null,
        startedAt: null,
        token: null,
        blockCount: 0,
        pcHits: {},
        startHook: null,
        workerThreadId: null,
        hookHits: [],
        error: null,
    };

    function clearState() {
        state.active = false;
        state.ranges = [];
        state.challenge = null;
        state.startedAt = null;
        state.token = null;
        state.blockCount = 0;
        state.pcHits = {};
        state.startHook = null;
        state.workerThreadId = null;
        state.hookHits = [];
        state.error = null;
    }

    function startForThread(threadId, hookName) {
        if (state.workerThreadId !== null) return;
        state.workerThreadId = threadId;
        state.startHook = hookName;
        Stalker.follow(threadId, {
            transform: function (iterator) {
                var instruction;
                while ((instruction = iterator.next()) !== null) {
                    var blockHead = ptr(instruction.address);
                    if (insideAny(blockHead, state.ranges)) {
                        state.blockCount++;
                        (function (capturedPc) {
                            iterator.putCallout(function () {
                                bump(state.pcHits, capturedPc.toString());
                            });
                        })(blockHead);
                    }
                    iterator.keep();
                }
            }
        });
    }

    function stopWorkerTrace() {
        try {
            if (state.workerThreadId !== null) {
                Stalker.unfollow(state.workerThreadId);
            }
        } catch (e) {}
        try { Stalker.garbageCollect(); } catch (e) {}
    }

    function onNativeHook(hookName, ctx) {
        if (!state.active) return;
        var tid = Process.getCurrentThreadId();
        state.hookHits.push({
            hook: hookName,
            threadId: tid,
            pc: fmt(ctx.pc),
            lr: fmt(ctx.lr),
        });
        if (state.hookHits.length > 16) state.hookHits.shift();
        try {
            startForThread(tid, hookName);
        } catch (e) {
            state.error = String(e);
        }
    }

    Interceptor.attach(unrealBase.add(RESOLVE_ENCODER_OFFSET), {
        onEnter: function () {
            onNativeHook('resolve_encoder', this.context);
        }
    });

    Interceptor.attach(unrealBase.add(BLR_X8_OFFSET), {
        onEnter: function () {
            onNativeHook('blr_x8', this.context);
        }
    });

    globalThis.__jitNativeThreadTraceRun = function (challenge) {
        clearState();
        state.active = true;
        state.challenge = challenge;
        state.startedAt = (new Date()).toISOString();
        state.ranges = chooseTraceRanges();
        if (state.ranges.length === 0) {
            state.active = false;
            state.error = 'interesting exec ranges not found';
            return JSON.stringify(state);
        }

        try {
            Java.performNow(function () {
                var r = null;
                try {
                    var inst = Java.use('nmss.app.NmssSa').getInstObj();
                    if (!inst) {
                        r = 'NO_INSTANCE';
                    } else {
                        r = inst.getCertValue(challenge);
                        if (r) r = r.toString();
                    }
                } catch (inner) {
                    r = 'ERR:' + inner;
                }
                state.token = r || '';
            });
        } catch (e) {
            state.error = String(e);
        } finally {
            state.active = false;
            stopWorkerTrace();
        }

        return JSON.stringify({
            challenge: state.challenge,
            token: state.token,
            startedAt: state.startedAt,
            workerThreadId: state.workerThreadId,
            startHook: state.startHook,
            hookHits: state.hookHits,
            blockCount: state.blockCount,
            pcHits: state.pcHits,
            top: sortedTop(state.pcHits, 40),
            ranges: describeRanges(state.ranges),
            error: state.error,
        });
    };
})();
