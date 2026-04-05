// Low-overhead cert-call stalker.
// Follows only the current RPC thread while rpc.exports.callCert() runs and
// records JIT basic-block heads inside the live jit-cache execute mapping.

'use strict';

(function () {
    if (globalThis.__jitCertCalltrace && globalThis.__jitCertCalltrace.installed) {
        console.log('[CAPTURE] [JCALL] relay already installed');
        return;
    }

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
                var rs = Process.enumerateRanges(prots[i]);
                for (var j = 0; j < rs.length; j++) {
                    var r = rs[j];
                    if (isInterestingExecRange(r)) {
                        out.push(r);
                    }
                }
            } catch (e) {}
        }
        return out;
    }

    function insideAny(addr, ranges) {
        if (!ranges || ranges.length === 0) return false;
        var p = ptr(addr);
        for (var i = 0; i < ranges.length; i++) {
            var range = ranges[i];
            if (p.compare(range.base) >= 0 && p.compare(range.base.add(range.size)) < 0) {
                return true;
            }
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

    var state = globalThis.__jitCertCalltrace = {
        installed: true,
        last: null,
    };

    globalThis.__jitCertCalltraceRun = function (challenge) {
        var ranges = chooseTraceRanges();
        if (!ranges || ranges.length === 0) {
            return JSON.stringify({
                ok: false,
                error: 'interesting exec ranges not found',
            });
        }

        var threadId = null;
        var pcHits = {};
        var blockCount = 0;
        var token = null;
        var error = null;
        var startedAt = (new Date()).toISOString();

        try {
            Java.performNow(function () {
                threadId = Process.getCurrentThreadId();
                Stalker.follow(threadId, {
                    transform: function (iterator) {
                        var instruction;
                        while ((instruction = iterator.next()) !== null) {
                            var blockHead = ptr(instruction.address);
                            if (insideAny(blockHead, ranges)) {
                                blockCount++;
                                (function (capturedPc) {
                                    iterator.putCallout(function () {
                                        bump(pcHits, capturedPc.toString());
                                    });
                                })(blockHead);
                            }
                            iterator.keep();
                        }
                    }
                });

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
                token = r || '';
            });
        } catch (e) {
            error = String(e);
        } finally {
            try {
                if (threadId !== null && threadId !== undefined) {
                    Stalker.unfollow(threadId);
                }
            } catch (e) {}
            try { Stalker.garbageCollect(); } catch (e) {}
        }

        state.last = {
            ok: !error,
            challenge: challenge,
            token: token,
            threadId: threadId,
            startedAt: startedAt,
            endedAt: (new Date()).toISOString(),
            ranges: describeRanges(ranges),
            blockCount: blockCount,
            pcHits: pcHits,
            top: sortedTop(pcHits, 40),
            error: error,
        };

        return JSON.stringify(state.last);
    };

    globalThis.__jitCertCalltraceDump = function () {
        return JSON.stringify(state.last);
    };
})();
