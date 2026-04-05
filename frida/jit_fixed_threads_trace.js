// Follow a fixed set of worker thread IDs during a cert call and count block heads
// in interesting non-system executable mappings.

'use strict';

(function () {
    if (globalThis.__jitFixedThreadsTrace && globalThis.__jitFixedThreadsTrace.installed) {
        console.log('[CAPTURE] [JFIX] relay already installed');
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
            if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) {
                return true;
            }
        }
        return false;
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

    var state = globalThis.__jitFixedThreadsTrace = {
        installed: true,
        last: null,
    };

    globalThis.__jitFixedThreadsTraceRun = function (challenge, jsonThreads) {
        if (typeof globalThis.__jitGateFixedThreadTraceRun === 'function') {
            var forwarded = globalThis.__jitGateFixedThreadTraceRun(challenge, jsonThreads);
            try {
                state.last = typeof forwarded === 'string' ? JSON.parse(forwarded) : forwarded;
            } catch (e) {
                state.last = forwarded;
            }
            return forwarded;
        }

        var ranges = chooseTraceRanges();
        var threadIds = [];
        try {
            threadIds = typeof jsonThreads === 'string' ? JSON.parse(jsonThreads) : jsonThreads;
        } catch (e) {
            threadIds = [];
        }
        if (!Array.isArray(threadIds) || threadIds.length === 0) {
            return JSON.stringify({ ok: false, error: 'no thread ids' });
        }

        var pcHits = {};
        var blockCount = 0;
        var token = null;
        var error = null;
        var followed = [];

        try {
            threadIds.forEach(function (tid) {
                var threadId = parseInt(tid, 10);
                if (!(threadId > 0)) return;
                followed.push(threadId);
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
            });

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
                token = r || '';
            });
        } catch (e) {
            error = String(e);
        } finally {
            followed.forEach(function (threadId) {
                try { Stalker.unfollow(threadId); } catch (e) {}
            });
            try { Stalker.garbageCollect(); } catch (e) {}
        }

        state.last = {
            challenge: challenge,
            token: token,
            followed: followed,
            blockCount: blockCount,
            pcHits: pcHits,
            top: sortedTop(pcHits, 40),
            ranges: describeRanges(ranges),
            error: error,
        };
        return JSON.stringify(state.last);
    };
})();
