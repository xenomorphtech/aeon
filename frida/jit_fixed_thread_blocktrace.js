// Follow a fixed worker thread during a cert call and record ordered JIT block
// heads. This avoids LR-based stop heuristics and captures the obfuscated path
// until the cert call completes.

'use strict';

(function () {
    if (globalThis.__jitFixedThreadBlocktrace && globalThis.__jitFixedThreadBlocktrace.installed) {
        console.log('[CAPTURE] [JFBT] relay already installed');
        return;
    }

    var MAX_BLOCK_TRACE = 16384;

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
        if (path.indexOf('/data/data/com.netmarble.thered/files/') >= 0 &&
            path.indexOf('(deleted)') >= 0) {
            return true;
        }
        if (path.indexOf('(deleted)') >= 0) return true;
        if (path.indexOf('/data/app/') >= 0) return true;
        if (path.indexOf('/apex/') === 0) return false;
        if (path.indexOf('/system/') === 0) return false;
        return false;
    }

    function chooseTraceRanges() {
        var out = [];
        var seen = {};
        ['r-x', '--x', 'rwx', '-wx'].forEach(function (prot) {
            try {
                Process.enumerateRanges(prot).forEach(function (range) {
                    var key = range.base.toString() + ':' + range.size.toString();
                    if (seen[key]) return;
                    if (!isInterestingExecRange(range)) return;
                    seen[key] = true;
                    out.push(range);
                });
            } catch (e) {}
        });
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

    function parseThreadIds(jsonThreads) {
        var threadIds = [];
        try {
            threadIds = typeof jsonThreads === 'string' ? JSON.parse(jsonThreads) : jsonThreads;
        } catch (e) {
            threadIds = [];
        }
        if (!Array.isArray(threadIds)) {
            threadIds = [];
        }
        return threadIds
            .map(function (tid) { return parseInt(tid, 10); })
            .filter(function (tid) { return tid > 0; });
    }

    function enumerateTraceThreadIds() {
        var currentTid = null;
        try {
            currentTid = Process.getCurrentThreadId();
        } catch (e) {}
        var seen = {};
        var out = [];
        try {
            Process.enumerateThreads().forEach(function (thread) {
                var tid = parseInt(thread.id, 10);
                if (!(tid > 0)) return;
                if (currentTid !== null && tid === currentTid) return;
                if (seen[tid]) return;
                seen[tid] = true;
                out.push(tid);
            });
        } catch (e) {}
        return out;
    }

    var state = globalThis.__jitFixedThreadBlocktrace = {
        installed: true,
        last: null,
    };

    globalThis.__jitFixedThreadBlocktraceRun = function (challenge, jsonThreads) {
        var ranges = chooseTraceRanges();
        var threadIds = parseThreadIds(jsonThreads);
        if (threadIds.length === 0) {
            threadIds = enumerateTraceThreadIds();
        }
        if (threadIds.length === 0) {
            return JSON.stringify({ ok: false, error: 'no traceable threads' });
        }
        if (ranges.length === 0) {
            return JSON.stringify({ ok: false, error: 'jit ranges not found' });
        }

        var pcHits = {};
        var blockTrace = [];
        var blockTraceDrops = 0;
        var blockCount = 0;
        var token = null;
        var error = null;
        var followed = [];
        var startedAt = (new Date()).toISOString();

        function pushBlock(event) {
            if (blockTrace.length >= MAX_BLOCK_TRACE) {
                blockTraceDrops++;
                return;
            }
            blockTrace.push(event);
        }

        function onBlock(threadId, pc, context) {
            var pcKey = fmt(pc);
            var seq = ++blockCount;
            pushBlock({
                seq: seq,
                threadId: threadId,
                pc: pcKey,
                lr: fmt(context.lr),
                sp: fmt(context.sp),
                x0: fmt(context.x0),
                x1: fmt(context.x1),
                x8: fmt(context.x8),
                count: bump(pcHits, pcKey),
            });
        }

        try {
            threadIds.forEach(function (tid) {
                var threadId = parseInt(tid, 10);
                if (!(threadId > 0)) return;
                followed.push(threadId);
                Stalker.follow(threadId, {
                    transform: function (iterator) {
                        var instruction = iterator.next();
                        if (instruction === null) {
                            return;
                        }
                        var blockHead = ptr(instruction.address);
                        if (insideAny(blockHead, ranges)) {
                            (function (capturedPc) {
                                iterator.putCallout(function (context) {
                                    onBlock(threadId, capturedPc, context);
                                });
                            })(blockHead);
                        }
                        iterator.keep();
                        instruction = iterator.next();
                        while (instruction !== null) {
                            iterator.keep();
                            instruction = iterator.next();
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
            ok: !error,
            challenge: challenge,
            token: token,
            followed: followed,
            startedAt: startedAt,
            endedAt: (new Date()).toISOString(),
            ranges: describeRanges(ranges),
            blockCount: blockCount,
            blockTraceDrops: blockTraceDrops,
            blockTrace: blockTrace,
            pcHits: pcHits,
            top: sortedTop(pcHits, 40),
            error: error,
        };
        return JSON.stringify(state.last);
    };

    globalThis.__jitFixedThreadBlocktraceDump = function () {
        return JSON.stringify(state.last);
    };
})();
