// Trap-started LR-bounded cert trace.
// Arms a page trap on the live jit-cache corridor, starts stalking the first
// trapped execute thread during a cert call, and records ordered block heads
// until control returns to the LR seen at the trap entry.

'use strict';

(function () {
    if (globalThis.__jitNativeThreadLrTrace && globalThis.__jitNativeThreadLrTrace.installed) {
        console.log('[CAPTURE] [JNATLR] relay already installed');
        return;
    }

    var PTR_MASK = ptr('0x00FFFFFFFFFFFFFF');
    var PAGE_MASK = ptr('0xFFFFFFFFFFFFF000');
    var EXEC_PROTECTIONS = ['r-x', '--x'];
    var ACTIVE_EXEC_SIZE = 0x50000;
    var CERT_CORRIDOR_START = 0x12000;
    var CERT_CORRIDOR_END = 0x20000;
    var PAGE_SIZE = 0x1000;
    var MAX_BLOCK_TRACE = 16384;

    var state = globalThis.__jitNativeThreadLrTrace = {
        installed: true,
        active: false,
        currentBase: null,
        currentSize: 0,
        currentFile: null,
        activePage: null,
        challenge: null,
        startedAt: null,
        traceStartedAt: null,
        endedAt: null,
        token: null,
        workerThreadId: null,
        pendingThreadId: null,
        pendingStart: null,
        startPc: null,
        targetLr: null,
        trapStart: null,
        returnHit: null,
        stopReason: null,
        traceSeq: 0,
        blockCount: 0,
        blockTrace: [],
        blockTraceDrops: 0,
        pcHits: {},
        pageHits: {},
        edgeHits: {},
        trapCounts: {},
        ranges: [],
        exceptions: [],
        protections: [],
        failures: [],
        error: null,
    };

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function isoNow() {
        return (new Date()).toISOString();
    }

    function noteFailure(label, error) {
        state.failures.push({
            label: label,
            error: String(error),
            timestamp: isoNow(),
        });
        if (state.failures.length > 32) {
            state.failures.shift();
        }
        console.log('[CAPTURE] [JNATLR] ' + label + ' failed: ' + error);
    }

    function untagPtr(value) {
        try {
            return ptr(value).and(PTR_MASK);
        } catch (e) {
            return ptr('0');
        }
    }

    function pageBaseFor(value) {
        try {
            return untagPtr(value).and(PAGE_MASK);
        } catch (e) {
            return ptr('0');
        }
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

    function findExecRangeFor(addr) {
        var p = ptr(addr);
        var ranges = enumerateExecRanges();
        for (var i = 0; i < ranges.length; i++) {
            var r = ranges[i];
            if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) {
                return r;
            }
        }
        return null;
    }

    function isTrapCandidate(range) {
        var path = filePathFor(range);
        if (!path) return false;
        if (path.indexOf('jit-cache') >= 0) return true;
        if (path.indexOf('/data/data/com.netmarble.thered/files/') >= 0 &&
            path.indexOf('(deleted)') >= 0) {
            return true;
        }
        return false;
    }

    function scoreTrapCandidate(range) {
        var score = 0;
        var path = filePathFor(range) || '';
        if (path.indexOf('/memfd:jit-cache') >= 0) score += 1000;
        if (path.indexOf('/data/data/com.netmarble.thered/files/') >= 0) score += 500;
        if (path.indexOf('(deleted)') >= 0) score += 100;
        score += Math.min(range.size >>> 12, 0xffff);
        return score;
    }

    function chooseTrapRange() {
        var best = null;
        enumerateExecRanges().forEach(function (range) {
            if (!isTrapCandidate(range)) return;
            if (best === null || scoreTrapCandidate(range) > scoreTrapCandidate(best)) {
                best = range;
            }
        });
        return best;
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
            } catch (e) {
                noteFailure('choose trace ranges ' + prot, e);
            }
        });
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
        return (ranges || []).map(function (r) {
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

    function pushException(event) {
        state.exceptions.push(event);
        if (state.exceptions.length > 32) {
            state.exceptions.shift();
        }
    }

    function bumpTrapCount(addr) {
        var key = addr ? String(addr) : 'null';
        var count = (state.trapCounts[key] || 0) + 1;
        state.trapCounts[key] = count;
        return count;
    }

    function currentThreadIdMaybe() {
        try {
            return Process.getCurrentThreadId();
        } catch (e) {
            return null;
        }
    }

    function restoreExecProtection() {
        if (!state.currentBase || !state.currentSize) return true;
        try {
            Memory.protect(state.currentBase, state.currentSize, 'r-x');
            state.activePage = null;
            return true;
        } catch (e) {
            noteFailure('restore exec protection ' + fmt(state.currentBase), e);
            return false;
        }
    }

    function activatePage(pageBase) {
        try {
            if (!pageBase || pageBase.equals(ptr('0'))) return false;
            if (state.activePage && !state.activePage.equals(pageBase)) {
                Memory.protect(state.activePage, PAGE_SIZE, 'r--');
            }
            Memory.protect(pageBase, PAGE_SIZE, 'r-x');
            state.activePage = pageBase;
            return true;
        } catch (e) {
            noteFailure('activate page ' + fmt(pageBase), e);
            return false;
        }
    }

    function ensureTrapProtection(range) {
        try {
            var ok = Memory.protect(state.currentBase, state.currentSize, 'r--');
            state.protections.push({
                base: fmt(state.currentBase),
                size: '0x' + state.currentSize.toString(16),
                file: filePathFor(range),
                protection: 'r--',
                ok: !!ok,
                timestamp: isoNow(),
            });
            if (state.protections.length > 32) {
                state.protections.shift();
            }
            console.log('[CAPTURE] [JNATLR] protect jit ' + fmt(state.currentBase) +
                        ' size=0x' + state.currentSize.toString(16) + ' -> r-- ok=' + !!ok);
            return ok;
        } catch (e) {
            noteFailure('protect jit ' + fmt(range.base), e);
            return false;
        }
    }

    function installForRange(range) {
        if (!range) return false;
        restoreExecProtection();
        var maxSize = Math.min(range.size, ACTIVE_EXEC_SIZE);
        if (maxSize <= CERT_CORRIDOR_START) {
            noteFailure('install corridor ' + fmt(range.base), 'range too small');
            return false;
        }
        var corridorBase = range.base.add(CERT_CORRIDOR_START);
        var corridorSize = Math.min(maxSize, CERT_CORRIDOR_END) - CERT_CORRIDOR_START;
        state.currentBase = corridorBase;
        state.currentSize = corridorSize;
        state.currentFile = filePathFor(range);
        state.activePage = null;
        console.log('[CAPTURE] [JNATLR] installing for exec range base=' + range.base +
                    ' corridor=' + state.currentBase +
                    ' trap_size=0x' + state.currentSize.toString(16) +
                    ' file=' + (state.currentFile || ''));
        return true;
    }

    function isInsideTrappedJit(addr) {
        if (!state.currentBase || !state.currentSize || addr === null || addr === undefined) {
            return false;
        }
        try {
            var p = untagPtr(addr);
            return p.compare(state.currentBase) >= 0 &&
                   p.compare(state.currentBase.add(state.currentSize)) < 0;
        } catch (e) {
            return false;
        }
    }

    function isTargetTrapException(details) {
        if (!state.active) return false;
        if (!details || details.type !== 'access-violation') return false;
        var memoryOp = details.memory ? details.memory.operation : null;
        if (memoryOp !== 'execute') return false;
        if (details.memory && isInsideTrappedJit(details.memory.address)) return true;
        if (details.address && isInsideTrappedJit(details.address)) return true;
        if (details.context && isInsideTrappedJit(details.context.pc)) return true;
        return false;
    }

    function clearRunState() {
        state.active = false;
        state.challenge = null;
        state.startedAt = null;
        state.traceStartedAt = null;
        state.endedAt = null;
        state.token = null;
        state.workerThreadId = null;
        state.pendingThreadId = null;
        state.startPc = null;
        state.targetLr = null;
        state.trapStart = null;
        state.pendingStart = null;
        state.returnHit = null;
        state.stopReason = null;
        state.traceSeq = 0;
        state.blockCount = 0;
        state.blockTrace = [];
        state.blockTraceDrops = 0;
        state.pcHits = {};
        state.pageHits = {};
        state.edgeHits = {};
        state.trapCounts = {};
        state.ranges = [];
        state.exceptions = [];
        state.protections = [];
        state.error = null;
    }

    function clearAll() {
        clearRunState();
        state.currentBase = null;
        state.currentSize = 0;
        state.currentFile = null;
        state.activePage = null;
        state.failures = [];
    }

    function pushBlock(event) {
        if (state.blockTrace.length >= MAX_BLOCK_TRACE) {
            state.blockTraceDrops++;
            return;
        }
        state.blockTrace.push(event);
    }

    function shouldTraceBlock(blockHead) {
        if (state.targetLr !== null && fmt(blockHead) === state.targetLr) {
            return true;
        }
        return insideAny(blockHead, state.ranges);
    }

    function onBlock(threadId, pc, context) {
        if (!state.active || state.returnHit !== null) return;

        var pcKey = fmt(pc);
        var hitCount = bump(state.pcHits, pcKey);
        var seq = ++state.traceSeq;
        var isReturnToLr = state.targetLr !== null && pcKey === state.targetLr;
        var event = {
            seq: seq,
            threadId: threadId,
            pc: pcKey,
            lr: fmt(context.lr),
            sp: fmt(context.sp),
            x0: fmt(context.x0),
            x1: fmt(context.x1),
            x8: fmt(context.x8),
            count: hitCount,
            returnedToLr: isReturnToLr,
        };

        state.blockCount = seq;
        pushBlock(event);

        if (isReturnToLr) {
            state.returnHit = {
                seq: seq,
                threadId: threadId,
                pc: pcKey,
                lr: event.lr,
                sp: event.sp,
                x0: event.x0,
                timestamp: isoNow(),
            };
            state.stopReason = 'returned-to-lr';
        }
    }

    function pushTrapStart(threadId, context, event) {
        var pcKey = event.pc;
        var hitCount = bump(state.pcHits, pcKey);
        var isReturnToLr = state.targetLr !== null && pcKey === state.targetLr;
        var trapEvent = {
            seq: ++state.traceSeq,
            threadId: threadId,
            pc: pcKey,
            lr: event.lr,
            sp: fmt(context.sp),
            x0: fmt(context.x0),
            x1: fmt(context.x1),
            x8: fmt(context.x8),
            count: hitCount,
            returnedToLr: isReturnToLr,
            source: 'trap',
        };
        state.blockCount = state.traceSeq;
        pushBlock(trapEvent);
        if (isReturnToLr) {
            state.returnHit = {
                seq: trapEvent.seq,
                threadId: threadId,
                pc: trapEvent.pc,
                lr: trapEvent.lr,
                sp: trapEvent.sp,
                x0: trapEvent.x0,
                timestamp: isoNow(),
            };
            state.stopReason = 'returned-to-lr';
        }
    }

    function stopTrace(reason) {
        if (reason && state.stopReason === null) {
            state.stopReason = reason;
        }
        try {
            if (state.workerThreadId !== null) {
                Stalker.unfollow(state.workerThreadId);
            }
        } catch (e) {
            noteFailure('stalker stop thread=' + state.workerThreadId, e);
        }
        try { Stalker.garbageCollect(); } catch (e) {}
        state.pendingThreadId = null;
        state.pendingStart = null;
    }

    function scheduleTraceForThread(threadId, context, event) {
        if (!state.active || state.workerThreadId !== null ||
            threadId === null || threadId === undefined || !context) {
            return;
        }
        if (state.pendingThreadId === threadId) {
            return;
        }

        state.startPc = event.pc;
        state.targetLr = event.lr;
        state.trapStart = {
            timestamp: isoNow(),
            threadId: threadId,
            pc: event.pc,
            lr: event.lr,
            sp: fmt(context.sp),
            x0: fmt(context.x0),
            x1: fmt(context.x1),
            x8: fmt(context.x8),
            page: event.page,
            edge: event.edge,
        };

        pushTrapStart(threadId, context, event);

        if (state.returnHit !== null) {
            return;
        }

        state.pendingThreadId = threadId;
        state.pendingStart = {
            threadId: threadId,
            startPc: event.pc,
            targetLr: event.lr,
        };

        setTimeout(function () {
            if (!state.active || state.pendingThreadId !== threadId ||
                state.workerThreadId !== null || state.pendingStart === null) {
                return;
            }

            state.pendingThreadId = null;
            state.workerThreadId = threadId;
            state.traceStartedAt = isoNow();

            try {
                Stalker.follow(threadId, {
                    transform: function (iterator) {
                        var instruction;
                        while ((instruction = iterator.next()) !== null) {
                            var blockHead = ptr(instruction.address);
                            if (shouldTraceBlock(blockHead)) {
                                (function (capturedPc) {
                                    iterator.putCallout(function (ctx) {
                                        onBlock(threadId, capturedPc, ctx);
                                    });
                                })(blockHead);
                            }
                            iterator.keep();
                        }
                    }
                });

                console.log('[CAPTURE] [JNATLR] stalker start thread=' + threadId +
                            ' start_pc=' + state.pendingStart.startPc +
                            ' target_lr=' + state.pendingStart.targetLr);
            } catch (e) {
                state.error = String(e);
                state.workerThreadId = null;
                noteFailure('stalker follow thread=' + threadId, e);
            } finally {
                state.pendingStart = null;
            }
        }, 0);
    }

    function startTraceForThread(threadId, context, event) {
        if (state.workerThreadId !== null || threadId === null || threadId === undefined) {
            return;
        }
        if (!context) {
            return;
        }
        if (state.pendingThreadId === threadId || state.trapStart !== null) {
            return;
        }

        scheduleTraceForThread(threadId, context, event);
    }

    function buildResult() {
        return {
            ok: !state.error,
            challenge: state.challenge,
            token: state.token,
            startedAt: state.startedAt,
            traceStartedAt: state.traceStartedAt,
            endedAt: state.endedAt,
            workerThreadId: state.workerThreadId,
            startPc: state.startPc,
            targetLr: state.targetLr,
            stopReason: state.stopReason,
            trapStart: state.trapStart,
            returnHit: state.returnHit,
            corridor: state.currentBase ? {
                base: fmt(state.currentBase),
                size: state.currentSize,
                file: state.currentFile,
            } : null,
            blockCount: state.blockCount,
            blockTraceDrops: state.blockTraceDrops,
            blockTrace: state.blockTrace,
            pcHits: state.pcHits,
            top: sortedTop(state.pcHits, 40),
            exceptions: state.exceptions,
            protections: state.protections,
            failures: state.failures,
            ranges: describeRanges(state.ranges),
            error: state.error,
        };
    }

    if (!globalThis.__jitNativeThreadLrTraceExceptionHandlerInstalled) {
        Process.setExceptionHandler(function (details) {
            if (!isTargetTrapException(details)) {
                return false;
            }

            var event = {
                type: details.type || null,
                address: details.address ? fmt(details.address) : null,
                memory: details.memory ? {
                    operation: details.memory.operation || null,
                    address: details.memory.address ? fmt(details.memory.address) : null,
                } : null,
                pc: details.context ? fmt(details.context.pc) : null,
                lr: details.context ? fmt(details.context.lr) : null,
                matched_trap: true,
            };
            var pageBase = details.context ? pageBaseFor(details.context.pc) : pageBaseFor(details.address);
            var pageKey = pageBase ? pageBase.toString() : '0x0';
            var pcKey = event.pc || '0x0';
            var lrKey = event.lr || '0x0';
            var edgeKey = lrKey + '->' + pcKey;
            var threadId = details.threadId;
            if (threadId === null || threadId === undefined) {
                threadId = currentThreadIdMaybe();
            }
            var trapCount = bumpTrapCount(pcKey);
            state.pageHits[pageKey] = bump(state.pageHits, pageKey);
            state.edgeHits[edgeKey] = bump(state.edgeHits, edgeKey);
            event.page = pageKey;
            event.edge = edgeKey;
            event.threadId = threadId;
            event.count = trapCount;
            pushException(event);

            if (trapCount <= 4 || (trapCount % 1024) === 0) {
                console.log('[CAPTURE] [JNATLR] trapped execute fault type=' + event.type +
                            ' address=' + event.address +
                            ' pc=' + event.pc +
                            ' lr=' + event.lr +
                            ' thread=' + threadId +
                            ' page=' + event.page +
                            ' edge=' + event.edge +
                            ' count=' + trapCount);
            }

            if (state.workerThreadId === null && details.context) {
                try {
                    startTraceForThread(threadId, details.context, event);
                } catch (e) {
                    state.error = String(e);
                    noteFailure('start trace thread=' + threadId, e);
                }
            }

            if (!activatePage(pageBase)) {
                return false;
            }
            return true;
        });
        globalThis.__jitNativeThreadLrTraceExceptionHandlerInstalled = true;
        console.log('[CAPTURE] [JNATLR] installed exception handler');
    }

    function callCertValue(challenge) {
        var token = null;
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
        return token;
    }

    globalThis.__jitNativeThreadLrTraceRun = function (challenge) {
        clearRunState();
        state.active = true;
        state.challenge = challenge;
        state.startedAt = isoNow();
        state.ranges = chooseTraceRanges();

        var range = chooseTrapRange();
        if (!range || !installForRange(range)) {
            state.active = false;
            state.stopReason = 'trap-range-not-found';
            state.endedAt = isoNow();
            return JSON.stringify(buildResult());
        }
        ensureTrapProtection(range);

        try {
            state.token = callCertValue(challenge);
        } catch (e) {
            state.error = String(e);
        } finally {
            state.active = false;
            stopTrace(state.returnHit ? 'returned-to-lr' :
                      (state.workerThreadId !== null ? 'call-complete' :
                       (state.trapStart !== null ? 'trap-hit' : 'trap-not-hit')));
            restoreExecProtection();
            state.endedAt = isoNow();
        }

        return JSON.stringify(buildResult());
    };

    globalThis.__jitNativeThreadLrTraceDump = function () {
        return JSON.stringify(buildResult());
    };

    globalThis.__jitNativeThreadLrTraceClear = function () {
        clearAll();
        return 'OK';
    };
})();
