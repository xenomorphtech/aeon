'use strict';

(function () {
    var READY_CHALLENGE = '6BA4D60738580083';
    var TRACE_CHALLENGES = ['1122334455667788', 'A1B2C3D4E5F60718'];

    function delay(ms) {
        return new Promise(function (resolve) { setTimeout(resolve, ms); });
    }

    function isGoodToken(token) {
        return typeof token === 'string' && /^[0-9A-Fa-f]{32,}$/.test(token);
    }

    function parseJsonMaybe(value) {
        if (typeof value !== 'string') return value;
        try {
            return JSON.parse(value);
        } catch (_) {
            return value;
        }
    }

    function topThreadsFromDump(dump, limit) {
        var out = [];
        var top = dump && Array.isArray(dump.topThreads) ? dump.topThreads : [];
        for (var i = 0; i < top.length && out.length < limit; i++) {
            var tid = parseInt(top[i].thread, 10);
            if (!(tid > 0)) continue;
            if (out.indexOf(tid) !== -1) continue;
            out.push(tid);
        }
        return out;
    }

    function sortHitList(map, keep) {
        return Object.keys(map || {})
            .map(function (key) {
                return { pc: key, hits: map[key] };
            })
            .sort(function (a, b) { return b.hits - a.hits; })
            .slice(0, keep || 24);
    }

    function runFixedTrace(challenge, threads) {
        globalThis.__jitGateFixedThreadTraceClear();
        if (threads && threads.length > 0) {
            globalThis.__jitGateFixedThreadTraceArm(JSON.stringify(threads));
        } else {
            globalThis.__jitGateFixedThreadTraceArm();
        }
        var token = rpc.exports.callCert(challenge);
        var state = parseJsonMaybe(globalThis.__jitGateFixedThreadTraceStatus());
        var trace = state && state.trace ? state.trace : null;
        return {
            challenge: challenge,
            token: token,
            trace: trace,
        };
    }

    function diffTraceMaps(pc1, pc2) {
        var only1 = [];
        var only2 = [];
        var changed = [];
        var seen = {};

        Object.keys(pc1).forEach(function (pc) {
            seen[pc] = true;
            if (!(pc in pc2)) {
                only1.push({ pc: pc, hits: pc1[pc] });
                return;
            }
            if (pc1[pc] !== pc2[pc]) {
                changed.push({
                    pc: pc,
                    c1: pc1[pc],
                    c2: pc2[pc],
                    delta: pc2[pc] - pc1[pc],
                    abs_delta: Math.abs(pc2[pc] - pc1[pc]),
                });
            }
        });

        Object.keys(pc2).forEach(function (pc) {
            if (seen[pc]) return;
            only2.push({ pc: pc, hits: pc2[pc] });
        });

        only1.sort(function (a, b) { return b.hits - a.hits; });
        only2.sort(function (a, b) { return b.hits - a.hits; });
        changed.sort(function (a, b) { return b.abs_delta - a.abs_delta; });

        return {
            only1: only1.slice(0, 40),
            only2: only2.slice(0, 40),
            changed: changed.slice(0, 80),
        };
    }

    async function main() {
        var ready = null;
        if (isGoodToken(globalThis.__jitDirectReadyToken)) {
            ready = String(globalThis.__jitDirectReadyToken);
            send({ type: 'ready', attempt: 0, token: ready, reused: true });
        } else {
            for (var attempt = 1; attempt <= 8; attempt++) {
                var token = rpc.exports.callCert(READY_CHALLENGE);
                send({ type: 'ready', attempt: attempt, token: token, reused: false });
                if (isGoodToken(token)) {
                    ready = token;
                    break;
                }
                await delay(5000);
            }
        }

        if (!ready) {
            send({ type: 'final', ok: false, stage: 'ready', error: 'cert not ready' });
            return;
        }

        var warm = rpc.exports.callCert(READY_CHALLENGE);
        send({ type: 'warm', token: warm });

        var dump = parseJsonMaybe(globalThis.__jitGateTraceDump());
        var threads = topThreadsFromDump(dump, 3);
        send({
            type: 'hot',
            topThreads: dump && dump.topThreads ? dump.topThreads.slice(0, 8) : [],
            topPages: dump && dump.topPages ? dump.topPages.slice(0, 8) : [],
            threads: threads,
        });

        var traces = [];
        for (var i = 0; i < TRACE_CHALLENGES.length; i++) {
            var challenge = TRACE_CHALLENGES[i];
            var result = runFixedTrace(challenge, threads);
            var trace = result.trace || {};
            send({
                type: 'trace',
                challenge: challenge,
                token: result.token,
                followed: trace.followed || [],
                blockCount: trace.blockCount || 0,
                pcCount: trace.pcHits ? Object.keys(trace.pcHits).length : 0,
                top: sortHitList(trace.pcHits || {}, 24),
                error: trace.error || null,
            });
            if ((trace.blockCount || 0) === 0) {
                var refreshDump = parseJsonMaybe(globalThis.__jitGateTraceDump());
                var refreshed = topThreadsFromDump(refreshDump, 3);
                send({ type: 'refresh_threads', old: threads, refreshed: refreshed });
                if (refreshed.length > 0) {
                    threads = refreshed;
                    result = runFixedTrace(challenge, threads);
                    trace = result.trace || {};
                    send({
                        type: 'trace_retry',
                        challenge: challenge,
                        token: result.token,
                        followed: trace.followed || [],
                        blockCount: trace.blockCount || 0,
                        pcCount: trace.pcHits ? Object.keys(trace.pcHits).length : 0,
                        top: sortHitList(trace.pcHits || {}, 24),
                        error: trace.error || null,
                    });
                }
            }
            traces.push(result.trace || {});
        }

        var pc1 = traces[0] && traces[0].pcHits ? traces[0].pcHits : {};
        var pc2 = traces[1] && traces[1].pcHits ? traces[1].pcHits : {};
        var diff = diffTraceMaps(pc1, pc2);

        send({
            type: 'final',
            ok: true,
            readyToken: ready,
            trace1: {
                challenge: TRACE_CHALLENGES[0],
                blockCount: traces[0].blockCount || 0,
                pcCount: Object.keys(pc1).length,
            },
            trace2: {
                challenge: TRACE_CHALLENGES[1],
                blockCount: traces[1].blockCount || 0,
                pcCount: Object.keys(pc2).length,
            },
            diff: diff,
        });
    }

    setImmediate(function () {
        main().catch(function (e) {
            send({
                type: 'final',
                ok: false,
                stage: 'exception',
                error: String(e),
                stack: e && e.stack ? String(e.stack) : null,
            });
        });
    });
})();
