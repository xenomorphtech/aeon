'use strict';

(function () {
    var READY_CHALLENGE = '6BA4D60738580083';
    var TARGET_CHALLENGE = READY_CHALLENGE;
    var DEVICE_BOOTSTRAP_JS = '/data/local/tmp/jit_direct_bootstrap.js';
    var DEVICE_GATE_JS = '/data/local/tmp/jit_trace_gate.js';
    var DEVICE_TRANSLATED_ELF = '/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.elf';
    var DEVICE_TRANSLATED_MAP = '/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.map.json.compact.blockmap.jsonl';
    var MAX_STEPS = 200000;
    var MAX_EVENTS = 1024;

    function readTextFile(path) {
        var libc = Process.getModuleByName('libc.so');
        var openFn = new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int', 'int']);
        var readFn = new NativeFunction(libc.getExportByName('read'), 'int', ['int', 'pointer', 'int']);
        var closeFn = new NativeFunction(libc.getExportByName('close'), 'int', ['int']);
        var fd = openFn(Memory.allocUtf8String(path), 0, 0);
        if (fd < 0) return null;
        var chunkSize = 0x4000;
        var chunks = [];
        try {
            while (true) {
                var buf = Memory.alloc(chunkSize);
                var n = readFn(fd, buf, chunkSize);
                if (n <= 0) break;
                chunks.push(buf.readUtf8String(n) || '');
                if (n < chunkSize) break;
            }
        } finally {
            closeFn(fd);
        }
        return chunks.join('');
    }

    function loadOne(path) {
        var source = readTextFile(path);
        if (source === null) {
            throw new Error('failed to read agent source: ' + path);
        }
        (0, eval)(source);
    }

    function parseJsonMaybe(value) {
        if (typeof value !== 'string') return value;
        try {
            return JSON.parse(value);
        } catch (e) {
            return value;
        }
    }

    function unwrapPrepareResult(result) {
        var parsed = parseJsonMaybe(result);
        if (!parsed || typeof parsed !== 'object') return parsed;
        if (Object.prototype.hasOwnProperty.call(parsed, 'value') &&
            parsed.value && typeof parsed.value === 'object') {
            return parsed.value;
        }
        return parsed;
    }

    function emit(obj) {
        try {
            console.log(JSON.stringify(obj));
        } catch (e) {
            console.log(String(obj));
        }
        try {
            send(obj);
        } catch (e) {}
    }

    function sendStage(stage, extra) {
        var out = { type: 'stage', stage: stage };
        if (extra) {
            Object.keys(extra).forEach(function (key) {
                out[key] = extra[key];
            });
        }
        emit(out);
    }

    function main() {
        sendStage('load_bootstrap');
        loadOne(DEVICE_BOOTSTRAP_JS);
        sendStage('load_gate');
        loadOne(DEVICE_GATE_JS);

        sendStage('preflight');
        var preflightRaw = globalThis.__jitGatePrepareNmss(READY_CHALLENGE, READY_CHALLENGE);
        var preflight = unwrapPrepareResult(preflightRaw);
        emit({ type: 'preflight', raw: preflightRaw, data: preflight });
        if (!preflight || !preflight.ok || !preflight.token) {
            emit({
                type: 'final',
                ok: false,
                stage: 'preflight',
                preflight_raw: preflightRaw,
                preflight: preflight,
            });
            return;
        }

        sendStage('translated_arm');
        var arm = parseJsonMaybe(
            globalThis.__jitGateTranslatedArm(
                DEVICE_TRANSLATED_ELF,
                DEVICE_TRANSLATED_MAP,
                null,
                MAX_STEPS
            )
        );
        emit({ type: 'arm', data: arm });

        var traceThreadId = null;
        try {
            var maybeTid = preflight.thread_id;
            if (maybeTid !== null && maybeTid !== undefined) {
                var parsedTid = parseInt(maybeTid, 10);
                if (parsedTid > 0) traceThreadId = parsedTid;
            }
        } catch (e) {}

        sendStage('scope_begin', { thread_id: traceThreadId });
        var scopeBegin = parseJsonMaybe(
            globalThis.__jitGateTranslatedScopeBegin(TARGET_CHALLENGE, traceThreadId)
        );
        emit({ type: 'scope_begin', data: scopeBegin });

        sendStage('traced_call');
        var tracedCallRaw = globalThis.__jitGatePrepareNmss(TARGET_CHALLENGE, READY_CHALLENGE);
        var tracedCall = unwrapPrepareResult(tracedCallRaw);
        emit({ type: 'traced_call', raw: tracedCallRaw, data: tracedCall });

        sendStage('scope_end');
        var scopeEnd = parseJsonMaybe(globalThis.__jitGateTranslatedScopeEnd());
        emit({ type: 'scope_end', data: scopeEnd });

        sendStage('trace_dump');
        var traceDump = parseJsonMaybe(
            globalThis.__jitGateTranslatedTraceDump(0, MAX_EVENTS, true)
        );

        sendStage('translated_status');
        var translatedStatus = parseJsonMaybe(globalThis.__jitGateTranslatedStatus());

        emit({
            type: 'final',
            ok: true,
            preflight: preflight,
            arm: arm,
            scope_begin: scopeBegin,
            traced_call_raw: tracedCallRaw,
            traced_call: tracedCall,
            scope_end: scopeEnd,
            trace_dump: traceDump,
            translated_status: translatedStatus,
        });
    }

    setImmediate(function () {
        try {
            main();
        } catch (e) {
            emit({
                type: 'fatal',
                error: String(e),
                stack: e && e.stack ? String(e.stack) : null,
            });
        }
    });
})();
