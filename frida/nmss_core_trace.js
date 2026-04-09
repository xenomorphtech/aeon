'use strict';

(function () {
    if (globalThis.__nmssCoreTraceInstalled) {
        console.log('[CAPTURE] [NMSS] core trace already installed');
        return;
    }
    globalThis.__nmssCoreTraceInstalled = true;

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function currentThreadIdMaybe() {
        try { return Process.getCurrentThreadId(); } catch (e) { return null; }
    }

    function threadNameMaybe(threadId) {
        try {
            var threads = Process.enumerateThreads();
            for (var i = 0; i < threads.length; i++) {
                if (threads[i].id === threadId) return threads[i].name || null;
            }
        } catch (e) {}
        return null;
    }

    function backtraceStrings(context, limit) {
        try {
            return Thread.backtrace(context, Backtracer.ACCURATE)
                .slice(0, limit || 8)
                .map(function (addr) {
                    try {
                        return DebugSymbol.fromAddress(addr).toString();
                    } catch (e) {
                        return ptr(addr).toString();
                    }
                });
        } catch (e) {
            return ['<bt-error:' + String(e) + '>'];
        }
    }

    function install() {
        var mod = Process.findModuleByName('libnmsssa.so');
        if (!mod) {
            console.log('[CAPTURE] [NMSS] libnmsssa.so not found');
            return false;
        }

        var CORE_BODY = mod.base.add(0x123288);
        var HELPER_A = mod.base.add(0x128eb4);

        Interceptor.attach(CORE_BODY, {
            onEnter: function (args) {
                var tid = currentThreadIdMaybe();
                console.log('[CAPTURE] [NMSS] core_body enter tid=' + tid +
                    ' name=' + (threadNameMaybe(tid) || '<unknown>') +
                    ' pc=' + fmtPtr(this.context.pc) +
                    ' lr=' + fmtPtr(this.context.lr) +
                    ' x0=' + fmtPtr(args[0]) +
                    ' x1=' + fmtPtr(args[1]) +
                    ' x2=' + fmtPtr(args[2]) +
                    ' bt=' + JSON.stringify(backtraceStrings(this.context, 8)));
            },
            onLeave: function (retval) {
                console.log('[CAPTURE] [NMSS] core_body leave tid=' + currentThreadIdMaybe() +
                    ' ret=' + fmtPtr(retval));
            }
        });

        Interceptor.attach(HELPER_A, {
            onEnter: function (args) {
                var tid = currentThreadIdMaybe();
                console.log('[CAPTURE] [NMSS] helper_128eb4 enter tid=' + tid +
                    ' name=' + (threadNameMaybe(tid) || '<unknown>') +
                    ' pc=' + fmtPtr(this.context.pc) +
                    ' lr=' + fmtPtr(this.context.lr) +
                    ' x0=' + fmtPtr(args[0]) +
                    ' x1=' + fmtPtr(args[1]) +
                    ' x2=' + fmtPtr(args[2]) +
                    ' bt=' + JSON.stringify(backtraceStrings(this.context, 8)));
            },
            onLeave: function (retval) {
                console.log('[CAPTURE] [NMSS] helper_128eb4 leave tid=' + currentThreadIdMaybe() +
                    ' ret=' + fmtPtr(retval));
            }
        });

        console.log('[CAPTURE] [NMSS] hooks installed base=' + fmtPtr(mod.base));
        return true;
    }

    try {
        Java.performNow(install);
    } catch (e) {
        console.log('[CAPTURE] [NMSS] install error: ' + e);
    }
})();
