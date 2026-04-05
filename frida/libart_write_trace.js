// Capture the first execution of the previously observed libart token-record write site.
// This is lighter than MemoryAccessMonitor and records only one raw caller chain.

'use strict';

(function () {
    if (globalThis.__artWriteTrace && globalThis.__artWriteTrace.installed) {
        console.log('[CAPTURE] [ARTWRITE] relay already installed');
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

    function rangeFor(addr) {
        try {
            var r = Process.findRangeByAddress(ptr(addr));
            if (!r) return null;
            return {
                base: r.base.toString(),
                size: r.size,
                protection: r.protection,
                file: filePathFor(r),
            };
        } catch (e) {
            return { error: String(e) };
        }
    }

    function backtrace(context) {
        try {
            return Thread.backtrace(context, Backtracer.FUZZY).slice(0, 8).map(function (addr) {
                return fmt(addr);
            });
        } catch (e) {
            return ['ERR:' + e];
        }
    }

    var libart = Process.getModuleByName('libart.so');
    var target = libart.base.add(0x54a764);
    var state = globalThis.__artWriteTrace = {
        installed: true,
        module: {
            name: libart.name,
            base: libart.base.toString(),
            size: libart.size,
            path: libart.path,
        },
        target: target.toString(),
        count: 0,
        event: null,
        errors: [],
    };

    function noteError(label, error) {
        state.errors.push({ label: label, error: String(error) });
        if (state.errors.length > 16) state.errors.shift();
        console.log('[CAPTURE] [ARTWRITE] ' + label + ': ' + error);
    }

    try {
        var listener = Interceptor.attach(target, {
            onEnter: function () {
                state.count++;
                if (state.event !== null) return;
                state.event = {
                    pc: fmt(this.context.pc),
                    lr: fmt(this.context.lr),
                    x0: fmt(this.context.x0),
                    x1: fmt(this.context.x1),
                    x2: fmt(this.context.x2),
                    x3: fmt(this.context.x3),
                    x4: fmt(this.context.x4),
                    pcRange: rangeFor(this.context.pc),
                    lrRange: rangeFor(this.context.lr),
                    backtrace: backtrace(this.context),
                };
                try { listener.detach(); } catch (e) {}
                console.log('[CAPTURE] [ARTWRITE] hit pc=' + state.event.pc + ' lr=' + state.event.lr);
            }
        });
    } catch (e) {
        noteError('attach ' + target, e);
    }

    globalThis.__artWriteTraceClear = function () {
        state.count = 0;
        state.event = null;
        state.errors.length = 0;
        return 'OK';
    };

    globalThis.__artWriteTraceDump = function () {
        return JSON.stringify({
            module: state.module,
            target: state.target,
            count: state.count,
            event: state.event,
            errors: state.errors,
        });
    };
})();
