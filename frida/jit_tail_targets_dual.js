// Follow the 0x9b61c600 tail path by hooking both resolved second-stage targets.

'use strict';

(function () {
    if (globalThis.__jitTailDual && globalThis.__jitTailDual.installed) {
        console.log('[CAPTURE] [TAILDUAL] relay already installed');
        return;
    }

    var TARGETS = [
        { name: 'stub_796f718000', addr: ptr('0x796f718000') },
        { name: 'body_796f71814c', addr: ptr('0x796f71814c') },
    ];

    var state = globalThis.__jitTailDual = {
        installed: true,
        counts: {},
        seen: {},
    };

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function hexdumpMaybe(value, size) {
        try {
            return hexdump(ptr(value), { length: size, ansi: false });
        } catch (e) {
            return null;
        }
    }

    function looksPtr(value) {
        try {
            var p = ptr(value);
            return !p.equals(ptr('0')) && p.compare(ptr('0x10000')) > 0;
        } catch (e) {
            return false;
        }
    }

    function bump(name, kind) {
        if (!state.counts[name]) state.counts[name] = { enter: 0, leave: 0 };
        state.counts[name][kind] += 1;
        return state.counts[name][kind];
    }

    function shouldLog(name, kind, count, signature) {
        var key = name + ':' + kind + ':' + signature;
        if (kind === 'enter' && !state.seen[key]) {
            state.seen[key] = true;
            return true;
        }
        if (count <= 8) return true;
        return (count % 128) === 0;
    }

    globalThis.__jitTailDualDump = function () {
        return JSON.stringify(state.counts);
    };

    TARGETS.forEach(function (target) {
        console.log('[CAPTURE] [TAILDUAL] attaching ' + target.name + ' @ ' + target.addr);
        Interceptor.attach(target.addr, {
            onEnter: function () {
                var count = bump(target.name, 'enter');
                var sig = [
                    fmt(this.context.x0),
                    fmt(this.context.x1),
                    fmt(this.context.x2),
                    fmt(this.context.x17),
                    fmt(this.context.lr),
                ].join('|');
                this._tailName = target.name;
                this._x0In = fmt(this.context.x0);
                this._x1In = fmt(this.context.x1);
                this._x2In = fmt(this.context.x2);
                if (!shouldLog(target.name, 'enter', count, sig)) return;
                console.log('[CAPTURE] [TAILDUAL] ' + JSON.stringify({
                    kind: 'enter',
                    name: target.name,
                    count: count,
                    addr: target.addr.toString(),
                    pc: fmt(this.context.pc),
                    lr: fmt(this.context.lr),
                    x0: this._x0In,
                    x1: this._x1In,
                    x2: this._x2In,
                    x3: fmt(this.context.x3),
                    x8: fmt(this.context.x8),
                    x17: fmt(this.context.x17),
                    x21: fmt(this.context.x21),
                    x22: fmt(this.context.x22),
                    x0_dump: looksPtr(this.context.x0) ? hexdumpMaybe(this.context.x0, 64) : null,
                    x1_dump: looksPtr(this.context.x1) ? hexdumpMaybe(this.context.x1, 64) : null,
                    x2_dump: looksPtr(this.context.x2) ? hexdumpMaybe(this.context.x2, 64) : null,
                }));
            },
            onLeave: function (retval) {
                var count = bump(target.name, 'leave');
                if (!shouldLog(target.name, 'leave', count, fmt(retval))) return;
                console.log('[CAPTURE] [TAILDUAL] ' + JSON.stringify({
                    kind: 'leave',
                    name: target.name,
                    count: count,
                    addr: target.addr.toString(),
                    retval: fmt(retval),
                    x0_in: this._x0In || null,
                    x1_in: this._x1In || null,
                    x2_in: this._x2In || null,
                    x0_after: fmt(this.context.x0),
                    pc: fmt(this.context.pc),
                    lr: fmt(this.context.lr),
                }));
            }
        });
    });
})();
