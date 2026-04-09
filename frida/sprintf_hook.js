'use strict';

(function () {
    if (globalThis.__sprintfHookInstalled) {
        console.log('[SPRINTF] already installed');
        return;
    }
    globalThis.__sprintfHookInstalled = true;

    var libc = Process.getModuleByName('libc.so');
    var _open = new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int', 'int']);
    var _write = new NativeFunction(libc.getExportByName('write'), 'long', ['int', 'pointer', 'long']);
    var _close = new NativeFunction(libc.getExportByName('close'), 'int', ['int']);

    var LOG_PATH = '/data/local/tmp/aeon_capture/sprintf_log.txt';
    var logFd = -1;
    var logCount = 0;
    var armed = false;

    function openLog() {
        // mkdir -p
        var _mkdir = new NativeFunction(libc.getExportByName('mkdir'), 'int', ['pointer', 'int']);
        _mkdir(Memory.allocUtf8String('/data/local/tmp/aeon_capture'), 0x1ff);
        // truncate and open
        logFd = _open(Memory.allocUtf8String(LOG_PATH), 0x241, 0x1a4); // O_WRONLY|O_CREAT|O_TRUNC
        return logFd >= 0;
    }

    function logLine(s) {
        if (logFd < 0) return;
        var line = s + '\n';
        var buf = Memory.allocUtf8String(line);
        _write(logFd, buf, line.length);
        logCount++;
    }

    function closeLog() {
        if (logFd >= 0) {
            _close(logFd);
            logFd = -1;
        }
    }

    var PTR_MASK = ptr('0x00FFFFFFFFFFFFFF');

    function safeReadCString(p, maxLen) {
        var limit = maxLen || 128;
        try {
            if (p.isNull()) return '<null>';
            var clean = p.and(PTR_MASK);
            var s = clean.readCString(limit);
            if (s === null) return '<null>';
            if (s.length > limit) s = s.substring(0, limit);
            return s;
        } catch (e) {
            return '<unreadable@' + p + '>';
        }
    }

    function fmtCaller(lr) {
        try {
            var mod = Process.findModuleByAddress(lr);
            if (mod) {
                return mod.name + '+0x' + lr.sub(mod.base).toString(16);
            }
        } catch (e) {}
        return lr.toString();
    }

    // Hook targets: all sprintf-family functions in libc
    var targets = [
        'sprintf', 'snprintf', 'vsprintf', 'vsnprintf',
        '__sprintf_chk', '__snprintf_chk', '__vsprintf_chk', '__vsnprintf_chk',
        'swprintf', 'asprintf', 'vasprintf',
    ];

    var hooks = [];

    targets.forEach(function (name) {
        var addr;
        try {
            addr = libc.getExportByName(name);
        } catch (e) {
            return; // not exported
        }
        if (!addr) return;

        var isN = name.indexOf('snprintf') >= 0; // has size arg
        var isChk = name.indexOf('_chk') >= 0;
        var isV = name.indexOf('vs') >= 0 || name.indexOf('va') >= 0;

        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    if (!armed) return;
                    this._name = name;
                    this._dst = args[0];
                    // For snprintf: dst, size, fmt, ...
                    // For sprintf:  dst, fmt, ...
                    // For __snprintf_chk: dst, maxlen, flag, slen, fmt, ...
                    // For __sprintf_chk:  dst, flag, slen, fmt, ...
                    if (isChk && isN) {
                        this._fmt = safeReadCString(args[4]);
                    } else if (isChk) {
                        this._fmt = safeReadCString(args[3]);
                    } else if (isN) {
                        this._fmt = safeReadCString(args[2]);
                    } else {
                        this._fmt = safeReadCString(args[1]);
                    }
                    this._caller = fmtCaller(this.context.lr);
                    this._tid = this.threadId;
                },
                onLeave: function (retval) {
                    if (!armed || !this._name) return;
                    var nchars = retval.toInt32();
                    var readLen = nchars > 0 ? Math.min(nchars + 1, 256) : 64;
                    var result = safeReadCString(this._dst, readLen);
                    logLine(this._tid + '\t' + this._name + '\t' + this._caller +
                            '\tfmt=' + this._fmt +
                            '\tresult=' + result +
                            '\tret=' + nchars);
                }
            });
            hooks.push(name);
        } catch (e) {
            console.log('[SPRINTF] hook fail ' + name + ': ' + e);
        }
    });

    console.log('[SPRINTF] hooked: ' + hooks.join(', '));

    globalThis.__sprintfArm = function () {
        openLog();
        logCount = 0;
        armed = true;
        logLine('# armed at ' + new Date().toISOString() + ' pid=' + Process.id);
        console.log('[SPRINTF] ARMED');
        return 'ARMED';
    };

    globalThis.__sprintfDisarm = function () {
        armed = false;
        logLine('# disarmed at ' + new Date().toISOString() + ' count=' + logCount);
        closeLog();
        console.log('[SPRINTF] DISARMED count=' + logCount);
        return JSON.stringify({ count: logCount, path: LOG_PATH });
    };

    globalThis.__sprintfStatus = function () {
        return JSON.stringify({ armed: armed, count: logCount, path: LOG_PATH, hooks: hooks });
    };
})();
