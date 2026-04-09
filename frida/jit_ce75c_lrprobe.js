'use strict';

(function () {
    if (globalThis.__jitCe75cLrProbe && globalThis.__jitCe75cLrProbe.installed) {
        console.log('[CAPTURE] [CE75C-LR] relay already installed');
        return;
    }

    var DEFAULT_CHALLENGE = 'AABBCCDDEEFF0011';
    var READY_CHALLENGE = '6BA4D60738580083';
    var DEFAULT_TARGET_OFFSET = 0xce75c;
    var PTR_MASK = ptr('0x00FFFFFFFFFFFFFF');
    var STACK_RESULT_OFFSET = 0x9c0;
    var STACK_AUX_OFFSET = 0x60;
    var SSO_SIZE = 24;
    var SAMPLE_LIMIT = 96;
    var MAX_EVENTS = 128;
    var KNOWN_RESUME_OFFSETS = [
        0x155c70,
        0x1565b0,
        0x1c3378,
    ];

    var state = globalThis.__jitCe75cLrProbe = {
        installed: true,
        armed: false,
        warmed: false,
        warmChallenge: READY_CHALLENGE,
        targetOffset: DEFAULT_TARGET_OFFSET,
        challenge: null,
        currentBase: null,
        target: null,
        targetFile: null,
        returnProbe: null,
        hookInstalled: false,
        returnHookInstalled: false,
        nativeHandoffHookInstalled: false,
        hooks: {},
        resumeHooks: {},
        callStacks: {},
        seq: 0,
        drops: 0,
        events: [],
        failures: [],
        finalToken: null,
        lastSummary: null,
    };

    function fmt(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function untagPtr(value) {
        try {
            return ptr(value).and(PTR_MASK);
        } catch (e) {
            return ptr('0');
        }
    }

    function candidatePtrs(value) {
        var out = [];
        try {
            var original = ptr(value);
            out.push(original);
            var untagged = untagPtr(original);
            if (!samePtr(original, untagged)) {
                out.push(untagged);
            }
        } catch (e) {}
        return out;
    }

    function pushEvent(event) {
        if (state.events.length >= MAX_EVENTS) {
            state.events.shift();
            state.drops++;
        }
        state.events.push(event);
    }

    function noteFailure(where, error) {
        var entry = { where: where, error: String(error) };
        state.failures.push(entry);
        if (state.failures.length > 32) state.failures.shift();
        console.log('[CAPTURE] [CE75C-LR] ' + where + ' failed: ' + error);
    }

    function clearThreadState() {
        state.callStacks = {};
    }

    function resetRunState() {
        state.armed = false;
        state.challenge = null;
        state.finalToken = null;
        state.lastSummary = null;
        state.seq = 0;
        state.drops = 0;
        state.events.length = 0;
        state.failures.length = 0;
        clearThreadState();
    }

    function enumerateExecRanges() {
        var prots = ['r-x', '--x'];
        var out = [];
        var seen = {};
        prots.forEach(function (prot) {
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
                noteFailure('enumerate ' + prot, e);
            }
        });
        return out;
    }

    function instructionTextAt(addr) {
        try {
            return Instruction.parse(ptr(addr)).toString();
        } catch (e) {
            return null;
        }
    }

    function matchesTargetSignature(base) {
        try {
            var target = ptr(base).add(state.targetOffset);
            var ins0 = instructionTextAt(target);
            var ins1 = instructionTextAt(target.add(4));
            var ins2 = instructionTextAt(target.add(8));
            var ins3 = instructionTextAt(target.add(12));
            return ins0 === 'sub sp, sp, #0xa0' &&
                   ins1 === 'stp x28, x27, [sp, #0x40]' &&
                   ins2 === 'stp x26, x25, [sp, #0x50]' &&
                   ins3 === 'stp x24, x23, [sp, #0x60]';
        } catch (e) {
            return false;
        }
    }

    function targetRanges() {
        var grouped = {};
        enumerateExecRanges().forEach(function (range) {
            if (!range || !range.base) return;
            var path = range && range.file && range.file.path ? String(range.file.path) : '';
            if (!path) return;
            if (path.indexOf('(deleted)') < 0) return;
            if (path.indexOf('/data/data/com.netmarble.thered/files/') < 0) return;
            if (!grouped[path]) grouped[path] = [];
            grouped[path].push(range);
        });

        return Object.keys(grouped).map(function (path) {
            var ranges = grouped[path];
            ranges.sort(function (a, b) {
                return a.base.compare(b.base);
            });
            var base = ranges[0].base;
            var end = ranges[0].base.add(ranges[0].size);
            ranges.forEach(function (range) {
                var rangeEnd = range.base.add(range.size);
                if (rangeEnd.compare(end) > 0) end = rangeEnd;
            });
            return {
                base: base,
                size: Number(end.sub(base)),
                path: path,
            };
        }).filter(function (group) {
            if (!group || !group.base || group.size <= state.targetOffset + 4) return false;
            return matchesTargetSignature(group.base);
        });
    }

    function samePtr(left, right) {
        try {
            return ptr(left).equals(ptr(right));
        } catch (e) {
            return false;
        }
    }

    function offsetHex(base, value) {
        try {
            var basePtr = ptr(base);
            var valuePtr = ptr(value);
            if (valuePtr.compare(basePtr) < 0) return null;
            return '0x' + valuePtr.sub(basePtr).toString(16);
        } catch (e) {
            return null;
        }
    }

    function popMatchingFrame(tid, expectedLr) {
        var stack = state.callStacks[tid];
        if (!stack || stack.length === 0) return null;
        for (var i = stack.length - 1; i >= 0; i--) {
            if (samePtr(stack[i].origLr, expectedLr)) {
                return stack.splice(i, 1)[0];
            }
        }
        return null;
    }

    function peekFrame(tid) {
        var stack = state.callStacks[tid];
        if (!stack || stack.length === 0) return null;
        return stack[stack.length - 1];
    }

    function readByteArrayMaybe(addr, size) {
        var candidates = candidatePtrs(addr);
        for (var i = 0; i < candidates.length; i++) {
            var p = candidates[i];
            if (p.isNull()) continue;
            try {
                if (typeof p.readVolatile === 'function') {
                    return p.readVolatile(size);
                }
            } catch (e) {}
            try {
                return Memory.readByteArray(p, size);
            } catch (e) {}
        }
        return null;
    }

    function bytesToHex(bytes) {
        if (bytes === null) return null;
        try {
            var view = new Uint8Array(bytes);
            var out = [];
            for (var i = 0; i < view.length; i++) {
                var h = view[i].toString(16);
                out.push(h.length === 1 ? '0' + h : h);
            }
            return out.join('');
        } catch (e) {
            return null;
        }
    }

    function asciiMaybe(bytes) {
        if (bytes === null) return null;
        try {
            var view = new Uint8Array(bytes);
            var chars = [];
            for (var i = 0; i < view.length; i++) {
                if (view[i] === 0) break;
                chars.push(String.fromCharCode(view[i]));
            }
            return chars.join('');
        } catch (e) {
            return null;
        }
    }

    function looksHexAscii(text) {
        return !!(text && /^[0-9A-Fa-f]+$/.test(text));
    }

    function rawAsciiHexSlot(raw) {
        var text = asciiMaybe(raw);
        if (!looksHexAscii(text)) return null;
        return {
            kind: 'inline_hex',
            len: text.length,
            text: text,
            hex_ascii: true,
        };
    }

    function readRawSlot(addr) {
        var base = untagPtr(addr);
        var data = readByteArrayMaybe(base, SSO_SIZE);
        return {
            addr: fmt(base),
            raw_hex: bytesToHex(data),
        };
    }

    function readSsoSlot(addr) {
        var base = untagPtr(addr);
        var raw = readByteArrayMaybe(base, SSO_SIZE);
        if (raw === null) {
            return {
                addr: base.toString(),
                error: 'unreadable',
            };
        }

        var view = new Uint8Array(raw);
        var out = {
            addr: base.toString(),
            raw_hex: bytesToHex(raw),
        };

        var inlineHex = rawAsciiHexSlot(raw);
        if (inlineHex !== null) {
            out.kind = inlineHex.kind;
            out.len = inlineHex.len;
            out.text = inlineHex.text;
            out.hex_ascii = inlineHex.hex_ascii;
            out.data_hex = out.raw_hex;
            return out;
        }

        var tag = view[0];
        try {
            if ((tag & 1) === 0) {
                var shortLen = tag >>> 1;
                var shortBytes = view.slice(1, 1 + Math.min(shortLen, 22));
                var shortHex = [];
                for (var i = 0; i < shortBytes.length; i++) {
                    var h = shortBytes[i].toString(16);
                    shortHex.push(h.length === 1 ? '0' + h : h);
                }
                var shortText = '';
                for (var j = 0; j < shortBytes.length; j++) {
                    shortText += String.fromCharCode(shortBytes[j]);
                }
                out.kind = 'short';
                out.len = shortLen;
                out.data_hex = shortHex.join('');
                out.text = shortText.replace(/\u0000+$/, '');
                out.hex_ascii = looksHexAscii(out.text);
                return out;
            }

            var sizeValue = Memory.readU64(base.add(8));
            var size = typeof sizeValue === 'number' ? sizeValue :
                (sizeValue && typeof sizeValue.toNumber === 'function' ? sizeValue.toNumber() : parseInt(String(sizeValue), 10));
            var dataPtr = untagPtr(Memory.readPointer(base.add(16)));
            out.kind = 'long';
            out.len = size;
            out.ptr = dataPtr.toString();
            if (size > 0 && size <= 0x1000 && !dataPtr.isNull()) {
                var sampleSize = Math.min(size, SAMPLE_LIMIT);
                var sample = readByteArrayMaybe(dataPtr, sampleSize);
                out.data_hex = bytesToHex(sample);
                var text = asciiMaybe(sample);
                out.text = text;
                out.hex_ascii = looksHexAscii(text);
            }
            return out;
        } catch (e) {
            out.error = String(e);
            return out;
        }
    }

    function compareText(left, right) {
        if (!left || !right) {
            return {
                exact: false,
                prefix: false,
                substring: false,
            };
        }
        return {
            exact: left === right,
            prefix: right.indexOf(left) === 0,
            substring: right.indexOf(left) >= 0,
            left_len: left.length,
            right_len: right.length,
            };
    }

    function captureResumeEvent(kind, frame, context) {
        var sp = ptr(context.sp);
        var x19 = untagPtr(context.x19);
        var x20 = untagPtr(context.x20);
        var x22 = untagPtr(context.x22);
        return {
            seq: ++state.seq,
            kind: kind,
            tid: Process.getCurrentThreadId(),
            challenge: state.challenge,
            selector: frame.selector,
            entry_target: frame.target.toString(),
            entry_target_offset: frame.targetOffset,
            entry_lr: frame.origLr.toString(),
            entry_lr_offset: frame.origLrOffset,
            pc: fmt(context.pc),
            pc_offset: frame.origLrOffset,
            lr: fmt(context.lr),
            sp: sp.toString(),
            x0: fmt(context.x0),
            x1: fmt(context.x1),
            x2: fmt(context.x2),
            x19: x19.toString(),
            x20: x20.toString(),
            x22: x22.toString(),
            entry_x19: frame.entryX19.toString(),
            entry_x20: frame.entryX20.toString(),
            entry_x22: frame.entryX22.toString(),
            sp_plus_0x60: readRawSlot(sp.add(STACK_AUX_OFFSET)),
            sp_plus_0x9c0: readSsoSlot(sp.add(STACK_RESULT_OFFSET)),
            x19_slot: readSsoSlot(x19),
            x19_plus_0x68: readSsoSlot(x19.add(0x68)),
            x20_slot: readSsoSlot(x20),
            x20_plus_0x68: readSsoSlot(x20.add(0x68)),
            x22_slot: readSsoSlot(x22),
            x22_plus_0x68: readSsoSlot(x22.add(0x68)),
            entry_x19_slot: readSsoSlot(frame.entryX19),
            entry_x19_plus_0x68: readSsoSlot(frame.entryX19.add(0x68)),
            entry_x20_slot: readSsoSlot(frame.entryX20),
            entry_x20_plus_0x68: readSsoSlot(frame.entryX20.add(0x68)),
            entry_x22_slot: readSsoSlot(frame.entryX22),
            entry_x22_plus_0x68: readSsoSlot(frame.entryX22.add(0x68)),
        };
    }

    function ensureResumeHook(addr, filePath, basePtr) {
        var resumePc = ptr(addr);
        var hookKey = resumePc.toString();
        if (state.resumeHooks[hookKey]) return;
        try {
            Interceptor.attach(resumePc, {
                onEnter: function () {
                    var tid = Process.getCurrentThreadId();
                    var frame = popMatchingFrame(tid, resumePc);
                    if (!frame) return;
                    if (!state.armed) return;
                    pushEvent(captureResumeEvent('resume', frame, this.context));
                }
            });
            state.resumeHooks[hookKey] = {
                pc: hookKey,
                offset: offsetHex(basePtr, resumePc),
                file: filePath,
            };
            console.log('[CAPTURE] [CE75C-LR] hooked resume @ ' + resumePc +
                        ' offset=' + (offsetHex(basePtr, resumePc) || '[external]') +
                        ' file=' + filePath);
        } catch (e) {
            noteFailure('attach resume @ ' + resumePc, e);
        }
    }

    function ensureReturnProbe() {
        if (state.returnProbe !== null) return;
        try {
            var code = Memory.alloc(Process.pageSize);
            Memory.protect(code, Process.pageSize, 'rwx');
            var writer = new Arm64Writer(code);
            writer.putRet();
            writer.flush();
            state.returnProbe = code;
        } catch (e) {
            noteFailure('allocate return probe', e);
            return;
        }

        try {
            Interceptor.attach(state.returnProbe, {
                onEnter: function () {
                    var tid = Process.getCurrentThreadId();
                    var frame = peekFrame(tid);
                    if (!frame) {
                        noteFailure('return probe', 'empty stack for tid=' + tid);
                        return;
                    }

                    if (state.armed) {
                        pushEvent(captureResumeEvent('lr_return', frame, this.context));
                    }

                    this.context.pc = frame.origLr;
                    this.context.lr = frame.origLr;
                }
            });
            state.returnHookInstalled = true;
        } catch (e) {
            noteFailure('attach return probe', e);
        }
    }

    function installAt(base, size, filePath) {
        ensureReturnProbe();
        var basePtr = ptr(base);
        var target = basePtr.add(state.targetOffset);
        var hookKey = target.toString();
        if (state.hooks[hookKey]) return;

        try {
            Interceptor.attach(target, {
                onEnter: function () {
                    var tid = Process.getCurrentThreadId();
                    var stack = state.callStacks[tid];
                    if (!stack) {
                        stack = [];
                        state.callStacks[tid] = stack;
                    }

                    var selector = 0;
                    try { selector = Number(ptr(this.context.x0)) >>> 0; } catch (e) {}

                    var frame = {
                        origLr: ptr(this.context.lr),
                        origLrOffset: offsetHex(basePtr, this.context.lr),
                        selector: selector,
                        entryX19: untagPtr(this.context.x19),
                        entryX20: untagPtr(this.context.x20),
                        entryX22: ptr(this.context.x22),
                        target: target,
                        targetOffset: '0x' + state.targetOffset.toString(16),
                    };
                    stack.push(frame);
                    ensureResumeHook(frame.origLr, filePath, basePtr);

                    if (state.armed) {
                        pushEvent({
                            seq: ++state.seq,
                            kind: 'enter',
                            tid: tid,
                            challenge: state.challenge,
                            selector: selector,
                            target: target.toString(),
                            target_offset: '0x' + state.targetOffset.toString(16),
                            file: filePath,
                            pc: fmt(this.context.pc),
                            orig_lr: frame.origLr.toString(),
                            orig_lr_offset: frame.origLrOffset,
                            new_lr: state.returnProbe ? state.returnProbe.toString() : null,
                            sp: fmt(this.context.sp),
                            x0: fmt(this.context.x0),
                            x1: fmt(this.context.x1),
                            x2: fmt(this.context.x2),
                            x19: fmt(this.context.x19),
                            x20: fmt(this.context.x20),
                            x22: fmt(this.context.x22),
                            x25: fmt(this.context.x25),
                            sp_plus_0x60: readRawSlot(ptr(this.context.sp).add(STACK_AUX_OFFSET)),
                            sp_plus_0x9c0: readSsoSlot(ptr(this.context.sp).add(STACK_RESULT_OFFSET)),
                            x19_slot: readSsoSlot(this.context.x19),
                            x22_slot: readSsoSlot(this.context.x22),
                        });
                    }

                    if (state.returnProbe !== null) {
                        this.context.lr = state.returnProbe;
                    }
                }
            });
            state.hooks[hookKey] = {
                base: basePtr.toString(),
                target: target.toString(),
                size: size,
                file: filePath,
            };
            state.currentBase = basePtr;
            state.target = target;
            state.targetFile = filePath;
            state.hookInstalled = true;
            KNOWN_RESUME_OFFSETS.forEach(function (off) {
                ensureResumeHook(basePtr.add(off), filePath, basePtr);
            });
            console.log('[CAPTURE] [CE75C-LR] hooked target @ ' + target +
                        ' offset=0x' + state.targetOffset.toString(16) +
                        ' base=' + basePtr +
                        ' file=' + filePath);
        } catch (e) {
            noteFailure('attach target @ ' + target, e);
        }
    }

    function installAcrossRanges() {
        var ranges = targetRanges();
        ranges.forEach(function (range) {
            installAt(range.base, range.size, range.path || '[anon]');
        });
    }

    function ensureNativeHandoffHook() {
        if (state.nativeHandoffHookInstalled) return;
        if (typeof nmsscr_base === 'undefined' || nmsscr_base === null || typeof BLR_X8_OFFSET === 'undefined') {
            return;
        }
        try {
            var handoff = nmsscr_base.add(BLR_X8_OFFSET);
            Interceptor.attach(handoff, {
                onEnter: function () {
                    installAcrossRanges();
                }
            });
            state.nativeHandoffHookInstalled = true;
            console.log('[CAPTURE] [CE75C-LR] hooked native handoff @ ' + handoff);
        } catch (e) {
            noteFailure('attach native handoff', e);
        }
    }

    function ensureInstalled() {
        ensureReturnProbe();
        ensureNativeHandoffHook();
        installAcrossRanges();
    }

    function callCertValue(challenge) {
        if (typeof rpc === 'undefined' || !rpc || !rpc.exports || typeof rpc.exports.callCert !== 'function') {
            throw new Error('rpc.exports.callCert unavailable');
        }
        return String(rpc.exports.callCert(challenge) || '');
    }

    function firstText(slot) {
        if (!slot || typeof slot !== 'object') return null;
        if (typeof slot.text === 'string' && slot.text.length > 0) return slot.text;
        return null;
    }

    function buildSummary(challenge, token) {
        var resumeEvents = state.events.filter(function (event) {
            return event.kind === 'resume';
        });
        var comparisons = resumeEvents.map(function (event, index) {
            var spText = firstText(event.sp_plus_0x9c0);
            var x19Text = firstText(event.x19_slot);
            var x19p68Text = firstText(event.x19_plus_0x68);
            var x20Text = firstText(event.x20_slot);
            var x20p68Text = firstText(event.x20_plus_0x68);
            var x22NowText = firstText(event.x22_slot);
            var x22NowP68Text = firstText(event.x22_plus_0x68);
            var x22Text = firstText(event.entry_x22_slot);
            var x22p68Text = firstText(event.entry_x22_plus_0x68);
            return {
                index: index,
                selector: event.selector,
                entry_lr: event.entry_lr,
                entry_lr_offset: event.entry_lr_offset,
                sp_0x9c0_text: spText,
                x19_text: x19Text,
                x19_plus_0x68_text: x19p68Text,
                x20_text: x20Text,
                x20_plus_0x68_text: x20p68Text,
                x22_text: x22NowText,
                x22_plus_0x68_text: x22NowP68Text,
                entry_x22_text: x22Text,
                entry_x22_plus_0x68_text: x22p68Text,
                sp_0x9c0_vs_final: compareText(spText, token),
                x19_vs_final: compareText(x19Text, token),
                x19_plus_0x68_vs_final: compareText(x19p68Text, token),
                x20_vs_final: compareText(x20Text, token),
                x20_plus_0x68_vs_final: compareText(x20p68Text, token),
                x22_vs_final: compareText(x22NowText, token),
                x22_plus_0x68_vs_final: compareText(x22NowP68Text, token),
                entry_x22_vs_final: compareText(x22Text, token),
                entry_x22_plus_0x68_vs_final: compareText(x22p68Text, token),
            };
        });

        return {
            ok: true,
            challenge: challenge,
            token: token,
            warmChallenge: state.warmChallenge,
            target: state.target ? state.target.toString() : null,
            targetOffset: '0x' + state.targetOffset.toString(16),
            returnProbe: state.returnProbe ? state.returnProbe.toString() : null,
            events: state.events,
            comparisons: comparisons,
            resumeHookCount: Object.keys(state.resumeHooks).length,
            eventCount: state.events.length,
            drops: state.drops,
            failures: state.failures,
        };
    }

    globalThis.__jitCe75cLrProbeClear = function () {
        resetRunState();
        return 'OK';
    };

    globalThis.__jitCe75cLrProbeDump = function () {
        return JSON.stringify({
            installed: state.installed,
            armed: state.armed,
            warmed: state.warmed,
            warmChallenge: state.warmChallenge,
            currentBase: state.currentBase ? state.currentBase.toString() : null,
            target: state.target ? state.target.toString() : null,
            targetFile: state.targetFile,
            returnProbe: state.returnProbe ? state.returnProbe.toString() : null,
            eventCount: state.events.length,
            drops: state.drops,
            hooks: state.hooks,
            resumeHooks: state.resumeHooks,
            events: state.events,
            failures: state.failures,
            finalToken: state.finalToken,
            lastSummary: state.lastSummary,
        });
    };

    globalThis.__jitCe75cLrProbeRun = function (challenge, jsonOptions) {
        ensureInstalled();

        var opts = {};
        if (jsonOptions !== undefined && jsonOptions !== null) {
            try {
                opts = JSON.parse(String(jsonOptions));
            } catch (e) {
                noteFailure('parse options', e);
            }
        }

        var targetChallenge = challenge ? String(challenge) : DEFAULT_CHALLENGE;
        var doWarm = opts.warm !== false;
        if (opts.warmChallenge) {
            state.warmChallenge = String(opts.warmChallenge);
        }
        if (opts.targetOffset !== undefined && opts.targetOffset !== null) {
            try {
                var parsedOffset = parseInt(String(opts.targetOffset), 16);
                if (isFinite(parsedOffset)) {
                    state.targetOffset = parsedOffset;
                    state.hookInstalled = false;
                    state.currentBase = null;
                    state.target = null;
                    state.targetFile = null;
                    state.hooks = {};
                }
            } catch (e) {
                noteFailure('parse targetOffset', e);
            }
        } else {
            state.targetOffset = DEFAULT_TARGET_OFFSET;
            state.hookInstalled = false;
            state.currentBase = null;
            state.target = null;
            state.targetFile = null;
            state.hooks = {};
        }

        resetRunState();
        ensureInstalled();

        if (doWarm && !state.warmed) {
            try {
                state.lastWarmToken = callCertValue(state.warmChallenge);
                state.warmed = true;
                ensureInstalled();
            } catch (e) {
                noteFailure('warm call', e);
            }
        }

        state.challenge = targetChallenge;
        state.armed = true;
        try {
            state.finalToken = callCertValue(targetChallenge);
        } finally {
            state.armed = false;
            state.challenge = null;
            clearThreadState();
        }

        state.lastSummary = buildSummary(targetChallenge, state.finalToken || '');
        return JSON.stringify(state.lastSummary);
    };

    if (typeof maybeAdoptJit === 'function') {
        var origMaybeAdoptJit = maybeAdoptJit;
        maybeAdoptJit = function (target, source) {
            var mod = origMaybeAdoptJit(target, source);
            installAcrossRanges();
            return mod;
        };
    }

    ensureInstalled();
})();
