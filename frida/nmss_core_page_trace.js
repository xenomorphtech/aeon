'use strict';

(function () {
    if (globalThis.__nmssCorePageTraceInstalled) {
        console.log('[CAPTURE] [NMSSPAGE] already installed');
        return;
    }
    globalThis.__nmssCorePageTraceInstalled = true;

    var PAGE_SIZE = 0x1000;
    var ACTIVE_EXEC_BASE = ptr('0x9cf7a000');
    var ACTIVE_EXEC_SIZE = 0x50000;
    var ACTIVE_EXEC_END = ACTIVE_EXEC_BASE.add(ACTIVE_EXEC_SIZE);
    var ARM_ALL_CORRIDOR = true;
    var QUIT_ON_WOULD_TRAP = true;
    var pageMask = ptr('0xFFFFFFFFFFFFF000');
    var tracked = {};
    var handlerInstalled = false;
    var traceState = {
        closed: false,
        closeReason: null,
        wouldTrap: null,
        unknownInstruction: null,
        ownerTid: null,
        exact140358Hook: null,
        exact1549acContHook: null,
        exact1549acPostMemcpyHook: null,
        exact1549acSavedReturnHook: null,
        exact1549acSavedFollowHook: null,
        exact1549acBranch141a2cHook: null,
        exact1549acBranch141a34Hook: null,
        exact1549acBranch141a3cHook: null,
        exact1549acBranch141a50Hook: null,
        exact1549acBranch143c30Hook: null,
        exact1549acBranch143c34Hook: null,
        exact1549acBranch141c60Hook: null,
        exact1549acBranch141cbcHook: null,
        exact1549acBranch141d64Hook: null,
        stalkerThreadId: null,
        stalkerReason: null,
        stalkerEvents: [],
        stalkerActive: false,
        stalkerMaxEvents: 512,
        stalkerTimeoutId: null,
        stalkerSawCorridor: false,
        nmssModuleBase: null,
        nmssModuleEnd: null,
        exactArtQuickGenericJniSavedCallerPreHook: null,
        exactArtQuickGenericJniSavedCallerHook: null,
        exactArtQuickGenericJniSavedCallerNextHook: null,
        exactArtQuickGenericJniRetHook: null,
    };
    var sequence = {
        coreBodySeen: false,
        core1236Seen: false,
        helper128eb4Seen: false,
        helper12c68cSeen: false,
    };

    function fmtPtr(value) {
        try { return ptr(value).toString(); } catch (e) { return String(value); }
    }

    function pageBaseOf(value) {
        return ptr(value).and(pageMask);
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

    function currentTid() {
        try { return Process.getCurrentThreadId(); } catch (e) {}
        return null;
    }

    function isInActiveExecCorridor(value) {
        try {
            var p = ptr(value);
            return p.compare(ACTIVE_EXEC_BASE) >= 0 && p.compare(ACTIVE_EXEC_END) < 0;
        } catch (e) {}
        return false;
    }

    function isInNmssModule(value) {
        try {
            if (traceState.nmssModuleBase === null || traceState.nmssModuleEnd === null) return false;
            var p = ptr(value);
            return p.compare(traceState.nmssModuleBase) >= 0 && p.compare(traceState.nmssModuleEnd) < 0;
        } catch (e) {}
        return false;
    }

    function logContextEvent(label, kind, context) {
        var tid = currentTid();
        console.log('[CAPTURE] [NMSSPAGE] ' + label + ' kind=' + kind +
            ' tid=' + (tid === null ? 'unknown' : tid) +
            ' name=' + (threadNameMaybe(tid) || '<unknown>') +
            ' pc=' + fmtPtr(context.pc) +
            ' lr=' + fmtPtr(context.lr) +
            ' x0=' + fmtPtr(context.x0) +
            ' x1=' + fmtPtr(context.x1) +
            ' x2=' + fmtPtr(context.x2));
    }

    function logHit(kind, context) {
        logContextEvent('hit', kind, context);
    }

    function logAnchor(kind, context) {
        logContextEvent('anchor', kind, context);
    }

    function logSkip(kind, context) {
        logContextEvent('skip', kind, context);
    }

    function classifyStalkerMnemonic(mnemonic) {
        if (!mnemonic) return null;
        var m = String(mnemonic);
        if (m === 'ret') return 'ret';
        if (m === 'bl' || m === 'blr') return 'call';
        if (m === 'br') return 'branch';
        if (m === 'b' || m.indexOf('b.') === 0) return 'branch';
        if (m === 'cbz' || m === 'cbnz' || m === 'tbz' || m === 'tbnz') return 'branch';
        return null;
    }

    function tryReadU32(addr) {
        try { return ptr(addr).readU32() >>> 0; } catch (e) { return null; }
    }

    function fmtHex32(value) {
        if (value === null || value === undefined) return 'null';
        var s = (value >>> 0).toString(16);
        while (s.length < 8) s = '0' + s;
        return '0x' + s;
    }

    function classifyInsn(word) {
        if (word === null) return 'unreadable';
        if (word === 0x00000000) return 'zero';
        if ((word & 0xfffffc1f) === 0xd65f0000) return 'ret';
        if ((word & 0xfc000000) === 0x14000000) return 'b';
        if ((word & 0xfc000000) === 0x94000000) return 'bl';
        if ((word & 0xfffffc1f) === 0xd61f0000) return 'br';
        if ((word & 0xfffffc1f) === 0xd63f0000) return 'blr';
        if ((word & 0x7f000000) === 0x34000000) return 'cbz_cbnz';
        if ((word & 0x7f000000) === 0x36000000) return 'tbz_tbnz';
        if ((word & 0xffe0001f) === 0xd4200000) return 'brk';
        if ((word & 0xffff0000) === 0x00000000) return 'udf_or_zeroish';
        return 'other';
    }

    function clearOwnerStalkerTimeout() {
        if (traceState.stalkerTimeoutId !== null) {
            try { clearTimeout(traceState.stalkerTimeoutId); } catch (e) {}
            traceState.stalkerTimeoutId = null;
        }
    }

    function stopOwnerStalker(reason) {
        clearOwnerStalkerTimeout();
        if (traceState.stalkerThreadId !== null) {
            try {
                Stalker.unfollow(traceState.stalkerThreadId);
            } catch (e) {
                console.log('[CAPTURE] [NMSSSTALK] unfollow error=' + e);
            }
        }
        try { Stalker.garbageCollect(); } catch (e) {}
        if (traceState.stalkerActive || traceState.stalkerThreadId !== null) {
            console.log('[CAPTURE] [NMSSSTALK] stop tid=' +
                (traceState.stalkerThreadId === null ? 'null' : traceState.stalkerThreadId) +
                ' reason=' + (reason || 'unspecified') +
                ' events=' + traceState.stalkerEvents.length);
        }
        traceState.stalkerThreadId = null;
        traceState.stalkerReason = null;
        traceState.stalkerEvents = [];
        traceState.stalkerActive = false;
        traceState.stalkerSawCorridor = false;
    }

    function appendOwnerStalkerEvent(kind, pc, context) {
        var tid = currentTid();
        var inCorridor = false;
        var inNmss = false;
        var region = null;
        if (!traceState.stalkerActive) return;
        if (traceState.stalkerThreadId !== null && tid !== traceState.stalkerThreadId) return;
        inCorridor = isInActiveExecCorridor(pc);
        inNmss = isInNmssModule(pc);
        if (inCorridor) {
            traceState.stalkerSawCorridor = true;
            region = 'corridor';
        } else if (!traceState.stalkerSawCorridor && inNmss) {
            region = 'nmss';
        } else {
            return;
        }
        if (traceState.stalkerEvents.length >= traceState.stalkerMaxEvents) return;
        var event = {
            index: traceState.stalkerEvents.length,
            tid: tid,
            kind: kind,
            region: region,
            pc: fmtPtr(pc),
            lr: fmtPtr(context.lr),
        };
        traceState.stalkerEvents.push(event);
        console.log('[CAPTURE] [NMSSSTALK] event idx=' + event.index +
            ' tid=' + (tid === null ? 'unknown' : tid) +
            ' region=' + event.region +
            ' kind=' + kind +
            ' pc=' + event.pc +
            ' lr=' + event.lr);
    }

    function startOwnerStalker(threadId, reason) {
        console.log('[CAPTURE] [NMSSSTALK] enter threadId=' +
            (threadId === null || threadId === undefined ? 'null' : threadId) +
            ' reason=' + (reason || 'unspecified') +
            ' active=' + (traceState.stalkerActive ? 'yes' : 'no') +
            ' currentTid=' + (currentTid() === null ? 'unknown' : currentTid()));
        if (threadId === null || threadId === undefined) {
            console.log('[CAPTURE] [NMSSSTALK] enter abort=null-thread');
            return;
        }
        if (traceState.stalkerActive && traceState.stalkerThreadId === threadId) {
            console.log('[CAPTURE] [NMSSSTALK] enter abort=already-active tid=' + threadId);
            return;
        }
        stopOwnerStalker('switch');
        traceState.stalkerThreadId = threadId;
        traceState.stalkerReason = reason || 'unspecified';
        traceState.stalkerEvents = [];
        traceState.stalkerActive = true;
        traceState.stalkerSawCorridor = false;
        console.log('[CAPTURE] [NMSSSTALK] start tid=' + threadId +
            ' reason=' + traceState.stalkerReason +
            ' corridor=' + fmtPtr(ACTIVE_EXEC_BASE) + '..' + fmtPtr(ACTIVE_EXEC_END) +
            ' nmss=' + fmtPtr(traceState.nmssModuleBase) + '..' + fmtPtr(traceState.nmssModuleEnd));
        try {
            console.log('[CAPTURE] [NMSSSTALK] pre-follow tid=' + threadId);
            Stalker.follow(threadId, {
                transform: function (iterator) {
                    var instruction;
                    while ((instruction = iterator.next()) !== null) {
                        var kind = classifyStalkerMnemonic(instruction.mnemonic);
                        if (kind !== null) {
                            (function (capturedPc, capturedKind) {
                                iterator.putCallout(function (context) {
                                    appendOwnerStalkerEvent(capturedKind, capturedPc, context);
                                });
                            })(ptr(instruction.address), kind);
                        }
                        iterator.keep();
                    }
                }
            });
            console.log('[CAPTURE] [NMSSSTALK] post-follow tid=' + threadId);
        } catch (e) {
            traceState.stalkerActive = false;
            console.log('[CAPTURE] [NMSSSTALK] follow error=' + e);
            return;
        }
        traceState.stalkerTimeoutId = setTimeout(function () {
            stopOwnerStalker('window');
        }, 1000);
        console.log('[CAPTURE] [NMSSSTALK] armed-timeout tid=' + threadId + ' ms=1000');
    }

    function logWouldTrap(kind, reason, context) {
        var tid = currentTid();
        var word = tryReadU32(context.pc);
        var event = {
            kind: kind,
            reason: reason,
            tid: tid,
            name: threadNameMaybe(tid),
            pc: fmtPtr(context.pc),
            lr: fmtPtr(context.lr),
            x0: fmtPtr(context.x0),
            x1: fmtPtr(context.x1),
            x2: fmtPtr(context.x2),
            insn: fmtHex32(word),
            insn_kind: classifyInsn(word),
        };
        traceState.wouldTrap = event;
        console.log('[CAPTURE] [NMSSPAGE] would_trap kind=' + kind +
            ' reason=' + reason +
            ' tid=' + (tid === null ? 'unknown' : tid) +
            ' name=' + (event.name || '<unknown>') +
            ' pc=' + event.pc +
            ' lr=' + event.lr +
            ' x0=' + event.x0 +
            ' x1=' + event.x1 +
            ' x2=' + event.x2 +
            ' insn=' + event.insn +
            ' insn_kind=' + event.insn_kind);
        return event;
    }

    function maybeLogUnknownInstruction(kind, context) {
        var word = tryReadU32(context.pc);
        var insnKind = classifyInsn(word);
        if (insnKind !== 'brk' && insnKind !== 'udf_or_zeroish' && insnKind !== 'zero' && insnKind !== 'unreadable') {
            return false;
        }
        traceState.unknownInstruction = {
            kind: kind,
            pc: fmtPtr(context.pc),
            lr: fmtPtr(context.lr),
            insn: fmtHex32(word),
            insn_kind: insnKind,
        };
        console.log('[CAPTURE] [NMSSPAGE] unknown_instruction kind=' + kind +
            ' pc=' + fmtPtr(context.pc) +
            ' lr=' + fmtPtr(context.lr) +
            ' insn=' + fmtHex32(word) +
            ' insn_kind=' + insnKind);
        return true;
    }

    function armPage(base, kind, options) {
        var finalOptions = Object.assign({}, options || {});
        if (ARM_ALL_CORRIDOR &&
            finalOptions.armed === false &&
            !finalOptions.sharedPage &&
            !finalOptions.ownerScoped) {
            finalOptions.armed = true;
        }
        tracked[base.toString()] = Object.assign({
            base: base,
            kind: kind,
            armed: true,
            hits: 0,
            targetPc: null,
            nextPage: null,
            windowStart: null,
            windowEnd: null,
            logOnlyInWindow: false,
            sharedPage: false,
            ownerTid: null,
            ownerScoped: false,
        }, finalOptions);
        if (tracked[base.toString()].armed) {
            Memory.protect(base, PAGE_SIZE, 'r--');
            console.log('[CAPTURE] [NMSSPAGE] armed kind=' + kind + ' page=' + base);
        } else {
            console.log('[CAPTURE] [NMSSPAGE] staged kind=' + kind + ' page=' + base);
        }
    }

    function armDynamicPage(base, kind, options) {
        tracked[base.toString()] = Object.assign({
            base: base,
            kind: kind,
            armed: true,
            hits: 0,
            targetPc: null,
            nextPage: null,
            windowStart: null,
            windowEnd: null,
            logOnlyInWindow: false,
            sharedPage: false,
            ownerTid: null,
        }, options || {});
        Memory.protect(base, PAGE_SIZE, 'r--');
        console.log('[CAPTURE] [NMSSPAGE] activated dynamic kind=' + kind + ' page=' + base +
            (options && options.targetPc ? ' target=' + fmtPtr(options.targetPc) : ''));
    }

    function pcInAllowedWindows(pc, info) {
        if (info.allowedWindows && info.allowedWindows.length) {
            for (var i = 0; i < info.allowedWindows.length; i++) {
                var win = info.allowedWindows[i];
                if (pc.compare(win.start) >= 0 && pc.compare(win.end) < 0) {
                    return true;
                }
            }
            return false;
        }
        if (info.windowStart && info.windowEnd) {
            return pc.compare(info.windowStart) >= 0 && pc.compare(info.windowEnd) < 0;
        }
        return true;
    }

    function setOwnerTid(tid, why) {
        if (tid === null || tid === undefined) return;
        if (traceState.ownerTid === tid) return;
        if (traceState.ownerTid === null) {
            traceState.ownerTid = tid;
            console.log('[CAPTURE] [NMSSPAGE] owner tid=' + tid +
                ' name=' + (threadNameMaybe(tid) || '<unknown>') +
                ' why=' + why);
        }
    }

    function disarmAll(reason) {
        traceState.closed = true;
        traceState.closeReason = reason || 'unspecified';
        stopOwnerStalker('disarm');
        if (traceState.exact140358Hook !== null) {
            try {
                traceState.exact140358Hook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] exact hook detach error: ' + e);
            }
            traceState.exact140358Hook = null;
        }
        if (traceState.exact1549acContHook !== null) {
            try {
                traceState.exact1549acContHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac cont hook detach error: ' + e);
            }
            traceState.exact1549acContHook = null;
        }
        if (traceState.exact1549acPostMemcpyHook !== null) {
            try {
                traceState.exact1549acPostMemcpyHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac post memcpy hook detach error: ' + e);
            }
            traceState.exact1549acPostMemcpyHook = null;
        }
        if (traceState.exact1549acSavedReturnHook !== null) {
            try {
                traceState.exact1549acSavedReturnHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac saved return hook detach error: ' + e);
            }
            traceState.exact1549acSavedReturnHook = null;
        }
        if (traceState.exact1549acSavedFollowHook !== null) {
            try {
                traceState.exact1549acSavedFollowHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac saved follow hook detach error: ' + e);
            }
            traceState.exact1549acSavedFollowHook = null;
        }
        if (traceState.exact1549acBranch141a2cHook !== null) {
            try {
                traceState.exact1549acBranch141a2cHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141a2c hook detach error: ' + e);
            }
            traceState.exact1549acBranch141a2cHook = null;
        }
        if (traceState.exact1549acBranch141a34Hook !== null) {
            try {
                traceState.exact1549acBranch141a34Hook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141a34 hook detach error=' + e);
            }
            traceState.exact1549acBranch141a34Hook = null;
        }
        if (traceState.exact1549acBranch141a3cHook !== null) {
            try {
                traceState.exact1549acBranch141a3cHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141a3c hook detach error=' + e);
            }
            traceState.exact1549acBranch141a3cHook = null;
        }
        if (traceState.exact1549acBranch141a50Hook !== null) {
            try {
                traceState.exact1549acBranch141a50Hook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141a50 hook detach error=' + e);
            }
            traceState.exact1549acBranch141a50Hook = null;
        }
        if (traceState.exact1549acBranch143c30Hook !== null) {
            try {
                traceState.exact1549acBranch143c30Hook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 143c30 hook detach error=' + e);
            }
            traceState.exact1549acBranch143c30Hook = null;
        }
        if (traceState.exact1549acBranch141c60Hook !== null) {
            try {
                traceState.exact1549acBranch141c60Hook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141c60 hook detach error=' + e);
            }
            traceState.exact1549acBranch141c60Hook = null;
        }
        if (traceState.exact1549acBranch141cbcHook !== null) {
            try {
                traceState.exact1549acBranch141cbcHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141cbc hook detach error: ' + e);
            }
            traceState.exact1549acBranch141cbcHook = null;
        }
        if (traceState.exact1549acBranch141d64Hook !== null) {
            try {
                traceState.exact1549acBranch141d64Hook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141d64 hook detach error: ' + e);
            }
            traceState.exact1549acBranch141d64Hook = null;
        }
        if (traceState.exactArtQuickGenericJniSavedCallerPreHook !== null) {
            try {
                traceState.exactArtQuickGenericJniSavedCallerPreHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] art jni saved caller pre hook detach error: ' + e);
            }
            traceState.exactArtQuickGenericJniSavedCallerPreHook = null;
        }
        if (traceState.exactArtQuickGenericJniSavedCallerHook !== null) {
            try {
                traceState.exactArtQuickGenericJniSavedCallerHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] art jni saved caller hook detach error: ' + e);
            }
            traceState.exactArtQuickGenericJniSavedCallerHook = null;
        }
        if (traceState.exactArtQuickGenericJniSavedCallerNextHook !== null) {
            try {
                traceState.exactArtQuickGenericJniSavedCallerNextHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] art jni saved caller next hook detach error: ' + e);
            }
            traceState.exactArtQuickGenericJniSavedCallerNextHook = null;
        }
        if (traceState.exactArtQuickGenericJniRetHook !== null) {
            try {
                traceState.exactArtQuickGenericJniRetHook.detach();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] art jni ret hook detach error: ' + e);
            }
            traceState.exactArtQuickGenericJniRetHook = null;
        }
        Object.keys(tracked).forEach(function (key) {
            var info = tracked[key];
            if (!info) return;
            try {
                Memory.protect(info.base, PAGE_SIZE, 'r-x');
                info.armed = false;
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] disarm error kind=' + info.kind +
                    ' page=' + info.base + ' err=' + e);
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] disarmed all reason=' + (reason || 'unspecified'));
    }

    function rearmPageLater(base) {
        setTimeout(function () {
            var info = tracked[base.toString()];
            if (!info) return;
            try {
                Memory.protect(base, PAGE_SIZE, 'r--');
                info.armed = true;
                console.log('[CAPTURE] [NMSSPAGE] rearmed kind=' + info.kind + ' page=' + base);
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] rearm error kind=' + info.kind + ' page=' + base + ' err=' + e);
            }
        }, 1);
    }

    function installExact140358Hook(addr, ownerTid) {
        if (traceState.exact140358Hook !== null) return;
        traceState.exact140358Hook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_154a6c_cont_140358_exact', this.context);
            var savedRet = null;
            try {
                savedRet = ptr(this.context.sp).add(0xc8).readPointer();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] exact_140358 read_saved_ret error=' + e);
            }
            console.log('[CAPTURE] [NMSSPAGE] exact_140358 tid=' + tid +
                ' sp=' + fmtPtr(this.context.sp) +
                ' saved_ret=' + fmtPtr(savedRet) +
                ' x19=' + fmtPtr(this.context.x19) +
                ' x0=' + fmtPtr(this.context.x0));
            if (savedRet !== null) {
                armDynamicPage(pageBaseOf(savedRet), 'helper_154a6c_cont_return_page', {
                    ownerTid: ownerTid,
                    targetPc: savedRet,
                    windowStart: savedRet.sub(0x10),
                    windowEnd: savedRet.add(0x40),
                    logOnlyInWindow: true,
                });
            }
            if (traceState.exact140358Hook !== null) {
                try {
                    traceState.exact140358Hook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] exact_140358 detach error=' + e);
                }
                traceState.exact140358Hook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_154a6c_cont_140358_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acContHook(addr, ownerTid) {
        if (traceState.exact1549acContHook !== null) return;
        traceState.exact1549acContHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_cont_79aac_exact', this.context);
            var retPc = ptr(this.context.lr);
            var postMemcpyPc = ptr(this.context.pc).add(0x20);
            var savedCallerRet = null;
            try {
                savedCallerRet = ptr(this.context.sp).add(0x38).readPointer();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_cont read_saved_caller_ret error=' + e);
            }
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_cont tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(retPc) +
                ' saved_caller_ret=' + fmtPtr(savedCallerRet) +
                ' post_memcpy=' + fmtPtr(postMemcpyPc) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x1=' + fmtPtr(this.context.x1) +
                ' x19=' + fmtPtr(this.context.x19));
            installExact1549acPostMemcpyHook(postMemcpyPc, ownerTid);
            if (savedCallerRet !== null) {
                installExact1549acSavedReturnHook(savedCallerRet, ownerTid);
            }
            if (traceState.exact1549acContHook !== null) {
                try {
                    traceState.exact1549acContHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac cont detach error=' + e);
                }
                traceState.exact1549acContHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_cont_79aac_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acPostMemcpyHook(addr, ownerTid) {
        if (traceState.exact1549acPostMemcpyHook !== null) return;
        traceState.exact1549acPostMemcpyHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_cont_post_memcpy_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_post_memcpy tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x19=' + fmtPtr(this.context.x19) +
                ' x22=' + fmtPtr(this.context.x22));
            if (traceState.exact1549acPostMemcpyHook !== null) {
                try {
                    traceState.exact1549acPostMemcpyHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac post memcpy detach error=' + e);
                }
                traceState.exact1549acPostMemcpyHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_cont_post_memcpy_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acSavedReturnHook(addr, ownerTid) {
        if (traceState.exact1549acSavedReturnHook !== null) return;
        traceState.exact1549acSavedReturnHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_cont_saved_return_exact', this.context);
            var followPc = ptr(this.context.pc).add(0x234);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_saved_return tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' follow=' + fmtPtr(followPc) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x1=' + fmtPtr(this.context.x1) +
                ' x19=' + fmtPtr(this.context.x19));
            installExact1549acSavedFollowHook(followPc, ownerTid);
            if (traceState.exact1549acSavedReturnHook !== null) {
                try {
                    traceState.exact1549acSavedReturnHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac saved return detach error=' + e);
                }
                traceState.exact1549acSavedReturnHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_cont_saved_return_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acSavedFollowHook(addr, ownerTid) {
        if (traceState.exact1549acSavedFollowHook !== null) return;
        traceState.exact1549acSavedFollowHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_cont_saved_follow_141ad8_exact', this.context);
            startOwnerStalker(tid, 'anchor_1549ac_cont_saved_follow_141ad8_exact');
            var branch141a2c = ptr(this.context.pc).sub(0xac);
            var branch141cbc = ptr(this.context.pc).add(0x1e4);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_saved_follow tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' branch_141a2c=' + fmtPtr(branch141a2c) +
                ' branch_141cbc=' + fmtPtr(branch141cbc) +
                ' w8=0x' + (this.context.w8 >>> 0).toString(16) +
                ' w19=0x' + (this.context.w19 >>> 0).toString(16) +
                ' w21=0x' + (this.context.w21 >>> 0).toString(16) +
                ' w24=0x' + (this.context.w24 >>> 0).toString(16) +
                ' w25=0x' + (this.context.w25 >>> 0).toString(16) +
                ' w28=0x' + (this.context.w28 >>> 0).toString(16));
            installExact1549acBranch141a2cHook(branch141a2c, ownerTid);
            installExact1549acBranch141cbcHook(branch141cbc, ownerTid);
            if (traceState.exact1549acSavedFollowHook !== null) {
                try {
                    traceState.exact1549acSavedFollowHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac saved follow detach error=' + e);
                }
                traceState.exact1549acSavedFollowHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_cont_saved_follow_141ad8_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acBranch141a2cHook(addr, ownerTid) {
        if (traceState.exact1549acBranch141a2cHook !== null) return;
        traceState.exact1549acBranch141a2cHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_branch_141a2c_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_branch_141a2c tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' w20=0x' + (this.context.w20 >>> 0).toString(16) +
                ' w21=0x' + (this.context.w21 >>> 0).toString(16) +
                ' w22=0x' + (this.context.w22 >>> 0).toString(16));
            if (traceState.exact1549acBranch141a2cHook !== null) {
                try {
                    traceState.exact1549acBranch141a2cHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141a2c detach error=' + e);
                }
                traceState.exact1549acBranch141a2cHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_branch_141a2c_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acBranch141a34Hook(addr, ownerTid) {
        if (traceState.exact1549acBranch141a34Hook !== null) return;
        traceState.exact1549acBranch141a34Hook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_branch_141a34_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_branch_141a34 tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' w20=0x' + (this.context.w20 >>> 0).toString(16) +
                ' w21=0x' + (this.context.w21 >>> 0).toString(16));
            if (traceState.exact1549acBranch141a34Hook !== null) {
                try {
                    traceState.exact1549acBranch141a34Hook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141a34 detach error=' + e);
                }
                traceState.exact1549acBranch141a34Hook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_branch_141a34_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acBranch141a3cHook(addr, ownerTid) {
        if (traceState.exact1549acBranch141a3cHook !== null) return;
        traceState.exact1549acBranch141a3cHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_branch_141a3c_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_branch_141a3c tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' w20=0x' + (this.context.w20 >>> 0).toString(16) +
                ' w21=0x' + (this.context.w21 >>> 0).toString(16));
            if (traceState.exact1549acBranch141a3cHook !== null) {
                try {
                    traceState.exact1549acBranch141a3cHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141a3c detach error=' + e);
                }
                traceState.exact1549acBranch141a3cHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_branch_141a3c_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acBranch141a50Hook(addr, ownerTid) {
        if (traceState.exact1549acBranch141a50Hook !== null) return;
        traceState.exact1549acBranch141a50Hook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_branch_141a50_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_branch_141a50 tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x1=' + fmtPtr(this.context.x1) +
                ' x2=' + fmtPtr(this.context.x2));
            if (traceState.exact1549acBranch141a50Hook !== null) {
                try {
                    traceState.exact1549acBranch141a50Hook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141a50 detach error=' + e);
                }
                traceState.exact1549acBranch141a50Hook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_branch_141a50_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acBranch143c30Hook(addr, ownerTid) {
        if (traceState.exact1549acBranch143c30Hook !== null) return;
        traceState.exact1549acBranch143c30Hook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_branch_143c30_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_branch_143c30 tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x1=' + fmtPtr(this.context.x1) +
                ' x2=' + fmtPtr(this.context.x2) +
                ' x8=' + fmtPtr(this.context.x8));
            if (traceState.exact1549acBranch143c30Hook !== null) {
                try {
                    traceState.exact1549acBranch143c30Hook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 143c30 detach error=' + e);
                }
                traceState.exact1549acBranch143c30Hook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_branch_143c30_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }


    function installExact1549acBranch143c34Hook(addr, ownerTid) {
        if (traceState.exact1549acBranch143c34Hook !== null) return;
        traceState.exact1549acBranch143c34Hook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_branch_143c34_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_branch_143c34 tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' x8=' + fmtPtr(this.context.x8) +
                ' x9=' + fmtPtr(this.context.x9) +
                ' x19=' + fmtPtr(this.context.x19));
            if (traceState.exact1549acBranch143c34Hook !== null) {
                try {
                    traceState.exact1549acBranch143c34Hook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 143c34 detach error=' + e);
                }
                traceState.exact1549acBranch143c34Hook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_branch_143c34_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acBranch141c60Hook(addr, ownerTid) {
        if (traceState.exact1549acBranch141c60Hook !== null) return;
        traceState.exact1549acBranch141c60Hook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_branch_141c60_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_branch_141c60 tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x1=' + fmtPtr(this.context.x1) +
                ' w21=0x' + (this.context.w21 >>> 0).toString(16) +
                ' w22=0x' + (this.context.w22 >>> 0).toString(16));
            if (traceState.exact1549acBranch141c60Hook !== null) {
                try {
                    traceState.exact1549acBranch141c60Hook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141c60 detach error=' + e);
                }
                traceState.exact1549acBranch141c60Hook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_branch_141c60_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acBranch141cbcHook(addr, ownerTid) {
        if (traceState.exact1549acBranch141cbcHook !== null) return;
        traceState.exact1549acBranch141cbcHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_branch_141cbc_exact', this.context);
            startOwnerStalker(tid, 'anchor_1549ac_branch_141cbc_exact');
            var branch141a34 = ptr(this.context.pc).sub(0x288);
            var branch141a3c = ptr(this.context.pc).sub(0x280);
            var follow141a50 = ptr(this.context.pc).sub(0x26c);
            var follow143c30 = ptr(this.context.pc).add(0x1f74);
            var follow143c34 = follow143c30.add(0x4);
            var follow141c60 = ptr(this.context.pc).sub(0x5c);
            var follow141d64 = ptr(this.context.pc).add(0xa8);
            var nextBranch = (this.context.w20 >>> 0) !== 0 ? branch141a34 : branch141a3c;
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_branch_141cbc tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' branch_141a34=' + fmtPtr(branch141a34) +
                ' branch_141a3c=' + fmtPtr(branch141a3c) +
                ' next_branch=' + fmtPtr(nextBranch) +
                ' follow_141a50=' + fmtPtr(follow141a50) +
                ' follow_143c30=' + fmtPtr(follow143c30) +
                ' follow_143c34=' + fmtPtr(follow143c34) +
                ' follow_141c60=' + fmtPtr(follow141c60) +
                ' follow_141d64=' + fmtPtr(follow141d64) +
                ' w20=0x' + (this.context.w20 >>> 0).toString(16) +
                ' w21=0x' + (this.context.w21 >>> 0).toString(16) +
                ' x1=' + fmtPtr(this.context.x1) +
                ' x2=' + fmtPtr(this.context.x2) +
                ' x8=' + fmtPtr(this.context.x8));
            installExact1549acBranch141a34Hook(branch141a34, ownerTid);
            installExact1549acBranch141a3cHook(branch141a3c, ownerTid);
            installExact1549acBranch141a50Hook(follow141a50, ownerTid);
            installExact1549acBranch143c30Hook(follow143c30, ownerTid);
            installExact1549acBranch143c34Hook(follow143c34, ownerTid);
            installExact1549acBranch141c60Hook(follow141c60, ownerTid);
            installExact1549acBranch141d64Hook(follow141d64, ownerTid);
            if (traceState.exact1549acBranch141cbcHook !== null) {
                try {
                    traceState.exact1549acBranch141cbcHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141cbc detach error=' + e);
                }
                traceState.exact1549acBranch141cbcHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_branch_141cbc_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExact1549acBranch141d64Hook(addr, ownerTid) {
        if (traceState.exact1549acBranch141d64Hook !== null) return;
        traceState.exact1549acBranch141d64Hook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_1549ac_branch_141d64_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] exact_1549ac_branch_141d64 tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x19=' + fmtPtr(this.context.x19));
            if (traceState.exact1549acBranch141d64Hook !== null) {
                try {
                    traceState.exact1549acBranch141d64Hook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] 1549ac branch 141d64 detach error=' + e);
                }
                traceState.exact1549acBranch141d64Hook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=helper_1549ac_branch_141d64_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExactArtQuickGenericJniSavedCallerPreHook(addr, ownerTid) {
        if (traceState.exactArtQuickGenericJniSavedCallerPreHook !== null) return;
        traceState.exactArtQuickGenericJniSavedCallerPreHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_art_quick_generic_jni_saved_caller_pre_exact', this.context);
            var callee = null;
            try {
                callee = ptr(this.context.x0).add(0x18).readPointer();
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] art_quick_generic_jni_saved_caller_pre read_callee error: ' + e);
            }
            console.log('[CAPTURE] [NMSSPAGE] art_quick_generic_jni_saved_caller_pre tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x19=' + fmtPtr(this.context.x19) +
                ' x22=' + fmtPtr(this.context.x22) +
                ' x24=' + fmtPtr(this.context.x24) +
                ' callee=' + fmtPtr(callee));
            if (traceState.exactArtQuickGenericJniSavedCallerPreHook !== null) {
                try {
                    traceState.exactArtQuickGenericJniSavedCallerPreHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] art jni saved caller pre detach error: ' + e);
                }
                traceState.exactArtQuickGenericJniSavedCallerPreHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=art_quick_generic_jni_saved_caller_pre_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExactArtQuickGenericJniSavedCallerHook(addr, ownerTid) {
        if (traceState.exactArtQuickGenericJniSavedCallerHook !== null) return;
        traceState.exactArtQuickGenericJniSavedCallerHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_art_quick_generic_jni_saved_caller_exact', this.context);
            var retPc = ptr(this.context.lr);
            var nextTarget = null;
            var opcode = null;
            try {
                opcode = ptr(this.context.x22).add(0x6).readU16() & 0xff;
                nextTarget = ptr(this.context.x24).add(opcode << 7);
            } catch (e) {
                console.log('[CAPTURE] [NMSSPAGE] art_quick_generic_jni_saved_caller compute_next error: ' + e);
            }
            console.log('[CAPTURE] [NMSSPAGE] art_quick_generic_jni_saved_caller tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(retPc) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x1=' + fmtPtr(this.context.x1) +
                ' x19=' + fmtPtr(this.context.x19) +
                ' x22=' + fmtPtr(this.context.x22) +
                ' x24=' + fmtPtr(this.context.x24) +
                ' x29=' + fmtPtr(this.context.x29) +
                ' opcode=' + (opcode === null ? 'null' : ('0x' + opcode.toString(16))) +
                ' next_target=' + fmtPtr(nextTarget));
            if (nextTarget !== null) {
                installExactArtQuickGenericJniSavedCallerNextHook(nextTarget, ownerTid);
            }
            armDynamicPage(pageBaseOf(retPc), 'art_quick_generic_jni_saved_caller_return_page', {
                ownerTid: ownerTid,
                targetPc: retPc,
                windowStart: retPc.sub(0x10),
                windowEnd: retPc.add(0x40),
                logOnlyInWindow: true,
            });
            if (traceState.exactArtQuickGenericJniSavedCallerHook !== null) {
                try {
                    traceState.exactArtQuickGenericJniSavedCallerHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] art jni saved caller detach error: ' + e);
                }
                traceState.exactArtQuickGenericJniSavedCallerHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=art_quick_generic_jni_saved_caller_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExactArtQuickGenericJniSavedCallerNextHook(addr, ownerTid) {
        if (traceState.exactArtQuickGenericJniSavedCallerNextHook !== null) return;
        traceState.exactArtQuickGenericJniSavedCallerNextHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_art_quick_generic_jni_saved_caller_next_exact', this.context);
            console.log('[CAPTURE] [NMSSPAGE] art_quick_generic_jni_saved_caller_next tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(this.context.lr) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x1=' + fmtPtr(this.context.x1) +
                ' x19=' + fmtPtr(this.context.x19) +
                ' x22=' + fmtPtr(this.context.x22) +
                ' x24=' + fmtPtr(this.context.x24));
            if (traceState.exactArtQuickGenericJniSavedCallerNextHook !== null) {
                try {
                    traceState.exactArtQuickGenericJniSavedCallerNextHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] art jni saved caller next detach error: ' + e);
                }
                traceState.exactArtQuickGenericJniSavedCallerNextHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=art_quick_generic_jni_saved_caller_next_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function installExactArtQuickGenericJniRetHook(addr, ownerTid) {
        if (traceState.exactArtQuickGenericJniRetHook !== null) return;
        traceState.exactArtQuickGenericJniRetHook = Interceptor.attach(addr, function () {
            var tid = currentTid();
            if (ownerTid !== null && tid !== ownerTid) return;
            logAnchor('anchor_art_quick_generic_jni_ret_exact', this.context);
            var retPc = ptr(this.context.lr);
            console.log('[CAPTURE] [NMSSPAGE] art_quick_generic_jni_ret tid=' + tid +
                ' pc=' + fmtPtr(this.context.pc) +
                ' lr=' + fmtPtr(retPc) +
                ' x0=' + fmtPtr(this.context.x0) +
                ' x1=' + fmtPtr(this.context.x1) +
                ' x19=' + fmtPtr(this.context.x19));
            armDynamicPage(pageBaseOf(retPc), 'art_quick_generic_jni_ret_return_page', {
                ownerTid: ownerTid,
                targetPc: retPc,
                windowStart: retPc.sub(0x10),
                windowEnd: retPc.add(0x40),
                logOnlyInWindow: true,
            });
            if (traceState.exactArtQuickGenericJniRetHook !== null) {
                try {
                    traceState.exactArtQuickGenericJniRetHook.detach();
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] art jni ret detach error=' + e);
                }
                traceState.exactArtQuickGenericJniRetHook = null;
            }
        });
        console.log('[CAPTURE] [NMSSPAGE] installed exact hook kind=art_quick_generic_jni_ret_exact addr=' +
            fmtPtr(addr) + ' ownerTid=' + (ownerTid === null ? 'null' : ownerTid));
    }

    function install() {
        var mod = Process.findModuleByName('libnmsssa.so');
        if (!mod) {
            console.log('[CAPTURE] [NMSSPAGE] libnmsssa.so not found');
            return false;
        }
        traceState.nmssModuleBase = mod.base;
        traceState.nmssModuleEnd = mod.base.add(mod.size);

        var coreBody = mod.base.add(0x123288);
        var helperA = mod.base.add(0x128eb4);
        var helperB = mod.base.add(0x12c114);
        var helperBPre1 = mod.base.add(0x12c3e4);
        var helperBPre2 = mod.base.add(0x12c428);
        var helperBExact = mod.base.add(0x12c68c);
        var helperBCall1 = mod.base.add(0x133908);
        var helperBCall2 = mod.base.add(0x1339a0);
        var helperBCall3Alt = mod.base.add(0x133f20);
        var helperBCall3 = mod.base.add(0x8ddd0);
        var helperBCall3Callee1Pre = mod.base.add(0x1549ac);
        var helperBCall3Callee1 = mod.base.add(0x154a6c);
        var helper1549acCont = mod.base.add(0x79aac);
        var helperBCall3Callee1b = mod.base.add(0x154b18);
        var helperBCall3Callee1c = mod.base.add(0x154d14);
        var helperBCall3Callee2 = mod.base.add(0x17e848);
        var helper154a6cContRet = mod.base.add(0x140358);
        var helperFamily17c1 = mod.base.add(0x17cff8);
        var helperFamily17c2 = mod.base.add(0x17d06c);
        var helper17e848Callee1 = mod.base.add(0x17cee4);
        var helper17e848Callee2 = mod.base.add(0x17d62c);
        var libart = Process.findModuleByName('libart.so');
        var artQuickGenericJniRet = libart ? libart.base.add(0x22229c) : null;
        var corePage = pageBaseOf(coreBody);
        var helperPage = pageBaseOf(helperA);
        var helperBPage = pageBaseOf(helperB);
        var helperBCallPage1 = pageBaseOf(helperBCall1);
        var helperBCallPage3 = pageBaseOf(helperBCall3);
        var helperBCall3CalleePage1 = pageBaseOf(helperBCall3Callee1);
        var helperBCall3CalleePage2 = pageBaseOf(helperBCall3Callee2);
        var helperFamily17cPage = pageBaseOf(helperFamily17c1);
        var helper17e848CalleePage2 = pageBaseOf(helper17e848Callee2);

        if (!handlerInstalled) {
            Process.setExceptionHandler(function (details) {
                try {
                    if (!details || !details.context || details.type !== 'access-violation') return false;
                    if (traceState.closed) return false;
                    var pc = ptr(details.context.pc);
                    var base = pageBaseOf(pc);
                    var info = tracked[base.toString()];
                    if (!info || !info.armed) return false;
                    var tid = currentTid();
                    if (info.ownerTid !== null && tid !== info.ownerTid) {
                        logSkip(info.kind + '_owner_mismatch', details.context);
                        Memory.protect(base, PAGE_SIZE, 'r-x');
                        info.armed = false;
                        return true;
                    }
                    info.armed = false;
                    info.hits++;
                    var shouldLog = true;
                    if (info.logOnlyInWindow) {
                        shouldLog = pcInAllowedWindows(pc, info);
                    }
                    if (shouldLog) {
                        logHit(info.kind, details.context);
                    } else {
                        logSkip(info.kind, details.context);
                        logWouldTrap(info.kind, 'outside_expected_window', details.context);
                        if (QUIT_ON_WOULD_TRAP) {
                            disarmAll('would_trap:' + info.kind);
                            return true;
                        }
                    }
                    if (maybeLogUnknownInstruction(info.kind, details.context)) {
                        if (QUIT_ON_WOULD_TRAP) {
                            disarmAll('unknown_instruction:' + info.kind);
                            return true;
                        }
                    }
                    if (info.kind === 'core_body_page') {
                        sequence.coreBodySeen = true;
                        if (info.nextPage) {
                            var nextFromCore = tracked[info.nextPage.toString()];
                            if (nextFromCore && !nextFromCore.armed) {
                                nextFromCore.armed = true;
                                Memory.protect(nextFromCore.base, PAGE_SIZE, 'r--');
                                console.log('[CAPTURE] [NMSSPAGE] activated next kind=' + nextFromCore.kind +
                                    ' page=' + nextFromCore.base +
                                    ' after=' + info.kind);
                            }
                        }
                    }
                    if (info.kind === 'helper_128eb4_page' && info.targetPc && pc.equals(info.targetPc)) {
                        sequence.helper128eb4Seen = true;
                        if (info.nextPage) {
                            var nextInfo = tracked[info.nextPage.toString()];
                            if (nextInfo && !nextInfo.armed) {
                                nextInfo.armed = true;
                                Memory.protect(nextInfo.base, PAGE_SIZE, 'r--');
                                console.log('[CAPTURE] [NMSSPAGE] activated next kind=' + nextInfo.kind +
                                    ' page=' + nextInfo.base +
                                    ' after=' + info.kind);
                            }
                        }
                    }
                    if (info.kind === 'helper_12c68c_call_8ddd0_page' &&
                        info.targetPc && pc.equals(info.targetPc) &&
                        info.nextPages) {
                        setOwnerTid(tid, info.kind);
                        for (var nci = 0; nci < info.nextPages.length; nci++) {
                            var nextPage3 = info.nextPages[nci];
                            var nextInfo3 = tracked[nextPage3.toString()];
                            if (nextInfo3 && !nextInfo3.armed) {
                                nextInfo3.ownerTid = traceState.ownerTid;
                                nextInfo3.armed = true;
                                Memory.protect(nextInfo3.base, PAGE_SIZE, 'r--');
                                console.log('[CAPTURE] [NMSSPAGE] activated next kind=' + nextInfo3.kind +
                                    ' page=' + nextInfo3.base +
                                    ' after=' + info.kind);
                            }
                        }
                    }
                    if (info.kind === 'helper_8ddd0_family_154x_page') {
                        if (info.exact1549ac && pc.equals(info.exact1549ac)) {
                            setOwnerTid(tid, 'anchor_1549ac');
                            logAnchor('anchor_1549ac', details.context);
                            var retPc1549ac = ptr(details.context.lr);
                            armDynamicPage(pageBaseOf(retPc1549ac), 'helper_1549ac_return_page', {
                                ownerTid: traceState.ownerTid,
                                targetPc: retPc1549ac,
                                windowStart: retPc1549ac.sub(0x10),
                                windowEnd: retPc1549ac.add(0x40),
                                logOnlyInWindow: true,
                            });
                        }
                        if (info.exact154a6c && pc.equals(info.exact154a6c)) {
                            setOwnerTid(tid, 'anchor_154a6c');
                            logAnchor('anchor_154a6c', details.context);
                            var retPc154 = ptr(details.context.lr);
                            var retPage154 = pageBaseOf(retPc154);
                            armDynamicPage(retPage154, 'helper_154a6c_return_page', {
                                ownerTid: traceState.ownerTid,
                                targetPc: retPc154,
                                windowStart: retPc154.sub(0x10),
                                windowEnd: retPc154.add(0x40),
                                logOnlyInWindow: true,
                            });
                        }
                        if (info.exact154b18 && pc.equals(info.exact154b18)) {
                            setOwnerTid(tid, 'anchor_154b18');
                            logAnchor('anchor_154b18', details.context);
                            if (info.nextPagesOn154b) {
                                for (var nib = 0; nib < info.nextPagesOn154b.length; nib++) {
                                    var nextPageB = info.nextPagesOn154b[nib];
                                    var nextInfoB = tracked[nextPageB.toString()];
                                    if (nextInfoB && !nextInfoB.armed) {
                                        nextInfoB.ownerTid = traceState.ownerTid;
                                        nextInfoB.armed = true;
                                        Memory.protect(nextInfoB.base, PAGE_SIZE, 'r--');
                                        console.log('[CAPTURE] [NMSSPAGE] activated next kind=' + nextInfoB.kind +
                                            ' page=' + nextInfoB.base +
                                            ' after=anchor_154b18');
                                    }
                                }
                            }
                        }
                        if (info.exact154d14 && pc.equals(info.exact154d14)) {
                            setOwnerTid(tid, 'anchor_154d14');
                            logAnchor('anchor_154d14', details.context);
                            if (info.nextPagesOn154d) {
                                for (var nid = 0; nid < info.nextPagesOn154d.length; nid++) {
                                    var nextPageD = info.nextPagesOn154d[nid];
                                    var nextInfoD = tracked[nextPageD.toString()];
                                    if (nextInfoD && !nextInfoD.armed) {
                                        nextInfoD.ownerTid = traceState.ownerTid;
                                        nextInfoD.armed = true;
                                        Memory.protect(nextInfoD.base, PAGE_SIZE, 'r--');
                                        console.log('[CAPTURE] [NMSSPAGE] activated next kind=' + nextInfoD.kind +
                                            ' page=' + nextInfoD.base +
                                            ' after=anchor_154d14');
                                    }
                                }
                            }
                        }
                    }
                    if (info.kind === 'helper_8ddd0_call_17e848_page' &&
                        info.targetPc && pc.equals(info.targetPc) &&
                        info.nextPages) {
                        setOwnerTid(tid, 'anchor_17e848');
                        logAnchor('anchor_17e848', details.context);
                        for (var ni17 = 0; ni17 < info.nextPages.length; ni17++) {
                            var nextPage17 = info.nextPages[ni17];
                            var nextInfo17 = tracked[nextPage17.toString()];
                            if (nextInfo17 && !nextInfo17.armed) {
                                nextInfo17.ownerTid = traceState.ownerTid;
                                nextInfo17.armed = true;
                                Memory.protect(nextInfo17.base, PAGE_SIZE, 'r--');
                                console.log('[CAPTURE] [NMSSPAGE] activated next kind=' + nextInfo17.kind +
                                    ' page=' + nextInfo17.base +
                                    ' after=anchor_17e848');
                            }
                        }
                    }
                    if (info.kind === 'helper_12c68c_page') {
                        if (info.baseTargetPc && pc.equals(info.baseTargetPc)) {
                            logAnchor('anchor_12c114', details.context);
                        }
                        if (info.preTargetPc1 && pc.equals(info.preTargetPc1)) {
                            setOwnerTid(tid, 'anchor_12c3e4');
                            logAnchor('anchor_12c3e4', details.context);
                            var retPc12c3e4 = ptr(details.context.lr);
                            armDynamicPage(pageBaseOf(retPc12c3e4), 'helper_12c3e4_return_page', {
                                ownerTid: traceState.ownerTid,
                                targetPc: retPc12c3e4,
                                windowStart: retPc12c3e4.sub(0x10),
                                windowEnd: retPc12c3e4.add(0x40),
                                logOnlyInWindow: true,
                            });
                        }
                        if (info.preTargetPc2 && pc.equals(info.preTargetPc2)) {
                            logAnchor('anchor_12c428', details.context);
                        }
                        if (info.targetPc && pc.equals(info.targetPc)) {
                            sequence.helper12c68cSeen = true;
                            setOwnerTid(tid, 'anchor_12c68c');
                            logAnchor('anchor_12c68c', details.context);
                            if (info.nextPages) {
                                for (var ni = 0; ni < info.nextPages.length; ni++) {
                                    var nextPage = info.nextPages[ni];
                                    var nextInfo2 = tracked[nextPage.toString()];
                                    if (nextInfo2 && !nextInfo2.armed) {
                                        nextInfo2.ownerTid = traceState.ownerTid;
                                        nextInfo2.armed = true;
                                        Memory.protect(nextInfo2.base, PAGE_SIZE, 'r--');
                                        console.log('[CAPTURE] [NMSSPAGE] activated next kind=' + nextInfo2.kind +
                                            ' page=' + nextInfo2.base +
                                            ' after=' + info.kind);
                                    }
                                }
                            }
                        }
                    }
                    if (info.kind === 'helper_12c68c_call_1339xx_page') {
                        if (info.targetPc1 && pc.equals(info.targetPc1)) {
                            logAnchor('anchor_133908', details.context);
                        }
                        if (info.targetPc2 && pc.equals(info.targetPc2)) {
                            logAnchor('anchor_1339a0', details.context);
                        }
                        if (info.targetPc3 && pc.equals(info.targetPc3)) {
                            logAnchor('anchor_133f20', details.context);
                        }
                    }
                    if (info.kind === 'helper_12c3e4_return_page' &&
                        info.targetPc && pc.equals(info.targetPc)) {
                        logAnchor('anchor_12c3e4_return', details.context);
                        var nextInfoFrom12c3e4 = tracked[helperBCallPage3.toString()];
                        if (nextInfoFrom12c3e4 && !nextInfoFrom12c3e4.armed) {
                            nextInfoFrom12c3e4.ownerTid = traceState.ownerTid;
                            nextInfoFrom12c3e4.armed = true;
                            Memory.protect(nextInfoFrom12c3e4.base, PAGE_SIZE, 'r--');
                            console.log('[CAPTURE] [NMSSPAGE] activated next kind=' + nextInfoFrom12c3e4.kind +
                                ' page=' + nextInfoFrom12c3e4.base +
                                ' after=anchor_12c3e4_return');
                        }
                    }
                    if (info.kind === 'helper_1549ac_return_page' &&
                        info.targetPc && pc.equals(info.targetPc)) {
                        logAnchor('anchor_1549ac_return', details.context);
                        installExact1549acContHook(helper1549acCont, traceState.ownerTid);
                    }
                    if (info.kind === 'helper_1549ac_cont_return_page' &&
                        info.targetPc && pc.equals(info.targetPc)) {
                        logAnchor('anchor_1549ac_cont_return', details.context);
                    }
                    if (info.kind === 'helper_154a6c_return_page' &&
                        info.targetPc && pc.equals(info.targetPc)) {
                        logAnchor('anchor_154a6c_return', details.context);
                        installExact140358Hook(helper154a6cContRet, traceState.ownerTid);
                    }
                    if (info.kind === 'helper_154a6c_cont_return_page' &&
                        info.targetPc && pc.equals(info.targetPc)) {
                        logAnchor('anchor_154a6c_cont_return', details.context);
                        var artSavedCallerRet = null;
                        try {
                            artSavedCallerRet = ptr(details.context.x28).add(0xd8).readPointer();
                        } catch (e) {
                            console.log('[CAPTURE] [NMSSPAGE] art_cont_return read_saved_caller_ret error=' + e);
                        }
                        console.log('[CAPTURE] [NMSSPAGE] art_cont_return tid=' + tid +
                            ' x28=' + fmtPtr(details.context.x28) +
                            ' saved_caller_ret=' + fmtPtr(artSavedCallerRet) +
                            ' x19=' + fmtPtr(details.context.x19) +
                            ' x0=' + fmtPtr(details.context.x0));
                        if (artSavedCallerRet !== null) {
                            installExactArtQuickGenericJniSavedCallerPreHook(artSavedCallerRet.sub(0x8), traceState.ownerTid);
                            installExactArtQuickGenericJniSavedCallerHook(artSavedCallerRet, traceState.ownerTid);
                        }
                        if (artQuickGenericJniRet !== null) {
                            installExactArtQuickGenericJniRetHook(artQuickGenericJniRet, traceState.ownerTid);
                        }
                    }
                    if (info.kind === 'art_quick_generic_jni_saved_caller_return_page' &&
                        info.targetPc && pc.equals(info.targetPc)) {
                        logAnchor('anchor_art_quick_generic_jni_saved_caller_return', details.context);
                    }
                    if (info.kind === 'art_quick_generic_jni_ret_return_page' &&
                        info.targetPc && pc.equals(info.targetPc)) {
                        logAnchor('anchor_art_quick_generic_jni_ret_return', details.context);
                    }
                    Memory.protect(base, PAGE_SIZE, 'r-x');
                    rearmPageLater(base);
                    return true;
                } catch (e) {
                    console.log('[CAPTURE] [NMSSPAGE] handler error: ' + e);
                    return false;
                }
            });
            handlerInstalled = true;
        }

        armPage(corePage, 'core_body_page', {
            nextPage: helperPage,
        });
        if (!helperPage.equals(corePage)) {
            armPage(helperPage, 'helper_128eb4_page', {
                armed: false,
                targetPc: helperA,
                nextPage: helperBPage,
            });
        }
        if (!helperBPage.equals(corePage) && !helperBPage.equals(helperPage)) {
            armPage(helperBPage, 'helper_12c68c_page', {
                armed: false,
                allowedWindows: [
                    { start: helperB.sub(0x10), end: helperB.add(0x80) },
                    { start: helperBPre1.sub(0x10), end: helperBPre1.add(0x50) },
                    { start: helperBPre2.sub(0x10), end: helperBPre2.add(0x100) },
                    { start: helperBExact.sub(0x10), end: helperBExact.add(0x40) },
                ],
                logOnlyInWindow: true,
                baseTargetPc: helperB,
                preTargetPc1: helperBPre1,
                preTargetPc2: helperBPre2,
                targetPc: helperBExact,
                nextPages: [helperBCallPage1, helperBCallPage3],
            });
        }
        if (!helperBCallPage1.equals(corePage) && !helperBCallPage1.equals(helperPage) && !helperBCallPage1.equals(helperBPage)) {
            armPage(helperBCallPage1, 'helper_12c68c_call_1339xx_page', {
                armed: false,
                ownerScoped: true,
                allowedWindows: [
                    { start: helperBCall1.sub(0x10), end: helperBCall1.add(0x30) },
                    { start: helperBCall2.sub(0x10), end: helperBCall2.add(0x30) },
                    { start: helperBCall3Alt.sub(0x10), end: helperBCall3Alt.add(0x50) },
                ],
                logOnlyInWindow: true,
                targetPc1: helperBCall1,
                targetPc2: helperBCall2,
                targetPc3: helperBCall3Alt,
            });
        }
        if (!helperBCallPage3.equals(corePage) && !helperBCallPage3.equals(helperPage) && !helperBCallPage3.equals(helperBPage) && !helperBCallPage3.equals(helperBCallPage1)) {
            armPage(helperBCallPage3, 'helper_12c68c_call_8ddd0_page', {
                armed: false,
                ownerScoped: true,
                windowStart: helperBCall3.sub(0x10),
                windowEnd: helperBCall3.add(0x20),
                logOnlyInWindow: true,
                targetPc: helperBCall3,
                nextPages: [helperBCall3CalleePage1, helperBCall3CalleePage2],
            });
        }
        if (!helperBCall3CalleePage1.equals(corePage) &&
            !helperBCall3CalleePage1.equals(helperPage) &&
            !helperBCall3CalleePage1.equals(helperBPage) &&
            !helperBCall3CalleePage1.equals(helperBCallPage1) &&
            !helperBCall3CalleePage1.equals(helperBCallPage3)) {
            armPage(helperBCall3CalleePage1, 'helper_8ddd0_family_154x_page', {
                armed: false,
                ownerScoped: true,
                windowStart: helperBCall3Callee1Pre.sub(0x10),
                windowEnd: helperBCall3Callee1c.add(0x40),
                logOnlyInWindow: true,
                exact1549ac: helperBCall3Callee1Pre,
                exact154a6c: helperBCall3Callee1,
                exact154b18: helperBCall3Callee1b,
                exact154d14: helperBCall3Callee1c,
                nextPagesOn154b: [helperFamily17cPage],
                nextPagesOn154d: [helperFamily17cPage],
            });
        }
        if (!helperBCall3CalleePage2.equals(corePage) &&
            !helperBCall3CalleePage2.equals(helperPage) &&
            !helperBCall3CalleePage2.equals(helperBPage) &&
            !helperBCall3CalleePage2.equals(helperBCallPage1) &&
            !helperBCall3CalleePage2.equals(helperBCallPage3) &&
            !helperBCall3CalleePage2.equals(helperBCall3CalleePage1)) {
            armPage(helperBCall3CalleePage2, 'helper_8ddd0_call_17e848_page', {
                armed: false,
                ownerScoped: true,
                windowStart: helperBCall3Callee2.sub(0x10),
                windowEnd: helperBCall3Callee2.add(0x40),
                logOnlyInWindow: true,
                targetPc: helperBCall3Callee2,
                nextPages: [helperFamily17cPage, helper17e848CalleePage2],
            });
        }
        if (!helperFamily17cPage.equals(corePage) &&
            !helperFamily17cPage.equals(helperPage) &&
            !helperFamily17cPage.equals(helperBPage) &&
            !helperFamily17cPage.equals(helperBCallPage1) &&
            !helperFamily17cPage.equals(helperBCallPage3) &&
            !helperFamily17cPage.equals(helperBCall3CalleePage1) &&
            !helperFamily17cPage.equals(helperBCall3CalleePage2)) {
            armPage(helperFamily17cPage, 'helper_154x_call_17cff8_17d06c_page', {
                armed: false,
                ownerScoped: true,
                windowStart: helperFamily17c1.sub(0x10),
                windowEnd: helperFamily17c2.add(0x20),
                logOnlyInWindow: true,
            });
        }
        if (!helper17e848CalleePage2.equals(corePage) &&
            !helper17e848CalleePage2.equals(helperPage) &&
            !helper17e848CalleePage2.equals(helperBPage) &&
            !helper17e848CalleePage2.equals(helperBCallPage1) &&
            !helper17e848CalleePage2.equals(helperBCallPage3) &&
            !helper17e848CalleePage2.equals(helperBCall3CalleePage1) &&
            !helper17e848CalleePage2.equals(helperBCall3CalleePage2) &&
            !helper17e848CalleePage2.equals(helperFamily17cPage)) {
            armPage(helper17e848CalleePage2, 'helper_17e848_call_17d62c_page', {
                armed: false,
                ownerScoped: true,
                windowStart: helper17e848Callee2.sub(0x10),
                windowEnd: helper17e848Callee2.add(0x20),
                logOnlyInWindow: true,
            });
        }

        console.log('[CAPTURE] [NMSSPAGE] installed base=' + fmtPtr(mod.base) +
            ' core=' + fmtPtr(coreBody) +
            ' helper=' + fmtPtr(helperA) +
            ' helper_b=' + fmtPtr(helperB) +
            ' helper_b_pre_12c3e4=' + fmtPtr(helperBPre1) +
            ' helper_b_pre_12c428=' + fmtPtr(helperBPre2) +
            ' helper_b_exact=' + fmtPtr(helperBExact) +
            ' helper_b_call_133908=' + fmtPtr(helperBCall1) +
            ' helper_b_call_1339a0=' + fmtPtr(helperBCall2) +
            ' helper_b_call_133f20=' + fmtPtr(helperBCall3Alt) +
            ' helper_b_call_8ddd0=' + fmtPtr(helperBCall3) +
            ' helper_8ddd0_call_1549ac=' + fmtPtr(helperBCall3Callee1Pre) +
            ' helper_8ddd0_call_154a6c=' + fmtPtr(helperBCall3Callee1) +
            ' helper_1549ac_cont_79aac=' + fmtPtr(helper1549acCont) +
            ' helper_8ddd0_call_154b18=' + fmtPtr(helperBCall3Callee1b) +
            ' helper_8ddd0_call_154d14=' + fmtPtr(helperBCall3Callee1c) +
            ' helper_8ddd0_call_17e848=' + fmtPtr(helperBCall3Callee2) +
            ' helper_154x_call_17cff8=' + fmtPtr(helperFamily17c1) +
            ' helper_154x_call_17d06c=' + fmtPtr(helperFamily17c2) +
            ' helper_17e848_call_17cee4=' + fmtPtr(helper17e848Callee1) +
            ' helper_17e848_call_17d62c=' + fmtPtr(helper17e848Callee2) +
            (artQuickGenericJniRet !== null ? ' art_quick_generic_jni_ret=' + fmtPtr(artQuickGenericJniRet) : ''));
        return true;
    }

    try {
        globalThis.__nmssCorePageTraceCtl = {
            disarmAll: disarmAll,
            state: function () { return traceState; },
            pendingExactHooks: function () {
                return {
                    pre: traceState.exactArtQuickGenericJniSavedCallerPreHook !== null,
                    saved: traceState.exactArtQuickGenericJniSavedCallerHook !== null,
                    next: traceState.exactArtQuickGenericJniSavedCallerNextHook !== null,
                    ret: traceState.exactArtQuickGenericJniRetHook !== null,
                    cont140358: traceState.exact140358Hook !== null,
                    cont1549ac: traceState.exact1549acContHook !== null ||
                        traceState.exact1549acPostMemcpyHook !== null ||
                        traceState.exact1549acSavedReturnHook !== null ||
                        traceState.exact1549acSavedFollowHook !== null ||
                        traceState.exact1549acBranch141a2cHook !== null ||
                        traceState.exact1549acBranch141a34Hook !== null ||
                        traceState.exact1549acBranch141a3cHook !== null ||
                        traceState.exact1549acBranch141a50Hook !== null ||
                        traceState.exact1549acBranch143c30Hook !== null ||
                        traceState.exact1549acBranch143c34Hook !== null ||
                        traceState.exact1549acBranch141c60Hook !== null ||
                        traceState.exact1549acBranch141cbcHook !== null ||
                        traceState.exact1549acBranch141d64Hook !== null ||
                        traceState.stalkerActive,
                    closed: traceState.closed,
                    ownerTid: traceState.ownerTid,
                    stalkerThreadId: traceState.stalkerThreadId,
                    stalkerReason: traceState.stalkerReason,
                    stalkerEvents: traceState.stalkerEvents.length,
                };
            },
        };
        install();
    } catch (e) {
        console.log('[CAPTURE] [NMSSPAGE] install error: ' + e);
    }
})();
