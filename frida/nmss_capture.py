#!/usr/bin/env python3
"""
NMSS Capture Server — HTTP API wrapping frida CLI + Xerda.

Endpoints:
    GET  /status                  — session state
    GET  /call?c=<hex16>          — call getCertValue, return token
    GET  /prepare?c=<hex16>       — plain readiness preflight before mem/dynamic hooks
    GET  /translated/load         — load translated JIT ELF + map into the live Frida session
    GET  /translated/arm          — arm translated JIT dispatch for execute faults in the trapped JIT window
    GET  /translated/status       — translated JIT dispatch status
    GET  /translated/clear        — disable translated JIT dispatch
    GET  /dynamic/load            — load resident dynamic Aeon runtime into the live Frida session
    GET  /dynamic/arm             — arm dynamic exact-PC JIT dispatch for execute faults in the trapped JIT window
    GET  /dynamic/status          — dynamic JIT dispatch status
    GET  /dynamic/clear           — disable dynamic JIT dispatch
    GET  /capture?c=<hex16>       — call + capture JIT hash state to disk
    GET  /trace?c=<hex16>         — capture JIT hash state + run Aeon JIT trace
    POST /eval                    — evaluate arbitrary JS in the REPL
    GET  /relay?path=<file.js>    — load one or more JS files into the REPL
    POST /relay                   — load JS files into the REPL
    GET  /pull                    — pull latest capture from device to host

Usage:
    python3 frida/nmss_capture.py [--port 8877] [--attach] [--relay-js path.js ...]

Device prerequisite:
    Run `/data/local/tmp/xerda-server` on the device. This bridge forwards
    host `localhost:27043` to that exact on-device binary on device port `27042`.
"""

import subprocess, os, sys, time, json, threading, re, argparse, logging, shlex
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

XERDA_HOST_PORT = 27043
XERDA_DEVICE_PORT = 27042
XERDA_SERVER_PATH = "/data/local/tmp/xerda-server"
PACKAGE = "com.netmarble.thered"
ADB = ["adb", "-s", "localhost:5555"]
DEVICE_DIR = "/data/local/tmp/aeon_capture"
TRANSLATED_DEVICE_ELF = "/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.elf"
TRANSLATED_DEVICE_MAP = "/data/local/tmp/jit_exec_alias_0x9b5fe000.translated.map.json.compact.blockmap.jsonl"
DYNAMIC_DEVICE_LIB = "/data/user/0/com.netmarble.thered/files/libaeon_instrument.so"
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DIR = os.path.join(REPO_ROOT, "capture", "jit_hash")
TRACE_PATH = os.path.join(OUTPUT_DIR, "trace.bin")
DYNAMIC_TRACE_DEVICE_PATH = "/data/user/0/com.netmarble.thered/files/aeon_dyn_trace.jsonl"
DYNAMIC_TRACE_HOST_PATH = os.path.join(OUTPUT_DIR, "dynamic_trace.jsonl")
READY_CHALLENGE = "6BA4D60738580083"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("capture")

AGENT_JS = r"""
'use strict';
var CERT_FN_OFFSET = 0x17ded0;
var RESOLVE_ENCODER_OFFSET = 0x209dc4;
var BLR_X8_OFFSET = 0x20b548;
var ROOT_DIR = '__DEVICE_DIR__';
var DIR = ROOT_DIR + '/jit_hash';
var ANALYSIS_BASE = 0x10000000;
var CERT_ENCODER_ENTRY_OFFSET = 0x10828c;
var TRACE_RANGE_START = 0x10828c;
var TRACE_RANGE_END = 0x18a000;
var JIT_IMAGE_SIZE = 0x200000;
var USE_DYNAMIC_JIT_HOOKS = false;
var JIT_CAPTURE_POINTS = [
    { label: 'hash_dispatch', offset: 0x1627d8, trace_start: TRACE_RANGE_START, trace_end: TRACE_RANGE_END },
    { label: 'resume_point', offset: 0x1629a8, trace_start: TRACE_RANGE_START, trace_end: TRACE_RANGE_END },
    { label: 'helper_chain', offset: 0x177740, trace_start: TRACE_RANGE_START, trace_end: TRACE_RANGE_END },
    { label: 'decision_point', offset: 0x1777f0, trace_start: TRACE_RANGE_START, trace_end: TRACE_RANGE_END },
    { label: 'hash_entry', offset: 0x177ebc, trace_start: TRACE_RANGE_START, trace_end: TRACE_RANGE_END }
];
var EXTRA_POINTERS = [
    { label: 'x21', size: 0x1000, getter: function(ctx) { return ctx.x21; } },
    { label: 'x22', size: 0x1000, getter: function(ctx) { return ctx.x22; } }
];

var libc = Process.getModuleByName('libc.so');
var _open = new NativeFunction(libc.getExportByName('open'),'int',['pointer','int','int']);
var _write = new NativeFunction(libc.getExportByName('write'),'long',['int','pointer','long']);
var _close = new NativeFunction(libc.getExportByName('close'),'int',['int']);
var _mkdir = new NativeFunction(libc.getExportByName('mkdir'),'int',['pointer','int']);
var _unlink = new NativeFunction(libc.getExportByName('unlink'),'int',['pointer']);
var ZERO_PAGE = Memory.alloc(0x4000);

function openWrite(path) {
    return _open(Memory.allocUtf8String(path), 0x241, 0x1a4);
}
function writeFile(path, ab) {
    var fd = openWrite(path);
    if (fd < 0) { console.log('[!] open ' + path + ' fail'); return false; }
    var tmp = Memory.alloc(ab.byteLength);
    tmp.writeByteArray(new Uint8Array(ab));
    _write(fd, tmp, ab.byteLength);
    _close(fd);
    return true;
}
function writeRange(path, addr, size) {
    var fd = openWrite(path);
    if (fd < 0) { console.log('[!] open ' + path + ' fail'); return false; }
    var chunkSize = 0x4000;
    for (var off = 0; off < size; off += chunkSize) {
        var chunk = Math.min(chunkSize, size - off);
        var data = safeRead(ptr(addr).add(off), chunk);
        if (data !== null) {
            var tmp = Memory.alloc(chunk);
            tmp.writeByteArray(new Uint8Array(data));
            _write(fd, tmp, chunk);
        } else {
            _write(fd, ZERO_PAGE, chunk);
        }
    }
    _close(fd);
    return true;
}
function writeStr(path, s) {
    var fd = openWrite(path);
    if (fd < 0) return false;
    _write(fd, Memory.allocUtf8String(s), s.length);
    _close(fd);
    return true;
}
function safeRead(a,sz) { try { return ptr(a).readByteArray(sz); } catch(e) { return null; } }
function isReadablePointer(addr) { try { ptr(addr).readU8(); return true; } catch(e) { return false; } }
function unlinkIfExists(path) { try { _unlink(Memory.allocUtf8String(path)); } catch(e) {} }
function readTpidrEl0() {
    var c = Memory.alloc(4096);
    c.writeU32(0xD53BD040);
    c.add(4).writeU32(0xD65F03C0);
    Memory.protect(c, 4096, 'r-x');
    return new NativeFunction(c, 'pointer', [])();
}

var nmsscr_base = null;
var hookInstalled = false;
var captureNext = false;
var pendingChallenge = '';
var jitMod = null;
var jitHookBase = null;
var jitHookState = {};

function findNmsscr() {
    var ranges = Process.enumerateRanges('r-x');
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        if (r.size < 0x200000) continue;
        try { if ((r.base.add(CERT_FN_OFFSET).readU32() >>> 24) === 0xa9) return r.base; } catch(e) {}
    }
    return null;
}

function findExecRange(addr) {
    var p = ptr(addr);
    var ranges = Process.enumerateRanges('r-x');
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        if (p.compare(r.base) >= 0 && p.compare(r.base.add(r.size)) < 0) return r;
    }
    return null;
}

function makePseudoModule(base, size, source, range) {
    var meta = {
        base: ptr(base),
        size: size,
        name: 'jit_anon',
        path: '[jit-anon]',
        source: source
    };
    if (range !== null) {
        meta.range_base = range.base;
        meta.range_size = range.size;
    }
    return meta;
}

function scoreJitBase(base) {
    var hits = 0;
    var offsets = [CERT_ENCODER_ENTRY_OFFSET, TRACE_RANGE_START, 0x177ebc];
    var p = ptr(base);
    for (var i = 0; i < offsets.length; i++) {
        var data = safeRead(p.add(offsets[i]), 4);
        if (data !== null) hits++;
    }
    return hits;
}

function inferJitModule(target, source) {
    var p = ptr(target);
    var mod = Process.findModuleByAddress(p);
    if (mod !== null) {
        if (nmsscr_base !== null && mod.base.equals(nmsscr_base)) return null;
        if (mod.name !== 'libnmsssa.so') return mod;
    }

    var execRange = findExecRange(p);
    var guessedBase = p.sub(CERT_ENCODER_ENTRY_OFFSET);
    var score = scoreJitBase(guessedBase);
    if (score >= 2) {
        console.log('[CAPTURE] inferred jit base=' + guessedBase + ' score=' + score + ' source=' + source +
                    ' target=' + p + (execRange ? ' rx=' + execRange.base + '+0x' + execRange.size.toString(16) : ''));
        return makePseudoModule(guessedBase, JIT_IMAGE_SIZE, source, execRange);
    }

    if (execRange !== null) {
        var rxScore = scoreJitBase(execRange.base);
        console.log('[CAPTURE] adopt miss source=' + source + ' target=' + p +
                    ' guessed=' + guessedBase + ' score=' + score +
                    ' rx=' + execRange.base + '+0x' + execRange.size.toString(16) +
                    ' rxScore=' + rxScore);
        if (rxScore >= 2) {
            return makePseudoModule(execRange.base, Math.max(execRange.size, JIT_IMAGE_SIZE), source + ':rx', execRange);
        }
    } else {
        console.log('[CAPTURE] adopt miss source=' + source + ' target=' + p + ' guessed=' + guessedBase + ' score=' + score + ' rx=null');
    }

    return null;
}

function maybeAdoptJit(target, source) {
    try {
        if (target === null || ptr(target).isNull()) return null;
        var p = ptr(target);
        if (jitMod !== null && p.compare(jitMod.base) >= 0 && p.compare(jitMod.base.add(jitMod.size)) < 0) return jitMod;
        var mod = inferJitModule(target, source);
        if (mod === null) return null;
        jitMod = mod;
        if (jitHookBase !== null && jitHookBase.equals(mod.base)) return mod;
        jitHookBase = mod.base;
        console.log('[CAPTURE] jit=' + mod.base + ' size=' + mod.size + ' source=' + source + ' name=' + mod.name);
        if (USE_DYNAMIC_JIT_HOOKS) installJitHooks(mod);
        return mod;
    } catch (e) {
        console.log('[CAPTURE] jit adopt fail: ' + e);
        return null;
    }
}

function clearOutput() {
    var names = ['snapshot.json', 'module.bin', 'stack.bin', 'tls.bin', 'x21.bin', 'x22.bin'];
    for (var i = 0; i < 8; i++) names.push('arg_x' + i + '.bin');
    names.forEach(function(name) { unlinkIfExists(DIR + '/' + name); });
}

function capturePointer(regions, label, addr, size, modBase, modEnd, stackStart, stackEnd) {
    var p = ptr(addr);
    if (p.isNull() || !isReadablePointer(p)) return;
    if (p.compare(modBase) >= 0 && p.compare(modEnd) < 0) return;
    if (p.compare(stackStart) >= 0 && p.compare(stackEnd) < 0) return;
    var data = safeRead(p, size);
    if (data === null) return;
    if (!writeFile(DIR + '/' + label + '.bin', data)) return;
    regions.push({address:p.toString(), size:data.byteLength, file:label + '.bin', label:label});
    console.log('[CAPTURE] ' + label + ' ' + data.byteLength);
}

function captureJitState(ctx, mod, point) {
    console.log('[CAPTURE] === WRITING JIT SNAPSHOT ===');
    _mkdir(Memory.allocUtf8String(ROOT_DIR), 0x1ff);
    _mkdir(Memory.allocUtf8String(DIR), 0x1ff);
    clearOutput();

    var regs = {x:[], sp:ctx.sp.toString(), pc:ctx.pc.toString(), tpidr_el0:'0x0'};
    for (var i = 0; i < 29; i++) regs.x.push(ctx['x' + i].toString());
    regs.x.push(ctx.fp.toString());
    regs.x.push(ctx.lr.toString());
    if (point.entry_pc !== undefined) regs.pc = ptr(point.entry_pc).toString();
    if (point.entry_lr !== undefined) regs.x[30] = ptr(point.entry_lr).toString();
    try { regs.tpidr_el0 = readTpidrEl0().toString(); } catch (e) {}

    if (!writeRange(DIR + '/module.bin', mod.base, mod.size)) {
        console.log('[CAPTURE] module dump failed');
        return;
    }
    console.log('[CAPTURE] module.bin ' + mod.size);

    var regions = [
        {address:mod.base.toString(), size:mod.size, file:'module.bin', label:'module'}
    ];
    var stackStart = ctx.sp.sub(0x8000);
    var stackSize = 0x10000;
    var stackEnd = stackStart.add(stackSize);
    var stackData = safeRead(stackStart, stackSize);
    if (stackData !== null && writeFile(DIR + '/stack.bin', stackData)) {
        regions.push({address:stackStart.toString(), size:stackData.byteLength, file:'stack.bin', label:'stack'});
        console.log('[CAPTURE] stack ' + stackData.byteLength);
    }
    var tls = ptr(regs.tpidr_el0);
    var tlsData = safeRead(tls, 0x200);
    if (!tls.isNull() && tlsData !== null && writeFile(DIR + '/tls.bin', tlsData)) {
        regions.push({address:tls.toString(), size:tlsData.byteLength, file:'tls.bin', label:'tls'});
        console.log('[CAPTURE] tls ' + tlsData.byteLength);
    }

    var modEnd = mod.base.add(mod.size);
    for (var j = 0; j < 8; j++) {
        capturePointer(regions, 'arg_x' + j, ctx['x' + j], 0x4000, mod.base, modEnd, stackStart, stackEnd);
    }
    EXTRA_POINTERS.forEach(function(spec) {
        capturePointer(regions, spec.label, spec.getter(ctx), spec.size, mod.base, modEnd, stackStart, stackEnd);
    });

    writeStr(DIR + '/snapshot.json', JSON.stringify({
        function_name: point.label,
        trigger_function: 'nmssCoreGetCertValue',
        challenge: pendingChallenge,
        module_name: mod.name,
        module_path: mod.path,
        module_base: mod.base.toString(),
        target_offset: point.offset_text ? point.offset_text : ('0x' + point.offset.toString(16)),
        jit_base: mod.base.toString(),
        analysis_base: '0x10000000',
        code_range_start: point.trace_start !== undefined ? mod.base.add(point.trace_start).toString() : null,
        code_range_end: point.trace_end !== undefined ? mod.base.add(point.trace_end).toString() : null,
        registers: regs,
        regions: regions,
        timestamp: new Date().toISOString(),
        pid: Process.id,
        arch: Process.arch
    }, null, 2));
    console.log('[CAPTURE] SNAPSHOT DONE label=' + point.label + ' pc=' + ctx.pc);
}

function installJitHooks(mod) {
    JIT_CAPTURE_POINTS.forEach(function(point) {
        var addr = mod.base.add(point.offset);
        if (jitHookState[addr.toString()]) return;
        if (safeRead(addr, 4) === null) {
            console.log('[CAPTURE] skip hook ' + point.label + '@' + addr + ' unreadable');
            return;
        }
        console.log('[CAPTURE] hook ' + point.label + '@' + addr);
        try {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    console.log('[CAPTURE] hit ' + point.label + ' pc=' + this.context.pc);
                    if (!captureNext) return;
                    captureNext = false;
                    captureJitState(this.context, mod, point);
                }
            });
            jitHookState[addr.toString()] = true;
        } catch (e) {
            console.log('[CAPTURE] hook fail ' + point.label + '@' + addr + ' ' + e);
        }
    });
}

function setupHook() {
    if (hookInstalled) return;
    nmsscr_base = findNmsscr();
    if (!nmsscr_base) return;
    hookInstalled = true;

    console.log('[CAPTURE] nmsscr=' + nmsscr_base + ' hook=jit_hash');

    Interceptor.attach(nmsscr_base.add(RESOLVE_ENCODER_OFFSET), {
        onLeave: function(retval) {
            var mod = maybeAdoptJit(retval, 'sub_209dc4');
            if (captureNext) console.log('[CAPTURE] resolve_encoder captureNext retval=' + retval + ' mod=' + (mod ? mod.base : 'null'));
            if (!captureNext || mod === null || ptr(retval).isNull()) return;
            captureNext = false;
            var entryOffset = parseInt(ptr(retval).sub(mod.base).toString());
            if (!isFinite(entryOffset)) entryOffset = CERT_ENCODER_ENTRY_OFFSET;
            captureJitState(this.context, mod, {
                label: 'cert_entry',
                offset: entryOffset,
                offset_text: '0x' + entryOffset.toString(16),
                trace_start: TRACE_RANGE_START,
                trace_end: TRACE_RANGE_END,
                entry_pc: retval,
                entry_lr: nmsscr_base.add(BLR_X8_OFFSET + 4)
            });
        }
    });

    Interceptor.attach(nmsscr_base.add(BLR_X8_OFFSET), {
        onEnter: function(args) {
            var mod = maybeAdoptJit(this.context.x8, 'blr_x8');
            if (captureNext) console.log('[CAPTURE] blr_x8 captureNext x8=' + this.context.x8 + ' mod=' + (mod ? mod.base : 'null'));
            if (!captureNext || mod === null) return;
            captureNext = false;
            var entryOffset = parseInt(ptr(this.context.x8).sub(mod.base).toString());
            if (!isFinite(entryOffset)) entryOffset = CERT_ENCODER_ENTRY_OFFSET;
            captureJitState(this.context, mod, {
                label: 'cert_entry',
                offset: entryOffset,
                offset_text: '0x' + entryOffset.toString(16),
                trace_start: TRACE_RANGE_START,
                trace_end: TRACE_RANGE_END,
                entry_pc: this.context.x8,
                entry_lr: nmsscr_base.add(BLR_X8_OFFSET + 4)
            });
        }
    });
}

[12,18,24,30].forEach(function(t){setTimeout(function(){Java.perform(function(){try{Java.use("java.lang.Runtime").getRuntime().exec("input keyevent 66");}catch(e){}});},t*1000);});

function resolveAppLoader() {
    var loader = null;
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var app = ActivityThread.currentApplication();
        if (app) loader = app.getClassLoader();
        if (!loader) {
            var at = ActivityThread.currentActivityThread();
            if (at) {
                var app2 = at.getApplication();
                if (app2) loader = app2.getClassLoader();
            }
        }
    } catch (e) {}
    return loader;
}

var nmssLifecycle = {
    hooks_installed: false,
    game_oncreate: 0,
    game_onresume: 0,
    nmss_init: 0,
    nmss_resume: 0,
    nmss_last_error: null,
    last_activity_class: null,
    last_instance_source: null,
    last_prepare_source: null,
};

function nowIso() {
    return (new Date()).toISOString();
}

function noteLifecycle(key, extra) {
    try {
        nmssLifecycle[key] = (nmssLifecycle[key] || 0) + 1;
        nmssLifecycle.last_event = key;
        nmssLifecycle.last_event_at = nowIso();
        if (extra) {
            Object.keys(extra).forEach(function (name) {
                nmssLifecycle[name] = extra[name];
            });
        }
        console.log('[CAPTURE] lifecycle ' + key + ' ' + JSON.stringify(extra || {}));
    } catch (e) {}
}

function installLifecycleHooks() {
    if (nmssLifecycle.hooks_installed) return true;
    return withAppLoader(function () {
        try {
            var GameActivity = Java.use('com.epicgames.unreal.GameActivity');
            try {
                var onCreate = GameActivity.onCreate.overload('android.os.Bundle');
                onCreate.implementation = function (bundle) {
                    noteLifecycle('game_oncreate', { activity_class: this.$className });
                    nmssLifecycle.last_activity_class = this.$className;
                    return onCreate.call(this, bundle);
                };
            } catch (e) {}
            try {
                var onResume = GameActivity.onResume.overload();
                onResume.implementation = function () {
                    noteLifecycle('game_onresume', { activity_class: this.$className });
                    nmssLifecycle.last_activity_class = this.$className;
                    return onResume.call(this);
                };
            } catch (e) {}
        } catch (e) {
            nmssLifecycle.nmss_last_error = 'GameActivity hook ERR:' + e;
        }
        try {
            var NmssSa = Java.use('nmss.app.NmssSa');
            try {
                var init2 = NmssSa.init.overload('android.app.Activity', 'nmss.app.NmssSa$DetectCallBack');
                init2.implementation = function (activity, callback) {
                    noteLifecycle('nmss_init', {
                        activity_class: activity ? activity.$className : 'null',
                        has_callback: callback ? true : false
                    });
                    nmssLifecycle.last_activity_class = activity ? activity.$className : nmssLifecycle.last_activity_class;
                    return init2.call(this, activity, callback);
                };
            } catch (e) {}
            try {
                var init3 = NmssSa.init.overload('android.app.Activity', 'nmss.app.NmssSa$DetectCallBack', 'java.lang.String');
                init3.implementation = function (activity, callback, extra) {
                    noteLifecycle('nmss_init', {
                        activity_class: activity ? activity.$className : 'null',
                        has_callback: callback ? true : false,
                        extra: extra ? String(extra) : ''
                    });
                    nmssLifecycle.last_activity_class = activity ? activity.$className : nmssLifecycle.last_activity_class;
                    return init3.call(this, activity, callback, extra);
                };
            } catch (e) {}
            try {
                var onResumeNmss = NmssSa.onResume.overload();
                onResumeNmss.implementation = function () {
                    noteLifecycle('nmss_resume');
                    return onResumeNmss.call(this);
                };
            } catch (e) {}
        } catch (e) {
            nmssLifecycle.nmss_last_error = 'NmssSa hook ERR:' + e;
        }
        nmssLifecycle.hooks_installed = true;
        console.log('[CAPTURE] lifecycle hooks installed');
        return true;
    });
}

function getCurrentGameActivity() {
    return withAppLoader(function () {
        try {
            var GameActivity = Java.use('com.epicgames.unreal.GameActivity');
            var current = GameActivity._activity.value;
            if (current) return current;
        } catch (e) {}
        var found = null;
        try {
            Java.choose('com.epicgames.unreal.GameActivity', {
                onMatch: function (instance) {
                    found = instance;
                },
                onComplete: function () {}
            });
        } catch (e) {}
        return found;
    });
}

function waitForGameActivity(timeoutMs) {
    return withAppLoader(function () {
        var Thread = Java.use('java.lang.Thread');
        var deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            var activity = getCurrentGameActivity();
            if (activity) {
                nmssLifecycle.last_activity_class = activity.$className;
                return activity;
            }
            Thread.sleep(100);
        }
        return null;
    });
}

function withAppLoader(fn) {
    var previous = null;
    var changed = false;
    try {
        var loader = resolveAppLoader();
        if (loader) {
            previous = Java.classFactory.loader;
            Java.classFactory.loader = loader;
            changed = true;
        }
        return fn();
    } finally {
        if (changed) {
            Java.classFactory.loader = previous;
        }
    }
}

function getNmssInstance() {
    return withAppLoader(function () {
        var NmssSa = Java.use("nmss.app.NmssSa");
        try {
            var inst = NmssSa.getInstObj();
            if (inst) {
                nmssLifecycle.last_instance_source = 'getInstObj';
                return inst;
            }
        } catch (e) {
            nmssLifecycle.nmss_last_error = 'getInstObj ERR:' + e;
        }
        var found = null;
        try {
            Java.choose('nmss.app.NmssSa', {
                onMatch: function (instance) {
                    if (found === null) found = instance;
                },
                onComplete: function () {}
            });
        } catch (e) {
            nmssLifecycle.nmss_last_error = 'choose ERR:' + e;
        }
        if (found) {
            nmssLifecycle.last_instance_source = 'Java.choose';
            return found;
        }
        return null;
    });
}

function getAppClass(name) {
    return withAppLoader(function () {
        return Java.use(name);
    });
}

function nmssStateSnapshot(inst) {
    function stringifyValue(value) {
        try { return value === null ? 'null' : String(value); } catch (e) { return '<err:' + e + '>'; }
    }
    if (!inst) return { inst: false };
    function readField(name) {
        try { return stringifyValue(inst[name].value); } catch (e) { return '<err>'; }
    }
    return {
        inst: true,
        m_bAppExit: readField('m_bAppExit'),
        m_bIsRPExists: readField('m_bIsRPExists'),
        m_nCode: readField('m_nCode'),
        m_strMsg: readField('m_strMsg'),
        m_activity: (function () {
            try {
                var a = inst.m_activity.value;
                return a ? a.$className : 'null';
            } catch (e) {
                return '<err>';
            }
        })(),
        m_detectCallBack: (function () {
            try {
                var cb = inst.m_detectCallBack.value;
                return cb ? cb.$className : 'null';
            } catch (e) {
                return '<err>';
            }
        })(),
    };
}

function prepareCertReadyCore(challenge, readyChallenge) {
    var requestedChallenge = challenge || '6BA4D60738580083';
    var warmChallenge = readyChallenge || '6BA4D60738580083';
    var result = {
        ok: false,
        challenge: requestedChallenge,
        ready_challenge: warmChallenge,
        token: '',
        token_len: 0,
        bridge_init: 'skip',
        load_cr: 'skip',
        on_resume: 'skip',
        run: 'skip',
        state_before: null,
        state_after: null,
        error: null,
    };
    Java.performNow(function () {
        try {
            var waitedActivity = waitForGameActivity(5000);
            if (waitedActivity) {
                result.activity_class = waitedActivity.$className;
            }
            var NmssSa = getAppClass("nmss.app.NmssSa");
            var Bridge = null;
            try { Bridge = getAppClass("nmss.app.SecurityUnrealBridge"); } catch (e) {}
            var inst = getNmssInstance();
            result.instance_source = nmssLifecycle.last_instance_source;
            result.state_before = nmssStateSnapshot(inst);
            if (!inst) {
                result.error = 'NO_INSTANCE';
                result.lifecycle = JSON.parse(JSON.stringify(nmssLifecycle));
                return;
            }
            var activity = null;
            try { activity = inst.m_activity.value; } catch (e) {}
            if (!activity) activity = waitedActivity;
            var shouldInit = false;
            try { shouldInit = !inst.m_activity.value && !!activity; } catch (e) { shouldInit = !!activity; }
            if (Bridge && activity && shouldInit) {
                try {
                    var bridge = Bridge.$new();
                    bridge.init(activity);
                    result.bridge_init = 'ok';
                } catch (e) {
                    result.bridge_init = 'ERR:' + e;
                }
            } else if (activity) {
                result.bridge_init = 'skip_existing_activity';
            }
            result.load_cr = 'deferred';
            try { inst.onResume(); result.on_resume = 'ok'; } catch (e) { result.on_resume = 'ERR:' + e; }
            try { inst.run(warmChallenge); result.run = 'ok'; } catch (e) { result.run = 'ERR:' + e; }
            try {
                var token = inst.getCertValue(requestedChallenge);
                result.token = token ? token.toString() : '';
                result.token_len = result.token.length;
                result.ok = result.token_len > 0;
            } catch (e) {
                result.error = 'getCertValue ERR:' + e;
            }
            result.state_after = nmssStateSnapshot(inst);
            result.lifecycle = JSON.parse(JSON.stringify(nmssLifecycle));
            result.prepare_source = nmssLifecycle.last_instance_source || 'unknown';
        } catch (outer) {
            result.error = 'prepareCertReady ERR:' + outer;
            result.lifecycle = JSON.parse(JSON.stringify(nmssLifecycle));
        }
    });
    console.log('[CAPTURE] prepareCertReady challenge=' + requestedChallenge +
                ' ready=' + warmChallenge +
                ' token_len=' + result.token_len +
                ' bridge_init=' + result.bridge_init +
                ' load_cr=' + String(result.load_cr) +
                ' on_resume=' + result.on_resume +
                ' run=' + result.run);
    return JSON.stringify(result);
}

rpc.exports = {
    ping: function() {
        return JSON.stringify({
            hook:hookInstalled,
            nmsscr_base:nmsscr_base?nmsscr_base.toString():null,
            jit_base:jitMod?jitMod.base.toString():null,
            jit_size:jitMod?jitMod.size:0,
            target:'jit_hash',
            trace_range:'0x' + TRACE_RANGE_START.toString(16) + '..0x' + TRACE_RANGE_END.toString(16),
            capture_points:JIT_CAPTURE_POINTS.map(function(p) { return p.label + '@0x' + p.offset.toString(16); })
        });
    },
    callCert: function(c) {
        var r=null; Java.performNow(function(){try{var i=getNmssInstance();
        if(!i){r='NO_INSTANCE';return;} r=i.getCertValue(c); if(r)r=r.toString();}catch(e){r='ERR:'+e;}}); return r||'';
    },
    captureCert: function(c) {
        setupHook();
        console.log('[CAPTURE] captureCert arm challenge=' + c);
        captureNext=true;
        pendingChallenge=c;
        var r=null; Java.performNow(function(){try{var i=getNmssInstance();
        if(!i){r='NO_INSTANCE';return;} r=i.getCertValue(c); if(r)r=r.toString();}catch(e){r='ERR:'+e;}}); return r||'';
    },
    prepareCertReady: function(challenge, readyChallenge) {
        return prepareCertReadyCore(challenge, readyChallenge);
    },
    nmssLifecycleState: function() {
        return JSON.stringify(nmssLifecycle);
    },
};
console.log('[CAPTURE] Agent loaded, RPC ready');
""".replace("__DEVICE_DIR__", DEVICE_DIR)

MINIMAL_AGENT_JS = r"""
'use strict';

function resolveAppLoader() {
    var loader = null;
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var app = ActivityThread.currentApplication();
        if (app) loader = app.getClassLoader();
        if (!loader) {
            var at = ActivityThread.currentActivityThread();
            if (at) {
                var app2 = at.getApplication();
                if (app2) loader = app2.getClassLoader();
            }
        }
    } catch (e) {}
    return loader;
}

function withAppLoader(fn) {
    var previous = null;
    var changed = false;
    try {
        var loader = resolveAppLoader();
        if (loader) {
            previous = Java.classFactory.loader;
            Java.classFactory.loader = loader;
            changed = true;
        }
        return fn();
    } finally {
        if (changed) Java.classFactory.loader = previous;
    }
}

function getCurrentGameActivity() {
    return withAppLoader(function () {
        try {
            var GameActivity = Java.use('com.epicgames.unreal.GameActivity');
            var current = GameActivity._activity.value;
            if (current) return current;
        } catch (e) {}
        var found = null;
        try {
            Java.choose('com.epicgames.unreal.GameActivity', {
                onMatch: function (instance) {
                    if (found === null) found = instance;
                },
                onComplete: function () {}
            });
        } catch (e) {}
        return found;
    });
}

function waitForGameActivity(timeoutMs) {
    return withAppLoader(function () {
        var Thread = Java.use('java.lang.Thread');
        var deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            var activity = getCurrentGameActivity();
            if (activity) return activity;
            Thread.sleep(100);
        }
        return null;
    });
}

function getNmssInstance() {
    return withAppLoader(function () {
        var NmssSa = Java.use('nmss.app.NmssSa');
        try {
            var inst = NmssSa.getInstObj();
            if (inst) return { inst: inst, source: 'getInstObj' };
        } catch (e) {}
        var found = null;
        try {
            Java.choose('nmss.app.NmssSa', {
                onMatch: function (instance) {
                    if (found === null) found = instance;
                },
                onComplete: function () {}
            });
        } catch (e) {}
        return { inst: found, source: found ? 'Java.choose' : null };
    });
}

function nmssStateSnapshot(inst) {
    function stringifyValue(value) {
        try { return value === null ? 'null' : String(value); } catch (e) { return '<err:' + e + '>'; }
    }
    if (!inst) return { inst: false };
    function readField(name) {
        try { return stringifyValue(inst[name].value); } catch (e) { return '<err>'; }
    }
    return {
        inst: true,
        m_bAppExit: readField('m_bAppExit'),
        m_bIsRPExists: readField('m_bIsRPExists'),
        m_nCode: readField('m_nCode'),
        m_strMsg: readField('m_strMsg'),
        m_activity: (function () {
            try {
                var a = inst.m_activity.value;
                return a ? a.$className : 'null';
            } catch (e) {
                return '<err>';
            }
        })(),
        m_detectCallBack: (function () {
            try {
                var cb = inst.m_detectCallBack.value;
                return cb ? cb.$className : 'null';
            } catch (e) {
                return '<err>';
            }
        })(),
    };
}

function prepareCertReadyCore(challenge, readyChallenge) {
    var requestedChallenge = challenge || '6BA4D60738580083';
    var warmChallenge = readyChallenge || '6BA4D60738580083';
    var result = {
        ok: false,
        challenge: requestedChallenge,
        ready_challenge: warmChallenge,
        token: '',
        token_len: 0,
        bridge_init: 'skip',
        load_cr: 'deferred',
        on_resume: 'skip',
        run: 'skip',
        state_before: null,
        state_after: null,
        instance_source: null,
        activity_class: null,
        error: null,
    };
    Java.performNow(function () {
        try {
            var waitedActivity = waitForGameActivity(5000);
            if (waitedActivity) result.activity_class = waitedActivity.$className;
            var instanceInfo = getNmssInstance();
            var inst = instanceInfo.inst;
            result.instance_source = instanceInfo.source;
            result.state_before = nmssStateSnapshot(inst);
            if (!inst) {
                result.error = 'NO_INSTANCE';
                return;
            }
            var activity = null;
            try { activity = inst.m_activity.value; } catch (e) {}
            if (!activity) activity = waitedActivity;
            if (activity) result.bridge_init = 'skip_existing_activity';
            try { inst.onResume(); result.on_resume = 'ok'; } catch (e) { result.on_resume = 'ERR:' + e; }
            try { inst.run(warmChallenge); result.run = 'ok'; } catch (e) { result.run = 'ERR:' + e; }
            try {
                var token = inst.getCertValue(requestedChallenge);
                result.token = token ? token.toString() : '';
                result.token_len = result.token.length;
                result.ok = result.token_len > 0;
            } catch (e) {
                result.error = 'getCertValue ERR:' + e;
            }
            result.state_after = nmssStateSnapshot(inst);
        } catch (outer) {
            result.error = 'prepareCertReady ERR:' + outer;
        }
    });
    console.log('[CAPTURE] minimal prepareCertReady challenge=' + requestedChallenge +
                ' ready=' + warmChallenge +
                ' token_len=' + result.token_len +
                ' source=' + result.instance_source +
                ' on_resume=' + result.on_resume +
                ' run=' + result.run);
    return JSON.stringify(result);
}

rpc.exports = {
    ping: function() {
        return JSON.stringify({ target: 'minimal_ready' });
    },
    callCert: function(c) {
        var r = null;
        Java.performNow(function () {
            try {
                var info = getNmssInstance();
                if (!info.inst) { r = 'NO_INSTANCE'; return; }
                r = info.inst.getCertValue(c);
                if (r) r = r.toString();
            } catch (e) {
                r = 'ERR:' + e;
            }
        });
        return r || '';
    },
    prepareCertReady: function(challenge, readyChallenge) {
        return prepareCertReadyCore(challenge, readyChallenge);
    }
};
console.log('[CAPTURE] Minimal agent loaded, RPC ready');
"""


class FridaCLI:
    def __init__(self):
        self.proc = None
        self.alive = False
        self.ready = False
        self._lock = threading.Lock()
        self._lines = []
        self._rlines_lock = threading.Lock()
        self.loaded_scripts = []

    def start(self, spawn=True, pid=None, agent_source=None):
        subprocess.run(
            ADB + ["forward", f"tcp:{XERDA_HOST_PORT}", f"tcp:{XERDA_DEVICE_PORT}"],
            capture_output=True,
            timeout=5,
        )
        agent = "/tmp/aeon_capture_agent.js"
        with open(agent, "w") as f:
            f.write(agent_source if agent_source is not None else AGENT_JS)
        if spawn:
            cmd = ["frida", "-H", f"localhost:{XERDA_HOST_PORT}", "-f", PACKAGE, "-l", agent]
        else:
            cmd = ["frida", "-H", f"localhost:{XERDA_HOST_PORT}", "-p", str(pid), "-l", agent]
        log.info(f"Starting: {' '.join(cmd)}")
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.alive = True
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            while self.proc and self.proc.poll() is None:
                line = self.proc.stdout.readline()
                if not line: break
                line = line.rstrip('\n')
                if '[CAPTURE]' in line:
                    log.info(f"[JS] {line}")
                if 'RPC ready' in line or 'nmsscr=' in line:
                    self.ready = True
                with self._rlines_lock:
                    self._lines.append(line)
                    if len(self._lines) > 500:
                        self._lines = self._lines[-200:]
        except: pass
        self.alive = False
        log.warning("Frida process ended")

    def eval_rpc(self, expr, timeout=15):
        if not self.alive: return None
        with self._lock:
            with self._rlines_lock:
                self._lines.clear()
            tag = f"__AEON_RPC_RESULT__{time.time_ns()}__"
            wrapped = (
                "(function(){"
                "try {"
                f"var __aeon_r = eval({json.dumps(expr)});"
                "if (typeof __aeon_r === 'string') {"
                f"console.log('{tag}' + __aeon_r);"
                "} else if (__aeon_r === undefined) {"
                f"console.log('{tag}null');"
                "} else {"
                f"console.log('{tag}' + JSON.stringify(__aeon_r));"
                "}"
                "} catch (e) {"
                f"console.log('{tag}ERR:' + (e && e.stack ? e.stack : String(e)));"
                "}"
                "})()"
            )
            try:
                self.proc.stdin.write(wrapped + "\n")
                self.proc.stdin.flush()
            except:
                self.alive = False
                return None
            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(0.15)
                with self._rlines_lock:
                    snapshot = list(self._lines)
                for line in snapshot:
                    stripped = line.strip()
                    if stripped.startswith("'" + tag) and stripped.endswith("'"):
                        payload = stripped[1:-1].split(tag, 1)[1]
                    elif stripped.startswith('"' + tag) and stripped.endswith('"'):
                        payload = stripped[1:-1].split(tag, 1)[1]
                    elif stripped.startswith(tag):
                        payload = stripped.split(tag, 1)[1]
                    else:
                        continue
                    if payload.startswith("ERR:"):
                        return payload
                    return payload
            return None

    def kill(self):
        if self.proc:
            try: self.proc.terminate(); self.proc.wait(3)
            except:
                try: self.proc.kill()
                except: pass

    def load_script(self, path, timeout=20):
        resolved = resolve_relay_path(path)
        if not os.path.exists(resolved):
            return {"path": path, "resolved": resolved, "ok": False, "error": "file not found"}
        if not resolved.endswith(".js"):
            return {"path": path, "resolved": resolved, "ok": False, "error": "expected a .js file"}
        try:
            with open(resolved, "r", encoding="utf-8") as f:
                source = f.read()
        except OSError as exc:
            return {"path": path, "resolved": resolved, "ok": False, "error": str(exc)}

        expr = (
            "(function(){"
            "try{"
            f"Script.evaluate({json.dumps(resolved)}, {json.dumps(source)});"
            "return 'OK';"
            "}catch(e){"
            "return 'ERR:' + (e.stack || e);"
            "}"
            "})()"
        )
        result = self.eval_rpc(expr, timeout=timeout)
        entry = {
            "path": path,
            "resolved": resolved,
            "size": len(source.encode("utf-8")),
            "result": result,
            "ok": isinstance(result, str) and result == "OK",
        }
        if entry["ok"]:
            self.loaded_scripts.append({
                "path": resolved,
                "size": entry["size"],
                "loaded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            })
        elif result is None:
            entry["error"] = "no REPL response"
        else:
            entry["error"] = result
        return entry

    def load_scripts(self, paths, timeout=20):
        return [self.load_script(path, timeout=timeout) for path in paths]


bridge = FridaCLI()


def resolve_relay_path(path):
    if os.path.isabs(path):
        return os.path.abspath(path)
    candidates = [
        os.path.join(REPO_ROOT, path),
        os.path.join(os.getcwd(), path),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return os.path.abspath(candidate)
    return os.path.abspath(candidates[0])


def parse_relay_request(body, params):
    paths = list(params.get("path") or [])
    if body:
        stripped = body.strip()
        if stripped:
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                if isinstance(payload.get("path"), str):
                    paths.append(payload["path"])
                if isinstance(payload.get("paths"), list):
                    paths.extend([p for p in payload["paths"] if isinstance(p, str)])
            elif isinstance(payload, list):
                paths.extend([p for p in payload if isinstance(p, str)])
            else:
                paths.extend([line.strip() for line in stripped.splitlines() if line.strip()])
    deduped = []
    seen = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        deduped.append(path)
    return deduped


def parse_int_param(params, name, default, minimum=1, maximum=300):
    raw = (params.get(name) or [str(default)])[0]
    try:
        value = int(raw, 10)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def parse_bool_param(params, name, default=False):
    raw = (params.get(name) or [None])[0]
    if raw is None:
        return default
    return str(raw).strip().lower() not in ("", "0", "false", "no", "off")


def parse_thread_ids(params):
    values = []
    values.extend(params.get("thread") or [])
    values.extend(params.get("threads") or [])
    thread_ids = []
    for raw in values:
        for piece in str(raw).split(","):
            piece = piece.strip()
            if not piece:
                continue
            try:
                thread_id = int(piece, 10)
            except ValueError:
                continue
            if thread_id <= 0 or thread_id in thread_ids:
                continue
            thread_ids.append(thread_id)
    return thread_ids


def parse_json_result(value):
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(stripped)
            except Exception:
                return value
    return value


def prepare_cert_ready(challenge, ready_challenge=READY_CHALLENGE, timeout=60):
    expr = (
        f"rpc.exports.prepareCertReady("
        f"{json.dumps(challenge)}, {json.dumps(ready_challenge)})"
    )
    result = bridge.eval_rpc(expr, timeout=timeout) if bridge.alive else None
    return parse_json_result(result)


def pull_capture():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    files = {}
    names = ["snapshot.json", "module.bin", "stack.bin", "tls.bin", "x21.bin", "x22.bin"]
    names.extend([f"arg_x{i}.bin" for i in range(8)])
    for name in names:
        p = os.path.join(OUTPUT_DIR, name)
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
        subprocess.run(
            ADB + ["pull", f"{DEVICE_DIR}/jit_hash/{name}", p],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if os.path.exists(p):
            files[name] = os.path.getsize(p)
    try:
        os.remove(DYNAMIC_TRACE_HOST_PATH)
    except FileNotFoundError:
        pass
    subprocess.run(
        ADB + ["pull", DYNAMIC_TRACE_DEVICE_PATH, DYNAMIC_TRACE_HOST_PATH],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if os.path.exists(DYNAMIC_TRACE_HOST_PATH):
        files[os.path.basename(DYNAMIC_TRACE_HOST_PATH)] = os.path.getsize(DYNAMIC_TRACE_HOST_PATH)
    return files


MEMDUMP_DEVICE_DIR = f"{DEVICE_DIR}/memdump"
MEMDUMP_HOST_DIR = os.path.join(REPO_ROOT, "capture", "manual", f"process_snapshot_{time.strftime('%Y%m%d')}")


def pull_memdump(file_list_json=None):
    """Pull memdump files from device to host."""
    os.makedirs(MEMDUMP_HOST_DIR, exist_ok=True)
    files = {}
    if file_list_json:
        try:
            names = json.loads(file_list_json)
        except (json.JSONDecodeError, TypeError):
            names = []
    else:
        r = subprocess.run(
            ADB + ["shell", f"ls {MEMDUMP_DEVICE_DIR}/"],
            capture_output=True, text=True, timeout=10,
        )
        names = [n.strip() for n in r.stdout.strip().split("\n") if n.strip()]

    for name in names:
        src = f"{MEMDUMP_DEVICE_DIR}/{name}"
        dst = os.path.join(MEMDUMP_HOST_DIR, name)
        try:
            os.remove(dst)
        except FileNotFoundError:
            pass
        r = subprocess.run(
            ADB + ["pull", src, dst],
            capture_output=True, text=True, timeout=120,
        )
        if os.path.exists(dst):
            files[name] = os.path.getsize(dst)
            if files[name] > 1024 * 1024:
                log.info(f"  pulled {name}: {files[name] / (1024*1024):.1f}MB")
    return files


def trace_cmd(output_dir=OUTPUT_DIR, trace_path=TRACE_PATH):
    snapshot_path = os.path.join(output_dir, "snapshot.json")
    cmd = [
        "cargo",
        "run",
        "-q",
        "-p",
        "aeon-instrument",
        "--example",
        "frida_trace",
        "--",
        output_dir,
    ]
    try:
        with open(snapshot_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        start = meta.get("code_range_start")
        end = meta.get("code_range_end")
        if start and end:
            cmd.extend(["--code-range", str(start), str(end)])
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    cmd.append(trace_path)
    return cmd


def run_aeon_trace():
    if not os.path.exists(os.path.join(OUTPUT_DIR, "snapshot.json")):
        return {"ok": False, "error": f"missing capture snapshot in {OUTPUT_DIR}"}
    try:
        os.remove(TRACE_PATH)
    except FileNotFoundError:
        pass

    cmd = trace_cmd()
    try:
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "cmd": shlex.join(cmd),
            "error": "Aeon JIT trace timed out",
            "stdout": (exc.stdout or "").strip().splitlines()[-20:],
            "stderr": (exc.stderr or "").strip().splitlines()[-40:],
        }
    trace = {
        "cmd": shlex.join(cmd),
        "trace_file": TRACE_PATH,
        "returncode": proc.returncode,
    }
    if os.path.exists(TRACE_PATH):
        trace["trace_size"] = os.path.getsize(TRACE_PATH)
    if proc.stdout.strip():
        trace["stdout"] = proc.stdout.strip().splitlines()[-20:]
    if proc.stderr.strip():
        trace["stderr"] = proc.stderr.strip().splitlines()[-40:]
    trace["ok"] = proc.returncode == 0 and os.path.exists(TRACE_PATH) and os.path.getsize(TRACE_PATH) > 0
    return trace


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/status":
            ping = bridge.eval_rpc("rpc.exports.ping()") if bridge.alive else None
            self._json(200, {
                "alive": bridge.alive,
                "ready": bridge.ready,
                "ping": ping,
                "relay_scripts": bridge.loaded_scripts[-20:],
            })

        elif parsed.path == "/call":
            c = (params.get("c") or ["6BA4D60738580083"])[0]
            call_timeout = parse_int_param(params, "timeout", 120, minimum=5, maximum=300)
            prepare = parse_bool_param(params, "prepare", default=False)
            fixed_trace = parse_bool_param(params, "fixed_trace", default=False)
            stalker = parse_bool_param(params, "stalker", default=False)
            thread_ids = parse_thread_ids(params)
            prepare_result = prepare_cert_ready(c, timeout=min(call_timeout, 60)) if prepare and bridge.alive else None
            stalker_armed = bridge.eval_rpc(
                "globalThis.__jitGateStalkerArm && globalThis.__jitGateStalkerArm()",
                timeout=5,
            ) if stalker and bridge.alive else None
            fixed_trace_arm = None
            if fixed_trace and bridge.alive:
                arm_arg = json.dumps(json.dumps(thread_ids)) if thread_ids else "undefined"
                fixed_trace_arm = bridge.eval_rpc(
                    f"globalThis.__jitGateFixedThreadTraceArm && globalThis.__jitGateFixedThreadTraceArm({arm_arg})",
                    timeout=10,
                )
            result = bridge.eval_rpc(f"rpc.exports.callCert('{c}')", timeout=call_timeout)
            page_trace_pending = None
            if bridge.alive:
                pending_deadline = time.time() + 10.0
                pending_waited = 0.0
                while time.time() < pending_deadline:
                    try:
                        page_trace_pending = bridge.eval_rpc(
                            "globalThis.__nmssCorePageTraceCtl && globalThis.__nmssCorePageTraceCtl.pendingExactHooks && JSON.stringify(globalThis.__nmssCorePageTraceCtl.pendingExactHooks())",
                            timeout=5,
                        )
                    except Exception:
                        page_trace_pending = None
                        break
                    try:
                        if not page_trace_pending:
                            break
                        pending_obj = json.loads(page_trace_pending)
                        if not any(bool(pending_obj.get(k)) for k in ("pre", "saved", "next", "ret", "cont140358", "cont1549ac")):
                            break
                        if bool(pending_obj.get("closed")):
                            break
                    except Exception:
                        break
                    time.sleep(0.1)
                    pending_waited += 0.1
                try:
                    if page_trace_pending and pending_waited > 0:
                        log.info(f"Page trace pending wait: {pending_waited:.1f}s pending={page_trace_pending}")
                except Exception:
                    pass
            page_trace_disarm = bridge.eval_rpc(
                "globalThis.__nmssCorePageTraceCtl && globalThis.__nmssCorePageTraceCtl.disarmAll('after /call')",
                timeout=5,
            ) if bridge.alive else None
            stalker_dump = bridge.eval_rpc(
                "globalThis.__jitGateStalkerDump && globalThis.__jitGateStalkerDump()",
                timeout=5,
            ) if stalker and bridge.alive else None
            stalker_stop = bridge.eval_rpc(
                "globalThis.__jitGateStalkerStop && globalThis.__jitGateStalkerStop('after /call')",
                timeout=5,
            ) if stalker and bridge.alive else None
            self._json(200, {
                "challenge": c,
                "prepare": prepare_result,
                "token": result,
                "page_trace_pending": page_trace_pending,
                "page_trace_disarm": page_trace_disarm,
                "fixed_trace_arm": fixed_trace_arm,
                "stalker_armed": stalker_armed,
                "stalker": stalker_dump,
                "stalker_stop": stalker_stop,
            })

        elif parsed.path == "/prepare":
            c = (params.get("c") or [READY_CHALLENGE])[0]
            timeout = parse_int_param(params, "timeout", 60, minimum=10, maximum=300)
            ready_challenge = (params.get("ready") or [READY_CHALLENGE])[0]
            result = prepare_cert_ready(c, ready_challenge=ready_challenge, timeout=timeout)
            self._json(200, {
                "challenge": c,
                "ready_challenge": ready_challenge,
                "result": result,
            })

        elif parsed.path == "/fixed-trace/arm":
            thread_ids = parse_thread_ids(params)
            arm_arg = json.dumps(json.dumps(thread_ids)) if thread_ids else "undefined"
            result = bridge.eval_rpc(
                f"globalThis.__jitGateFixedThreadTraceArm && globalThis.__jitGateFixedThreadTraceArm({arm_arg})",
                timeout=10,
            ) if bridge.alive else None
            self._json(200, {
                "threads": thread_ids,
                "result": result,
            })

        elif parsed.path == "/fixed-trace/status":
            result = bridge.eval_rpc(
                "globalThis.__jitGateFixedThreadTraceStatus && globalThis.__jitGateFixedThreadTraceStatus()",
                timeout=10,
            ) if bridge.alive else None
            self._json(200, {"result": result})

        elif parsed.path == "/fixed-trace/clear":
            result = bridge.eval_rpc(
                "globalThis.__jitGateFixedThreadTraceClear && globalThis.__jitGateFixedThreadTraceClear()",
                timeout=10,
            ) if bridge.alive else None
            self._json(200, {"result": result})

        elif parsed.path == "/memdump":
            c = (params.get("c") or ["6BA4D60738580083"])[0]
            call_timeout = parse_int_param(params, "timeout", 300, minimum=10, maximum=600)
            prepare_result = prepare_cert_ready(c, timeout=min(call_timeout, 60)) if bridge.alive else None
            if not (isinstance(prepare_result, dict) and (prepare_result.get("token") or "")):
                self._json(409, {
                    "challenge": c,
                    "error": "plain readiness preflight returned empty token",
                    "prepare": prepare_result,
                })
                return
            log.info(f"Memdump: arm + getCertValue({c})")
            # 1. Arm memdump
            arm_result = bridge.eval_rpc(
                "globalThis.__jitGateMemdumpArm && globalThis.__jitGateMemdumpArm()",
                timeout=10,
            ) if bridge.alive else None
            # 2. Call cert (before snapshot captured in exception handler, after snapshot on return)
            token = bridge.eval_rpc(f"rpc.exports.callCert('{c}')", timeout=call_timeout)
            # 3. Check status
            status = bridge.eval_rpc(
                "globalThis.__jitGateMemdumpStatus && globalThis.__jitGateMemdumpStatus()",
                timeout=10,
            ) if bridge.alive else None
            # 4. Pull files from device
            time.sleep(2)
            file_list = bridge.eval_rpc(
                "globalThis.__jitGateMemdumpListFiles && globalThis.__jitGateMemdumpListFiles()",
                timeout=10,
            ) if bridge.alive else None
            log.info(f"Memdump: pulling files from device...")
            files = pull_memdump(file_list)
            log.info(f"Memdump: pulled {len(files)} files, {sum(files.values()) / (1024*1024):.1f}MB total")
            self._json(200, {
                "challenge": c,
                "prepare": prepare_result,
                "token": token,
                "arm": arm_result,
                "status": status,
                "host_dir": MEMDUMP_HOST_DIR,
                "files_pulled": len(files),
                "total_bytes": sum(files.values()),
                "manifests": {k: v for k, v in files.items() if k.endswith(".json")},
            })

        elif parsed.path == "/memdump/status":
            status = bridge.eval_rpc(
                "globalThis.__jitGateMemdumpStatus && globalThis.__jitGateMemdumpStatus()",
                timeout=10,
            ) if bridge.alive else None
            self._json(200, {"status": status})

        elif parsed.path == "/memdump/pull":
            file_list = bridge.eval_rpc(
                "globalThis.__jitGateMemdumpListFiles && globalThis.__jitGateMemdumpListFiles()",
                timeout=10,
            ) if bridge.alive else None
            files = pull_memdump(file_list)
            self._json(200, {
                "host_dir": MEMDUMP_HOST_DIR,
                "files": files,
                "total_bytes": sum(files.values()),
            })

        elif parsed.path == "/capture":
            c = (params.get("c") or ["6BA4D60738580083"])[0]
            prepare_result = prepare_cert_ready(c, timeout=60) if bridge.alive else None
            if not (isinstance(prepare_result, dict) and (prepare_result.get("token") or "")):
                self._json(409, {
                    "challenge": c,
                    "error": "plain readiness preflight returned empty token",
                    "prepare": prepare_result,
                })
                return
            log.info(f"Capture JIT hash: getCertValue({c})")
            result = bridge.eval_rpc(f"rpc.exports.captureCert('{c}')", timeout=20)
            time.sleep(3)  # wait for file writes on device
            files = pull_capture()
            self._json(200, {
                "challenge": c,
                "prepare": prepare_result,
                "token": result,
                "capture_dir": OUTPUT_DIR,
                "files": files,
                "trace_cmd": shlex.join(trace_cmd()),
            })

        elif parsed.path == "/trace":
            c = (params.get("c") or ["6BA4D60738580083"])[0]
            prepare_result = prepare_cert_ready(c, timeout=60) if bridge.alive else None
            if not (isinstance(prepare_result, dict) and (prepare_result.get("token") or "")):
                self._json(409, {
                    "challenge": c,
                    "error": "plain readiness preflight returned empty token",
                    "prepare": prepare_result,
                })
                return
            log.info(f"Trace JIT hash: getCertValue({c})")
            result = bridge.eval_rpc(f"rpc.exports.captureCert('{c}')", timeout=20)
            time.sleep(3)  # wait for file writes on device
            files = pull_capture()
            trace = run_aeon_trace()
            self._json(200, {
                "challenge": c,
                "prepare": prepare_result,
                "token": result,
                "capture_dir": OUTPUT_DIR,
                "files": files,
                "trace": trace,
            })

        elif parsed.path == "/translated/load":
            elf_path = (params.get("elf") or [TRANSLATED_DEVICE_ELF])[0]
            map_path = (params.get("map") or [TRANSLATED_DEVICE_MAP])[0]
            expr = f"rpc.exports.jitGateTranslatedLoad({json.dumps(elf_path)}, {json.dumps(map_path)})"
            result = bridge.eval_rpc(expr, timeout=120) if bridge.alive else None
            self._json(200, {
                "elf": elf_path,
                "map": map_path,
                "result": result,
            })

        elif parsed.path == "/translated/arm":
            elf_path = (params.get("elf") or [None])[0]
            map_path = (params.get("map") or [None])[0]
            min_pc = (params.get("min_pc") or params.get("minPc") or [None])[0]
            max_steps = parse_int_param(params, "max_steps", 4096, minimum=1, maximum=1_000_000)
            elf_arg = json.dumps(elf_path) if elf_path else "undefined"
            map_arg = json.dumps(map_path) if map_path else "undefined"
            min_pc_arg = json.dumps(min_pc) if min_pc else "undefined"
            expr = f"rpc.exports.jitGateTranslatedArm({elf_arg}, {map_arg}, {min_pc_arg}, {max_steps})"
            result = bridge.eval_rpc(expr, timeout=120) if bridge.alive else None
            self._json(200, {
                "elf": elf_path,
                "map": map_path,
                "min_pc": min_pc,
                "max_steps": max_steps,
                "result": result,
            })

        elif parsed.path == "/translated/status":
            result = bridge.eval_rpc("rpc.exports.jitGateTranslatedStatus()", timeout=10) if bridge.alive else None
            self._json(200, {"result": result})

        elif parsed.path == "/translated/clear":
            result = bridge.eval_rpc("rpc.exports.jitGateTranslatedClear()", timeout=10) if bridge.alive else None
            self._json(200, {"result": result})

        elif parsed.path == "/dynamic/load":
            lib_path = (params.get("lib") or [DYNAMIC_DEVICE_LIB])[0]
            expr = f"rpc.exports.jitGateDynamicLoad({json.dumps(lib_path)})"
            result = bridge.eval_rpc(expr, timeout=120) if bridge.alive else None
            self._json(200, {
                "lib": lib_path,
                "result": result,
            })

        elif parsed.path == "/dynamic/arm":
            lib_path = (params.get("lib") or [None])[0]
            min_pc = (params.get("min_pc") or params.get("minPc") or [None])[0]
            max_steps = parse_int_param(params, "max_steps", 4096, minimum=1, maximum=1_000_000)
            lib_arg = json.dumps(lib_path) if lib_path else "undefined"
            min_pc_arg = json.dumps(min_pc) if min_pc else "undefined"
            expr = f"rpc.exports.jitGateDynamicArm({lib_arg}, {min_pc_arg}, {max_steps})"
            result = bridge.eval_rpc(expr, timeout=120) if bridge.alive else None
            self._json(200, {
                "lib": lib_path,
                "min_pc": min_pc,
                "max_steps": max_steps,
                "result": result,
            })

        elif parsed.path == "/dynamic/status":
            result = bridge.eval_rpc("rpc.exports.jitGateDynamicStatus()", timeout=10) if bridge.alive else None
            self._json(200, {"result": result})

        elif parsed.path == "/dynamic/clear":
            result = bridge.eval_rpc("rpc.exports.jitGateDynamicClear()", timeout=10) if bridge.alive else None
            self._json(200, {"result": result})

        elif parsed.path == "/pull":
            files = pull_capture()
            self._json(200, {"files": files, "dir": OUTPUT_DIR})

        elif parsed.path == "/relay":
            paths = parse_relay_request("", params)
            if not paths:
                self._json(400, {"error": "missing path query parameter"})
                return
            results = bridge.load_scripts(paths, timeout=30)
            self._json(200, {
                "results": results,
                "ok": all(entry.get("ok") for entry in results),
            })

        elif parsed.path == "/":
            self._json(200, {"endpoints": {
                "GET /status": "session state",
                "GET /call?c=<hex16>": "call getCertValue",
                "GET /call?c=<hex16>&fixed_trace=1[&threads=tid,tid][&timeout=300]": "call getCertValue and arm in-process fixed-thread trace",
                f"GET /translated/load[?elf={TRANSLATED_DEVICE_ELF}&map={TRANSLATED_DEVICE_MAP}]": "load translated JIT ELF + map into Frida session",
                f"GET /translated/arm[?elf={TRANSLATED_DEVICE_ELF}&map={TRANSLATED_DEVICE_MAP}&min_pc=0x...&max_steps=4096]": "arm translated execute-fault diversion into translated JIT blocks",
                "GET /translated/status": "translated JIT dispatch status",
                "GET /translated/clear": "disable translated JIT dispatch",
                f"GET /dynamic/load[?lib={DYNAMIC_DEVICE_LIB}]": "load resident dynamic Aeon runtime into Frida session",
                f"GET /dynamic/arm[?lib={DYNAMIC_DEVICE_LIB}&min_pc=0x...&max_steps=4096]": "arm exact-PC dynamic execute-fault diversion",
                "GET /dynamic/status": "dynamic JIT dispatch status",
                "GET /dynamic/clear": "disable dynamic JIT dispatch",
                "GET /capture?c=<hex16>": "call + capture JIT hash state",
                "GET /trace?c=<hex16>": "capture JIT hash state + run Aeon JIT trace",
                "GET /fixed-trace/arm[?threads=tid,tid]": "arm in-process fixed-thread trace for the next cert call",
                "GET /fixed-trace/status": "poll in-process fixed-thread trace result",
                "GET /fixed-trace/clear": "clear armed/completed fixed-thread trace state",
                "GET /memdump?c=<hex16>[&timeout=300]": "arm page-trap memdump + cert call + pull before/after snapshots",
                "GET /memdump/status": "check memdump status",
                "GET /memdump/pull": "pull memdump files from device",
                "GET /pull": "pull latest capture from device",
                "POST /eval": "evaluate JS in REPL (body = JS code)",
                "GET /relay?path=<file.js>": "load one or more JS files into the REPL",
                "POST /relay": "load JS files into the REPL (JSON {path|paths} or newline-separated body)",
            }})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/eval":
            params = parse_qs(parsed.query)
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode() if length else ""
            if not body:
                self._json(400, {"error": "empty body"})
                return
            timeout = parse_int_param(params, "timeout", 15, minimum=1, maximum=300)
            result = bridge.eval_rpc(body, timeout=timeout)
            self._json(200, {"expr": body, "result": result})
        elif parsed.path == "/relay":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode() if length else ""
            paths = parse_relay_request(body, parse_qs(urlparse(self.path).query))
            if not paths:
                self._json(400, {"error": "empty relay request"})
                return
            results = bridge.load_scripts(paths, timeout=30)
            self._json(200, {
                "results": results,
                "ok": all(entry.get("ok") for entry in results),
            })
        else:
            self._json(404, {"error": "not found"})

    def _json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # quiet


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument("--attach", action="store_true")
    parser.add_argument("--minimal", action="store_true", help="use minimal readiness-only Frida agent")
    parser.add_argument("--relay-js", action="append", default=[], help="extra .js file to load into the Frida REPL after startup")
    args = parser.parse_args()

    agent_source = MINIMAL_AGENT_JS if args.minimal else AGENT_JS

    if args.attach:
        r = subprocess.run(ADB + ["shell", "su 0 pidof com.netmarble.thered"],
                           capture_output=True, text=True, timeout=5)
        pid = r.stdout.strip()
        if not pid:
            log.error("Game not running"); sys.exit(1)
        bridge.start(spawn=False, pid=int(pid), agent_source=agent_source)
    else:
        bridge.start(spawn=True, agent_source=agent_source)

    log.info("Waiting for agent...")
    for _ in range(60):
        if bridge.ready or not bridge.alive: break
        time.sleep(1)

    if bridge.alive and bridge.ready and args.relay_js:
        relay_results = bridge.load_scripts(args.relay_js, timeout=30)
        for entry in relay_results:
            if entry.get("ok"):
                log.info(f"Relayed JS: {entry['resolved']}")
            else:
                log.warning(f"Relay failed: {entry.get('resolved', entry.get('path'))}: {entry.get('error')}")

    server = HTTPServer(("0.0.0.0", args.port), Handler)
    log.info(
        f"Expected device server: {XERDA_SERVER_PATH} listening on tcp:{XERDA_DEVICE_PORT}; host forward on tcp:{XERDA_HOST_PORT}"
    )
    log.info(f"Capture server on :{args.port}")
    log.info(f"  GET /status        — check readiness")
    log.info(f"  GET /call?c=<hex>  — call getCertValue")
    log.info(f"  GET /prepare?c=<hex> — plain onResume/run readiness preflight")
    log.info(f"  GET /call?c=<hex>&fixed_trace=1 — arm fixed-thread trace for this call")
    log.info(f"  GET /translated/load[?elf=...&map=...] — load translated JIT ELF + map")
    log.info(f"  GET /translated/arm[?elf=...&map=...&min_pc=0x...&max_steps=4096] — arm translated dispatch")
    log.info(f"  GET /translated/status — translated dispatch status")
    log.info(f"  GET /translated/clear — disable translated dispatch")
    log.info(f"  GET /dynamic/load[?lib={DYNAMIC_DEVICE_LIB}] — load resident dynamic Aeon runtime")
    log.info(f"  GET /dynamic/arm[?lib={DYNAMIC_DEVICE_LIB}&min_pc=0x...&max_steps=4096] — arm dynamic exact-PC dispatch")
    log.info(f"  GET /dynamic/status — dynamic dispatch status")
    log.info(f"  GET /dynamic/clear — disable dynamic dispatch")
    log.info(f"  GET /capture?c=<hex> — capture JIT hash + pull")
    log.info(f"  GET /trace?c=<hex> — capture JIT hash + Aeon JIT trace")
    log.info(f"  GET /fixed-trace/arm[?threads=tid,tid] — arm in-process fixed-thread trace")
    log.info(f"  GET /fixed-trace/status — poll in-process fixed-thread trace result")
    log.info(f"  GET /fixed-trace/clear — clear in-process fixed-thread trace state")
    log.info(f"  POST /eval[?timeout=300] — run JS in REPL")
    log.info(f"  GET /relay?path=... — load .js into the REPL")
    log.info(f"  POST /relay        — load one or more .js into the REPL")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        bridge.kill()


if __name__ == "__main__":
    main()
