// Frida capture script for NMSS obfuscated functions
//
// Hooks target functions, captures full execution state (registers + memory)
// on entry, and writes a snapshot that aeon-instrument can replay.
//
// Usage:
//   frida -U -f <package> -l nmss_capture.js --no-pause
//   frida -U -n <process> -l nmss_capture.js
//
// Output: /data/local/tmp/aeon_capture/<function>/
//   snapshot.json      - registers and region manifest
//   module.bin         - full module memory (relocated GOT, initialized data)
//   stack.bin          - stack region around SP
//   tls.bin            - TLS block (tpidr_el0 region)
//   arg_x<N>.bin       - memory at argument register pointers
//
// Then on the host:
//   adb pull /data/local/tmp/aeon_capture/ ./capture/
//   cargo run --example frida_trace -- ./capture/sub_20bb48/

'use strict';

// ── Configuration ───────────────────────────────────────────────────

// Module containing the target functions.
var MODULE_NAME = 'libnmsssa.so';

// Target functions as offset from module base.
var TARGETS = {
    'sub_20bb48': 0x20bb48,
    'sub_2070a8': 0x2070a8,
};

var OUTPUT_BASE = '/data/local/tmp/aeon_capture';

// How much memory to capture around various pointers.
var STACK_CAPTURE_BELOW = 0x8000;   // 32 KB below SP
var STACK_CAPTURE_ABOVE = 0x8000;   // 32 KB above SP
var TLS_CAPTURE_SIZE    = 0x200;    // 512 bytes from tpidr_el0
var ARG_CAPTURE_SIZE    = 0x4000;   // 16 KB per argument pointer

// Only capture the first N invocations per function.
var MAX_CAPTURES = 1;

// ── Helpers ─────────────────────────────────────────────────────────

function mkdirp(path) {
    try {
        var f = new File(path + '/.probe', 'w');
        f.close();
    } catch (e) {
        // Split and create parents
        var parts = path.split('/').filter(function(p) { return p.length > 0; });
        var cur = '';
        for (var i = 0; i < parts.length; i++) {
            cur += '/' + parts[i];
            try {
                var probe = new File(cur + '/.probe', 'w');
                probe.close();
            } catch (e2) {
                // directory doesn't exist and we can't create probe - skip
            }
        }
    }
}

function writeRegionFile(dir, filename, addr, size) {
    try {
        var data = Memory.readByteArray(addr, size);
        if (data === null) return null;
        var f = new File(dir + '/' + filename, 'wb');
        f.write(data);
        f.close();
        return { address: addr.toString(), size: size, file: filename };
    } catch (e) {
        console.log('  [!] Failed to read ' + filename + ' at ' + addr + ': ' + e);
        return null;
    }
}

function isReadablePointer(addr) {
    try {
        Memory.readU8(addr);
        return true;
    } catch (e) {
        return false;
    }
}

function readTpidrEl0() {
    // MRS X0, TPIDR_EL0 = 0xD53BD040
    // RET                = 0xD65F03C0
    var code = Memory.alloc(Process.pageSize);
    code.writeU32(0xD53BD040);
    code.add(4).writeU32(0xD65F03C0);
    Memory.protect(code, Process.pageSize, 'r-x');
    var fn = new NativeFunction(code, 'pointer', []);
    return fn();
}

// ── Module detection ────────────────────────────────────────────────

function findTargetModule() {
    if (MODULE_NAME !== null) {
        var m = Process.findModuleByName(MODULE_NAME);
        if (m) return m;
    }

    // Auto-detect: look for a module containing one of the target offsets
    // by checking if the offset within the module has executable code.
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var mod = modules[i];
        // Skip small system libraries
        if (mod.size < 0x200000) continue;

        var firstOffset = null;
        for (var name in TARGETS) {
            firstOffset = TARGETS[name];
            break;
        }
        if (firstOffset === null) continue;

        var testAddr = mod.base.add(firstOffset);
        if (isReadablePointer(testAddr)) {
            console.log('[*] Auto-detected module: ' + mod.name +
                        ' base=' + mod.base + ' size=0x' + mod.size.toString(16));
            return mod;
        }
    }

    console.log('[!] Could not find target module. Loaded modules:');
    modules.forEach(function(m) {
        if (m.size > 0x100000) {
            console.log('    ' + m.name + ' base=' + m.base +
                        ' size=0x' + m.size.toString(16));
        }
    });
    return null;
}

// ── Capture logic ───────────────────────────────────────────────────

function captureState(ctx, funcName, mod) {
    var dir = OUTPUT_BASE + '/' + funcName;

    var regions = [];

    // 1. Registers
    var regs = {
        x: [],
        sp: ctx.sp.toString(),
        pc: ctx.pc.toString(),
        tpidr_el0: '0x0',
    };
    for (var i = 0; i < 29; i++) {
        regs.x.push(ctx['x' + i].toString());
    }
    regs.x.push(ctx.fp.toString());  // x29
    regs.x.push(ctx.lr.toString());  // x30

    // Read tpidr_el0
    try {
        regs.tpidr_el0 = readTpidrEl0().toString();
    } catch (e) {
        console.log('  [!] Could not read tpidr_el0: ' + e);
    }

    // 2. Module memory (full — includes relocated GOT, initialized data)
    console.log('  [*] Dumping module memory (' +
                (mod.size / 1024 / 1024).toFixed(1) + ' MB)...');
    var modRegion = writeRegionFile(dir, 'module.bin', mod.base, mod.size);
    if (modRegion) {
        modRegion.label = 'module';
        regions.push(modRegion);
    }

    // 3. Stack region
    var sp = ctx.sp;
    var stackStart = sp.sub(STACK_CAPTURE_BELOW);
    var stackSize = STACK_CAPTURE_BELOW + STACK_CAPTURE_ABOVE;
    var stackRegion = writeRegionFile(dir, 'stack.bin', stackStart, stackSize);
    if (stackRegion) {
        stackRegion.label = 'stack';
        regions.push(stackRegion);
    }

    // 4. TLS block
    var tls = ptr(regs.tpidr_el0);
    if (!tls.isNull() && isReadablePointer(tls)) {
        var tlsRegion = writeRegionFile(dir, 'tls.bin', tls, TLS_CAPTURE_SIZE);
        if (tlsRegion) {
            tlsRegion.label = 'tls';
            regions.push(tlsRegion);
        }
    }

    // 5. Memory at argument register pointers (X0-X7)
    for (var j = 0; j < 8; j++) {
        var argAddr = ptr(regs.x[j]);
        if (argAddr.isNull()) continue;
        if (!isReadablePointer(argAddr)) continue;

        // Don't re-capture if it falls within the module or stack
        if (argAddr.compare(mod.base) >= 0 &&
            argAddr.compare(mod.base.add(mod.size)) < 0) continue;
        if (argAddr.compare(stackStart) >= 0 &&
            argAddr.compare(stackStart.add(stackSize)) < 0) continue;

        var argRegion = writeRegionFile(dir, 'arg_x' + j + '.bin',
                                         argAddr, ARG_CAPTURE_SIZE);
        if (argRegion) {
            argRegion.label = 'arg_x' + j;
            regions.push(argRegion);
        }
    }

    // 6. Write snapshot metadata
    var snapshot = {
        function_name: funcName,
        module_name: mod.name,
        module_base: mod.base.toString(),
        module_path: mod.path,
        registers: regs,
        regions: regions,
        timestamp: new Date().toISOString(),
        pid: Process.id,
        arch: Process.arch,
    };

    var metaFile = new File(dir + '/snapshot.json', 'w');
    metaFile.write(JSON.stringify(snapshot, null, 2));
    metaFile.close();

    return snapshot;
}

// ── Hook installation ───────────────────────────────────────────────

function installHooks() {
    var mod = findTargetModule();
    if (!mod) {
        console.log('[!] Retrying module detection in 3 seconds...');
        setTimeout(installHooks, 3000);
        return;
    }

    var captureCount = {};

    for (var funcName in TARGETS) {
        (function(name, offset) {
            captureCount[name] = 0;
            var addr = mod.base.add(offset);

            console.log('[*] Hooking ' + name + ' at ' + addr);

            Interceptor.attach(addr, {
                onEnter: function(args) {
                    if (captureCount[name] >= MAX_CAPTURES) return;
                    captureCount[name]++;

                    console.log('[+] ' + name + ' called (capture #' +
                                captureCount[name] + ')');

                    var snapshot = captureState(this.context, name, mod);
                    if (snapshot) {
                        var totalSize = 0;
                        snapshot.regions.forEach(function(r) { totalSize += r.size; });
                        console.log('[+] Captured ' + snapshot.regions.length +
                                    ' regions (' + (totalSize / 1024).toFixed(0) +
                                    ' KB) → ' + OUTPUT_BASE + '/' + name + '/');
                    }

                    if (captureCount[name] >= MAX_CAPTURES) {
                        console.log('[*] Max captures reached for ' + name);
                    }
                }
            });
        })(funcName, TARGETS[funcName]);
    }

    console.log('[*] Hooks installed. Output directory: ' + OUTPUT_BASE);

    // Invoke the first target directly so we don't need to wait for app to call it
    var firstFunc = null;
    var firstOffset = null;
    for (var n in TARGETS) { firstFunc = n; firstOffset = TARGETS[n]; break; }
    if (firstFunc) {
        console.log('[*] Invoking ' + firstFunc + ' directly...');
        setTimeout(function() {
            invokeTarget(mod, firstFunc, firstOffset);
        }, 1000);
    }
}

// ── Direct invocation ───────────────────────────────────────────────

function invokeTarget(mod, funcName, offset) {
    var addr = mod.base.add(offset);
    console.log('[*] Calling ' + funcName + ' at ' + addr + ' ...');

    // Allocate scratch buffers for arguments (the function expects pointers)
    var buf0 = Memory.alloc(0x1000);
    var buf1 = Memory.alloc(0x1000);

    // sub_20bb48(x0=buf, x1=buf) / sub_2070a8(x0=buf, w1=0, w2=0)
    var fn = new NativeFunction(addr, 'pointer', ['pointer', 'pointer']);
    try {
        fn(buf0, buf1);
    } catch (e) {
        console.log('[*] ' + funcName + ' returned/threw: ' + e);
    }
}

// ── Entry point ─────────────────────────────────────────────────────

console.log('');
console.log('=== aeon NMSS obfuscated function capture ===');
console.log('');

// Delay slightly to let the process fully initialize
setTimeout(installHooks, 500);
