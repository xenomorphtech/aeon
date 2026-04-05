// Direct memory dump — no hooks, no waiting for function calls.
// Captures libnmsssa.so module memory + synthetic register state
// immediately after the module loads.
//
// Usage: frida -D localhost:5555 -f com.netmarble.thered -l frida/nmss_dump.js

'use strict';

var MODULE_NAME = 'libnmsssa.so';
var OUTPUT_BASE = '/data/local/tmp/aeon_capture';
var TARGETS = {
    'sub_20bb48': 0x20bb48,
    'sub_2070a8': 0x2070a8,
};

function waitForModule(name, cb) {
    var mod = Process.findModuleByName(name);
    if (mod) { cb(mod); return; }
    console.log('[*] Waiting for ' + name + ' to load...');
    var timer = setInterval(function() {
        mod = Process.findModuleByName(name);
        if (mod) {
            clearInterval(timer);
            cb(mod);
        }
    }, 500);
}

function readTpidrEl0() {
    var code = Memory.alloc(Process.pageSize);
    code.writeU32(0xD53BD040);
    code.add(4).writeU32(0xD65F03C0);
    Memory.protect(code, Process.pageSize, 'r-x');
    return new NativeFunction(code, 'pointer', [])();
}

function dumpModule(mod) {
    console.log('[*] Found ' + mod.name + ' at ' + mod.base + ' size=0x' + mod.size.toString(16));

    var tls = '0x0';
    try { tls = readTpidrEl0().toString(); } catch(e) { console.log('[!] tpidr_el0: ' + e); }
    console.log('[*] tpidr_el0 = ' + tls);

    for (var funcName in TARGETS) {
        (function(name, offset) {
            var dir = OUTPUT_BASE + '/' + name;
            var funcAddr = mod.base.add(offset);
            console.log('[*] Dumping for ' + name + ' at ' + funcAddr);

            // Dump full module
            console.log('[*]   module (' + (mod.size/1024/1024).toFixed(1) + ' MB)...');
            var modData = Memory.readByteArray(mod.base, mod.size);
            var f = new File(dir + '/module.bin', 'wb');
            f.write(modData);
            f.close();

            // Dump TLS region
            var tlsPtr = ptr(tls);
            var tlsRegions = [];
            if (!tlsPtr.isNull()) {
                try {
                    var tlsData = Memory.readByteArray(tlsPtr, 0x200);
                    var tf = new File(dir + '/tls.bin', 'wb');
                    tf.write(tlsData);
                    tf.close();
                    tlsRegions.push({ address: tls, size: 0x200, file: 'tls.bin', label: 'tls' });
                    console.log('[*]   tls (512 bytes)');
                } catch(e) { console.log('[!]   tls: ' + e); }
            }

            // Write snapshot.json with synthetic register state
            // (PC set to function entry, SP/LR zeroed — engine will use its own stack)
            var regs = {
                x: [],
                sp: '0x0',
                pc: funcAddr.toString(),
                tpidr_el0: tls,
            };
            for (var i = 0; i < 31; i++) regs.x.push('0x0');

            var regions = [
                { address: mod.base.toString(), size: mod.size, file: 'module.bin', label: 'module' }
            ];
            regions = regions.concat(tlsRegions);

            var snapshot = {
                function_name: name,
                module_name: mod.name,
                module_base: mod.base.toString(),
                module_path: mod.path,
                registers: regs,
                regions: regions,
                timestamp: new Date().toISOString(),
                pid: Process.id,
                arch: Process.arch,
            };

            var mf = new File(dir + '/snapshot.json', 'w');
            mf.write(JSON.stringify(snapshot, null, 2));
            mf.close();

            console.log('[+] ' + name + ' → ' + dir + '/');
        })(funcName, TARGETS[funcName]);
    }

    console.log('[+] Done! Pull with: adb pull ' + OUTPUT_BASE + '/ ./capture/');
}

console.log('');
console.log('=== aeon NMSS direct dump ===');
console.log('');

waitForModule(MODULE_NAME, function(mod) {
    dumpModule(mod);
});
