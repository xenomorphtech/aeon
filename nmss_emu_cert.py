#!/usr/bin/env python3
"""
NMSS Cert Value Emulator - Full tokenProc (sub_20aad4) + JIT encoder
Emulates the complete cert token computation from nmsscr.dec binary.

Strategy: Run sub_20aad4 natively with hooks for libc/runtime functions.
sub_2070a8 is mocked to return minimal state.
sub_209dc4 is mocked to return the REAL encoder function (fx at JIT+0x10828c).
The BLR x8 at 0x20b548 is redirected to JIT_BASE+0x10828c with x8 patched.
The JIT module's PLT/GOT is patched so its libc calls route through our hooks.
sub_20a3b0 formats the output as hex.

Verified test vectors:
  "0000000000000000" -> "F29B982D9B52B0F7819FA57503A890475F8D0DF74F814359"
  "FFFFFFFFFFFFFFFF" -> "3E369148823B89A9403C2C21CA3FD0C9DEA1271B4B2E3452"
"""

import errno
import struct
import os
import time
import sys
import hashlib
import json
from collections import deque

from unicorn import *
from unicorn.arm64_const import *

BINARY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "output/decrypted/nmsscr.dec")

JIT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "jit_module.bin")

CODE_BASE    = 0x0
CODE_SIZE    = 0x600000  # Extended to cover BSS at 0x515000-0x595000

# JIT encoder module
JIT_BASE     = 0x10000000
# The captured JIT ELF is only 0x453000 bytes, but live runtime pointers reach
# zero-backed JIT data/BSS pages as far as +0xb70003. Map a larger tail so
# rebased live pointers can land inside the emulator's JIT region.
JIT_SIZE     = 0xC00000
JIT_RUNTIME_SIZE = 0x2600000
JIT_LIVE_GOT_OVERRIDE_START = 0x446000
JIT_LIVE_GOT_OVERRIDE_END = 0x449000

STACK_TOP    = 0x7F400000
STACK_SIZE   = 0x4000000  # 64MB downward-growing stack; keep top fixed
STACK_BASE   = STACK_TOP - STACK_SIZE

HEAP_BASE    = 0x80000000
HEAP_SIZE    = 0x8000000  # 128MB heap

MANAGER_BASE = 0x60000000
MANAGER_SIZE = 0x2000

TLS_BASE     = 0x50000000
TLS_SIZE     = 0x1000

CHALLENGE_BASE = 0x61000000
SCRATCH_BASE = 0x64000000
SCRATCH_SIZE = 0x200000
OUTPUT_OBJ_VCALL_STUB = SCRATCH_BASE + 0x10010
LIVE_PTHREAD_CREATE_STUB = SCRATCH_BASE + 0x50090
LIVE_CALLBACK_DECODE_ENTRY = 0x76EA989270
LIVE_CALLBACK_DECODE_FALLBACK = 0x76EA992450
STALE_NMSSCR_RUNTIME_ZERO_RANGES = (
    (0x4EAE68, 8),
    (0x4E8C70, 0x20),
)
JIT_CERT_STAGE1_THUNK = JIT_BASE + 0x1C211C

# Device identity from current install (codex-nmss):
#   I_NMSessionID = C2B7A8B206F74D8F816F29EBD6752B5D (per-install, survives restarts)
#   I_UDID        = 7B0D26CDC87D42EA
# Old snapshot values: SESSION_KEY=F61DFB2DA2C94AA1B67CAFCD51DA7E85, DEVICE_ID=0x71893E50
SESSION_KEY = bytes.fromhex("F82FC41278170013A0180013F82FC412")
SCORE       = 118         # matches live device owner+0x314 (from device_session_fresh.json)
DEVICE_ID   = 0x00000001  # doesn't affect cert output
CERT_CE75C_FMT_8E = b"%08X%08X%08X%08X%08X%08X"
CERT_CE75C_FMT_8D = b"%s"  # opcode 0x8d: format string for stage 2 (cert hex string pointer)

TEST_VECTORS = [
    ("0000000000000000", "F29B982D9B52B0F7819FA57503A890475F8D0DF74F814359"),
    ("0000000000000001", "F2E5F4D5787A9FC4FDC17FA615B863E4D0281529F559ADBB"),
    ("0000000000000002", "01E475EB4FAF460D2E0371C3D8D8FE9F3C835152FD404079"),
    ("0000000000000003", "D11B639A917F8BE2DE052F10A7BB299D27EF3E75EABE11C3"),
    ("1055B831EADA0F85", "4BAF77F3F7FC9977F01F882FBAF1074622F24997802E57CF"),
    ("1111111111111111", "65026628BE31DE117A743079F5B244B77381D43AA8F9C557"),
    ("33E5ADCE73F2F69E", "071AED0A31E2384DFAA3AE727220CCB27DF53FD160EBC23B"),
    ("ABCDEF0123456789", "FA6F90FD3DE3C02B7D5725D48B8B2A1F5843C3E35642AB25"),
    ("DEADBEEF12345678", "7AA92CCBB4F7A03BAB08ABCC4B8B2B51330D486461367058"),
    ("FFFFFFFFFFFFFFFF", "3E369148823B89A9403C2C21CA3FD0C9DEA1271B4B2E3452"),
]

# JIT module ELF layout (from analysis of jit_module.bin):
# LOAD[0]: vaddr=0x0       offset=0x0       filesz=0x410f20  (R/X)
# LOAD[1]: vaddr=0x415920  offset=0x411920  filesz=0x3702c   memsz=0x3cbc8 (RW)
# BSS:     vaddr=0x44c94c  size=0x5b9c
# dynsym:  file offset 0xd00, 442 entries, 24 bytes each
# dynstr:  file offset 0x3670
# JMPREL:  vaddr 0x533d8, size 0x1230 (194 entries, R_AARCH64_JUMP_SLOT)
# RELA:    vaddr 0x4c40, size 0x4e798 (R_AARCH64_RELATIVE + R_AARCH64_GLOB_DAT)
# The real encoder function 'fx' is at JIT_BASE+0x10828c (shndx=10, val=0x10828c)

JIT_LOAD0_VADDR  = 0x0
JIT_LOAD0_OFFSET = 0x0
JIT_LOAD0_FILESZ = 0x410f20

JIT_LOAD1_VADDR  = 0x415920
JIT_LOAD1_OFFSET = 0x411920
JIT_LOAD1_FILESZ = 0x3702c
JIT_LOAD1_MEMSZ  = 0x3cbc8

JIT_ENCODER_FN   = JIT_BASE + 0x10828c   # 'fx' function

JIT_DYNSYM_OFFSET = 0xd00   # file offset of dynsym[0]
JIT_DYNSYM_COUNT  = 442
JIT_DYNSTR_OFFSET = 0x3670  # file offset of dynstr

JIT_JMPREL_VADDR  = 0x533d8
JIT_JMPREL_SIZE   = 0x1230
JIT_RELA_VADDR    = 0x4c40
JIT_RELA_SIZE     = 0x4e798
JIT_BAD_EXEC_RANGES = (
    # Keep this empty unless a specific non-code island is proven hot.
    # The old 0x55000-0x57000 blanket trap was wrong: ce75c legitimately
    # calls helpers at 0x55040, 0x55160, and 0x56b44 inside that window.
)

# Stub area for JIT PLT hooks: within JIT mapping at a safe offset
# We use JIT_BASE + 0x4FF000 for our JIT-side hook stubs
JIT_STUB_BASE = JIT_BASE + 0x4FF000
JIT_STUB_SLOT_SIZE = 0x10
JIT_INTEGRITY_STUB_WORDS = {
    # 0x1d8a54 compares the first 4 bytes of selected import stubs against
    # hardcoded signatures before it seeds its return bit.
    'fopen':   0x46C04778,
    'dlopen':  0x46C04778,
    'sprintf': 0x477846C0,
    'memset':  0xE51FF004,
    'strlen':  0xE51FF004,
}
JIT_ENTRY_TRACE_START = JIT_ENCODER_FN
JIT_ENTRY_TRACE_END = JIT_ENCODER_FN + 0x200
JIT_HANDOFF_TRACE_START = JIT_BASE + 0x155B68
JIT_HANDOFF_TRACE_END = JIT_HANDOFF_TRACE_START + 0x200
JIT_CFF_BRIDGE_CALL = JIT_BASE + 0x155BAC
JIT_CFF_BRIDGE_POST = JIT_BASE + 0x155BB0
JIT_CFF_BRIDGE_SITES = {
    JIT_CFF_BRIDGE_CALL: JIT_CFF_BRIDGE_POST,
}
JIT_CFF_BRIDGE_DEFAULT_POST = JIT_CFF_BRIDGE_POST
JIT_INNER_CFF_ENTRY = JIT_BASE + 0x8A2C4  # inner CFF function prologue
JIT_INNER_CFF_STR   = JIT_BASE + 0x8A2F0  # str x0, [sp, #0x60] — stores manager ptr
JIT_INNER_CFF_ENTRY_TRACE_END = JIT_INNER_CFF_ENTRY + 4
LIVE_CFF_CALLBACK_X1 = 0xE
LIVE_CFF_CALLBACK_X2 = 0x0F53A8D2
LIVE_CFF_CALLBACK_X22_FALLBACK = 0xA29
JIT_UNSIGNED_TREE_PATCH_START = 0x8A000
JIT_UNSIGNED_TREE_PATCH_END   = 0xB0000
JIT_DISPATCH_TRACE_START = JIT_BASE + 0x8B000
JIT_DISPATCH_TRACE_END = JIT_BASE + 0x8DFFF
JIT_DISPATCH_HUB = JIT_BASE + 0x8CC78
JIT_CFF_ITER_LOOP = JIT_BASE + 0x8BA5C  # iteration loop: ldur x5,[fp,#-0x80]
JIT_CFF_EPILOGUE_RET = JIT_BASE + 0x8CCE4  # ret after CFF epilogue restores LR from stack
JIT_POST_CFF_DISPATCH_HUB = JIT_BASE + 0xCE698
JIT_POST_CFF_LOOP_THRESHOLD = 256
JIT_ONCE_INIT_HELPER = JIT_BASE + 0x6A7F8
JIT_ONCE_INIT_HELPER_END = JIT_BASE + 0x6A864
JIT_ONCE_INIT_GLOBAL = JIT_BASE + 0x44C960
JIT_ONCE_INIT_GUARD = JIT_BASE + 0x44C968
JIT_ONCE_INIT_VTABLE = JIT_BASE + 0x415990
JIT_CLASSMAP_INIT_FN = JIT_BASE + 0x20E4E0
JIT_CLASSMAP_BASE = JIT_BASE + 0x44E9C0
JIT_CLASSMAP_GUARD = JIT_CLASSMAP_BASE + 0x64
JIT_LIB_LOADER_ENTRY = JIT_BASE + 0x7847C  # Library loader function entry
JIT_CERT_FAST_BRANCH = JIT_BASE + 0x108d20  # tbnz w0,#0,0x108f88 after bl 0x155b68
JIT_CFF_CALL_159DA4 = JIT_BASE + 0x159DA4  # CFF call from main cert path
JIT_CFF_CALL_15DF68 = JIT_BASE + 0x15DF68  # Second config CFF call (same pattern as 159DA4)
JIT_CERT_BL_1C6314 = JIT_BASE + 0x1c6314   # bl 0x1d126c inside cert CFF (x2=encoder)
JIT_CERT_CALLEE_1D126C = JIT_BASE + 0x1d126c  # Callee that receives x2 encoder obj
JIT_CERT_WRAPPER_RET0 = JIT_BASE + 0x1c75e0  # str wzr,[sp,#80] - failure return in cert wrapper
JIT_CERT_WRAPPER_POST_CFF = JIT_BASE + 0x108fa4  # tbz w0,#0,skip - post-CFF branch
JIT_CERT_BL_1D8A54 = JIT_BASE + 0x1d2088  # bl 0x1d8a54 from 0x1d126c
JIT_CERT_FN_1D8A54 = JIT_BASE + 0x1d8a54  # encoding function called by 0x1d126c
JIT_CERT_INNER_CFF_BL = JIT_BASE + 0x1c2180  # bl 0x8a2c4 from cert wrapper
JIT_CERT_INNER_CFF_RET = JIT_BASE + 0x1c2184  # str x0,[sp,#0x48] after inner CFF returns
JIT_CERT_CFF_PREHUB = JIT_BASE + 0x1c32b4
JIT_CERT_POST_CFF_HUB = JIT_BASE + 0x1c8738
JIT_CERT_POST_CFF_CE75C_PREP = JIT_BASE + 0x1c3364
JIT_CERT_POST_CFF_CE75C_CALL = JIT_BASE + 0x1c3374
JIT_CERT_POST_CFF_CE75C_STATE = 0x4C69B01C
JIT_CERT_POST_SUCCESS_WALKER_EPILOGUE = JIT_BASE + 0x1c20c4
JIT_SECOND_CFF_CALLER_LOCK = JIT_BASE + 0x784D4
JIT_SECOND_CFF_CALLER_PRECALL = JIT_BASE + 0x784E0
JIT_SECOND_CFF_CALLER_POSTRET = JIT_BASE + 0x784E4
JIT_SECOND_CFF_GLOBAL = JIT_BASE + 0x44C978
JIT_SECOND_CFF_RESULT_0 = JIT_BASE + 0x78574
JIT_SECOND_CFF_RESULT_18 = JIT_BASE + 0x78A28
JIT_SECOND_CFF_RESULT_20 = JIT_BASE + 0x78A98
JIT_SECOND_CFF_RESULT_28 = JIT_BASE + 0x78B08
JIT_STATE_MACHINE_ENTRY = JIT_BASE + 0x6A5C0
JIT_STATE_MACHINE_RET = JIT_BASE + 0x6A7D4
JIT_STATE_TABLE_PTR = JIT_BASE + 0x44C958
JIT_STATE_TABLE_IDX = JIT_BASE + 0x44C950
JIT_CXA_GLOBALS_KEY = JIT_BASE + 0x44E950
JIT_CXA_GLOBALS_ONCE = JIT_BASE + 0x44E954
JIT_CXA_GLOBALS_MUTEX = JIT_BASE + 0x44E958
JIT_CXA_GLOBALS_COND = JIT_BASE + 0x44E980
JIT_CXA_GLOBALS_INIT_FN = JIT_BASE + 0x1E5E60
JIT_CXA_GLOBALS_DTOR_FN = JIT_BASE + 0x1E5E94
JIT_CXA_NODE_RELEASE_FN = JIT_BASE + 0x1E5B38
JIT_CXA_TLS_LIST_STEP_FN = JIT_BASE + 0x1E5BD0
JIT_CXA_GETSPECIFIC_RET = JIT_BASE + 0x1E5DC4
JIT_CXA_GETSPECIFIC_FAST_RET = JIT_BASE + 0x1E5E50
JIT_CXA_CALLOC_RET = JIT_BASE + 0x1E5DD8
JIT_CXA_SETSPECIFIC_RET = JIT_BASE + 0x1E5DEC
JIT_CXA_DTOR_FREE_RET = JIT_BASE + 0x1E5EA0
JIT_CXA_DTOR_CLEAR_RET = JIT_BASE + 0x1E5EB0
JIT_CXA_NORETURN_CALL_FN = JIT_BASE + 0x1E60C0
JIT_CXA_TLS_CLEANUP_FN = JIT_BASE + 0x1E6100
JIT_CXA_CLEANUP_DRIVER_FN = JIT_BASE + 0x1E6B04
JIT_RESOLVER_OPENAT_RET = JIT_BASE + 0x79690
JIT_RESOLVER_READ_RET = JIT_BASE + 0x7973C
JIT_RESOLVER_LSEEK_RET = JIT_BASE + 0x797E8
SYS_CLOSE = 57
SYS_OPENAT = 56
SYS_LSEEK = 62
SYS_READ = 63
JIT_INVALID_INDCALL_PC1 = JIT_BASE + 0xDB244
JIT_INVALID_INDCALL_PC2 = JIT_BASE + 0xDB2C8
JIT_DECISION_TRACE_PCS = {
    JIT_BASE + 0x8BA5C,  # ldur x5, [fp-0x80]
    JIT_BASE + 0x8BA60,  # ldur x24, [fp-0x60]
    JIT_BASE + 0x8BA68,  # both loads completed; branch data now live in regs
    JIT_BASE + 0x8BA70,  # cmp x24, x5
    JIT_BASE + 0x8BA7C,  # csel w5, ...
    JIT_BASE + 0x8CD50,  # [fp-0x60] has just been written from x8 at 0x8cd4c
    JIT_BASE + 0x8DCC8,  # [fp-0x80] has just been written from w0 at 0x8dcc4
}
JIT_STACK_SEED_PCS = {
    JIT_BASE + 0x8CD50,
    JIT_BASE + 0x8BA5C,
    JIT_BASE + 0x8BA60,
    JIT_BASE + 0x8BA68,
    JIT_BASE + 0x8BA70,
    JIT_BASE + 0x8BA7C,
}
LIVE_JIT_STACK_SNAPSHOT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "output/live_jit_snapshot_raw4.txt",
)
LIVE_JIT_SNAPSHOT_JSON_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "output/live_jit_snapshot_manual7.json",
)
CURRENT_SESSION_CAPTURE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "current_session_capture.json",
)
LIVE_JIT_CODE_OVERLAY_RANGES = (
    # Veneer/PLT stub page shared by callers in the cert path.
    (0x05F000, 0x060000),
    # Post-0x1627d8 vector-pack tail. Overlay just the self-contained SIMD
    # pack loop that reloads x12/x13/x8/x9 from the frame; the earlier module
    # bytes still match the existing scrambler fast-forwards at 0x132528/0x132598.
    (0x132680, 0x132800),
    # Helper body at 0x1702c8.
    (0x170000, 0x171000),
    # Cert CFF wrapper at 0x1c2124.  Module version is CFF-obfuscated with
    # wrong random state constants — dispatch tree can't resolve handlers.
    # Live version is a de-obfuscated straight-line function that works.
    # DISABLED: live overlay overwrites 42 module helper call sites at
    # 0x1c2108/0x1c211c and introduces live CFF constants that stall.
    # The module CFF (0x1c2124) works via stall-skip; only the truncation
    # fix at 0x6afb4 is needed for correct hash output.
    # (0x1C0000, 0x1E0000),
    # Allocator/string wrappers called by the live cert function.
    (0x272000, 0x274000),
    # memcpy/memmove used by live cert code.
    (0x060000, 0x061000),
)
LIVE_JIT_PREDICATE_SLOTS = {
    # The live 0x162628 CFF state machine consults opaque predicate cells via
    # these JIT globals. The captured live qwords point into donor-process heap
    # pages we do not have, so restoring the raw bytes here only reintroduces
    # dead pointers. Patch just the slots we actually need to stable scratch
    # cells instead of overlaying whole donor pages.
    0x4E2F88: 0,
    0x4E3D40: 0,
}
LIVE_JIT_PREDICATE_CELL_BASE = SCRATCH_BASE + 0x180000
LIVE_JIT_PREDICATE_CELL_STRIDE = 0x100
LIVE_CERT_OVERLAY_ACTIVE = any(
    max(start, 0x1C0000) < min(end, 0x1E0000)
    for start, end in LIVE_JIT_CODE_OVERLAY_RANGES
)


class SimpleHeap:
    def __init__(self, base, size):
        self.base, self.size, self.offset = base, size, 0
        self.allocs = {}
        self._free_list = {}  # size -> [addr, ...]

    def malloc(self, size):
        size = max((size + 15) & ~15, 16)
        # Check free list for a suitable block
        if size in self._free_list and self._free_list[size]:
            addr = self._free_list[size].pop()
            self.allocs[addr] = size
            return addr
        if self.offset + size > self.size:
            raise MemoryError("Heap exhausted")
        addr = self.base + self.offset
        self.offset += size
        self.allocs[addr] = size
        return addr

    def free(self, addr):
        # Keep freed blocks reserved for the remainder of the emulation run.
        # Several wrapper return paths leave shallow pointer graphs behind, and
        # immediate size-based reuse can overwrite caller-visible result storage
        # before compute_cert() extracts it.
        self.allocs.pop(addr, None)

    def reset(self):
        self.offset = 0
        self.allocs.clear()
        self._free_list.clear()


class NMSSCertEmulator:
    """Emulates sub_20aad4 from nmsscr.dec to compute the full 48-char cert token."""

    LAZY_RESOLVER = 0x5edc0
    PLT_FALLBACK = SCRATCH_BASE + 0x50000

    # The REAL encoder dispatch function from vtable at 0x4b1648
    # Now redirected to JIT encoder 'fx' at JIT_BASE+0x10828c
    ENCODER_DISPATCH_FN = JIT_BASE + 0x10828c

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.binary_data = open(BINARY_PATH, "rb").read()
        self.jit_data = open(JIT_PATH, "rb").read() if os.path.exists(JIT_PATH) else None
        jit_live_flat_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jit_live_flat.bin")
        self.jit_live_flat = open(jit_live_flat_path, "rb").read() if os.path.exists(jit_live_flat_path) else None
        self.live_jit_stack_snapshot = self._load_live_jit_stack_snapshot()
        self._snapshot_jit_live_base = None
        self._snapshot_jit_live_size = 0
        self._jit_live_bases = []
        self._jit_live_got_overrides = {}
        self._jit_live_predicate_cells = {}
        self._load_live_runtime_bases()
        self.heap = SimpleHeap(HEAP_BASE, HEAP_SIZE)
        self.uc = None
        self.hook_count = 0
        self._rand_counter = 0
        self._srand_counter = 0
        self._last_srand_seed = None
        self._fake_time_sec = 1_700_000_000  # Match native harness FAKE_TIME_BASE_SEC
        self._fake_time_nsec = 123_456_789   # Match native harness FAKE_TIME_BASE_NSEC
        self._rng_state = [0] * 31
        self._rng_fidx = 3
        self._rng_ridx = 0
        self._reset_bionic_random()
        self.hooked_functions = {}
        self.mapped_pages = set()
        self._insn_count = 0
        self._last_pc = 0
        self._max_insn = 500_000_000
        self._dispatch_trace = deque(maxlen=256)
        self._dispatch_decision_trace = deque(maxlen=128)
        self._x28_trace = deque(maxlen=128)
        self._recent_data_events = deque(maxlen=128)
        self._last_traced_x28 = None
        self._dispatch_hub_hits = 0
        self._dispatch_trace_seq = 0
        # Global CB area pointer (set by _hook_sub_2070a8)
        self._cb_area = 0
        self._dispatch_hub_log_stride = 5000
        self._cert_post_cff_w26_trace = deque(maxlen=128)
        self._cert_post_cff_last_w26 = None
        self._cert_cff_hub1_last_state = None
        self._cert_ce75c_minus_pending = False
        self._cert_post_cff_1c3374_state = None
        self._cert_post_cff_1c3374_hits = 0
        self._cert_post_cff_route_fix_applied = 0
        self._cert_native_post_callback_seed_hits = 0
        self._jit_stack_struct_seeded = False
        self._jit_inner_entry_logged = False
        self._jit_inner_entry_snapshot = None
        self._jit_cff_bridge_saved_x22 = {}
        self._post_cff_dispatch_last_key = None
        self._post_cff_dispatch_same_count = 0
        self._post_cff_dispatch_skips = 0
        self._jit_invalid_indcall_skips = 0
        self._jit_once_init_hits = 0
        self._cff_hub_count = 0
        self._jit_cff_frame_ctx = {}
        self._cff_current_return_lr = None
        self._cff_current_caller_sp = None
        self._cff_current_caller_fp = None
        self._jit_symbol_stubs = {}
        self._jit_stub_entry_redirects = {}
        self._session_resolver_stub = 0
        self._inline_sha_read_watch_installed = False
        self._inline_sha_read_watch_range = None
        self._inline_sha_read_count = 0
        self._inline_sha_msg_logged = False
        self._inline_sha_write_watch_installed = False
        self._inline_sha_write_watch_range = None
        self._inline_sha_write_count = 0
        self._sha_input_watch_installed = False
        self._sha_input_watch_range = None
        self._sha_input_write_count = 0
        self._sha_input_memcpy_count = 0
        self._sha_input_last_snapshot = ""
        self._cert_feeder_last = None
        self._jit_dl_iterate_phdr_calls = 0
        self._jit_cxa_atexit_calls = 0
        self._jit_cxa_atexit_trace = []
        self._jit_state_machine_calls = 0
        self._jit_state_machine_trace = []
        self._jit_state_machine_current = None
        self._jit_fake_tree_nodes = {}
        self._session_desc_key_map = {}
        self._session_desc_map_addr = 0
        self._dl_modules = self._init_dl_modules()
        self._second_cff_caller_trace = []
        self._second_cff_current_iter = None
        self._jit_raw_syscall_trace = []
        self._jit_fd_table = {}
        self._jit_next_fd = 0x400
        self._jit_virtual_files = self._load_jit_virtual_files()
        self._jit_stdio_logs = 0
        self._jit_tls_values = {}
        self._jit_tls_next_key = 1
        self._jit_cxa_globals_key = 0
        self._post_cert_cleanup_bypass_active = False
        self._post_cert_cleanup_bypass_hits = 0
        self._xor_pack_last_src = 0
        self._fake_pthread_handles = {}
        self._live_region_page_data = {}
        self._live_region_page_index = {}
        self._live_session_regions_loaded = False
        self._live_session_region_pages = 0
        self._live_encoder_x2_template = None
        # JIT stub table: stub_vaddr -> hook_handler
        self._jit_stub_map = {}
        # SVC-based fast dispatch: index -> (handler, original_bytes)
        self._svc_handlers = {}
        self._svc_originals = {}
        self._fast_mode = False  # SVC dispatch disabled
        self._block_mode = False  # UC_HOOK_BLOCK (broken: PC redirect unreliable)
        self._range_mode = True   # Range-limited hooks: skip JIT encoder core
        # General-purpose stall detector (works across all JIT code)
        self._stall_jit_count = 0
        self._stall_last_fp = 0
        self._stall_same_count = 0
        self._stall_skips = 0
        self._stall_check_interval = 10_000
        self._stall_threshold = 3
        self._stall_block_limit = 150_000
        self._stall_live_block_limit = 250_000
        self._stall_last_page = 0
        self._stall_page_count = 0
        self._stall_last_progress_block = 0
        self._stall_returned_lrs = {}  # lr -> count, for escalation

    def log(self, msg):
        if self.verbose:
            print(f"  [EMU] {msg}")

    def _load_live_runtime_bases(self):
        import json

        bases = []
        if os.path.exists(LIVE_JIT_SNAPSHOT_JSON_PATH):
            try:
                with open(LIVE_JIT_SNAPSHOT_JSON_PATH) as f:
                    snap = json.load(f)
                jit_base = snap.get("jit_base")
                if isinstance(jit_base, int) and jit_base > 0:
                    self._snapshot_jit_live_base = jit_base
                    bases.append(jit_base)
                jit_size = snap.get("jit_size")
                if isinstance(jit_size, int) and jit_size > 0:
                    self._snapshot_jit_live_size = jit_size
            except Exception:
                pass

        for base in (self.JIT_LIVE_BASE, self.JIT_SEG_LIVE_BASE):
            if base not in bases:
                bases.append(base)
        self._jit_live_bases = bases

    def _jit_runtime_size(self):
        return max(JIT_SIZE, JIT_RUNTIME_SIZE, self._snapshot_jit_live_size or 0)

    def _load_live_encoder_x2_template(self):
        if self._live_encoder_x2_template is not None:
            return self._live_encoder_x2_template

        import json

        base_dir = os.path.dirname(os.path.abspath(__file__))
        snap_paths = [
            LIVE_JIT_SNAPSHOT_JSON_PATH,
            os.path.join(base_dir, "encoder_snapshot.json"),
        ]
        for snap_path in snap_paths:
            if not os.path.exists(snap_path):
                continue
            try:
                with open(snap_path) as f:
                    snap = json.load(f)
                x2_hex = snap.get("mem", {}).get("x2", {}).get("hex")
                if x2_hex:
                    self._live_encoder_x2_template = bytes.fromhex(x2_hex)
                    return self._live_encoder_x2_template
            except Exception:
                pass

        self._live_encoder_x2_template = b""
        return self._live_encoder_x2_template

    def _load_live_region_page_index(self):
        if self._live_region_page_index:
            return self._live_region_page_index

        import json

        base_dir = os.path.dirname(os.path.abspath(__file__))
        snap_paths = [
            LIVE_JIT_SNAPSHOT_JSON_PATH,
            os.path.join(base_dir, "encoder_snapshot.json"),
        ]
        for snap_path in snap_paths:
            if not os.path.exists(snap_path):
                continue
            try:
                with open(snap_path) as f:
                    snap = json.load(f)
            except Exception:
                continue
            regions = snap.get("regions", [])
            if not regions:
                continue
            page_index = {}
            for region in regions:
                addr = region.get("addr")
                hex_data = region.get("hex", "")
                if not isinstance(addr, int) or not hex_data:
                    continue
                try:
                    data = bytes.fromhex(hex_data)
                except Exception:
                    continue
                untagged_addr = addr & 0x0000FFFFFFFFFFFF
                page_index[untagged_addr & ~0xFFF] = data
            if page_index:
                self._live_region_page_index = page_index
                return self._live_region_page_index

        self._live_region_page_index = {}
        return self._live_region_page_index

    def _should_preserve_overlay_ptr(self, val):
        page_index = self._load_live_region_page_index()
        for cand in self._candidate_ptrs(val):
            cand_pg = cand & ~0xFFF
            if cand_pg in self._live_region_page_data or cand_pg in page_index:
                return True
        return False

    def _normalize_encoder_template_ptr(self, ptr):
        if not ptr:
            return 0

        # Snapshot-backed heap/session pointers are tagged; prefer their mapped,
        # untagged pages once _build_session_object() has loaded the regions.
        untagged = ptr & 0x0000FFFFFFFFFFFF
        if (untagged & ~0xFFF) in self._live_region_page_data:
            return untagged

        if self.NMSSCR_LIVE_BASE <= ptr < self.NMSSCR_LIVE_BASE + CODE_SIZE:
            return ptr - self.NMSSCR_LIVE_BASE + CODE_BASE

        jit_runtime_size = self._jit_runtime_size()
        for base in self._jit_live_bases:
            if base <= ptr < base + jit_runtime_size:
                return ptr - base + JIT_BASE

        if self._snapshot_jit_live_base and self._snapshot_jit_live_base <= ptr < self._snapshot_jit_live_base + jit_runtime_size:
            return ptr - self._snapshot_jit_live_base + JIT_BASE

        return ptr

    def _seed_encoder_builder_globals_from_template(self, uc):
        x2_template = self._load_live_encoder_x2_template()
        if len(x2_template) < 0xC0:
            return

        def qword(off):
            return struct.unpack_from("<Q", x2_template, off)[0]

        def dword(off):
            return struct.unpack_from("<I", x2_template, off)[0]

        mgr_area = 0x4e8cb8

        # tokenProc copies these fields into the encoder context immediately
        # before the JIT call. Seed them from the live x2 snapshot instead of
        # the old zero-stub-era placeholders.
        uc.mem_write(mgr_area + 0x28, struct.pack("<I", dword(0x1c)))
        uc.mem_write(mgr_area + 0x2c, struct.pack("<I", dword(0x20)))
        uc.mem_write(mgr_area + 0x30, struct.pack("<I", dword(0x24)))
        uc.mem_write(mgr_area + 0x34, struct.pack("<I", dword(0x28)))
        uc.mem_write(mgr_area + 0x38, struct.pack("<I", dword(0xe0)))
        uc.mem_write(mgr_area + 0x3c, struct.pack("<I", dword(0xe4)))
        uc.mem_write(mgr_area + 0x40, bytes([0x00]))
        uc.mem_write(
            mgr_area + 0x90,
            struct.pack("<Q", self._normalize_encoder_template_ptr(qword(0x08))),
        )

        # 0x5f1c0 copies pointer-pair state from these manager slots into
        # x2+0x80/x2+0x98/x2+0xb0. The live x2 object exposes the target qwords.
        for mgr_off, ctx_off in (
            (0x48, 0x80),
            (0x50, 0x88),
            (0x60, 0x98),
            (0x68, 0xA0),
            (0x78, 0xB0),
            (0x80, 0xB8),
        ):
            uc.mem_write(
                mgr_area + mgr_off,
                struct.pack("<Q", self._normalize_encoder_template_ptr(qword(ctx_off))),
            )
        uc.mem_write(mgr_area + 0x9A, bytes([0x01]))

        # The 0x4eae28 cluster is copied verbatim into x2+0x30/+0x38/+0x40/+0x48.
        uc.mem_write(0x4eae28, struct.pack("<Q", self._normalize_encoder_template_ptr(qword(0x30))))
        uc.mem_write(0x4eae30, struct.pack("<Q", qword(0x38)))
        uc.mem_write(0x4eae38, struct.pack("<Q", self._normalize_encoder_template_ptr(qword(0x40))))
        uc.mem_write(0x4eae40, struct.pack("<Q", self._normalize_encoder_template_ptr(qword(0x48))))

    def _signed64(self, value):
        value &= 0xFFFFFFFFFFFFFFFF
        if value & (1 << 63):
            value -= 1 << 64
        return value

    def _neg_errno(self, code):
        return (-int(code)) & 0xFFFFFFFFFFFFFFFF

    def _read_c_string(self, uc, addr, max_len=4096):
        addr = self._resolve_mem_addr(uc, addr)
        if addr <= 0x1000:
            return b""
        out = bytearray()
        for i in range(max_len):
            try:
                b = bytes(uc.mem_read(addr + i, 1))[0]
            except Exception:
                break
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def _candidate_ptrs(self, addr):
        candidates = []
        def add_candidate(value):
            if value <= 0:
                return
            if value not in candidates:
                candidates.append(value)

        low32 = addr & 0xFFFFFFFF
        untag8 = addr & 0x00FFFFFFFFFFFFFF
        untag16 = addr & 0x0000FFFFFFFFFFFF

        for cand in (addr, untag8, untag16, low32):
            for rebased in self._rebase_live_runtime_addr(cand):
                add_candidate(rebased)

        # Some live JIT structures encode module-relative offsets as 0x1????????.
        # Treat those as JIT_BASE + low32 so accesses land in the zero-backed tail
        # instead of mapping a bogus high address page.
        if (addr >> 32) == 0x1 and low32 < self._jit_runtime_size():
            add_candidate(JIT_BASE + low32)

        for cand in (untag16, untag8, low32, addr):
            add_candidate(cand)
        return candidates

    def _rebase_live_runtime_addr(self, addr):
        rebased = []
        if self.NMSSCR_LIVE_BASE <= addr < self.NMSSCR_LIVE_BASE + CODE_SIZE:
            rebased.append(addr - self.NMSSCR_LIVE_BASE + CODE_BASE)
        jit_runtime_size = self._jit_runtime_size()
        for base in self._jit_live_bases:
            if base <= addr < base + jit_runtime_size:
                rebased_addr = addr - base + JIT_BASE
                if rebased_addr not in rebased:
                    rebased.append(rebased_addr)
        return rebased

    def _is_page_accessible(self, uc, pg):
        try:
            uc.mem_read(pg, 1)
            self.mapped_pages.add(pg)
            return True
        except Exception:
            return False

    def _map_page_bytes(self, uc, pg, data):
        if self._is_page_accessible(uc, pg):
            try:
                uc.mem_write(pg, data[:0x1000])
                return True
            except Exception:
                return False
        try:
            uc.mem_map(pg, 0x1000, UC_PROT_ALL)
            uc.mem_write(pg, data[:0x1000])
            self.mapped_pages.add(pg)
            return True
        except Exception as e:
            if not hasattr(self, '_map_fail_count'):
                self._map_fail_count = 0
            self._map_fail_count += 1
            if self._map_fail_count <= 5:
                print(f"[MAP-FAIL #{self._map_fail_count}] pg={pg:#x}: {e}", flush=True)
            return False

    def _seed_mapped_pages(self):
        def add_range(base, size):
            start = base & ~0xFFF
            end = (base + size + 0xFFF) & ~0xFFF
            for pg in range(start, end, 0x1000):
                self.mapped_pages.add(pg)

        for base, size in (
            (CODE_BASE, CODE_SIZE),
            (STACK_BASE, STACK_SIZE),
            (HEAP_BASE, HEAP_SIZE),
            (MANAGER_BASE, MANAGER_SIZE),
            (TLS_BASE, TLS_SIZE),
            (CHALLENGE_BASE, 0x2000),
            (SCRATCH_BASE, SCRATCH_SIZE),
        ):
            add_range(base, size)
        if self.jit_data:
            add_range(JIT_BASE, self._jit_runtime_size())

    def _resolve_mem_addr(self, uc, addr):
        if addr <= 0x1000:
            return addr
        for cand in self._candidate_ptrs(addr):
            try:
                if (cand & ~0xFFF) not in self.mapped_pages:
                    self._tbi_map_page(uc, cand)
                uc.mem_read(cand, 1)
                return cand
            except Exception:
                continue
        return addr

    def _read_bytes_with_fallback(self, uc, addr, size):
        if size <= 0:
            return b""

        out = bytearray()
        cur = addr
        remaining = size
        page_index = None
        while remaining > 0:
            chunk = None
            for cand in self._candidate_ptrs(cur):
                cand_pg = cand & ~0xFFF
                cand_off = cand & 0xFFF
                take = min(remaining, 0x1000 - cand_off)
                try:
                    if self._is_page_accessible(uc, cand_pg):
                        chunk = bytes(uc.mem_read(cand, take))
                        break
                except Exception:
                    pass

                page_data = self._live_region_page_data.get(cand_pg)
                if page_data is not None:
                    chunk = page_data[cand_off:cand_off + take]
                    break

                if page_index is None:
                    page_index = self._load_live_region_page_index()
                page_data = page_index.get(cand_pg)
                if page_data is not None:
                    chunk = page_data[cand_off:cand_off + take]
                    break

            if chunk is None or not chunk:
                raise RuntimeError(f"unmapped read at {cur:#x} size={remaining:#x}")
            out.extend(chunk)
            cur += len(chunk)
            remaining -= len(chunk)

        return bytes(out)

    def _dump_mem_hex_fallback(self, uc, addr, size):
        try:
            return self._read_bytes_with_fallback(uc, addr, size).hex()
        except Exception as exc:
            return f"ERR({exc})"

    def _record_recent_data_event(self, kind, src=0, dst=0, size=0, lr=0, pc=0, head=b""):
        head = bytes(head[:32]) if head else b""
        self._recent_data_events.append({
            "kind": kind,
            "src": src,
            "dst": dst,
            "size": size,
            "lr": lr,
            "pc": pc,
            "head": head,
        })

    def _format_recent_data_events(self, focus_addr=0, focus_size=0x100, limit=8):
        events = list(self._recent_data_events)
        selected = []
        if focus_addr and focus_size > 0:
            focus_end = focus_addr + focus_size
            for ev in reversed(events):
                src = ev.get("src", 0) or 0
                dst = ev.get("dst", 0) or 0
                size = ev.get("size", 0) or 0
                src_hit = size > 0 and src < focus_end and (src + size) > focus_addr
                dst_hit = size > 0 and dst < focus_end and (dst + size) > focus_addr
                if src_hit or dst_hit:
                    selected.append(ev)
                    if len(selected) >= limit:
                        break
        if not selected:
            selected = list(reversed(events[-limit:]))
        out = []
        for ev in reversed(selected):
            head = ev.get("head", b"")
            out.append(
                f"{ev.get('kind')} pc=JIT+{((ev.get('pc', 0) or JIT_BASE) - JIT_BASE):#x} "
                f"src={ev.get('src', 0):#x} dst={ev.get('dst', 0):#x} "
                f"sz={ev.get('size', 0)} lr={ev.get('lr', 0):#x} head={head.hex()}"
            )
        return " | ".join(out)

    def _close_jit_fd_table(self):
        for entry in self._jit_fd_table.values():
            host_fd = entry.get("host_fd")
            if host_fd is not None:
                try:
                    os.close(host_fd)
                except OSError:
                    pass
        self._jit_fd_table.clear()
        self._jit_next_fd = 0x400

    def _alloc_jit_fd(self, kind, path=b"", data=b"", host_fd=None):
        fd = self._jit_next_fd
        self._jit_next_fd += 1
        self._jit_fd_table[fd] = {
            "kind": kind,
            "path": bytes(path),
            "data": bytes(data),
            "pos": 0,
            "host_fd": host_fd,
            "eof": False,
            "err": 0,
        }
        return fd

    def _load_jit_virtual_files(self):
        files = {}
        bins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bins")
        if not os.path.isdir(bins_dir):
            return files
        for name in os.listdir(bins_dir):
            if not name.endswith(".nmss"):
                continue
            path = os.path.join(bins_dir, name)
            try:
                data = open(path, "rb").read()
            except OSError:
                continue
            short = name.split("_", 1)[1] if "_" in name else name
            base = short[:-5] if short.endswith(".nmss") else short
            for alias in (path, name, short, base, base + ".nmss"):
                files[alias] = data
        return files

    def _resolve_jit_host_or_virtual_path(self, path_bytes):
        if not path_bytes:
            return None, None, ""
        try:
            path = path_bytes.decode("utf-8", errors="ignore")
        except Exception:
            path = ""
        base = os.path.basename(path) if path else ""
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        bins_dir = os.path.join(repo_dir, "bins")

        if path == "/proc/self/maps":
            return None, self._build_synthetic_proc_self_maps(), path

        host_override = None
        if base == "nmsscr.nmss":
            host_override = os.environ.get("NMSS_FREAD_NMSSCR_PATH")
            if not host_override:
                for cand in os.listdir(bins_dir) if os.path.isdir(bins_dir) else ():
                    if cand.endswith("_nmsscr.nmss"):
                        host_override = os.path.join(bins_dir, cand)
                        break
        elif base == "nmsskc.nmss":
            host_override = os.environ.get("NMSS_FREAD_NMSSKC_PATH")
            if not host_override:
                for cand in os.listdir(bins_dir) if os.path.isdir(bins_dir) else ():
                    if cand.endswith("_nmsskc.nmss"):
                        host_override = os.path.join(bins_dir, cand)
                        break
        elif base == "base.apk":
            host_override = os.environ.get("NMSS_FREAD_BASE_APK_PATH")

        if host_override and os.path.exists(host_override):
            return host_override, None, path
        if path and os.path.exists(path):
            return path, None, path

        for alias in (path, base):
            if alias and alias in self._jit_virtual_files:
                return None, self._jit_virtual_files[alias], path
        return None, None, path

    def _jit_read_fd_entry(self, uc, entry, buf, count):
        if entry is None:
            return -1
        try:
            if entry["kind"] == "host":
                chunk = os.read(entry["host_fd"], count)
            else:
                data = entry["data"]
                pos = entry["pos"]
                chunk = data[pos:pos + count]
                entry["pos"] = pos + len(chunk)
            if chunk:
                uc.mem_write(buf, chunk)
            entry["eof"] = len(chunk) < count
            entry["err"] = 0
            return len(chunk)
        except OSError as exc:
            entry["err"] = exc.errno or errno.EIO
            entry["eof"] = False
            return -1

    def _jit_resolve_stream_fd(self, uc, stream_ptr):
        if stream_ptr <= 0x1000:
            return 0
        try:
            return struct.unpack("<Q", uc.mem_read(stream_ptr, 8))[0]
        except Exception:
            return 0

    def _jit_log_stdio(self, msg):
        if self._jit_stdio_logs < 16:
            print(msg, flush=True)
        self._jit_stdio_logs += 1

    def _build_synthetic_proc_self_maps(self):
        lines = [
            "00000000-00600000 r-xp 00000000 00:00 0 /data/app/com.netease.sky/lib/arm64/libnmsscr.so",
            "00600000-00610000 rw-p 00600000 00:00 0 /data/app/com.netease.sky/lib/arm64/libnmsscr.so",
            "10000000-10500000 r-xp 00000000 00:00 0 /data/app/com.netease.sky/cache/jit_module.bin",
            "10500000-10510000 rw-p 00500000 00:00 0 /data/app/com.netease.sky/cache/jit_module.bin",
            "71000000-71180000 r-xp 00000000 00:00 0 /apex/com.android.runtime/lib64/bionic/libc.so",
            "71180000-71190000 rw-p 00180000 00:00 0 /apex/com.android.runtime/lib64/bionic/libc.so",
            "71200000-71210000 r-xp 00000000 00:00 0 /apex/com.android.runtime/lib64/bionic/libdl.so",
            "71210000-71220000 rw-p 00010000 00:00 0 /apex/com.android.runtime/lib64/bionic/libdl.so",
            "72000000-72040000 r-xp 00000000 00:00 0 /apex/com.android.runtime/bin/linker64",
            "72040000-72050000 rw-p 00040000 00:00 0 /apex/com.android.runtime/bin/linker64",
        ]
        return ("\n".join(lines) + "\n").encode("ascii")

    def _jit_tls_key_create(self):
        key = self._jit_cxa_globals_key
        if key == 0:
            key = self._jit_tls_next_key
            self._jit_tls_next_key += 1
            self._jit_cxa_globals_key = key
        return key

    def _jit_tls_get(self, key):
        return self._jit_tls_values.get(int(key) & 0xFFFFFFFF, 0)

    def _jit_tls_set(self, key, value):
        self._jit_tls_values[int(key) & 0xFFFFFFFF] = value & 0xFFFFFFFFFFFFFFFF

    def _emulate_jit_cxa_globals_init(self, uc):
        key = self._jit_tls_key_create()
        try:
            uc.mem_write(JIT_CXA_GLOBALS_KEY, struct.pack("<I", key))
        except Exception:
            pass
        for addr, size in (
            (JIT_CXA_GLOBALS_MUTEX, 0x28),
            (JIT_CXA_GLOBALS_COND, 0x20),
        ):
            try:
                uc.mem_write(addr, b"\x00" * size)
            except Exception:
                pass

    def _record_raw_syscall(self, entry):
        if len(self._jit_raw_syscall_trace) < 256:
            self._jit_raw_syscall_trace.append(entry)

    def _emulate_raw_syscall(self, uc, syscall_num):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x3 = uc.reg_read(UC_ARM64_REG_X3)
        x4 = uc.reg_read(UC_ARM64_REG_X4)
        result = 0
        trace = {
            "syscall": syscall_num,
            "lr": lr,
            "x0": x0,
            "x1": x1,
            "x2": x2,
            "x3": x3,
            "x4": x4,
        }

        if syscall_num == SYS_OPENAT:
            dirfd = self._signed64(x0)
            path = self._read_c_string(uc, x1, max_len=512)
            flags = x2 & 0xFFFFFFFF
            mode = x3 & 0xFFFFFFFF
            trace.update({
                "kind": "openat",
                "dirfd": dirfd,
                "path": path,
                "flags": flags,
                "mode": mode,
            })
            if path.startswith(b"/proc/") and path.endswith(b"/maps"):
                result = self._alloc_jit_fd("proc_maps", path=path, data=self._build_synthetic_proc_self_maps())
            else:
                try:
                    host_path = path.decode("utf-8", errors="ignore")
                except Exception:
                    host_path = ""
                if host_path and os.path.exists(host_path):
                    try:
                        host_fd = os.open(host_path, os.O_RDONLY)
                        result = self._alloc_jit_fd("host", path=path, host_fd=host_fd)
                    except OSError as exc:
                        result = self._neg_errno(exc.errno or errno.EIO)
                else:
                    result = self._neg_errno(errno.ENOENT)
        elif syscall_num == SYS_READ:
            fd = int(x0 & 0xFFFFFFFFFFFFFFFF)
            buf = x1
            count = int(x2 & 0xFFFFFFFFFFFFFFFF)
            trace.update({
                "kind": "read",
                "fd": fd,
                "buf": buf,
                "count": count,
            })
            entry = self._jit_fd_table.get(fd)
            if entry is None:
                result = 0 if fd in (0, 1, 2) else self._neg_errno(errno.EBADF)
            elif entry["kind"] == "host":
                try:
                    chunk = os.read(entry["host_fd"], count)
                    if chunk:
                        uc.mem_write(buf, chunk)
                    result = len(chunk)
                    trace["preview"] = chunk[:96]
                except OSError as exc:
                    result = self._neg_errno(exc.errno or errno.EIO)
            else:
                data = entry["data"]
                pos = entry["pos"]
                chunk = data[pos:pos + count]
                if chunk:
                    uc.mem_write(buf, chunk)
                entry["pos"] = pos + len(chunk)
                result = len(chunk)
                trace["path"] = entry.get("path", b"")
                trace["preview"] = chunk[:96]
        elif syscall_num == SYS_LSEEK:
            fd = int(x0 & 0xFFFFFFFFFFFFFFFF)
            offset = self._signed64(x1)
            whence = int(x2 & 0xFFFFFFFFFFFFFFFF)
            trace.update({
                "kind": "lseek",
                "fd": fd,
                "offset": offset,
                "whence": whence,
            })
            entry = self._jit_fd_table.get(fd)
            if entry is None:
                result = self._neg_errno(errno.EBADF)
            elif entry["kind"] == "host":
                try:
                    result = os.lseek(entry["host_fd"], offset, whence)
                except OSError as exc:
                    result = self._neg_errno(exc.errno or errno.EIO)
            else:
                data_len = len(entry["data"])
                cur = entry["pos"]
                if whence == 0:
                    new_pos = offset
                elif whence == 1:
                    new_pos = cur + offset
                elif whence == 2:
                    new_pos = data_len + offset
                else:
                    new_pos = -1
                if new_pos < 0:
                    result = self._neg_errno(errno.EINVAL)
                else:
                    entry["pos"] = min(new_pos, data_len)
                    result = entry["pos"]
        elif syscall_num == SYS_CLOSE:
            fd = int(x0 & 0xFFFFFFFFFFFFFFFF)
            trace.update({
                "kind": "close",
                "fd": fd,
            })
            entry = self._jit_fd_table.pop(fd, None)
            if entry is None:
                result = 0 if fd in (0, 1, 2) else self._neg_errno(errno.EBADF)
            else:
                host_fd = entry.get("host_fd")
                if host_fd is not None:
                    try:
                        os.close(host_fd)
                    except OSError:
                        pass
                result = 0
        else:
            trace["kind"] = "default"
            result = 0

        trace["result"] = self._signed64(result)
        self._record_raw_syscall(trace)
        uc.reg_write(UC_ARM64_REG_X0, result & 0xFFFFFFFFFFFFFFFF)

    def _load_live_jit_stack_snapshot(self):
        path = LIVE_JIT_STACK_SNAPSHOT_PATH
        if not os.path.exists(path):
            return None

        fp = None
        sp = None
        mem_sp_addr = None
        mem_sp = None
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("CC_REG_fp="):
                    fp = int(line.split("=", 1)[1], 16)
                elif line.startswith("CC_REG_sp="):
                    sp = int(line.split("=", 1)[1], 16)
                elif line.startswith("CC_MEM_sp="):
                    _, rest = line.split("=", 1)
                    addr_str, hex_blob = rest.split(",", 1)
                    mem_sp_addr = int(addr_str, 16)
                    mem_sp = bytes.fromhex(hex_blob.strip())

        if fp is None or sp is None or mem_sp_addr is None or mem_sp is None:
            return None

        def read_qword(addr):
            rel = addr - mem_sp_addr
            if rel < 0 or rel + 8 > len(mem_sp):
                return None
            return struct.unpack_from("<Q", mem_sp, rel)[0]

        def read_u32(addr):
            rel = addr - mem_sp_addr
            if rel < 0 or rel + 4 > len(mem_sp):
                return None
            return struct.unpack_from("<I", mem_sp, rel)[0]

        slot_m80_addr = fp - 0x80
        slot_m60_addr = fp - 0x60
        slot_m80_q = read_qword(slot_m80_addr)
        slot_m60_q = read_qword(slot_m60_addr)
        stack_obj_addr = sp + 0x60
        stack_obj_q = read_qword(stack_obj_addr)
        return {
            "path": path,
            "fp": fp,
            "sp": sp,
            "stack_obj_addr": stack_obj_addr,
            "stack_obj_q": stack_obj_q,
            "slot_m80_addr": slot_m80_addr,
            "slot_m60_addr": slot_m60_addr,
            "slot_m80_q": slot_m80_q,
            "slot_m60_q": slot_m60_q,
            "slot_m80_w": read_u32(slot_m80_addr),
            "slot_m60_w": read_u32(slot_m60_addr),
            "slot_m80_fp_delta": None if slot_m80_q is None else slot_m80_q - fp,
            "slot_m60_fp_delta": None if slot_m60_q is None else slot_m60_q - fp,
            "stack_obj_388_q": None if stack_obj_q is None else read_qword(stack_obj_q + 0x388),
            "stack_obj_3a0_q": None if stack_obj_q is None else read_qword(stack_obj_q + 0x3a0),
        }

    def setup(self):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # Map nmsscr regions
        for base, size in [(CODE_BASE, CODE_SIZE), (STACK_BASE, STACK_SIZE),
                           (HEAP_BASE, HEAP_SIZE), (MANAGER_BASE, MANAGER_SIZE),
                           (TLS_BASE, TLS_SIZE), (CHALLENGE_BASE, 0x2000),
                           (SCRATCH_BASE, SCRATCH_SIZE)]:
            self.uc.mem_map(base, size, UC_PROT_ALL)
        self._load_native_module()
        self._apply_relocations()

        # Map JIT module
        if self.jit_data:
            self.uc.mem_map(JIT_BASE, self._jit_runtime_size(), UC_PROT_ALL)
            self._load_jit_module()

        self._jit_rw_snapshot = None  # set later after all init is complete
        # Snapshot wrapper (nmsscr) data region for per-run restore. The BSS/data
        # segment spans roughly 0x4e4000-0x600000, but we snapshot a broader range
        # to catch all modifiable globals.
        self._nmsscr_data_snapshot = None

        self._seed_mapped_pages()
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)
        self.uc.mem_write(TLS_BASE + 0x28, struct.pack("<Q", 0xDEADBEEFCAFEBABE))
        self._setup_manager()
        self._setup_globals()
        self._install_hooks()

        # Load nmsscr RW dumps LAST so they override _setup_globals() zeros
        self._load_nmsscr_rw()
        if self.jit_data:
            self._patch_live_predicate_slots()
        self._apply_runtime_code_fixes()

        # Snapshot all mutable memory after full setup for per-run restore.
        # This ensures compute_cert() starts from identical state each time.
        if self.jit_data:
            jit_total = self._jit_runtime_size()
            self._jit_rw_snapshot = (JIT_BASE, bytes(self.uc.mem_read(JIT_BASE, jit_total)))
        nmsscr_rw_start = 0x4e4000  # nmsscr data/BSS segment start
        nmsscr_rw_size = CODE_SIZE - nmsscr_rw_start  # to end of CODE region
        self._nmsscr_data_snapshot = (
            CODE_BASE + nmsscr_rw_start,
            bytes(self.uc.mem_read(CODE_BASE + nmsscr_rw_start, nmsscr_rw_size))
        )
        # Also snapshot the nmsscr RW overlay pages (written by _load_nmsscr_rw)
        self._nmsscr_rw_overlay_snapshots = []
        for offset in [0x13e000, 0x17b000, 0x17f000, 0x3c0000, 0x3c5000]:
            data = bytes(self.uc.mem_read(CODE_BASE + offset, 0x1000))
            self._nmsscr_rw_overlay_snapshots.append((CODE_BASE + offset, data))
        # Also snapshot MANAGER region
        self._manager_snapshot = (
            MANAGER_BASE,
            bytes(self.uc.mem_read(MANAGER_BASE, MANAGER_SIZE))
        )
        # Snapshot stack, TLS, and scratch so compute_cert starts clean each time
        self._stack_snapshot = (
            STACK_BASE,
            bytes(self.uc.mem_read(STACK_BASE, STACK_SIZE))
        )
        self._tls_snapshot = (
            TLS_BASE,
            bytes(self.uc.mem_read(TLS_BASE, TLS_SIZE))
        )
        self._scratch_snapshot = (
            SCRATCH_BASE,
            bytes(self.uc.mem_read(SCRATCH_BASE, SCRATCH_SIZE))
        )
        # Save the set of pages mapped at setup time. During compute_cert,
        # the TBI handler may map additional pages that accumulate stale data
        # across runs. At reset, any page NOT in this base set gets zeroed.
        self._base_mapped_pages = set(self.mapped_pages)
        # Snapshot heap memory and allocator state so compute_cert() can
        # restore them together, preserving pointer consistency.
        self._heap_snapshot = (HEAP_BASE, bytes(self.uc.mem_read(HEAP_BASE, HEAP_SIZE)))
        import copy
        self._heap_allocator_snapshot = {
            'offset': self.heap.offset,
            'allocs': copy.deepcopy(self.heap.allocs),
            'free_list': copy.deepcopy(self.heap._free_list),
        }
        # Snapshot code regions — memcpy and XOR decrypt can write into
        # executable pages during cert computation, corrupting them for the
        # next run.
        self._code_text_snapshot = (CODE_BASE, bytes(self.uc.mem_read(CODE_BASE, 0x4e4000)))
        jit_text_size = JIT_LOAD1_VADDR  # text ends where RW segment starts
        self._jit_text_snapshot = (JIT_BASE, bytes(self.uc.mem_read(JIT_BASE, jit_text_size)))
        # Save a deep copy of all mutable Python-side state after setup.
        # compute_cert() restores this to prevent ANY stale state leaking.
        import copy as _copy
        _skip = {'uc', '_setup_pystate_snapshot', '_pystate_snapshot',
                 '_code_text_snapshot', '_jit_text_snapshot',
                 '_jit_rw_snapshot', '_nmsscr_data_snapshot',
                 '_nmsscr_rw_overlay_snapshots', '_manager_snapshot',
                 '_stack_snapshot', '_tls_snapshot', '_scratch_snapshot',
                 '_heap_snapshot', '_heap_allocator_snapshot',
                 '_base_mapped_pages'}
        _snap = {}
        for k, v in self.__dict__.items():
            if k in _skip or callable(v):
                continue
            try:
                _snap[k] = _copy.deepcopy(v)
            except (TypeError, Exception):
                pass  # skip un-copyable objects
        self._setup_pystate_snapshot = _snap
        self._setup_attr_keys = set(self.__dict__.keys())

    def _apply_runtime_code_fixes(self):
        # The post-0x155b68 cert path calls 0x101c211c with only x0 prepared.
        # In our mapped image that address is a bare RET, which short-circuits
        # the stage-1 cert handoff and leaves sp+0x620 / obj+0x68 empty. The
        # adjacent helper at 0x101c2110 matches the one-arg calling convention
        # and restores the live path into the deeper cert CFF.
        # NOTE: Skip thunk when live overlay covers 0x1c0000-0x1e0000 — the
        # overlay already has the correct code at 0x1c211c and the thunk's
        # B #-3 would create an infinite loop back to 0x1c2110.
        if self.jit_live_flat is None:
            self.uc.mem_write(JIT_CERT_STAGE1_THUNK, struct.pack("<I", 0x17FFFFFD))

    # Runtime bases from the nmsscr RW dump session
    NMSSCR_LIVE_BASE = 0x735e46a000
    JIT_LIVE_BASE    = 0x7355f04000  # fallback JIT base from older nmsscr_rw session
    JIT_SEG_LIVE_BASE = 0x7352092000  # fallback JIT base from jit_seg dump session

    def _load_nmsscr_rw(self):
        """Load nmsscr's live RW segments (.data/.bss) to provide runtime-initialized globals.
        These contain function pointers, vtable data, and state set during nmssCoreInit.
        Pointers within nmsscr are rebased from NMSSCR_LIVE_BASE to CODE_BASE (0).
        """
        # Load all nmsscr RW dumps: BSS, runtime data tables, etc.
        # The .data/.got at 0x4e4000 is already set up by _apply_relocations(),
        # but we still overlay BSS and other runtime-initialized segments.
        rw_files = [
            (0x13e000, "nmsscr_rw_13e000.bin"),
            (0x17b000, "nmsscr_rw_17b000.bin"),
            (0x17f000, "nmsscr_rw_17f000.bin"),
            (0x3c0000, "nmsscr_rw_3c0000.bin"),
            (0x3c5000, "nmsscr_rw_3c5000.bin"),
            (0x4e4000, "nmsscr_rw_4e4000.bin"),
            (0x4e9000, "nmsscr_rw_4e9000.bin"),
            (0x515000, "nmsscr_rw_515000.bin"),
            (0x54b000, "nmsscr_rw_54b000.bin"),
            (0x571000, "nmsscr_rw_571000.bin"),
        ]
        script_dir = os.path.dirname(os.path.abspath(__file__))
        for offset, fname in rw_files:
            path = os.path.join(script_dir, fname)
            if not os.path.exists(path):
                continue
            with open(path, "rb") as f:
                data = bytearray(f.read())

            # Rebase nmsscr-internal and JIT pointers. Preserve tagged/live-snapshot
            # runtime pointers so later TBI mapping can reach their real pages.
            rebased = 0
            jit_rebased = 0
            preserved = 0
            zeroed = 0
            for i in range(0, len(data) - 7, 8):
                val = struct.unpack_from('<Q', data, i)[0]
                if val == 0:
                    continue
                if self.NMSSCR_LIVE_BASE <= val < self.NMSSCR_LIVE_BASE + 0x600000:
                    # nmsscr-internal pointer: rebase to CODE_BASE
                    new_val = val - self.NMSSCR_LIVE_BASE + CODE_BASE
                    struct.pack_into('<Q', data, i, new_val)
                    rebased += 1
                else:
                    new_val = None
                    jit_runtime_size = self._jit_runtime_size()
                    for base in self._jit_live_bases:
                        if base <= val < base + jit_runtime_size:
                            new_val = val - base + JIT_BASE
                            break
                    if new_val is not None:
                        # JIT module pointer: rebase to emulator JIT mapping
                        struct.pack_into('<Q', data, i, new_val)
                        jit_rebased += 1
                    elif self._should_preserve_overlay_ptr(val):
                        preserved += 1
                    elif val > 0x700000000000 or (0x7000000000 <= val < 0x8000000000):
                        # Other external runtime pointer: zero it
                        struct.pack_into('<Q', data, i, 0)
                        zeroed += 1

            # Write over the emulator's memory (after relocations, so live values win)
            self.uc.mem_write(offset, bytes(data))
            self.log(
                f"Loaded nmsscr RW: 0x{offset:x} ({len(data)} bytes, "
                f"{rebased} nmsscr + {jit_rebased} JIT ptrs rebased, "
                f"{preserved} preserved, {zeroed} zeroed)"
            )

        # Some live RW globals point at process-local runtime caches that do not
        # survive snapshot transplant. On a clean process these start null/empty;
        # preserving the snapshot values makes nmsscr walk stale heap objects and
        # tree nodes from the donor run.
        for addr, size in STALE_NMSSCR_RUNTIME_ZERO_RANGES:
            self.uc.mem_write(addr, b"\x00" * size)

    def _load_native_module(self):
        """Load only the nmsscr PT_LOAD segments.

        Writing the whole ELF file flat at CODE_BASE pollutes the RW/BSS tail
        with non-loadable section data. Several native globals live in that
        zero-fill range (for example 0x4e8c08/0x4e8c70), so they must start as
        zeroed runtime state, not as bytes from .comment/.symtab-style data.
        """
        phdrs = self._parse_elf_program_headers(self.binary_data)
        if not phdrs:
            self.uc.mem_write(CODE_BASE, self.binary_data)
            return

        for ph in phdrs:
            if ph["type"] != 1 or ph["filesz"] == 0:
                continue
            start = ph["offset"]
            end = start + ph["filesz"]
            self.uc.mem_write(CODE_BASE + ph["vaddr"], self.binary_data[start:end])
            if ph["memsz"] > ph["filesz"]:
                bss_addr = CODE_BASE + ph["vaddr"] + ph["filesz"]
                bss_size = ph["memsz"] - ph["filesz"]
                self.uc.mem_write(bss_addr, b"\x00" * bss_size)

    def _load_jit_module(self):
        """Load JIT module ELF segments and patch GOT entries."""
        data = self.jit_data

        # Load LOAD[0]: vaddr=0, file_offset=0, filesz=0x410f20
        load0 = data[JIT_LOAD0_OFFSET : JIT_LOAD0_OFFSET + JIT_LOAD0_FILESZ]
        self.uc.mem_write(JIT_BASE + JIT_LOAD0_VADDR, load0)

        # Load LOAD[1]: vaddr=0x415920, file_offset=0x411920, filesz=0x3702c
        load1 = data[JIT_LOAD1_OFFSET : JIT_LOAD1_OFFSET + JIT_LOAD1_FILESZ]
        self.uc.mem_write(JIT_BASE + JIT_LOAD1_VADDR, load1)

        # Zero BSS: vaddr=0x44c94c, size=0x5b9c
        bss_vaddr = JIT_LOAD1_VADDR + JIT_LOAD1_FILESZ
        bss_size  = JIT_LOAD1_MEMSZ - JIT_LOAD1_FILESZ
        self.uc.mem_write(JIT_BASE + bss_vaddr, b'\x00' * bss_size)

        # The emulator still uses jit_module.bin as the structural base image,
        # but some hot helper chains were captured from a materially different
        # live JIT. Overlay just those code windows from jit_live_flat.bin so
        # executed bytes match the live disassembly used for debugging.
        if self.jit_live_flat is not None:
            for start, end in LIVE_JIT_CODE_OVERLAY_RANGES:
                chunk = self.jit_live_flat[start:end]
                if len(chunk) != end - start:
                    continue
                self.uc.mem_write(JIT_BASE + start, chunk)
                self.log(
                    f"Overlayed live JIT code {JIT_BASE + start:#x}-{JIT_BASE + end:#x}"
                )

        # The live overlay at 0x1c0000-0x1e0000 overwrites several small module
        # helper functions at 0x1c20f0-0x1c2120 that are called by dozens of
        # module code sites (42 BL call sites).  We must:
        #   1. Save the live cert prologue bytes (0x1c20f4-0x1c211f)
        #   2. Restore module helper bytes at 0x1c20f0-0x1c2120
        #   3. Write a relocated cert prologue to scratch exec space
        #   4. Patch cert entry BLs to target the relocated prologue
        if self.jit_live_flat is not None and LIVE_CERT_OVERLAY_ACTIVE:
            self._fix_cert_prologue_helper_conflict()

            print("[CERT-ENTRY] Patched cert BLs -> relocated prologue, "
                  "restored module helpers at 0x1c20f0-0x1c2120", flush=True)

        # Shadow module rodata for crypto functions.
        # Module crypto code (0x55000-0x6c000) uses ADRP to reference lookup
        # tables (AES S-box, round constants) at pages 0x3a6000-0x3ae000.
        # The live JIT overlay overwrites those addresses with different code.
        # We copy the module rodata to a shadow region and patch the ADRP
        # instructions in the module crypto functions to point there instead.
        self._install_module_rodata_shadow()

        # Load extended live data area beyond BSS — runtime-initialized tables
        # used by encoding functions (e.g., 0x1d8a54 reads lookup data at 0x4e4340).
        # The ELF only covers up to ~0x4524E8 but live data extends to 0x4f0000.
        if self.jit_live_flat is not None:
            elf_end = JIT_LOAD1_VADDR + JIT_LOAD1_MEMSZ  # 0x4524E8
            live_end = len(self.jit_live_flat)
            if live_end > elf_end:
                ext_data = bytearray(self.jit_live_flat[elf_end:live_end])
                # Rebase JIT/nmsscr pointers (same logic as _load_jit_rw_segments)
                ext_rebased = 0
                ext_preserved = 0
                ext_zeroed = 0
                for i in range(0, len(ext_data) - 7, 8):
                    val = struct.unpack_from('<Q', ext_data, i)[0]
                    if val == 0:
                        continue
                    if self.NMSSCR_LIVE_BASE <= val < self.NMSSCR_LIVE_BASE + 0x600000:
                        new_val = val - self.NMSSCR_LIVE_BASE + CODE_BASE
                        struct.pack_into('<Q', ext_data, i, new_val)
                        ext_rebased += 1
                    else:
                        new_val = None
                        jit_runtime_size = self._jit_runtime_size()
                        for base in self._jit_live_bases:
                            if base <= val < base + jit_runtime_size:
                                new_val = val - base + JIT_BASE
                                break
                        if new_val is not None:
                            struct.pack_into('<Q', ext_data, i, new_val)
                            ext_rebased += 1
                        elif self._should_preserve_overlay_ptr(val):
                            ext_preserved += 1
                        elif 0x7000000000 <= val < 0x8000000000:
                            # Unknown device pointer — zero it
                            struct.pack_into('<Q', ext_data, i, 0)
                            ext_zeroed += 1
                self.uc.mem_write(JIT_BASE + elf_end, bytes(ext_data))
                self.log(f"Loaded extended live data: {JIT_BASE + elf_end:#x}-{JIT_BASE + live_end:#x} "
                        f"({live_end - elf_end:#x} bytes, {ext_rebased} rebased, "
                        f"{ext_preserved} preserved, {ext_zeroed} zeroed)")

        # The JIT dispatch tree uses SIGNED relational branches (b.gt/b.le)
        # intentionally — the CFF states are arranged for signed comparison.
        # Do NOT patch to unsigned; that breaks the binary search and causes
        # every CFF state to self-loop because the tree can't find handlers.
        # self._patch_jit_dispatch_unsigned_branches()

        # Apply R_AARCH64_RELATIVE relocations from RELA section
        self._apply_jit_relative_relocs()

        # Load live JIT RW segments FIRST — they contain runtime-initialized data
        # including algorithm tables. Must be loaded before GOT patching because the
        # RW overlay at 0x415000 covers the GOT range (0x446xxx) and would overwrite
        # GOT patches if loaded after.
        self._load_jit_rw_segments()

        # Setup JIT stub area (RET instructions for unknown calls)
        self._setup_jit_stubs()

        # Patch GOT: JMPREL (JUMP_SLOT) entries
        self._patch_jit_jmprel()

        # Patch GOT: GLOB_DAT entries
        self._patch_jit_glob_dat()

        # Patch remaining GOT entries that still have runtime addresses
        self._patch_jit_remaining_got()

        # Restore only the specific live predicate globals we still need. The
        # full donor-page overlay is too broad and reintroduces stale pointers
        # from unrelated early-execution tables.
        self._patch_live_predicate_slots()

        # Apply memdump data overlay if available — this replaces the pre-relocation
        # data segments with post-relocation data captured from a real device memory
        # dump, fixing ~14000 internal pointer relocations that were previously wrong.
        self._apply_memdump_data_overlay()

        self.log(f"JIT module loaded at {JIT_BASE:#x}, encoder at {JIT_ENCODER_FN:#x}")

    # ---- Memdump data overlay constants ----
    MEMDUMP_DATA_OVERLAY_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "memdump_data_overlay.bin")
    MEMDUMP_DATA_OVERLAY_JSON = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "memdump_data_overlay.json")

    def _apply_memdump_data_overlay(self):
        """Overlay JIT data segments from full process memory dump.

        The memdump's data segments have correct post-relocation internal
        pointers (already rebased from memdump VA to emulator VA during
        overlay generation). This fixes ~14000 CFF dispatch table entries
        and other internal function pointers that the ELF relocation engine
        could not resolve correctly.
        """
        if not os.path.exists(self.MEMDUMP_DATA_OVERLAY_PATH):
            return
        if not os.path.exists(self.MEMDUMP_DATA_OVERLAY_JSON):
            return

        with open(self.MEMDUMP_DATA_OVERLAY_JSON) as f:
            meta = json.load(f)
        with open(self.MEMDUMP_DATA_OVERLAY_PATH, "rb") as f:
            overlay_bin = f.read()

        rodata_off = meta["rodata_offset"]  # 0x4b0000
        rodata_sz = meta["rodata_size"]     # 0x34000
        data_off = meta["data_offset"]      # 0x4e4000
        data_sz = meta["data_size"]         # 0x5000
        bss_off = meta["bss_offset"]        # 0x4e9000
        bss_sz = meta["bss_size"]           # 0x7000

        # The overlay bin is: rodata || data || bss
        rodata_data = overlay_bin[0:rodata_sz]
        data_data = overlay_bin[rodata_sz:rodata_sz + data_sz]
        bss_data = overlay_bin[rodata_sz + data_sz:rodata_sz + data_sz + bss_sz]

        # Write rodata overlay
        self.uc.mem_write(JIT_BASE + rodata_off, rodata_data)
        # Write data overlay
        self.uc.mem_write(JIT_BASE + data_off, data_data)
        # Write bss overlay
        self.uc.mem_write(JIT_BASE + bss_off, bss_data)

        print(f"[MEMDUMP-OVERLAY] Applied post-relocation data segments from memory dump:", flush=True)
        print(f"  rodata: {JIT_BASE + rodata_off:#x} ({rodata_sz:#x} bytes)", flush=True)
        print(f"  data:   {JIT_BASE + data_off:#x} ({data_sz:#x} bytes)", flush=True)
        print(f"  bss:    {JIT_BASE + bss_off:#x} ({bss_sz:#x} bytes)", flush=True)

        # Re-apply GOT patches that may have been overwritten if any GOT entries
        # fall within the overlay range (unlikely since GOT is at 0x446xxx)
        # and re-apply predicate slots that were just set
        for slot_off, cell_addr in self._jit_live_predicate_cells.items():
            if rodata_off <= slot_off < rodata_off + rodata_sz or \
               data_off <= slot_off < data_off + data_sz or \
               bss_off <= slot_off < bss_off + bss_sz:
                self.uc.mem_write(JIT_BASE + slot_off, struct.pack("<Q", cell_addr))

    def _patch_live_predicate_slots(self):
        if not self.jit_data:
            return

        for idx, (slot_off, initial_value) in enumerate(LIVE_JIT_PREDICATE_SLOTS.items()):
            cell_addr = LIVE_JIT_PREDICATE_CELL_BASE + idx * LIVE_JIT_PREDICATE_CELL_STRIDE
            self.uc.mem_write(cell_addr, b"\x00" * LIVE_JIT_PREDICATE_CELL_STRIDE)
            self.uc.mem_write(cell_addr, struct.pack("<I", initial_value & 0xFFFFFFFF))
            self.uc.mem_write(JIT_BASE + slot_off, struct.pack("<Q", cell_addr))
            self._jit_live_predicate_cells[slot_off] = cell_addr
            if self.jit_live_flat is not None and slot_off + 8 <= len(self.jit_live_flat):
                donor_ptr = struct.unpack_from("<Q", self.jit_live_flat, slot_off)[0]
            else:
                donor_ptr = 0
            self.log(
                f"Patched live predicate slot {JIT_BASE + slot_off:#x}: "
                f"{donor_ptr:#x} -> {cell_addr:#x} (init={initial_value:#x})"
            )

    def _load_jit_rw_segments(self):
        """Load live JIT RW segment dumps as overlays over the ELF data.
        These contain runtime-initialized algorithm tables set during nmssCoreInit.
        The local artifacts come from multiple ASLR instances, so JIT pointers are
        rebased against the snapshot-provided JIT base first, then the older
        fallback bases.
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rw_files = [
            (0x415000, "jit_seg_415000.bin"),
            (0x448000, "jit_seg_448000.bin"),
            (0x44d000, "jit_seg_44d000.bin"),
        ]
        total_rebased = 0
        total_preserved = 0
        total_zeroed = 0
        jit_runtime_size = self._jit_runtime_size()
        for vaddr, fname in rw_files:
            path = os.path.join(script_dir, fname)
            if not os.path.exists(path):
                continue
            with open(path, "rb") as f:
                data = bytearray(f.read())

            # The 0x44d000 RW segment in jit_seg_44d000.bin is sparse; overlay
            # it from the full live flat snapshot when available so symbols like
            # x.49 / y.50 keep their real runtime values.
            if self.jit_live_flat is not None and vaddr == 0x44d000:
                live_slice = self.jit_live_flat[vaddr:vaddr + len(data)]
                if len(live_slice) == len(data):
                    data = bytearray(live_slice)

            rebased = 0
            preserved = 0
            zeroed = 0
            for i in range(0, len(data) - 7, 8):
                val = struct.unpack_from('<Q', data, i)[0]
                if val == 0:
                    continue
                if self.NMSSCR_LIVE_BASE <= val < self.NMSSCR_LIVE_BASE + 0x600000:
                    # nmsscr pointer: rebase
                    new_val = val - self.NMSSCR_LIVE_BASE + CODE_BASE
                    struct.pack_into('<Q', data, i, new_val)
                    rebased += 1
                else:
                    new_val = None
                    # Prioritize JIT_SEG_LIVE_BASE for jit_seg files since
                    # those dumps came from the seg session, not the snapshot
                    # session.  With JIT_RUNTIME_SIZE much larger than the
                    # actual JIT image, the wrong base can match first.
                    seg_first_bases = [self.JIT_SEG_LIVE_BASE] + [
                        b for b in self._jit_live_bases if b != self.JIT_SEG_LIVE_BASE
                    ]
                    for base in seg_first_bases:
                        if base <= val < base + jit_runtime_size:
                            new_val = val - base + JIT_BASE
                            break
                    if new_val is not None:
                        # JIT-internal pointer: rebase from whichever live JIT
                        # snapshot/session this dump came from.
                        struct.pack_into('<Q', data, i, new_val)
                        dest_vaddr = vaddr + i
                        if JIT_LIVE_GOT_OVERRIDE_START <= dest_vaddr < JIT_LIVE_GOT_OVERRIDE_END:
                            self._jit_live_got_overrides[JIT_BASE + dest_vaddr] = new_val
                        rebased += 1
                    elif self._should_preserve_overlay_ptr(val):
                        preserved += 1
                    elif val > 0x700000000000 or (0x7000000000 <= val < 0x8000000000):
                        # External pointer: zero
                        struct.pack_into('<Q', data, i, 0)
                        zeroed += 1

            self.uc.mem_write(JIT_BASE + vaddr, bytes(data))
            total_rebased += rebased
            total_preserved += preserved
            total_zeroed += zeroed

        if total_rebased or total_preserved or total_zeroed:
            self.log(
                f"JIT RW overlay: {total_rebased} ptrs rebased, "
                f"{total_preserved} preserved, {total_zeroed} zeroed"
            )

    def _patch_jit_dispatch_unsigned_branches(self):
        """Patch signed hash-tree branches to unsigned in the JIT dispatch forest."""
        data = self.jit_data
        cmp_w_reg_mask = 0xFFE0FC1F
        cmp_w_reg_base = 0x6B00001F  # cmp wN, wM (alias of subs wzr, wN, wM)
        b_cond_mask = 0xFF000010
        b_cond_base = 0x54000000
        cond_gt = 0xC
        cond_le = 0xD
        cond_hi = 0x8
        cond_ls = 0x9

        patched_gt = 0
        patched_le = 0

        for off in range(JIT_UNSIGNED_TREE_PATCH_START, JIT_UNSIGNED_TREE_PATCH_END - 8, 4):
            cmp_insn = struct.unpack_from("<I", data, off)[0]
            if (cmp_insn & cmp_w_reg_mask) != cmp_w_reg_base:
                continue

            branch_off = off + 4
            branch_insn = struct.unpack_from("<I", data, branch_off)[0]
            if (branch_insn & b_cond_mask) != b_cond_base:
                continue

            cond = branch_insn & 0xF
            if cond == cond_gt:
                patched = (branch_insn & ~0xF) | cond_hi
                patched_gt += 1
            elif cond == cond_le:
                patched = (branch_insn & ~0xF) | cond_ls
                patched_le += 1
            else:
                continue

            self.uc.mem_write(JIT_BASE + branch_off, struct.pack("<I", patched))

        self.log(
            "Patched JIT dispatch branches to unsigned:"
            f" gt->hi={patched_gt} le->ls={patched_le}"
            f" range=[{JIT_BASE + JIT_UNSIGNED_TREE_PATCH_START:#x},"
            f" {JIT_BASE + JIT_UNSIGNED_TREE_PATCH_END:#x})"
        )

    def _jit_vaddr_to_file(self, vaddr):
        """Convert JIT module vaddr to file offset."""
        if JIT_LOAD0_VADDR <= vaddr < JIT_LOAD0_VADDR + JIT_LOAD0_FILESZ:
            return vaddr - JIT_LOAD0_VADDR + JIT_LOAD0_OFFSET
        if JIT_LOAD1_VADDR <= vaddr < JIT_LOAD1_VADDR + JIT_LOAD1_FILESZ:
            return vaddr - JIT_LOAD1_VADDR + JIT_LOAD1_OFFSET
        return None

    def _fix_cert_prologue_helper_conflict(self):
        """Resolve the conflict between live cert prologue and module helpers.

        The live overlay at 0x1c0000-0x1e0000 overwrites small module helper
        functions at 0x1c20f0-0x1c2120 (called by 42 BL sites).  We:
        1. Copy the live cert prologue (0x1c20f4-0x1c211f) to scratch exec space
        2. Restore module bytes at 0x1c20f0-0x1c2120
        3. Append a B to JIT_BASE+0x1c2120 at end of the relocated prologue
        4. Patch cert entry BLs (0x108fa0, 0x13377c) to target the stub
        """
        # Put the stub within the JIT module address space (BL range is ±128MB,
        # so scratch space at 0x64000000 is unreachable from JIT at 0x10000000).
        # Use the gap between LOAD0 end (0x410f20) and LOAD1 start (0x415920).
        STUB_ADDR = JIT_BASE + 0x411000

        # 1. Copy the live cert prologue bytes (currently in emulator memory
        #    because the overlay was already applied)
        prologue_start = 0x1c20f4
        prologue_end = 0x1c2120  # exclusive — 11 instructions (44 bytes)
        live_prologue = bytes(self.uc.mem_read(JIT_BASE + prologue_start,
                                               prologue_end - prologue_start))

        # 2. Build the relocated stub: live prologue + B back to JIT code
        stub = bytearray(live_prologue)
        # Append: B JIT_BASE+0x1c2120
        # PC of the branch = STUB_ADDR + len(stub)
        branch_pc = STUB_ADDR + len(stub)
        branch_target = JIT_BASE + prologue_end
        branch_offset = (branch_target - branch_pc) >> 2
        branch_imm26 = branch_offset & 0x3FFFFFF
        stub += struct.pack('<I', 0x14000000 | branch_imm26)  # B imm26
        self.uc.mem_write(STUB_ADDR, bytes(stub))
        print(f"[CERT-PROLOGUE] Relocated {len(live_prologue)} bytes to "
              f"{STUB_ADDR:#x}, B -> {JIT_BASE + prologue_end:#x}", flush=True)

        # 3. Restore module helper bytes at 0x1c20f0-0x1c2120
        module_bytes = self.jit_data[prologue_start - 4:prologue_end]
        # Actually restore from 0x1c20f0 to 0x1c2120 (48 bytes)
        restore_start = 0x1c20f0
        restore_end = 0x1c2120
        module_helpers = self.jit_data[restore_start:restore_end]
        self.uc.mem_write(JIT_BASE + restore_start, module_helpers)
        print(f"[CERT-PROLOGUE] Restored module helpers at "
              f"{JIT_BASE + restore_start:#x}-{JIT_BASE + restore_end:#x}", flush=True)

        # 4. Patch cert entry BLs to target the relocated prologue
        for caller in (0x108fa0, 0x13377c):
            bl_target = STUB_ADDR
            bl_offset = (bl_target - (JIT_BASE + caller)) >> 2
            bl_imm26 = bl_offset & 0x3FFFFFF
            bl_word = 0x94000000 | bl_imm26
            self.uc.mem_write(JIT_BASE + caller, struct.pack('<I', bl_word))

    def _install_module_rodata_shadow(self):
        """Shadow module rodata at a separate address so module crypto code works.

        The live JIT overlay replaces pages 0x3a6000-0x3ae000 with different
        code.  Module crypto functions (AES key schedule, CBC, etc.) at
        0x55000-0x6c000 use ADRP to read lookup tables from those pages.  We
        copy the original module bytes to JIT_BASE+0x500000 and rewrite every
        ADRP in the crypto range that targeted a conflicting page.
        """
        SHADOW_BASE = 0x500000  # relative to JIT_BASE
        CONFLICT_PAGES = {
            0x3a6000: SHADOW_BASE + 0x0000,
            0x3a7000: SHADOW_BASE + 0x1000,
            0x3a8000: SHADOW_BASE + 0x2000,
            0x3ae000: SHADOW_BASE + 0x8000,
        }
        SHADOW_SIZE = 0x9000  # 0x500000..0x509000
        CRYPTO_START = 0x55000
        CRYPTO_END = 0x6c000

        if self.jit_data is None:
            return

        # Map shadow region
        try:
            self.uc.mem_map(JIT_BASE + SHADOW_BASE, SHADOW_SIZE, UC_PROT_READ)
        except Exception:
            pass  # already mapped

        # Copy module rodata pages to shadow
        for old_page, new_off in CONFLICT_PAGES.items():
            chunk = self.jit_data[old_page:old_page + 0x1000]
            if len(chunk) == 0x1000:
                self.uc.mem_write(JIT_BASE + new_off, chunk)

        # Patch ADRP instructions in module crypto code
        patch_count = 0
        for off in range(CRYPTO_START, min(CRYPTO_END, len(self.jit_data)), 4):
            word = struct.unpack_from('<I', self.jit_data, off)[0]
            if (word & 0x9F000000) != 0x90000000:
                continue  # not ADRP
            immlo = (word >> 29) & 0x3
            immhi = (word >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            old_page = (off & ~0xFFF) + (imm << 12)
            if old_page not in CONFLICT_PAGES:
                continue
            new_page = CONFLICT_PAGES[old_page]
            new_delta = new_page - (off & ~0xFFF)
            new_imm = new_delta >> 12
            rd = word & 0x1F
            new_immhi = (new_imm >> 2) & 0x7FFFF
            new_immlo = new_imm & 0x3
            new_word = 0x90000000 | (new_immlo << 29) | (new_immhi << 5) | rd
            self.uc.mem_write(JIT_BASE + off, struct.pack('<I', new_word))
            patch_count += 1

        if patch_count:
            print(f"[RODATA-SHADOW] Installed {patch_count} ADRP patches "
                  f"(crypto 0x{CRYPTO_START:x}-0x{CRYPTO_END:x} -> shadow 0x{SHADOW_BASE:x})",
                  flush=True)

    def _apply_jit_relative_relocs(self):
        """Apply R_AARCH64_RELATIVE relocations for JIT module."""
        data = self.jit_data
        R_AARCH64_RELATIVE = 1027

        applied = 0
        n_rela = JIT_RELA_SIZE // 24
        for i in range(n_rela):
            off = JIT_RELA_VADDR + i * 24
            file_off = self._jit_vaddr_to_file(off)
            if file_off is None:
                continue
            r_offset = struct.unpack_from('<Q', data, file_off)[0]
            r_info   = struct.unpack_from('<Q', data, file_off + 8)[0]
            r_addend = struct.unpack_from('<q', data, file_off + 16)[0]
            r_type = r_info & 0xFFFFFFFF

            if r_type == R_AARCH64_RELATIVE:
                # *offset = JIT_BASE + addend
                target_emu = JIT_BASE + r_addend
                dest_emu   = JIT_BASE + r_offset
                try:
                    self.uc.mem_write(dest_emu,
                                      struct.pack("<Q", target_emu & 0xFFFFFFFFFFFFFFFF))
                    applied += 1
                except Exception:
                    pass

        self.log(f"Applied {applied} JIT RELATIVE relocations")

    def _setup_jit_stubs(self):
        """Create stub table at JIT_STUB_BASE with MOV X0,#0; RET stubs."""
        # Each stub: MOV X0, XZR (0xAA1F03E0) + RET (0xD65F03C0) = 8 bytes
        mov_x0_zero = struct.pack("<I", 0xAA1F03E0)  # MOV X0, XZR
        ret_insn = struct.pack("<I", 0xd65f03c0)      # RET
        stub_pair = mov_x0_zero + ret_insn

        # The stub area holds one stub per symbol slot (up to 512 stubs, 8 bytes each)
        stub_count = 512
        stubs = stub_pair * stub_count
        self.uc.mem_write(JIT_STUB_BASE, stubs)

        # Register the generic fallback stub
        self.hooked_functions[JIT_STUB_BASE] = self._hook_noop
        self.log(f"JIT stub table at {JIT_STUB_BASE:#x} ({stub_count} slots)")

    def _get_jit_stub(self, sym_name):
        """
        Return the address of a stub for the given symbol.
        For functions we hook, return the nmsscr hook address directly.
        For unknown functions, return the RET stub in JIT_STUB_BASE.
        """
        # Map libc symbol names to existing nmsscr hook addresses
        # These addresses already have hook handlers registered
        nmsscr_hooks = {
            'malloc':       0x272968,
            'free':         0x2729a0,
            'memcpy':       0x060150,
            'memset':       0x05f9b0,
            'memmove':      0x0601e0,
            'strlen':       0x060330,
            'sprintf':      0x12807c,
            'strcmp':       None,   # handled below
            'strcasecmp':   None,
            'strdup':       None,
            'realloc':      0x272968,  # redirect to malloc hook (size is first arg)
            'calloc':       None,      # special
            'abort':        None,
            'exit':         None,
        }

        if sym_name in nmsscr_hooks:
            addr = nmsscr_hooks[sym_name]
            if addr is not None:
                return addr

        # For symbols not in nmsscr hooks, allocate a unique stub slot
        # Use a slot based on hash of name (8 bytes per stub: MOV X0,#0 + RET)
        slot = hash(sym_name) & 0xFF
        stub_addr = JIT_STUB_BASE + slot * 8
        # Register a noop for it if not already registered
        if stub_addr not in self.hooked_functions:
            self.hooked_functions[stub_addr] = self._make_jit_noop(sym_name)
        return stub_addr

    def _make_jit_noop(self, sym_name):
        """Create a named noop handler for debug purposes."""
        def handler(uc, x0, x1, x2, x8):
            if self.verbose:
                print(f"  [JIT-NOOP] {sym_name}(x0={x0:#x})")
            uc.reg_write(UC_ARM64_REG_X0, 0)
        return handler

    def _patch_jit_jmprel(self):
        """Patch all JMPREL (JUMP_SLOT) GOT entries with stub addresses."""
        data = self.jit_data
        R_AARCH64_JUMP_SLOT = 1026

        # Parse dynsym to get symbol names
        dynsym_names = self._parse_jit_dynsym()

        n_jmprel = JIT_JMPREL_SIZE // 24
        patched = 0
        for i in range(n_jmprel):
            off = JIT_JMPREL_VADDR + i * 24
            file_off = self._jit_vaddr_to_file(off)
            if file_off is None:
                continue

            r_offset = struct.unpack_from('<Q', data, file_off)[0]
            r_info   = struct.unpack_from('<Q', data, file_off + 8)[0]
            r_type = r_info & 0xFFFFFFFF
            r_sym  = r_info >> 32

            if r_type != R_AARCH64_JUMP_SLOT:
                continue

            got_emu = JIT_BASE + r_offset
            sym_info = dynsym_names.get(r_sym)
            if sym_info is None:
                # Point to fallback
                self._write_jit_got(got_emu, JIT_STUB_BASE)
                continue

            name, st_shndx, st_value = sym_info

            if st_shndx != 0 and st_value != 0:
                # Defined in JIT module: point to JIT_BASE + value
                self._write_jit_got(got_emu, JIT_BASE + st_value)
                self.log(f"JMPREL[{i}] {name!r}: defined -> {JIT_BASE + st_value:#x}")
            else:
                # External: get stub address
                stub_addr = self._get_jit_stub(name)
                self._write_jit_got(got_emu, stub_addr)
                self.log(f"JMPREL[{i}] {name!r}: external -> stub {stub_addr:#x}")
            patched += 1

        self.log(f"Patched {patched} JMPREL GOT entries")

    def _patch_jit_glob_dat(self):
        """Patch all GLOB_DAT GOT entries."""
        data = self.jit_data
        R_AARCH64_GLOB_DAT = 1025

        dynsym_names = self._parse_jit_dynsym()

        n_rela = JIT_RELA_SIZE // 24
        patched = 0
        for i in range(n_rela):
            off = JIT_RELA_VADDR + i * 24
            file_off = self._jit_vaddr_to_file(off)
            if file_off is None:
                continue

            r_offset = struct.unpack_from('<Q', data, file_off)[0]
            r_info   = struct.unpack_from('<Q', data, file_off + 8)[0]
            r_addend = struct.unpack_from('<q', data, file_off + 16)[0]
            r_type = r_info & 0xFFFFFFFF
            r_sym  = r_info >> 32

            if r_type != R_AARCH64_GLOB_DAT:
                continue

            got_emu = JIT_BASE + r_offset
            sym_info = dynsym_names.get(r_sym)
            if sym_info is None:
                self._write_jit_got(got_emu, JIT_STUB_BASE)
                continue

            name, st_shndx, st_value = sym_info

            if st_shndx == 0 and st_value == 0:
                # Pure external symbol - function or data
                self._patch_jit_glob_dat_external(got_emu, name)
            elif st_shndx != 0 and st_value != 0:
                # Defined in JIT (x/y obfuscation vars, internal data)
                target = JIT_BASE + st_value
                self._write_jit_got(got_emu, target)
                self.log(f"GLOB_DAT {name!r}: defined val={st_value:#x} -> {target:#x}")
            else:
                self._write_jit_got(got_emu, JIT_STUB_BASE)
            patched += 1

        self.log(f"Patched {patched} GLOB_DAT GOT entries")

    def _patch_jit_glob_dat_external(self, got_emu, name):
        """Handle external GLOB_DAT symbol."""
        if name == '__stack_chk_guard':
            # Write the canary value directly into GOT cell
            self.uc.mem_write(got_emu, struct.pack("<Q", 0xDEADBEEFCAFEBABE))
            return

        # Function pointers that need to call back into our hooks
        func_syms = {
            'malloc', 'free', 'memcpy', 'memset', 'memmove', 'strlen',
            'sprintf', 'strcmp', 'strcasecmp', 'strdup', 'realloc', 'calloc',
            'fread', 'fwrite', 'fseek', 'fopen', 'fclose', 'fputc', 'fputs',
            'ferror', 'feof', 'fflush', 'ftell', 'fstat', 'fileno',
            'pthread_create', 'pthread_join', 'pthread_mutex_lock',
            'pthread_mutex_unlock', 'pthread_mutex_init', 'pthread_mutex_destroy',
            'pthread_rwlock_rdlock', 'pthread_rwlock_wrlock', 'pthread_rwlock_unlock',
            'pthread_rwlock_init', 'pthread_rwlock_destroy',
            'pthread_setspecific', 'pthread_getspecific', 'pthread_self',
            'pthread_once', 'pthread_attr_init', 'pthread_attr_destroy',
            'pthread_attr_setdetachstate', 'pthread_key_create', 'pthread_key_delete',
            'pthread_cond_wait', 'pthread_cond_broadcast', 'pthread_equal',
            'getentropy', 'dl_iterate_phdr',
            'mmap', 'munmap', 'mlock', 'madvise', 'mprotect', 'getpagesize',
            'getpid', 'geteuid', 'getauxval',
            'open', 'close', 'read', 'write', 'lseek',
            'socket', 'connect', 'bind', 'listen', 'accept', 'recv', 'send',
            'sendto', 'recvfrom', 'shutdown', 'socketpair',
            'getsockopt', 'setsockopt', 'getsockname', 'getpeername',
            'getaddrinfo', 'freeaddrinfo', 'getnameinfo', 'gethostname',
            'gethostbyname', 'inet_pton', 'inet_ntop', 'inet_ntoa',
            'dlopen', 'dlclose', 'dlsym', 'dlerror',
            'fork', 'execl', 'waitpid', 'exit', 'abort',
            'signal', 'sigaction', 'kill',
            'time', 'gettimeofday', 'gmtime', 'gmtime_r', 'localtime',
            'clock_gettime', 'strftime',
            'rand', 'srand', 'atoi', 'strtol', 'strtoul',
            'strchr', 'strrchr', 'strstr', 'strcat', 'strcpy', 'strncpy',
            'strncmp', 'strncasecmp', 'strdup', 'strpbrk', 'strcspn', 'strspn',
            'strtok_r', 'strtok',
            'qsort', 'memcmp', 'memchr', 'memrchr',
            'snprintf', 'vsnprintf', 'vasprintf', 'vfprintf', 'fprintf', 'sscanf',
            'isalpha', 'isspace', 'isupper', 'isxdigit', 'tolower', 'toupper',
            'sysconf', 'opendir', 'closedir', 'readdir',
            'access', 'stat', 'unlink', 'rename',
            'openlog', 'closelog', 'syslog',
            'syslog', 'strerror', 'strerror_r', 'basename',
            'setvbuf', 'fcntl', 'ioctl', 'syscall', 'tcgetattr', 'tcsetattr',
            'gai_strerror', 'fnmatch', 'getenv', 'getpwuid_r', 'if_nametoindex',
            'AAsset_close', 'AAsset_read', 'AAsset_getLength', 'AAssetManager_open',
            'inflateInit_', 'inflateInit2_', 'inflate', 'inflateEnd', 'zlibVersion',
            'android_set_abort_message', '__FD_SET_chk', '__cxa_finalize',
            '__cxa_atexit', '__stack_chk_fail', '__errno',
            'dup2', 'poll', 'fork', 'execl',
            'pthread_detach', 'pthread_atfork',
            'mmap', 'strpbrk', 'vasprintf', 'vsnprintf', 'getpid',
            '__sF', 'bio_lookup_lock', 'global_engine_lock',
        }

        if name in func_syms:
            stub_addr = self._get_jit_stub(name)
            # For GLOB_DAT, the GOT holds the function pointer directly
            self.uc.mem_write(got_emu, struct.pack("<Q", stub_addr))
        else:
            # Unknown external data symbol: allocate zero memory
            sym_mem = self.heap.malloc(16)
            self.uc.mem_write(got_emu, struct.pack("<Q", sym_mem))

    def _patch_jit_remaining_got(self):
        """
        Scan the entire GOT range and patch any remaining runtime addresses
        (0x7357b... pattern) with appropriate stubs.
        The GOT for JMPREL spans 0x446938..0x446f48 and GLOB_DAT spans further.
        We also need to handle the PLTGOT at the beginning of the GOT area.
        """
        # GOT range: we know JMPREL slots are 0x446938 to 0x446f48 (0xc8 bytes * 8 = 0x640)
        # Actually: JMPREL entries go from got=0x446938 to got=0x446f40 (194 entries)
        got_start = 0x446938
        # GLOB_DAT goes up to 0x447ff0 based on analysis
        got_end   = 0x448000

        # Scan all 8-byte words in GOT range for runtime-looking addresses
        runtime_prefix_lo = 0x7000000000000000
        runtime_prefix_hi = 0x8000000000000000
        # Also catch values with high 32-bits = 0x20 (PLT-like entries seen in dump)
        plt_mask = 0xFFFFFFFF00000000
        plt_val  = 0x2000000000000000

        patched = 0
        for vaddr in range(got_start, got_end, 8):
            emu_addr = JIT_BASE + vaddr
            try:
                raw = bytes(self.uc.mem_read(emu_addr, 8))
                val = struct.unpack("<Q", raw)[0]
            except Exception:
                continue

            # Check if this looks like a runtime address that slipped through
            is_runtime = (runtime_prefix_lo <= val < runtime_prefix_hi)
            # Check for 0x20XXXXXNN pattern (PLT-like residuals)
            is_plt_residual = ((val & 0xFF00000000000000) == 0x2000000000000000 and
                               (val & 0x00000000FF000000) != 0)

            if is_runtime or is_plt_residual:
                # This is a runtime address we haven't patched; replace with fallback stub
                self.uc.mem_write(emu_addr, struct.pack("<Q", JIT_STUB_BASE))
                patched += 1

        self.log(f"Patched {patched} residual runtime GOT entries")

    def _write_jit_got(self, emu_addr, value):
        """Write a 64-bit value to a GOT entry at emulator address."""
        try:
            self.uc.mem_write(emu_addr, struct.pack("<Q", value))
        except Exception as e:
            self.log(f"_write_jit_got failed at {emu_addr:#x}: {e}")

    def _parse_jit_dynsym(self):
        """
        Parse the JIT module's dynsym table.
        Returns dict: sym_idx -> (name, st_shndx, st_value)
        """
        data = self.jit_data
        dynstr_off  = JIT_DYNSTR_OFFSET
        dynstr_size = 6544
        dynstr = data[dynstr_off : dynstr_off + dynstr_size]

        dynsym_off   = JIT_DYNSYM_OFFSET
        dynsym_count = JIT_DYNSYM_COUNT

        result = {}
        for i in range(dynsym_count):
            off = dynsym_off + i * 24
            if off + 24 > len(data):
                break
            e = data[off : off + 24]
            st_name  = struct.unpack_from('<I', e)[0]
            st_info  = e[4]
            st_shndx = struct.unpack_from('<H', e, 6)[0]
            st_value = struct.unpack_from('<Q', e, 8)[0]

            if st_name < len(dynstr):
                end  = dynstr.find(b'\x00', st_name)
                name = dynstr[st_name:end].decode('ascii', 'replace') if end >= 0 else ''
            else:
                name = ''

            result[i] = (name, st_shndx, st_value)

        return result

    def _apply_relocations(self):
        """Apply R_AARCH64_RELATIVE relocations from .rela.dyn.
        These fill in vtable pointers, function pointers in globals, etc.
        R_AARCH64_RELATIVE: *offset = base + addend (base = 0 for us).
        """
        data = self.binary_data
        e_shoff = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum = struct.unpack_from('<H', data, 60)[0]

        applied = 0
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            sh_type = struct.unpack_from('<I', data, sh + 4)[0]
            if sh_type != 4:  # SHT_RELA
                continue
            rela_off = struct.unpack_from('<Q', data, sh + 24)[0]
            rela_size = struct.unpack_from('<Q', data, sh + 32)[0]
            rela_entsize = struct.unpack_from('<Q', data, sh + 56)[0]
            if rela_entsize == 0:
                rela_entsize = 24
            count = rela_size // rela_entsize

            for j in range(count):
                off = rela_off + j * rela_entsize
                r_offset = struct.unpack_from('<Q', data, off)[0]
                r_info = struct.unpack_from('<Q', data, off + 8)[0]
                r_addend = struct.unpack_from('<q', data, off + 16)[0]
                r_type = r_info & 0xFFFFFFFF

                if r_type == 1027:  # R_AARCH64_RELATIVE
                    # *offset = base + addend (base = 0)
                    if r_offset < CODE_SIZE:
                        try:
                            self.uc.mem_write(r_offset, struct.pack("<Q", r_addend & 0xFFFFFFFFFFFFFFFF))
                            applied += 1
                        except:
                            pass

        self.log(f"Applied {applied} RELATIVE relocations")

        # Also resolve GLOB_DAT relocations for x/y obfuscation variables
        # and other external symbols. The x/y checks are tautologies (always
        # take the same branch regardless of value), but the GOT entries must
        # point to valid readable memory.
        self._resolve_glob_dat()

    def _resolve_glob_dat(self):
        """Resolve R_AARCH64_GLOB_DAT relocations.
        For x/y symbols: allocate memory and write a small integer.
        For known symbols: write known addresses/values.
        For others: allocate readable zero memory.
        """
        data = self.binary_data
        e_shoff = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum = struct.unpack_from('<H', data, 60)[0]

        # Find .dynsym and .dynstr
        dynsym_off = dynsym_size = dynsym_entsize = 0
        dynstr_off = dynstr_size = 0
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            sh_type = struct.unpack_from('<I', data, sh + 4)[0]
            if sh_type == 11:  # SHT_DYNSYM
                dynsym_off = struct.unpack_from('<Q', data, sh + 24)[0]
                dynsym_size = struct.unpack_from('<Q', data, sh + 32)[0]
                dynsym_entsize = struct.unpack_from('<Q', data, sh + 56)[0]
                sh_link = struct.unpack_from('<I', data, sh + 40)[0]
                link_sh = e_shoff + sh_link * e_shentsize
                dynstr_off = struct.unpack_from('<Q', data, link_sh + 24)[0]
                dynstr_size = struct.unpack_from('<Q', data, link_sh + 32)[0]
        if dynsym_off == 0:
            return

        dynstr = data[dynstr_off:dynstr_off + dynstr_size]

        # Allocate a block for external symbol storage
        ext_base = SCRATCH_BASE + 0x100000
        ext_offset = 0

        resolved = 0
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            sh_type = struct.unpack_from('<I', data, sh + 4)[0]
            if sh_type != 4:  # SHT_RELA
                continue
            rela_off = struct.unpack_from('<Q', data, sh + 24)[0]
            rela_size = struct.unpack_from('<Q', data, sh + 32)[0]
            rela_entsize = struct.unpack_from('<Q', data, sh + 56)[0]
            if rela_entsize == 0:
                rela_entsize = 24
            count = rela_size // rela_entsize

            for j in range(count):
                off = rela_off + j * rela_entsize
                r_offset = struct.unpack_from('<Q', data, off)[0]
                r_info = struct.unpack_from('<Q', data, off + 8)[0]
                r_type = r_info & 0xFFFFFFFF
                r_sym = r_info >> 32

                if r_type != 1025:  # R_AARCH64_GLOB_DAT
                    continue
                if r_offset >= CODE_SIZE:
                    continue

                # Get symbol name
                sym_off = dynsym_off + r_sym * dynsym_entsize
                st_name_idx = struct.unpack_from('<I', data, sym_off)[0]
                end = dynstr.find(b'\x00', st_name_idx)
                sym_name = dynstr[st_name_idx:end].decode('ascii', errors='replace')

                # Allocate storage for this symbol and write GOT entry
                sym_addr = ext_base + ext_offset
                ext_offset += 16  # 16 bytes per symbol (alignment)

                # Write a default value (5 for x/y, 0 for others)
                is_xy = (sym_name == 'x' or sym_name == 'y' or
                         (sym_name.startswith('x.') and sym_name[2:].isdigit()) or
                         (sym_name.startswith('y.') and sym_name[2:].isdigit()))

                if is_xy:
                    self.uc.mem_write(sym_addr, struct.pack("<I", 0))  # runtime confirmed: all 0
                elif sym_name == '__stack_chk_guard':
                    self.uc.mem_write(sym_addr, struct.pack("<Q", 0xDEADBEEFCAFEBABE))
                elif sym_name in ('malloc', 'calloc', 'realloc', 'free',
                                  'fread', 'fwrite', 'fseek', 'fputc',
                                  'strdup', 'strcmp', 'strcasecmp',
                                  'pthread_create', 'getentropy',
                                  'dl_iterate_phdr', 'environ'):
                    # These need function pointers - point to our fallback
                    self.uc.mem_write(sym_addr, struct.pack("<Q", self.PLT_FALLBACK))
                else:
                    self.uc.mem_write(sym_addr, b'\x00' * 16)

                # Write the pointer to GOT entry
                try:
                    self.uc.mem_write(r_offset, struct.pack("<Q", sym_addr))
                    resolved += 1
                except:
                    pass

        self.log(f"Resolved {resolved} GLOB_DAT entries (ext_base={ext_base:#x})")

    def _setup_manager(self):
        self.uc.mem_write(MANAGER_BASE, b'\x00' * MANAGER_SIZE)
        # Score
        self.uc.mem_write(MANAGER_BASE + 0x314, struct.pack("<I", SCORE))
        # Device ID
        self.uc.mem_write(MANAGER_BASE + 0x340, struct.pack("<I", DEVICE_ID))
        # Raw session key bytes at MANAGER_BASE+0x380 (matches live device layout).
        # The live device stores SESSION_KEY[4:] + SESSION_KEY at +0x380.
        # Note: the CFF code reads [obj+0x388] where obj is a STACK struct
        # (not the manager), so these values are not directly used by the CFF loop.
        raw_key = SESSION_KEY[4:] + SESSION_KEY
        self.uc.mem_write(MANAGER_BASE + 0x380, raw_key[:24])
        # String at MANAGER_BASE+0x210: session key hex string (32 chars).
        # The JIT encoder reads this for its crypto computation.
        # 32 chars > 22 (short SSO limit), so use LONG SSO format.
        sk_hex = SESSION_KEY.hex().encode('ascii')  # 32-char hex string
        sk_hex_heap = self.heap.malloc(len(sk_hex) + 1)
        self.uc.mem_write(sk_hex_heap, sk_hex + b'\x00')
        # Android libc++ long SSO: [cap*2|1 at +0, size at +8, data_ptr at +16]
        sso_buf = bytearray(24)
        cap = len(sk_hex) + 1  # capacity (includes NUL)
        struct.pack_into("<Q", sso_buf, 0, (cap * 2) | 1)  # cap with long flag
        struct.pack_into("<Q", sso_buf, 8, len(sk_hex))     # size
        struct.pack_into("<Q", sso_buf, 16, sk_hex_heap)    # data pointer
        self.uc.mem_write(MANAGER_BASE + 0x210, bytes(sso_buf))
        # Detection array
        det = MANAGER_BASE + 0x900
        self.uc.mem_write(MANAGER_BASE + 0x488, struct.pack("<Q", det))
        self.uc.mem_write(det + 29*8, struct.pack("<Q", 35))
        self.uc.mem_write(det + 42*8, struct.pack("<Q", 1))
        # manager+0x3a0 (m3a0): SSO string with 8 zero bytes.
        # The SSO byte0 must be non-zero (0x10 = len 8 short SSO) so that
        # the encoder dispatch chain reads a non-null value via ldr x0,[mgr+0x3a0]
        # and takes the encoding path instead of the early-exit path.
        m3a0_sso = bytearray(24)
        m3a0_sso[0] = 0x10  # short SSO, length = 8
        self.uc.mem_write(MANAGER_BASE + 0x3a0, bytes(m3a0_sso))

    def _setup_globals(self):
        # Once-init flags: set to 0x01 (already initialized)
        for addr in [0x4e8d58, 0x4e8cb8, 0x4e8b88, 0x4eae00]:
            self.uc.mem_write(addr, bytes([0x01]))
        self.uc.mem_write(0x4e8b78, struct.pack("<Q", 0))
        self.uc.mem_write(0x4e8b70, struct.pack("<I", 0))
        # Global state
        self.uc.mem_write(0x4eae08, struct.pack("<Q", 0))
        self.uc.mem_write(0x4eadd8, struct.pack("<Q", 0))
        self.uc.mem_write(0x4eae48, struct.pack("<Q", 0))
        self.uc.mem_write(0x4eae50, struct.pack("<Q", 0))
        self.uc.mem_write(0x4eae00, bytes([0x01]))
        self.uc.mem_write(0x4eae10, struct.pack("<Q", 0))

        # Manager singleton area at 0x4e8cb8
        mgr_area = 0x4e8cb8
        # +0x90: function pointer for encoder object +0x08
        self.uc.mem_write(mgr_area + 0x90, struct.pack("<Q", self.PLT_FALLBACK))
        # Encoder algorithm parameters (constant across sessions, from live RW dump)
        # These are read by tokenProc and copied into the encoder_object at +0x1c-0x28
        self.uc.mem_write(mgr_area + 0x28, struct.pack("<I", 5))
        self.uc.mem_write(mgr_area + 0x2c, struct.pack("<I", 5))
        self.uc.mem_write(mgr_area + 0x30, struct.pack("<I", 2))
        self.uc.mem_write(mgr_area + 0x34, struct.pack("<I", 4))
        self.uc.mem_write(mgr_area + 0x38, struct.pack("<I", 3))
        self.uc.mem_write(mgr_area + 0x3c, struct.pack("<I", SCORE))
        self.uc.mem_write(mgr_area + 0x40, bytes([0x00]))
        self.uc.mem_write(mgr_area + 0x48, struct.pack("<Q", 0))
        self.uc.mem_write(mgr_area + 0x50, struct.pack("<Q", 0))
        self.uc.mem_write(mgr_area + 0x60, struct.pack("<Q", 0))
        self.uc.mem_write(mgr_area + 0x68, struct.pack("<Q", 0))
        self.uc.mem_write(mgr_area + 0x78, struct.pack("<Q", 0))
        self.uc.mem_write(mgr_area + 0x80, struct.pack("<Q", 0))
        self.uc.mem_write(mgr_area + 0x9a, bytes([0x00]))

        # Keep a plain RET scratch slot available, but do not rewrite the helper
        # object's vtable. The real finalize/copy path is native sub_20a3b0; the
        # slot at [vptr+8] is destructor-like and should stay snapshot-backed.
        ret_addr = SCRATCH_BASE + 0x10000
        self.uc.mem_write(ret_addr, struct.pack("<I", 0xd65f03c0))  # RET
        self.uc.mem_write(OUTPUT_OBJ_VCALL_STUB, struct.pack("<I", 0xd65f03c0))

        # Allocator pointer at 0x4e3680
        alloc_ptr = self.heap.malloc(0x100)
        self.uc.mem_write(0x4e3680, struct.pack("<Q", alloc_ptr))

        # String constant at 0x4382ac (empty string "")
        self.uc.mem_write(0x4382ac, b"\x00")

    def _install_hooks(self):
        self.hooked_functions = {
            # Memory management
            0x272968: self._hook_malloc, 0x27293c: self._hook_malloc,
            0x272964: self._hook_malloc,
            0x2729a0: self._hook_free, 0x272990: self._hook_free,
            0x060150: self._hook_memcpy, 0x060330: self._hook_strlen,
            0x05f9b0: self._hook_memset, 0x0601e0: self._hook_memmove,

            # String operations
            0x05f460: self._hook_string_assign,
            0x05f120: self._hook_string_append,
            0x05f1a0: self._hook_string_resize,
            0x05f1c0: self._hook_string_copy_assign,
            0x05f370: self._hook_string_find,
            0x05f640: self._hook_string_substr,
            0x05faa0: self._hook_string_concat,
            0x05fad0: self._hook_noop,  # strtok
            0x05f710: self._hook_string_create,
            0x05ee10: self._hook_string_erase,
            0x05f600: self._hook_vector_string_destroy,

            # Post-append nmsscr helpers
            0x05eec0: self._hook_vector_string_copy_ctor,
            0x05eef0: self._hook_gmtime,
            0x05fa10: self._hook_time,

            # No-ops
            0x05f020: self._hook_noop,  # __cxa_atexit
            0x05fec0: self._hook_noop,  # mutex_lock
            0x05f990: self._hook_noop,  # mutex_unlock
            0x05f2f0: self._hook_noop,  # stack_chk_fail
            0x060430: self._hook_noop,

            # Clock/rand
            0x05fb20: self._hook_clock,
            0x060290: self._hook_rand,

            # Manager/singleton
            0x180870: self._hook_get_manager,
            0x180198: self._hook_noop,
            0x180994: self._hook_noop,

            # Session key
            0x14cebc: self._hook_get_session_key,
            0x152850: self._hook_decode_session_callback,
            0x110758: self._hook_get_string_by_index,

            # String formatting
            0x12807c: self._hook_sprintf,

            # CXA guards
            0x272634: self._hook_cxa_guard_acquire,
            0x2726f4: self._hook_noop,  # guard_release
            0x272770: self._hook_noop,  # guard_abort
            0x29c76c: self._hook_cxa_throw,

            # Detection checks
            0x0be324: self._hook_det_chk,
            0x182364: self._hook_sensor_chk,

            # Complex functions - mock sub_2070a8 and sub_209dc4
            # sub_2070a8 needs complex runtime state we can't replicate
            0x2070a8: self._hook_sub_2070a8,
            0x209dc4: self._hook_sub_209dc4,
            0x1f8ee0: self._hook_noop,  # session_gen
            0x0c1080: self._hook_noop,  # data_gen

            # SVC wrapper
            0x2708a8: self._hook_svc_wrapper,

            # Additional stubs
            0x05ff10: self._hook_noop,  # pthread_mutex_init
            0x05fc60: self._hook_noop,
            0x05f860: self._hook_noop,
            0x1110d8: self._hook_noop,
            0x079ff8: self._hook_noop,
            0x224128: self._hook_noop,
            LIVE_PTHREAD_CREATE_STUB: self._hook_live_pthread_create,

            # sub_11aed8 (encryptor) and sub_11b104 (encoder) - no-op
            0x11aed8: self._hook_noop,
            0x11b104: self._hook_noop,
        }

        if self._block_mode:
            # Block hook: fires once per basic block — much faster than per-instruction
            self.uc.hook_add(UC_HOOK_BLOCK, self._block_hook)
            self.uc.hook_add(UC_HOOK_INTR, self._intr_hook)
            # Patch all hooked function entries with RET as safety net.
            # If block_hook's PC redirect fails, the RET naturally returns to caller.
            ret_insn_bytes = struct.pack("<I", 0xd65f03c0)
            for hook_addr in self.hooked_functions:
                try:
                    self.uc.mem_write(hook_addr, ret_insn_bytes)
                except:
                    pass
        elif self._range_mode:
            # Range-limited hooks: only fire for nmsscr + JIT stub ranges.
            # JIT encoder core (0x10000000-0x104FEFFF) runs with ZERO Python overhead.
            self.uc.hook_add(UC_HOOK_CODE, self._code_hook,
                            begin=0x5ee10, end=0x29c800)  # nmsscr hooked range
            # Use UC_HOOK_BLOCK for stall detection in JIT range.
            # Fires once per basic block (~10-30x less overhead than per-instruction).
            self.uc.hook_add(UC_HOOK_BLOCK, self._jit_block_hook,
                            begin=JIT_BASE, end=JIT_BASE + JIT_SIZE - 1)
            self._1702_range_hook_installed = True
            self._1702_trace_active = False
            self._1702_exec_count = 0
            self._1702_entry_count = 0
            self.uc.hook_add(UC_HOOK_CODE, self._1702_exec_range_hook,
                            begin=JIT_BASE + 0x1702c8, end=JIT_BASE + 0x170630)
            self.uc.hook_add(UC_HOOK_CODE, self._dispatch_probe_hook,
                            begin=JIT_ENTRY_TRACE_START, end=JIT_ENTRY_TRACE_END)
            self.uc.hook_add(UC_HOOK_CODE, self._dispatch_probe_hook,
                            begin=JIT_HANDOFF_TRACE_START, end=JIT_HANDOFF_TRACE_END)
            for call_pc, post_pc in JIT_CFF_BRIDGE_SITES.items():
                self.uc.hook_add(UC_HOOK_CODE, self._jit_cff_bridge_hook,
                                begin=call_pc, end=call_pc)
                self.uc.hook_add(UC_HOOK_CODE, self._jit_cff_bridge_hook,
                                begin=post_pc, end=post_pc)
            self.uc.hook_add(UC_HOOK_CODE, self._jit_inner_entry_hook,
                            begin=JIT_INNER_CFF_ENTRY, end=JIT_INNER_CFF_ENTRY_TRACE_END)
            self.uc.hook_add(UC_HOOK_CODE, self._dispatch_probe_hook,
                            begin=JIT_DISPATCH_TRACE_START, end=JIT_DISPATCH_TRACE_END)
            self.uc.hook_add(UC_HOOK_CODE, self._post_cff_dispatch_hub_hook,
                            begin=JIT_POST_CFF_DISPATCH_HUB, end=JIT_POST_CFF_DISPATCH_HUB)
            self.uc.hook_add(UC_HOOK_CODE, self._jit_once_init_hook,
                            begin=JIT_ONCE_INIT_HELPER, end=JIT_ONCE_INIT_HELPER)
            # CFF iter loop hook disabled — was a workaround for zeroed stubs,
            # corrupts real session data (patches valid heap pointers at [fp-0x60])
            # self.uc.hook_add(UC_HOOK_CODE, self._cff_iter_loop_hook,
            #                 begin=JIT_CFF_ITER_LOOP, end=JIT_CFF_ITER_LOOP + 4)
            self.uc.hook_add(UC_HOOK_CODE, self._cff_epilogue_ret_hook,
                            begin=JIT_CFF_EPILOGUE_RET, end=JIT_CFF_EPILOGUE_RET + 4)
            # Library loader hook — return 2 (not found) to skip module table search
            self.uc.hook_add(UC_HOOK_CODE, self._lib_loader_hook,
                            begin=JIT_LIB_LOADER_ENTRY, end=JIT_LIB_LOADER_ENTRY + 4)
            self.uc.hook_add(UC_HOOK_CODE, self._second_cff_caller_hook,
                            begin=JIT_SECOND_CFF_CALLER_LOCK, end=JIT_SECOND_CFF_RESULT_28)
            self.uc.hook_add(UC_HOOK_CODE, self._jit_state_machine_hook,
                            begin=JIT_STATE_MACHINE_ENTRY, end=JIT_STATE_MACHINE_RET)
            self.uc.hook_add(UC_HOOK_CODE, self._jit_invalid_indcall_hook,
                            begin=JIT_INVALID_INDCALL_PC1, end=JIT_INVALID_INDCALL_PC1)
            self.uc.hook_add(UC_HOOK_CODE, self._jit_invalid_indcall_hook,
                            begin=JIT_INVALID_INDCALL_PC2, end=JIT_INVALID_INDCALL_PC2)
            # Skip CFF call at 0x159da4 (infinite loop with incomplete data)
            self.uc.hook_add(UC_HOOK_CODE, self._cff_call_159da4_hook,
                            begin=JIT_CFF_CALL_159DA4, end=JIT_CFF_CALL_159DA4 + 4)
            # Second config CFF call at 0x15DF68 — same pattern (w1=0x1d, x0=session)
            self.uc.hook_add(UC_HOOK_CODE, self._cff_call_15df68_hook,
                            begin=JIT_CFF_CALL_15DF68, end=JIT_CFF_CALL_15DF68 + 4)
            # Reachability probe: does cert CFF reach the second callee (0x1d126c)?
            # Truncate 0x6af04 output after AES decrypt — zero padding bytes
            # beyond logical_length so hash computation is correct.
            self.uc.hook_add(UC_HOOK_CODE, self._source_materialize_truncate_hook,
                            begin=JIT_BASE + 0x6afb4, end=JIT_BASE + 0x6afb4 + 4)
            self.uc.hook_add(UC_HOOK_CODE, self._cert_path_probe_hook,
                            begin=JIT_CERT_BL_1C6314, end=JIT_CERT_BL_1C6314 + 4)
            self.uc.hook_add(UC_HOOK_CODE, self._cert_path_probe_hook,
                            begin=JIT_CERT_CALLEE_1D126C, end=JIT_CERT_CALLEE_1D126C + 4)
            # Hook 0x1d8a54 entry/return (encoding fn called by 0x1d126c)
            self.uc.hook_add(UC_HOOK_CODE, self._cert_1d8a54_hook,
                            begin=JIT_CERT_FN_1D8A54, end=JIT_CERT_FN_1D8A54 + 4)
            self.uc.hook_add(UC_HOOK_CODE, self._cert_1d8a54_ret_hook,
                            begin=JIT_CERT_BL_1D8A54 + 4, end=JIT_CERT_BL_1D8A54 + 8)
            # Hook inner CFF call from cert wrapper (0x1c2180) and its return
            self.uc.hook_add(UC_HOOK_CODE, self._cert_inner_cff_call_hook,
                            begin=JIT_CERT_INNER_CFF_BL, end=JIT_CERT_INNER_CFF_BL + 4)
            self.uc.hook_add(UC_HOOK_CODE, self._cert_inner_cff_call_hook,
                            begin=JIT_CERT_INNER_CFF_RET, end=JIT_CERT_INNER_CFF_RET + 4)
            # Hook the inner CFF function entry to fix [sp+0x60] before it's used
            self.uc.hook_add(UC_HOOK_CODE, self._inner_cff_fix_hook,
                            begin=JIT_INNER_CFF_STR, end=JIT_INNER_CFF_STR + 4)
            # CERT-SKIP-2ND: instruction-level hooks on the post-prologue cert
            # wrapper entry and epilogue success move.
            self.uc.hook_add(UC_HOOK_CODE, self._cert_wrapper_entry_hook,
                            begin=JIT_BASE + 0x1c2124, end=JIT_BASE + 0x1c2124 + 4)
            self.uc.hook_add(UC_HOOK_CODE, self._cert_wrapper_return_hook,
                            begin=JIT_BASE + 0x1c2480, end=JIT_BASE + 0x1c2480 + 4)
            # SHA-256 message assembly instrumentation at JIT+0x14f818
            self.uc.hook_add(UC_HOOK_CODE, self._sha256_msg_assembly_hook,
                            begin=JIT_BASE + 0x14f818, end=JIT_BASE + 0x14f818 + 4)
            # SHA-256 message load instrumentation at JIT+0x14f894
            self.uc.hook_add(UC_HOOK_CODE, self._sha256_msg_load_hook,
                            begin=JIT_BASE + 0x14f894, end=JIT_BASE + 0x14f894 + 4)
            # SHA-256 hex-encode call instrumentation at JIT+0x150b64
            self.uc.hook_add(UC_HOOK_CODE, self._sha256_hexenc_hook,
                            begin=JIT_BASE + 0x150b64, end=JIT_BASE + 0x150b64 + 4)
            # Hash chain input buffer dump at JIT+0x109334
            self.uc.hook_add(UC_HOOK_CODE, self._hashchain_input_hook,
                            begin=JIT_BASE + 0x109334, end=JIT_BASE + 0x109334 + 4)
            # Post-concatenation dump at JIT+0x109370
            self.uc.hook_add(UC_HOOK_CODE, self._post_concat_hook,
                            begin=JIT_BASE + 0x109370, end=JIT_BASE + 0x109370 + 4)
            # Watchpoint on sp+0x7b0 region (32 bytes) to trace SHA-256 input source
            # SP at SHA-256 assembly = 0x7f3fb2c0, so sp+0x7b0 = 0x7f3fba70
            _sp7b0_addr = 0x7f3fba70
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._sp7b0_mem_write_hook,
                            begin=_sp7b0_addr, end=_sp7b0_addr + 31)
            # Write tracker on sp+0x810 (64 bytes) to capture SHA-256 message blocks
            _sp810_addr = 0x7f3fb2c0 + 0x810  # = 0x7f3fbad0
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._sp810_write_hook,
                            begin=_sp810_addr, end=_sp810_addr + 63)
            # Heap read tracker for hash chain source identification
            self.uc.hook_add(UC_HOOK_MEM_READ, self._hashchain_read_hook,
                            begin=0x80000000, end=0x80300000)
            # Hook SHA-256 block loop at JIT+0x118850
            self.uc.hook_add(UC_HOOK_CODE, self._sha256_block_loop_hook,
                            begin=JIT_BASE + 0x118850, end=JIT_BASE + 0x118850 + 4)
            # Buffer injection: override the 128-byte rand buffer after lazy init
            self._device_rand_buffer = None
            buf_hex = os.environ.get('NMSS_RAND_BUFFER', '')
            if len(buf_hex) == 256:
                self._device_rand_buffer = bytes.fromhex(buf_hex)
                print(f"[BUFFER-INJECT] Will inject 128-byte device buffer", flush=True)
            self.uc.hook_add(UC_HOOK_CODE, self._rand_buffer_inject_hook,
                            begin=JIT_BASE + 0x6a69c, end=JIT_BASE + 0x6a69c + 4)
            self.uc.hook_add(UC_HOOK_CODE, self._code_hook,
                            begin=JIT_STUB_BASE, end=JIT_STUB_BASE + 0x1000)  # JIT stubs
            self.uc.hook_add(UC_HOOK_CODE, self._code_hook,
                            begin=0x64050000, end=0x64060000)  # scratch noop
            self.uc.hook_add(UC_HOOK_CODE, self._live_callback_decode_hook,
                            begin=LIVE_CALLBACK_DECODE_ENTRY, end=LIVE_CALLBACK_DECODE_ENTRY)
            self.uc.hook_add(UC_HOOK_CODE, self._live_callback_decode_hook,
                            begin=LIVE_CALLBACK_DECODE_FALLBACK, end=LIVE_CALLBACK_DECODE_FALLBACK)
            # Catch wild execution (jumps to ELF headers, unmapped, etc.)
            self.uc.hook_add(UC_HOOK_CODE, self._wild_exec_hook,
                            begin=0x0, end=0x5ee0f)  # below nmsscr code
            self.uc.hook_add(UC_HOOK_INTR, self._intr_hook)
            # Memory read tracer for session object analysis
            self.uc.hook_add(UC_HOOK_MEM_READ, self._heap_read_trace,
                            begin=HEAP_BASE, end=HEAP_BASE + HEAP_SIZE - 1)
        elif not self._fast_mode:
            self.uc.hook_add(UC_HOOK_CODE, self._code_hook_slow)
            self.uc.hook_add(UC_HOOK_INTR, self._intr_hook)
        # Note: in fast mode, hooks are installed after _patch_jit_got_critical
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                        UC_HOOK_MEM_FETCH_UNMAPPED, self._mem_hook)

        # EARLY watchpoint on session+0x210 SSO struct (MANAGER_BASE+0x210).
        # Catches ALL writes from the moment emulation starts — before any CFF
        # code runs — so we can trace what zeroes or updates the cert token.
        sess210_addr = MANAGER_BASE + 0x210
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._sess210_write_hook,
                        begin=sess210_addr, end=sess210_addr + 24)
        # Also watch the heap buffer that holds the session key hex string
        sk_heap_ptr = struct.unpack("<Q", bytes(self.uc.mem_read(sess210_addr + 16, 8)))[0]
        if sk_heap_ptr > 0x1000:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._sess210_data_write_hook,
                            begin=sk_heap_ptr, end=sk_heap_ptr + 64)
            print(f"[SESS-WATCH-EARLY] Installed watchpoint on session+0x210 SSO @ {sess210_addr:#x} "
                  f"and heap data @ {sk_heap_ptr:#x}", flush=True)
        else:
            print(f"[SESS-WATCH-EARLY] Installed watchpoint on session+0x210 SSO @ {sess210_addr:#x} "
                  f"(no heap ptr yet)", flush=True)
        self._sess210_watch_installed = True

        # PLT fallbacks for nmsscr
        ret_insn = struct.pack("<I", 0xd65f03c0)
        self.uc.mem_write(self.PLT_FALLBACK, ret_insn)
        self.hooked_functions[self.PLT_FALLBACK] = self._hook_noop
        self.uc.mem_write(0x4e2280, struct.pack("<Q", self.PLT_FALLBACK))

        # Patch unresolved PLT entries to fallback
        for a in range(0x5f000, 0x60500, 0x10):
            if a in self.hooked_functions:
                continue
            try:
                c = bytes(self.uc.mem_read(a, 16))
                i0 = struct.unpack("<I", c[0:4])[0]
                i1 = struct.unpack("<I", c[4:8])[0]
                if (i0 & 0x9F000000) != 0x90000000: continue
                if (i1 & 0xFFC00000) != 0xf9400000: continue
                immhi = (i0 >> 5) & 0x7FFFF; immlo = (i0 >> 29) & 0x3
                ir = (immhi << 2) | immlo
                if ir & (1 << 20): ir -= (1 << 21)
                pg = (a & ~0xFFF) + (ir << 12)
                im12 = (i1 >> 10) & 0xFFF
                ga = pg + im12 * 8
                if 0 <= ga < len(self.binary_data):
                    gv = struct.unpack("<Q", bytes(self.uc.mem_read(ga, 8)))[0]
                    if gv == 0 or gv == self.LAZY_RESOLVER:
                        self.uc.mem_write(ga, struct.pack("<Q", self.PLT_FALLBACK))
            except:
                pass

        # If JIT module is loaded, patch its GOT entries for critical libc functions
        if self.jit_data:
            self._patch_jit_got_critical()

        # Install BLR x8 trampoline for range/block/fast modes (binary patch, no hook needed)
        if (self._range_mode or self._block_mode or self._fast_mode) and self.jit_data:
            self._install_blr_trampoline()

        # Install SVC patches LAST (after all hooked_functions are registered)
        if self._fast_mode:
            self._install_svc_patches()
            self.uc.hook_add(UC_HOOK_INTR, self._fast_intr_hook)

    def _patch_jit_got_critical(self):
        """Patch JIT GOT JUMP_SLOT entries for critical libc functions.
        Each function gets a unique stub address in the JIT stub area.
        The stub address is registered in hooked_functions so the code_hook
        intercepts it and runs our Python handler.
        """
        self._jit_symbol_stubs = {}
        self._jit_stub_entry_redirects = {}
        # JIT JUMP_SLOT GOT offsets (from ELF analysis)
        jit_got = {
            'malloc':       0x446a50,
            'calloc':       0x446a98,
            'realloc':      0x446dd8,
            'free':         0x446b30,
            'memcpy':       0x446e40,
            'memset':       0x446c40,
            'memmove':      0x446c38,
            'memcmp':       0x446a08,
            'strlen':       0x446ed0,
            'strcmp':        0x446bb8,
            'strncmp':      0x446e08,
            'strcpy':       0x446aa8,
            'strdup':       0x446bb0,
            'strncpy':      0x446978,
            'strchr':       0x446b98,
            'strrchr':      0x446c68,
            'strstr':       0x446c70,
            'strcasecmp':   0x446be0,
            'strncasecmp':  0x446f10,
            'sprintf':      0x446ed8,
            'snprintf':     0x446d20,
            'sscanf':       0x446dc0,
            'fprintf':      0x446cf0,
            'vsnprintf':    0x446e60,
            'fopen':        0x446e10,
            'fclose':       0x446ce8,
            'fread':        0x446a48,
            'fwrite':       0x446a90,
            'fseek':        0x446a60,
            'ftell':        0x446c60,
            'fflush':       0x446b80,
            'fgets':        0x446a38,
            'fputs':        0x446a40,
            'fputc':        0x446b40,
            'ferror':       0x446d00,
            'feof':         0x446e88,
            'fileno':       0x446ea0,
            'getentropy':   0x4469d8,
            'clock_gettime': 0x446f20,
            'gettimeofday': 0x446ca0,
            'time':         0x446c58,
            'rand':         0x446e98,
            'srand':        0x446f30,
            'open':         0x446ba0,
            'close':        0x446b00,
            'read':         0x446af0,
            'write':        0x446d58,
            'mmap':         0x446948,
            'munmap':       0x446d10,
            'mprotect':     0x446f40,
            'madvise':      0x446e68,
            'mlock':        0x446d78,
            'stat':         0x446a00,
            'fstat':        0x446db0,
            'lseek':        0x446980,
            'access':       0x446a20,
            'unlink':       0x446e90,
            'getpid':       0x446960,
            'getenv':       0x446bd0,
            'sysconf':      0x446bc0,
            'getpagesize':  0x446d88,
            'pthread_self':         0x446938,
            'pthread_create':       0x446a18,
            'pthread_join':         0x446a28,
            'pthread_mutex_init':   0x446cd8,
            'pthread_mutex_lock':   0x446d80,
            'pthread_mutex_unlock': 0x446c30,
            'pthread_mutex_destroy': 0x446da0,
            'pthread_once':         0x446a78,
            'pthread_key_create':   0x446ef8,
            'pthread_key_delete':   0x446e00,
            'pthread_getspecific':  0x4469b0,
            'pthread_setspecific':  0x446c08,
            'pthread_rwlock_init':     0x446a10,
            'pthread_rwlock_rdlock':   0x4469c0,
            'pthread_rwlock_wrlock':   0x446940,
            'pthread_rwlock_unlock':   0x446b60,
            'pthread_rwlock_destroy':  0x446998,
            'pthread_cond_wait':       0x446ae8,
            'pthread_cond_broadcast':  0x446bf0,
            'pthread_attr_init':       0x446bc8,
            'pthread_attr_destroy':    0x446b48,
            'pthread_attr_setdetachstate': 0x4469b8,
            'pthread_detach':   0x446f08,
            'pthread_atfork':   0x446a30,
            'pthread_equal':    0x446ea8,
            '__cxa_atexit':     0x4469e0,
            '__cxa_finalize':   0x446c80,
            '__stack_chk_fail': 0x446a80,
            '__errno':          0x446b78,
            'dlopen':           0x446a68,
            'dlsym':            0x446c28,
            'dlclose':          0x446d30,
            'dlerror':          0x446ce0,
            'AAssetManager_open': 0x446db8,
            'AAsset_getLength':   0x446cf8,
            'AAsset_read':        0x446c10,
            'AAsset_close':       0x446e20,
            'dl_iterate_phdr':  0x446950,
            'abort':            0x446d28,
            'exit':             0x446be8,
            'qsort':            0x4469e8,
            'strtol':           0x446d68,
            'strtoul':          0x446e38,
            'atoi':             0x446ec8,
            'isalpha':          0x446b18,
            'isspace':          0x446dc8,
            'isupper':          0x446d38,
            'isxdigit':         0x446c78,
            'toupper':          0x446b68,
            'tolower':          0x446e70,
        }

        # Map handlers: critical functions get proper handlers, rest get noop
        handler_map = {
            'malloc':   self._hook_malloc,
            'calloc':   self._hook_calloc,
            'realloc':  self._hook_realloc,
            'free':     self._hook_free,
            'memcpy':   self._hook_memcpy,
            'memset':   self._hook_memset,
            'memmove':  self._hook_memmove,
            'strlen':   self._hook_strlen,
            'memcmp':   self._hook_memcmp,
            'strcmp':    self._hook_strcmp,
            'strcpy':   self._hook_strcpy,
            'getentropy': self._hook_getentropy,
            'clock_gettime': self._hook_clock,
            'gettimeofday': self._hook_clock,
            'time':     self._hook_time,
            'rand':     self._hook_rand,
            'srand':    self._hook_srand,
            'getpid':   self._hook_getpid,
            'getpagesize': self._hook_getpagesize,
            'sysconf':  self._hook_sysconf,
            'access':   self._hook_jit_access_or_calloc,
            'fopen':    self._hook_jit_fopen,
            'fread':    self._hook_jit_fread,
            'fclose':   self._hook_jit_fclose,
            'fseek':    self._hook_jit_fseek,
            'ftell':    self._hook_jit_ftell,
            'ferror':   self._hook_jit_ferror,
            'feof':     self._hook_jit_feof,
            'fileno':   self._hook_jit_fileno,
            'fflush':   self._hook_noop,
            'closedir': self._hook_jit_closedir_or_setspecific,
            'execl':    self._hook_jit_execl_or_free,
            'pthread_self': self._hook_pthread_self,
            'pthread_once': self._hook_pthread_once,
            'dl_iterate_phdr': self._hook_dl_iterate_phdr,
            '__cxa_atexit': self._hook_cxa_atexit,
            '__errno':  self._hook_errno,
            'AAssetManager_open': self._hook_aasset_open,
            'AAsset_getLength':   self._hook_aasset_get_length,
            'AAsset_read':        self._hook_aasset_read,
            'AAsset_close':       self._hook_aasset_close,
            'snprintf': self._hook_snprintf,
            'vsnprintf': self._hook_vsnprintf,
            'sprintf':  self._hook_jit_sprintf,
            'abort':    self._hook_passthrough,
        }

        mov_x0_zero = struct.pack("<I", 0xAA1F03E0)  # MOV X0, XZR
        ret_insn = struct.pack("<I", 0xd65f03c0)  # RET
        stub_pair = mov_x0_zero + ret_insn
        stub_idx = 0
        patched = 0
        for name, got_vaddr in jit_got.items():
            stub_addr = JIT_STUB_BASE + stub_idx * JIT_STUB_SLOT_SIZE
            trampoline_addr = stub_addr + 8
            # The fallback stub should return a clean zero value if the code
            # hook misses it or the handler deliberately degenerates.
            if name in JIT_INTEGRITY_STUB_WORDS:
                # Layout:
                #   +0 expected 4-byte signature (read by 0x1d8a54)
                #   +4 b +4 (to +8 trampoline)
                #   +8 safe fallback bytes; actual Python handler is hooked here
                expected = struct.pack("<I", JIT_INTEGRITY_STUB_WORDS[name])
                branch_to_trampoline = struct.pack("<I", 0x14000001)
                if name == 'abort':
                    trampoline_bytes = ret_insn + ret_insn
                else:
                    trampoline_bytes = stub_pair
                self.uc.mem_write(
                    stub_addr,
                    expected + branch_to_trampoline + trampoline_bytes,
                )
                self._jit_stub_entry_redirects[stub_addr] = trampoline_addr
                handler_addr = trampoline_addr
            elif name == 'abort':
                self.uc.mem_write(stub_addr, ret_insn + ret_insn)
                handler_addr = stub_addr
            else:
                self.uc.mem_write(stub_addr, stub_pair)
                handler_addr = stub_addr
            # Patch the GOT entry
            self.uc.mem_write(JIT_BASE + got_vaddr, struct.pack("<Q", stub_addr))
            # Register handler
            handler = handler_map.get(name, self._hook_noop)
            self.hooked_functions[handler_addr] = handler
            self._jit_symbol_stubs[name] = stub_addr
            stub_idx += 1
            patched += 1

        live_jump_patched = 0
        if self.jit_live_flat is not None:
            try:
                import lief

                live_elf = lief.parse(os.path.join(os.path.dirname(os.path.abspath(__file__)), "jit_live_flat.bin"))
            except Exception:
                live_elf = None

            if live_elf is not None:
                seen_live_offsets = set()
                for rel in live_elf.relocations:
                    try:
                        if rel.type != lief.ELF.Relocation.TYPE.AARCH64_JUMP_SLOT:
                            continue
                        got_vaddr = int(rel.address)
                        if got_vaddr in seen_live_offsets:
                            continue
                        seen_live_offsets.add(got_vaddr)
                        name = rel.symbol.name if rel.has_symbol and rel.symbol is not None else ""
                    except Exception:
                        continue
                    if not name:
                        continue
                    stub_addr = self._jit_symbol_stubs.get(name)
                    if stub_addr is None:
                        stub_addr = self._get_jit_stub(name)
                        if name in handler_map:
                            self.hooked_functions[stub_addr] = handler_map[name]
                        self._jit_symbol_stubs[name] = stub_addr
                    got_emu = JIT_BASE + got_vaddr
                    self.uc.mem_write(got_emu, struct.pack("<Q", stub_addr))
                    self._jit_live_got_overrides[got_emu] = stub_addr
                    live_jump_patched += 1

        # Also patch GLOB_DAT entries for __stack_chk_guard, x/y vars, and libc syms
        # x/y GLOB_DAT: allocate one shared block for all x/y variables
        xy_block = self.heap.malloc(0x200)
        self.uc.mem_write(xy_block, b'\x00' * 0x200)

        # Scan GLOB_DAT from the RELA section
        jit = self.jit_data
        syms = self._parse_jit_dynsym()
        rela_off = JIT_RELA_VADDR
        rela_end = rela_off + JIT_RELA_SIZE
        glob_patched = 0
        for off in range(rela_off, min(rela_end, len(jit) - 23), 24):
            r_offset = struct.unpack_from('<Q', jit, off)[0]
            r_info = struct.unpack_from('<Q', jit, off + 8)[0]
            r_type = r_info & 0xFFFFFFFF
            r_sym = r_info >> 32
            if r_type != 1025:  # R_AARCH64_GLOB_DAT
                continue
            if r_sym not in syms:
                continue
            name, st_shndx, st_value = syms[r_sym]
            got_emu = JIT_BASE + r_offset
            if name.startswith('x') or name.startswith('y'):
                override_target = self._jit_live_got_overrides.get(got_emu)
                if override_target is not None:
                    self.uc.mem_write(got_emu, struct.pack("<Q", override_target))
                elif st_shndx != 0 and st_value != 0:
                    target = JIT_BASE + st_value
                    if self.jit_live_flat is not None and st_value + 16 <= len(self.jit_live_flat):
                        self.uc.mem_write(target, self.jit_live_flat[st_value:st_value + 16])
                    self.uc.mem_write(got_emu, struct.pack("<Q", target))
                else:
                    self.uc.mem_write(got_emu, struct.pack("<Q", xy_block))
                glob_patched += 1
            elif name == 'bio_lookup_lock' or name == 'global_engine_lock':
                self.uc.mem_write(got_emu, struct.pack("<Q", xy_block))
                glob_patched += 1
            elif name == '__stack_chk_guard':
                guard_addr = self.heap.malloc(16)
                self.uc.mem_write(guard_addr, struct.pack("<Q", 0xDEADBEEFCAFEBABE))
                self.uc.mem_write(got_emu, struct.pack("<Q", guard_addr))
                glob_patched += 1
            elif name == '__sF':
                sf_addr = self.heap.malloc(0x100)
                self.uc.mem_write(got_emu, struct.pack("<Q", sf_addr))
                glob_patched += 1
            elif name in handler_map or name in jit_got:
                # Function pointer in GLOB_DAT — point to the same stub
                for gname, gvaddr in jit_got.items():
                    if gname == name:
                        cur = struct.unpack("<Q", bytes(self.uc.mem_read(JIT_BASE + gvaddr, 8)))[0]
                        self.uc.mem_write(got_emu, struct.pack("<Q", cur))
                        glob_patched += 1
                        break
            elif st_shndx != 0 and st_value != 0:
                # Internal JIT variable with defined value — rebase and copy live data
                target = JIT_BASE + st_value
                if self.jit_live_flat is not None and st_value + 16 <= len(self.jit_live_flat):
                    self.uc.mem_write(target, self.jit_live_flat[st_value:st_value + 16])
                self.uc.mem_write(got_emu, struct.pack("<Q", target))
                glob_patched += 1

        self.log(
            f"Patched {patched} JIT JUMP_SLOT + {live_jump_patched} live JUMP_SLOT "
            f"+ {glob_patched} GLOB_DAT entries"
        )

        # Catch-all: patch any remaining JIT GOT entries that still have device addresses
        # These are entries not in the jit_got dict — scan the GOT range and fix them
        got_range_start = 0x446920
        got_range_end = 0x446f60
        catchall_patched = 0
        catchall_stub = JIT_STUB_BASE + stub_idx * 16
        # Write a single MOV X0, XZR; RET stub for all catch-all entries
        self.uc.mem_write(catchall_stub, stub_pair)
        self.hooked_functions[catchall_stub] = self._hook_noop
        for got_off in range(got_range_start, got_range_end, 8):
            try:
                val = struct.unpack("<Q", bytes(self.uc.mem_read(JIT_BASE + got_off, 8)))[0]
            except:
                continue
            # Check if it's already pointing to a valid emulator address
            # Note: val==0 entries ALSO need patching — JIT data loader zeroes
            # external device addresses, leaving GOT entries as NULL. PLT stubs
            # then do `ldr x17, [GOT]; br x17` → jump to 0 → WILD-EXEC.
            if val == 0:
                self.uc.mem_write(JIT_BASE + got_off, struct.pack("<Q", catchall_stub))
                catchall_patched += 1
                continue
            in_emu = (JIT_BASE <= val < JIT_BASE + self._jit_runtime_size() + 0x10000 or
                      JIT_STUB_BASE <= val < JIT_STUB_BASE + 0x10000 or
                      0x0 <= val < 0x500000 or  # nmsscr range
                      HEAP_BASE <= val < HEAP_BASE + HEAP_SIZE)
            if not in_emu:
                self.uc.mem_write(JIT_BASE + got_off, struct.pack("<Q", catchall_stub))
                catchall_patched += 1
        for got_emu, target in self._jit_live_got_overrides.items():
            self.uc.mem_write(got_emu, struct.pack("<Q", target))
        if catchall_patched:
            print(f"[GOT-CATCHALL] Patched {catchall_patched} remaining JIT GOT entries", flush=True)
        else:
            print(f"[GOT-CATCHALL] No unpatched entries found in GOT range", flush=True)

    # ---- Additional libc hook handlers for JIT ----
    def _sanitize_alloc_size(self, requested, kind):
        sz = requested if requested > 0 else 16
        max_sz = 0x100000
        if sz > max_sz:
            if not hasattr(self, '_alloc_clamp_logs'):
                self._alloc_clamp_logs = 0
            self._alloc_clamp_logs += 1
            if self._alloc_clamp_logs <= 16:
                print(
                    f"[{kind}-CLAMP #{self._alloc_clamp_logs}] "
                    f"req={requested:#x} -> {max_sz:#x}",
                    flush=True,
                )
            sz = max_sz
        return sz

    def _hook_calloc(self, uc, x0, x1, *a):
        raw_sz = (x0 * x1) if x0 < 0x100000 and x1 < 0x100000 else 16
        sz = self._sanitize_alloc_size(max(raw_sz, 16), "CALLOC")
        addr = self.heap.malloc(sz)
        uc.mem_write(addr, b'\x00' * min(sz, 0x10000))
        uc.reg_write(UC_ARM64_REG_X0, addr)

    def _hook_realloc(self, uc, x0, x1, *a):
        sz = self._sanitize_alloc_size(x1 if x1 > 0 else 16, "REALLOC")
        try:
            addr = self.heap.malloc(sz)
        except MemoryError:
            if not hasattr(self, '_realloc_failsafe_logs'):
                self._realloc_failsafe_logs = 0
            self._realloc_failsafe_logs += 1
            if self._realloc_failsafe_logs <= 8:
                print(
                    f"[REALLOC-FAILSAFE #{self._realloc_failsafe_logs}] "
                    f"ptr={x0:#x} req={x1:#x} -> reuse existing",
                    flush=True,
                )
            uc.reg_write(UC_ARM64_REG_X0, x0)
            return
        uc.mem_write(addr, b'\x00' * min(sz, 0x10000))
        if x0 and x0 != addr:
            try:
                old_data = bytes(uc.mem_read(x0, min(sz, 0x10000)))
                uc.mem_write(addr, old_data)
            except:
                pass
        uc.reg_write(UC_ARM64_REG_X0, addr)

    def _hook_memcmp(self, uc, x0, x1, x2, *a):
        if 0 < x2 < 0x1000000:
            a_addr = self._resolve_mem_addr(uc, x0)
            b_addr = self._resolve_mem_addr(uc, x1)
            a_data = bytes(uc.mem_read(a_addr, x2))
            b_data = bytes(uc.mem_read(b_addr, x2))
            result = (a_data > b_data) - (a_data < b_data)
        else:
            result = 0
        uc.reg_write(UC_ARM64_REG_X0, result & 0xFFFFFFFFFFFFFFFF)

    def _hook_strcmp(self, uc, x0, x1, *a):
        def read_cstr(addr, max_len=4096):
            s = b''
            for i in range(max_len):
                b = bytes(uc.mem_read(addr + i, 1))[0]
                if b == 0: break
                s += bytes([b])
            return s
        a = read_cstr(x0)
        b = read_cstr(x1)
        result = (a > b) - (a < b)
        uc.reg_write(UC_ARM64_REG_X0, result & 0xFFFFFFFFFFFFFFFF)

    def _hook_strcpy(self, uc, x0, x1, *a):
        n = 0
        try:
            while n < 0x100000 and bytes(uc.mem_read(x1 + n, 1))[0]:
                n += 1
        except:
            pass
        if n > 0:
            data = bytes(uc.mem_read(x1, n))
            uc.mem_write(x0, data + b'\x00')
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_getentropy(self, uc, x0, x1, *a):
        if 0 < x1 < 0x10000:
            uc.mem_write(x0, os.urandom(x1))
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_getpagesize(self, uc, *a):
        uc.reg_write(UC_ARM64_REG_X0, 0x1000)

    def _hook_sysconf(self, uc, x0, *a):
        uc.reg_write(UC_ARM64_REG_X0, 0x1000 if x0 == 30 else 8)  # _SC_PAGESIZE=30

    def _hook_pthread_self(self, uc, *a):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        key = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
        if lr in (JIT_CXA_GETSPECIFIC_RET, JIT_CXA_GETSPECIFIC_FAST_RET):
            if self._jit_cxa_globals_key == 0:
                self._jit_tls_key_create()
            if key == self._jit_cxa_globals_key:
                uc.reg_write(UC_ARM64_REG_X0, self._jit_tls_get(key))
                return
        uc.reg_write(UC_ARM64_REG_X0, 0xDEAD0001)

    def _hook_jit_access_or_calloc(self, uc, x0, x1, *a):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        if lr == JIT_CXA_CALLOC_RET and x0 <= 0x1000 and x1 <= 0x1000:
            self._hook_calloc(uc, x0, x1)
            return
        path = self._read_c_string(uc, x0, max_len=512)
        if path:
            host_path, data, display = self._resolve_jit_host_or_virtual_path(path)
            ok = data is not None or (host_path is not None and os.access(host_path, int(x1 & 0xFFFFFFFF)))
            if self._jit_stdio_logs < 8:
                self._jit_log_stdio(
                    f"[JIT-ACCESS] path={display or path!r} mode={int(x1 & 0xFFFFFFFF):#x} "
                    f"host={host_path!r} virtual={'yes' if data is not None else 'no'} ok={ok}"
                )
            uc.reg_write(UC_ARM64_REG_X0, 0 if ok else 0xFFFFFFFFFFFFFFFF)
            return
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_jit_fopen(self, uc, x0, x1, *a):
        path = self._read_c_string(uc, x0, max_len=512)
        mode = self._read_c_string(uc, x1, max_len=32)
        host_path, data, display = self._resolve_jit_host_or_virtual_path(path)
        stream = 0
        fd = 0
        if data is not None:
            fd = self._alloc_jit_fd("virtual", path=path or display.encode("utf-8", errors="ignore"), data=data)
        elif host_path:
            try:
                host_fd = os.open(host_path, os.O_RDONLY)
                fd = self._alloc_jit_fd("host", path=path or display.encode("utf-8", errors="ignore"), host_fd=host_fd)
            except OSError:
                fd = 0
        if fd:
            stream = self.heap.malloc(0x20)
            uc.mem_write(stream, b"\x00" * 0x20)
            uc.mem_write(stream, struct.pack("<Q", fd))
        if self._jit_stdio_logs < 12:
            try:
                mode_str = mode.decode("utf-8", errors="ignore")
            except Exception:
                mode_str = ""
            self._jit_log_stdio(
                f"[JIT-FOPEN] path={display or path!r} mode={mode_str!r} "
                f"host={host_path!r} virtual={'yes' if data is not None else 'no'} "
                f"stream={stream:#x}"
            )
        uc.reg_write(UC_ARM64_REG_X0, stream)

    def _hook_jit_fread(self, uc, x0, x1, x2, x3, *a):
        elem_size = int(x1 & 0xFFFFFFFFFFFFFFFF)
        count = int(x2 & 0xFFFFFFFFFFFFFFFF)
        total = elem_size * count
        fd = self._jit_resolve_stream_fd(uc, x3)
        entry = self._jit_fd_table.get(fd)
        read_len = self._jit_read_fd_entry(uc, entry, x0, total) if total and entry else -1
        if read_len < 0 or elem_size == 0:
            uc.reg_write(UC_ARM64_REG_X0, 0)
            return
        uc.reg_write(UC_ARM64_REG_X0, read_len // elem_size)

    def _hook_jit_fclose(self, uc, x0, *a):
        fd = self._jit_resolve_stream_fd(uc, x0)
        entry = self._jit_fd_table.pop(fd, None)
        if entry is not None:
            host_fd = entry.get("host_fd")
            if host_fd is not None:
                try:
                    os.close(host_fd)
                except OSError:
                    pass
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_jit_fseek(self, uc, x0, x1, x2, *a):
        fd = self._jit_resolve_stream_fd(uc, x0)
        entry = self._jit_fd_table.get(fd)
        if entry is None:
            uc.reg_write(UC_ARM64_REG_X0, 0xFFFFFFFFFFFFFFFF)
            return
        offset = self._signed64(x1)
        whence = int(x2 & 0xFFFFFFFF)
        try:
            if entry["kind"] == "host":
                os.lseek(entry["host_fd"], offset, whence)
            else:
                data_len = len(entry["data"])
                cur = entry["pos"]
                if whence == 0:
                    new_pos = offset
                elif whence == 1:
                    new_pos = cur + offset
                elif whence == 2:
                    new_pos = data_len + offset
                else:
                    raise OSError(errno.EINVAL, "bad whence")
                if new_pos < 0:
                    raise OSError(errno.EINVAL, "negative seek")
                entry["pos"] = min(new_pos, data_len)
            entry["eof"] = False
            entry["err"] = 0
            uc.reg_write(UC_ARM64_REG_X0, 0)
        except OSError as exc:
            entry["err"] = exc.errno or errno.EIO
            uc.reg_write(UC_ARM64_REG_X0, 0xFFFFFFFFFFFFFFFF)

    def _hook_jit_ftell(self, uc, x0, *a):
        fd = self._jit_resolve_stream_fd(uc, x0)
        entry = self._jit_fd_table.get(fd)
        if entry is None:
            uc.reg_write(UC_ARM64_REG_X0, 0xFFFFFFFFFFFFFFFF)
            return
        try:
            if entry["kind"] == "host":
                pos = os.lseek(entry["host_fd"], 0, os.SEEK_CUR)
            else:
                pos = entry["pos"]
            uc.reg_write(UC_ARM64_REG_X0, pos & 0xFFFFFFFFFFFFFFFF)
        except OSError as exc:
            entry["err"] = exc.errno or errno.EIO
            uc.reg_write(UC_ARM64_REG_X0, 0xFFFFFFFFFFFFFFFF)

    def _hook_jit_ferror(self, uc, x0, *a):
        fd = self._jit_resolve_stream_fd(uc, x0)
        entry = self._jit_fd_table.get(fd)
        uc.reg_write(UC_ARM64_REG_X0, (entry or {}).get("err", 0))

    def _hook_jit_feof(self, uc, x0, *a):
        fd = self._jit_resolve_stream_fd(uc, x0)
        entry = self._jit_fd_table.get(fd)
        uc.reg_write(UC_ARM64_REG_X0, 1 if (entry or {}).get("eof") else 0)

    def _hook_jit_fileno(self, uc, x0, *a):
        fd = self._jit_resolve_stream_fd(uc, x0)
        uc.reg_write(UC_ARM64_REG_X0, fd if fd else 0xFFFFFFFFFFFFFFFF)

    def _hook_jit_closedir_or_setspecific(self, uc, x0, x1, *a):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        if lr in (JIT_CXA_SETSPECIFIC_RET, JIT_CXA_DTOR_CLEAR_RET):
            self._jit_tls_set(x0 & 0xFFFFFFFF, x1)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            return
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_jit_execl_or_free(self, uc, x0, *a):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        if lr == JIT_CXA_DTOR_FREE_RET:
            self._hook_free(uc, x0)
            return
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_pthread_once(self, uc, x0, x1, *a):
        try:
            state = self._safe_mem_read_u32(uc, x0) or 0
        except Exception:
            state = 0

        if state == 0:
            if x1 == JIT_CLASSMAP_INIT_FN:
                for start, end in ((0x00, 0x20), (0x40, 0x61)):
                    uc.mem_write(JIT_CLASSMAP_BASE + start, b"\x08" * (end - start))
            elif x1 == JIT_CXA_GLOBALS_INIT_FN:
                self._emulate_jit_cxa_globals_init(uc)
            try:
                uc.mem_write(x0, struct.pack("<I", 1))
            except Exception:
                pass

        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_dl_iterate_phdr(self, uc, x0, x1, *a):
        self._jit_dl_iterate_phdr_calls += 1
        target_pc = self._safe_mem_read_qword(uc, x1) if x1 else None
        result = 0
        if target_pc is not None:
            result = self._synthesize_unwind_fde_lookup(uc, x1, target_pc)
        if self._jit_dl_iterate_phdr_calls <= 4:
            self.log(
                f"dl_iterate_phdr(cb={x0:#x}, data={x1:#x}, "
                f"target={target_pc if target_pc is not None else 0:#x}, result={result})"
            )
        uc.reg_write(UC_ARM64_REG_X0, result)

    def _hook_cxa_atexit(self, uc, x0, x1, x2, *a):
        self._jit_cxa_atexit_calls += 1
        if len(self._jit_cxa_atexit_trace) < 64:
            snap = {
                "call": self._jit_cxa_atexit_calls,
                "lr": uc.reg_read(UC_ARM64_REG_LR),
                "x0": x0,
                "x1": x1,
                "x2": x2,
            }
            if x1:
                for off, key in (
                    (0x00, "a0"),
                    (0x08, "a8"),
                    (0x10, "a10"),
                    (0x18, "a18"),
                    (0x20, "a20"),
                    (0x28, "a28"),
                    (0x30, "a30"),
                ):
                    snap[key] = self._safe_mem_read_qword(uc, x1 + off)
            self._jit_cxa_atexit_trace.append(snap)
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_errno(self, uc, *a):
        # __errno() returns pointer to errno variable
        errno_addr = self.heap.malloc(16)
        uc.mem_write(errno_addr, struct.pack("<I", 0))
        uc.reg_write(UC_ARM64_REG_X0, errno_addr)

    def _hook_snprintf(self, uc, x0, x1, x2, *a):
        """snprintf(buf, size, fmt, ...)"""
        self._do_printf(uc, x0, x1, x2)

    def _hook_vsnprintf(self, uc, x0, x1, x2, *a):
        """vsnprintf(buf, size, fmt, va_list) — va_list is a pointer to args on ARM64"""
        self._do_printf(uc, x0, x1, x2)

    def _hook_jit_sprintf(self, uc, x0, x1, x2, *a):
        """sprintf(buf, fmt, ...)"""
        self._do_printf(uc, x0, 0x10000, x1)

    def _do_printf(self, uc, buf, maxlen, fmt_addr):
        """Minimal printf implementation for %02X, %02x, %d, %s, %x, %X patterns."""
        try:
            fmt = bytes(uc.mem_read(fmt_addr, 256)).split(b'\x00')[0]
        except:
            uc.reg_write(UC_ARM64_REG_X0, 0)
            return

        # Read args from x3-x7, then stack
        arg_regs = [UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                    UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        sp = uc.reg_read(UC_ARM64_REG_SP)
        args = [uc.reg_read(r) for r in arg_regs]
        # Read extra args from stack (after saved regs)
        for i in range(32):
            try:
                val = struct.unpack("<Q", bytes(uc.mem_read(sp + i * 8, 8)))[0]
                args.append(val)
            except:
                args.append(0)

        result = b''
        ai = 0
        i = 0
        while i < len(fmt):
            if fmt[i:i+1] == b'%' and i + 1 < len(fmt):
                # Parse format specifier
                j = i + 1
                width = ''
                while j < len(fmt) and fmt[j:j+1] in (b'0', b'1', b'2', b'3', b'4',
                                                        b'5', b'6', b'7', b'8', b'9'):
                    width += chr(fmt[j])
                    j += 1
                if j < len(fmt):
                    spec = chr(fmt[j])
                    val = args[ai] if ai < len(args) else 0
                    ai += 1
                    if spec == 'X':
                        s = f"{val & 0xFF:X}" if width == '02' else f"{val & 0xFFFFFFFF:X}"
                        if width == '02': s = s.zfill(2)
                        result += s.encode()
                    elif spec == 'x':
                        s = f"{val & 0xFF:x}" if width == '02' else f"{val & 0xFFFFFFFF:x}"
                        if width == '02': s = s.zfill(2)
                        result += s.encode()
                    elif spec == 'd':
                        v = val if val < 0x80000000 else val - 0x100000000
                        result += str(v).encode()
                    elif spec == 'u':
                        result += str(val & 0xFFFFFFFF).encode()
                    elif spec == 's':
                        try:
                            n = 0
                            while n < 256 and bytes(uc.mem_read(val + n, 1))[0]:
                                n += 1
                            result += bytes(uc.mem_read(val, n))
                        except:
                            pass
                    elif spec == 'p':
                        result += f"0x{val:x}".encode()
                    elif spec == '%':
                        result += b'%'
                        ai -= 1
                    else:
                        result += fmt[i:j+1]
                    i = j + 1
                else:
                    result += fmt[i:i+1]
                    i += 1
            else:
                result += fmt[i:i+1]
                i += 1

        # Write result (truncate to maxlen-1)
        if maxlen > 0:
            result = result[:maxlen - 1]
        try:
            uc.mem_write(buf, result + b'\x00')
        except:
            pass
        uc.reg_write(UC_ARM64_REG_X0, len(result))
        self.log(f"printf(fmt={fmt[:30]!r}) -> {len(result)} bytes: {result[:60]!r}")

    # ---- Interrupt handler (for SVC #0) ----
    def _intr_hook(self, uc, intno, ud):
        if intno == 2:  # SVC on ARM64
            syscall_num = uc.reg_read(UC_ARM64_REG_X8)
            self.log(f"SVC #0: syscall={syscall_num:#x}")
            self._emulate_raw_syscall(uc, syscall_num)
        else:
            uc.reg_write(UC_ARM64_REG_X0, 0)

    # ---- Known memory regions (for unmapped-execution detection) ----
    _KNOWN_REGIONS = None  # lazily built

    def _in_known_region(self, addr):
        """Check if addr is in a known code/data region."""
        if self._KNOWN_REGIONS is None:
            self._KNOWN_REGIONS = [
                (CODE_BASE, CODE_BASE + CODE_SIZE),
                (JIT_BASE, JIT_BASE + JIT_SIZE),
                (STACK_BASE, STACK_BASE + STACK_SIZE),
                (HEAP_BASE, HEAP_BASE + HEAP_SIZE),
                (MANAGER_BASE, MANAGER_BASE + MANAGER_SIZE),
                (TLS_BASE, TLS_BASE + TLS_SIZE),
                (SCRATCH_BASE, SCRATCH_BASE + SCRATCH_SIZE),
                (CHALLENGE_BASE, CHALLENGE_BASE + 0x2000),
            ]
        return any(lo <= addr < hi for lo, hi in self._KNOWN_REGIONS)

    def _is_bad_jit_exec_addr(self, addr):
        return any(lo <= addr < hi for lo, hi in JIT_BAD_EXEC_RANGES)

    # ---- Code hook ----
    def _invoke_hook_preserving_callee_saved(self, uc, handler):
        saved_regs = {}
        callee_saved = (
            UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22,
            UC_ARM64_REG_X23, UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26,
            UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29,
        )
        for reg_id in callee_saved:
            saved_regs[reg_id] = uc.reg_read(reg_id)
        handler(
            uc,
            uc.reg_read(UC_ARM64_REG_X0),
            uc.reg_read(UC_ARM64_REG_X1),
            uc.reg_read(UC_ARM64_REG_X2),
            uc.reg_read(UC_ARM64_REG_X8),
        )
        for reg_id, value in saved_regs.items():
            uc.reg_write(reg_id, value)

    def _capture_cert_wrapper_caller_frame(self, uc, current_sp=None, current_fp=None, current_lr=None):
        if current_sp is None:
            current_sp = uc.reg_read(UC_ARM64_REG_SP)
        if current_fp is None:
            current_fp = uc.reg_read(UC_ARM64_REG_X29)
        if current_lr is None:
            current_lr = uc.reg_read(UC_ARM64_REG_LR)

        caller = {
            'lr': current_lr,
            'sp': current_sp,
            'fp': current_fp,
            'saved_regs': {},
        }
        if current_fp == 0:
            return caller

        try:
            caller_fp, saved_lr = struct.unpack("<QQ", bytes(uc.mem_read(current_fp, 16)))
            caller['sp'] = current_fp + 0x10
            caller['fp'] = caller_fp
            caller['saved_lr'] = saved_lr

            slot_map = (
                (current_fp - 0x50, (UC_ARM64_REG_X28, UC_ARM64_REG_X27)),
                (current_fp - 0x40, (UC_ARM64_REG_X26, UC_ARM64_REG_X25)),
                (current_fp - 0x30, (UC_ARM64_REG_X24, UC_ARM64_REG_X23)),
                (current_fp - 0x20, (UC_ARM64_REG_X22, UC_ARM64_REG_X21)),
                (current_fp - 0x10, (UC_ARM64_REG_X20, UC_ARM64_REG_X19)),
            )
            for slot_addr, (reg_a, reg_b) in slot_map:
                val_a, val_b = struct.unpack("<QQ", bytes(uc.mem_read(slot_addr, 16)))
                caller['saved_regs'][reg_a] = val_a
                caller['saved_regs'][reg_b] = val_b
        except Exception as exc:
            warn_cnt = getattr(self, '_cert_wrapper_capture_warn_count', 0) + 1
            self._cert_wrapper_capture_warn_count = warn_cnt
            if warn_cnt <= 3:
                print(
                    f"[CERT-FRAME-CAPTURE-FAIL #{warn_cnt}] sp={current_sp:#x} "
                    f"fp={current_fp:#x} lr={current_lr:#x}: {exc}",
                    flush=True,
                )
        return caller

    def _restore_cert_wrapper_caller_frame(self, uc, caller, ret_w0, rewrite_pc=True, skip_regs=None):
        if skip_regs is None:
            skip_regs = set()
        for reg_id, value in caller.get('saved_regs', {}).items():
            if reg_id in skip_regs:
                continue
            uc.reg_write(reg_id, value)

        fp = caller.get('fp')
        if fp is not None:
            uc.reg_write(UC_ARM64_REG_X29, fp)

        sp = caller.get('sp')
        if sp is not None:
            uc.reg_write(UC_ARM64_REG_SP, sp)

        lr = caller.get('lr')
        if lr is not None:
            uc.reg_write(UC_ARM64_REG_LR, lr)

        uc.reg_write(UC_ARM64_REG_X0, ret_w0 & 0xFFFFFFFFFFFFFFFF)

        if rewrite_pc and lr is not None:
            uc.reg_write(UC_ARM64_REG_PC, lr)

    def _code_hook(self, uc, addr, size, ud):
        self._insn_count += 1
        self._last_pc = addr
        self._record_x28_trace(uc, addr)
        self._record_dispatch_trace(uc, addr)

        pending = getattr(self, '_cert_wrapper_block_restore_pending', None)
        if pending is not None and addr == pending.get('lr'):
            self._restore_cert_wrapper_caller_frame(
                uc,
                pending,
                pending.get('ret_w0', 1),
                rewrite_pc=False,
                skip_regs={UC_ARM64_REG_X27},
            )
            print(
                f"[CERT-SKIP-2ND-APPLY #{pending['call_count']}] "
                f"lr={pending['lr']:#x} sp={pending['sp']:#x} fp={pending['fp']:#x}",
                flush=True,
            )
            self._cert_wrapper_block_restore_pending = None

        redir = self._jit_stub_entry_redirects.get(addr)
        if redir is not None:
            uc.reg_write(UC_ARM64_REG_PC, redir)
            return

        # Fast path: check hooked functions (dict lookup = O(1))
        h = self.hooked_functions.get(addr)
        if h is not None:
            self.hook_count += 1
            lr = uc.reg_read(UC_ARM64_REG_LR)
            self._invoke_hook_preserving_callee_saved(uc, h)
            uc.reg_write(UC_ARM64_REG_PC, lr)

    def _code_hook_slow(self, uc, addr, size, ud):
        """Original code hook with all safety checks (for debugging)."""
        self._insn_count += 1
        self._last_pc = addr
        self._record_x28_trace(uc, addr)
        self._record_dispatch_trace(uc, addr)

        if self._insn_count > self._max_insn:
            self.log(f"Instruction limit reached at {addr:#x}")
            uc.emu_stop()
            return

        # Catch low addresses (ELF headers at CODE_BASE=0, not executable code)
        if addr < 0x1000:
            lr = uc.reg_read(UC_ARM64_REG_LR)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if not self._in_known_region(addr):
            lr = uc.reg_read(UC_ARM64_REG_LR)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if self._is_bad_jit_exec_addr(addr):
            lr = uc.reg_read(UC_ARM64_REG_LR)
            if not hasattr(self, '_jit_bad_exec_count'):
                self._jit_bad_exec_count = 0
            self._jit_bad_exec_count += 1
            if self._jit_bad_exec_count <= 8:
                print(
                    f"[JIT-DATA-EXEC #{self._jit_bad_exec_count}] "
                    f"pc={addr:#x} lr={lr:#x} -> return 0",
                    flush=True,
                )
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if addr == 0x20b548 and self.jit_data:
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            # Replace encoder object with snapshot-built version that has populated vectors
            if hasattr(self, '_challenge_hex') and not getattr(self, '_snap_encoder_applied', False):
                snap_enc = self._build_encoder_object_from_snapshot(uc, x2)
                if snap_enc:
                    uc.reg_write(UC_ARM64_REG_X2, snap_enc)
                    x2 = snap_enc
                    self._snap_encoder_applied = True
                    self.log(f"Replaced encoder x2 with snapshot object at {snap_enc:#x}")
            if x2 and hasattr(self, '_challenge_hex'):
                try:
                    self._write_sso(uc, x2 + 0x50, self._challenge_hex.encode('ascii'))
                except Exception:
                    pass
            uc.reg_write(UC_ARM64_REG_X8, JIT_ENCODER_FN)
            return

        redir = self._jit_stub_entry_redirects.get(addr)
        if redir is not None:
            uc.reg_write(UC_ARM64_REG_PC, redir)
            return

        if addr in self.hooked_functions:
            h = self.hooked_functions[addr]
            self.hook_count += 1
            lr = uc.reg_read(UC_ARM64_REG_LR)
            h(uc, uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1),
              uc.reg_read(UC_ARM64_REG_X2), uc.reg_read(UC_ARM64_REG_X8))
            uc.reg_write(UC_ARM64_REG_PC, lr)

    def _record_dispatch_trace(self, uc, addr):
        if not (JIT_DISPATCH_TRACE_START <= addr <= JIT_DISPATCH_TRACE_END):
            return

        live_session_regions = self._live_session_regions_loaded

        # (removed: w5 sync hack)

        if addr in JIT_STACK_SEED_PCS and not live_session_regions:
            self._seed_jit_stack_struct(uc)

        self._dispatch_trace_seq += 1
        if addr == JIT_DISPATCH_HUB:
            self._dispatch_hub_hits += 1
            # After CERT-SKIP-2ND fires, the PLT bounce loop still hits the
            # dispatch hub every few blocks.  If we keep resetting progress
            # here, the stale counter never grows and the stall detector
            # never fires.  Gate the reset on whether we already skipped
            # the second cert wrapper call.
            if getattr(self, '_cert_wrapper_call_count', 0) < 2:
                self._stall_last_progress_block = self._stall_jit_count

            w5 = uc.reg_read(UC_ARM64_REG_X5) & 0xFFFFFFFF

            # Hub-limit bailout is only for zero-stub-era runs. With live snapshot
            # session pages loaded, later CFF callers legitimately enter long-running
            # real dispatch trees and forcing a return here corrupts cert computation.
            if not live_session_regions:
                CFF_HUB_LIMIT = 500
                self._cff_hub_count += 1
                if self._cff_hub_count >= CFF_HUB_LIMIT:
                    sp = uc.reg_read(UC_ARM64_REG_SP)
                    if self._cff_current_return_lr is not None:
                        saved_lr = self._cff_current_return_lr
                        saved_fp = self._cff_current_caller_fp
                        caller_sp = self._cff_current_caller_sp
                    else:
                        cff_ctx = self._jit_cff_frame_ctx.pop(sp, None)
                        if cff_ctx is not None:
                            saved_lr = cff_ctx["return_lr"]
                            saved_fp = cff_ctx["caller_fp"]
                            caller_sp = cff_ctx["caller_sp"]
                        else:
                            saved_lr = JIT_CFF_BRIDGE_DEFAULT_POST
                            saved_fp = uc.reg_read(UC_ARM64_REG_X29)
                            caller_sp = sp + 0x1A0
                    # Restore callee-saved registers from CFF frame
                    try:
                        for i, off in enumerate([0x140, 0x148, 0x150, 0x158, 0x160, 0x168,
                                                 0x170, 0x178, 0x180, 0x188]):
                            reg_id = [UC_ARM64_REG_X28, UC_ARM64_REG_X27,
                                      UC_ARM64_REG_X26, UC_ARM64_REG_X25,
                                      UC_ARM64_REG_X24, UC_ARM64_REG_X23,
                                      UC_ARM64_REG_X22, UC_ARM64_REG_X21,
                                      UC_ARM64_REG_X20, UC_ARM64_REG_X19][i]
                            val = struct.unpack("<Q", uc.mem_read(sp + off, 8))[0]
                            uc.reg_write(reg_id, val)
                    except Exception as e:
                        print(f"[CFF-HUB-LIMIT] Warning: callee-saved restore failed: {e}")
                    self._cff_skip_total += 1
                    print(f"[CFF-HUB-LIMIT #{self._cff_skip_total}] entry={self._cff_entry_total} "
                          f"hub={self._cff_hub_count} state={w5:#010x} → lr={saved_lr:#x}", flush=True)
                    uc.reg_write(UC_ARM64_REG_SP, caller_sp)
                    uc.reg_write(UC_ARM64_REG_X29, saved_fp)
                    uc.reg_write(UC_ARM64_REG_X0, 0)
                    uc.reg_write(UC_ARM64_REG_PC, saved_lr)
                    self._cff_hub_count = 0
                    self._cff_same_count = 0
                    self._cff_current_return_lr = None
                    return

            if not live_session_regions:
                # Zero-stub-era infinite-loop detector; disabled once live
                # session pages are loaded because it mutates real CFF frames.
                self._cff_hub_count += 1
                if not hasattr(self, '_cff_last_state'):
                    self._cff_last_state = w5
                    self._cff_same_count = 0
                if w5 == self._cff_last_state:
                    self._cff_same_count += 1
                else:
                    self._cff_last_state = w5
                    self._cff_same_count = 0

                if self._cff_hub_count == 50 or self._cff_same_count >= 5:
                    # Force return from inner CFF function (frame size 0x1a0)
                    sp = uc.reg_read(UC_ARM64_REG_SP)
                    # Use cached return info from entry hook (stack LR is corrupted
                    # by `mov w30, w5` in dispatch hub + CFF handlers storing it back)
                    if self._cff_current_return_lr is not None:
                        saved_lr = self._cff_current_return_lr
                        saved_fp = self._cff_current_caller_fp
                        caller_sp = self._cff_current_caller_sp
                    else:
                        # Fallback: try frame ctx dict, then stack
                        cff_ctx = self._jit_cff_frame_ctx.pop(sp, None)
                        if cff_ctx is not None:
                            saved_lr = cff_ctx["return_lr"]
                            saved_fp = cff_ctx["caller_fp"]
                            caller_sp = cff_ctx["caller_sp"]
                        else:
                            # Last resort: use bridge post address
                            saved_lr = JIT_CFF_BRIDGE_DEFAULT_POST
                            saved_fp = uc.reg_read(UC_ARM64_REG_X29)
                            caller_sp = sp + 0x1A0
                    # Restore callee-saved registers from CFF frame
                    try:
                        for i, off in enumerate([0x140, 0x148, 0x150, 0x158, 0x160, 0x168,
                                                 0x170, 0x178, 0x180, 0x188]):
                            reg_id = [UC_ARM64_REG_X28, UC_ARM64_REG_X27,
                                      UC_ARM64_REG_X26, UC_ARM64_REG_X25,
                                      UC_ARM64_REG_X24, UC_ARM64_REG_X23,
                                      UC_ARM64_REG_X22, UC_ARM64_REG_X21,
                                      UC_ARM64_REG_X20, UC_ARM64_REG_X19][i]
                            val = struct.unpack("<Q", uc.mem_read(sp + off, 8))[0]
                            uc.reg_write(reg_id, val)
                    except Exception as e:
                        print(f"[CFF-SKIP] Warning: callee-saved restore failed: {e}")
                    self._cff_skip_total += 1
                    if self._cff_skip_total <= 5 or self._cff_skip_total % 1000 == 0:
                        print(f"[CFF-SKIP #{self._cff_skip_total}] state={w5:#010x} hub={self._cff_hub_count} → "
                              f"{saved_lr:#x}")
                    uc.reg_write(UC_ARM64_REG_SP, caller_sp)
                    uc.reg_write(UC_ARM64_REG_X29, saved_fp)
                    uc.reg_write(UC_ARM64_REG_X0, 0)
                    uc.reg_write(UC_ARM64_REG_PC, saved_lr)
                    self._cff_hub_count = 0
                    self._cff_same_count = 0
                    self._cff_current_return_lr = None
                    return

            if self._dispatch_hub_hits % self._dispatch_hub_log_stride == 0:
                print(
                    "  [dispatch-hub]"
                    f" hit={self._dispatch_hub_hits}"
                    f" seq={self._dispatch_trace_seq}"
                    f" pc={addr:#x}"
                    f" w30={uc.reg_read(UC_ARM64_REG_X30) & 0xFFFFFFFF:#010x}"
                    f" w5={w5:#010x}"
                    f" lr={uc.reg_read(UC_ARM64_REG_LR):#x}"
                )

        entry = {
            "seq": self._dispatch_trace_seq,
            "insn": self._insn_count,
            "pc": addr,
            "w30": uc.reg_read(UC_ARM64_REG_X30) & 0xFFFFFFFF,
            "w5": uc.reg_read(UC_ARM64_REG_X5) & 0xFFFFFFFF,
            "sp": uc.reg_read(UC_ARM64_REG_SP),
            "lr": uc.reg_read(UC_ARM64_REG_LR),
        }
        x28 = uc.reg_read(UC_ARM64_REG_X28)

        if addr in JIT_DECISION_TRACE_PCS:
            fp = uc.reg_read(UC_ARM64_REG_X29)
            sp = uc.reg_read(UC_ARM64_REG_SP)
            entry["fp"] = fp
            entry["sp"] = sp
            entry["x0"] = uc.reg_read(UC_ARM64_REG_X0)
            entry["x24"] = uc.reg_read(UC_ARM64_REG_X24)
            entry["x28"] = x28
            entry["x28_fp_delta"] = self._maybe_delta(x28, fp)
            entry["x28_sp_delta"] = self._maybe_delta(x28, sp)
            slot_m80_addr = fp - 0x80
            slot_m60_addr = fp - 0x60
            stack_obj_addr = sp + 0x60
            entry["slot_m80_addr"] = slot_m80_addr
            entry["slot_m60_addr"] = slot_m60_addr
            entry["stack_obj_addr"] = stack_obj_addr
            entry["stack_obj_q"] = self._safe_mem_read_qword(uc, stack_obj_addr)
            entry["slot_m80_q"] = self._safe_mem_read_qword(uc, slot_m80_addr)
            entry["slot_m60_q"] = self._safe_mem_read_qword(uc, slot_m60_addr)
            entry["slot_m80_w"] = self._safe_mem_read_u32(uc, slot_m80_addr)
            entry["slot_m60_w"] = self._safe_mem_read_u32(uc, slot_m60_addr)
            entry["slot_m80_fp_delta"] = self._maybe_delta(entry["slot_m80_q"], fp)
            entry["slot_m60_fp_delta"] = self._maybe_delta(entry["slot_m60_q"], fp)
            if entry["stack_obj_q"] is not None:
                entry["stack_obj_388_q"] = self._safe_mem_read_qword(uc, entry["stack_obj_q"] + 0x388)
                entry["stack_obj_3a0_q"] = self._safe_mem_read_qword(uc, entry["stack_obj_q"] + 0x3A0)
            else:
                entry["stack_obj_388_q"] = None
                entry["stack_obj_3a0_q"] = None
            self._dispatch_decision_trace.append(entry.copy())

        self._dispatch_trace.append(entry)

    def _heap_read_trace(self, uc, access, addr, size, value, ud):
        """Trace memory reads from the heap area (session object + stubs).
        Only active during the first CFF dispatch iterations to identify
        what data the CFF code needs from the session object."""
        if not hasattr(self, '_heap_trace_active'):
            return
        if not self._heap_trace_active:
            return
        # Only trace during inner CFF (after it enters, before stall skip)
        pc = self._last_pc
        # Only trace reads from JIT code into heap
        if not (JIT_BASE <= pc < JIT_BASE + JIT_SIZE):
            return
        # Read the current value at the address
        try:
            if size == 8:
                val = struct.unpack("<Q", bytes(uc.mem_read(addr, 8)))[0]
            elif size == 4:
                val = struct.unpack("<I", bytes(uc.mem_read(addr, 4)))[0]
            elif size == 2:
                val = struct.unpack("<H", bytes(uc.mem_read(addr, 2)))[0]
            elif size == 1:
                val = bytes(uc.mem_read(addr, 1))[0]
            else:
                val = 0
        except:
            val = 0

        # Compute offset relative to session object if applicable
        if hasattr(self, '_session_obj'):
            obj = self._session_obj
            obj_end = obj + 0x1000  # session object size
            if obj <= addr < obj_end:
                off = addr - obj
                tag = f"OBJ+0x{off:03x}"
            else:
                tag = f"HEAP+0x{addr - HEAP_BASE:x}"
        else:
            tag = f"HEAP+0x{addr - HEAP_BASE:x}"

        if not hasattr(self, '_heap_trace_log'):
            self._heap_trace_log = []
        if len(self._heap_trace_log) < 2000:
            self._heap_trace_log.append({
                'pc': pc, 'addr': addr, 'size': size, 'val': val,
                'tag': tag, 'hub_hits': self._dispatch_hub_hits,
            })

    def _jit_block_hook(self, uc, addr, size, ud):
        """Lightweight stall detection via basic block hook.
        Also detects CFF stalls at known hubs and forces skip."""
        if self._is_bad_jit_exec_addr(addr):
            lr = uc.reg_read(UC_ARM64_REG_LR)
            if not hasattr(self, '_jit_bad_exec_count'):
                self._jit_bad_exec_count = 0
            self._jit_bad_exec_count += 1
            if self._jit_bad_exec_count <= 8:
                print(
                    f"[JIT-DATA-EXEC #{self._jit_bad_exec_count}] "
                    f"pc={addr:#x} lr={lr:#x} -> return 0",
                    flush=True,
                )
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        off = addr - JIT_BASE
        if self._maybe_bypass_post_cert_cleanup(uc, addr):
            return
        if off == 0x156064:
            cnt = getattr(self, "_fmt_x_block_diag_count", 0) + 1
            self._fmt_x_block_diag_count = cnt
            if cnt <= 8:
                x20 = uc.reg_read(UC_ARM64_REG_X20)
                x22 = uc.reg_read(UC_ARM64_REG_X22)
                x25 = uc.reg_read(UC_ARM64_REG_X25)
                x29 = uc.reg_read(UC_ARM64_REG_X29)
                w21 = uc.reg_read(UC_ARM64_REG_X21) & 0xFFFFFFFF
                try:
                    fmt_head = bytes(uc.mem_read(x20, 8))
                except Exception as exc:
                    fmt_head = f"ERR({exc})".encode()
                try:
                    args_hex = self._dump_mem_hex(uc, x25, 0x20)
                except Exception as exc:
                    args_hex = f"ERR({exc})"
                print(
                    f"[FMT-X-BLOCK #{cnt}]{self._fmt_call_tag()} "
                    f"x20={x20:#x} x29={x29:#x} fmt_head={fmt_head!r} "
                    f"x22={x22:#x} x25={x25:#x} w21={w21:#x} args={args_hex}",
                    flush=True,
                )
        # ---- BULK-XOR inner loop fast-forward (block-level) at 0x56d1c
        # Must fire in block hook since stall detection can preempt code hooks.
        if off == 0x56d1c:
            x12 = uc.reg_read(UC_ARM64_REG_X12)
            x13 = uc.reg_read(UC_ARM64_REG_X13)
            x14 = uc.reg_read(UC_ARM64_REG_X14)
            remaining_bytes = 0x4000 - x12
            if remaining_bytes > 32:
                try:
                    src_data = bytearray(self._read_bytes_with_fallback(uc, x14 + x12, remaining_bytes))
                    dst_data = bytearray(self._read_bytes_with_fallback(uc, x13 + x12, remaining_bytes))
                    for j in range(0, remaining_bytes, 4):
                        v = (int.from_bytes(dst_data[j:j+4], 'little') ^
                             int.from_bytes(src_data[j:j+4], 'little'))
                        dst_data[j:j+4] = v.to_bytes(4, 'little')
                    uc.mem_write(x13 + x12, bytes(dst_data))
                    self._record_recent_data_event(
                        "bulkxor-inner",
                        src=x14 + x12,
                        dst=x13 + x12,
                        size=remaining_bytes,
                        lr=uc.reg_read(UC_ARM64_REG_LR),
                        pc=addr,
                        head=bytes(dst_data[:32]),
                    )
                    uc.reg_write(UC_ARM64_REG_X12, 0x4000)
                    self._stall_last_progress_block = self._stall_jit_count
                    uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x56d38)
                    return
                except Exception:
                    pass  # unmapped → let normal execution handle it
        # Also fast-forward the outer loop at 0x56d04 from block hook
        if off == 0x56d04:
            self._stall_last_progress_block = self._stall_jit_count
        # ---- SHA256-LOOP fast-forward at 0x16d02c: obfuscated SHA-256 block loop
        # The CFF body walks 64-byte blocks and eventually materializes the
        # 32-byte digest at sp+0x3c4. Bypass it with hashlib and jump to the
        # post-loop exit at 0x16f870.
        if off == 0x16d02c:
            # SHA-256 fast-forward: read data from x10-relative source ONLY.
            # x22 is garbage at this point. The actual data pointer is computed
            # from the asm: x10 = 0x448430 + w10 (uxtw), data at [x10+x8].
            cnt = getattr(self, '_sha256_loop_hits', 0) + 1
            self._sha256_loop_hits = cnt
            self._stall_last_progress_block = self._stall_jit_count
            sp = uc.reg_read(UC_ARM64_REG_SP)
            w10 = uc.reg_read(UC_ARM64_REG_X10) & 0xFFFFFFFF
            w28 = uc.reg_read(UC_ARM64_REG_X28) & 0xFFFFFFFF
            data_ptr = (JIT_BASE + 0x448430 + w10) & 0xFFFFFFFFFFFFFFFF
            if data_ptr > 0x1000 and 0 < w28 <= 0x1000000:
                try:
                    padded_data = self._read_bytes_with_fallback(uc, data_ptr, w28)
                    # The CFF SHA-256 processes pre-padded data (exact 64-byte blocks).
                    # Standard SHA-256 padding: last 8 bytes = bit length (BE in standard,
                    # but this implementation stores LE bit count).
                    # Try to extract message length; if it looks pre-padded, use raw
                    # block compression.
                    bit_len_le = struct.unpack("<Q", padded_data[-8:])[0]
                    msg_len = bit_len_le // 8
                    if not (0 < msg_len <= w28):
                        bit_len_be = struct.unpack(">Q", padded_data[-8:])[0]
                        msg_len_be = bit_len_be // 8
                        if 0 < msg_len_be <= w28:
                            msg_len = msg_len_be
                        else:
                            msg_len = w28
                    message = padded_data[:msg_len]
                    if w28 % 64 == 0:
                        # Pre-padded: raw SHA-256 block compression
                        h0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
                        K = [
                            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
                        ]
                        M = 0xFFFFFFFF
                        def _rr(x, n): return ((x >> n) | (x << (32 - n))) & M
                        H = list(h0)
                        for blk_off in range(0, w28, 64):
                            block = padded_data[blk_off:blk_off+64]
                            w_sched = [struct.unpack(">I", block[4*j:4*j+4])[0] for j in range(16)]
                            for j in range(16, 64):
                                s0 = _rr(w_sched[j-15], 7) ^ _rr(w_sched[j-15], 18) ^ (w_sched[j-15] >> 3)
                                s1 = _rr(w_sched[j-2], 17) ^ _rr(w_sched[j-2], 19) ^ (w_sched[j-2] >> 10)
                                w_sched.append((w_sched[j-16] + s0 + w_sched[j-7] + s1) & M)
                            a, b, c, d, e, f, g, hh = H
                            for j in range(64):
                                S1 = _rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25)
                                ch = (e & f) ^ ((~e & M) & g)
                                t1 = (hh + S1 + ch + K[j] + w_sched[j]) & M
                                S0 = _rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22)
                                maj = (a & b) ^ (a & c) ^ (b & c)
                                t2 = (S0 + maj) & M
                                hh = g; g = f; f = e; e = (d + t1) & M
                                d = c; c = b; b = a; a = (t1 + t2) & M
                            H = [(H[i] + v) & M for i, v in enumerate([a, b, c, d, e, f, g, hh])]
                        digest = b''.join(struct.pack(">I", v) for v in H)
                    else:
                        digest = hashlib.sha256(message).digest()
                    # Write 32-byte digest to sp+0x3c4
                    uc.mem_write(sp + 0x3c4, digest)
                    h = struct.unpack("<IIII", digest[:16])
                    uc.reg_write(UC_ARM64_REG_X16, h[0])
                    uc.reg_write(UC_ARM64_REG_X6, h[1])
                    uc.reg_write(UC_ARM64_REG_X13, h[2])
                    uc.reg_write(UC_ARM64_REG_X15, h[3])
                    try:
                        x23_val = struct.unpack("<Q", uc.mem_read(sp + 0xb8, 8))[0]
                        uc.reg_write(UC_ARM64_REG_X23, x23_val)
                    except:
                        pass
                    w0 = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
                    uc.reg_write(UC_ARM64_REG_X12, w0)
                    uc.reg_write(UC_ARM64_REG_X8, 0)
                    uc.reg_write(UC_ARM64_REG_X25, sp + 0x378)
                    uc.reg_write(UC_ARM64_REG_X10, w28)
                    if cnt <= 8:
                        # Decode the hash input as ASCII for debugging
                        try:
                            ascii_msg = message.decode('ascii', errors='replace')[:80]
                        except:
                            ascii_msg = ''
                        print(
                            f"[SHA256-FF #{cnt}] ptr={data_ptr:#x} w10={w10:#x} "
                            f"w28={w28:#x} msg_len={msg_len} "
                            f"digest={digest.hex()} "
                            f"msg_head={padded_data[:64].hex()} "
                            f"ascii='{ascii_msg}'",
                            flush=True,
                        )
                    uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x16f890)
                    return
                except Exception as e:
                    if cnt <= 8:
                        print(f"[SHA256-FF-ERR #{cnt}] ptr={data_ptr:#x} w10={w10:#x} w28={w28:#x} err={e}", flush=True)
            elif cnt <= 8:
                print(f"[SHA256-FF-SKIP #{cnt}] bad-args w10={w10:#x} w28={w28:#x} ptr={data_ptr:#x}", flush=True)
        # Mark the entire SHA-256 CFF range as progress to prevent stall detection
        # from killing the emulator while Unicorn processes the obfuscated SHA-256.
        if 0x16D000 <= off < 0x170000:
            self._stall_last_progress_block = self._stall_jit_count
        # 0x6a96c is a tiny cleanup helper that clears 0x100 bytes via an
        # imported memset-like routine at 0x54c40. That import bounces in the
        # emulator and can strand the post-output tail after the hash has
        # already been materialized. Zero the object directly and return.
        if off == 0x6a96c:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            if x0 > 0x1000:
                try:
                    uc.mem_write(x0, b"\x00" * 0x108)
                except Exception:
                    pass
            cnt = getattr(self, "_cleanup_6a96c_ff_hits", 0) + 1
            self._cleanup_6a96c_ff_hits = cnt
            if cnt <= 8:
                print(f"[CLEANUP-6A96C-FF #{cnt}] obj={x0:#x} lr={uc.reg_read(UC_ARM64_REG_LR):#x}", flush=True)
            self._stall_last_progress_block = self._stall_jit_count
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        # 0x11cfd0 used to be treated as a late-output epilogue, but on the
        # current live image it sits inside active post-SHA processing. Keep it
        # diagnostic-only so we do not jump out of the real handoff path.
        if off == 0x11cfd0:
            cnt = getattr(self, "_output_tail_seen_hits", 0) + 1
            self._output_tail_seen_hits = cnt
            if cnt <= 4:
                sp = uc.reg_read(UC_ARM64_REG_SP)
                x27 = uc.reg_read(UC_ARM64_REG_X27)
                diag_parts = []
                for label, base, off_val, sz in [
                    ("x27+0x210", x27, 0x210, 48),
                    ("x27+0x2a0", x27, 0x2a0, 48),
                    ("sp+0x620", sp, 0x620, 48),
                    ("sp+0x5f0", sp, 0x5f0, 32),
                ]:
                    try:
                        raw = bytes(uc.mem_read(base + off_val, sz))
                        diag_parts.append(f"{label}={raw.hex()}")
                    except:
                        diag_parts.append(f"{label}=ERR")
                print(f"[OUTPUT-TAIL-SEEN #{cnt}] {' '.join(diag_parts)}", flush=True)
        # Clear stale CFF return state when entering cert function prologue.
        # This prevents GENERAL-STALL from using an old LR to force-return
        # out of the cert function before it can execute.
        if off in (0x1c20f4, 0x1c2110, 0x1c2124):
            if self._cff_current_return_lr is not None:
                print(f"[CERT-ENTRY-CLEAR] off={off:#x} clearing stale CFF lr={self._cff_current_return_lr:#x}", flush=True)
                self._cff_current_return_lr = None
                self._cff_current_caller_sp = None
                self._cff_current_caller_fp = None
            # Cert wrapper diagnostics live in _cert_wrapper_entry_hook, but the
            # second-call skip now runs here in the block hook so the current
            # block can finish before we restore the caller frame at LR.
            self._stall_last_progress_block = getattr(self, '_stall_jit_count', 0)
            # One-shot diagnostic: why does 0x1c2110 keep repeating?
            cnt_key = '_cert_block_diag_count'
            cnt = getattr(self, cnt_key, 0) + 1
            setattr(self, cnt_key, cnt)
            if cnt <= 3:
                lr = uc.reg_read(UC_ARM64_REG_LR)
                sp = uc.reg_read(UC_ARM64_REG_SP)
                pc = uc.reg_read(UC_ARM64_REG_PC)
                x29 = uc.reg_read(UC_ARM64_REG_X29)
                x22 = uc.reg_read(UC_ARM64_REG_X22)
                prev = getattr(self, '_prev_jit_block', 0) - JIT_BASE
                print(f"[CERT-DIAG #{cnt}] off={off:#x} pc={pc:#x} lr={lr:#x} sp={sp:#x} x29={x29:#x} x22={x22:#x} prev_block={prev:#x} blk_size={size}", flush=True)
        # Quick CFF hub 0x10f61c stall detector (state in w20)
        if addr == JIT_BASE + 0x10f61c:
            if not hasattr(self, '_hub10f61c_cnt'):
                self._hub10f61c_cnt = 0
                self._hub10f61c_state = None
            self._hub10f61c_cnt += 1
            w20 = uc.reg_read(UC_ARM64_REG_X20) & 0xFFFFFFFF
            if self._hub10f61c_cnt <= 3:
                x19 = uc.reg_read(UC_ARM64_REG_X19)
                lr = uc.reg_read(UC_ARM64_REG_LR)
                sp = uc.reg_read(UC_ARM64_REG_SP)
                x29 = uc.reg_read(UC_ARM64_REG_X29)
                hist = [f"{b-JIT_BASE:#x}" for b in getattr(self, '_jit_recent_blocks', [])]
                print(f"[HUB-10f61c #{self._hub10f61c_cnt}] w20={w20:#010x} x19={x19:#x} lr={lr:#x} sp={sp:#x} x29={x29:#x}", flush=True)
                print(f"  recent blocks: {' -> '.join(hist[-12:])}", flush=True)
                if self._hub10f61c_cnt == 1:
                    # Dump frame chain
                    fp = x29
                    for i in range(8):
                        try:
                            frame_bytes = bytes(uc.mem_read(fp, 16))
                            saved_fp, saved_lr = struct.unpack('<QQ', frame_bytes)
                            off_lr = saved_lr - JIT_BASE if JIT_BASE <= saved_lr < JIT_BASE + 0x500000 else saved_lr
                            print(f"  frame[{i}] fp={fp:#x} -> saved_fp={saved_fp:#x} saved_lr={off_lr:#x}", flush=True)
                            if saved_fp == 0 or saved_fp == fp:
                                break
                            fp = saved_fp
                        except:
                            print(f"  frame[{i}] fp={fp:#x} -> UNREADABLE", flush=True)
                            break
            if self._hub10f61c_cnt > 50 and w20 == self._hub10f61c_state:
                # Same state for 50+ iterations - force skip
                # LR may be garbage; walk frame chain to find a valid return
                lr = uc.reg_read(UC_ARM64_REG_LR)
                ret_addr = lr
                if not (JIT_BASE <= lr < JIT_BASE + 0x500000 or
                        0x20000000 <= lr < 0x70000000):
                    # LR is garbage, walk frame chain
                    fp = uc.reg_read(UC_ARM64_REG_X29)
                    for depth in range(16):
                        try:
                            fb = bytes(uc.mem_read(fp, 16))
                            sfp, slr = struct.unpack('<QQ', fb)
                            valid_jit = JIT_BASE <= slr < JIT_BASE + 0x500000
                            valid_scratch = SCRATCH_BASE <= slr < SCRATCH_BASE + SCRATCH_SIZE
                            valid_nmsscr = 0x20000000 <= slr < 0x30000000
                            if valid_jit or valid_scratch or valid_nmsscr:
                                ret_addr = slr
                                # Restore SP to just past this frame
                                uc.reg_write(UC_ARM64_REG_X29, sfp)
                                uc.reg_write(UC_ARM64_REG_SP, fp + 16)
                                tag = f"{ret_addr-JIT_BASE:#x}" if valid_jit else f"{ret_addr:#x}"
                                print(f"[HUB-10f61c STALL] walked {depth+1} frames -> ret {tag}", flush=True)
                                break
                            if sfp == 0 or sfp == fp:
                                break
                            fp = sfp
                        except:
                            break
                    else:
                        print(f"[HUB-10f61c STALL] no valid frame found, using _walk_frame_chain_return", flush=True)
                        ret_addr = None
                if ret_addr is not None:
                    print(f"[HUB-10f61c STALL] w20={w20:#010x} iter={self._hub10f61c_cnt} -> ret {ret_addr:#x}", flush=True)
                    uc.reg_write(UC_ARM64_REG_X0, 0)
                    uc.reg_write(UC_ARM64_REG_PC, ret_addr)
                else:
                    # Last resort: try _walk_frame_chain_return helper
                    self._walk_frame_chain_return(uc, "hub10f61c-stall")
                self._hub10f61c_cnt = 0
                self._stall_last_progress_block = self._stall_jit_count
                return
            self._hub10f61c_state = w20
        self._prev_jit_block = getattr(self, '_last_jit_block', 0)
        self._last_jit_block = addr
        block_hist = list(getattr(self, '_jit_recent_blocks', []))
        block_hist.append(addr)
        self._jit_recent_blocks = block_hist[-12:]
        self._stall_jit_count += 1
        live_session_regions = self._live_session_regions_loaded
        block_limit = (
            self._stall_live_block_limit
            if live_session_regions
            else self._stall_block_limit
        )
        if self._stall_jit_count % 50000 == 0:
            elapsed = time.time() - self._emu_start_time if hasattr(self, '_emu_start_time') else 0
            w5 = uc.reg_read(UC_ARM64_REG_X5) & 0xFFFFFFFF
            last_hub = self._dispatch_hub_hits
            blk_since = self._stall_jit_count - self._stall_last_progress_block
            cff_entries = getattr(self, '_cff_entry_total', 0)
            cff_skips = getattr(self, '_cff_skip_total', 0)
            pc_now = addr - JIT_BASE
            recent = [hex(b - JIT_BASE) for b in self._jit_recent_blocks[-4:]]
            print(f"[PROGRESS] blocks={self._stall_jit_count} hub={last_hub} "
                  f"w5={w5:#010x} t={elapsed:.0f}s stale={blk_since} "
                  f"cff={cff_entries}(skip={cff_skips}) pc={pc_now:#x} recent={recent}", flush=True)
            # One-time diagnostic dump at ~30s
            if not self._diag_dumped and elapsed > 25:
                self._diag_dumped = True
                lr_hist = self._cff_lr_hist
                nat_rets = self._cff_natural_returns
                print(f"\n[DIAG] CFF caller LR histogram (len={len(lr_hist)}, entries={self._cff_entry_total}):", flush=True)
                for lr_val, cnt in sorted(lr_hist.items(), key=lambda x: -x[1])[:10]:
                    print(f"  LR={lr_val:#010x} count={cnt}", flush=True)
                print(f"[DIAG] CFF natural return values (first 20):", flush=True)
                for w0, lr_val in nat_rets:
                    print(f"  w0={w0:#010x} → LR={lr_val:#x}", flush=True)
                print(flush=True)

        # Post-CERT-SKIP budget: the cert is already computed after the first
        # wrapper call.  Everything after CERT-SKIP-2ND is cleanup / PLT bounce
        # that we don't need.  Give it 200K blocks then stop.
        post_skip_start = getattr(self, '_post_cert_skip_block_start', None)
        if post_skip_start is not None:
            post_skip_blocks = self._stall_jit_count - post_skip_start
            if post_skip_blocks > 200_000:
                print(f"[POST-CERT-SKIP-BUDGET] {post_skip_blocks} blocks after "
                      f"CERT-SKIP-2ND, stopping emulation", flush=True)
                uc.emu_stop()
                return

        # General stall: no progress (hub hit) for too long → force return.
        # Live snapshot-backed runs legitimately spend long stretches outside the
        # old CFF hub paths, so keep the zero-stub-era bailout aggressive only
        # for synthetic runs and give real sessions a much larger budget.
        blocks_since_progress = self._stall_jit_count - self._stall_last_progress_block
        if blocks_since_progress > block_limit and self._stall_jit_count % 10000 == 0:
            fp = uc.reg_read(UC_ARM64_REG_X29)
            sp = uc.reg_read(UC_ARM64_REG_SP)
            if live_session_regions and self._maybe_exit_cert_post_success_walker(
                uc, addr, blocks_since_progress
            ):
                self._cff_current_return_lr = None
                self._stall_last_progress_block = self._stall_jit_count
                return
            if live_session_regions and self._allow_live_frame_walk(addr, blocks_since_progress):
                walked = self._walk_frame_chain_return(uc, addr, fp, sp)
                if walked:
                    self._cff_current_return_lr = None
                    self._stall_last_progress_block = self._stall_jit_count
                    return
                # Walk failed — frame chain is corrupt/empty.
                # Use the saved cert wrapper caller frame to force-return.
                off = addr - JIT_BASE if JIT_BASE <= addr < JIT_BASE + JIT_SIZE else addr
                self._stall_skips += 1
                caller = getattr(self, '_cert_wrapper_caller', None)
                if caller:
                    print(f"[CERT-FORCE-RET #{self._stall_skips}] off={off:#x} "
                          f"→ cert caller lr={caller['lr']:#x} "
                          f"sp={caller['sp']:#x} fp={caller['fp']:#x}", flush=True)
                    self._restore_cert_wrapper_caller_frame(uc, caller, 0)
                    self._cert_wrapper_caller = None  # only use once
                else:
                    print(f"[WALK-FAIL #{self._stall_skips}] off={off:#x} "
                          f"no cert caller saved", flush=True)
                self._stall_last_progress_block = self._stall_jit_count
                if self._stall_skips > 30:
                    uc.emu_stop()
                return
            # The cached CFF return LR is only reliable for the older synthetic
            # runs. In live snapshot-backed runs it frequently goes stale and
            # bounces execution into terminate/error paths unrelated to the
            # current loop, so only use it outside live-session mode.
            if not live_session_regions and self._cff_current_return_lr is not None:
                saved_lr = self._cff_current_return_lr
                returned_lrs = getattr(self, '_stall_returned_lrs', {})
                lr_hits = returned_lrs.get(saved_lr, 0)
                if lr_hits >= 2:
                    # This LR keeps stalling — escalate via frame walk
                    print(f"[GENERAL-STALL-ESCALATE] CFF lr={saved_lr:#x} hit {lr_hits} times, walking deeper", flush=True)
                    walked = self._walk_frame_chain_return(uc, addr, fp, sp)
                    if walked:
                        self._cff_current_return_lr = None
                        self._stall_last_progress_block = self._stall_jit_count
                        return
                returned_lrs[saved_lr] = lr_hits + 1
                self._stall_returned_lrs = returned_lrs
                self._stall_skips += 1
                caller_sp = self._cff_current_caller_sp
                saved_fp_val = self._cff_current_caller_fp
                print(f"[GENERAL-STALL #{self._stall_skips}] pc={addr:#x} → CFF lr={saved_lr:#x} (lr_hits={lr_hits+1})", flush=True)
                uc.reg_write(UC_ARM64_REG_SP, caller_sp)
                uc.reg_write(UC_ARM64_REG_X29, saved_fp_val)
                uc.reg_write(UC_ARM64_REG_X0, 0)
                uc.reg_write(UC_ARM64_REG_PC, saved_lr)
                self._cff_current_return_lr = None
                self._stall_last_progress_block = self._stall_jit_count
                if self._stall_skips > 30:
                    uc.emu_stop()
                return
            # Walk frame chain to find a valid return address. Keep this
            # unconditional only for synthetic runs; live-session runs use the
            # allow-list above so early decoder/copy loops are not unwound.
            if not live_session_regions:
                walked = self._walk_frame_chain_return(uc, addr, fp, sp)
                if walked:
                    self._stall_last_progress_block = self._stall_jit_count
                    return
            # Last resort: just keep going, bump progress so we check again later
            self._stall_last_progress_block = self._stall_jit_count

    def _allow_live_frame_walk(self, addr, blocks_since_progress):
        """Constrain live-session unwinds to the cert tail loops we trust."""
        if not (JIT_BASE <= addr < JIT_BASE + JIT_SIZE):
            return False
        off = addr - JIT_BASE
        # MD5 compression loop area
        if 0x16D000 <= off < 0x170000:
            return True
        # XOR scrambler tail
        if 0x132700 <= off < 0x132800 and blocks_since_progress >= 300_000:
            return True
        # PLT-bouncing pre-computation loops (various JIT offset ranges)
        if 0x054000 <= off < 0x056000:  # PLT stub area (0x547xx etc.)
            return True
        if 0x4FF000 <= off < 0x500000:  # PLT bounce targets (~0x4ffxxx)
            return True
        if 0x1E5000 <= off < 0x1EA000:  # PLT bounce inner (~0x1e5xxx-0x1e8xxx)
            return True
        # Cert CFF wrapper body (0x1c1700-0x1c3400) — inner state machine stalls
        if 0x1C1000 <= off < 0x1C4000:
            return True
        return False

    def _maybe_bypass_post_cert_cleanup(self, uc, addr):
        """Skip recursive TLS/C++ cleanup once the cert walker has already exited."""
        if not self._post_cert_cleanup_bypass_active:
            return False
        if addr not in (
            JIT_CXA_NODE_RELEASE_FN,
            JIT_CXA_TLS_LIST_STEP_FN,
            JIT_CXA_NORETURN_CALL_FN,
            JIT_CXA_TLS_CLEANUP_FN,
            JIT_CXA_CLEANUP_DRIVER_FN,
        ):
            return False
        self._post_cert_cleanup_bypass_hits += 1
        # If we've been bouncing through cleanup far too many times,
        # the cert is already computed — just stop emulation.
        if self._post_cert_cleanup_bypass_hits > 20:
            print(f"[POST-CERT-CLEANUP-DONE] {self._post_cert_cleanup_bypass_hits} "
                  f"bypass hits, stopping emulation", flush=True)
            uc.emu_stop()
            return True
        lr = uc.reg_read(UC_ARM64_REG_LR)
        target = lr
        skipped_frame = False
        if target == addr or not self._in_known_region(target):
            fp = uc.reg_read(UC_ARM64_REG_X29)
            try:
                saved_fp = struct.unpack("<Q", uc.mem_read(fp, 8))[0]
                saved_lr = struct.unpack("<Q", uc.mem_read(fp + 8, 8))[0]
            except Exception:
                saved_fp = 0
                saved_lr = 0
            if saved_lr and saved_lr != addr and self._in_known_region(saved_lr):
                uc.reg_write(UC_ARM64_REG_SP, fp + 0x10)
                uc.reg_write(UC_ARM64_REG_X29, saved_fp)
                target = saved_lr
                skipped_frame = True
        if self._post_cert_cleanup_bypass_hits <= 8:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            print(
                f"[POST-CERT-CLEANUP-BYPASS #{self._post_cert_cleanup_bypass_hits}] "
                f"pc={addr:#x} x0={x0:#x} lr={lr:#x} -> "
                f"{'frame-skip' if skipped_frame else 'return'} {target:#x}",
                flush=True,
            )
        self._stall_last_progress_block = getattr(self, "_stall_jit_count", 0)
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, target)
        return True

    def _maybe_exit_cert_post_success_walker(self, uc, addr, blocks_since_progress):
        """Exit the 0x1c15b8 cert walker via its own epilogue.

        The 0x1c19xx-0x1c1fxx dispatcher is a real function with a large saved-
        register frame. Returning to its caller by frame-walk skips the epilogue,
        so x19-x28 stay clobbered and the parent later dereferences garbage.
        Force a local null return through the function's real restore path.
        """
        if not (JIT_BASE <= addr < JIT_BASE + JIT_SIZE):
            return False
        off = addr - JIT_BASE
        if not (0x1C1900 <= off < 0x1C2000):
            return False
        if blocks_since_progress < 180_000:
            return False

        self._stall_skips += 1
        print(
            f"[CERT-WALKER-EXIT #{self._stall_skips}] pc={addr:#x} "
            f"stale={blocks_since_progress} -> epilogue {JIT_CERT_POST_SUCCESS_WALKER_EPILOGUE:#x}",
            flush=True,
        )
        self._post_cert_cleanup_bypass_active = True
        self._post_cert_cleanup_bypass_hits = 0
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, JIT_CERT_POST_SUCCESS_WALKER_EPILOGUE)
        if self._stall_skips > 30:
            uc.emu_stop()
        return True

    def _walk_frame_chain_return(self, uc, addr, fp, sp):
        """Walk AArch64 frame chain from fp to find a valid return address.
        Return True if successfully redirected execution.
        Escalates: if an LR was already returned to 2+ times, skip it and
        walk deeper to avoid re-entering the same stalling loop."""
        returned_lrs = getattr(self, '_stall_returned_lrs', {})
        cur_fp = fp
        candidates = []
        for depth in range(16):
            if cur_fp == 0 or cur_fp < STACK_BASE or cur_fp >= STACK_BASE + STACK_SIZE:
                break
            try:
                saved_fp = struct.unpack("<Q", uc.mem_read(cur_fp, 8))[0]
                saved_lr = struct.unpack("<Q", uc.mem_read(cur_fp + 8, 8))[0]
            except:
                break
            in_jit = JIT_BASE <= saved_lr < JIT_BASE + JIT_SIZE
            in_nmsscr = 0x5ee10 <= saved_lr < 0x29c800
            if in_jit or in_nmsscr:
                jit_offset = saved_lr - JIT_BASE if in_jit else saved_lr
                if in_jit and jit_offset < 0x1000:
                    cur_fp = saved_fp
                    continue
                candidates.append((depth, saved_lr, saved_fp, cur_fp))
            cur_fp = saved_fp

        if not candidates:
            if getattr(self, '_walk_fail_diag', 0) < 3:
                self._walk_fail_diag = getattr(self, '_walk_fail_diag', 0) + 1
                off = addr - JIT_BASE if JIT_BASE <= addr < JIT_BASE + JIT_SIZE else addr
                print(f"[WALK-FAIL #{self._walk_fail_diag}] pc={off:#x} fp={fp:#x} sp={sp:#x} "
                      f"no valid candidates in frame chain", flush=True)
                # Dump chain for diagnostics
                cur = fp
                for d in range(6):
                    try:
                        sfp = struct.unpack("<Q", uc.mem_read(cur, 8))[0]
                        slr = struct.unpack("<Q", uc.mem_read(cur + 8, 8))[0]
                        slr_off = slr - JIT_BASE if JIT_BASE <= slr < JIT_BASE + JIT_SIZE else slr
                        print(f"  chain[{d}] fp={cur:#x} saved_fp={sfp:#x} saved_lr={slr_off:#x}", flush=True)
                        if sfp == 0 or sfp == cur:
                            break
                        cur = sfp
                    except:
                        print(f"  chain[{d}] fp={cur:#x} UNREADABLE", flush=True)
                        break
            return False

        # Pick the first candidate not already exhausted (returned to >=2 times)
        chosen = None
        for depth, saved_lr, saved_fp, frame_fp in candidates:
            hit_count = returned_lrs.get(saved_lr, 0)
            if hit_count < 2:
                chosen = (depth, saved_lr, saved_fp, frame_fp)
                break
        # If all candidates exhausted, pick the deepest one as last resort
        if chosen is None:
            chosen = candidates[-1]
            # Also clear the returned_lrs to prevent infinite escalation
            returned_lrs.clear()

        depth, saved_lr, saved_fp, frame_fp = chosen
        returned_lrs[saved_lr] = returned_lrs.get(saved_lr, 0) + 1
        self._stall_returned_lrs = returned_lrs

        self._stall_skips += 1
        caller_sp = frame_fp + 16
        escalated = " (ESCALATED)" if depth > 0 else ""
        print(f"[FRAME-WALK #{self._stall_skips}] depth={depth}{escalated} pc={addr:#x} "
              f"fp={fp:#x} → lr={saved_lr:#x} caller_sp={caller_sp:#x} "
              f"(lr_hits={returned_lrs[saved_lr]})", flush=True)
        uc.reg_write(UC_ARM64_REG_SP, caller_sp)
        uc.reg_write(UC_ARM64_REG_X29, saved_fp)
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, saved_lr)
        if self._stall_skips > 30:
            uc.emu_stop()
        return True

    def _wild_exec_hook(self, uc, addr, size, ud):
        """Catch execution at invalid/wild addresses and redirect to LR."""
        lr = uc.reg_read(UC_ARM64_REG_LR)
        if not hasattr(self, '_wild_exec_count'):
            self._wild_exec_count = 0
        self._wild_exec_count += 1
        if self._wild_exec_count <= 10:
            print(f"[WILD-EXEC #{self._wild_exec_count}] pc={addr:#x} lr={lr:#x}")
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _seed_jit_once_init_state(self, uc):
        uc.mem_write(JIT_ONCE_INIT_GLOBAL, struct.pack("<Q", JIT_ONCE_INIT_VTABLE))
        uc.mem_write(JIT_ONCE_INIT_GUARD, b"\x01")
        # Pre-fill the type resolver state table at JIT+0x44e9c0 with 8 ("resolved").
        # Without this, the resolver loop at JIT+0x20e640 spins forever checking
        # state_table[idx]==8 for uninitialized (0) entries.
        state_table_addr = JIT_BASE + 0x44e9c0
        uc.mem_write(state_table_addr, b'\x08' * 0x80)  # 128 entries, covers 0x00-0x7f

    def _jit_once_init_hook(self, uc, addr, size, ud):
        if addr != JIT_ONCE_INIT_HELPER:
            return
        if self._live_session_regions_loaded:
            return
        self._seed_jit_once_init_state(uc)
        self._jit_once_init_hits += 1
        if self._jit_once_init_hits <= 3:
            self.log(
                f"JIT-ONCE-INIT fast path #{self._jit_once_init_hits} "
                f"-> x0={JIT_ONCE_INIT_GLOBAL:#x}"
            )
        uc.reg_write(UC_ARM64_REG_X0, JIT_ONCE_INIT_GLOBAL)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def _force_return_from_stall(self, uc, addr, fp):
        """Force-return from a stalled function using the AArch64 frame chain.
        Standard AArch64: saved_fp=[fp], saved_lr=[fp+8], caller_sp=fp+0x10.
        Also restores callee-saved x19-x28 from [fp-0x08] down to [fp-0x50]."""
        try:
            saved_fp = struct.unpack("<Q", uc.mem_read(fp, 8))[0]
            saved_lr = struct.unpack("<Q", uc.mem_read(fp + 8, 8))[0]
        except Exception as e:
            print(f"[STALL-SKIP] Failed to read frame at fp={fp:#x}: {e}")
            self._stall_same_count = 0
            return

        # Sanity check: saved_lr should look like a JIT or nmsscr address
        if saved_lr == 0 or saved_lr > 0x20000000:
            print(f"[STALL-SKIP] Bad saved_lr={saved_lr:#x} at fp={fp:#x}, skipping")
            self._stall_same_count = 0
            return

        # Restore callee-saved registers from standard offsets
        # [fp-0x08]=x19, [fp-0x10]=x20, ..., [fp-0x50]=x28
        reg_offsets = [
            (UC_ARM64_REG_X19, -0x08), (UC_ARM64_REG_X20, -0x10),
            (UC_ARM64_REG_X21, -0x18), (UC_ARM64_REG_X22, -0x20),
            (UC_ARM64_REG_X23, -0x28), (UC_ARM64_REG_X24, -0x30),
            (UC_ARM64_REG_X25, -0x38), (UC_ARM64_REG_X26, -0x40),
            (UC_ARM64_REG_X27, -0x48), (UC_ARM64_REG_X28, -0x50),
        ]
        for reg_id, off in reg_offsets:
            try:
                val = struct.unpack("<Q", uc.mem_read(fp + off, 8))[0]
                uc.reg_write(reg_id, val)
            except Exception:
                pass

        caller_sp = fp + 0x10
        ret_x0 = 0
        if JIT_ONCE_INIT_HELPER <= addr <= JIT_ONCE_INIT_HELPER_END:
            self._seed_jit_once_init_state(uc)
            ret_x0 = JIT_ONCE_INIT_GLOBAL
        self._stall_skips += 1
        insns_stuck = max(self._stall_same_count, self._stall_page_count) * self._stall_check_interval
        print(f"[STALL-SKIP #{self._stall_skips}] Stuck at pc={addr:#x} fp={fp:#x} "
              f"for {insns_stuck} insns → return to lr={saved_lr:#x} "
              f"(caller_sp={caller_sp:#x}, saved_fp={saved_fp:#x}, ret_x0={ret_x0:#x})")
        if self._stall_skips > 20:
            print("[STALL-SKIP] Too many skips, aborting")
            self.uc.emu_stop()
            return

        uc.reg_write(UC_ARM64_REG_SP, caller_sp)
        uc.reg_write(UC_ARM64_REG_X29, saved_fp)
        uc.reg_write(UC_ARM64_REG_X0, ret_x0)
        uc.reg_write(UC_ARM64_REG_PC, saved_lr)
        self._stall_same_count = 0
        self._stall_last_fp = 0
        self._stall_post_skip_count = 0  # track insns after this skip

    def _record_x28_trace(self, uc, addr):
        interesting = (
            (0x209000 <= addr <= 0x20c000)
            or (JIT_ENTRY_TRACE_START <= addr <= JIT_ENTRY_TRACE_END)
            or (JIT_HANDOFF_TRACE_START <= addr <= JIT_HANDOFF_TRACE_END)
            or (JIT_DISPATCH_TRACE_START <= addr <= JIT_DISPATCH_TRACE_END)
        )
        if not interesting:
            return
        x28 = uc.reg_read(UC_ARM64_REG_X28)
        if x28 == self._last_traced_x28:
            return
        fp = uc.reg_read(UC_ARM64_REG_X29)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        self._x28_trace.append(
            {
                "seq": self._dispatch_trace_seq,
                "insn": self._insn_count,
                "pc": addr,
                "x28": x28,
                "fp": fp,
                "sp": sp,
                "x28_fp_delta": x28 - fp,
                "x28_sp_delta": x28 - sp,
            }
        )
        self._last_traced_x28 = x28

    def _safe_mem_read_qword(self, uc, addr):
        try:
            return struct.unpack("<Q", bytes(uc.mem_read(addr, 8)))[0]
        except Exception:
            return None

    def _safe_mem_read_u32(self, uc, addr):
        try:
            return struct.unpack("<I", bytes(uc.mem_read(addr, 4)))[0]
        except Exception:
            return None

    def _safe_mem_read_u8(self, uc, addr):
        try:
            return bytes(uc.mem_read(addr, 1))[0]
        except Exception:
            return None

    def _snapshot_second_cff_state(self, uc, addr, phase, iter_no):
        sp = uc.reg_read(UC_ARM64_REG_SP)
        fp = uc.reg_read(UC_ARM64_REG_X29)
        slot90 = self._safe_mem_read_qword(uc, sp + 0x90)
        obj_ptr = slot90 if slot90 is not None else 0
        snap = {
            "iter": iter_no,
            "phase": phase,
            "pc": addr,
            "sp": sp,
            "fp": fp,
            "lr": uc.reg_read(UC_ARM64_REG_LR),
            "x0": uc.reg_read(UC_ARM64_REG_X0),
            "x1": uc.reg_read(UC_ARM64_REG_X1),
            "x2": uc.reg_read(UC_ARM64_REG_X2),
            "x3": uc.reg_read(UC_ARM64_REG_X3),
            "x22": uc.reg_read(UC_ARM64_REG_X22),
            "x26": uc.reg_read(UC_ARM64_REG_X26),
            "x27": uc.reg_read(UC_ARM64_REG_X27),
            "w20": uc.reg_read(UC_ARM64_REG_X20) & 0xFFFFFFFF,
            "slot80": self._safe_mem_read_qword(uc, sp + 0x80),
            "slot90": slot90,
            "slot98": self._safe_mem_read_qword(uc, sp + 0x98),
            "lock9b0": self._safe_mem_read_u32(uc, JIT_BASE + 0x44C9B0),
            "g0": self._safe_mem_read_qword(uc, JIT_SECOND_CFF_GLOBAL + 0x00),
            "g8": self._safe_mem_read_qword(uc, JIT_SECOND_CFF_GLOBAL + 0x08),
            "g10": self._safe_mem_read_qword(uc, JIT_SECOND_CFF_GLOBAL + 0x10),
            "g18": self._safe_mem_read_qword(uc, JIT_SECOND_CFF_GLOBAL + 0x18),
            "g28": self._safe_mem_read_qword(uc, JIT_SECOND_CFF_GLOBAL + 0x28),
            "g30": self._safe_mem_read_qword(uc, JIT_SECOND_CFF_GLOBAL + 0x30),
        }
        if obj_ptr:
            for off, key in (
                (0x00, "obj0"),
                (0x08, "obj8"),
                (0x18, "obj18"),
                (0x28, "obj28"),
                (0x30, "obj30"),
                (0x388, "obj388"),
                (0x3A0, "obj3a0"),
            ):
                snap[key] = self._safe_mem_read_qword(uc, obj_ptr + off)
        return snap

    def _lib_loader_hook(self, uc, addr, size, ud):
        """Hook the library loader function at JIT+0x7847C.
        This function searches a zeroed module table for library paths (like 'linker').
        Since the table is empty, it always returns 2 (not found), causing infinite retries.
        We short-circuit it to return 0 (success) immediately."""
        if addr != JIT_LIB_LOADER_ENTRY:
            return
        lr = uc.reg_read(UC_ARM64_REG_LR)
        x4 = uc.reg_read(UC_ARM64_REG_X4)
        # Try to read the path string from x4
        path = b""
        if x4 > 0x1000:
            try:
                path = bytes(uc.mem_read(x4, 64)).split(b'\x00')[0]
            except:
                pass
        if not hasattr(self, '_lib_loader_skip_count'):
            self._lib_loader_skip_count = 0
        self._lib_loader_skip_count += 1
        if self._lib_loader_skip_count <= 5:
            print(f"[LIB-LOADER #{self._lib_loader_skip_count}] path={path} → skip, return 2 (not found)", flush=True)
        # Return 2 (not found) — module table doesn't have this entry
        # Returning 0 (success) caused caller to use NULL function pointers → WILD-EXEC
        uc.reg_write(UC_ARM64_REG_X0, 2)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _cff_call_159da4_hook(self, uc, addr, size, ud):
        """Skip the CFF call at JIT+0x159da4 (bl #0x8a2c4).
        The CFF computes a config value used as iteration count.
        With incomplete snapshot data, it loops forever.
        Return 29 (0x1d, the w1 argument) as the config value."""
        if addr != JIT_CFF_CALL_159DA4:
            return
        if self._live_session_regions_loaded:
            return
        if not hasattr(self, '_cff_159da4_count'):
            self._cff_159da4_count = 0
        self._cff_159da4_count += 1
        # Skip the BL — set PC to return address (next instruction)
        ret_val = 29  # 0x1d — matches the w1 argument to the CFF
        uc.reg_write(UC_ARM64_REG_X0, ret_val)
        uc.reg_write(UC_ARM64_REG_PC, JIT_CFF_CALL_159DA4 + 4)
        if self._cff_159da4_count <= 3:
            print(f"[CFF-SKIP-159DA4 #{self._cff_159da4_count}] → w0={ret_val}", flush=True)

    def _cff_call_15df68_hook(self, uc, addr, size, ud):
        """Skip the second config CFF call at JIT+0x15df68 (bl #0x8a2c4).
        Same pattern as 0x159DA4: w1=0x1d, computes iteration count."""
        if addr != JIT_CFF_CALL_15DF68:
            return
        if self._live_session_regions_loaded:
            return
        if not hasattr(self, '_cff_15df68_count'):
            self._cff_15df68_count = 0
        self._cff_15df68_count += 1
        ret_val = 29
        uc.reg_write(UC_ARM64_REG_X0, ret_val)
        uc.reg_write(UC_ARM64_REG_PC, JIT_CFF_CALL_15DF68 + 4)
        if self._cff_15df68_count <= 3:
            print(f"[CFF-SKIP-15DF68 #{self._cff_15df68_count}] → w0={ret_val}", flush=True)

    def _source_materialize_truncate_hook(self, uc, addr, size, ud):
        """Truncate 0x6af04 output to logical_length after AES-CBC decrypt.

        The materialization function at 0x6af04 copies record[+0x104] (block_size,
        16/32) bytes and decrypts them. But the compare path at 0x6afec uses
        record[+0x100] (logical_length, 13/17). Zero dest[logical:block] so the
        padding bytes don't corrupt the hash.
        """
        x19 = uc.reg_read(UC_ARM64_REG_X19)
        x20 = uc.reg_read(UC_ARM64_REG_X20)
        try:
            logical_len = struct.unpack("<I", uc.mem_read(x19 + 0x100, 4))[0]
            block_size = struct.unpack("<I", uc.mem_read(x19 + 0x104, 4))[0]
            if 0 < logical_len < block_size <= 64 and x20 != 0:
                pad = block_size - logical_len
                uc.mem_write(x20 + logical_len, b'\x00' * pad)
                # Track all source record logical lengths
                if not hasattr(self, '_trunc_source_lens'):
                    self._trunc_source_lens = []
                self._trunc_source_lens.append(logical_len)
                trunc_count = len(self._trunc_source_lens)
                # Collect materialized data for 1627d8 bypass
                if not hasattr(self, '_trunc_source_data'):
                    self._trunc_source_data = []
                try:
                    mat_data = bytes(uc.mem_read(x20, logical_len))
                    self._trunc_source_data.append(mat_data)
                    mat_hex = mat_data.hex()[:40]
                except Exception:
                    mat_hex = "?"
                print(f"[TRUNC-6af04 #{trunc_count}] logical={logical_len} block={block_size} "
                      f"pad={pad} x19={x19:#x} x20={x20:#x} data={mat_hex}",
                      flush=True)
        except Exception:
            pass

    def _cert_path_probe_hook(self, uc, addr, size, ud):
        """Reachability probe for cert CFF second callee path."""
        off = addr - JIT_BASE
        pending = getattr(self, '_cert_wrapper_block_restore_pending', None)
        if pending is not None and addr == pending.get('lr'):
            self._restore_cert_wrapper_caller_frame(
                uc,
                pending,
                pending.get('ret_w0', 1),
                rewrite_pc=False,
                skip_regs={UC_ARM64_REG_X27},
            )
            print(
                f"[CERT-SKIP-2ND-APPLY #{pending['call_count']}] "
                f"lr={pending['lr']:#x} sp={pending['sp']:#x} fp={pending['fp']:#x}",
                flush=True,
            )
            self._cert_wrapper_block_restore_pending = None
        if off == 0x1c6314:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            x2_val = 0
            try:
                x2_val = struct.unpack("<Q", uc.mem_read(sp + 0x50, 8))[0]
            except:
                pass
            # Read x2+0x60 (challenge byte) if possible
            chall_byte = 0
            if x2_val > 0x1000:
                try:
                    chall_byte = uc.mem_read(x2_val + 0x60, 1)[0]
                except:
                    pass
            print(f"[CERT-PROBE] HIT 0x1c6314 (bl 0x1d126c): [sp+0x50]={x2_val:#x} "
                  f"x2+0x60={chall_byte:#x} ('{chr(chall_byte) if 0x20<=chall_byte<0x7f else '?'}')",
                  flush=True)
        elif off == 0x1d126c:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            chall_byte = 0
            if x2 > 0x1000:
                try:
                    chall_byte = uc.mem_read(x2 + 0x60, 1)[0]
                except:
                    pass
            print(f"[CERT-PROBE] HIT 0x1d126c entry: x0={x0:#x} x1={x1:#x} x2={x2:#x} "
                  f"x3={x3:#x} x2+0x60={chall_byte:#x} ('{chr(chall_byte) if 0x20<=chall_byte<0x7f else '?'}')",
                  flush=True)

    def _cert_1d8a54_hook(self, uc, addr, size, ud):
        """Trace entry and pre-call of 0x1d8a54 (encoding function called by 0x1d126c).
        Also hooks the return site to capture w0."""
        off = addr - JIT_BASE
        if off == 0x1d8a54:
            # Entry: capture all args
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            x4 = uc.reg_read(UC_ARM64_REG_X4)
            w5 = uc.reg_read(UC_ARM64_REG_X5) & 0xFFFFFFFF
            w6 = uc.reg_read(UC_ARM64_REG_X6) & 0xFFFFFFFF
            lr = uc.reg_read(UC_ARM64_REG_LR)
            # x3 should be a GOT-loaded function pointer
            # x0,x1,x2 are data pointers - dump some bytes
            x0_data = x1_data = x2_data = b""
            for ptr, name in [(x0, "x0"), (x1, "x1"), (x2, "x2")]:
                if ptr > 0x1000:
                    try:
                        d = bytes(uc.mem_read(ptr, 32))
                        if name == "x0":
                            x0_data = d
                        elif name == "x1":
                            x1_data = d
                        else:
                            x2_data = d
                    except:
                        pass
            print(f"[1D8A54-ENTRY] x0={x0:#x} x1={x1:#x} x2={x2:#x} x3={x3:#x} "
                  f"x4={x4:#x} w5={w5} w6={w6} lr={lr:#x}", flush=True)
            print(f"  [x0]={x0_data[:16].hex() if x0_data else '??'}", flush=True)
            print(f"  [x1]={x1_data[:16].hex() if x1_data else '??'}", flush=True)
            print(f"  [x2]={x2_data[:16].hex() if x2_data else '??'}", flush=True)
            # Save return address to detect when function returns
            self._1d8a54_ret_addr = lr
            self._1d8a54_entered = True

    def _cert_1d8a54_ret_hook(self, uc, addr, size, ud):
        """Capture return from 0x1d8a54 — hooks 0x1d208c (instruction after bl)."""
        if not getattr(self, '_1d8a54_entered', False):
            return
        self._1d8a54_entered = False
        w0 = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
        print(f"[1D8A54-RET] w0={w0:#x} (bit0={w0 & 1})", flush=True)

    def _sha256_msg_assembly_hook(self, uc, addr, size, ud):
        """Instrument JIT+0x14f818: just before the 40-byte SHA-256 message is assembled.
        x10 = [sp+0x1d0] (table pointer), x19 = index into table.
        sp+0x7b0 has the 32 bytes of binary data to hash."""
        sp = uc.reg_read(UC_ARM64_REG_SP)
        x10 = uc.reg_read(UC_ARM64_REG_X10)
        x19 = uc.reg_read(UC_ARM64_REG_X19)
        cnt = getattr(self, '_sha256_msg_asm_count', 0) + 1
        self._sha256_msg_asm_count = cnt
        try:
            sp_1d0 = struct.unpack("<Q", uc.mem_read(sp + 0x1d0, 8))[0]
        except:
            sp_1d0 = 0
        try:
            table_val = struct.unpack("<Q", uc.mem_read(sp_1d0 + x19, 8))[0] if sp_1d0 else 0
        except:
            table_val = 0
        try:
            sp_7b0 = bytes(uc.mem_read(sp + 0x7b0, 32))
        except:
            sp_7b0 = b''
        try:
            sp_230 = bytes(uc.mem_read(sp + 0x230, 16))
        except:
            sp_230 = b''
        try:
            sp_220 = bytes(uc.mem_read(sp + 0x220, 16))
        except:
            sp_220 = b''
        print(f"[SHA256-MSG-ASM #{cnt}] sp={sp:#x} x10={x10:#x} x19={x19:#x} "
              f"sp+0x1d0={sp_1d0:#x} table[x19]={table_val:#x}", flush=True)
        if sp_7b0:
            print(f"  sp+0x7b0(32): {sp_7b0.hex()}", flush=True)
        if sp_230:
            print(f"  sp+0x230(16): {sp_230.hex()}", flush=True)
        if sp_220:
            print(f"  sp+0x220(16): {sp_220.hex()}", flush=True)

    def _post_concat_hook(self, uc, addr, size, ud):
        """Instrument JIT+0x109370: right after challenge+session_key concat at sp+0x810."""
        sp = uc.reg_read(UC_ARM64_REG_SP)
        try:
            sso = bytes(uc.mem_read(sp + 0x810, 24))
            byte0 = sso[0]
            if byte0 & 1:  # long SSO
                sz = struct.unpack("<Q", sso[8:16])[0]
                ptr = struct.unpack("<Q", sso[16:24])[0]
                data = bytes(uc.mem_read(ptr, min(sz, 128)))
                print(f"[POST-CONCAT] sp+0x810 LONG SSO sz={sz} ptr={ptr:#x} data={data}", flush=True)
            else:
                sz = byte0 >> 1
                data = sso[1:1+sz]
                print(f"[POST-CONCAT] sp+0x810 SHORT SSO sz={sz} data={data}", flush=True)
        except Exception as e:
            print(f"[POST-CONCAT] sp+0x810 read error: {e}", flush=True)
        # Also dump the 12 offsets at sp+0x72c (x21)
        try:
            offsets = struct.unpack("<12I", uc.mem_read(sp + 0x72c, 48))
            print(f"[POST-CONCAT] offsets@sp+0x72c: {[hex(o) for o in offsets]}", flush=True)
        except Exception as e:
            print(f"[POST-CONCAT] offsets read error: {e}", flush=True)

    def _hashchain_input_hook(self, uc, addr, size, ud):
        """Instrument JIT+0x109334: right after the hash chain input buffer is populated.
        x22 = buffer ptr (0x411 bytes), x21 = sp+0x72c.
        If device detection buffer is available, inject it here."""
        x22 = uc.reg_read(UC_ARM64_REG_X22)
        x21 = uc.reg_read(UC_ARM64_REG_X21)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        # --- Device detection buffer injection ---
        device_det_buf = getattr(self, '_device_det_buf_ascii', None)
        if device_det_buf is not None and len(device_det_buf) == 1040:
            try:
                uc.mem_write(x22, device_det_buf.encode('ascii'))
                print(f"[DET-BUF-INJECT] injected device detection buffer (1040 chars) at x22={x22:#x}", flush=True)
            except Exception as e:
                print(f"[DET-BUF-INJECT] write error: {e}", flush=True)
        try:
            buf = bytes(uc.mem_read(x22, 0x411))
        except:
            buf = b''
        # Also dump the SSO at sp+0x4f0 for comparison
        try:
            sso_head = bytes(uc.mem_read(sp + 0x4f0, 24))
        except:
            sso_head = b''
        # Session key at sp+0x1d0
        try:
            sp_1d0 = struct.unpack("<Q", uc.mem_read(sp + 0x1d0, 8))[0]
        except:
            sp_1d0 = 0
        # Challenge at sp+0x50 (or wherever)
        try:
            sp_680 = bytes(uc.mem_read(sp + 0x680, 32))
        except:
            sp_680 = b''
        print(f"[HASHCHAIN-INPUT] x22={x22:#x} x21={x21:#x} sp={sp:#x}", flush=True)
        if buf:
            print(f"  buf[0:64]: {buf[:64].hex()}", flush=True)
            print(f"  buf[64:128]: {buf[64:128].hex()}", flush=True)
            print(f"  buf[128:192]: {buf[128:192].hex()}", flush=True)
            # Find first zero run (end of actual data)
            nul_pos = buf.find(b'\x00')
            print(f"  first_nul_at: {nul_pos} total_nonzero: {sum(1 for b in buf if b)}", flush=True)
            # Check if it looks like ASCII
            ascii_part = buf.split(b'\x00')[0]
            if all(0x20 <= b < 0x7f for b in ascii_part[:64]):
                print(f"  ascii: {ascii_part[:128]}", flush=True)
        print(f"  sp+0x1d0={sp_1d0:#x} sp+0x680={sp_680.hex()}", flush=True)

    def _sp810_write_hook(self, uc, access, addr, size, value, ud):
        """Track writes to sp+0x810 (SHA-256 message block buffer).
        Also captures reads from sp+0x810 during hash chain (access type check)."""
        if not getattr(self, '_hashchain_read_tracking', False):
            return
        cnt = getattr(self, '_sp810_write_count', 0) + 1
        self._sp810_write_count = cnt
        pc = uc.reg_read(UC_ARM64_REG_PC)
        jit_off = pc - JIT_BASE if JIT_BASE <= pc < JIT_BASE + 0x300000 else None
        loc = f"JIT+{jit_off:#x}" if jit_off is not None else f"pc={pc:#x}"
        sp = uc.reg_read(UC_ARM64_REG_SP)
        sp_off = addr - sp
        val_hex = (value & ((1 << (size*8)) - 1)).to_bytes(size, 'little').hex() if size <= 16 else f"({size}B)"
        if cnt <= 40:
            print(f"[SP810-WRITE #{cnt}] {loc} => sp+{sp_off:#x} size={size} val={val_hex}", flush=True)

    def _sha256_block_loop_hook(self, uc, addr, size, ud):
        """Hook JIT+0x118850: SHA-256 block processing loop entry.
        sp+0x300 = source pointer, sp+0x308 = loop counter."""
        cnt = getattr(self, '_sha256_block_loop_count', 0) + 1
        self._sha256_block_loop_count = cnt
        if cnt <= 20 or cnt % 100 == 0:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            try:
                src_ptr = struct.unpack("<Q", uc.mem_read(sp + 0x300, 8))[0]
                loop_ctr = struct.unpack("<Q", uc.mem_read(sp + 0x308, 8))[0]
                x20 = uc.reg_read(UC_ARM64_REG_X20)
                print(f"[SHA256-BLOCK #{cnt}] sp+0x300={src_ptr:#x} sp+0x308={loop_ctr:#x} x20={x20:#x}", flush=True)
                if cnt == 1:
                    # Dump sp+0x810 (message block), sp+0x7b0 (prev hash), sp+0x940 (state)
                    msg = bytes(uc.mem_read(sp + 0x810, 64))
                    print(f"  sp+0x810(64): {msg.hex()}", flush=True)
                    prev = bytes(uc.mem_read(sp + 0x7b0, 32))
                    print(f"  sp+0x7b0(32): {prev.hex()}", flush=True)
                    state = bytes(uc.mem_read(sp + 0x940, 32))
                    print(f"  sp+0x940(32): {state.hex()}", flush=True)
                    # Dump all regs for context
                    for rn, rv in [("x0", UC_ARM64_REG_X0), ("x1", UC_ARM64_REG_X1),
                                   ("x2", UC_ARM64_REG_X2), ("x3", UC_ARM64_REG_X3),
                                   ("x7", UC_ARM64_REG_X7), ("x9", UC_ARM64_REG_X9),
                                   ("x19", UC_ARM64_REG_X19), ("x21", UC_ARM64_REG_X21),
                                   ("x22", UC_ARM64_REG_X22), ("x24", UC_ARM64_REG_X24),
                                   ("x26", UC_ARM64_REG_X26), ("x28", UC_ARM64_REG_X28)]:
                        print(f"  {rn}={uc.reg_read(rv):#x}", flush=True)
            except Exception as e:
                print(f"[SHA256-BLOCK #{cnt}] error: {e}", flush=True)

    def _hashchain_read_hook(self, uc, access, addr, size, value, ud):
        """Track heap reads during hash chain window to find SHA-256 source."""
        if not getattr(self, '_hashchain_read_tracking', False):
            return
        page = addr & ~0xFFF
        tracker = self._hashchain_read_tracker
        if page not in tracker:
            tracker[page] = {'min': addr, 'max': addr + size, 'count': 0}
        entry = tracker[page]
        entry['min'] = min(entry['min'], addr)
        entry['max'] = max(entry['max'], addr + size)
        entry['count'] += 1

    def _sp7b0_mem_write_hook(self, uc, access, addr, size, value, ud):
        """Watchpoint: catch writes to the 32-byte region at sp+0x7b0 (SHA-256 input source)."""
        pc = uc.reg_read(UC_ARM64_REG_PC)
        jit_off = pc - JIT_BASE if JIT_BASE <= pc < JIT_BASE + 0x300000 else None
        nmsscr_off = pc - CODE_BASE if CODE_BASE <= pc < CODE_BASE + 0x200000 else None
        loc = f"JIT+{jit_off:#x}" if jit_off is not None else (f"nmsscr+{nmsscr_off:#x}" if nmsscr_off is not None else f"pc={pc:#x}")
        # Show the value being written (up to 16 bytes shown as hex)
        val_hex = (value & ((1 << (size*8)) - 1)).to_bytes(size, 'little').hex() if size <= 16 else f"({size}B)"
        sp_off = addr - uc.reg_read(UC_ARM64_REG_SP)
        cnt = getattr(self, '_sp7b0_write_count', 0) + 1
        self._sp7b0_write_count = cnt
        if cnt <= 200:  # cap output
            print(f"[SP7B0-WRITE #{cnt}] {loc} => [{addr:#x}] (sp+{sp_off:#x}) size={size} val={val_hex}", flush=True)
        # On first non-zero write (cnt==5, i.e. first actual hash output), dump the message buffer
        if cnt == 5:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            try:
                msg_buf = bytes(uc.mem_read(sp + 0x810, 64))
                print(f"[SHA256-R1-MSG] sp+0x810(64): {msg_buf.hex()}", flush=True)
                msg_buf2 = bytes(uc.mem_read(sp + 0x850, 64))
                print(f"[SHA256-R1-MSG] sp+0x850(64): {msg_buf2.hex()}", flush=True)
                # Also dump sp+0x940 (hash state before finalization)
                state = bytes(uc.mem_read(sp + 0x940, 32))
                print(f"[SHA256-R1-STATE] sp+0x940(32): {state.hex()}", flush=True)
                # Also dump the 80-byte concat string ptr
                sso810 = bytes(uc.mem_read(sp + 0x810, 24))
                print(f"[SHA256-R1-SSO810] raw: {sso810.hex()}", flush=True)
                # Dump x22 buffer offset[0] area
                x22 = uc.reg_read(UC_ARM64_REG_X22)
                chunk0 = bytes(uc.mem_read(x22, 80))
                print(f"[SHA256-R1-CHUNK0] x22={x22:#x} data: {chunk0.hex()}", flush=True)
            except Exception as e:
                print(f"[SHA256-R1-MSG] error: {e}", flush=True)
            # Dump heap read tracker results
            self._hashchain_read_tracking = False  # stop tracking
            tracker = getattr(self, '_hashchain_read_tracker', {})
            print(f"[HASHCHAIN-READS] {len(tracker)} heap pages read during hash chain round 1:", flush=True)
            for page in sorted(tracker.keys()):
                e = tracker[page]
                span = e['max'] - e['min']
                print(f"  page {page:#x}: reads={e['count']} range=[{e['min']:#x}..{e['max']:#x}] span={span:#x}", flush=True)

    def _sha256_msg_load_hook(self, uc, addr, size, ud):
        """Instrument inline SHA-256 message load at JIT+0x14f894.
        At this point: x10 = source message ptr (already +0x28 adjusted),
        x8 = loop index (0..0x40), x11 = sp+0x810 (destination).
        Dump the 64-byte message block on first iteration (x8==0)."""
        x8 = uc.reg_read(UC_ARM64_REG_X8)
        if x8 != 0:
            return  # only dump on first iteration
        x10 = uc.reg_read(UC_ARM64_REG_X10)
        x11 = uc.reg_read(UC_ARM64_REG_X11)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        cnt = getattr(self, '_sha256_msg_load_count', 0) + 1
        self._sha256_msg_load_count = cnt
        try:
            msg_data = bytes(uc.mem_read(x10, 0x40))
        except Exception:
            msg_data = b''
        print(f"[SHA256-MSG-LOAD #{cnt}] x10={x10:#x} x11={x11:#x} sp={sp:#x}", flush=True)
        if msg_data:
            for i in range(0, 64, 16):
                print(f"  +{i:02x}: {msg_data[i:i+16].hex()}", flush=True)
        # Also dump the full 40-byte buffer (x10 - 0x28)
        try:
            full_buf = bytes(uc.mem_read(x10 - 0x28, 0x28))
            print(f"  full_buf(-0x28..0): {full_buf.hex()}", flush=True)
        except Exception:
            pass
        # Also dump what's at sp+0x764 (cert token source area) if populated
        try:
            cert_area = bytes(uc.mem_read(sp + 0x764, 24))
            print(f"  sp+0x764: {cert_area.hex()}", flush=True)
        except Exception:
            pass

    def _sha256_hexenc_hook(self, uc, addr, size, ud):
        """Instrument JIT+0x150b64 (bl to hex-encode).
        At this point x0 = sp+0x764, w1 = 0x18 (24 bytes to hex-encode).
        Dump the 24 bytes that become the cert token, plus the full 32-byte
        digest at sp+0x810 area."""
        sp = uc.reg_read(UC_ARM64_REG_SP)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        w1 = uc.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF
        cnt = getattr(self, '_sha256_hexenc_count', 0) + 1
        self._sha256_hexenc_count = cnt
        try:
            token_bytes = bytes(uc.mem_read(x0, max(w1, 24)))
        except Exception:
            token_bytes = b''
        try:
            # sp+0x760 has full 32-byte region (H0..H7)
            full_digest = bytes(uc.mem_read(sp + 0x760, 32))
        except Exception:
            full_digest = b''
        print(f"[SHA256-HEXENC #{cnt}] x0={x0:#x} w1={w1:#x} sp={sp:#x}", flush=True)
        if token_bytes:
            print(f"  token_bytes({len(token_bytes)}): {token_bytes.hex()}", flush=True)
        if full_digest:
            print(f"  sp+0x760(32): {full_digest.hex()}", flush=True)
            # Parse as 8 big-endian words (SHA-256 H0..H7)
            words = [int.from_bytes(full_digest[i:i+4], 'big') for i in range(0, 32, 4)]
            print(f"  H0..H7(BE): {' '.join(f'{w:08X}' for w in words)}", flush=True)
            # Also try little-endian
            words_le = [int.from_bytes(full_digest[i:i+4], 'little') for i in range(0, 32, 4)]
            print(f"  H0..H7(LE): {' '.join(f'{w:08X}' for w in words_le)}", flush=True)

    def _cert_inner_cff_call_hook(self, uc, addr, size, ud):
        """Trace the inner CFF call from cert wrapper (0x1c2180) and its return (0x1c2184).
        Captures session state before/after to see what inner CFF produces."""
        off = addr - JIT_BASE
        if off == 0x1c2180:
            x0 = uc.reg_read(UC_ARM64_REG_X0)  # session/manager ptr
            x1 = uc.reg_read(UC_ARM64_REG_X1)  # w1=8
            x19 = uc.reg_read(UC_ARM64_REG_X19)
            x27 = uc.reg_read(UC_ARM64_REG_X27)
            sp = uc.reg_read(UC_ARM64_REG_SP)
            # Dump session+0x388 (linked list head for inner CFF)
            sess_388 = 0
            if x0 > 0x1000:
                try:
                    sess_388 = struct.unpack("<Q", uc.mem_read(x0 + 0x388, 8))[0]
                except:
                    pass
            # Dump x27+0x210 (SSO string - will be modified by CFF?)
            x27_210 = b""
            if x27 > 0x1000:
                try:
                    x27_210 = bytes(uc.mem_read(x27 + 0x210, 48))
                except:
                    pass
            # Dump session object key areas
            sess_dump = b""
            if x0 > 0x1000:
                try:
                    sess_dump = bytes(uc.mem_read(x0, 64))
                except:
                    pass
            print(f"[INNER-CFF-PRE] bl 0x8a2c4: x0={x0:#x} w1={x1&0xFFFFFFFF} x19={x19:#x} "
                  f"x27={x27:#x} sp={sp:#x}", flush=True)
            print(f"  session+0x388={sess_388:#x} (linked list head)", flush=True)
            print(f"  x27+0x210={x27_210[:24].hex() if x27_210 else '??'}", flush=True)
            print(f"  session[0:64]={sess_dump.hex() if sess_dump else '??'}", flush=True)
            self._inner_cff_pre_x27 = x27
            self._inner_cff_pre_x0 = x0
        elif off == 0x1c2184:
            # Post-return: x0 = return value from inner CFF
            x0_ret = uc.reg_read(UC_ARM64_REG_X0)
            x27 = getattr(self, '_inner_cff_pre_x27', 0)
            sess = getattr(self, '_inner_cff_pre_x0', 0)
            # Check what changed in session
            sess_388 = 0
            if sess > 0x1000:
                try:
                    sess_388 = struct.unpack("<Q", uc.mem_read(sess + 0x388, 8))[0]
                except:
                    pass
            # Check x27+0x210 after
            x27_210_post = b""
            if x27 > 0x1000:
                try:
                    x27_210_post = bytes(uc.mem_read(x27 + 0x210, 48))
                except:
                    pass
            print(f"[INNER-CFF-POST] x0_ret={x0_ret:#x}", flush=True)
            print(f"  session+0x388={sess_388:#x} (linked list head after)", flush=True)
            print(f"  x27+0x210={x27_210_post[:24].hex() if x27_210_post else '??'}", flush=True)

    def _second_cff_caller_hook(self, uc, addr, size, ud):
        if self._live_session_regions_loaded:
            return
        if addr == JIT_SECOND_CFF_CALLER_LOCK:
            iter_no = len(self._second_cff_caller_trace) + 1
            entry = {"iter": iter_no}
            entry["lock"] = self._snapshot_second_cff_state(uc, addr, "lock", iter_no)
            self._second_cff_caller_trace.append(entry)
            self._second_cff_current_iter = entry
            return
        if addr == JIT_SECOND_CFF_CALLER_PRECALL:
            entry = self._second_cff_current_iter
            if entry is None:
                iter_no = len(self._second_cff_caller_trace) + 1
                entry = {"iter": iter_no}
                self._second_cff_caller_trace.append(entry)
                self._second_cff_current_iter = entry
            entry["precall"] = self._snapshot_second_cff_state(uc, addr, "precall", entry["iter"])
            return
        if addr == JIT_SECOND_CFF_CALLER_POSTRET:
            entry = self._second_cff_current_iter
            if entry is None:
                return
            entry["cff_ret"] = uc.reg_read(UC_ARM64_REG_X0)
            return
        if addr in (
            JIT_SECOND_CFF_RESULT_0,
            JIT_SECOND_CFF_RESULT_18,
            JIT_SECOND_CFF_RESULT_20,
            JIT_SECOND_CFF_RESULT_28,
        ):
            entry = self._second_cff_current_iter
            if entry is None:
                return
            key = {
                JIT_SECOND_CFF_RESULT_0: "ret0",
                JIT_SECOND_CFF_RESULT_18: "ret18",
                JIT_SECOND_CFF_RESULT_20: "ret20",
                JIT_SECOND_CFF_RESULT_28: "ret28",
            }[addr]
            entry[key] = uc.reg_read(UC_ARM64_REG_X0)

    def _jit_state_machine_hook(self, uc, addr, size, ud):
        site_names = {
            JIT_SECOND_CFF_RESULT_0: "ret0",
            JIT_SECOND_CFF_RESULT_18: "ret18",
            JIT_SECOND_CFF_RESULT_20: "ret20",
            JIT_SECOND_CFF_RESULT_28: "ret28",
        }
        if addr == JIT_STATE_MACHINE_ENTRY:
            self._jit_state_machine_calls += 1
            lr = uc.reg_read(UC_ARM64_REG_LR)
            idx_before = self._safe_mem_read_u32(uc, JIT_STATE_TABLE_IDX)
            table_ptr = self._safe_mem_read_qword(uc, JIT_STATE_TABLE_PTR)
            current = {
                "call": self._jit_state_machine_calls,
                "iter": None if self._second_cff_current_iter is None else self._second_cff_current_iter["iter"],
                "site": site_names.get(lr, hex(lr)),
                "lr": lr,
                "arg0": uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF,
                "arg1": uc.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF,
                "idx_before": idx_before,
                "table_ptr": table_ptr,
            }
            if table_ptr is not None and idx_before is not None:
                for delta, key in (
                    (0, "slot_cur"),
                    (9, "slot_p9"),
                    (13, "slot_p13"),
                    (15, "slot_p15"),
                ):
                    idx = (idx_before + delta) & 0xF
                    current[key] = self._safe_mem_read_qword(uc, table_ptr + idx * 8)
            if len(self._jit_state_machine_trace) < 4096:
                self._jit_state_machine_trace.append(current)
            self._jit_state_machine_current = current
            return
        if addr == JIT_STATE_MACHINE_RET:
            current = self._jit_state_machine_current
            if current is None:
                return
            current["result"] = uc.reg_read(UC_ARM64_REG_X0)
            current["idx_after"] = self._safe_mem_read_u32(uc, JIT_STATE_TABLE_IDX)
            table_ptr = current.get("table_ptr")
            idx_after = current.get("idx_after")
            if table_ptr is not None and idx_after is not None:
                current["slot_after"] = self._safe_mem_read_qword(uc, table_ptr + ((idx_after & 0xF) * 8))
            self._jit_state_machine_current = None

    def _init_dl_modules(self):
        modules = []
        for name, base, blob in (
            ("nmsscr", CODE_BASE, self.binary_data),
            ("jit", JIT_BASE, self.jit_data),
        ):
            if not blob:
                continue
            phdrs = self._parse_elf_program_headers(blob)
            if phdrs:
                modules.append({
                    "name": name,
                    "base": base,
                    "phdrs": phdrs,
                })
        return modules

    def _parse_elf_program_headers(self, blob):
        if not blob or blob[:4] != b"\x7fELF" or blob[4] != 2:
            return []
        try:
            e_phoff = struct.unpack_from("<Q", blob, 0x20)[0]
            e_phentsize = struct.unpack_from("<H", blob, 0x36)[0]
            e_phnum = struct.unpack_from("<H", blob, 0x38)[0]
        except struct.error:
            return []

        phdrs = []
        for idx in range(e_phnum):
            off = e_phoff + idx * e_phentsize
            try:
                p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                    "<IIQQQQQQ", blob, off
                )
            except struct.error:
                break
            phdrs.append({
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
                "align": p_align,
            })
        return phdrs

    def _synthesize_unwind_fde_lookup(self, uc, data_ptr, target_pc):
        for module in self._dl_modules:
            hit = self._find_fde_for_pc(uc, module, target_pc)
            if hit is None:
                continue
            func_start, fde_addr = hit
            self._safe_mem_write_qword(uc, data_ptr + 0x08, 0)
            self._safe_mem_write_qword(uc, data_ptr + 0x10, 0)
            self._safe_mem_write_qword(uc, data_ptr + 0x18, func_start)
            self._safe_mem_write_qword(uc, data_ptr + 0x20, fde_addr)
            return 1
        return 0

    def _find_fde_for_pc(self, uc, module, target_pc):
        pt_load = 1
        pt_gnu_eh_frame = 0x6474E550

        load_hit = False
        eh_hdr_vaddr = None
        for phdr in module["phdrs"]:
            if phdr["type"] == pt_load:
                start = module["base"] + phdr["vaddr"]
                end = start + phdr["memsz"]
                if start <= target_pc < end:
                    load_hit = True
            elif phdr["type"] == pt_gnu_eh_frame:
                eh_hdr_vaddr = phdr["vaddr"]

        if not load_hit or eh_hdr_vaddr is None:
            return None

        eh_hdr_addr = module["base"] + eh_hdr_vaddr
        try:
            hdr = bytes(uc.mem_read(eh_hdr_addr, 12))
        except Exception:
            return None
        if len(hdr) < 12 or hdr[:4] != b"\x01\x1b\x03\x3b":
            return None

        fde_count = struct.unpack_from("<I", hdr, 8)[0]
        if fde_count == 0:
            return None

        table_addr = eh_hdr_addr + 12

        def read_entry(idx):
            entry = bytes(uc.mem_read(table_addr + idx * 8, 8))
            func_rel, fde_rel = struct.unpack("<ii", entry)
            return eh_hdr_addr + func_rel, eh_hdr_addr + fde_rel

        lo = 0
        hi = fde_count
        while lo < hi:
            mid = (lo + hi) // 2
            func_start, _ = read_entry(mid)
            if target_pc < func_start:
                hi = mid
            else:
                lo = mid + 1

        idx = max(lo - 1, 0)
        func_start, fde_addr = read_entry(idx)
        if target_pc < func_start or fde_addr == 0:
            return None
        return func_start, fde_addr

    def _safe_mem_write_qword(self, uc, addr, value):
        if value is None:
            return
        try:
            uc.mem_write(addr, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))
        except Exception:
            pass

    def _seed_jit_stack_struct(self, uc):
        if self._jit_stack_struct_seeded:
            return
        self._jit_stack_struct_seeded = True

        fp = uc.reg_read(UC_ARM64_REG_X29)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        obj = fp - 0x60
        iterator = fp + 0x570
        cursor = fp - 0x40
        x19 = uc.reg_read(UC_ARM64_REG_X19)
        x22 = uc.reg_read(UC_ARM64_REG_X22)
        x23 = uc.reg_read(UC_ARM64_REG_X23)
        x25 = uc.reg_read(UC_ARM64_REG_X25)
        x27 = uc.reg_read(UC_ARM64_REG_X27)
        x28 = uc.reg_read(UC_ARM64_REG_X28)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        sp_70 = self._safe_mem_read_qword(uc, sp + 0x70)
        canary = self._safe_mem_read_qword(uc, TLS_BASE + 0x28)
        x27_plus_e48 = None if x27 == 0 else x27 + 0xE48

        # Live execution keeps a stack-local struct here; the emulator was
        # incorrectly pointing this slot at MANAGER_BASE instead.
        self._safe_mem_write_qword(uc, sp + 0x60, obj)

        seeds = {
            obj + 0x00: cursor,
            obj + 0x08: canary,
            obj + 0x10: sp_70,
            obj + 0x18: x28,
            obj + 0x20: x22,
            obj + 0x28: x25,
            obj + 0x30: fp + 0x50,
            obj + 0x38: x27_plus_e48,
            obj + 0x40: iterator,
            obj + 0x48: iterator,
            obj + 0x50: x23,
            obj + 0x58: x19,
            obj + 0x60: fp + 0x350,
            obj + 0x68: lr,
            obj + 0x70: 1,
            obj + 0x78: fp + 0x360,
            obj + 0x80: x27_plus_e48,
            obj + 0x90: x27,
            obj + 0x388: x28,
            obj + 0x390: 0xA29,
            obj + 0x398: x28,
            obj + 0x3A0: iterator,
        }
        for addr, value in seeds.items():
            self._safe_mem_write_qword(uc, addr, value)

        self._safe_mem_write_qword(uc, fp - 0x60, cursor)
        self._safe_mem_write_qword(uc, fp - 0x80, iterator)

    def _maybe_delta(self, value, base):
        if value is None or base is None:
            return None
        return value - base

    def _format_delta(self, value):
        if value is None:
            return "?"
        sign = "+" if value >= 0 else "-"
        return f"{sign}0x{abs(value):x}"

    def _format_opt_hex(self, value, width=0):
        if value is None:
            return "?"
        if width:
            return f"0x{value:0{width}x}"
        return f"0x{value:x}"

    def _dump_dispatch_trace(self, limit=32):
        if not self._dispatch_trace:
            return

        print(
            f"  Dispatcher trace: hub_hits={self._dispatch_hub_hits} "
            f"terminal_pc={self._last_pc:#x} entries={len(self._dispatch_trace)}"
        )
        for entry in list(self._dispatch_trace)[-limit:]:
            marker = "*" if entry["pc"] == JIT_DISPATCH_HUB else " "
            print(
                f"  {marker}seq={entry['seq']:>8} insn={entry['insn']:>8} pc={entry['pc']:#x} "
                f"w30={entry['w30']:#010x} w5={entry['w5']:#010x} "
                f"sp={entry['sp']:#x} lr={entry['lr']:#x}"
            )
        self._dump_dispatch_decision_trace(limit=min(limit, 16))
        self._dump_x28_trace(limit=min(limit, 16))

    def _dump_dispatch_decision_trace(self, limit=16):
        live = self.live_jit_stack_snapshot
        if live is not None:
            print(
                "  Live stack ref:"
                f" fp={live['fp']:#x} sp={live['sp']:#x}"
                f" [sp+0x60]={self._format_opt_hex(live['stack_obj_q'])}"
                f" [fp-0x80]={self._format_opt_hex(live['slot_m80_q'])}"
                f"({self._format_delta(live['slot_m80_fp_delta'])})"
                f" [fp-0x60]={self._format_opt_hex(live['slot_m60_q'])}"
                f"({self._format_delta(live['slot_m60_fp_delta'])})"
                f" [obj+0x388]={self._format_opt_hex(live['stack_obj_388_q'])}"
                f" [obj+0x3a0]={self._format_opt_hex(live['stack_obj_3a0_q'])}"
            )

        if not self._dispatch_decision_trace:
            return

        print(f"  Decision trace entries={len(self._dispatch_decision_trace)}")
        for entry in list(self._dispatch_decision_trace)[-limit:]:
            print(
                f"    pc={entry['pc']:#x} fp={entry['fp']:#x}"
                f" x0={entry['x0']:#x} x24={entry['x24']:#x}"
                f" [sp+0x60]={self._format_opt_hex(entry['stack_obj_q'])}"
                f" [fp-0x80]={self._format_opt_hex(entry['slot_m80_q'])}"
                f"({self._format_delta(entry['slot_m80_fp_delta'])})"
                f" [fp-0x60]={self._format_opt_hex(entry['slot_m60_q'])}"
                f"({self._format_delta(entry['slot_m60_fp_delta'])})"
                f" [obj+0x388]={self._format_opt_hex(entry['stack_obj_388_q'])}"
                f" [obj+0x3a0]={self._format_opt_hex(entry['stack_obj_3a0_q'])}"
                f" x28={self._format_opt_hex(entry['x28'])}"
                f" x28-fp={self._format_delta(entry['x28_fp_delta'])}"
                f" x28-sp={self._format_delta(entry['x28_sp_delta'])}"
                f" w80={self._format_opt_hex(entry['slot_m80_w'], 8)}"
                f" w60={self._format_opt_hex(entry['slot_m60_w'], 8)}"
            )

    def _dump_x28_trace(self, limit=16):
        if not self._x28_trace:
            return

        print(f"  x28 trace entries={len(self._x28_trace)}")
        for entry in list(self._x28_trace)[-limit:]:
            print(
                f"    pc={entry['pc']:#x}"
                f" x28={self._format_opt_hex(entry['x28'])}"
                f" fp={self._format_opt_hex(entry['fp'])}"
                f" sp={self._format_opt_hex(entry['sp'])}"
                f" x28-fp={self._format_delta(entry['x28_fp_delta'])}"
                f" x28-sp={self._format_delta(entry['x28_sp_delta'])}"
            )

    def _inner_cff_fix_hook(self, uc, addr, size, ud):
        """Observation hook at inner CFF STR x0, [sp, #0x60].
        Records emulator session address for potential future substitution.
        NOTE: patching [sp+0x60] here breaks CFF pointer traversal.
        The real address leakage is via %08X sprintf args (see SPRINTF-FF-S1)."""
        if addr != JIT_INNER_CFF_STR:
            return
        if not hasattr(self, '_cff_obs_count'):
            self._cff_obs_count = 0
        self._cff_obs_count += 1
        if self._cff_obs_count <= 3:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            print(f"[CFF-OBS] STR x0,[sp,#0x60]: x0={x0:#x} (#{self._cff_obs_count})")

    def _cff_iter_loop_hook(self, uc, addr, size, ud):
        """Fix the CFF iteration loop at 0x8ba5c that compares [fp-0x80]+8 with [fp-0x60].
        When [fp-0x60] is invalid (not a stack address), set it to [fp-0x80]+8 so the
        loop iterates once and exits normally via the CFF dispatch tree."""
        if addr != JIT_CFF_ITER_LOOP:
            return
        fp = uc.reg_read(UC_ARM64_REG_X29)
        try:
            cur_ptr = struct.unpack("<Q", uc.mem_read(fp - 0x80, 8))[0]
            end_ptr = struct.unpack("<Q", uc.mem_read(fp - 0x60, 8))[0]
        except:
            return
        # Check if end_ptr is a valid stack address (near cur_ptr)
        if STACK_BASE <= end_ptr < STACK_BASE + STACK_SIZE:
            return  # looks valid, don't patch
        if end_ptr == 0:
            return  # zero might be intentional
        # Bad end pointer — patch to cur_ptr+8 so loop exits after one iteration
        fixed = cur_ptr + 8
        uc.mem_write(fp - 0x60, struct.pack("<Q", fixed))
        if not hasattr(self, '_cff_iter_fix_count'):
            self._cff_iter_fix_count = 0
        self._cff_iter_fix_count += 1
        if self._cff_iter_fix_count <= 5:
            print(f"[CFF-ITER-FIX #{self._cff_iter_fix_count}] fp={fp:#x} "
                  f"cur={cur_ptr:#x} bad_end={end_ptr:#x} → fixed={fixed:#x}", flush=True)

    def _cff_epilogue_ret_hook(self, uc, addr, size, ud):
        """Fix corrupted LR at the inner CFF function's RET instruction.
        The dispatch hub's `mov w30, w5` clobbers LR with CFF state values,
        and CFF handlers store the corrupted x30 back to [sp+0x198].
        When the epilogue does `ldp x29, x30, [sp, #0x190]` it loads garbage LR."""
        if addr != JIT_CFF_EPILOGUE_RET:
            return
        if self._live_session_regions_loaded:
            return
        lr = uc.reg_read(UC_ARM64_REG_LR)
        # Check if LR looks valid
        in_jit = JIT_BASE <= lr < JIT_BASE + JIT_SIZE
        in_nmsscr = 0x5ee10 <= lr < 0x29c800
        if in_jit or in_nmsscr:
            # Track natural CFF return values
            if hasattr(self, '_cff_natural_returns') and len(self._cff_natural_returns) < 20:
                w0 = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
                self._cff_natural_returns.append((w0, lr))
            return  # LR looks OK
        # LR is corrupted — use cached return address
        if self._cff_current_return_lr is not None:
            fixed_lr = self._cff_current_return_lr
            uc.reg_write(UC_ARM64_REG_LR, fixed_lr)
            if not hasattr(self, '_cff_lr_fix_count'):
                self._cff_lr_fix_count = 0
            self._cff_lr_fix_count += 1
            if self._cff_lr_fix_count <= 10:
                print(f"[CFF-LR-FIX #{self._cff_lr_fix_count}] bad_lr={lr:#x} → {fixed_lr:#x}", flush=True)
            self._cff_current_return_lr = None

    def _jit_cff_bridge_hook(self, uc, addr, size, ud):
        post_pc = JIT_CFF_BRIDGE_SITES.get(addr)
        if post_pc is not None:
            if self._live_session_regions_loaded:
                if not getattr(self, "_cff_bridge_live_passthru_logged", False):
                    self._cff_bridge_live_passthru_logged = True
                    print(
                        f"[CFF-BRIDGE-LIVE] preserving natural args at {addr:#x}",
                        flush=True,
                    )
                return
            orig_x2 = uc.reg_read(UC_ARM64_REG_X2)
            orig_x22 = uc.reg_read(UC_ARM64_REG_X22)
            live_x22 = self._safe_mem_read_u32(uc, orig_x2 + 0x18)
            if live_x22 is None:
                live_x22 = LIVE_CFF_CALLBACK_X22_FALLBACK
            self._cff_hub_count = 0
            saved_stack = self._jit_cff_bridge_saved_x22.setdefault(post_pc, [])
            saved_stack.append(orig_x22)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_X1, LIVE_CFF_CALLBACK_X1)
            uc.reg_write(UC_ARM64_REG_X2, LIVE_CFF_CALLBACK_X2)
            uc.reg_write(UC_ARM64_REG_X22, live_x22)
            self.log(
                f"JIT-CFF-BRIDGE call={addr:#x} patched x0=0x0 x1={LIVE_CFF_CALLBACK_X1:#x} "
                f"x2={LIVE_CFF_CALLBACK_X2:#x} x22={live_x22:#x} "
                f"(saved_x22={orig_x22:#x}, orig_x2={orig_x2:#x})"
            )
            return
        saved_stack = self._jit_cff_bridge_saved_x22.get(addr)
        if saved_stack:
            uc.reg_write(UC_ARM64_REG_X22, saved_stack.pop())
            if not saved_stack:
                del self._jit_cff_bridge_saved_x22[addr]

    def _jit_inner_entry_hook(self, uc, addr, size, ud):
        if addr != JIT_INNER_CFF_ENTRY:
            return
        self._jit_inner_entry_logged = True
        self._cff_entry_total += 1
        # Reset CFF hub count on every entry — previously only reset in bridge hook,
        # causing direct calls from 0x784E0 to carry stale counts and skip immediately
        self._cff_hub_count = 0
        self._cff_same_count = 0
        self._cff_last_state = None

        # Skip integrity-check CFF calls (x1=0x1d) that try to read /proc/pid/maps.
        # These stall forever in the emulator because procfs isn't available, and the
        # stall-recovery corrupts the outer CFF state causing cascading infinite loops.
        x1_val = uc.reg_read(UC_ARM64_REG_X1)
        if x1_val == 0x1d:
            lr = uc.reg_read(UC_ARM64_REG_LR)
            self._cff_skip_total += 1
            print(f"[CFF-SKIP-INTEGRITY #{self._cff_skip_total}] x1=0x1d lr={lr:#x} → return 0 (clean)", flush=True)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return
        lr = uc.reg_read(UC_ARM64_REG_LR)
        lr_key = lr & 0xFFFFFFFF
        self._cff_lr_hist[lr_key] = self._cff_lr_hist.get(lr_key, 0) + 1
        if self._cff_entry_total <= 5:
            sp_pre = uc.reg_read(UC_ARM64_REG_SP)
            fp_pre = uc.reg_read(UC_ARM64_REG_X29)
            x0_pre = uc.reg_read(UC_ARM64_REG_X0)
            x1_pre = uc.reg_read(UC_ARM64_REG_X1)
            x2_pre = uc.reg_read(UC_ARM64_REG_X2)
            x3_pre = uc.reg_read(UC_ARM64_REG_X3)
            x4_pre = uc.reg_read(UC_ARM64_REG_X4)
            x22_pre = uc.reg_read(UC_ARM64_REG_X22)
            # Read 0x7847C's saved LR from [fp+8] (who calls 0x7847C)
            caller_lr = 0
            try:
                caller_lr = struct.unpack("<Q", uc.mem_read(fp_pre + 8, 8))[0]
            except:
                pass
            # Read x22 string if it's a pointer
            x22_str = b""
            if x22_pre > 0x1000:
                try:
                    x22_str = bytes(uc.mem_read(x22_pre, 64)).split(b'\x00')[0]
                except:
                    pass
            print(f"[CFF-ENTRY #{self._cff_entry_total}] lr={lr:#x} x0={x0_pre:#x} x1={x1_pre:#x} "
                  f"x2={x2_pre:#x} x3={x3_pre:#x} x4={x4_pre:#x} x22={x22_pre:#x} "
                  f"caller_of_7847c={caller_lr:#x} x22_str={x22_str}", flush=True)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        fp = uc.reg_read(UC_ARM64_REG_X29)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x22 = uc.reg_read(UC_ARM64_REG_X22)
        slot_68 = self._safe_mem_read_qword(uc, sp + 0x68)
        slot_c8 = self._safe_mem_read_qword(uc, sp + 0xC8)
        self._jit_cff_frame_ctx[sp - 0x1A0] = {
            "caller_sp": sp,
            "caller_fp": fp,
            "return_lr": lr,
        }
        # Cache for CFF stall skip — avoids stack-read of corrupted LR
        self._cff_current_return_lr = lr
        self._cff_current_caller_sp = sp
        self._cff_current_caller_fp = fp
        self._jit_inner_entry_snapshot = {
            "pc": addr,
            "x0": x0,
            "x1": x1,
            "x2": x2,
            "x22": x22,
            "lr": lr,
            "sp": sp,
            "fp": fp,
            "slot_68": slot_68,
            "slot_c8": slot_c8,
        }
        self.log(
            f"JIT-CFF-ENTRY pc={addr:#x} x0={x0:#x} x1={x1:#x} x2={x2:#x}"
            f" x22={x22:#x} lr={lr:#x} sp={sp:#x} fp={fp:#x}"
            f" [sp+0x68]={self._format_opt_hex(slot_68)}"
            f" [sp+0xc8]={self._format_opt_hex(slot_c8)}"
        )

    def _fx_flow_probe_hook(self, uc, addr, size, ud):
        """Trace key branch points in the fx function."""
        off = addr - JIT_BASE
        pending = getattr(self, '_cert_wrapper_block_restore_pending', None)
        if pending is not None and addr == pending.get('lr'):
            self._restore_cert_wrapper_caller_frame(
                uc,
                pending,
                pending.get('ret_w0', 1),
                rewrite_pc=False,
                skip_regs={UC_ARM64_REG_X27},
            )
            print(
                f"[CERT-SKIP-2ND-APPLY #{pending['call_count']}] "
                f"lr={pending['lr']:#x} sp={pending['sp']:#x} fp={pending['fp']:#x}",
                flush=True,
            )
            self._cert_wrapper_block_restore_pending = None
        if addr == JIT_CERT_POST_CFF_HUB:
            w26 = uc.reg_read(UC_ARM64_REG_X26) & 0xFFFFFFFF
            self._cert_post_cff_last_w26 = w26
            self._cert_post_cff_w26_trace.append((self._insn_count, addr, w26))
            if self._maybe_route_cert_post_cff_ce75c(uc, w26):
                return
        elif addr == JIT_CERT_CFF_PREHUB:
            self._cert_cff_hub1_last_state = uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF
        elif addr == JIT_CERT_POST_CFF_CE75C_PREP:
            self._maybe_seed_cert_ce75c_output(uc)
        elif addr == JIT_CERT_POST_CFF_CE75C_CALL:
            self._cert_post_cff_1c3374_hits += 1
            self._cert_post_cff_1c3374_state = self._cert_post_cff_last_w26
        elif off in (0x108d1c, 0x165690):
            self._begin_fmt_call(off)
        elif off in (0x155ba4, 0x155bb0):
            self._install_fmt_vararg_watch(uc)
        elif off == 0x155c6c:
            # ce75c(0x8e) — format string for the printf-style formatter.
            # Must return %08X*6 so the gate at 0x155c9c passes.
            w0 = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
            if w0 == 0x8E:
                dest = uc.reg_read(UC_ARM64_REG_X8)
                self._write_sso(uc, dest, CERT_CE75C_FMT_8E, force_long=True)
                uc.reg_write(UC_ARM64_REG_X0, dest)
                uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x155c70)
                cnt = getattr(self, "_ce75c_8e_synth_hits", 0) + 1
                self._ce75c_8e_synth_hits = cnt
                if cnt <= 2:
                    print(
                        f"[CE75C-8E-SYNTH #{cnt}] dest={dest:#x} fmt={CERT_CE75C_FMT_8E!r}",
                        flush=True,
                    )
                return
        elif off == 0x1565ac:
            # ce75c(0x8d) — stage 2 format string. Returns "%s" to format the
            # pre-computed cert hex string at descriptor+0xa0.
            w0 = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
            if w0 == 0x8D:
                sp = uc.reg_read(UC_ARM64_REG_SP)
                dest_addr = sp + 0x9c0  # x8 = sp+0x9c0 (set at 0x1565a0)
                self._write_sso(uc, dest_addr, CERT_CE75C_FMT_8D)
                uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x1565b0)
                cnt = getattr(self, "_ce75c_8d_synth_hits", 0) + 1
                self._ce75c_8d_synth_hits = cnt
                # Dump the stage 2 arg (descriptor+0xa0 SSO) for diagnostics
                try:
                    x12 = struct.unpack("<Q", uc.mem_read(sp + 0x278, 8))[0]  # saved descriptor+0xa0
                    sso_raw = bytes(uc.mem_read(x12, 24))
                    tag = sso_raw[0]
                    if tag & 1:  # long string
                        size = struct.unpack("<Q", sso_raw[8:16])[0]
                        ptr = struct.unpack("<Q", sso_raw[16:24])[0]
                        try:
                            data = bytes(uc.mem_read(ptr, min(size, 64)))
                            desc_str = data.decode('ascii', errors='replace')
                        except:
                            desc_str = f"PTR={ptr:#x},SZ={size}"
                    else:
                        slen = tag >> 1
                        desc_str = sso_raw[1:1+slen].decode('ascii', errors='replace')
                    print(f"[CE75C-8D-SYNTH #{cnt}] fmt='%s' desc+0xa0='{desc_str}'", flush=True)
                except Exception as e:
                    print(f"[CE75C-8D-SYNTH #{cnt}] fmt='%s' desc+0xa0=ERR({e})", flush=True)
                return
        # ---- SPRINTF FAST-FORWARD ----
        # Stage 1: intercept at 0x155d60 (b 0x156548, format loop entry)
        # Registers: x20=fmt_ptr, x25=sp+0x8b0(args), x22=sp+0x770(out)
        elif off == 0x155d60:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            x20 = uc.reg_read(UC_ARM64_REG_X20)
            x25 = uc.reg_read(UC_ARM64_REG_X25)
            x22 = uc.reg_read(UC_ARM64_REG_X22)
            try:
                fmt = self._read_c_string(uc, x20, 128).decode('ascii', errors='replace')
            except:
                fmt = ""
            if fmt:
                result = self._sprintf_fast(uc, fmt, x25)
                if result is not None:
                    uc.mem_write(x22, result + b'\x00')
                    uc.reg_write(UC_ARM64_REG_X22, x22 + len(result))
                    uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x15657c)
                    cnt = getattr(self, "_sprintf_ff_stage1_hits", 0) + 1
                    self._sprintf_ff_stage1_hits = cnt
                    # --- S1#1 stack residue fix ---
                    # Patch the sprintf OUTPUT (x22 buffer) rather than the args
                    # buffer (x25) to avoid corrupting CFF state on the stack.
                    # --- Device S1 output overrides ---
                    # All three S1 sprintf calls must match device values exactly.
                    # S1#2 and S1#3 contain address-dependent values (stack/heap/JIT
                    # pointers) that differ between emulator and device.
                    # Load S1 overrides from device capture if available
                    _device_s1 = {
                        1: b'0000000100000001000000000000000000000000400300CC',
                    }
                    # Dynamically load S1#2/#3 from device capture
                    dcc_s1 = getattr(self, '_device_s1_overrides', {})
                    _device_s1.update(dcc_s1)
                    if cnt in _device_s1:
                        device_val = _device_s1[cnt]
                        if result != device_val:
                            uc.mem_write(x22, device_val + b'\x00')
                            result = device_val
                            print(f"[S1-OUTPUT-FIX] overwrote S1#{cnt} output with device values", flush=True)
                    if cnt <= 5:
                        # Dump the 6 uint32 args being formatted (8-byte slots)
                        try:
                            args_raw = bytes(uc.mem_read(x25, 48))
                            args_u32 = [struct.unpack("<I", args_raw[i*8:i*8+4])[0] for i in range(6)]
                            args_hex = ''.join(f'{v:08X}' for v in args_u32)
                            # Also dump raw 48 bytes for full picture
                            raw_hex = args_raw.hex()
                        except:
                            args_hex = "READ_ERROR"
                            raw_hex = ""
                        print(f"[SPRINTF-FF-S1 #{cnt}] fmt='{fmt}' -> '{result.decode('ascii','replace')}' "
                              f"len={len(result)} args=[{args_hex}]", flush=True)
                        if raw_hex:
                            print(f"[SPRINTF-FF-S1 #{cnt}] x25={x25:#x} raw48={raw_hex}", flush=True)
                        # Dump S1 buffer write trace for this call
                        s1_writes = getattr(self, '_s1_buf_writes', [])
                        if s1_writes and cnt <= 3:
                            # Filter writes to actual x25 buffer region [x25, x25+0x30)
                            relevant = [(off, a, sz, v) for off, a, sz, v in s1_writes
                                        if x25 <= a < x25 + 0x30]
                            print(f"[S1-WRITE-TRACE #{cnt}] total_writes={len(s1_writes)} "
                                  f"relevant_to_x25={len(relevant)}", flush=True)
                            for off, a, sz, v in relevant:
                                slot = (a - x25) // 8
                                slot_off = (a - x25) % 8
                                print(f"  [S1-WR] JIT+{off:#x} -> [{a:#x}] "
                                      f"slot{slot}+{slot_off} sz={sz} val={v:#x}", flush=True)
                            if cnt == 1:
                                # Dump ALL writes to see full picture
                                print(f"[S1-ALL-WRITES] dumping all {len(s1_writes)} writes:", flush=True)
                                for off, a, sz, v in s1_writes:
                                    delta = a - x25
                                    print(f"  [S1-ALL] JIT+{off:#x} -> [{a:#x}] "
                                          f"x25{delta:+d} sz={sz} val={v:#x}", flush=True)
                            # Clear for next S1 call
                            self._s1_buf_writes = []
                    return
        # Stage 2: intercept at 0x1566dc (inline format loop for stage 2)
        # Registers: x24=fmt_ptr, x22=sp+0x570(out), args at sp+0x8b0
        elif off == 0x1566dc:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            x24 = uc.reg_read(UC_ARM64_REG_X24)
            x22 = uc.reg_read(UC_ARM64_REG_X22)
            try:
                fmt = self._read_c_string(uc, x24, 128).decode('ascii', errors='replace')
            except:
                fmt = ""
            if fmt:
                arg_ptr = sp + 0x8b0
                result = self._sprintf_fast(uc, fmt, arg_ptr)
                if result is not None:
                    uc.mem_write(x22, result + b'\x00')
                    uc.reg_write(UC_ARM64_REG_X22, x22 + len(result))
                    uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x157008)
                    cnt = getattr(self, "_sprintf_ff_stage2_hits", 0) + 1
                    self._sprintf_ff_stage2_hits = cnt
                    if cnt <= 5:
                        try:
                            args_raw = bytes(uc.mem_read(arg_ptr, 48))
                            args_u32 = [struct.unpack("<I", args_raw[i:i+4])[0] for i in range(0, 48, 4)]
                            args_hex = ' '.join(f'{v:08X}' for v in args_u32[:6])
                        except:
                            args_hex = "READ_ERROR"
                        print(f"[SPRINTF-FF-S2 #{cnt}] fmt='{fmt}' -> '{result.decode('ascii','replace')}' "
                              f"len={len(result)} args=[{args_hex}]", flush=True)
                    return
        # --- Filter diagnostic for JIT+0x177290 collection loop ---
        if off == 0x6af14:
            # Inside filter 0x6af04: ldr w8, [x19, #0x100]
            x19v = uc.reg_read(UC_ARM64_REG_X19)
            try:
                field_100 = struct.unpack("<I", uc.mem_read(x19v + 0x100, 4))[0]
                field_104 = struct.unpack("<I", uc.mem_read(x19v + 0x104, 4))[0]
                field_118 = struct.unpack("<B", uc.mem_read(x19v + 0x118, 1))[0]
                head = self._dump_mem_hex(uc, x19v, 0x20)
            except Exception as e:
                field_100 = field_104 = field_118 = 0
                head = f"ERR({e})"
            print(f"[FILTER-6af04] x19={x19v:#x} [+0x100]={field_100:#x} [+0x104]={field_104:#x} [+0x118]={field_118:#x} head={head}", flush=True)
        elif off == 0x177654:
            # Loop entry: x21=current element, x27=collection base
            x21v = uc.reg_read(UC_ARM64_REG_X21)
            x27v = uc.reg_read(UC_ARM64_REG_X27)
            try:
                col_start = struct.unpack("<Q", uc.mem_read(x27v + 0x10, 8))[0]
                col_end = struct.unpack("<Q", uc.mem_read(x27v + 0x18, 8))[0]
                n_elems = (col_end - col_start) // 0x140 if col_end > col_start else 0
            except Exception:
                col_start = col_end = n_elems = 0
            idx = (x21v - col_start) // 0x140 if col_start and x21v >= col_start else -1
            print(f"[LOOP-177654] x21={x21v:#x} idx={idx} col=[{col_start:#x}..{col_end:#x}] n={n_elems}", flush=True)
        elif off == 0x177664:
            # After filter: tbz w0, #0 → skip if bit0=0
            w0 = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
            x21v = uc.reg_read(UC_ARM64_REG_X21)
            sp = uc.reg_read(UC_ARM64_REG_SP)
            x21_resolved = self._resolve_mem_addr(uc, x21v)
            try:
                field_100 = struct.unpack("<I", uc.mem_read(x21_resolved + 0x100, 4))[0]
                field_104 = struct.unpack("<I", uc.mem_read(x21_resolved + 0x104, 4))[0]
                field_118 = struct.unpack("<B", uc.mem_read(x21_resolved + 0x118, 1))[0]
                src_head = self._dump_mem_hex(uc, x21_resolved, 0x20)
            except Exception:
                field_100 = field_104 = field_118 = 0
                src_head = "ERR"
            raw_buf = self._read_c_string(uc, sp + 0x198, 0x40)
            raw_hex = self._dump_mem_hex(uc, sp + 0x198, 0x40)
            print(f"[FILTER-RET] w0={w0:#x} x21={x21v:#x} pass={bool(w0 & 1)}", flush=True)
            print(
                f"[PROD-6AFE8] x21={x21v:#x}->{x21_resolved:#x} "
                f"[+0x100]={field_100:#x} [+0x104]={field_104:#x} [+0x118]={field_118:#x} "
                f"src_head={src_head} sp+0x198={raw_hex} raw_buf={raw_buf!r}",
                flush=True,
            )
            # The source path leaves the decrypted temp buffer sized to the
            # aligned block length (+0x104), while the compare path rebuilds a
            # canonical string using the logical record length (+0x100). Clamp
            # the temp buffer here so the immediate strlen/SSO builder sees the
            # logical text instead of padded tail bytes.
            if (w0 & 1) and 0 < field_100 <= field_104 <= 0x400:
                zero_end = min(field_104 + 1, 0x400)
                zero_len = zero_end - field_100
                if zero_len > 0:
                    try:
                        uc.mem_write(sp + 0x198 + field_100, b"\x00" * zero_len)
                        if not hasattr(self, "_prod_trim_count"):
                            self._prod_trim_count = 0
                        self._prod_trim_count += 1
                        if self._prod_trim_count <= 12:
                            trimmed = self._read_c_string(uc, sp + 0x198, 0x40)
                            print(
                                f"[PROD-TRIM #{self._prod_trim_count}] "
                                f"logical={field_100:#x} block={field_104:#x} trimmed={trimmed!r}",
                                flush=True,
                            )
                    except Exception:
                        pass
        elif off == 0x177670:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            raw_len = uc.reg_read(UC_ARM64_REG_X0)
            preview_len = min(max(int(raw_len) + 8, 0x20), 0x40)
            raw_buf = self._read_c_string(uc, sp + 0x198, preview_len)
            raw_hex = self._dump_mem_hex(uc, sp + 0x198, preview_len)
            print(
                f"[PROD-55160] len={raw_len:#x} sp+0x198={raw_hex} raw_buf={raw_buf!r}",
                flush=True,
            )
        elif off == 0x177680:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            slot28 = self._describe_sso_slot(uc, sp + 0x28)
            raw_hex = self._dump_mem_hex(uc, sp + 0x198, 0x40)
            print(
                f"[PROD-6BE48] sp+0x28={slot28} sp+0x198={raw_hex}",
                flush=True,
            )
        elif off == 0x17768c:
            # Inside loop body: ldrb w8, [sp, #0x40] after processing
            sp = uc.reg_read(UC_ARM64_REG_SP)
            try:
                flag40 = struct.unpack("<B", uc.mem_read(sp + 0x40, 1))[0]
                sp58_head = self._dump_mem_hex(uc, sp + 0x58, 0x18)
            except Exception as e:
                flag40 = 0; sp58_head = f"ERR({e})"
            x21v = uc.reg_read(UC_ARM64_REG_X21)
            print(f"[LOOP-BODY-FLAG] x21={x21v:#x} [sp+0x40]={flag40:#x} [sp+0x58]={sp58_head}", flush=True)
        elif off == 0x1776b4:
            # After flag check: about to call 0x73ec4
            sp = uc.reg_read(UC_ARM64_REG_SP)
            try:
                sp40 = self._dump_mem_hex(uc, sp + 0x40, 0x20)
            except Exception as e:
                sp40 = f"ERR({e})"
            print(f"[LOOP-POST-FLAG] sp+0x40={sp40}", flush=True)
        elif off == 0x1776c0:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            try:
                sp40 = self._dump_mem_hex(uc, sp + 0x40, 0x30)
                slot58 = self._describe_sso_slot(uc, sp + 0x58)
                slot50 = struct.unpack("<Q", uc.mem_read(sp + 0x50, 8))[0]
                x28v = uc.reg_read(UC_ARM64_REG_X28)
                x28s = self._read_c_string(uc, x28v, 0x40)
            except Exception as e:
                sp40 = f"ERR({e})"
                slot58 = f"ERR({e})"
                slot50 = 0
                x28v = 0
                x28s = b""
            print(
                f"[LOOP-POST-73EC4] sp+0x40={sp40} slot58={slot58} "
                f"slot50={slot50:#x} x28={x28v:#x} x28_cstr={x28s!r}",
                flush=True,
            )
        elif off == 0x6b6b4:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            try:
                field_100 = struct.unpack("<I", uc.mem_read(x0v + 0x100, 4))[0] if x0v > 0x1000 else 0
                field_104 = struct.unpack("<I", uc.mem_read(x0v + 0x104, 4))[0] if x0v > 0x1000 else 0
                field_118 = struct.unpack("<B", uc.mem_read(x0v + 0x118, 1))[0] if x0v > 0x1000 else 0
            except Exception:
                field_100 = field_104 = field_118 = 0
            x1_preview = self._read_c_string(uc, x1v, 0x40)
            self._6b6b4_last_cmp = None
            self._6b6b4_last_len = None
            # Track all compare record logical lengths
            if not hasattr(self, '_compare_record_lens'):
                self._compare_record_lens = []
            self._compare_record_lens.append(field_100)
            # Also read x1 length (needle string length via SSO)
            needle_len = 0
            try:
                # std::string: if capacity < 23, inline; [x1+0x8]=length (SSO)
                # or pointer-based: [x1]=ptr, [x1+8]=len
                raw_cap = struct.unpack("<Q", uc.mem_read(x1v + 0x10, 8))[0]
                raw_len = struct.unpack("<Q", uc.mem_read(x1v + 0x8, 8))[0]
                if raw_cap < 23:
                    needle_len = raw_len  # SSO length
                else:
                    needle_len = raw_len
            except Exception:
                pass
            print(
                f"[6B6B4-ENTRY] x0={x0v:#x} x1={x1v:#x} "
                f"[x0+0x100]={field_100:#x} [x0+0x104]={field_104:#x} [x0+0x118]={field_118:#x} "
                f"x1_preview={x1_preview!r} needle_sso_len={needle_len}",
                flush=True,
            )
        elif off == 0x6b6f8:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            print(f"[6B6B4-CALL-6AE6C] x0={x0v:#x}", flush=True)
        elif off == 0x6b700:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            s = self._read_c_string(uc, x0v, 0x40)
            print(f"[6B6B4-RET-6AE6C] x0={x0v:#x} s={s!r}", flush=True)
        elif off == 0x6b738:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x20v = uc.reg_read(UC_ARM64_REG_X20)
            rec_n = uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF
            needle_n = uc.reg_read(UC_ARM64_REG_X10) & 0xFFFFFFFF
            record = self._read_c_string(uc, x0v, 0x40)
            needle = self._read_c_string(uc, x20v, 0x40)
            self._6b6b4_last_len = {
                "record_n": rec_n,
                "needle_n": needle_n,
                "record": record,
                "needle": needle,
            }
            print(
                f"[6B6B4-LEN] rec_n={rec_n} needle_n={needle_n} "
                f"record={record!r} needle={needle!r}",
                flush=True,
            )
        elif off == 0x6b780:
            idx = uc.reg_read(UC_ARM64_REG_X9)
            lhs = uc.reg_read(UC_ARM64_REG_X10) & 0xFF
            rhs = uc.reg_read(UC_ARM64_REG_X11) & 0xFF
            self._6b6b4_last_cmp = {
                "idx": idx,
                "lhs": lhs,
                "rhs": rhs,
            }
        elif off == 0x6b79c:
            detail = ""
            if self._6b6b4_last_len and self._6b6b4_last_len["record_n"] != self._6b6b4_last_len["needle_n"]:
                rec_n = self._6b6b4_last_len["record_n"]
                needle_n = self._6b6b4_last_len["needle_n"]
                detail = (
                    f" len-mismatch rec_n={rec_n} needle_n={needle_n} "
                    f"record={self._6b6b4_last_len['record']!r} "
                    f"needle={self._6b6b4_last_len['needle']!r}"
                )
            elif self._6b6b4_last_cmp:
                detail = (
                    f" byte-mismatch idx={self._6b6b4_last_cmp['idx']} "
                    f"lhs={self._6b6b4_last_cmp['lhs']:#x} "
                    f"rhs={self._6b6b4_last_cmp['rhs']:#x}"
                )
            print(f"[6B6B4-NOMATCH]{detail}", flush=True)
        elif off == 0x6b794:
            print("[6B6B4-MATCH]", flush=True)
        elif off == 0x6b7b8:
            w0 = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
            print(f"[6B6B4-RET] w0={w0:#x}", flush=True)
        elif off == 0x6ae6c:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            try:
                field_100 = struct.unpack("<I", uc.mem_read(x0v + 0x100, 4))[0] if x0v > 0x1000 else 0
                field_118 = struct.unpack("<B", uc.mem_read(x0v + 0x118, 1))[0] if x0v > 0x1000 else 0
            except Exception:
                field_100 = field_118 = 0
            print(f"[6AE6C-ENTRY] x0={x0v:#x} [x0+0x100]={field_100:#x} [x0+0x118]={field_118:#x}", flush=True)
        elif off == 0x6aec8:
            x19v = uc.reg_read(UC_ARM64_REG_X19)
            try:
                field_100 = struct.unpack("<I", uc.mem_read(x19v + 0x100, 4))[0] if x19v > 0x1000 else 0
                field_104 = struct.unpack("<I", uc.mem_read(x19v + 0x104, 4))[0] if x19v > 0x1000 else 0
                field_118 = struct.unpack("<B", uc.mem_read(x19v + 0x118, 1))[0] if x19v > 0x1000 else 0
                aux108 = struct.unpack("<Q", uc.mem_read(x19v + 0x108, 8))[0] if x19v > 0x1000 else 0
                aux110 = struct.unpack("<Q", uc.mem_read(x19v + 0x110, 8))[0] if x19v > 0x1000 else 0
            except Exception:
                field_100 = field_104 = field_118 = 0
                aux108 = aux110 = 0
            data = self._read_c_string(uc, x19v, 0x40)
            print(
                f"[6AE6C-DECODED] x19={x19v:#x} len={field_100:#x} cap={field_104:#x} "
                f"dirty={field_118:#x} aux108={aux108:#x} aux110={aux110:#x} data={data!r}",
                flush=True,
            )
        elif off == 0x6aef8:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            s = self._read_c_string(uc, x0v, 0x40)
            print(f"[6AE6C-RET] x0={x0v:#x} s={s!r}", flush=True)
        elif off == 0x177754:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            x20v = uc.reg_read(UC_ARM64_REG_X20)
            try:
                vec = self._dump_mem_hex(uc, sp + 0x58, 0x20)
                slot50 = struct.unpack("<Q", uc.mem_read(sp + 0x50, 8))[0]
            except Exception as e:
                vec = f"ERR({e})"
                slot50 = 0
            print(f"[LOOP-ASSIGN] x20={x20v:#x} sp+0x58={vec} [sp+0x50]={slot50:#x}", flush=True)
        elif off == 0x177770:
            x23v = uc.reg_read(UC_ARM64_REG_X23)
            x20v = uc.reg_read(UC_ARM64_REG_X20)
            print(f"[LOOP-COPY-OUT] x23={x23v:#x} x20={x20v:#x}", flush=True)
        elif off == 0x1777d4:
            x21v = uc.reg_read(UC_ARM64_REG_X21)
            x27v = uc.reg_read(UC_ARM64_REG_X27)
            try:
                col_end = struct.unpack("<Q", uc.mem_read(x27v + 0x18, 8))[0]
            except Exception:
                col_end = 0
            print(f"[LOOP-NEXT] x21={x21v:#x} col_end={col_end:#x}", flush=True)
        # --- CFF 0x162628 state machine trace ---
        if off == 0x162628:
            w9 = uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF
            if not hasattr(self, '_cff162628_trace'):
                self._cff162628_trace = []
            self._cff162628_trace.append(w9)
            if len(self._cff162628_trace) <= 5:
                sp = uc.reg_read(UC_ARM64_REG_SP)
                w4 = uc.reg_read(UC_ARM64_REG_X4) & 0xFFFFFFFF
                w3 = uc.reg_read(UC_ARM64_REG_X3) & 0xFFFFFFFF
                w26 = uc.reg_read(UC_ARM64_REG_X26) & 0xFFFFFFFF
                w27 = uc.reg_read(UC_ARM64_REG_X27) & 0xFFFFFFFF
                try:
                    sp3c = struct.unpack("<I", uc.mem_read(sp + 0x3c, 4))[0]
                except Exception:
                    sp3c = 0xDEAD
                print(f"[CFF-162628 #{len(self._cff162628_trace)}] w9={w9:#010x} [sp+0x3c]={sp3c:#x} w4={w4:#010x} w3={w3:#010x} w26={w26:#010x} w27={w27:#010x}", flush=True)
        elif off == 0x16220c:
            if not hasattr(self, '_h16220c_cnt'):
                self._h16220c_cnt = 0
            self._h16220c_cnt += 1
            if self._h16220c_cnt <= 3:
                sp = uc.reg_read(UC_ARM64_REG_SP)
                x12 = uc.reg_read(UC_ARM64_REG_X12)
                x25 = uc.reg_read(UC_ARM64_REG_X25)
                try:
                    sp30 = struct.unpack("<Q", uc.mem_read(sp + 0x30, 8))[0]
                    sp48 = struct.unpack("<Q", uc.mem_read(sp + 0x48, 8))[0]
                    sp40 = struct.unpack("<Q", uc.mem_read(sp + 0x40, 8))[0]
                    sp60 = struct.unpack("<Q", uc.mem_read(sp + 0x60, 8))[0]
                    sp70 = struct.unpack("<Q", uc.mem_read(sp + 0x70, 8))[0]
                    x19_8 = struct.unpack("<Q", uc.mem_read(sp30 + 8, 8))[0] if sp30 else 0
                    sp48_28 = struct.unpack("<Q", uc.mem_read(sp48 + 0x28, 8))[0] if sp48 else 0
                    sp60_deref = struct.unpack("<I", uc.mem_read(sp60, 4))[0] if sp60 else 0
                    x12_val = struct.unpack("<I", uc.mem_read(x12, 4))[0]
                    x25_val = struct.unpack("<I", uc.mem_read(x25, 4))[0]
                except Exception as e:
                    print(f"[CFF-16220c #{self._h16220c_cnt}] ERR: {e}", flush=True)
                    sp30 = sp48 = sp40 = sp60 = sp70 = x19_8 = sp48_28 = sp60_deref = x12_val = x25_val = 0
                print(f"[CFF-16220c #{self._h16220c_cnt}] sp30={sp30:#x} [sp30+8]={x19_8:#x} sp48={sp48:#x} [sp48+28]={sp48_28:#x} sp40={sp40:#x} sp60={sp60:#x} [[sp60]]={sp60_deref:#x} sp70={sp70:#x} x12={x12:#x} [x12]={x12_val:#x} x25={x25:#x} [x25]={x25_val:#x}", flush=True)
        elif off == 0x1622cc:
            if not hasattr(self, '_h1622cc_cnt'):
                self._h1622cc_cnt = 0
            self._h1622cc_cnt += 1
            if self._h1622cc_cnt <= 3:
                w8 = uc.reg_read(UC_ARM64_REG_X8) & 0xFFFFFFFF
                w3 = uc.reg_read(UC_ARM64_REG_X3) & 0xFFFFFFFF
                nzcv = uc.reg_read(UC_ARM64_REG_NZCV)
                z = (nzcv >> 30) & 1
                print(f"[CFF-1622cc #{self._h1622cc_cnt}] w8={w8:#010x} w3={w3:#010x} Z={z} (ne->w8, eq->w3)", flush=True)
        elif off == 0x177290:
            if not hasattr(self, '_h177290_cnt'):
                self._h177290_cnt = 0
            self._h177290_cnt += 1
            if self._h177290_cnt <= 2:
                x0v = uc.reg_read(UC_ARM64_REG_X0)
                x1v = uc.reg_read(UC_ARM64_REG_X1)
                x2v = uc.reg_read(UC_ARM64_REG_X2)
                x3v = uc.reg_read(UC_ARM64_REG_X3)
                lrv = uc.reg_read(UC_ARM64_REG_LR)
                sp = uc.reg_read(UC_ARM64_REG_SP)
                try:
                    ctx = self._dump_mem_hex(uc, x1v + 0x380, 0x30) if x1v else "0"
                except Exception as exc:
                    ctx = f"ERR({exc})"

                def vec_triplet(vec_addr):
                    if not vec_addr:
                        return (0, 0, 0)
                    begin = self._safe_mem_read_qword(uc, vec_addr + 0x00) or 0
                    cur = self._safe_mem_read_qword(uc, vec_addr + 0x08) or 0
                    end = self._safe_mem_read_qword(uc, vec_addr + 0x10) or 0
                    return begin, cur, end

                x2_begin, x2_cur, x2_end = vec_triplet(x2v)
                x3_begin, x3_cur, x3_end = vec_triplet(x3v)
                x3_first = "0"
                if x3_begin:
                    x3r = self._resolve_mem_addr(uc, x3_begin)
                    try:
                        f100 = struct.unpack("<I", uc.mem_read(x3r + 0x100, 4))[0]
                        f104 = struct.unpack("<I", uc.mem_read(x3r + 0x104, 4))[0]
                        f118 = struct.unpack("<B", uc.mem_read(x3r + 0x118, 1))[0]
                        data = self._read_c_string(uc, x3r, 0x40)
                        head = self._dump_mem_hex(uc, x3r, 0x20)
                        x3_first = (
                            f"{x3_begin:#x}->{x3r:#x} [+0x100]={f100:#x} [+0x104]={f104:#x} "
                            f"[+0x118]={f118:#x} head={head} data={data!r}"
                        )
                    except Exception as exc:
                        x3_first = f"{x3_begin:#x}=ERR({exc})"
                print(
                    f"[177290-ENTRY #{self._h177290_cnt}] x0={x0v:#x} x1={x1v:#x} "
                    f"x2={x2v:#x} x3={x3v:#x} lr={lrv:#x} sp={sp:#x}",
                    flush=True,
                )
                print(f"[177290-CTX #{self._h177290_cnt}] x1+0x380={ctx}", flush=True)
                print(
                    f"[177290-VECS #{self._h177290_cnt}] "
                    f"x2=[{x2_begin:#x},{x2_cur:#x},{x2_end:#x}] "
                    f"x3=[{x3_begin:#x},{x3_cur:#x},{x3_end:#x}]",
                    flush=True,
                )
                print(f"[177290-X3-FIRST #{self._h177290_cnt}] {x3_first}", flush=True)
        elif off == 0x1772c8:
            if not hasattr(self, '_h1772c8_cnt'):
                self._h1772c8_cnt = 0
            self._h1772c8_cnt += 1
            if self._h1772c8_cnt <= 2:
                x1v = uc.reg_read(UC_ARM64_REG_X1)
                try:
                    fields = self._dump_mem_hex(uc, x1v + 0x380, 0x30)
                except Exception as exc:
                    fields = f"ERR({exc})"
                print(f"[LOOP-SRC-CTX #{self._h1772c8_cnt}] x1={x1v:#x} x1+0x380={fields}", flush=True)
        elif off == 0x1772cc:
            if not hasattr(self, '_h1772cc_cnt'):
                self._h1772cc_cnt = 0
            self._h1772cc_cnt += 1
            if self._h1772cc_cnt <= 2:
                x27v = uc.reg_read(UC_ARM64_REG_X27)
                try:
                    vec = self._dump_mem_hex(uc, x27v, 0x28)
                    begin = struct.unpack("<Q", uc.mem_read(x27v + 0x10, 8))[0]
                    end = struct.unpack("<Q", uc.mem_read(x27v + 0x18, 8))[0]
                except Exception as exc:
                    vec = f"ERR({exc})"
                    begin = end = 0
                print(
                    f"[LOOP-SRC-VEC #{self._h1772cc_cnt}] x27={x27v:#x} "
                    f"vec={vec} begin={begin:#x} end={end:#x}",
                    flush=True,
                )
        elif off == 0x1772f4:
            if not hasattr(self, '_h1772f4_cnt'):
                self._h1772f4_cnt = 0
            self._h1772f4_cnt += 1
            if self._h1772f4_cnt <= 2:
                x21v = uc.reg_read(UC_ARM64_REG_X21)
                x8v = uc.reg_read(UC_ARM64_REG_X8)
                x21r = self._resolve_mem_addr(uc, x21v)
                try:
                    fields = (
                        struct.unpack("<I", uc.mem_read(x21r + 0x100, 4))[0],
                        struct.unpack("<I", uc.mem_read(x21r + 0x104, 4))[0],
                        struct.unpack("<B", uc.mem_read(x21r + 0x118, 1))[0],
                    )
                    head = self._dump_mem_hex(uc, x21r, 0x20)
                except Exception as exc:
                    fields = (0, 0, 0)
                    head = f"ERR({exc})"
                print(
                    f"[LOOP-SRC-FIRST #{self._h1772f4_cnt}] x21={x21v:#x}->{x21r:#x} end={x8v:#x} "
                    f"[+0x100]={fields[0]:#x} [+0x104]={fields[1]:#x} [+0x118]={fields[2]:#x} "
                    f"head={head}",
                    flush=True,
                )
        multi_fire = {0x1d212c, 0x1d2094, 0x1d2088, 0x1c3364, 0x1c3374, 0x1c32b4, 0x1c8738, 0x20ffec, 0xceba0, 0x1cee54, 0x1cee58, 0x1cee5c, 0x1cee60, 0x1cee64, 0x1cee68, 0x1cee6c, 0x1c3318, 0x1c87a4, 0x6af14, 0x6ae6c, 0x6aec8, 0x6aef8, 0x6b6b4, 0x6b6f8, 0x6b700, 0x6b738, 0x6b780, 0x6b794, 0x6b79c, 0x6b7b8, 0x177290, 0x1772c8, 0x1772cc, 0x1772f4, 0x177654, 0x177664, 0x177670, 0x177680, 0x17768c, 0x1776b4, 0x1776c0, 0x177754, 0x177770, 0x1777d4, 0x177ebc, 0x177f04, 0x177f4c, 0x178040, 0x17804c, 0x1780cc, 0x1780d0, 0x178114, 0x1781c4, 0x178910, 0x1789cc, 0x1789d8, 0x178a30, 0x178b60, 0x178b70, 0x178b80, 0x178bfc, 0x162628, 0x16220c, 0x1622cc, 0x1654ec, 0x165548, 0x165588, 0x16565c, 0x16567c, 0x165690, 0x165694, 0x1656b8, 0x1656bc}
        if off in multi_fire:
            cnt_key = f"mf_{off}"
            self._fx_branch_probes.setdefault(cnt_key, 0)
            self._fx_branch_probes[cnt_key] += 1
            if self._fx_branch_probes[cnt_key] > 200:
                return
        elif off in self._fx_branch_probes:
            return
        else:
            self._fx_branch_probes[off] = True
        w0 = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
        sp = uc.reg_read(UC_ARM64_REG_SP)
        labels = {
                0x155ba4: "0x155b68: prepare inner CFF args",
                0x155bac: "0x155b68: bl 0x8a2c4",
                0x155c30: "0x155b68: x22+0xa0 size guard passed/failed",
                0x155c50: "0x155b68: x22+0x1f8 size guard passed/failed",
                0x155bb0: "0x155b68: inner CFF returned (pre-mov w19,w0)",
                0x155c6c: "0x155b68: CALLING 0xce75c with w0=0x8e",
                0x155c70: "0x155b68: returned from 0xce75c",
                0x155c9c: "0x155b68: cbz check (computation gate)",
                0x155d60: "0x155b68: enter stage 1 formatter loop",
                0x155d64: "0x155b68: cbz TAKEN → stage 2",
                0x15657c: "0x155b68: POST-stage1, entering stage 2 setup",
                0x1565a0: "0x155b68: stage 2 prep (add x8,sp,#0x9c0)",
                0x1565ac: "0x155b68: CALLING ce75c(0x8d) for stage 2 fmt",
                0x1565b0: "0x155b68: returned from ce75c(0x8d)",
                0x1565f0: "0x155b68: stage 2 arg stored at sp+0x8b0",
                0x1565f8: "0x155b68: stage 2 cbz gate",
                0x156064: "0x155b68: %X formatter entry",
                0x1560d8: "0x155b68: %X zero-pad loop body",
                0x156100: "0x155b68: %X zero-pad loop compare",
                0x15a3bc: "0x155b68: hardcode return_flag=1",
                0x15a62c: "0x155b68: compare pair #1 before branch",
                0x15a670: "0x155b68: compare pair #2 before branch",
                0x15aa00: "0x155b68: save return_flag -> [sp+0x1d8]",
                0x15af90: "0x155b68: reload return_flag from [sp+0x1d8]",
                0x15b178: "0x155b68 RET",
                0x108d1c: "bl 0x155b68 (cert computation PRE-CALL)",
                0x108d20: f"tbnz w0,#0,0x108f88 (after 0x155b68) w0={w0:#x} bit0={w0&1}",
                0x108d24: "slow path ENTERED (branch NOT taken at 0x108d20)",
                0x108f88: "CFF call setup reached",
                0x108fa0: ("calling live cert CFF wrapper"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "calling module cert CFF wrapper"),
                0x108fa4: f"post-CFF: tbz w0,#0,0x1090c0 w0={w0:#x} bit0={w0&1}",
                0x108448: f"post-success: branch on sp+0x68-derived flag, w9={uc.reg_read(UC_ARM64_REG_X9)&0xFFFFFFFF:#x}",
                0x108450: "post-success: call 0x6be48",
                0x108458: "post-success: call 0x1af35c",
                0x108528: "post-success secondary: call 0x1af35c",
                0x108530: "post-success secondary: bl 0x1af35c",
                0x108538: "post-success: fast memcpy path from x20",
                0x108fcc: "POST-CFF APPEND: add x0,sp,#0x620 (combining challenge+CFF)",
                0x1090c0: "post-append cleanup complete / vector setup begins",
                0x10935c: "post-append: pre-bl 0xd5f6c (merge sp+0x620 with session descriptor)",
                0x10939c: "post-append: pre-bl 0x858d0 (append merged descriptor into sp+0x810)",
                0x1093a0: "post-append: returned from 0x858d0",
                0x149054: "candidate feeder build: append 32-byte tail after SoC model",
                0x14a4a4: "candidate feeder build: finalized 40-byte pre-SHA message",
                0x14fa14: "candidate inline-SHA helper: load session/descriptor state",
                0x14fa24: "candidate inline-SHA helper: load [obj+0x390]",
                0x14fa38: "candidate inline-SHA helper: vector ptr staged at sp+0x30",
                0x14fa54: "candidate inline-SHA helper: block-count/length calc",
                0x14b894: "SHA32 producer A: prologue",
                0x14ba3c: "SHA32 producer A: late block start",
                0x14cecc: "SHA32 producer B: prologue",
                0x14d0e4: "SHA32 producer B: late block start",
                0x14e5f8: "SHA32 producer C: late block start",
                0x14f9f4: "SHA32 producer D: late block start",
                0x14ff50: "inline SHA helper entry",
                0x1500b0: "inline SHA helper: pre-update bl 0x1501a0",
                0x1500c0: "inline SHA helper: pre-finalize bl 0x1503ec",
                0x1501a0: "inline SHA state: update/chunk append entry",
                0x1503ec: "inline SHA state: finalize entry",
                0x150504: "inline SHA state: digest loop begins",
                0x1505b4: "inline SHA state: digest words materialized",
                0x14fbb0: "candidate inline-SHA helper: record iteration setup",
                0x14fc24: "candidate inline-SHA helper: byte output write",
                0x1c20f4: ("cert LIVE prologue ENTERED (sub sp, #0xd0)"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "cert module helper 0x1c20e4 active"),
                0x1c2124: ("cert LIVE wrapper ENTERED [x27+0x210 checked below]"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "cert module CFF wrapper ENTERED"),
                0x1c2470: "cert CFF wrapper EPILOGUE / restore window",
                0x1c32b4: f"cert CFF Hub1 w9={uc.reg_read(UC_ARM64_REG_X9)&0xFFFFFFFF:#010x} w19={uc.reg_read(UC_ARM64_REG_X19)&0xFFFFFFFF:#010x} w28={uc.reg_read(UC_ARM64_REG_X28)&0xFFFFFFFF:#010x}",
                0x1c3374: f"cert CFF Hub1 bl 0xce75c! w0={w0:#x} x8={uc.reg_read(UC_ARM64_REG_X8):#x}",
                0x1c50d4: "cert CFF: pre-bl 0x1c88a0",
                0x1c50d8: f"cert CFF: about to call 0x1c88a0 (stale pre-call w0={w0:#x} bit0={w0&1})",
                0x1c50dc: f"cert CFF: str w0→[sp,#72] w0={w0:#x}",
                0x1c6314: "cert CFF: pre-bl 0x1d126c",
                0x1c6318: f"cert CFF: about to call 0x1d126c (stale pre-call w0={w0:#x} bit0={w0&1})",
                0x1c631c: f"cert CFF: str w0→[sp,#64] w0={w0:#x}",
                0x1c7554: f"DECISION: tst [sp64],#1 w0={w0:#x}",
                0x1c7560: f"DECISION: cbz w8 → return 0? w0={w0:#x}",
                0x1c75e0: "RETURN 0 PATH (str wzr,[sp,#80])",
                0x1c7630: "RETURN 1 PATH (str #1,[sp,#80])",
                0x1c8854: f"cert CFF wrapper RET w0={w0:#x}",
                0x1ce018: "0x1c88a0: empty descriptor range -> failure path",
                0x1cec94: "0x1c88a0: x20 != x19 -> success path",
                0x1cee70: f"0x1c88a0: ceba0 returned x0={uc.reg_read(UC_ARM64_REG_X0):#x}",
                0x1cee88: "0x1c88a0: descriptor loop exhausted -> failure path",
                0x1d0ac0: f"0x1c88a0 EPILOGUE: mov w0,w19 w19={uc.reg_read(UC_ARM64_REG_X19)&0xFFFFFFFF:#x}",
                0x1d0ae0: f"0x1c88a0 RET w0={w0:#x}",
                0x1d0ae4: "0x1c88a0 FAILURE PATH (mov w19,wzr)",
                0x1d0b0c: "0x1c88a0 SUCCESS PATH (orr w19,wzr,#1)",
                0x1d212c: f"0x1d126c: CFF hub w9={uc.reg_read(UC_ARM64_REG_X9)&0xFFFFFFFF:#010x}",
                0x1d2088: "0x1d126c: pre-bl 0x1d8a54",
                0x1d2094: f"0x1d126c: tst w0,#1 (ret={w0:#x} bit0={w0&1})",
                0x1d1710: "0x1d126c: set sp+28=1",
                0x1d20ac: "0x1d126c: copy sp+28→sp+24",
                0x1d1930: "0x1d126c: set result=1 (hardcoded)",
                0x1d190c: "0x1d126c: set result from sp+24",
                0x1d2480: "0x1d126c EPILOGUE",
                0x1d24a4: f"0x1d126c RET w0={w0:#x}",
                0x1c3364: "cert CFF: prepare callback-local ce75c buffer",
                0x1c3374: f"cert CFF: bl 0xce75c via w26={self._cert_post_cff_last_w26 if self._cert_post_cff_last_w26 is not None else 0:#010x}",
                0x1c3378: "cert CFF: RETURNED from 0xce75c",
                0x1c8738: f"cert post-success CFF hub w26={uc.reg_read(UC_ARM64_REG_X26)&0xFFFFFFFF:#010x}",
                0x20ffec: f"0x20ffec (hash fn?) entry x0={uc.reg_read(UC_ARM64_REG_X0):#x} x1={uc.reg_read(UC_ARM64_REG_X1):#x}",
                0x108468: f"0x10828c MODE-2 ENTRY: x19={uc.reg_read(UC_ARM64_REG_X19):#x} x20={uc.reg_read(UC_ARM64_REG_X20):#x}",
                0x108480: f"0x10828c MODE-2: bl 0x10875c x8(out)={uc.reg_read(UC_ARM64_REG_X8):#x} x1(src)={uc.reg_read(UC_ARM64_REG_X1):#x} x2(ctx)={uc.reg_read(UC_ARM64_REG_X2):#x}",
                0x108484: "0x10828c MODE-2: RETURNED from 0x10875c",
                0x108618: "0x10828c MODE-2: INLINE SSO path (zeros obj+0x68)",
                0x108630: f"0x10828c MODE-2: ldr q0,[sp,#0x50] ABOUT TO COPY",
                0x10886c: "0x10875c: post-session-descriptor setup",
                0x108fc0: "0x10875c: pre-append reload of sp+0x2f0",
                0x11cfa0: f"0x10875c: OUTPUT WRITE ldr x10,[sp,#0x1e0] (loading output buf ptr)",
                0x11cfb0: f"0x10875c: OUTPUT WRITE str x8,[x10,#0x10] x8={uc.reg_read(UC_ARM64_REG_X8):#x}",
                0x11cfc0: "0x10875c: OUTPUT WRITE str q0,[x10] (16 bytes to output buf)",
                0x109184: f"0x10875c: SAVE x26 to [sp,#0x1e0] x26={uc.reg_read(UC_ARM64_REG_X26):#x}",
                0x1090c0: f"0x10875c: INIT x20=[x27+0x390] x27={uc.reg_read(UC_ARM64_REG_X27):#x}",
                0x1090d0: f"0x10875c: INIT x19=[x20+0x588] x20={uc.reg_read(UC_ARM64_REG_X20):#x}",
                0x1090d8: f"0x10875c: POST-INIT sub x25=x23-x19 x19={uc.reg_read(UC_ARM64_REG_X19):#x} x23={uc.reg_read(UC_ARM64_REG_X23):#x}",
                0x109118: f"0x10875c: INIT bl malloc x25={uc.reg_read(UC_ARM64_REG_X25):#x} x0={uc.reg_read(UC_ARM64_REG_X0):#x}",
                0x109150: f"0x10875c: INIT cmp x19,x23 x19={uc.reg_read(UC_ARM64_REG_X19):#x} x23={uc.reg_read(UC_ARM64_REG_X23):#x}",
                0x109160: f"0x10875c: INIT b.eq? x19={uc.reg_read(UC_ARM64_REG_X19):#x} x23={uc.reg_read(UC_ARM64_REG_X23):#x}",
                0x109180: f"0x10875c: INIT str x27 to sp+0x1f8 x27={uc.reg_read(UC_ARM64_REG_X27):#x}",
                0x10e41c: "post-hash helper: pre-bl 0x55040",
                0x113454: "post-hash helper: pre-bl 0x55040 (copy from rodata tail)",
                0x1134e8: "post-hash helper: pre-bl 0x55040 (copy from sp+0x7d0)",
                0x115a50: "post-hash helper: pre-bl 0x55040 (copy from sp+0x7d0)",
                0x115f24: "post-hash helper: pre-bl 0x55040 (copy source message)",
                0x1173e4: "post-hash helper: pre-bl 0x55040 (final digest/pad copy)",
                0x11cf7c: f"0x10875c: HASH WRITE str q0,[x23] x23={uc.reg_read(UC_ARM64_REG_X23):#x} sp+0x578={sp+0x578:#x} match={'YES' if uc.reg_read(UC_ARM64_REG_X23)==sp+0x578 else 'NO!!! MISMATCH'}",
                0x11cf2c: f"0x10875c: PRE-HASH bl 0xdd830 x0={uc.reg_read(UC_ARM64_REG_X0):#x} x8={uc.reg_read(UC_ARM64_REG_X8):#x} x23={uc.reg_read(UC_ARM64_REG_X23):#x}",
                0x11cf84: f"0x10875c: PRE-OUTPUT ldr x0,[sp,#0x1d0] last_pc={self._last_pc:#x}",
                0x11ca30: f"0x11ca30: live-image cleanup block x0={uc.reg_read(UC_ARM64_REG_X0):#x} x19={uc.reg_read(UC_ARM64_REG_X19):#x}",
                0x11cf90: (
                    "0x10875c: OUTPUT SOURCE load from local SSO sp+0x590 "
                    f"sp+0x590={self._dump_mem_hex(uc, sp + 0x590, 24)} "
                    f"sp+0x5a0={self._dump_mem_hex(uc, sp + 0x5A0, 8)} "
                    f"sp+0x810={self._dump_mem_hex(uc, sp + 0x810, 32)}"
                ),
                0x11cae0: f"0x10875c: PRE-CALL-1627d8 x0={uc.reg_read(UC_ARM64_REG_X0):#x} x1={uc.reg_read(UC_ARM64_REG_X1):#x} x8={uc.reg_read(UC_ARM64_REG_X8):#x}",
                0x11cae4: "0x10875c: POST-CALL-1627d8 (checking sp+0x810)",
                0x11cb1c: "0x10875c: COPY ldr q0,[sp+0x810] (about to copy to sp+0x560)",
                0x11cb28: "0x10875c: COPY str q0→sp+0x560",
                0x1627d8: "0x1627d8: state writes output header field (+0x98)",
                0x1627f0: "0x1627d8: commit output header field (+0x98)",
                0x162850: "0x1627d8: csel next state from [fp-0x94]",
                0x1629a8: "0x1629a8: resume after upstream helper",
                0x162a74: "0x1629a8: precheck call 0x100dadc8",
                0x162a84: "0x1629a8: post-0x100dadc8",
                0x162ae0: "0x1629a8: compare precheck bytes",
                0x162aec: "0x1629a8: precheck mismatch branch",
                0x162b04: "0x1629a8: early branch to 0x1654ec",
                0x1654ec: "0x1654ec: post-precheck success continuation",
                0x165548: "0x1654ec: build local vector for sp+0x40c path",
                0x165588: "0x1654ec: copy local vector into ctx+0xc8",
                0x16565c: "0x1654ec: strlen loop over sp+0x40c",
                0x16567c: "0x1654ec: pre-bl 0x10054680",
                0x165690: "0x1654ec: pre-bl 0x155b68",
                0x165694: "0x1654ec: post-0x155b68 branch",
                0x1656b8: "0x1654ec: pre-bl 0x18aa08",
                0x1656bc: "0x1654ec: post-0x18aa08",
                0x1656f0: "0x1654ec: post-0x18aa08 strlen compare",
                0x1658a8: "0x1654ec: fallback builder after empty sp+0x3e8",
                0x162b9c: "0x1629a8: load candidate record",
                0x162bcc: "0x1629a8: candidate type compare",
                0x162bf4: "0x1629a8: prepare callback",
                0x162c40: "0x1629a8: invoke callback",
                0x162c44: "0x1629a8: callback returned",
                0x162c5c: "0x1629a8: choose null/non-null branch",
                0x162d68: "0x1629a8: dispatcher state",
                0x162eec: "0x1629a8: write output slot (+0xa0)",
                0x163344: "0x1629a8: return",
                0x16bb2c: "0x16bb2c: call SHA worker 0x16d36c",
                0x16bb34: "0x16bb34: call post-SHA accessor 0x16e0ac",
                0x16bb38: "0x16bb38: store first post-SHA accessor result",
                0x16bb40: "0x16bb40: call post-SHA accessor 0x16e1a8",
                0x16bb84: "0x16bb84: store second post-SHA accessor result",
                0x177728: "0x177740: source object before x19->x0",
                0x177730: ("0x177740: helper prologue"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: module collector pre-loop"),
                0x177740: ("0x177740: upstream helper entry"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: module collector loop"),
                0x177770: ("0x177740: after 0x1017a868"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: clone temp SSO into candidate slot (path A)"),
                0x17777c: ("0x177740: after 0x10247a6c"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: destroy temp SSO copy (path A)"),
                0x177790: ("0x177740: after 0x100be324"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: alt temp-SSO path after match gate"),
                0x1777a0: ("0x177740: build candidate list"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: choose temp SSO backing"),
                0x1777ac: ("0x177740: after 0x101c469c"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: load candidate range [x20+8]"),
                0x1777b4: ("0x177740: after 0x101ad620"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: branch if candidate range empty"),
                0x1777c0: ("0x177740: iterate candidate list"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: clone temp SSO into candidate slot (path B)"),
                0x1777d4: ("0x177740: before final 0x1702c8 normalize"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: advance source iterator"),
                0x1777dc: ("0x177740: after final 0x1702c8 / before 0x1ad668"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: compare source iterator vs end"),
                0x1777e4: ("0x177740: after 0x1ad668"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: final temp-SSO cleanup flag"),
                0x1777f0: ("0x177740: x21 flag check"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177740: temp-SSO free check"),
                0x177ebc: "0x177ebc: formatter helper entry",
                0x177f04: "0x177ebc: session gate",
                0x177f4c: "0x177ebc: load x28 range",
                0x178040: "0x177ebc: pre-dd9a8 formatter call",
                0x17804c: "0x177ebc: post-dd9a8 formatter call",
                0x1780cc: "0x177ebc: build append string from sp+0x420",
                0x1780d0: "0x177ebc: append into ctx+0xd0",
                0x178114: "0x177ebc: grow/append via ctx+0xc8",
                0x1781c4: "0x177ebc: empty-x28 fallback builder",
                0x178910: "0x177ebc: package-name fallback formatter",
                0x1789cc: "0x177ebc: pre-append main token",
                0x1789d8: "0x177ebc: copy main token into ctx+0xd0 slot",
                0x178a30: "0x177ebc: compare session label vs main token",
                0x178b60: "0x177ebc: main token compare mismatch",
                0x178b70: "0x177ebc: finalize main token slot",
                0x178b80: "0x177ebc: advance ctx+0xd0 after main token",
                0x178bfc: "0x177ebc: compare session label vs alt token",
                0x178170: ("0x177740: finalize helper state"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177ebc: free temp formatter buffer"),
                0x1781a8: ("0x177740: helper return success"
                           if LIVE_CERT_OVERLAY_ACTIVE
                           else "0x177ebc: formatter helper return"),
                0x1702e8: "0x1702c8: saved x21 slot initialized",
                0x17039c: "0x1702c8: before first vcall",
                0x1703a0: "0x1702c8: after first vcall",
                0x170538: "0x1702c8: before second vcall",
                0x17053c: "0x1702c8: after second vcall",
                0x17061c: "0x1702c8: before x21 restore",
                0x170620: "0x1702c8: after x21 restore",
        }
        label = labels.get(off, f"probe {off:#x}")
        extra = ""

        # ce75c intercepts are now in the main hook handler (0x155c6c and 0x1565ac)

        # When entering the cert wrapper, clear stale CFF return state from
        # previous functions so GENERAL-STALL recovery does not reuse an old LR.
        # Only treat 0x1c20f4 as an entry when the live 0x1c0000 overlay is
        # active; otherwise that offset is just the small module helper at
        # 0x1c20e4 and should not receive wrapper-specific fixups.
        cert_entry_sites = {0x1c2124}
        if LIVE_CERT_OVERLAY_ACTIVE:
            cert_entry_sites.add(0x1c20f4)
        if off in cert_entry_sites:
            self._cff_current_return_lr = None
            self._cff_current_caller_sp = None
            self._cff_current_caller_fp = None
            self._stall_last_progress_block = self._stall_jit_count
            # Restore x27 = session object if it was corrupted
            if hasattr(self, '_session_obj'):
                cur_x27 = uc.reg_read(UC_ARM64_REG_X27)
                if cur_x27 != self._session_obj:
                    uc.reg_write(UC_ARM64_REG_X27, self._session_obj)
                    print(f"[CERT-X27-FIX] Restored x27: {cur_x27:#x} -> "
                          f"{self._session_obj:#x}", flush=True)
                # The module caller passes the session in x1. Repair that handoff
                # as well, since stall-skip can leak a stale pointer into the
                # wrapper entry even when x27 is later reused for iteration.
                cur_x1 = uc.reg_read(UC_ARM64_REG_X1)
                if cur_x1 != self._session_obj:
                    uc.reg_write(UC_ARM64_REG_X1, self._session_obj)
                    print(f"[CERT-X1-FIX] Restored x1: {cur_x1:#x} -> "
                          f"{self._session_obj:#x}", flush=True)
                # x20 mirrors x1 only in the live wrapper prologue. Do not
                # clobber module-wrapper x20 when the live overlay is disabled.
                if LIVE_CERT_OVERLAY_ACTIVE and off == 0x1c2124:
                    cur_x20 = uc.reg_read(UC_ARM64_REG_X20)
                    if cur_x20 != self._session_obj:
                        uc.reg_write(UC_ARM64_REG_X20, self._session_obj)
                        print(f"[CERT-X20-FIX] Restored x20: {cur_x20:#x} -> "
                              f"{self._session_obj:#x}", flush=True)

        # Dump session+0x210 after 0x155b68 returns (the actual cert computation)
        if off == 0x108d1c:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            extra = (
                f" x0={x0:#x} x1={x1:#x} x2={x2:#x} x3={x3:#x} "
                f"{self._describe_cert_session_ptr(uc, x1)}"
            )
        elif off == 0x108d20:
            x27 = uc.reg_read(UC_ARM64_REG_X27)
            try:
                data210 = bytes(uc.mem_read(x27 + 0x210, 24))
                b0 = data210[0]
                if b0 & 1:
                    ptr = struct.unpack("<Q", data210[16:24])[0]
                    size = struct.unpack("<Q", data210[8:16])[0]
                    buf = b""
                    if ptr > 0x1000:
                        try:
                            buf = bytes(uc.mem_read(ptr, min(size, 64)))
                        except:
                            pass
                    extra += f" x27+0x210=HEAP(sz={size},ptr={ptr:#x}) data={buf.hex() if buf else '??'} ascii={buf.decode('ascii', errors='replace') if buf else '??'}"
                else:
                    slen = b0 >> 1
                    s = data210[1:1+slen].decode('ascii', errors='replace')
                    extra += f" x27+0x210=SSO({slen})={s!r}"
            except Exception as e:
                extra += f" x27+0x210=ERR({e})"
        elif off == 0x108fa0:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            obj0 = self._safe_mem_read_qword(uc, x0) if x0 > 0x1000 else None
            obj8 = self._safe_mem_read_qword(uc, x0 + 0x8) if x0 > 0x1000 else None
            obj30 = self._safe_mem_read_qword(uc, x0 + 0x30) if x0 > 0x1000 else None
            x3_word = self._safe_mem_read_u32(uc, x3) if x3 > 0x1000 else None
            if LIVE_CERT_OVERLAY_ACTIVE:
                extra = (
                    f" x0={x0:#x} [x0+0x30]={self._format_opt_hex(obj30)} "
                    f"x1={x1:#x} x2={x2:#x} x3={x3:#x} [x3]={self._format_opt_hex(x3_word)} "
                    f"{self._describe_cert_session_ptr(uc, x1)}"
                )
            else:
                extra = (
                    f" x0={x0:#x} [x0]={self._format_opt_hex(obj0)} [x0+0x8]={self._format_opt_hex(obj8)} "
                    f"[x0+0x30]={self._format_opt_hex(obj30)} "
                    f"x1={x1:#x} x2={x2:#x} x3={x3:#x} [x3]={self._format_opt_hex(x3_word)} "
                    f"{self._describe_cert_session_ptr(uc, x1)}"
                )
        elif off in (0x155ba4, 0x155bac):
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            x22 = uc.reg_read(UC_ARM64_REG_X22)
            extra = f" x0={x0:#x} x1={x1:#x} x2={x2:#x} x3={x3:#x} x22={x22:#x}"
            if x0 > 0x1000:
                extra += f" {self._describe_cert_session_ptr(uc, x0)}"
            elif x22 > 0x1000:
                extra += f" {self._describe_cert_session_ptr(uc, x22)}"
        elif off == 0x155bb0:
            x0_ret = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
            w19_pre = uc.reg_read(UC_ARM64_REG_X19) & 0xFFFFFFFF
            extra = f" x0_ret={x0_ret:#x} w19_pre={w19_pre:#x}"
        elif off == 0x155c30:
            x22 = uc.reg_read(UC_ARM64_REG_X22)
            try:
                hdr = bytes(uc.mem_read(x22 + 0xa0, 24))
                tag = hdr[0]
                if tag & 1:
                    size = struct.unpack("<Q", hdr[8:16])[0]
                    ptr = struct.unpack("<Q", hdr[16:24])[0]
                    extra = f" x22={x22:#x} +0xa0=LONG size={size:#x} ptr={ptr:#x}"
                else:
                    slen = tag >> 1
                    s = hdr[1:1+slen].decode('ascii', errors='replace')
                    extra = f" x22={x22:#x} +0xa0=SSO({slen})={s!r}"
            except Exception as e:
                extra = f" x22={x22:#x} +0xa0=ERR({e})"
        elif off == 0x155c50:
            x22 = uc.reg_read(UC_ARM64_REG_X22)
            try:
                hdr = bytes(uc.mem_read(x22 + 0x1f8, 24))
                tag = hdr[0]
                if tag & 1:
                    size = struct.unpack("<Q", hdr[8:16])[0]
                    ptr = struct.unpack("<Q", hdr[16:24])[0]
                    extra = f" x22={x22:#x} +0x1f8=LONG size={size:#x} ptr={ptr:#x}"
                else:
                    slen = tag >> 1
                    s = hdr[1:1+slen].decode('ascii', errors='replace')
                    extra = f" x22={x22:#x} +0x1f8=SSO({slen})={s!r}"
            except Exception as e:
                extra = f" x22={x22:#x} +0x1f8=ERR({e})"
        elif off == 0x15657c:
            # Post-stage1, entering stage 2 setup. Dump descriptor+0xa0 SSO.
            sp = uc.reg_read(UC_ARM64_REG_SP)
            try:
                desc_a0 = struct.unpack("<Q", uc.mem_read(sp + 0x278, 8))[0]
                sso_raw = bytes(uc.mem_read(desc_a0, 24))
                tag = sso_raw[0]
                if tag & 1:  # long
                    size = struct.unpack("<Q", sso_raw[8:16])[0]
                    ptr = struct.unpack("<Q", sso_raw[16:24])[0]
                    try:
                        data = bytes(uc.mem_read(ptr, min(size, 64)))
                        extra = f" desc+0xa0=LONG(sz={size},ptr={ptr:#x},data='{data.decode('ascii','replace')}')"
                    except:
                        extra = f" desc+0xa0=LONG(sz={size},ptr={ptr:#x},UNREADABLE)"
                else:
                    slen = tag >> 1
                    s = sso_raw[1:1+slen].decode('ascii', errors='replace')
                    extra = f" desc+0xa0=SSO({slen})='{s}'"
            except Exception as e:
                extra = f" desc+0xa0=ERR({e})"
        elif off == 0x155c70:
            # Just returned from 0xce75c — read the result SSO at sp+0x9c0
            sp = uc.reg_read(UC_ARM64_REG_SP)
            try:
                sso = bytes(uc.mem_read(sp + 0x9c0, 24))
                byte0 = sso[0]
                if byte0 & 1:  # long
                    size = struct.unpack("<Q", sso[8:16])[0]
                    ptr = struct.unpack("<Q", sso[16:24])[0]
                    try:
                        data = bytes(uc.mem_read(ptr, min(size, 64)))
                        extra = f" ce75c_result=LONG(sz={size:#x},ptr={ptr:#x},data={data.hex()})"
                    except:
                        extra = f" ce75c_result=LONG(sz={size:#x},ptr={ptr:#x},UNREADABLE)"
                else:
                    slen = byte0 >> 1
                    s = sso[1:1+slen]
                    extra = f" ce75c_result=SSO({slen})={s!r}"
            except Exception as e:
                extra = f" ce75c_result=ERR({e})"
        elif off == 0x1c3378:
            # cert CFF: RETURNED from 0xce75c — dump sp+0x60 and x19 safely
            try:
                sp60 = bytes(uc.mem_read(sp + 0x60, 24)).hex()
            except:
                sp60 = "UNREADABLE"
            extra = f" sp+0x60={sp60} x19={uc.reg_read(UC_ARM64_REG_X19):#x}"
        elif off == 0x108fcc:
            # POST-CFF APPEND: dump x27+0x210, x27+0x2a0, sp+0x5e0, sp+0x61c safely
            x27 = uc.reg_read(UC_ARM64_REG_X27)
            parts = []
            for name, addr_val in [("x27+0x210", x27+0x210), ("x27+0x2a0", x27+0x2a0),
                                   ("sp+0x5e0", sp+0x5e0), ("sp+0x61c", sp+0x61c)]:
                try:
                    parts.append(f"{name}={bytes(uc.mem_read(addr_val, 24)).hex()}")
                except:
                    parts.append(f"{name}=UNREADABLE")
            extra = f" x27={x27:#x} " + " ".join(parts)
        elif off == 0x155c74:
            # After ldrb w8, [sp, #0x9c0] — show w8 (the byte0 of the result)
            w8 = uc.reg_read(UC_ARM64_REG_X8) & 0xFF
            extra = f" w8(byte0)={w8:#x}"
        elif off == 0x155c9c:
            # cbz w8, #0x155d64 — show w8 and x20 (the string data ptr)
            w8 = uc.reg_read(UC_ARM64_REG_X8) & 0xFF
            x20 = uc.reg_read(UC_ARM64_REG_X20)
            try:
                first4 = bytes(uc.mem_read(x20, 4))
                extra = f" w8={w8:#x} x20={x20:#x} data={first4.hex()}"
            except:
                extra = f" w8={w8:#x} x20={x20:#x} data=UNREADABLE"
        elif off == 0x155d60:
            x20 = uc.reg_read(UC_ARM64_REG_X20)
            x25 = uc.reg_read(UC_ARM64_REG_X25)
            x29 = uc.reg_read(UC_ARM64_REG_X29)
            extra = (
                f" x20={x20:#x} x25={x25:#x} x29={x29:#x} "
                f"argwin={self._dump_mem_hex(uc, x25, 0x30)}"
            )
        elif off == 0x1565f0:
            # Stage 2 arg stored: str x8, [sp, #0x8b0]
            x8 = uc.reg_read(UC_ARM64_REG_X8)
            try:
                arg_str = self._read_c_string(uc, x8, 64)
                extra = f" x8(arg_ptr)={x8:#x} str='{arg_str.decode('ascii', errors='replace')}'"
            except Exception as e:
                extra = f" x8(arg_ptr)={x8:#x} ERR({e})"
        elif off == 0x1565f8:
            # Stage 2 cbz gate: cbz w8, 0x157004
            w8 = uc.reg_read(UC_ARM64_REG_X8) & 0xFF
            x24 = uc.reg_read(UC_ARM64_REG_X24)
            try:
                first8 = bytes(uc.mem_read(x24, 8))
                extra = f" w8={w8:#x} x24(fmt_ptr)={x24:#x} data={first8.hex()}"
            except:
                extra = f" w8={w8:#x} x24(fmt_ptr)={x24:#x} data=UNREADABLE"
        elif off == 0x156064:
            x20 = uc.reg_read(UC_ARM64_REG_X20)
            x22 = uc.reg_read(UC_ARM64_REG_X22)
            x25 = uc.reg_read(UC_ARM64_REG_X25)
            x29 = uc.reg_read(UC_ARM64_REG_X29)
            w21 = uc.reg_read(UC_ARM64_REG_X21) & 0xFFFFFFFF
            w11 = uc.reg_read(UC_ARM64_REG_X11) & 0xFFFFFFFF
            try:
                fmt = self._read_c_string(uc, max(x20 - 4, 0), 0x20)
            except Exception as e:
                fmt = f"ERR({e})".encode()
            args = []
            for i in range(6):
                try:
                    args.append(struct.unpack("<Q", uc.mem_read(x25 + i * 8, 8))[0])
                except Exception:
                    args.append(None)
            extra = (
                f" x20={x20:#x} fmt={fmt!r}"
                f" w21(width)={w21:#x} w11(flags)={w11:#x}"
                f" x22(out)={x22:#x} x25(args)={x25:#x} x29(fp)={x29:#x}"
                f" next_args={[hex(v) if v is not None else 'ERR' for v in args]}"
            )
        elif off == 0x1560d8:
            x22 = uc.reg_read(UC_ARM64_REG_X22)
            w8 = uc.reg_read(UC_ARM64_REG_X8) & 0xFFFFFFFF
            w9 = uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF
            w21 = uc.reg_read(UC_ARM64_REG_X21) & 0xFFFFFFFF
            try:
                tmp = self._read_c_string(uc, uc.reg_read(UC_ARM64_REG_X29) - 0x90, 0x40)
            except Exception as e:
                tmp = f"ERR({e})".encode()
            extra = (
                f" x22(out)={x22:#x} w8(flag)={w8:#x} w9(pad_count)={w9:#x}"
                f" w21(width)={w21:#x} tmp={tmp!r}"
            )
        elif off == 0x156100:
            w9 = uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF
            w12 = uc.reg_read(UC_ARM64_REG_X12) & 0xFFFFFFFF
            x22 = uc.reg_read(UC_ARM64_REG_X22)
            extra = f" x22(out)={x22:#x} w9(pad_count)={w9:#x} w12(limit)={w12:#x}"
        elif off == 0x15a3bc:
            w19 = uc.reg_read(UC_ARM64_REG_X19) & 0xFFFFFFFF
            w27 = uc.reg_read(UC_ARM64_REG_X27) & 0xFFFFFFFF
            extra = f" w19={w19:#x} w27={w27:#x}"
        elif off in (0x15a62c, 0x15a670):
            w19 = uc.reg_read(UC_ARM64_REG_X19) & 0xFFFFFFFF
            w0_now = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
            extra = f" w19={w19:#x} w0={w0_now:#x}"
        elif off in (0x15aa00, 0x15af90, 0x15b178):
            w24 = uc.reg_read(UC_ARM64_REG_X24) & 0xFFFFFFFF
            try:
                slot = struct.unpack("<I", uc.mem_read(sp + 0x1d8, 4))[0]
                extra = f" w24={w24:#x} [sp+0x1d8]={slot:#x}"
            except Exception as e:
                extra = f" w24={w24:#x} [sp+0x1d8]=ERR({e})"
        elif off in (0x1c3364, 0x1c3374):
            extra = (
                f" route_state={self._cert_post_cff_last_w26 if self._cert_post_cff_last_w26 is not None else 0:#010x}"
                f" hits={self._cert_post_cff_1c3374_hits}"
                f" w0={w0:#x}"
                f" sp+0x50={self._dump_mem_hex(uc, sp + 0x50, 0x20)}"
                f" sp+0x60={self._dump_mem_hex(uc, sp + 0x60, 0x20)}"
            )
        elif off == 0x1629a8:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x2v = uc.reg_read(UC_ARM64_REG_X2)
            x3v = uc.reg_read(UC_ARM64_REG_X3)
            x22v = uc.reg_read(UC_ARM64_REG_X22)
            x23rv = uc.reg_read(UC_ARM64_REG_X23)
            lrv = uc.reg_read(UC_ARM64_REG_X30)
            fpv = uc.reg_read(UC_ARM64_REG_X29)
            last_block = getattr(self, '_last_jit_block', 0)
            prev_block = getattr(self, '_prev_jit_block', 0)
            block_hist = getattr(self, '_jit_recent_blocks', [])
            self._1627_state_seq = []
            self._1627_entry_count = getattr(self, '_1627_entry_count', 0) + 1
            self._1627_trace_active = True
            self._1627_exec_count = 0
            self._install_1627_output_watch(uc, x0v)
            try:
                x1_blob = self._dump_mem_hex(uc, x1v, 0x20) if x1v > 0x1000 else "NA"
            except Exception:
                x1_blob = "ERR"
            caller_parts = []
            for slot_off in (0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70):
                try:
                    slot_val = struct.unpack("<Q", uc.mem_read(sp + slot_off, 8))[0]
                    caller_parts.append(f"[sp+{slot_off:#x}]={slot_val:#x}")
                except Exception as exc:
                    caller_parts.append(f"[sp+{slot_off:#x}]=ERR({exc})")
            for fp_off in (-0x90, -0x88, -0x80, -0x78, -0x70, -0x68, -0x60, -0x58):
                try:
                    slot_val = struct.unpack("<Q", uc.mem_read(fpv + fp_off, 8))[0]
                    caller_parts.append(f"[fp{fp_off:+#x}]={slot_val:#x}")
                except Exception as exc:
                    caller_parts.append(f"[fp{fp_off:+#x}]=ERR({exc})")
            def _safe_qword(addr):
                try:
                    return struct.unpack("<Q", uc.mem_read(addr, 8))[0]
                except Exception:
                    return 0

            ptr_parts = []
            for label, ptr in (
                ("x1", x1v),
                ("x22", x22v),
                ("x23", x23rv),
                ("sp+0x20", _safe_qword(sp + 0x20) if sp else 0),
                ("sp+0x30", _safe_qword(sp + 0x30) if sp else 0),
                ("sp+0x40", _safe_qword(sp + 0x40) if sp else 0),
                ("sp+0x48", _safe_qword(sp + 0x48) if sp else 0),
                ("fp-0x78", _safe_qword(fpv - 0x78) if fpv else 0),
                ("fp-0x68", _safe_qword(fpv - 0x68) if fpv else 0),
                ("fp-0x60", _safe_qword(fpv - 0x60) if fpv else 0),
            ):
                try:
                    if ptr <= 0x1000:
                        ptr_parts.append(f"{label}={ptr:#x}")
                        continue
                    head = self._dump_mem_hex(uc, ptr, 0x20)
                    plus28 = struct.unpack("<Q", uc.mem_read(ptr + 0x28, 8))[0]
                    ptr_parts.append(f"{label}={ptr:#x} head={head} [+0x28]={plus28:#x}")
                except Exception as exc:
                    ptr_parts.append(f"{label}={ptr:#x} ERR({exc})")
            ctx_vec = ""
            if x22v > 0x1000:
                try:
                    vec_b = self._safe_mem_read_qword(uc, x22v + 0xC8)
                    vec_c = self._safe_mem_read_qword(uc, x22v + 0xD0)
                    vec_e = self._safe_mem_read_qword(uc, x22v + 0xD8)
                    ctx_vec = (
                        f" ctx_vec=[{self._format_opt_hex(vec_b)},"
                        f"{self._format_opt_hex(vec_c)},"
                        f"{self._format_opt_hex(vec_e)}]"
                    )
                    if vec_b and vec_b > 0x1000:
                        ctx_vec += (
                            f" ctx_vec_first_raw={self._dump_mem_hex(uc, vec_b, 0x30)}"
                            f" ctx_vec_first_inline={self._read_c_string(uc, vec_b + 0x18, 0x18)!r}"
                        )
                    if vec_b and vec_c and vec_c - vec_b >= 0x30:
                        ctx_vec += (
                            f" ctx_vec_second_raw={self._dump_mem_hex(uc, vec_b + 0x30, 0x30)}"
                            f" ctx_vec_second_inline={self._read_c_string(uc, vec_b + 0x48, 0x18)!r}"
                        )
                except Exception as exc:
                    ctx_vec = f" ctx_vec=ERR({exc})"
            extra = (
                f" entry#{self._1627_entry_count}"
                f" x0={x0v:#x} x1={x1v:#x} x2={x2v:#x} x3={x3v:#x} x22={x22v:#x} x23={x23rv:#x}"
                f" lr={lrv:#x} fp={fpv:#x}"
                f" block={last_block - JIT_BASE if last_block >= JIT_BASE else last_block:#x}"
                f" prev_block={prev_block - JIT_BASE if prev_block >= JIT_BASE else prev_block:#x}"
                f" hist={[hex(b - JIT_BASE) if b >= JIT_BASE else hex(b) for b in block_hist[-8:]]}"
                f" x1mem={x1_blob}"
                f" {self._describe_1627_output_obj(uc, x0v)}"
                f"{ctx_vec}"
                f" caller={' '.join(caller_parts)}"
                f" ptrs={' ; '.join(ptr_parts)}"
            )
        elif off in (0x162a74, 0x162a84, 0x162ae0, 0x162aec, 0x162b04):
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x2v = uc.reg_read(UC_ARM64_REG_X2)
            x19v = uc.reg_read(UC_ARM64_REG_X19)
            x20v = uc.reg_read(UC_ARM64_REG_X20)
            x23v = uc.reg_read(UC_ARM64_REG_X23)
            precheck = self._dump_mem_hex(uc, x20v, 0x20) if x20v > 0x1000 else "NA"
            extra = (
                f" x0={x0v:#x} x1={x1v:#x} x2={x2v:#x} x19={x19v:#x} x20={x20v:#x} x23={x23v:#x}"
                f" x23+0x3a0={self._format_opt_hex(self._safe_mem_read_qword(uc, x23v + 0x3A0) if x23v > 0x1000 else None)}"
                f" x20_head={precheck}"
            )
            if off in (0x162ae0, 0x162aec, 0x162b04) and x20v > 0x1000:
                try:
                    cmp_bytes = bytes(uc.mem_read(x20v, 4))
                    extra += f" cmp_bytes={cmp_bytes!r}"
                except Exception as exc:
                    extra += f" cmp_bytes=ERR({exc})"
        elif off == 0x1627d8:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            self._1627_trace_active = True
            self._1627_exec_count = 0
            self._1627_live_hit_counts = {}
            self._1627_last_live_key = None
            self._1627_last_live_off = None
            try:
                obj_guess = struct.unpack("<Q", uc.mem_read(sp + 0x40, 8))[0]
            except Exception:
                obj_guess = 0
            try:
                src_a = struct.unpack("<Q", uc.mem_read(sp + 0x30, 8))[0]
            except Exception:
                src_a = 0
            try:
                src_b = struct.unpack("<Q", uc.mem_read(sp + 0x48, 8))[0]
            except Exception:
                src_b = 0
            if obj_guess:
                self._install_1627_output_watch(uc, obj_guess)
            extra = (
                f" x0={x0v:#x} x1={x1v:#x}"
                f" [sp+0x30]={src_a:#x}"
                f" [sp+0x40]={obj_guess:#x}"
                f" [sp+0x48]={src_b:#x}"
                f" {self._describe_1627_output_obj(uc, obj_guess)}"
            )
        elif off in (0x1702e8, 0x17039c, 0x1703a0, 0x170538, 0x17053c, 0x17061c, 0x170620):
            slot_addr = sp + 0x58
            if off == 0x1702e8 and getattr(self, '_1702_trace_active', False):
                self._install_1702_save_slot_watch(uc, slot_addr)
            saved_x21 = 0
            try:
                saved_x21 = struct.unpack("<Q", uc.mem_read(slot_addr, 8))[0]
            except Exception:
                saved_x21 = 0
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x8v = uc.reg_read(UC_ARM64_REG_X8)
            x21v = uc.reg_read(UC_ARM64_REG_X21)
            extra = (
                f" x0={x0v:#x} x8={x8v:#x} x21={x21v:#x}"
                f" save_slot={slot_addr:#x} saved_x21={saved_x21:#x}"
                f" x21_head={self._dump_mem_hex(uc, x21v, 0x20) if x21v > 0x1000 else 'NA'}"
                f" saved_head={self._dump_mem_hex(uc, saved_x21, 0x20) if saved_x21 > 0x1000 else 'NA'}"
            )
        elif off in (0x177728, 0x177730, 0x177740, 0x177770, 0x17777c, 0x177790, 0x1777a0, 0x1777ac, 0x1777b4, 0x1777c0, 0x1777d4, 0x1777dc, 0x1777e4, 0x1777f0, 0x177ebc, 0x177f04, 0x177f4c, 0x178040, 0x17804c, 0x1780cc, 0x1780d0, 0x178114, 0x1781c4, 0x178910, 0x1789cc, 0x1789d8, 0x178a30, 0x178b60, 0x178b70, 0x178b80, 0x178bfc, 0x178170, 0x1781a8):
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x8v = uc.reg_read(UC_ARM64_REG_X8)
            x19v = uc.reg_read(UC_ARM64_REG_X19)
            x20v = uc.reg_read(UC_ARM64_REG_X20)
            x21v = uc.reg_read(UC_ARM64_REG_X21)
            x22v = uc.reg_read(UC_ARM64_REG_X22)
            x23v = uc.reg_read(UC_ARM64_REG_X23)
            x27v = uc.reg_read(UC_ARM64_REG_X27)
            x28v = uc.reg_read(UC_ARM64_REG_X28)
            fpv = uc.reg_read(UC_ARM64_REG_X29)
            lrv = uc.reg_read(UC_ARM64_REG_X30)
            last_block = getattr(self, '_last_jit_block', 0)
            prev_block = getattr(self, '_prev_jit_block', 0)
            block_hist = getattr(self, '_jit_recent_blocks', [])
            try:
                local_a0 = self._dump_mem_hex(uc, fpv - 0xa0, 0x20) if fpv > 0x1000 else "NA"
            except Exception:
                local_a0 = "ERR"
            try:
                sp138 = self._dump_mem_hex(uc, sp + 0x138, 0x20)
            except Exception:
                sp138 = "ERR"
            x0_head = self._dump_mem_hex(uc, x0v, 0x20) if x0v > 0x1000 else "NA"
            x21_head = self._dump_mem_hex(uc, x21v, 0x20) if x21v > 0x1000 else "NA"
            x22_head = self._dump_mem_hex(uc, x22v, 0x20) if x22v > 0x1000 else "NA"
            extra = (
                f" x0={x0v:#x} x1={x1v:#x} x8={x8v:#x} x19={x19v:#x} x20={x20v:#x} x21={x21v:#x} x22={x22v:#x} x23={x23v:#x} x27={x27v:#x} x28={x28v:#x}"
                f" fp={fpv:#x} lr={lrv:#x}"
                f" block={last_block - JIT_BASE if last_block >= JIT_BASE else last_block:#x}"
                f" prev_block={prev_block - JIT_BASE if prev_block >= JIT_BASE else prev_block:#x}"
                f" hist={[hex(b - JIT_BASE) if b >= JIT_BASE else hex(b) for b in block_hist[-8:]]}"
                f" x0_head={x0_head}"
                f" x21_head={x21_head}"
                f" x22_head={x22_head}"
                f" [fp-0xa0]={local_a0}"
                f" [sp+0x138]={sp138}"
            )
            if (not LIVE_CERT_OVERLAY_ACTIVE and
                    off in (0x177790, 0x1777a0, 0x1777ac, 0x1777b4, 0x1777c0)):
                vec0 = self._safe_mem_read_qword(uc, x20v + 0x00) if x20v > 0x1000 else None
                vec8 = self._safe_mem_read_qword(uc, x20v + 0x08) if x20v > 0x1000 else None
                vec10 = self._safe_mem_read_qword(uc, x20v + 0x10) if x20v > 0x1000 else None
                x23_head = self._dump_mem_hex(uc, x23v, 0x20) if x23v > 0x1000 else "NA"
                extra += (
                    f" cand_vec=[{self._format_opt_hex(vec0)},{self._format_opt_hex(vec8)},{self._format_opt_hex(vec10)}]"
                    f" range_empty={'YES' if vec8 == vec10 else 'NO'}"
                    f" x23_head={x23_head}"
                )
            if off == 0x1777d4:
                callee_x21_slot = sp - 0x28
                self._1702_trace_active = True
                self._install_1702_save_slot_watch(uc, callee_x21_slot)
                extra += (
                    f" callee_pair={self._dump_mem_hex(uc, callee_x21_slot - 8, 0x10)}"
                )
            elif off == 0x1777dc:
                callee_x21_slot = sp - 0x28
                extra += (
                    f" callee_pair={self._dump_mem_hex(uc, callee_x21_slot - 8, 0x10)}"
                )
                self._1702_trace_active = False
            if off in (0x177ebc, 0x177f04, 0x177f4c, 0x178040, 0x17804c, 0x1780cc, 0x1780d0, 0x178114, 0x1781c4, 0x178910, 0x1789cc, 0x1789d8, 0x178a30, 0x178b60, 0x178b70, 0x178b80, 0x178bfc):
                def _fmt_triplet(base):
                    if base <= 0x1000:
                        return f"{base:#x}"
                    return (
                        f"[{self._format_opt_hex(self._safe_mem_read_qword(uc, base + 0x0))},"
                        f"{self._format_opt_hex(self._safe_mem_read_qword(uc, base + 0x8))},"
                        f"{self._format_opt_hex(self._safe_mem_read_qword(uc, base + 0x10))}]"
                    )
                sess88 = self._describe_sso_slot(uc, x21v + 0x88) if x21v > 0x1000 else "NA"
                sess1f8 = self._describe_sso_slot(uc, x21v + 0x1F8) if x21v > 0x1000 else "NA"
                ctx_c8 = _fmt_triplet(x27v + 0xC8) if x27v > 0x1000 else "NA"
                ctx_d0 = _fmt_triplet(x27v + 0xD0) if x27v > 0x1000 else "NA"
                x28_range = _fmt_triplet(x28v) if x28v > 0x1000 else "NA"
                x19_range = _fmt_triplet(x19v) if x19v > 0x1000 else "NA"
                extra += (
                    f" sess+0x88={sess88}"
                    f" sess+0x1f8={sess1f8}"
                    f" x28_rng={x28_range}"
                    f" x19_rng={x19_range}"
                    f" ctx+0xc8={ctx_c8}"
                    f" ctx+0xd0={ctx_d0}"
                )
                if off in (0x178040, 0x17804c):
                    extra += (
                        f" sp+0x6e0={self._describe_sso_slot(uc, sp + 0x6E0)}"
                        f" sp+0x840={self._describe_sso_slot(uc, sp + 0x840)}"
                    )
                if off in (0x1780cc, 0x1780d0, 0x178114, 0x1781c4, 0x178910, 0x1789cc, 0x1789d8, 0x178a30, 0x178b60, 0x178b70, 0x178b80, 0x178bfc):
                    extra += (
                        f" sp+0x420={self._describe_sso_slot(uc, sp + 0x420)}"
                        f" sp+0x840={self._describe_sso_slot(uc, sp + 0x840)}"
                        f" sp+0x980={self._describe_sso_slot(uc, sp + 0x980)}"
                        f" sp+0x5a0={self._describe_sso_slot(uc, sp + 0x5A0)}"
                        f" sp+0x6e0={self._describe_sso_slot(uc, sp + 0x6E0)}"
                    )
                    vec_begin = self._safe_mem_read_qword(uc, x27v + 0xC8) if x27v > 0x1000 else None
                    if vec_begin and vec_begin > 0x1000:
                        extra += (
                            f" ctx_vec_first_raw={self._dump_mem_hex(uc, vec_begin, 0x30)}"
                            f" ctx_vec_first_inline={self._read_c_string(uc, vec_begin + 0x18, 0x18)!r}"
                        )
                if off in (0x178a30, 0x178b60, 0x178bfc):
                    x9v = uc.reg_read(UC_ARM64_REG_X9)
                    x10v = uc.reg_read(UC_ARM64_REG_X10)
                    x11v = uc.reg_read(UC_ARM64_REG_X11)
                    extra += (
                        f" x22_slot={self._describe_sso_slot(uc, x22v) if x22v > 0x1000 else 'NA'}"
                        f" x9_str={self._read_c_string(uc, x9v, 0x40)!r}"
                        f" x10_str={self._read_c_string(uc, x10v, 0x40)!r}"
                        f" x11_len={x11v:#x}"
                    )
        elif off in (0x1654ec, 0x165548, 0x165588, 0x16565c, 0x16567c, 0x165690, 0x165694, 0x1656b8, 0x1656bc, 0x1656f0, 0x1658a8):
            if off == 0x16565c:
                try:
                    raw40c = bytes(uc.mem_read(sp + 0x40C, 0x41))
                except Exception:
                    raw40c = b""
                if raw40c[:1] == b"\x00":
                    tail = raw40c[1:64]
                    if len(tail) == 63 and all(48 <= b <= 57 or 97 <= b <= 102 for b in tail):
                        uc.mem_write(sp + 0x40C, b"0")
                        print(
                            f"[SP40C-FIX] restored leading '0' at {sp + 0x40C:#x} "
                            f"tail={tail[:16]!r}...",
                            flush=True,
                        )
            if off in (0x1656bc, 0x1656f0):
                repaired = self._repair_shifted_hex_cstr(uc, sp + 0x3E8)
                if repaired is not None:
                    start, run_len, preview = repaired
                    print(
                        f"[SP3E8-FIX] shifted hex run from +{start:#x} len={run_len} "
                        f"at {sp + 0x3E8:#x} preview={preview!r}",
                        flush=True,
                    )
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x2v = uc.reg_read(UC_ARM64_REG_X2)
            x3v = uc.reg_read(UC_ARM64_REG_X3)
            x5v = uc.reg_read(UC_ARM64_REG_X5)
            x19v = uc.reg_read(UC_ARM64_REG_X19)
            x20v = uc.reg_read(UC_ARM64_REG_X20)
            x22v = uc.reg_read(UC_ARM64_REG_X22)
            x25v = uc.reg_read(UC_ARM64_REG_X25)
            x26v = uc.reg_read(UC_ARM64_REG_X26)
            sp40c = self._read_c_string(uc, sp + 0x40C, 0x80)
            sp3e8 = self._read_c_string(uc, sp + 0x3E8, 0x80)
            ctx_c8 = "NA"
            if x22v > 0x1000:
                ctx_c8 = (
                    f"[{self._format_opt_hex(self._safe_mem_read_qword(uc, x22v + 0xC8))},"
                    f"{self._format_opt_hex(self._safe_mem_read_qword(uc, x22v + 0xD0))},"
                    f"{self._format_opt_hex(self._safe_mem_read_qword(uc, x22v + 0xD8))}]"
                )
            extra = (
                f" x0={x0v:#x} x1={x1v:#x} x2={x2v:#x} x3={x3v:#x} x5={x5v:#x}"
                f" x19={x19v:#x} x20={x20v:#x} x22={x22v:#x} x25={x25v:#x} x26={x26v:#x}"
                f" sp+0x40c={sp40c!r} sp+0x40c_hex={self._dump_mem_hex(uc, sp + 0x40C, 0x40)}"
                f" sp+0x3e8={sp3e8!r} sp+0x3e8_hex={self._dump_mem_hex(uc, sp + 0x3E8, 0x40)}"
                f" sp+0x248={self._describe_sso_slot(uc, sp + 0x248)}"
                f" sp+0x378={self._describe_sso_slot(uc, sp + 0x378)}"
                f" sp+0x4c0={self._describe_sso_slot(uc, sp + 0x4C0)}"
                f" ctx+0xc8={ctx_c8}"
            )
        elif off == 0x1627f0:
            try:
                obj_guess = struct.unpack("<Q", uc.mem_read(sp + 0x40, 8))[0]
            except Exception:
                obj_guess = 0
            extra = self._describe_1627_output_obj(uc, obj_guess)
        elif off == 0x162b9c:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            extra = (
                f" x0={x0v:#x}"
                f" cand+0x98={self._dump_mem_hex(uc, x0v + 0x98, 0x20) if x0v > 0x1000 else 'NA'}"
                f" cand+0xa0={self._describe_sso_slot(uc, x0v + 0xa0) if x0v > 0x1000 else 'NA'}"
            )
        elif off == 0x162bcc:
            try:
                cand = struct.unpack("<Q", uc.mem_read(sp + 0x50, 8))[0]
                type_word = struct.unpack("<I", uc.mem_read(cand + 4, 4))[0] if cand > 0x1000 else 0
            except Exception:
                cand = 0
                type_word = 0
            extra = f" cand={cand:#x} type={type_word:#x}"
        elif off == 0x162bf4:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            try:
                cand = struct.unpack("<Q", uc.mem_read(sp + 0x50, 8))[0]
            except Exception:
                cand = 0
            extra = (
                f" x0={x0v:#x} cand={cand:#x}"
                f" obj_before={self._describe_1627_output_obj(uc, x0v)}"
            )
        elif off == 0x162c40:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x8v = uc.reg_read(UC_ARM64_REG_X8)
            extra = (
                f" cb_x0={x0v:#x} cb_x1={x1v:#x} target={x8v:#x}"
                f" obj={self._describe_1627_output_obj(uc, x0v)}"
            )
        elif off == 0x162c44:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            obj = getattr(self, '_1627_watch_obj', 0)
            extra = f" ret={x0v:#x} {'NULL' if x0v == 0 else 'NONNULL'} {self._describe_1627_output_obj(uc, obj)}"
        elif off == 0x162c5c:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            extra = f" ret={x0v:#x} branch={'NULL->failure-state' if x0v == 0 else 'NONNULL->populate'}"
        elif off == 0x162d68:
            state = uc.reg_read(UC_ARM64_REG_X10) & 0xFFFFFFFF
            state_seq = getattr(self, '_1627_state_seq', [])
            if not state_seq or state_seq[-1] != state:
                state_seq = state_seq + [state]
                self._1627_state_seq = state_seq[-64:]
            try:
                sp28 = struct.unpack("<I", uc.mem_read(sp + 0x28, 4))[0]
            except Exception as exc:
                sp28 = f"ERR({exc})"
            try:
                sp50 = struct.unpack("<Q", uc.mem_read(sp + 0x50, 8))[0]
            except Exception as exc:
                sp50 = f"ERR({exc})"
            try:
                sp58 = struct.unpack("<Q", uc.mem_read(sp + 0x58, 8))[0]
            except Exception as exc:
                sp58 = f"ERR({exc})"
            try:
                sp60 = struct.unpack("<Q", uc.mem_read(sp + 0x60, 8))[0]
            except Exception as exc:
                sp60 = f"ERR({exc})"
            try:
                sp68 = struct.unpack("<Q", uc.mem_read(sp + 0x68, 8))[0]
            except Exception as exc:
                sp68 = f"ERR({exc})"
            try:
                sp70 = struct.unpack("<Q", uc.mem_read(sp + 0x70, 8))[0]
            except Exception as exc:
                sp70 = f"ERR({exc})"
            extra = (
                f" state={state:#010x}"
                f" seq_len={len(getattr(self, '_1627_state_seq', []))}"
                f" w19={uc.reg_read(UC_ARM64_REG_X19) & 0xFFFFFFFF:#x}"
                f" w22={uc.reg_read(UC_ARM64_REG_X22) & 0xFFFFFFFF:#x}"
                f" [sp+0x28]={sp28}"
                f" [sp+0x50]={sp50}"
                f" [sp+0x58]={sp58}"
                f" [sp+0x60]={sp60}"
                f" [sp+0x68]={sp68}"
                f" [sp+0x70]={sp70}"
            )
        elif off == 0x162850:
            try:
                idx = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM64_REG_X29) - 0x94, 4))[0]
            except Exception as exc:
                idx = f"ERR({exc})"
            extra = (
                f" idx={idx}"
                f" next_state={uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF:#010x}"
                f" alt_state={uc.reg_read(UC_ARM64_REG_X13) & 0xFFFFFFFF:#010x}"
            )
        elif off == 0x162eec:
            obj = uc.reg_read(UC_ARM64_REG_X11)
            if obj:
                self._install_1627_output_watch(uc, obj)
            extra = self._describe_1627_output_obj(uc, obj)
        elif off == 0x163344:
            obj = getattr(self, '_1627_watch_obj', 0)
            state_seq = getattr(self, '_1627_state_seq', [])
            self._1627_trace_active = False
            extra = (
                f" w0={w0:#x}"
                f" states={'->'.join(f'{s:#010x}' for s in state_seq[-16:]) if state_seq else 'NONE'}"
                f" {self._describe_1627_output_obj(uc, obj)}"
            )
        elif off in (0x16bb2c, 0x16bb34, 0x16bb38, 0x16bb40, 0x16bb84):
            fpv = uc.reg_read(UC_ARM64_REG_X29)
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x2v = uc.reg_read(UC_ARM64_REG_X2)
            try:
                sha_obj = struct.unpack("<Q", uc.mem_read(fpv - 0x88, 8))[0]
            except Exception:
                sha_obj = 0
            try:
                sha_ret_a = struct.unpack("<Q", uc.mem_read(fpv - 0x70, 8))[0]
            except Exception:
                sha_ret_a = 0
            try:
                sha_ret_b = struct.unpack("<Q", uc.mem_read(fpv - 0x68, 8))[0]
            except Exception:
                sha_ret_b = 0
            obj_head = self._dump_mem_hex(uc, sha_obj, 0x40) if sha_obj > 0x1000 else "NA"
            src_head = self._dump_mem_hex(uc, x1v, 0x20) if x1v > 0x1000 else "NA"
            extra = (
                f" x0={x0v:#x} x1={x1v:#x} x2={x2v:#x} fp={fpv:#x}"
                f" sha_obj={sha_obj:#x} sha_ret_a={sha_ret_a:#x} sha_ret_b={sha_ret_b:#x}"
                f" sha_obj_head={obj_head}"
            )
            if off == 0x16bb2c:
                extra += f" sha_src_head={src_head}"
        elif off == 0x11cae0:
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x2v = uc.reg_read(UC_ARM64_REG_X2)
            x8v = uc.reg_read(UC_ARM64_REG_X8)
            sp_2f0 = self._safe_mem_read_qword(uc, sp + 0x2f0) or 0
            sp_1f8 = self._safe_mem_read_qword(uc, sp + 0x1f8) or 0
            x25v = uc.reg_read(UC_ARM64_REG_X25)
            trunc_count = len(getattr(self, '_trunc_source_data', []))
            extra = (
                f" x0={x0v:#x} x1={x1v:#x} x2={x2v:#x} x8={x8v:#x}"
                f" sp+0x2f0={sp_2f0:#x} sp+0x1f8={sp_1f8:#x} x25={x25v:#x}"
                f" trunc_records={trunc_count}"
            )
        elif off == 0x11cae4:
            # Just returned from 0x1627d8 - check sp+0x810 (output)
            extra = f" sp+0x810={self._dump_mem_hex(uc, sp + 0x810, 32)} sp+0x560={self._dump_mem_hex(uc, sp + 0x560, 24)} w0={w0:#x}"
        elif off == 0x11cb28:
            # About to copy sp+0x810 → sp+0x560 via str q0,[x9,#0x1a0]
            extra = f" sp+0x810={self._dump_mem_hex(uc, sp + 0x810, 32)} sp+0x560={self._dump_mem_hex(uc, sp + 0x560, 24)}"
        elif off == 0x149054:
            x19v = uc.reg_read(UC_ARM64_REG_X19)
            x20v = uc.reg_read(UC_ARM64_REG_X20)
            x26v = uc.reg_read(UC_ARM64_REG_X26)
            total_len = self._safe_mem_read_qword(uc, sp + 664) or 0
            tail_ptr = sp + 0x7B0
            soc_bytes = b""
            heap_prefix = b""
            tail_bytes = b""
            if 0 < x19v <= 0x80 and x26v > 0x1000:
                try:
                    soc_bytes = self._read_bytes_with_fallback(uc, x26v, x19v)
                except Exception:
                    soc_bytes = b""
            if 0 < x19v <= 0x80 and x20v > 0x1000:
                try:
                    heap_prefix = self._read_bytes_with_fallback(uc, x20v, x19v)
                except Exception:
                    heap_prefix = b""
            tail_len = 0x20
            if total_len and total_len > x19v:
                tail_len = min(0x20, total_len - x19v)
            if tail_len > 0:
                try:
                    tail_bytes = self._read_bytes_with_fallback(uc, tail_ptr, tail_len)
                except Exception:
                    tail_bytes = b""
            feeder40 = soc_bytes + tail_bytes
            self._cert_feeder_last = {
                "heap": x20v,
                "soc_len": x19v,
                "total_len": total_len,
                "soc": soc_bytes,
                "tail": tail_bytes,
                "feeder": feeder40,
            }
            extra = f" heap={x20v:#x} src={x26v:#x} soc_len={x19v:#x} total={total_len:#x}"
            print(
                f"[CERT-FEEDER-BUILD] heap={x20v:#x} src={x26v:#x} soc_len={x19v:#x} total={total_len:#x} "
                f"soc_ascii={soc_bytes.decode('ascii', errors='replace')!r} "
                f"soc_src={soc_bytes.hex()} heap_prefix={heap_prefix.hex()} "
                f"tail32={tail_bytes.hex()} feeder40={feeder40.hex()}",
                flush=True,
            )
            recent = self._format_recent_data_events(tail_ptr, max(tail_len, 0x20), limit=8)
            if recent:
                print(f"[CERT-FEEDER-BUILD-SRC] {recent}", flush=True)
        elif off == 0x14a4a4:
            msg_ptr = uc.reg_read(UC_ARM64_REG_X19)
            total_len = self._safe_mem_read_qword(uc, sp + 664) or 0
            msg = b""
            if msg_ptr > 0x1000 and 0 < total_len <= 0x100:
                try:
                    msg = self._read_bytes_with_fallback(uc, msg_ptr, total_len)
                except Exception:
                    msg = b""
            feeder_prev = getattr(self, "_cert_feeder_last", None) or {}
            soc_len = feeder_prev.get("soc_len", 0) or 0
            prefix = msg[:soc_len] if soc_len else b""
            tail = msg[soc_len:soc_len + 0x20] if soc_len else b""
            prev_msg = feeder_prev.get("feeder", b"")
            extra = f" msg={msg_ptr:#x} total={total_len:#x} prev_match={msg == prev_msg}"
            print(
                f"[CERT-FEEDER-FINAL] msg={msg_ptr:#x} total={total_len:#x} "
                f"prefix_ascii={prefix.decode('ascii', errors='replace')!r} "
                f"prefix={prefix.hex()} tail32={tail.hex()} full={msg.hex()} "
                f"prev_match={msg == prev_msg}",
                flush=True,
            )
            recent = self._format_recent_data_events(msg_ptr, min(total_len, 0x40) if total_len else 0x40, limit=8)
            if recent:
                print(f"[CERT-FEEDER-FINAL-SRC] {recent}", flush=True)
        elif off == 0x108480:
            # About to call 0x10875c — dump source+0x210 SSO and output buffer
            x1_val = uc.reg_read(UC_ARM64_REG_X1)
            x8_val = uc.reg_read(UC_ARM64_REG_X8)
            if not getattr(self, '_sha_input_watch_installed', False):
                base = x8_val - 0x2A0
                self._sha_input_watch_installed = True
                self._sha_input_watch_range = (base, base + 0x20)
                self._sha_input_write_count = 0
                self._sha_input_memcpy_count = 0
                self._sha_input_last_snapshot = ""
                print(
                    f"[SHA32-WATCH] base={base:#x} outbuf={x8_val:#x} cur={self._dump_mem_hex(uc, base, 0x20)}",
                    flush=True,
                )
                h = uc.hook_add(
                    UC_HOOK_MEM_WRITE,
                    self._sha_input_mem_write_hook,
                    begin=base,
                    end=base + 0x1F,
                )
                self._per_run_hooks.append(h)
            try:
                sso210 = bytes(uc.mem_read(x1_val + 0x210, 24))
                b0 = sso210[0]
                if b0 & 1:
                    sz = struct.unpack("<Q", sso210[8:16])[0]
                    ptr = struct.unpack("<Q", sso210[16:24])[0]
                    buf = bytes(uc.mem_read(ptr, min(sz, 64))) if ptr > 0x1000 else b""
                    extra = f" src+0x210=HEAP(sz={sz},ptr={ptr:#x}) data={buf.hex()}"
                else:
                    slen = b0 >> 1
                    s = sso210[1:1+slen]
                    extra = f" src+0x210=SSO({slen})={s!r}"
            except Exception as e:
                extra = f" src+0x210=ERR({e})"
            extra += f" outbuf_before={self._dump_mem_hex(uc, x8_val, 24)}"
        elif off == 0x108484:
            # Just returned from 0x10875c — check what's at sp+0x50 (output buffer)
            extra = f" sp+0x50={self._dump_mem_hex(uc, sp + 0x50, 24)} sp+0x60={self._dump_mem_hex(uc, sp + 0x60, 8)}"
        elif off == 0x108630:
            # About to copy sp+0x50 to obj+0x68 — show what's being copied
            x20_val = uc.reg_read(UC_ARM64_REG_X20)
            extra = f" sp+0x50={self._dump_mem_hex(uc, sp + 0x50, 24)} dst(x20)={x20_val:#x}"
        elif off in (0x10886c, 0x108fc0):
            if not getattr(self, '_src48_watch_installed', False):
                base = sp - 0x458
                self._src48_watch_installed = True
                self._src48_watch_range = (base, base + 0x30)
                self._src48_write_count = 0
                self._src48_memcpy_count = 0
                self._src48_raw_writes = bytearray(0x30)
                print(
                    f"[SRC48-WATCH] base={base:#x} sp={sp:#x} cur={self._dump_mem_hex(uc, base, 0x30)}",
                    flush=True,
                )
                h = uc.hook_add(
                    UC_HOOK_MEM_WRITE,
                    self._src48_mem_write_hook,
                    begin=base,
                    end=base + 0x2F,
                )
                self._per_run_hooks.append(h)
            slot2f0 = self._safe_mem_read_qword(uc, sp + 0x2f0) or 0
            slot2f8 = self._safe_mem_read_qword(uc, sp + 0x2f8) or 0
            extra = f" sp={sp:#x} slot2f0={slot2f0:#x} slot2f8={slot2f8:#x}"
            try:
                extra += f" slot2f0_sso={self._describe_sso_slot(uc, slot2f0)}"
            except Exception as exc:
                extra += f" slot2f0_sso=ERR({exc})"
        elif off == 0x10935c:
            slot2f0 = self._safe_mem_read_qword(uc, sp + 0x2f0) or 0
            slot2f8 = self._safe_mem_read_qword(uc, sp + 0x2f8) or 0
            extra = (
                f" sp={sp:#x}"
                f" sp+0x620={self._dump_mem_hex(uc, sp + 0x620, 24)}"
                f" slot2f0={slot2f0:#x}"
                f" slot2f8={slot2f8:#x}"
            )
            try:
                extra += f" slot2f0_sso={self._describe_sso_slot(uc, slot2f0)}"
            except Exception as exc:
                extra += f" slot2f0_sso=ERR({exc})"
        elif off == 0x10939c:
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x2v = uc.reg_read(UC_ARM64_REG_X2)
            extra = (
                f" sp={sp:#x}"
                f" dest(sp+0x810)={self._dump_mem_hex(uc, sp + 0x810, 24)}"
                f" merged(sp+0x620)={self._dump_mem_hex(uc, sp + 0x620, 24)}"
                f" src_ptr={x1v:#x} len={x2v:#x}"
            )
            if x1v:
                extra += f" src_head={self._dump_mem_hex(uc, x1v, min(x2v, 0x40) if x2v else 0x10)}"
        elif off == 0x1093a0:
            extra = (
                f" sp={sp:#x}"
                f" sp+0x810={self._dump_mem_hex(uc, sp + 0x810, 24)}"
                f" sp+0x940={self._dump_mem_hex(uc, sp + 0x940, 24)}"
                f" sp+0x578={self._dump_mem_hex(uc, sp + 0x578, 24)}"
            )
        elif off in (0x10e41c, 0x113454, 0x1134e8, 0x115a50, 0x115f24, 0x1173e4):
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x2v = uc.reg_read(UC_ARM64_REG_X2)
            extra = f" sp={sp:#x} x0={x0v:#x} x1={x1v:#x} x2={x2v:#x}"
            if x1v:
                head_len = min(x2v if x2v else 0x20, 0x40)
                extra += f" x1_head={self._dump_mem_hex(uc, x1v, head_len)}"
            extra += (
                f" sp+0x578={self._dump_mem_hex(uc, sp + 0x578, 24)}"
                f" sp+0x620={self._dump_mem_hex(uc, sp + 0x620, 24)}"
                f" sp+0x810={self._dump_mem_hex(uc, sp + 0x810, 32)}"
            )
        # 0x11cd1c was an old comparison-gate hook in earlier images. On the
        # current live image it is part of normal local cleanup, so do not
        # mutate registers there; keep a light diagnostic only.
        if off == 0x11cd1c:
            w19 = uc.reg_read(UC_ARM64_REG_X19) & 0xFFFFFFFF
            sp_2f0 = struct.unpack("<Q", uc.mem_read(sp + 0x2f0, 8))[0]
            sp_1f8 = struct.unpack("<Q", uc.mem_read(sp + 0x1f8, 8))[0]
            x25v = uc.reg_read(UC_ARM64_REG_X25)
            cnt = getattr(self, "_off_11cd1c_seen_hits", 0) + 1
            self._off_11cd1c_seen_hits = cnt
            if cnt <= 4:
                print(f"[11CD1C-SEEN #{cnt}] w19={w19:#x} sp+0x2f0={sp_2f0:#x}"
                      f" sp+0x1f8={sp_1f8:#x} x25={x25v:#x}", flush=True)
        # ---- 0x121634 entry diagnostic + fix
        if off == 0x121634:
            sp_2f0 = struct.unpack("<Q", uc.mem_read(sp + 0x2f0, 8))[0]
            sp_1f8 = struct.unpack("<Q", uc.mem_read(sp + 0x1f8, 8))[0]
            x25v = uc.reg_read(UC_ARM64_REG_X25)
            x22v = uc.reg_read(UC_ARM64_REG_X22)
            # FIX: Device has all-zeros at x25+0x130 (32 bytes).
            # The emulator's XOR block chain incorrectly populates this
            # with a non-zero SHA state. Zero it out to match device behavior.
            try:
                uc.mem_write(x25v + 0x130, b'\x00' * 32)
                print(f"[SHA-STATE-FIX] zeroed x25+0x130 (32 bytes) at {x25v+0x130:#x}", flush=True)
            except Exception as e:
                print(f"[SHA-STATE-FIX] error: {e}", flush=True)
            # Read SSO at sp+0x2f0 pointer
            sso_info = ""
            try:
                sso_ptr = sp_2f0
                if sso_ptr > 0x1000:
                    sso_hdr = bytes(uc.mem_read(sso_ptr, 24))
                    b0 = sso_hdr[0]
                    if b0 & 1:
                        sz = struct.unpack("<Q", sso_hdr[8:16])[0]
                        dp = struct.unpack("<Q", sso_hdr[16:24])[0]
                        d = bytes(uc.mem_read(dp, min(sz, 64))) if dp > 0x1000 else b""
                        sso_info = f"LONG({sz})={d.hex()[:80]}"
                    else:
                        slen = b0 >> 1
                        sso_info = f"SHORT({slen})={sso_hdr[1:1+slen].hex()}"
                else:
                    sso_info = f"INVALID_PTR({sso_ptr:#x})"
            except Exception as e:
                sso_info = f"ERR({e})"
            # Read x25+0x130 (32 bytes appended to hash input)
            x25_130 = ""
            try:
                x25_130 = bytes(uc.mem_read(x25v + 0x130, 32)).hex()
            except Exception as e:
                x25_130 = f"ERR({e})"
            print(f"[SHA256-ENTRY] At 0x121634: sp+0x2f0={sp_2f0:#x} SSO={sso_info}"
                  f" sp+0x1f8={sp_1f8:#x} x25={x25v:#x} x22={x22v:#x}"
                  f" [x25+0x130]={x25_130}", flush=True)
        if off == 0x14fa54:
            cnt = getattr(self, "_inline_sha_probe_hits", 0) + 1
            self._inline_sha_probe_hits = cnt
            owner = self._safe_mem_read_qword(uc, sp + 0x8) or 0
            owner390 = self._safe_mem_read_qword(uc, owner + 0x390) or 0 if owner else 0
            vec = self._safe_mem_read_qword(uc, sp + 0x30) or 0
            begin = self._safe_mem_read_qword(uc, vec + 0x0) or 0 if vec else 0
            end = self._safe_mem_read_qword(uc, vec + 0x8) or 0 if vec else 0
            cap = self._safe_mem_read_qword(uc, vec + 0x10) or 0 if vec else 0
            span = (end - begin) if begin and end and end >= begin else 0
            rec_count = (span // 0x130) if span and span < 0x100000 else 0
            x0v = uc.reg_read(UC_ARM64_REG_X0)
            x1v = uc.reg_read(UC_ARM64_REG_X1)
            x2v = uc.reg_read(UC_ARM64_REG_X2)
            x8v = uc.reg_read(UC_ARM64_REG_X8)
            x10v = uc.reg_read(UC_ARM64_REG_X10)
            x19v = uc.reg_read(UC_ARM64_REG_X19)
            x20v = uc.reg_read(UC_ARM64_REG_X20)
            x21v = uc.reg_read(UC_ARM64_REG_X21)
            x22v = uc.reg_read(UC_ARM64_REG_X22)
            x25v = uc.reg_read(UC_ARM64_REG_X25)
            sha_len = x19v if 0 < x19v <= 0x4000 else 0
            sha_head = self._dump_mem_hex_fallback(uc, x0v, min(sha_len, 0x80)) if sha_len and x0v > 0x1000 else ""
            sha_digest = None
            sha_mid24 = ""
            if sha_len and x0v > 0x1000:
                try:
                    sha_buf = self._read_bytes_with_fallback(uc, x0v, sha_len)
                    sha_digest = hashlib.sha256(sha_buf).digest()
                    sha_mid24 = sha_digest[4:28].hex()
                except Exception:
                    sha_digest = None
            focus_addr = x0v if sha_len and x0v > 0x1000 else (begin or owner390 or vec)
            focus_size = min(sha_len if sha_len else (span if 0 < span <= 0x1000 else 0x200), 0x400)
            print(
                f"[INLINE-SHA-ENTRY #{cnt}] sp={sp:#x} x0={x0v:#x} x1={x1v:#x} x2={x2v:#x} "
                f"x8={x8v:#x} x10={x10v:#x} x19={x19v:#x} x20={x20v:#x} x21={x21v:#x} "
                f"x22={x22v:#x} x25={x25v:#x} owner={owner:#x} owner390={owner390:#x} "
                f"vec={vec:#x} begin={begin:#x} end={end:#x} cap={cap:#x} span={span:#x} recs={rec_count}",
                flush=True,
            )
            if sha_head:
                print(
                    f"[INLINE-SHA-X0 #{cnt}] len={sha_len:#x} head={sha_head}"
                    + (f" digest={sha_digest.hex()} mid24={sha_mid24}" if sha_digest is not None else ""),
                    flush=True,
                )
            if owner390:
                print(
                    f"[INLINE-SHA-OWNER390 #{cnt}] head={self._dump_mem_hex_fallback(uc, owner390, 0x40)}",
                    flush=True,
                )
            if begin and span:
                print(
                    f"[INLINE-SHA-BLOCK #{cnt}] begin={begin:#x} head={self._dump_mem_hex_fallback(uc, begin, min(span, 0x80))}",
                    flush=True,
                )
                for idx in range(min(rec_count, 2)):
                    rec = begin + idx * 0x130
                    f100 = self._safe_mem_read_u32(uc, rec + 0x100)
                    f104 = self._safe_mem_read_u32(uc, rec + 0x104)
                    f118 = self._safe_mem_read_u8(uc, rec + 0x118)
                    print(
                        f"[INLINE-SHA-REC #{cnt}.{idx}] rec={rec:#x} "
                        f"[+0x100]={self._format_opt_hex(f100)} [+0x104]={self._format_opt_hex(f104)} "
                        f"[+0x118]={self._format_opt_hex(f118)} head={self._dump_mem_hex_fallback(uc, rec, 0x40)}",
                        flush=True,
                    )
            recent = self._format_recent_data_events(focus_addr, focus_size, limit=10)
            if recent:
                print(f"[INLINE-SHA-FEED #{cnt}] {recent}", flush=True)
            watch_begin = 0
            watch_end = 0
            if sha_len and x0v > 0x1000:
                watch_begin = x0v
                watch_end = x0v + min(sha_len, 0x180)
            elif begin and span:
                watch_begin = begin
                watch_end = min(end, begin + min(span, 0x260))
            if watch_begin and watch_end and not getattr(self, "_inline_sha_read_watch_installed", False):
                if watch_end > watch_begin:
                    self._inline_sha_read_watch_installed = True
                    self._inline_sha_read_watch_range = (watch_begin, watch_end)
                    self._inline_sha_read_count = 0
                    h = uc.hook_add(
                        UC_HOOK_MEM_READ,
                        self._inline_sha_mem_read_hook,
                        begin=watch_begin,
                        end=watch_end - 1,
                    )
                    self._per_run_hooks.append(h)
                    print(
                        f"[INLINE-SHA-WATCH] begin={watch_begin:#x} end={watch_end:#x} "
                        f"span={watch_end - watch_begin:#x}",
                        flush=True,
                    )
            if watch_begin and watch_end and not getattr(self, "_inline_sha_write_watch_installed", False):
                if watch_end > watch_begin:
                    self._inline_sha_write_watch_installed = True
                    self._inline_sha_write_watch_range = (watch_begin, watch_end)
                    self._inline_sha_write_count = 0
                    h = uc.hook_add(
                        UC_HOOK_MEM_WRITE,
                        self._inline_sha_mem_write_hook,
                        begin=watch_begin,
                        end=watch_end - 1,
                    )
                    self._per_run_hooks.append(h)
                    print(
                        f"[INLINE-SHA-WATCH-WR] begin={watch_begin:#x} end={watch_end:#x} "
                        f"span={watch_end - watch_begin:#x}",
                        flush=True,
                    )
            if watch_begin and not getattr(self, "_sha_input_watch_installed", False):
                self._sha_input_watch_installed = True
                self._sha_input_watch_range = (watch_begin, watch_begin + 0x20)
                self._sha_input_write_count = 0
                self._sha_input_memcpy_count = 0
                self._sha_input_last_snapshot = ""
                print(
                    f"[SHA32-WATCH] base={watch_begin:#x} sp={sp:#x} cur={self._dump_mem_hex_fallback(uc, watch_begin, 0x20)}",
                    flush=True,
                )
                h = uc.hook_add(
                    UC_HOOK_MEM_WRITE,
                    self._sha_input_mem_write_hook,
                    begin=watch_begin,
                    end=watch_begin + 0x1F,
                )
                self._per_run_hooks.append(h)
        elif off in (0x14b894, 0x14ba3c, 0x14cecc, 0x14d0e4, 0x14e5f8, 0x14f9f4):
            cnt_key = f"sha32_src_{off:x}"
            cnt = getattr(self, cnt_key, 0) + 1
            setattr(self, cnt_key, cnt)
            if cnt <= 6:
                x0v = uc.reg_read(UC_ARM64_REG_X0)
                x1v = uc.reg_read(UC_ARM64_REG_X1)
                x2v = uc.reg_read(UC_ARM64_REG_X2)
                x19v = uc.reg_read(UC_ARM64_REG_X19)
                x20v = uc.reg_read(UC_ARM64_REG_X20)
                x21v = uc.reg_read(UC_ARM64_REG_X21)
                x22v = uc.reg_read(UC_ARM64_REG_X22)
                x23v = uc.reg_read(UC_ARM64_REG_X23)
                x24v = uc.reg_read(UC_ARM64_REG_X24)
                x25v = uc.reg_read(UC_ARM64_REG_X25)
                x26v = uc.reg_read(UC_ARM64_REG_X26)
                x27v = uc.reg_read(UC_ARM64_REG_X27)
                x28v = uc.reg_read(UC_ARM64_REG_X28)
                sha_watch = getattr(self, "_sha_input_watch_range", None)
                sha_lo = sha_watch[0] if sha_watch else 0
                sha_cur = self._dump_mem_hex_fallback(uc, sha_lo, 0x20) if sha_lo else "NA"
                ptrs = {
                    "x0": x0v,
                    "x1": x1v,
                    "x2": x2v,
                    "x19": x19v,
                    "x20": x20v,
                    "x21": x21v,
                    "x22": x22v,
                    "x23": x23v,
                    "x24": x24v,
                    "x25": x25v,
                    "x26": x26v,
                    "x27": x27v,
                    "x28": x28v,
                }
                parts = []
                for name, ptr in ptrs.items():
                    if ptr > 0x1000:
                        parts.append(f"{name}={ptr:#x}:{self._dump_mem_hex_fallback(uc, ptr, 0x20)}")
                    else:
                        parts.append(f"{name}={ptr:#x}")
                recent = self._format_recent_data_events(sha_lo, 0x20, limit=8) if sha_lo else ""
                print(
                    f"[SHA32-SRC #{cnt}] pc=JIT+{off:#x} sp={sp:#x} "
                    f"sha32@{sha_lo:#x}={sha_cur} "
                    f"w20={x20v & 0xFFFFFFFF:#x} w21={x21v & 0xFFFFFFFF:#x} "
                    f"w22={x22v & 0xFFFFFFFF:#x} w23={x23v & 0xFFFFFFFF:#x} "
                    f"w24={x24v & 0xFFFFFFFF:#x} w25={x25v & 0xFFFFFFFF:#x} "
                    + " ".join(parts),
                    flush=True,
                )
                if recent:
                    print(f"[SHA32-SRC-FEED #{cnt}] {recent}", flush=True)
        elif off in (0x14ff50, 0x1500b0, 0x1500c0):
            cnt = getattr(self, "_inline_sha_call_hits", 0) + 1
            self._inline_sha_call_hits = cnt
            if cnt <= 8:
                x0v = uc.reg_read(UC_ARM64_REG_X0)
                x1v = uc.reg_read(UC_ARM64_REG_X1)
                x2v = uc.reg_read(UC_ARM64_REG_X2)
                x3v = uc.reg_read(UC_ARM64_REG_X3)
                w1v = uc.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF
                w2v = uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
                w4v = uc.reg_read(UC_ARM64_REG_X4) & 0xFFFFFFFF
                x0_head = self._dump_mem_hex_fallback(uc, x0v, min(w1v, 0x80)) if x0v > 0x1000 and 0 < w1v <= 0x1000 else ""
                x3_head = self._dump_mem_hex_fallback(uc, x3v, min(w4v, 0x80)) if x3v > 0x1000 and 0 < w4v <= 0x1000 else ""
                if off == 0x1500b0:
                    state_ptr = x0v
                    chunk_ptr = x1v
                    chunk_len = x2v
                    chunk_head = self._dump_mem_hex_fallback(uc, chunk_ptr, min(chunk_len, 0x80)) if chunk_ptr > 0x1000 and 0 < chunk_len <= 0x1000 else ""
                    print(
                        f"[INLINE-SHA-CALL #{cnt}] pc=JIT+{off:#x} state={state_ptr:#x} chunk={chunk_ptr:#x} "
                        f"chunk_len={chunk_len:#x} state_head={self._dump_mem_hex_fallback(uc, state_ptr, 0x80) if state_ptr > 0x1000 else 'NA'} "
                        f"chunk_head={chunk_head}",
                        flush=True,
                    )
                elif off == 0x1500c0:
                    state_ptr = x0v
                    tail_ptr = x1v
                    tail_len = w2v
                    tail_head = self._dump_mem_hex_fallback(uc, tail_ptr, min(tail_len, 0x80)) if tail_ptr > 0x1000 and 0 < tail_len <= 0x1000 else ""
                    print(
                        f"[INLINE-SHA-CALL #{cnt}] pc=JIT+{off:#x} state={state_ptr:#x} tail={tail_ptr:#x} "
                        f"tail_len={tail_len:#x} state_head={self._dump_mem_hex_fallback(uc, state_ptr, 0x80) if state_ptr > 0x1000 else 'NA'} "
                        f"tail_head={tail_head}",
                        flush=True,
                    )
                else:
                    print(
                        f"[INLINE-SHA-CALL #{cnt}] pc=JIT+{off:#x} x0={x0v:#x} w1={w1v:#x} "
                        f"x3={x3v:#x} w4={w4v:#x} x2={x2v:#x} "
                        f"x0_head={x0_head} x3_head={x3_head}",
                        flush=True,
                    )
        elif off in (0x14fbb0, 0x14fc24):
            cnt = getattr(self, "_inline_sha_tail_hits", 0) + 1
            self._inline_sha_tail_hits = cnt
            if cnt <= 12:
                x0v = uc.reg_read(UC_ARM64_REG_X0)
                x2v = uc.reg_read(UC_ARM64_REG_X2)
                x13v = uc.reg_read(UC_ARM64_REG_X13)
                x16v = uc.reg_read(UC_ARM64_REG_X16)
                x18v = uc.reg_read(UC_ARM64_REG_X18)
                x26v = uc.reg_read(UC_ARM64_REG_X26)
                x27v = uc.reg_read(UC_ARM64_REG_X27)
                print(
                    f"[INLINE-SHA-TAIL #{cnt}] pc=JIT+{off:#x} sp={sp:#x} x0={x0v:#x} x2={x2v:#x} "
                    f"x13={x13v:#x} x16={x16v:#x} x18={x18v:#x} x26={x26v:#x} x27={x27v:#x} "
                    f"sp+0x30={self._safe_mem_read_qword(uc, sp + 0x30) or 0:#x} "
                    f"sp+0x40={self._safe_mem_read_qword(uc, sp + 0x40) or 0:#x} "
                    f"sp+0x48={self._safe_mem_read_qword(uc, sp + 0x48) or 0:#x}",
                    flush=True,
                )
        elif off in (0x1501a0, 0x1503ec, 0x150504, 0x1505b4):
            cnt = getattr(self, "_inline_sha_state_hits", 0) + 1
            self._inline_sha_state_hits = cnt
            if cnt <= 12:
                x0v = uc.reg_read(UC_ARM64_REG_X0)
                x1v = uc.reg_read(UC_ARM64_REG_X1)
                x2v = uc.reg_read(UC_ARM64_REG_X2)
                state_buf_len = 0
                state_total_len = 0
                state_head = "NA"
                if x0v > 0x1000:
                    state_buf_len = self._safe_mem_read_u32(uc, x0v + 0x60) or 0
                    state_total_len = self._safe_mem_read_qword(uc, x0v + 0x68) or 0
                    state_head = self._dump_mem_hex_fallback(uc, x0v, 0x80)
                state_buf = (
                    self._dump_mem_hex_fallback(uc, x0v + 0x40, min(state_buf_len, 0x80))
                    if x0v > 0x1000 and state_buf_len
                    else ""
                )
                tail_head = (
                    self._dump_mem_hex_fallback(uc, x1v, min(x2v, 0x80))
                    if x1v > 0x1000 and 0 < x2v <= 0x1000
                    else ""
                )
                sp_tail_ptr = self._safe_mem_read_qword(uc, sp + 0x20) or 0
                entry_tail = (
                    self._dump_mem_hex_fallback(uc, sp_tail_ptr, min(x2v, 0x80))
                    if sp_tail_ptr > 0x1000 and 0 < x2v <= 0x1000
                    else ""
                )
                digest_words = (
                    self._dump_mem_hex_fallback(uc, x0v + 0x20, 0x30)
                    if x0v > 0x1000
                    else ""
                )
                print(
                    f"[INLINE-SHA-STATE #{cnt}] pc=JIT+{off:#x} sp={sp:#x} "
                    f"x0={x0v:#x} x1={x1v:#x} x2={x2v:#x} "
                    f"buf_len=[x0+0x60]={state_buf_len:#x} total=[x0+0x68]={state_total_len:#x} "
                    f"sp+0x20={sp_tail_ptr:#x}",
                    flush=True,
                )
                print(
                    f"[INLINE-SHA-STATE #{cnt} DATA] state_head={state_head} "
                    f"state_buf={state_buf} tail={tail_head} sp_tail={entry_tail} digest_area={digest_words}",
                    flush=True,
                )
        # ---- STRLEN fast-forward at 0x131290: scans [x20+x8] for NUL
        if off == 0x131290:
            x20 = uc.reg_read(UC_ARM64_REG_X20)
            x8 = uc.reg_read(UC_ARM64_REG_X8)
            x10 = uc.reg_read(UC_ARM64_REG_X10)
            x21 = uc.reg_read(UC_ARM64_REG_X21)
            if x8 == 0:  # first entry only
                try:
                    buf = bytes(uc.mem_read(x20, 0x20000))
                    nul_pos = buf.index(0)
                except (ValueError, Exception):
                    nul_pos = -1
                if nul_pos >= 0 and nul_pos > 64:
                    # Fast-forward: set x8 = nul_pos + 1, x10 += nul_pos * x21, w9 = 0
                    new_x8 = nul_pos + 1
                    new_x10 = (x10 + nul_pos * x21) & 0xFFFFFFFFFFFFFFFF
                    uc.reg_write(UC_ARM64_REG_X8, new_x8)
                    uc.reg_write(UC_ARM64_REG_X10, new_x10)
                    uc.reg_write(UC_ARM64_REG_X9, 0)  # NUL byte
                    print(f"[STRLEN-FF] Fast-forwarded strlen at x20={x20:#x}, len={nul_pos}", flush=True)
                    uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x1312a0)
                    return
        # ---- XOR-SCRAMBLER fast-forward: Loop 1 at 0x132528
        # key[i] ^= (src_byte >> 1), i = (i+1) % 8, for x8 iterations
        if off == 0x132528:
            x11 = uc.reg_read(UC_ARM64_REG_X11)
            x8_count = uc.reg_read(UC_ARM64_REG_X8)
            x18 = uc.reg_read(UC_ARM64_REG_X18)
            w9 = uc.reg_read(UC_ARM64_REG_X9) & 0xFF
            if x8_count > 64:
                key_ptr = self._resolve_mem_addr(uc, x18)
                src_ptr = self._resolve_mem_addr(uc, x11)
                for off0 in range(0, x8_count, 0x1000):
                    self._tbi_map_page(uc, src_ptr + off0)
                key = bytearray(uc.mem_read(key_ptr, 8))
                src = bytes(uc.mem_read(src_ptr, x8_count))
                for b in src:
                    key[w9] ^= (b >> 1)
                    w9 = (w9 + 1) % 8
                uc.mem_write(key_ptr, bytes(key))
                uc.reg_write(UC_ARM64_REG_X11, x11 + x8_count)
                uc.reg_write(UC_ARM64_REG_X8, 0)
                uc.reg_write(UC_ARM64_REG_X9, w9)
                print(f"[XOR-SCRAMBLER-1] Fast-forwarded {x8_count} bytes, key={key.hex()}", flush=True)
                uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x132568)
                return
        # ---- XOR-SCRAMBLER fast-forward: Loop 2 at 0x132598
        # key[i] ^= src_byte, i = (i+1) % 8, for x9 iterations
        if off == 0x132598:
            x8_src = uc.reg_read(UC_ARM64_REG_X8)
            x9_count = uc.reg_read(UC_ARM64_REG_X9)
            x18 = uc.reg_read(UC_ARM64_REG_X18)
            w10 = uc.reg_read(UC_ARM64_REG_X10) & 0xFF
            if x9_count > 64:
                key_ptr = self._resolve_mem_addr(uc, x18)
                src_ptr = self._resolve_mem_addr(uc, x8_src)
                self._xor_pack_last_src = src_ptr
                for off0 in range(0, x9_count, 0x1000):
                    self._tbi_map_page(uc, src_ptr + off0)
                key = bytearray(uc.mem_read(key_ptr, 8))
                src = bytes(uc.mem_read(src_ptr, x9_count))
                for b in src:
                    key[w10] ^= b
                    w10 = (w10 + 1) % 8
                uc.mem_write(key_ptr, bytes(key))
                uc.reg_write(UC_ARM64_REG_X8, x8_src + x9_count)
                uc.reg_write(UC_ARM64_REG_X9, 0)
                uc.reg_write(UC_ARM64_REG_X10, w10)
                print(f"[XOR-SCRAMBLER-2] Fast-forwarded {x9_count} bytes, key={key.hex()}", flush=True)
                uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x1325ec)
                return
        # ---- POST-SCRAMBLER vector pack fast-forward at 0x13276c
        # The live helper uses x13 as the source span and x12 as the stack-local
        # destination scratch at fp-0xa8. A few broken runs collapsed those to
        # the 0x1 sentinel, so prefer the live registers and only fall back to
        # the frame-derived pointers if the register value is clearly bogus.
        if off == 0x13276c:
            x8_off = uc.reg_read(UC_ARM64_REG_X8)
            x9_off = uc.reg_read(UC_ARM64_REG_X9)
            raw_dst = uc.reg_read(UC_ARM64_REG_X12)
            raw_src = uc.reg_read(UC_ARM64_REG_X13)
            sp = uc.reg_read(UC_ARM64_REG_SP)
            fp = uc.reg_read(UC_ARM64_REG_X29)

            x12_dst = raw_dst
            x13_src = raw_src
            if x8_off > 0x40:
                x8_off = 0
            if x9_off > 0x40:
                x9_off = 0
            if x12_dst <= 0x1000:
                x12_dst = (fp - 0xA8) & 0xFFFFFFFFFFFFFFFF
            if x13_src <= 0x1000:
                x13_src = self._xor_pack_last_src or x13_src
            if x13_src <= 0x1000:
                try:
                    x13_src = struct.unpack("<Q", uc.mem_read(sp + 0xC8, 8))[0]
                except Exception:
                    x13_src = raw_src

            dst_ptr = self._resolve_mem_addr(uc, x12_dst)
            src_ptr = self._resolve_mem_addr(uc, x13_src)

            packed = b""
            cur_x8 = x8_off
            cur_x9 = x9_off
            while cur_x8 < 0x40:
                src_begin = src_ptr + cur_x9
                dst_read_begin = dst_ptr + cur_x9
                dst_write_begin = dst_ptr + cur_x8
                for page in (
                    src_begin & ~0xFFF,
                    dst_read_begin & ~0xFFF,
                    dst_write_begin & ~0xFFF,
                ):
                    self._tbi_map_page(uc, page)
                src_block = bytes(uc.mem_read(src_begin, 0x10))
                dst_block = bytes(uc.mem_read(dst_read_begin, 0x10))
                packed_block = bytes(a ^ b for a, b in zip(src_block, dst_block))
                if not packed:
                    packed = packed_block
                uc.mem_write(dst_write_begin, packed_block)
                cur_x8 += 0x10
                cur_x9 += 4

            uc.reg_write(UC_ARM64_REG_X8, cur_x8)
            uc.reg_write(UC_ARM64_REG_X9, cur_x9)
            print(
                f"[XOR-PACK-FF] raw_src={raw_src:#x} raw_dst={raw_dst:#x}"
                f" src={src_ptr:#x} dst={dst_ptr:#x} x8={x8_off:#x} x9={x9_off:#x}"
                f" saved_src={self._xor_pack_last_src:#x}"
                f" data={packed[:16].hex()}...",
                flush=True,
            )
            uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x1327d0)
            return
        # ---- BULK-XOR fast-forward at 0x56d04: outer loop of XOR decrypt
        # Inner loop XORs 0x4000 bytes (4-byte chunks) per round.
        # x8=round, x11=total_rounds, x0=ptr to dest ptr, x1=src base, w10=src offset
        # After loop: jump to 0x56d48 with final x8, w10
        if off == 0x56d04:
            x8 = uc.reg_read(UC_ARM64_REG_X8)
            x11 = uc.reg_read(UC_ARM64_REG_X11)
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            w10 = uc.reg_read(UC_ARM64_REG_X10) & 0xFFFFFFFF
            remaining = x11 - x8
            if remaining > 0:  # fast-forward any remaining rounds
                try:
                    dest_ptr = struct.unpack("<Q", uc.mem_read(x0, 8))[0]
                except Exception:
                    dest_ptr = 0
                if dest_ptr:
                    # Dump pre-XOR state of dest buffer
                    try:
                        pre_xor = bytes(uc.mem_read(dest_ptr, 32))
                        print(f"[BULK-XOR-PRE] dest_head_before_xor: {pre_xor.hex()}", flush=True)
                    except:
                        pass
                    # Check for src/dest overlap — the bump-allocator heap
                    # can place the dest buffer inside the nmsscr.nmss data
                    # that was written to the src buffer.  When overlap is
                    # detected, snapshot the original src data from the asset
                    # so memset corruption doesn't affect the XOR.
                    src_end = (x1 + (x11 << 14)) & 0xFFFFFFFFFFFFFFFF
                    asset_snapshot = None
                    if x1 <= dest_ptr < src_end:
                        overlap_round = (dest_ptr - x1) >> 14
                        file_offset = dest_ptr - x1
                        print(f"[BULK-XOR-OVERLAP] dest {dest_ptr:#x} inside src "
                              f"[{x1:#x}..{src_end:#x}], overlap at round {overlap_round} "
                              f"file_off=0x{file_offset:x}", flush=True)
                        # Find the nmsscr.nmss asset data to use as ground truth
                        for asset in getattr(self, '_jit_assets', {}).values():
                            if asset.get("name", "").endswith("nmsscr.nmss"):
                                asset_snapshot = asset["data"]
                                print(f"[BULK-XOR-OVERLAP] Using asset data "
                                      f"({len(asset_snapshot)} bytes) for overlap fix",
                                      flush=True)
                                break
                        if not asset_snapshot:
                            # Fallback: read from file
                            nmss_path = os.path.join(
                                os.path.dirname(os.path.abspath(__file__)),
                                "bins",
                            )
                            for f in os.listdir(nmss_path) if os.path.isdir(nmss_path) else ():
                                if f.endswith("_nmsscr.nmss"):
                                    asset_snapshot = open(os.path.join(nmss_path, f), "rb").read()
                                    print(f"[BULK-XOR-OVERLAP] Using file {f} "
                                          f"({len(asset_snapshot)} bytes) for overlap fix",
                                          flush=True)
                                    break
                    rounds_done = 0
                    cur_w10 = w10
                    cur_r = x8
                    for r in range(x8, x11):
                        inner_off = (r << 14) & 0xFFFFFFFF
                        inner_off_s = inner_off if inner_off < 0x80000000 else inner_off - 0x100000000
                        if (x1 + inner_off_s) & 0xFFFFFFFFFFFFFFFF == 0:
                            cur_w10 = (cur_w10 + 0x4000) & 0xFFFFFFFF
                            rounds_done += 1
                            cur_r = r + 1
                            continue
                        w10_s = cur_w10 if cur_w10 < 0x80000000 else cur_w10 - 0x100000000
                        src_addr = (x1 + w10_s) & 0xFFFFFFFFFFFFFFFF
                        # Use asset data for any round where heap corruption
                        # may have overwritten the nmsscr.nmss source buffer.
                        # The bump allocator places later allocations (dest buffer,
                        # etc.) INSIDE the nmsscr data, corrupting it.
                        src_file_off = w10_s if w10_s >= 0 else w10_s + 0x100000000
                        if (asset_snapshot is not None and
                                src_file_off + 0x4000 <= len(asset_snapshot)):
                            src_data = bytearray(asset_snapshot[src_file_off:src_file_off + 0x4000])
                        else:
                            try:
                                src_data = bytearray(self._read_bytes_with_fallback(uc, src_addr, 0x4000))
                            except Exception:
                                break
                        try:
                            dst_data = bytearray(self._read_bytes_with_fallback(uc, dest_ptr, 0x4000))
                        except Exception:
                            break  # unmapped → stop, let normal code handle rest
                        for j in range(0, 0x4000, 4):
                            v = (int.from_bytes(dst_data[j:j+4], 'little') ^
                                 int.from_bytes(src_data[j:j+4], 'little'))
                            dst_data[j:j+4] = v.to_bytes(4, 'little')
                        uc.mem_write(dest_ptr, bytes(dst_data))
                        self._record_recent_data_event(
                            "bulkxor-outer",
                            src=src_addr,
                            dst=dest_ptr,
                            size=0x4000,
                            lr=uc.reg_read(UC_ARM64_REG_LR),
                            pc=addr,
                            head=bytes(dst_data[:32]),
                        )
                        cur_w10 = (cur_w10 + 0x4000) & 0xFFFFFFFF
                        rounds_done += 1
                        cur_r = r + 1
                    if rounds_done > 0:
                        uc.reg_write(UC_ARM64_REG_X8, cur_r)
                        uc.reg_write(UC_ARM64_REG_X10, cur_w10)
                        # Dump key source info for debugging
                        first_src = (x1 + (x8 << 14 if x8 < 0x80000000 else x8 - 0x100000000)) & 0xFFFFFFFFFFFFFFFF
                        try:
                            src_head = bytes(uc.mem_read(first_src, 32)).hex() if first_src else "N/A"
                        except:
                            src_head = "UNMAPPED"
                        try:
                            dst_head = bytes(uc.mem_read(dest_ptr, 32)).hex()
                        except:
                            dst_head = "UNMAPPED"
                        if cur_r >= x11:
                            print(f"[BULK-XOR-FF] {rounds_done}/{remaining} rounds, dest={dest_ptr:#x} "
                                  f"x1={x1:#x} w10_start={w10:#x} first_src={first_src:#x}", flush=True)
                            print(f"  src_head: {src_head}", flush=True)
                            print(f"  dst_head: {dst_head}", flush=True)
                            # Compute SHA-256 of the 0x4000-byte XOR result for verification
                            try:
                                xor_result = bytes(uc.mem_read(dest_ptr, 0x4000))
                                xor_sha = hashlib.sha256(xor_result).hexdigest()
                                print(f"  SHA256(xor_result_0x4000): {xor_sha}", flush=True)
                                print(f"  dest_ptr={dest_ptr:#x}", flush=True)
                            except Exception as e:
                                print(f"  SHA256 error: {e}", flush=True)
                            uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x56d48)
                        else:
                            print(f"[BULK-XOR-FF] {rounds_done}/{remaining} partial (unmapped r={cur_r}), dest={dest_ptr:#x} "
                                  f"x1={x1:#x}", flush=True)
                            # Let the outer loop re-enter at 0x56d04 with updated x8/w10
                        return
        # ---- BULK-XOR-INNER fast-forward at 0x56d1c: inner XOR loop
        # XORs [x13+x12..x13+0x4000] ^= [x14+x12..x14+0x4000] in 4-byte chunks
        # After: x12=0x4000, falls through to 0x56d38
        if off == 0x56d1c:
            x12 = uc.reg_read(UC_ARM64_REG_X12)
            x13 = uc.reg_read(UC_ARM64_REG_X13)
            x14 = uc.reg_read(UC_ARM64_REG_X14)
            remaining_bytes = 0x4000 - x12
            if remaining_bytes > 32:
                try:
                    src_data = bytearray(self._read_bytes_with_fallback(uc, x14 + x12, remaining_bytes))
                    dst_data = bytearray(self._read_bytes_with_fallback(uc, x13 + x12, remaining_bytes))
                    for j in range(0, remaining_bytes, 4):
                        v = (int.from_bytes(dst_data[j:j+4], 'little') ^
                             int.from_bytes(src_data[j:j+4], 'little'))
                        dst_data[j:j+4] = v.to_bytes(4, 'little')
                    uc.mem_write(x13 + x12, bytes(dst_data))
                    self._record_recent_data_event(
                        "bulkxor-inner",
                        src=x14 + x12,
                        dst=x13 + x12,
                        size=remaining_bytes,
                        lr=uc.reg_read(UC_ARM64_REG_LR),
                        pc=addr,
                        head=bytes(dst_data[:32]),
                    )
                    uc.reg_write(UC_ARM64_REG_X12, 0x4000)
                    uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x56d38)
                    return
                except Exception:
                    pass  # let normal code run
        # ---- STRLEN-2 fast-forward at 0x13138c: scans [x16+x18] for NUL
        # Registers: x16=base, x18=index (start), x17=accumulator (+1 per byte)
        # Loop: ldrb w0,[x16,x18]; x17+=1; x18+=1; cbnz w0
        # Exit at 0x1313b4: cmp w18,#1; b.lt 0x13153c
        if off == 0x13138c:
            x16 = uc.reg_read(UC_ARM64_REG_X16)
            x18 = uc.reg_read(UC_ARM64_REG_X18)
            x17 = uc.reg_read(UC_ARM64_REG_X17)
            try:
                buf = bytes(uc.mem_read(x16 + x18, 0x10000))
                nul_pos = buf.index(0)
            except (ValueError, Exception):
                nul_pos = -1
            if nul_pos >= 0:
                # Fast-forward: x18 += nul_pos (lands on NUL), x17 += nul_pos
                new_x18 = x18 + nul_pos
                new_x17 = (x17 + nul_pos) & 0xFFFFFFFFFFFFFFFF
                uc.reg_write(UC_ARM64_REG_X18, new_x18)
                uc.reg_write(UC_ARM64_REG_X17, new_x17)
                uc.reg_write(UC_ARM64_REG_X0, 0)  # NUL byte
                print(f"[STRLEN-2-FF] x16={x16:#x} start_idx={x18} len={nul_pos}", flush=True)
                uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x1313b4)
                return
        # ---- HEX-PARSE fast-forward at 0x1313e0: parses hex string → sp+0x280
        # On first entry (x16==0): read hex string from [x15], length x18
        # Accumulator: acc = (acc<<4)|nibble for each hex char → standard hex parse
        # After: jump to 0x131544 with x16=strlen, sp+0x280=result
        if off == 0x1313e0:
            x16 = uc.reg_read(UC_ARM64_REG_X16)
            if x16 == 0:  # first iteration only
                x18 = uc.reg_read(UC_ARM64_REG_X18)
                x15 = uc.reg_read(UC_ARM64_REG_X15)
                sp = uc.reg_read(UC_ARM64_REG_SP)
                if x18 > 0:
                    try:
                        raw = bytes(uc.mem_read(x15, x18))
                        hex_str = raw.decode('ascii', errors='replace')
                        # Standard hex parse: acc = (acc<<4)|nibble
                        acc = 0
                        for ch in hex_str:
                            if '0' <= ch <= '9':
                                nib = ord(ch) - 0x30
                            elif 'a' <= ch <= 'f':
                                nib = ord(ch) - 0x57
                            elif 'A' <= ch <= 'F':
                                nib = ord(ch) - 0x37
                            else:
                                break  # non-hex char → stop
                            acc = ((acc << 4) | nib) & 0xFFFFFFFFFFFFFFFF
                        struct.pack("<Q", acc)  # validate
                        uc.mem_write(sp + 0x280, struct.pack("<Q", acc))
                        uc.reg_write(UC_ARM64_REG_X16, x18)  # strlen
                        print(f"[HEX-PARSE-FF] x15={x15:#x} len={x18} hex={hex_str[:32]}... acc={acc:#018x}", flush=True)
                        uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x131544)
                        return
                    except Exception as e:
                        print(f"[HEX-PARSE-FF] FAILED: {e}", flush=True)
        # ---- STRLEN-3A fast-forward at 0x1314d4: scans [x17+x16] for NUL
        # Registers: x17=base (x11+x15), x16=index (0), x18=counter (starts at 1)
        # Loop: ldrb w0,[x17,x16]; x18+=1; x16+=1; cbnz w0
        # Exit at 0x1314fc: b 0x131698
        if off == 0x1314d4:
            x17 = uc.reg_read(UC_ARM64_REG_X17)
            x16 = uc.reg_read(UC_ARM64_REG_X16)
            x18 = uc.reg_read(UC_ARM64_REG_X18)
            try:
                buf = bytes(uc.mem_read(x17 + x16, 0x10000))
                nul_pos = buf.index(0)
            except (ValueError, Exception):
                nul_pos = -1
            if nul_pos >= 0 and nul_pos > 8:
                new_x16 = x16 + nul_pos + 1
                new_x18 = (x18 + nul_pos) & 0xFFFFFFFFFFFFFFFF
                uc.reg_write(UC_ARM64_REG_X16, new_x16)
                uc.reg_write(UC_ARM64_REG_X18, new_x18)
                uc.reg_write(UC_ARM64_REG_X0, 0)
                print(f"[STRLEN-3A-FF] x17={x17:#x} len={nul_pos}", flush=True)
                uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x1314fc)
                return
        # ---- STRLEN-3B fast-forward at 0x131510: scans [x17+x16] for NUL
        # Same structure as 0x1314d4 but different obfuscation constant
        # Exit at 0x131538: b 0x13173c
        if off == 0x131510:
            x17 = uc.reg_read(UC_ARM64_REG_X17)
            x16 = uc.reg_read(UC_ARM64_REG_X16)
            x18 = uc.reg_read(UC_ARM64_REG_X18)
            try:
                buf = bytes(uc.mem_read(x17 + x16, 0x10000))
                nul_pos = buf.index(0)
            except (ValueError, Exception):
                nul_pos = -1
            if nul_pos >= 0 and nul_pos > 8:
                new_x16 = x16 + nul_pos + 1
                new_x18 = (x18 + nul_pos) & 0xFFFFFFFFFFFFFFFF
                uc.reg_write(UC_ARM64_REG_X16, new_x16)
                uc.reg_write(UC_ARM64_REG_X18, new_x18)
                uc.reg_write(UC_ARM64_REG_X0, 0)
                print(f"[STRLEN-3B-FF] x17={x17:#x} len={nul_pos}", flush=True)
                uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x131538)
                return
        # ---- STRLEN-4 fast-forward at 0x131578: scans [x18] post-increment for NUL
        # Registers: x18=ptr (post-incr), x15=counter, x16 += x21 per iter,
        #            w17=counter (starts at -1)
        # Loop: ldrb w0,[x18],#1; x15+=1; x16+=x21; w17+=1; cbnz w0
        # Exit at 0x131594: cmp w17,#1; b.lt 0x1317f4
        if off == 0x131578:
            x18 = uc.reg_read(UC_ARM64_REG_X18)
            x15 = uc.reg_read(UC_ARM64_REG_X15)
            x16 = uc.reg_read(UC_ARM64_REG_X16)
            x21 = uc.reg_read(UC_ARM64_REG_X21)
            w17 = uc.reg_read(UC_ARM64_REG_X17) & 0xFFFFFFFF
            try:
                buf = bytes(uc.mem_read(x18, 0x10000))
                nul_pos = buf.index(0)
            except (ValueError, Exception):
                nul_pos = -1
            if nul_pos >= 0 and nul_pos > 8:
                total_iters = nul_pos + 1  # includes NUL read
                new_x18 = x18 + total_iters
                # x15 increments via neg+sub trick, net +1 per iter
                new_x15 = (x15 + total_iters) & 0xFFFFFFFFFFFFFFFF
                new_x16 = (x16 + total_iters * x21) & 0xFFFFFFFFFFFFFFFF
                new_w17 = (w17 + total_iters) & 0xFFFFFFFF
                uc.reg_write(UC_ARM64_REG_X18, new_x18)
                uc.reg_write(UC_ARM64_REG_X15, new_x15)
                uc.reg_write(UC_ARM64_REG_X16, new_x16)
                uc.reg_write(UC_ARM64_REG_X17, new_w17)
                uc.reg_write(UC_ARM64_REG_X0, 0)
                print(f"[STRLEN-4-FF] x18={x18:#x} len={nul_pos}", flush=True)
                uc.reg_write(UC_ARM64_REG_PC, JIT_BASE + 0x131594)
                return
        # CFF wrapper 0x1c2124: track when the RETURN PATH is set.
        # Previously bypassed immediately, but this skips output-writing states.
        # Let the CFF continue; the stall detector handles the wind-down loop.
        if off in (0x1c75e0, 0x1c7630):
            ret_val = 1 if off == 0x1c7630 else 0
            cnt = getattr(self, '_cff_winddown_hits', 0) + 1
            self._cff_winddown_hits = cnt
            if cnt <= 3:
                print(f"[CFF-WINDDOWN-SEEN #{cnt}] RETURN {ret_val} PATH at {off:#x}", flush=True)
            # After many cycles through the return state, truly bypass.
            if cnt >= 50:
                uc.reg_write(UC_ARM64_REG_X19, ret_val)
                target = JIT_BASE + 0x1c8820
                print(f"[CFF-WINDDOWN-BYPASS] RETURN {ret_val} after {cnt} hits → epilogue {target:#x}", flush=True)
                uc.reg_write(UC_ARM64_REG_PC, target)
                return
        # 0x11ca30 is not the original hash gate in the current live image, but
        # forcing bit0 clear here is still required to keep emulation on the
        # late cert path that reaches the SHA/stage-2 formatter chain.
        if off == 0x11ca30:
            w19 = uc.reg_read(UC_ARM64_REG_X19) & 0xFFFFFFFF
            if w19 & 1:
                new_x19 = uc.reg_read(UC_ARM64_REG_X19) & ~1
                uc.reg_write(UC_ARM64_REG_X19, new_x19)
                print(
                    f"[PATH-FORCE-11CA30] Forced w19 bit0=0 (was {w19:#x})",
                    flush=True,
                )
        # Force compare vector to mirror source vector.
        # The cert CFF at 0x1c2124 normally populates container+0x588/+0x590
        # (compare vector) to match source vector (cont+0x10/+0x18). Our stall-
        # skip bypasses this, leaving stale compare records. Override x19/x23
        # at 0x1090d8 (right after both loads) with the source vector pointers
        # so every source record matches itself during the 0x6b6b4 compare loop.
        if off == 0x1090d8:
            if getattr(self, '_overlay_compare_vectors_injected', False):
                x19 = uc.reg_read(UC_ARM64_REG_X19)
                x23 = uc.reg_read(UC_ARM64_REG_X23)
                n_cmp = (x23 - x19) // 0x140 if x23 > x19 else 0
                print(f"[COMPARE-VEC-FIX] Skipped — overlay provided real compare data "
                      f"({n_cmp} recs @ {x19:#x})", flush=True)
            else:
                x20 = uc.reg_read(UC_ARM64_REG_X20)  # container
                if x20 > 0x1000:
                    try:
                        src_begin = struct.unpack("<Q", uc.mem_read(x20 + 0x10, 8))[0]
                        src_end = struct.unpack("<Q", uc.mem_read(x20 + 0x18, 8))[0]
                        old_x19 = uc.reg_read(UC_ARM64_REG_X19)
                        old_x23 = uc.reg_read(UC_ARM64_REG_X23)
                        if src_begin and src_end and src_begin != old_x19:
                            uc.reg_write(UC_ARM64_REG_X19, src_begin)
                            uc.reg_write(UC_ARM64_REG_X23, src_end)
                            n_src = (src_end - src_begin) // 0x140
                            n_old = (old_x23 - old_x19) // 0x140 if old_x23 > old_x19 else 0
                            print(f"[COMPARE-VEC-FIX] Replaced compare vector "
                                  f"({n_old} recs @ {old_x19:#x}) with source vector "
                                  f"({n_src} recs @ {src_begin:#x})", flush=True)
                    except Exception as e:
                        print(f"[COMPARE-VEC-FIX] Failed: {e}", flush=True)
        # The same function immediately loads a second begin/end pair from
        # container+0x5a0/+0x5a8 and copies it into a second working vector.
        # If the cert CFF bypass left those stale too, the later local-SSO
        # builder sees an empty compare/output set. Mirror the source vector
        # here as well.
        if off == 0x1091a8:
            if getattr(self, '_overlay_compare_vectors_injected', False):
                x22 = uc.reg_read(UC_ARM64_REG_X22)
                x19 = uc.reg_read(UC_ARM64_REG_X19)
                n_cmp = (x19 - x22) // 0x140 if x19 > x22 else 0
                print(f"[COMPARE-VEC-FIX-2] Skipped — overlay provided real compare data "
                      f"({n_cmp} recs @ {x22:#x})", flush=True)
            else:
                x20 = uc.reg_read(UC_ARM64_REG_X20)  # container
                if x20 > 0x1000:
                    try:
                        src_begin = struct.unpack("<Q", uc.mem_read(x20 + 0x10, 8))[0]
                        src_end = struct.unpack("<Q", uc.mem_read(x20 + 0x18, 8))[0]
                        old_x22 = uc.reg_read(UC_ARM64_REG_X22)
                        old_x19 = uc.reg_read(UC_ARM64_REG_X19)
                        if src_begin and src_end and src_begin != old_x22:
                            uc.reg_write(UC_ARM64_REG_X22, src_begin)
                            uc.reg_write(UC_ARM64_REG_X19, src_end)
                            n_src = (src_end - src_begin) // 0x140
                            n_old = (old_x19 - old_x22) // 0x140 if old_x19 > old_x22 else 0
                            print(f"[COMPARE-VEC-FIX-2] Replaced secondary vector "
                                  f"({n_old} recs @ {old_x22:#x}) with source vector "
                                  f"({n_src} recs @ {src_begin:#x})", flush=True)
                    except Exception as e:
                        print(f"[COMPARE-VEC-FIX-2] Failed: {e}", flush=True)
        # The final output write at 0x11cf90 reads a local SSO payload from
        # sp+0x590/+0x5a0. In broken runs that local copy stays empty even
        # though the hash/object at x23 was just populated at 0x11cf70..0x11cf7c.
        # Seed the local SSO tail from x23 so the normal output store can
        # proceed without writing an all-zero token.
        if off == 0x11cf90:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            x23 = uc.reg_read(UC_ARM64_REG_X23)
            try:
                slot_raw = bytes(uc.mem_read(sp + 0x590, 24))
                tag = slot_raw[0]
                if tag & 1:
                    live_size = struct.unpack("<Q", slot_raw[8:16])[0]
                    live_ptr = struct.unpack("<Q", slot_raw[16:24])[0]
                    if 0 < live_size <= 0x200 and live_ptr > 0x1000:
                        mapped = self._is_page_accessible(uc, live_ptr & ~0xFFF)
                        try:
                            live_output = self._read_bytes_with_fallback(uc, live_ptr, live_size)
                            if (
                                live_output
                                and live_size == 0x30
                                and not any(live_output)
                            ):
                                restored = None
                                restore_note = ""
                                exact_hex48 = getattr(self, "_hex48_memcpy_by_dst", {}).get(live_ptr)
                                if exact_hex48 and len(exact_hex48) >= live_size:
                                    restored = bytes(exact_hex48[:live_size])
                                    restore_note = "exact-dst-memcpy"
                                elif len(getattr(self, "_src48_last_full_hex", "")) >= live_size:
                                    restored = self._src48_last_full_hex[:live_size].encode("ascii")
                                    restore_note = "src48-last-full-hex"
                                if restored and any(restored):
                                    uc.mem_write(live_ptr, restored)
                                    live_output = restored
                                    print(
                                        f"[OUTPUT-LOCAL-REPAIR] restored ptr={live_ptr:#x} "
                                        f"size={live_size:#x} via {restore_note} "
                                        f"data={restored[:64]!r}",
                                        flush=True,
                                    )
                            if live_output:
                                self._last_live_output_text = bytes(live_output)
                                print(
                                    f"[LIVE-OUTPUT-CAPTURE] slot=LONG size={live_size:#x} "
                                    f"ptr={live_ptr:#x} mapped={mapped} data={live_output[:64]!r}",
                                    flush=True,
                                )
                        except Exception as exc:
                            print(
                                f"[LIVE-OUTPUT-CAPTURE] LONG read failed size={live_size:#x} "
                                f"ptr={live_ptr:#x} mapped={mapped} err={exc}",
                                flush=True,
                            )
                else:
                    live_size = tag >> 1
                    if live_size:
                        live_output = slot_raw[1:1 + min(live_size, 22)]
                        self._last_live_output_text = bytes(live_output)
                        print(
                            f"[LIVE-OUTPUT-CAPTURE] slot=SSO len={live_size} data={live_output!r}",
                            flush=True,
                        )
                cur_tail = struct.unpack("<Q", uc.mem_read(sp + 0x5A0, 8))[0]
                if cur_tail == 0:
                    q0 = bytes(uc.mem_read(sp + 0x810, 16))
                    tail = bytes(uc.mem_read(sp + 0x820, 8))
                    if tail != b"\x00" * 8 or q0 != b"\x00" * 16:
                        uc.mem_write(sp + 0x590, q0)
                        uc.mem_write(sp + 0x5A0, tail)
                        print(f"[OUTPUT-LOCAL-REPAIR] sp+0x810 q0={q0.hex()} tail={tail.hex()}", flush=True)
                    elif x23 > 0x1000:
                        q0 = bytes(uc.mem_read(x23, 16))
                        tail = bytes(uc.mem_read(x23 + 0x10, 8))
                        uc.mem_write(sp + 0x590, q0)
                        uc.mem_write(sp + 0x5A0, tail)
                        print(f"[OUTPUT-LOCAL-REPAIR] x23={x23:#x} q0={q0.hex()} tail={tail.hex()}", flush=True)
            except Exception as e:
                print(f"[OUTPUT-LOCAL-REPAIR] Failed: {e}", flush=True)
        # CFF computation path forcing (disabled - computation path blocks need GOT globals)
        # Hub1 at 0x1c3318 and Hub2 at 0x1c87a4 check [sp+0x90].
        # The "skip" path (40 blocks) is actually the normal execution path.
        # Session+0x210 write watchpoint is now installed EARLY in _install_hooks().
        # Also watch x27-based session if x27 differs from MANAGER_BASE.
        if off in (0x108d1c, 0x1c2124) and not getattr(self, '_sess210_x27_watch_done', False):
            x27 = uc.reg_read(UC_ARM64_REG_X27)
            if x27 != MANAGER_BASE and x27 > 0x1000:
                self._sess210_x27_watch_done = True
                h = uc.hook_add(UC_HOOK_MEM_WRITE, self._sess210_write_hook,
                            begin=x27 + 0x210, end=x27 + 0x228)
                self._per_run_hooks.append(h)
                print(f"[SESS-WATCH-X27] Also watching x27-based session+0x210 @ {x27+0x210:#x} "
                      f"(x27={x27:#x} != MANAGER_BASE={MANAGER_BASE:#x})", flush=True)
        # Trace x0 through the ceba0 call sequence (0x1cee54-0x1cee6c)
        if off in (0x1cee58, 0x1cee5c, 0x1cee60, 0x1cee64, 0x1cee68, 0x1cee6c):
            x0_val = uc.reg_read(UC_ARM64_REG_X0)
            extra = f" x0={x0_val:#x}"
        # Dump x9 at the ldr x0,[x9,#0x380] instruction
        if off == 0x1cee54:
            x9 = uc.reg_read(UC_ARM64_REG_X9)
            x9_data = ""
            try:
                d = bytes(uc.mem_read(x9 + 0x380, 24)).hex()
                x9_data = f" [{x9+0x380:#x}]={d}"
            except Exception as e:
                x9_data = f" [read_err={e}]"
            extra = f" x9={x9:#x}{x9_data}"
        # Dump ceba0 args to understand descriptor matching
        if off == 0xceba0:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            lr = uc.reg_read(UC_ARM64_REG_LR)
            # Try to read x0 as a string/SSO
            x0_str = ""
            try:
                hdr = bytes(uc.mem_read(x0, 24))
                if hdr[0] & 1:  # long
                    sz = struct.unpack("<Q", hdr[8:16])[0]
                    ptr = struct.unpack("<Q", hdr[16:24])[0]
                    if ptr > 0x1000:
                        buf = bytes(uc.mem_read(ptr, min(sz, 64)))
                        x0_str = f"LONG({sz})={buf.decode('ascii', errors='replace')!r}"
                else:
                    slen = hdr[0] >> 1
                    x0_str = f"SSO({slen})={hdr[1:1+slen].decode('ascii', errors='replace')!r}"
            except:
                x0_str = f"ptr={x0:#x}"
            # x1 = descriptor string
            x1_str = ""
            try:
                hdr1 = bytes(uc.mem_read(x1, 24))
                if hdr1[0] & 1:
                    sz = struct.unpack("<Q", hdr1[8:16])[0]
                    ptr = struct.unpack("<Q", hdr1[16:24])[0]
                    if ptr > 0x1000:
                        buf = bytes(uc.mem_read(ptr, min(sz, 64)))
                        x1_str = f"LONG({sz})={buf.decode('ascii', errors='replace')!r}"
                else:
                    slen = hdr1[0] >> 1
                    x1_str = f"SSO({slen})={hdr1[1:1+slen].decode('ascii', errors='replace')!r}"
            except:
                x1_str = f"ptr={x1:#x}"
            # Also dump raw bytes and x1 raw
            x1_raw = ""
            try:
                x1_raw = bytes(uc.mem_read(x1, 24)).hex()
            except:
                x1_raw = "UNREADABLE"
            x0_raw = ""
            try:
                x0_raw = bytes(uc.mem_read(x0, 24)).hex()
            except:
                x0_raw = "UNREADABLE"
            x1_cstr = ""
            try:
                x1_cstr = self._read_c_string(uc, x1, limit=0x40).decode("ascii", errors="replace")
            except:
                x1_cstr = ""
            x2_raw = self._dump_mem_hex(uc, x2, 0x40) if x2 else "0"
            # Read x0 source: the CFF code does ldr x0,[x9,#0x380] at 0x1cee54
            # Session is saved at sp+0xc8 in 0x1c88a0's frame
            sess_dbg = ""
            try:
                # Read session from the CFF wrapper stack
                sess_ptr = struct.unpack("<Q", uc.mem_read(sp + 0xc8, 8))[0]
                sess_380_tbi = bytes(uc.mem_read(sess_ptr + 0x380, 24)).hex()
                sess_untag = sess_ptr & 0x00FFFFFFFFFFFFFF
                sess_380_untag = bytes(uc.mem_read(sess_untag + 0x380, 24)).hex()
                # Also check the raw session address 0xb400007553c6c220
                raw_sess = 0xb400007553c6c220
                raw_380 = bytes(uc.mem_read(raw_sess + 0x380, 24)).hex()
                raw_untag = bytes(uc.mem_read(0x7553c6c5a0, 24)).hex()
                sess_dbg = f" sess={sess_ptr:#x} s380_tbi={sess_380_tbi} s380_untag={sess_380_untag} raw_tbi={raw_380} raw_untag={raw_untag}"
            except Exception as e:
                sess_dbg = f" sess_err={e}"
            print(
                f"[CEBA0-RAW] x0={x0:#x} x1={x1:#x} x2={x2:#x} lr={lr:#x} "
                f"x0s={x0_str}[{x0_raw}] x1s={x1_str}[{x1_raw}] x1c={x1_cstr!r} "
                f"x2buf={x2_raw}{sess_dbg}",
                flush=True,
            )
            extra = f" x0={x0_str}[{x0_raw}] x1({x1:#x})={x1_str}[{x1_raw}] x2={x2:#x}{sess_dbg}"
        # Dump challenge SSO at slow path entry
        if off == 0x108d24:
            try:
                sso = bytes(uc.mem_read(sp + 0x620, 24))
                sso600 = bytes(uc.mem_read(sp + 0x600, 24))
                x23 = uc.reg_read(UC_ARM64_REG_X23)
                extra += f" sp+0x620={sso.hex()} sp+0x600={sso600.hex()} x23={x23:#x} x23+0xa8=sp+{x23+0xa8-sp:#x}"
            except Exception as e:
                extra += f" sp+0x620=ERR({e})"
        if off in (0x108fcc, 0x1090c0):
            self._log_post_success_snapshot(uc, off)
        # At decision points, dump the key stack slots
        if off in (0x1c2124, 0x1c8854, 0x108fcc):
            # Dump x27+0x210 (CFF output / encoder state)
            x27 = uc.reg_read(UC_ARM64_REG_X27)
            try:
                data210 = bytes(uc.mem_read(x27 + 0x210, 48))
                b0 = data210[0]
                if b0 & 1 == 0:
                    slen = b0 >> 1
                    s = data210[1:1+slen].decode('ascii', errors='replace')
                    extra = f" x27={x27:#x} x27+0x210=SSO({slen})={s!r}"
                else:
                    extra = f" x27={x27:#x} x27+0x210={data210[:24].hex()}"
            except:
                extra = f" x27={x27:#x} x27+0x210=??"
            if off == 0x1c2124:
                x0 = uc.reg_read(UC_ARM64_REG_X0)
                x1 = uc.reg_read(UC_ARM64_REG_X1)
                x2 = uc.reg_read(UC_ARM64_REG_X2)
                x20 = uc.reg_read(UC_ARM64_REG_X20)
                x23 = uc.reg_read(UC_ARM64_REG_X23)
                obj30 = self._safe_mem_read_qword(uc, x0 + 0x30) if x0 > 0x1000 else None
                if LIVE_CERT_OVERLAY_ACTIVE:
                    extra += (
                        f" x0={x0:#x} [x0+0x30]={self._format_opt_hex(obj30)}"
                        f" x1={x1:#x} x2={x2:#x} x20={x20:#x} x23={x23:#x}"
                        f" {self._describe_cert_session_ptr(uc, x1)}"
                    )
                else:
                    obj0 = self._safe_mem_read_qword(uc, x0) if x0 > 0x1000 else None
                    obj8 = self._safe_mem_read_qword(uc, x0 + 0x8) if x0 > 0x1000 else None
                    extra += (
                        f" x0={x0:#x} [x0]={self._format_opt_hex(obj0)}"
                        f" [x0+0x8]={self._format_opt_hex(obj8)}"
                        f" [x0+0x30]={self._format_opt_hex(obj30)}"
                        f" x1={x1:#x} x2={x2:#x} x20={x20:#x} x23={x23:#x}"
                        f" {self._describe_cert_session_ptr(uc, x1)}"
                    )
        elif off == 0x1c2470:
            x27 = uc.reg_read(UC_ARM64_REG_X27)
            saved_x28 = self._safe_mem_read_qword(uc, sp + 0x70)
            saved_x27 = self._safe_mem_read_qword(uc, sp + 0x78)
            extra = (
                f" live_x27={x27:#x} saved_x28={self._format_opt_hex(saved_x28)}"
                f" saved_x27={self._format_opt_hex(saved_x27)}"
            )
        elif off == 0x1d2480:
            try:
                sp24 = struct.unpack("<I", uc.mem_read(sp + 24, 4))[0]
                sp28 = struct.unpack("<I", uc.mem_read(sp + 28, 4))[0]
                sp32 = struct.unpack("<I", uc.mem_read(sp + 32, 4))[0]
                sp36 = struct.unpack("<I", uc.mem_read(sp + 36, 4))[0]
                w8 = uc.reg_read(UC_ARM64_REG_X8) & 0xFFFFFFFF
                extra = f" sp+24={sp24:#x} sp+28={sp28:#x} sp+32={sp32:#x} sp+36={sp36:#x} w8={w8:#x}"
            except:
                pass
        elif off in (0x1c7554, 0x1c7560, 0x1c75e0, 0x1c7630):
            try:
                sp64 = struct.unpack("<I", uc.mem_read(sp + 64, 4))[0]
                sp72 = struct.unpack("<I", uc.mem_read(sp + 72, 4))[0]
                sp56 = struct.unpack("<I", uc.mem_read(sp + 56, 4))[0]
                sp80 = struct.unpack("<I", uc.mem_read(sp + 80, 4))[0]
                w8 = uc.reg_read(UC_ARM64_REG_X8) & 0xFFFFFFFF
                w9 = uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF
                extra = f" [sp+40h]={sp64:#x} [sp+48h]={sp72:#x} [sp+38h]={sp56:#x} [sp+50h]={sp80:#x} w8={w8:#x} w9={w9:#x}"
            except:
                pass
        elif off in (0x1ce018, 0x1cec94, 0x1cee70, 0x1cee88):
            try:
                x19 = uc.reg_read(UC_ARM64_REG_X19)
                x20 = uc.reg_read(UC_ARM64_REG_X20)
                x23 = uc.reg_read(UC_ARM64_REG_X23)
                x0 = uc.reg_read(UC_ARM64_REG_X0)
                sess = struct.unpack("<Q", uc.mem_read(sp + 0xc8, 8))[0]
                rng = struct.unpack("<Q", uc.mem_read(sp + 0xe8, 8))[0]
                extra = (f" x0={x0:#x} x19={x19:#x} x20={x20:#x} x23={x23:#x}"
                         f" [sp+c8]={sess:#x} [sp+e8]={rng:#x}")
                if sess:
                    try:
                        base_318 = struct.unpack("<Q", uc.mem_read(sess + 0x318, 8))[0]
                        base_320 = struct.unpack("<Q", uc.mem_read(sess + 0x320, 8))[0]
                        extra += f" sess[318]={base_318:#x} sess[320]={base_320:#x}"
                        extra += (
                            f" obj[300:340]={self._dump_mem_hex(uc, self._resolve_mem_addr(uc, sess + 0x300), 0x40)}"
                        )
                        if x23:
                            extra += (
                                f" x23blob={self._dump_mem_hex(uc, self._resolve_mem_addr(uc, x23), 0x48)}"
                            )
                    except:
                        pass
            except:
                pass
        if (
            0x155ba4 <= off <= 0x156100
            or off in (0x108d1c, 0x108d20, 0x165690, 0x165694)
        ):
            extra += self._fmt_call_tag()
        print(f"[FX-FLOW] JIT+{off:#x}: {label}{extra}", flush=True)

    def _maybe_route_cert_post_cff_ce75c(self, uc, w26):
        if w26 != JIT_CERT_POST_CFF_CE75C_STATE:
            return False
        if self._cert_post_cff_route_fix_applied:
            return False
        print(
            f"[CERT-CFF-CE75C-HUB] hub=JIT+0x1c8738 w26={w26:#010x}",
            flush=True,
        )
        return False

    def _maybe_seed_cert_ce75c_output(self, uc):
        if getattr(self, '_cert_cff_hub1_last_state', None) != JIT_CERT_POST_CFF_CE75C_STATE:
            return False
        sp = uc.reg_read(UC_ARM64_REG_SP)
        dest = sp + 0x50
        before = self._dump_mem_hex(uc, dest, 0x20)
        # Isolated execution confirms the missing flattened branch is ce75c(0x57),
        # which writes the short SSO b"-" into the callback-local output slot.
        self._write_sso(uc, dest, b"-")
        after = self._dump_mem_hex(uc, dest, 0x20)
        self._cert_post_cff_route_fix_applied += 1
        self._cert_ce75c_minus_pending = True
        print(
            f"[CERT-CFF-CE75C-SYNTH #{self._cert_post_cff_route_fix_applied}] "
            f"hub1_state={self._cert_cff_hub1_last_state:#010x} "
            f"dest={dest:#x} before={before} after={after}",
            flush=True,
        )
        return True

    def _maybe_apply_cert_ce75c_output(self, uc):
        # The ce75c synthesis is only valid for the callback-local slot at
        # sp+0x50. Mirroring it into the later 0x10875c local source slot
        # fabricates the visible "-" output and hides the real downstream
        # formatter state we are trying to debug.
        return False

    def _seed_single_element_vector(self, uc, vec_addr, data, elem_size):
        storage = self.heap.malloc(elem_size)
        uc.mem_write(storage, b"\x00" * elem_size)
        self._write_sso(uc, storage, data)
        uc.mem_write(
            vec_addr,
            struct.pack("<QQQ", storage, storage + elem_size, storage + elem_size),
        )
        return storage

    def _maybe_seed_cert_native_post_callback(self, uc):
        x20 = uc.reg_read(UC_ARM64_REG_X20)
        x21 = uc.reg_read(UC_ARM64_REG_X21)
        if not x20 or not x21:
            return False

        cand = x20 + 0x28
        try:
            cand_blob = bytes(uc.mem_read(cand, 0x30))
        except Exception:
            return False
        if cand_blob[:0x18] == b"\x00" * 0x18:
            return False

        before_68 = self._dump_mem_hex(uc, x21 + 0x68, 0x18)
        before_c8 = self._dump_mem_hex(uc, x21 + 0xC8, 0x20)

        self._write_sso(uc, x21 + 0x68, b"1")
        self._seed_single_element_vector(uc, x21 + 0x80, b"1", 0x30)
        self._seed_single_element_vector(uc, x21 + 0x98, b"1", 0x30)
        self._seed_single_element_vector(uc, x21 + 0xB0, b"", 0x18)
        uc.mem_write(x21 + 0xC8, struct.pack("<QQQ", cand, cand + 0x30, cand + 0x30))

        self._cert_native_post_callback_seed_hits += 1
        after_68 = self._dump_mem_hex(uc, x21 + 0x68, 0x18)
        after_c8 = self._dump_mem_hex(uc, x21 + 0xC8, 0x20)
        print(
            f"[CERT-NATIVE-POST-SEED #{self._cert_native_post_callback_seed_hits}] "
            f"x20={x20:#x} x21={x21:#x} cand={cand:#x} cand0={cand_blob.hex()} "
            f"x21+0x68(before)={before_68} x21+0x68(after)={after_68} "
            f"x21+0xc8(before)={before_c8} x21+0xc8(after)={after_c8}",
            flush=True,
        )
        return True

    def _begin_fmt_call(self, callsite_off):
        seq = getattr(self, "_fmt_call_seq", 0) + 1
        self._fmt_call_seq = seq
        self._fmt_active_call_id = seq
        self._fmt_active_callsite = callsite_off
        self._fmt_vararg_write_hits = 0
        self._fmt_x_block_diag_count = 0
        self._sp50_write_count = 0
        print(
            f"[FMT-CALL #{seq}] caller=JIT+0x{callsite_off:x}",
            flush=True,
        )

    def _fmt_call_tag(self):
        seq = getattr(self, "_fmt_active_call_id", 0)
        callsite = getattr(self, "_fmt_active_callsite", None)
        if not seq or callsite is None:
            return ""
        return f" [fmt_call#{seq}@JIT+0x{callsite:x}]"

    def _install_fmt_vararg_watch(self, uc):
        begin = uc.reg_read(UC_ARM64_REG_SP) + 0x8B0
        end = begin + 0x2F
        current = (begin, end)
        if getattr(self, "_fmt_vararg_watch_range", None) == current:
            return
        self._fmt_vararg_watch_range = current
        try:
            h = uc.hook_add(
                UC_HOOK_MEM_WRITE,
                self._fmt_vararg_write_hook,
                begin=begin,
                end=end,
            )
            self._per_run_hooks.append(h)
            window = self._dump_mem_hex(uc, begin, 0x30)
            print(
                f"[FMT-VARARG-WATCH]{self._fmt_call_tag()} "
                f"range={begin:#x}..{end:#x} initial={window}",
                flush=True,
            )
        except Exception as exc:
            print(f"[FMT-VARARG-WATCH] install failed: {exc}", flush=True)

    def _fmt_vararg_write_hook(self, uc, access, addr, size, value, ud):
        base, _ = getattr(self, "_fmt_vararg_watch_range", (0, 0))
        if not base:
            return
        cnt = getattr(self, "_fmt_vararg_write_hits", 0) + 1
        self._fmt_vararg_write_hits = cnt
        if cnt > 32:
            return
        pc = uc.reg_read(UC_ARM64_REG_PC)
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        slot = addr - base
        x25 = uc.reg_read(UC_ARM64_REG_X25)
        x20 = uc.reg_read(UC_ARM64_REG_X20)
        try:
            window = self._dump_mem_hex(uc, base, 0x30)
        except Exception as exc:
            window = f"ERR({exc})"
        print(
            f"[FMT-VARARG-WRITE #{cnt}]{self._fmt_call_tag()} "
            f"pc=JIT+{jit_off:#x} addr={addr:#x} "
            f"slot=+0x{slot:x} size={size} value={value:#x} "
            f"x25={x25:#x} x20={x20:#x} window={window}",
            flush=True,
        )

    def _cert_wrapper_entry_hook(self, uc, addr, size, ud):
        """UC_HOOK_CODE at cert wrapper entry (0x1c2124).
        The live hook point is post-prologue, so the actual skip logic is
        handled in the block hook. Keep this as a diagnostic entry probe and
        caller-frame capture for the emergency force-return path."""
        _lr = uc.reg_read(UC_ARM64_REG_LR)
        _sp = uc.reg_read(UC_ARM64_REG_SP)
        _fp = uc.reg_read(UC_ARM64_REG_X29)
        CERT_1ST_CALL_LR = JIT_BASE + 0x108fa4
        CERT_2ND_CALL_LR = JIT_BASE + 0x133780
        if _lr == CERT_1ST_CALL_LR:
            # Treat 0x108fa4 as the first wrapper call site only. The wrapper
            # can re-enter from the same LR during the first computation via
            # nested CFF dispatch; those re-entries must not be promoted to a
            # fake "second call" or they abort the real first wrapper early.
            if getattr(self, '_cert_wrapper_first_seen', False):
                print(
                    f"[CERT-WRAPPER-REENTRY] lr={_lr:#x} sp={_sp:#x} fp={_fp:#x}",
                    flush=True,
                )
                return
            cert_call_cnt = 1
            self._cert_wrapper_first_seen = True
            self._cert_wrapper_first_sp = _sp
            self._cert_wrapper_call_count = cert_call_cnt
        elif _lr == CERT_2ND_CALL_LR:
            # Only the dedicated 0x133780 caller is allowed to arm the
            # second-wrapper skip logic.
            if getattr(self, '_cert_wrapper_second_seen', False):
                print(
                    f"[CERT-WRAPPER-2ND-REENTRY] lr={_lr:#x} sp={_sp:#x} fp={_fp:#x}",
                    flush=True,
                )
                return
            cert_call_cnt = 2
            self._cert_wrapper_second_seen = True
            self._cert_wrapper_call_count = cert_call_cnt
        else:
            return
        caller = self._capture_cert_wrapper_caller_frame(uc, _sp, _fp, _lr)
        _x0 = uc.reg_read(UC_ARM64_REG_X0)
        _x1 = uc.reg_read(UC_ARM64_REG_X1)
        _x2 = uc.reg_read(UC_ARM64_REG_X2)
        _x3 = uc.reg_read(UC_ARM64_REG_X3)
        print(f"[CERT-WRAPPER #{cert_call_cnt}] lr={_lr:#x} x0={_x0:#x} x1={_x1:#x} "
              f"x2={_x2:#x} x3={_x3:#x} sp={_sp:#x} caller_sp={caller['sp']:#x}",
              flush=True)
        self._cert_wrapper_caller = caller
        if cert_call_cnt >= 2:
            # Dump descriptor+0x2a0 SSO state for diagnosis
            desc = struct.unpack("<Q", uc.mem_read(_sp + 0x1f8, 8))[0] if _sp else 0
            if desc:
                try:
                    sso_desc = self._describe_sso_slot(uc, desc + 0x2a0)
                    print(f"[CERT-SKIP-2ND #{cert_call_cnt}] lr={_lr:#x} desc={desc:#x} "
                          f"+0x2a0={sso_desc}", flush=True)
                except:
                    print(f"[CERT-SKIP-2ND #{cert_call_cnt}] lr={_lr:#x} desc={desc:#x} "
                          f"+0x2a0=READ_ERROR", flush=True)
            else:
                print(f"[CERT-SKIP-2ND #{cert_call_cnt}] lr={_lr:#x} desc=0", flush=True)
            # The live second wrapper now returns naturally with w0=1. Restoring
            # the captured caller frame here is wrong: it rewinds SP from the
            # active 0x10875c frame back to its caller and destroys locals like
            # sp+0x2f0/sp+0x2f8 before the post-CFF append path runs.
            self._cert_wrapper_block_restore_pending = None
            return
        # First call: save frame for emergency force-return, let it proceed
        self._stall_last_progress_block = getattr(self, '_stall_jit_count', 0)

    def _cert_wrapper_return_hook(self, uc, addr, size, ud):
        """Force w0=1 on the second cert-wrapper epilogue path."""
        pending = getattr(self, '_cert_wrapper_skip_pending', None)
        if not pending:
            return

        patch_addr = pending.get('patch_addr')
        patch_orig = pending.get('patch_orig')
        if patch_addr is not None and patch_orig is not None:
            uc.mem_write(patch_addr, patch_orig)
        uc.reg_write(UC_ARM64_REG_X19, 1)
        print(
            f"[CERT-SKIP-2ND-RET #{pending['call_count']}] "
            f"lr={pending['lr']:#x} sp={pending['sp']:#x} fp={pending['fp']:#x}",
            flush=True,
        )
        self._cert_wrapper_skip_pending = None

    def _sess210_write_hook(self, uc, access, addr, size, value, ud):
        """Watchpoint: fires when anything writes to session+0x210 SSO struct."""
        pc = self._last_pc if hasattr(self, '_last_pc') else 0
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        lr = uc.reg_read(UC_ARM64_REG_LR)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        mgr_off = addr - MANAGER_BASE
        lr_jit = lr - JIT_BASE if lr >= JIT_BASE else lr
        if not hasattr(self, '_sess210_write_count'):
            self._sess210_write_count = 0
        self._sess210_write_count += 1
        print(f"[SESS210-WRITE] #{self._sess210_write_count} pc=JIT+{jit_off:#x} "
              f"lr=JIT+{lr_jit:#x} sp={sp:#x} mgr+{mgr_off:#x} size={size} "
              f"value={value:#x}", flush=True)

    def _sess210_data_write_hook(self, uc, access, addr, size, value, ud):
        """Watchpoint: fires when anything writes to session+0x210's heap data buffer."""
        pc = self._last_pc if hasattr(self, '_last_pc') else 0
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        lr = uc.reg_read(UC_ARM64_REG_LR)
        lr_jit = lr - JIT_BASE if lr >= JIT_BASE else lr
        if not hasattr(self, '_sess210_data_writes'):
            self._sess210_data_writes = 0
        self._sess210_data_writes += 1
        if self._sess210_data_writes <= 30:
            print(f"[SESS210-DATA-WRITE] #{self._sess210_data_writes} pc=JIT+{jit_off:#x} "
                  f"lr=JIT+{lr_jit:#x} addr={addr:#x} size={size} value={value:#x}", flush=True)

    def _challenge_mem_read_hook(self, uc, access, addr, size, value, ud):
        """Watchpoint: fires when anything reads from the challenge area on fx stack."""
        if not hasattr(self, '_fx_sp'):
            return
        pc = self._last_pc if hasattr(self, '_last_pc') else 0
        off_from_sp = addr - self._fx_sp
        # Read the actual bytes at this address
        try:
            data = bytes(uc.mem_read(addr, size))
            data_hex = data.hex()
        except:
            data_hex = "??"
        entry = (pc, addr, off_from_sp, size, data_hex)
        # Log first 50 reads, then summarize
        if not hasattr(self, '_challenge_read_count'):
            self._challenge_read_count = 0
        self._challenge_read_count += 1
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        if self._challenge_read_count <= 50:
            print(f"[CHAL-READ #{self._challenge_read_count}] pc=JIT+{jit_off:#x} "
                  f"addr=sp+{off_from_sp:#x} size={size} data={data_hex}", flush=True)
        elif self._challenge_read_count in (100, 200, 500, 1000):
            print(f"[CHAL-READ #{self._challenge_read_count}] (sampling) pc=JIT+{jit_off:#x} "
                  f"addr=sp+{off_from_sp:#x} size={size} data={data_hex}", flush=True)
        self._challenge_read_log.append(entry)

    def _challenge_ctx_mem_read_hook(self, uc, access, addr, size, value, ud):
        """Watchpoint: fires when the JIT reads the context challenge slot at x2+0x50."""
        base = getattr(self, '_challenge_ctx_watch_base', 0)
        if not base:
            return
        pc = self._last_pc if hasattr(self, '_last_pc') else 0
        off = addr - base
        try:
            data = bytes(uc.mem_read(addr, size))
            data_hex = data.hex()
        except Exception:
            data_hex = "??"
        entry = (pc, addr, off, size, data_hex)
        if not hasattr(self, '_challenge_ctx_read_count'):
            self._challenge_ctx_read_count = 0
        self._challenge_ctx_read_count += 1
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        if self._challenge_ctx_read_count <= 50:
            print(
                f"[CTX-CHAL-READ #{self._challenge_ctx_read_count}] "
                f"pc=JIT+{jit_off:#x} addr=ctx+0x50+{off:#x} size={size} data={data_hex}",
                flush=True,
            )
        elif self._challenge_ctx_read_count in (100, 200, 500, 1000):
            print(
                f"[CTX-CHAL-READ #{self._challenge_ctx_read_count}] (sampling) "
                f"pc=JIT+{jit_off:#x} addr=ctx+0x50+{off:#x} size={size} data={data_hex}",
                flush=True,
            )
        self._challenge_ctx_read_log.append(entry)

    def _dump_challenge_watch_summary(self):
        if hasattr(self, '_challenge_ctx_read_log') and self._challenge_ctx_read_log:
            print(
                f"\n[CTX-CHAL-WATCH] Total reads from x2+0x50..0x6f: "
                f"{len(self._challenge_ctx_read_log)}"
            )
            from collections import Counter
            pc_counts = Counter()
            for pc, addr, off, sz, data in self._challenge_ctx_read_log:
                jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
                pc_counts[(jit_off, off, sz)] += 1
            print(f"[CTX-CHAL-WATCH] Unique (pc, ctx_offset, size) combos: {len(pc_counts)}")
            for (jit_off, off, sz), cnt in pc_counts.most_common(20):
                print(f"  JIT+{jit_off:#x} reads ctx+0x50+{off:#x} ({sz}B) x{cnt}")
        elif hasattr(self, '_challenge_ctx_read_log'):
            print("\n[CTX-CHAL-WATCH] NO reads from x2+0x50..0x6f!")

        if hasattr(self, '_challenge_read_log') and self._challenge_read_log:
            print(f"\n[CHAL-WATCH] Total reads from sp+0x5f0..sp+0x650: {len(self._challenge_read_log)}")
            from collections import Counter
            pc_counts = Counter()
            for pc, addr, off, sz, data in self._challenge_read_log:
                jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
                pc_counts[(jit_off, off, sz)] += 1
            print(f"[CHAL-WATCH] Unique (pc, sp_offset, size) combos: {len(pc_counts)}")
            for (jit_off, off, sz), cnt in pc_counts.most_common(30):
                print(f"  JIT+{jit_off:#x} reads sp+{off:#x} ({sz}B) x{cnt}")
        elif hasattr(self, '_challenge_read_log'):
            print(f"\n[CHAL-WATCH] NO reads from challenge area sp+0x5f0..sp+0x650!")

    def _obj68_mem_write_hook(self, uc, access, addr, size, value, ud):
        """Watch writes to the active helper object's +0x68 field during JIT callback."""
        pc = uc.reg_read(UC_ARM64_REG_PC)
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        sp = uc.reg_read(UC_ARM64_REG_SP)
        x19 = uc.reg_read(UC_ARM64_REG_X19)
        x20 = uc.reg_read(UC_ARM64_REG_X20)
        base = getattr(self, '_obj68_watch_base', 0)
        off = addr - base if base else 0
        if not hasattr(self, '_obj68_write_count'):
            self._obj68_write_count = 0
        self._obj68_write_count += 1
        try:
            cur = bytes(uc.mem_read(base, 0x10)).hex() if base else "??"
        except Exception as exc:
            cur = f"ERR({exc})"
        sp50 = self._dump_mem_hex(uc, sp + 0x50, 0x20)
        print(f"[OBJ68-WRITE #{self._obj68_write_count}] pc=JIT+{jit_off:#x} "
              f"addr={addr:#x} off=+{off:#x} size={size} value={value:#x} "
              f"sp={sp:#x} x19={x19:#x} x20={x20:#x} sp+0x50={sp50} field68={cur}", flush=True)
        # Save the cert output from sp+0x50 SSO if it looks valid
        if off == 0 and value > 0:
            try:
                sp50_raw = bytes(uc.mem_read(sp + 0x50, 24))
                sp50_b0 = sp50_raw[0]
                if (sp50_b0 & 1) == 1:  # LONG SSO
                    sp50_n = struct.unpack("<Q", sp50_raw[8:16])[0]
                    sp50_p = struct.unpack("<Q", sp50_raw[16:24])[0]
                    print(f"[OBJ68-SSO-PROBE] sp+0x50 LONG n={sp50_n} ptr={sp50_p:#x}", flush=True)
                    if 0 < sp50_n <= 256 and sp50_p > 0x1000:
                        heap_data = bytes(uc.mem_read(sp50_p, min(sp50_n, 64)))
                        print(f"[OBJ68-SSO-HEAP] raw={heap_data.hex()} ascii={heap_data.decode('ascii', errors='replace')[:64]}", flush=True)
                        txt = heap_data.decode('ascii', errors='ignore').strip('\x00')
                        if len(txt) >= 48 and all(c in '0123456789ABCDEFabcdef' for c in txt[:48]):
                            self._jit_cert_output = txt[:48]
                            print(f"[OBJ68-CERT-SAVED] {txt[:48]}", flush=True)
                else:
                    n = sp50_b0 >> 1
                    txt = sp50_raw[1:1+min(n,22)].decode('ascii', errors='ignore').strip('\x00')
                    print(f"[OBJ68-SSO-SHORT] n={n} txt={txt!r}", flush=True)
            except Exception as e:
                print(f"[OBJ68-CERT-ERR] {e}", flush=True)

    def _sp50_mem_write_hook(self, uc, access, addr, size, value, ud):
        """Watch writes to the callback-local 16-byte source later copied into obj+0x68."""
        pc = uc.reg_read(UC_ARM64_REG_PC)
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        base = getattr(self, '_sp50_watch_base', 0)
        off = addr - base if base else 0
        if not hasattr(self, '_sp50_write_count'):
            self._sp50_write_count = 0
        self._sp50_write_count += 1
        try:
            cur = bytes(uc.mem_read(base, 0x20)).hex() if base else "??"
        except Exception as exc:
            cur = f"ERR({exc})"
        print(f"[SP50-WRITE #{self._sp50_write_count}] pc=JIT+{jit_off:#x} "
              f"addr={addr:#x} off=+{off:#x} size={size} value={value:#x} "
              f"sp50={cur}", flush=True)

    def _describe_sso_slot(self, uc, addr):
        try:
            raw = bytes(uc.mem_read(addr, 24))
        except Exception as exc:
            return f"{addr:#x}=ERR({exc})"
        if raw == b"\x00" * 24:
            return f"{addr:#x}=ZERO(raw={raw.hex()})"
        tag = raw[0]
        if (tag & 1) == 0:
            slen = tag >> 1
            data = raw[1:1 + min(slen, 22)]
            return f"{addr:#x}=SSO(len={slen},data={data!r},raw={raw.hex()})"
        size = struct.unpack("<Q", raw[8:16])[0]
        ptr = struct.unpack("<Q", raw[16:24])[0]
        preview = b""
        if 0 < size <= 0x100 and ptr > 0x1000:
            try:
                preview = bytes(uc.mem_read(ptr, min(size, 32)))
            except Exception:
                preview = b""
        return (
            f"{addr:#x}=LONG(size={size:#x},ptr={ptr:#x},"
            f"data={preview!r},raw={raw.hex()})"
        )

    def _describe_cert_session_ptr(self, uc, ptr):
        if not ptr:
            return "sess=0"
        parts = [f"sess={ptr:#x}"]
        try:
            parts.append(f"+0x210={self._describe_sso_slot(uc, ptr + 0x210)}")
        except Exception as exc:
            parts.append(f"+0x210=ERR({exc})")
        cont = self._safe_mem_read_qword(uc, ptr + 0x390) if ptr > 0x1000 else None
        parts.append(f"[+0x390]={self._format_opt_hex(cont)}")
        parts.append(f"[+0x398]={self._format_opt_hex(self._safe_mem_read_qword(uc, ptr + 0x398) if ptr > 0x1000 else None)}")
        parts.append(f"[+0x3a0]={self._format_opt_hex(self._safe_mem_read_qword(uc, ptr + 0x3A0) if ptr > 0x1000 else None)}")
        if cont and cont > 0x1000:
            parts.append(f"[cont+0x10]={self._format_opt_hex(self._safe_mem_read_qword(uc, cont + 0x10))}")
            parts.append(f"[cont+0x18]={self._format_opt_hex(self._safe_mem_read_qword(uc, cont + 0x18))}")
            parts.append(f"[cont+0x588]={self._format_opt_hex(self._safe_mem_read_qword(uc, cont + 0x588))}")
            parts.append(f"[cont+0x590]={self._format_opt_hex(self._safe_mem_read_qword(uc, cont + 0x590))}")
        return " ".join(parts)

    def _read_c_string(self, uc, addr, limit=0x100):
        if not addr or addr < 0x1000 or limit <= 0:
            return b""
        try:
            data = bytes(uc.mem_read(addr, limit))
        except Exception:
            return b""
        nul = data.find(b"\x00")
        if nul >= 0:
            return data[:nul]
        return data

    def _repair_shifted_hex_cstr(self, uc, addr, scan_len=0x100, min_run=24):
        if not addr or addr < 0x1000 or scan_len <= 1:
            return None
        try:
            data = bytearray(uc.mem_read(addr, scan_len))
        except Exception:
            return None
        if data[:1] != b"\x00":
            return None
        best_start = best_end = None
        run_start = None
        for idx, byte in enumerate(data):
            is_hex = (
                48 <= byte <= 57 or
                65 <= byte <= 70 or
                97 <= byte <= 102
            )
            if is_hex:
                if run_start is None:
                    run_start = idx
                continue
            if run_start is not None:
                if best_start is None or idx - run_start > best_end - best_start:
                    best_start, best_end = run_start, idx
                run_start = None
        if run_start is not None:
            if best_start is None or len(data) - run_start > best_end - best_start:
                best_start, best_end = run_start, len(data)
        if best_start in (None, 0) or best_end - best_start < min_run:
            return None
        run = bytes(data[best_start:best_end])
        try:
            if best_start == 0x24:
                # The recovered donor string lives in the adjacent 24-byte slot
                # at addr+0x24. Only the leading byte at addr is consumed from
                # the prefix slot; copying the full run back to addr would
                # overwrite the donor bytes at addr+0x24. Split the recovered
                # run across the two slots: prefix byte at addr, remaining tail
                # back into the donor slot.
                uc.mem_write(addr, run[:1] + (b"\x00" * (best_start - 1)))
                uc.mem_write(addr + best_start, run[1:] + b"\x00")
            else:
                uc.mem_write(addr, run + b"\x00")
        except Exception:
            return None
        return best_start, len(run), run[:32]

    def _describe_1627_output_obj(self, uc, obj):
        if not obj:
            return "obj=0"
        try:
            prefix = struct.unpack("<Q", uc.mem_read(obj + 0x98, 8))[0]
        except Exception as exc:
            prefix = f"ERR({exc})"
        raw = self._dump_mem_hex(uc, obj + 0x98, 0x20)
        slot = self._describe_sso_slot(uc, obj + 0xA0)
        return f"obj={obj:#x} +0x98={prefix} raw={raw} slot={slot}"

    def _install_1627_output_watch(self, uc, obj):
        if not obj or obj < 0x1000:
            return
        watch_base = obj + 0x98
        if getattr(self, '_1627_watch_base', 0) == watch_base:
            return
        self._1627_watch_base = watch_base
        self._1627_watch_obj = obj
        self._1627_output_write_count = 0
        h = uc.hook_add(
            UC_HOOK_MEM_WRITE,
            self._1627_output_mem_write_hook,
            begin=watch_base,
            end=watch_base + 0x1f,
        )
        self._per_run_hooks.append(h)
        print(
            f"[1627-WATCH] obj={obj:#x} watching {watch_base:#x}..{watch_base + 0x1f:#x} "
            f"{self._describe_1627_output_obj(uc, obj)}",
            flush=True,
        )

    def _1627_output_mem_write_hook(self, uc, access, addr, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        base = getattr(self, '_1627_watch_base', 0)
        off = addr - base if base else 0
        if not hasattr(self, '_1627_output_write_count'):
            self._1627_output_write_count = 0
        self._1627_output_write_count += 1
        # Save raw write data for extraction — the slot may be zeroed later
        if not hasattr(self, '_1627_raw_writes'):
            self._1627_raw_writes = bytearray(32)
        if 0 <= off < 32 and size <= 8:
            self._1627_raw_writes[off:off + size] = (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
        obj = getattr(self, '_1627_watch_obj', 0)
        print(
            f"[1627-OUT-WRITE #{self._1627_output_write_count}] pc=JIT+{jit_off:#x} "
            f"addr={addr:#x} off=+{off:#x} size={size} value={value:#x} "
            f"{self._describe_1627_output_obj(uc, obj)}",
            flush=True,
        )

    def _install_1702_save_slot_watch(self, uc, slot_addr):
        if slot_addr <= 0x1000:
            return
        watch_begin = slot_addr - 8
        watch_end = slot_addr + 7
        watched = set(getattr(self, '_1702_watched_slots', set()))
        if watch_begin not in watched:
            h = uc.hook_add(
                UC_HOOK_MEM_WRITE,
                self._1702_save_slot_write_hook,
                begin=watch_begin,
                end=watch_end,
            )
            self._per_run_hooks.append(h)
            watched.add(watch_begin)
            self._1702_watched_slots = watched
        self._1702_watch_slot = slot_addr
        self._1702_watch_slot_begin = watch_begin
        print(
            f"[1702-WATCH] pair={watch_begin:#x}..{watch_end:#x} "
            f"x22_x21={self._dump_mem_hex(uc, watch_begin, 0x10)}",
            flush=True,
        )

    def _1702_save_slot_write_hook(self, uc, access, addr, size, value, ud):
        if not getattr(self, '_1702_trace_active', False):
            return
        slot_addr = getattr(self, '_1702_watch_slot', 0)
        slot_begin = getattr(self, '_1702_watch_slot_begin', 0)
        if not slot_addr or not slot_begin:
            return
        if addr + size <= slot_begin or addr > slot_addr + 7:
            return
        pc = uc.reg_read(UC_ARM64_REG_PC)
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        # Save raw write data for extraction
        if not hasattr(self, '_1702_raw_writes'):
            self._1702_raw_writes = bytearray(16)
        off = addr - slot_begin
        if 0 <= off < 16 and size <= 8:
            self._1702_raw_writes[off:off + size] = (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
        print(
            f"[1702-SAVE-WRITE] pc=JIT+{jit_off:#x} addr={addr:#x} size={size} value={value:#x} "
            f"pair={slot_begin:#x}..{slot_addr + 7:#x} cur={self._dump_mem_hex(uc, slot_begin, 0x10)}",
            flush=True,
        )

    def _1702_should_trace_lr(self, lr_off):
        return lr_off in {
            0x1777A0, 0x1777BC, 0x1777C8, 0x1777DC,
            0x1777F0, 0x177800, 0x177814,
        }

    def _safe_read_qword(self, uc, addr):
        if addr <= 0x1000:
            return 0
        try:
            return struct.unpack("<Q", uc.mem_read(addr, 8))[0]
        except Exception:
            return 0

    def _describe_1702_call_frame(self, uc):
        sp = uc.reg_read(UC_ARM64_REG_SP)
        x21 = uc.reg_read(UC_ARM64_REG_X21)
        saved_x21 = self._safe_read_qword(uc, sp + 0x58)
        local_obj = self._safe_read_qword(uc, sp)
        helper_obj = self._safe_read_qword(uc, sp + 0x10)
        helper_vtbl = self._safe_read_qword(uc, helper_obj)
        helper_vcall = self._safe_read_qword(uc, helper_vtbl + 0x30) if helper_vtbl else 0
        local_field40 = self._safe_read_qword(uc, local_obj + 0x40) if local_obj else 0
        parts = [
            f"x0={uc.reg_read(UC_ARM64_REG_X0):#x}",
            f"x8={uc.reg_read(UC_ARM64_REG_X8):#x}",
            f"x9={uc.reg_read(UC_ARM64_REG_X9):#x}",
            f"x21={x21:#x}",
            f"saved_x21={saved_x21:#x}",
            f"slot={sp + 0x58:#x}",
            f"obj={local_obj:#x}",
            f"obj+0x10={self._dump_mem_hex(uc, local_obj + 0x10, 0x10) if local_obj else '0'}",
            f"obj+0x40={local_field40:#x}",
            f"helper={helper_obj:#x}",
            f"helper_vtbl={helper_vtbl:#x}",
            f"helper_vcall={helper_vcall:#x}",
            f"x21_head={self._dump_mem_hex(uc, x21, 0x20) if x21 > 0x1000 else 'NA'}",
            f"saved_head={self._dump_mem_hex(uc, saved_x21, 0x20) if saved_x21 > 0x1000 else 'NA'}",
        ]
        return " ".join(parts)

    def _1702_exec_range_hook(self, uc, addr, size, ud):
        off = addr - JIT_BASE
        if off == 0x1702C8:
            lr = uc.reg_read(UC_ARM64_REG_LR)
            lr_off = lr - JIT_BASE if JIT_BASE <= lr < JIT_BASE + JIT_SIZE else lr
            self._1702_trace_active = self._1702_should_trace_lr(lr_off)
            if not self._1702_trace_active:
                return
            self._1702_entry_count = getattr(self, '_1702_entry_count', 0) + 1
            self._1702_exec_count = 0
            self._1702_callsite = lr_off
            self._1702_last_state = None
            self._1702_last_x21 = uc.reg_read(UC_ARM64_REG_X21)
            self._1702_last_saved_x21 = 0
            print(
                f"[1702-ENTRY #{self._1702_entry_count}] callsite=JIT+{lr_off:#x} "
                f"caller_x21={uc.reg_read(UC_ARM64_REG_X21):#x} caller_sp={uc.reg_read(UC_ARM64_REG_SP):#x}",
                flush=True,
            )
            return
        if not getattr(self, '_1702_trace_active', False):
            return

        self._1702_exec_count = getattr(self, '_1702_exec_count', 0) + 1
        sp = uc.reg_read(UC_ARM64_REG_SP)
        saved_x21 = self._safe_read_qword(uc, sp + 0x58)
        x21 = uc.reg_read(UC_ARM64_REG_X21)
        w8 = uc.reg_read(UC_ARM64_REG_X8) & 0xFFFFFFFF
        w9 = uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF

        interesting = {
            0x1702E8, 0x170374, 0x170378, 0x17038C, 0x17039C, 0x1703A0,
            0x170410, 0x170414, 0x170434, 0x1704A8, 0x1704B8, 0x170510,
            0x170528, 0x170538, 0x17053C, 0x17056C, 0x170570, 0x17057C,
            0x170584, 0x170594, 0x1705A4, 0x1705F0, 0x1705F4, 0x1705FC,
            0x170604, 0x170610, 0x170614, 0x17061C, 0x170620, 0x170630,
        }
        x21_changed = x21 != getattr(self, '_1702_last_x21', x21)
        saved_changed = saved_x21 != getattr(self, '_1702_last_saved_x21', saved_x21)
        state_changed = off == 0x17056C and w8 != getattr(self, '_1702_last_state', None)
        if off == 0x1702E8:
            self._install_1702_save_slot_watch(uc, sp + 0x58)
        if off in interesting or x21_changed or saved_changed or state_changed:
            extra = self._describe_1702_call_frame(uc)
            print(
                f"[1702-EXEC #{self._1702_exec_count}] JIT+{off:#x} "
                f"callsite=JIT+{getattr(self, '_1702_callsite', 0):#x} "
                f"w8={w8:#010x} w9={w9:#010x} {extra}",
                flush=True,
            )
        self._1702_last_x21 = x21
        self._1702_last_saved_x21 = saved_x21
        if off == 0x17056C:
            self._1702_last_state = w8
        if off == 0x170630:
            print(
                f"[1702-RET #{getattr(self, '_1702_entry_count', 0)}] "
                f"callsite=JIT+{getattr(self, '_1702_callsite', 0):#x} "
                f"x21={x21:#x} saved_x21={saved_x21:#x}",
                flush=True,
            )
            self._1702_trace_active = False

    def _describe_1626_live_state(self, uc, off):
        sp = uc.reg_read(UC_ARM64_REG_SP)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x19 = uc.reg_read(UC_ARM64_REG_X19)
        x21 = uc.reg_read(UC_ARM64_REG_X21)
        x12 = uc.reg_read(UC_ARM64_REG_X12)
        x20 = uc.reg_read(UC_ARM64_REG_X20)
        x23 = uc.reg_read(UC_ARM64_REG_X23)
        x25 = uc.reg_read(UC_ARM64_REG_X25)
        x28 = uc.reg_read(UC_ARM64_REG_X28)
        state = uc.reg_read(UC_ARM64_REG_X8) & 0xFFFFFFFF
        next_state = uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF
        w30 = uc.reg_read(UC_ARM64_REG_X30) & 0xFFFFFFFF
        slot_20 = self._safe_read_qword(uc, sp + 0x20)
        slot_10 = self._safe_read_qword(uc, sp + 0x10)
        slot_18 = self._safe_read_qword(uc, sp + 0x18)
        slot_2c = self._safe_mem_read_u32(uc, sp + 0x2c)
        slot_30 = self._safe_read_qword(uc, sp + 0x30)
        slot_40 = self._safe_read_qword(uc, sp + 0x40)
        slot_48 = self._safe_read_qword(uc, sp + 0x48)
        slot_54 = self._safe_mem_read_u32(uc, sp + 0x54)
        slot_58 = self._safe_read_qword(uc, sp + 0x58)
        slot_60 = self._safe_read_qword(uc, sp + 0x60)
        slot_70 = self._safe_read_qword(uc, sp + 0x70)
        slot_80 = self._safe_read_qword(uc, sp + 0x80)
        parts = [
            f"pc=JIT+{off:#x}",
            f"x0={x0:#x}",
            f"x1={x1:#x}",
            f"x19={x19:#x}",
            f"x20={x20:#x}",
            f"w8_state={state:#010x}",
            f"w9_next={next_state:#010x}",
            f"w1={x1 & 0xFFFFFFFF:#010x}",
            f"w13={uc.reg_read(UC_ARM64_REG_X13) & 0xFFFFFFFF:#010x}",
            f"w20={x20 & 0xFFFFFFFF:#010x}",
            f"w21={x21 & 0xFFFFFFFF:#010x}",
            f"w22={uc.reg_read(UC_ARM64_REG_X22) & 0xFFFFFFFF:#010x}",
            f"w23={x23 & 0xFFFFFFFF:#010x}",
            f"w24={uc.reg_read(UC_ARM64_REG_X24) & 0xFFFFFFFF:#010x}",
            f"w26={uc.reg_read(UC_ARM64_REG_X26) & 0xFFFFFFFF:#010x}",
            f"w27={uc.reg_read(UC_ARM64_REG_X27) & 0xFFFFFFFF:#010x}",
            f"w30={w30:#010x}",
            f"sp+0x3c={self._safe_mem_read_u32(uc, sp + 0x3c):#010x}",
            f"[sp+0x10]={slot_10:#x}",
            f"[sp+0x18]={slot_18:#x}",
            f"[sp+0x20]={slot_20:#x}",
            f"[sp+0x2c]={slot_2c:#010x}",
            f"[sp+0x30]={slot_30:#x}",
            f"[sp+0x40]={slot_40:#x}",
            f"[sp+0x48]={slot_48:#x}",
            f"[sp+0x54]={slot_54:#010x}",
            f"[sp+0x58]={slot_58:#x}",
            f"[sp+0x60]={slot_60:#x}",
            f"[sp+0x70]={slot_70:#x}",
            f"[sp+0x80]={slot_80:#x}",
            f"x28={x28:#x}",
        ]
        if x12 > 0x1000:
            parts.append(f"x12={x12:#x}")
            v = self._safe_mem_read_u32(uc, x12)
            parts.append(f"[x12]={v:#010x}" if v is not None else "[x12]=None")
        else:
            parts.append(f"x12={x12:#x}")
        if x25 > 0x1000:
            parts.append(f"x25={x25:#x}")
            parts.append(f"[x25]={self._safe_mem_read_u32(uc, x25):#010x}")
        else:
            parts.append(f"x25={x25:#x}")
        return " ".join(parts)

    def _1627_exec_range_hook(self, uc, addr, size, ud):
        if not getattr(self, '_1627_trace_active', False):
            return
        off = addr - JIT_BASE
        self._1627_exec_count = getattr(self, '_1627_exec_count', 0) + 1
        critical = {
            0x16220C, 0x162250, 0x16227C, 0x1623EC, 0x162440, 0x162468, 0x1624D0, 0x162540, 0x162574,
            0x16257C, 0x162580, 0x162590, 0x1625A4, 0x162628, 0x162630,
            0x162650, 0x162698, 0x162728, 0x1627AC,
            0x1627D8, 0x1627F0, 0x162850, 0x162900, 0x162934, 0x16294C, 0x162980,
            0x1629A8, 0x1629CC, 0x162A98, 0x162A9C,
            0x162AA0, 0x162AB4, 0x162B7C, 0x162B9C, 0x162BCC, 0x162BDC, 0x162BF4,
            0x162C40, 0x162C44, 0x162C5C, 0x162CE0, 0x162D04, 0x162D18, 0x162D4C,
            0x162D68, 0x162DC0, 0x162E08, 0x162EEC, 0x162EFC, 0x162F3C, 0x162FA8,
            0x163124, 0x163188, 0x163344,
        }
        if self._1627_exec_count > 400 and off not in critical and self._1627_exec_count not in (500, 750, 1000):
            return
        if self._1627_exec_count > 1200:
            self._1627_trace_active = False
            return
        live_state_points = {
            0x16220C, 0x162250, 0x16227C, 0x1623EC, 0x162440, 0x162468, 0x1624D0, 0x162540, 0x162574,
            0x16257C, 0x162580, 0x162590, 0x1625A4, 0x162628, 0x162650,
            0x162698, 0x162728, 0x1627AC, 0x1627D8, 0x1627F0, 0x162900, 0x162934, 0x16294C,
        }
        if off in live_state_points:
            hit_counts = dict(getattr(self, '_1627_live_hit_counts', {}))
            hit_counts[off] = hit_counts.get(off, 0) + 1
            self._1627_live_hit_counts = hit_counts
            state_key = (
                off,
                uc.reg_read(UC_ARM64_REG_X8) & 0xFFFFFFFF,
                uc.reg_read(UC_ARM64_REG_X9) & 0xFFFFFFFF,
                self._safe_mem_read_u32(uc, uc.reg_read(UC_ARM64_REG_SP) + 0x3c),
            )
            if (
                hit_counts[off] <= 12
                or state_key != getattr(self, '_1627_last_live_key', None)
                or hit_counts[off] in (25, 50, 100, 200, 400, 800)
            ):
                prev_off = getattr(self, '_1627_last_live_off', None)
                prev_txt = f"{prev_off:#x}" if prev_off is not None else "None"
                print(
                    f"[1627-LIVE #{self._1627_exec_count}] "
                    f"prev={prev_txt} -> JIT+{off:#x} hit={hit_counts[off]} "
                    f"{self._describe_1626_live_state(uc, off)}",
                    flush=True,
                )
            self._1627_last_live_key = state_key
            self._1627_last_live_off = off
        obj = getattr(self, '_1627_watch_obj', 0)
        obj_slot = self._describe_sso_slot(uc, obj + 0xA0) if obj else "obj=0"
        print(
            f"[1627-EXEC #{self._1627_exec_count}] JIT+{off:#x} "
            f"x0={uc.reg_read(UC_ARM64_REG_X0):#x} x1={uc.reg_read(UC_ARM64_REG_X1):#x} "
            f"x8={uc.reg_read(UC_ARM64_REG_X8):#x} x19={uc.reg_read(UC_ARM64_REG_X19):#x} "
            f"x22={uc.reg_read(UC_ARM64_REG_X22):#x} sp={uc.reg_read(UC_ARM64_REG_SP):#x} "
            f"slot={obj_slot}",
            flush=True,
        )

    def _dump_mem_hex(self, uc, addr, size):
        try:
            return bytes(uc.mem_read(addr, size)).hex()
        except Exception as exc:
            return f"ERR({exc})"

    def _log_1af35c_entry(self, uc):
        if not hasattr(self, '_af35c_target_calls'):
            self._af35c_target_calls = 0
        self._af35c_target_calls += 1
        call_no = self._af35c_target_calls
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        self._af35c_active_call_no = call_no
        self._af35c_active_src = x1
        self._af35c_active_dst = x0
        print(
            f"[1AF35C-ENTRY #{call_no}] pc=JIT+0x1af35c lr=JIT+{lr - JIT_BASE:#x} "
            f"x0={x0:#x} x1={x1:#x} sp={sp:#x}",
            flush=True,
        )
        print(
            f"[1AF35C-ENTRY #{call_no} MEM] "
            f"dst0={self._dump_mem_hex(uc, x0, 0x40)} "
            f"src0={self._dump_mem_hex(uc, x1, 0x40)}",
            flush=True,
        )

    def _log_1af35c_return(self, uc):
        call_no = getattr(self, '_af35c_active_call_no', 0)
        if not call_no:
            return
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        x19 = uc.reg_read(UC_ARM64_REG_X19)
        src = getattr(self, '_af35c_active_src', 0)
        dst = getattr(self, '_af35c_active_dst', 0)
        print(
            f"[1AF35C-RET #{call_no}] pc=JIT+0x108464 x0={x0:#x} x19={x19:#x} sp={sp:#x} "
            f"src={src:#x} dst={dst:#x}",
            flush=True,
        )
        print(
            f"[1AF35C-RET #{call_no} MEM] "
            f"sp+0x50={self._dump_mem_hex(uc, sp + 0x50, 0x20)} "
            f"dst0={self._dump_mem_hex(uc, dst, 0x40) if dst else '0'} "
            f"x19+0xc8={self._dump_mem_hex(uc, x19 + 0xc8, 0x40) if x19 else '0'}",
            flush=True,
        )
        self._af35c_active_call_no = 0
        self._af35c_active_src = 0
        self._af35c_active_dst = 0

    def _log_6be48_entry(self, uc):
        if not hasattr(self, '_6be48_target_calls'):
            self._6be48_target_calls = 0
        self._6be48_target_calls += 1
        call_no = self._6be48_target_calls
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        self._6be48_active_call_no = call_no
        self._6be48_active_dst = x0
        self._6be48_active_src = x1
        self._6be48_active_len = x2
        self._6be48_active_lr = lr
        print(
            f"[6BE48-ENTRY #{call_no}] pc=JIT+0x6be48 lr=JIT+{lr - JIT_BASE:#x} "
            f"x0={x0:#x} x1={x1:#x} x2={x2:#x} sp={sp:#x}",
            flush=True,
        )
        print(
            f"[6BE48-ENTRY #{call_no} MEM] "
            f"dst0={self._dump_mem_hex(uc, x0, 0x20)} "
            f"src0={self._dump_mem_hex(uc, x1, min(max(x2, 0x10), 0x40) if x2 < 0x1000 else 0x20)}",
            flush=True,
        )

    def _log_6be48_return(self, uc, ret_off):
        call_no = getattr(self, '_6be48_active_call_no', 0)
        if not call_no:
            return
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        dst = getattr(self, '_6be48_active_dst', 0)
        src = getattr(self, '_6be48_active_src', 0)
        x2_len = getattr(self, '_6be48_active_len', 0)
        print(
            f"[6BE48-RET #{call_no}] pc=JIT+{ret_off:#x} x0={x0:#x} "
            f"dst={dst:#x} src={src:#x} len={x2_len:#x} sp={sp:#x}",
            flush=True,
        )
        print(
            f"[6BE48-RET #{call_no} MEM] "
            f"sp+0x50={self._dump_mem_hex(uc, sp + 0x50, 0x20)} "
            f"dst0={self._dump_mem_hex(uc, dst, 0x20) if dst else '0'}",
            flush=True,
        )
        self._6be48_active_call_no = 0
        self._6be48_active_dst = 0
        self._6be48_active_src = 0
        self._6be48_active_len = 0
        self._6be48_active_lr = 0

    def _log_post_success_snapshot(self, uc, off):
        """Capture a one-shot dump at the post-success split points."""
        if not hasattr(self, '_post_success_snapshots'):
            self._post_success_snapshots = set()
        if off in self._post_success_snapshots:
            return
        self._post_success_snapshots.add(off)

        sp = uc.reg_read(UC_ARM64_REG_SP)
        regs = [f"sp={sp:#x}"]
        for idx in range(31):
            regs.append(f"x{idx}={uc.reg_read(UC_ARM64_REG_X0 + idx):#x}")
        print(f"[POST-SUCCESS JIT+{off:#x} REGS] " + " ".join(regs), flush=True)

        stack_offsets = [
            0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78,
            0x5e8, 0x5f0, 0x600, 0x608, 0x610, 0x618, 0x620, 0x628, 0x630, 0x638,
            0x800, 0x808, 0x810, 0x818, 0x820, 0x828, 0x830, 0x838,
        ]
        stack_parts = []
        for stack_off in stack_offsets:
            try:
                data = bytes(uc.mem_read(sp + stack_off, 0x10))
                stack_parts.append(f"sp+{stack_off:#x}={data.hex()}")
            except Exception as exc:
                stack_parts.append(f"sp+{stack_off:#x}=ERR({exc})")
        print(f"[POST-SUCCESS JIT+{off:#x} STACK] " + " ".join(stack_parts), flush=True)

        for reg_name, reg_id in (
            ("x19", UC_ARM64_REG_X19),
            ("x21", UC_ARM64_REG_X21),
            ("x22", UC_ARM64_REG_X22),
            ("x27", UC_ARM64_REG_X27),
        ):
            obj = uc.reg_read(reg_id)
            if not obj:
                print(f"[POST-SUCCESS JIT+{off:#x} {reg_name}] 0", flush=True)
                continue
            try:
                blob = bytes(uc.mem_read(obj, 0x200))
                print(f"[POST-SUCCESS JIT+{off:#x} {reg_name}={obj:#x}] {blob.hex()}", flush=True)
            except Exception as exc:
                print(f"[POST-SUCCESS JIT+{off:#x} {reg_name}={obj:#x}] ERR({exc})", flush=True)

    def _sp2f0_mem_write_hook(self, uc, access, addr, size, value, user_data):
        watch = getattr(self, '_sp2f0_watch_range', None)
        if not watch:
            return
        lo, hi = watch
        if not (lo <= addr < hi):
            return
        cnt = getattr(self, '_sp2f0_write_count', 0) + 1
        self._sp2f0_write_count = cnt
        if cnt > 8:
            return
        pc = uc.reg_read(UC_ARM64_REG_PC)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        slot2f0 = self._safe_mem_read_qword(uc, lo) or 0
        slot2f8 = self._safe_mem_read_qword(uc, lo + 8) or 0
        print(
            f"[SP2F0-WRITE #{cnt}] pc={pc:#x} sp={sp:#x} addr={addr:#x} size={size} "
            f"value={value:#x} slot2f0={slot2f0:#x} slot2f8={slot2f8:#x}",
            flush=True,
        )

    def _src48_mem_write_hook(self, uc, access, addr, size, value, user_data):
        watch = getattr(self, '_src48_watch_range', None)
        if not watch:
            return
        lo, hi = watch
        if addr + size <= lo or addr >= hi:
            return
        cnt = getattr(self, '_src48_write_count', 0) + 1
        self._src48_write_count = cnt
        pc = uc.reg_read(UC_ARM64_REG_PC)
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        sp = uc.reg_read(UC_ARM64_REG_SP)
        if not hasattr(self, '_src48_raw_writes'):
            self._src48_raw_writes = bytearray(0x30)
        recent = list(getattr(self, '_src48_recent_writes', []))
        off = addr - lo
        recent.append((jit_off, off, size, value, sp))
        if len(recent) > 16:
            recent = recent[-16:]
        self._src48_recent_writes = recent
        try:
            preview = bytearray(uc.mem_read(lo, 0x30))
        except Exception:
            preview = bytearray(0x30)
        if 0 <= off < 0x30 and size <= 8:
            raw = (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
            self._src48_raw_writes[off:off + size] = raw
            preview[off:off + size] = raw
        hexish = (
            len(preview) == 0x30
            and all(b in b"0123456789abcdefABCDEF" for b in preview if b != 0)
            and sum(1 for b in preview if b != 0) >= 24
        )
        full_hex = (
            len(preview) == 0x30
            and all(b in b"0123456789abcdefABCDEF" for b in preview)
        )
        if full_hex:
            try:
                hex_text = bytes(preview).decode("ascii")
                if getattr(self, "_src48_last_full_hex", "") != hex_text:
                    self._src48_last_full_hex = hex_text
                    raw24 = bytes.fromhex(hex_text)
                    be_words = " ".join(
                        f"{int.from_bytes(raw24[i:i + 4], 'big'):08x}"
                        for i in range(0, len(raw24), 4)
                    )
                    le_words = " ".join(
                        f"{int.from_bytes(raw24[i:i + 4], 'little'):08x}"
                        for i in range(0, len(raw24), 4)
                    )

                    def _snap_ptr(reg_name, reg_value, span=0x20):
                        if reg_value <= 0x1000:
                            return f"{reg_name}={reg_value:#x}"
                        mapped = self._is_page_accessible(uc, reg_value & ~0xFFF)
                        head = self._dump_mem_hex(uc, reg_value, span) if mapped else "UNMAPPED"
                        return f"{reg_name}={reg_value:#x} mapped={mapped} head={head}"

                    x8 = uc.reg_read(UC_ARM64_REG_X8)
                    x9 = uc.reg_read(UC_ARM64_REG_X9)
                    x10 = uc.reg_read(UC_ARM64_REG_X10)
                    x11 = uc.reg_read(UC_ARM64_REG_X11)
                    x12 = uc.reg_read(UC_ARM64_REG_X12)
                    x13 = uc.reg_read(UC_ARM64_REG_X13)
                    x19 = uc.reg_read(UC_ARM64_REG_X19)
                    x20 = uc.reg_read(UC_ARM64_REG_X20)
                    x21 = uc.reg_read(UC_ARM64_REG_X21)
                    x22 = uc.reg_read(UC_ARM64_REG_X22)
                    x23 = uc.reg_read(UC_ARM64_REG_X23)
                    x24 = uc.reg_read(UC_ARM64_REG_X24)
                    x25 = uc.reg_read(UC_ARM64_REG_X25)
                    x26 = uc.reg_read(UC_ARM64_REG_X26)
                    x27 = uc.reg_read(UC_ARM64_REG_X27)
                    print(
                        f"[SRC48-RAW24] pc=JIT+{jit_off:#x} sp={sp:#x} slot={lo:#x} "
                        f"hex={hex_text} raw24={raw24.hex()} be=[{be_words}] le=[{le_words}] "
                        f"sp+0x578={self._dump_mem_hex(uc, sp + 0x578, 0x30)} "
                        f"sp+0x590={self._dump_mem_hex(uc, sp + 0x590, 0x18)} "
                        f"x23_obj={self._dump_mem_hex(uc, x23, 0x30) if x23 > 0x1000 else 'NA'} "
                        f"{_snap_ptr('x8', x8)} {_snap_ptr('x9', x9)} "
                        f"{_snap_ptr('x10', x10)} {_snap_ptr('x11', x11, 0x10)} "
                        f"{_snap_ptr('x12', x12, 0x10)} {_snap_ptr('x13', x13, 0x10)} "
                        f"{_snap_ptr('x19', x19)} {_snap_ptr('x20', x20)} "
                        f"{_snap_ptr('x21', x21)} {_snap_ptr('x22', x22)} "
                        f"{_snap_ptr('x23', x23)} {_snap_ptr('x24', x24)} "
                        f"{_snap_ptr('x25', x25)} {_snap_ptr('x26', x26)} {_snap_ptr('x27', x27)}",
                        flush=True,
                    )
            except Exception as exc:
                print(f"[SRC48-RAW24] decode failed err={exc}", flush=True)
        if cnt > 4 and not hexish:
            return
        print(
            f"[SRC48-WRITE #{cnt}] pc=JIT+{jit_off:#x} sp={sp:#x} addr={addr:#x} "
            f"off=+0x{off:x} size={size} value={value:#x} "
            f"cur={self._dump_mem_hex(uc, lo, 0x30)} post={bytes(preview).hex()}",
            flush=True,
        )

    def _raw24_mem_write_hook(self, uc, access, addr, size, value, user_data):
        watch = getattr(self, '_raw24_watch_range', None)
        if not watch:
            return
        lo, hi = watch
        if addr + size <= lo or addr >= hi:
            return
        cnt = getattr(self, '_raw24_write_count', 0) + 1
        self._raw24_write_count = cnt
        pc = uc.reg_read(UC_ARM64_REG_PC)
        jit_off = pc - JIT_BASE if pc >= JIT_BASE else pc
        sp = uc.reg_read(UC_ARM64_REG_SP)
        off = addr - lo
        try:
            preview = bytearray(uc.mem_read(lo, hi - lo))
        except Exception:
            preview = bytearray(hi - lo)
        if 0 <= off < len(preview) and size <= 8:
            raw = (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
            preview[off:off + size] = raw
        dense = sum(1 for b in preview[:0x1C] if b != 0) >= 8
        if cnt <= 12 or dense:
            print(
                f"[RAW24-WRITE #{cnt}] pc=JIT+{jit_off:#x} sp={sp:#x} addr={addr:#x} "
                f"off=+0x{off:x} size={size} value={value:#x} "
                f"buf={bytes(preview).hex()}",
                flush=True,
            )
        if dense:
            cur_hex = bytes(preview[:0x1C]).hex()
            if getattr(self, '_raw24_last_snapshot', '') != cur_hex:
                self._raw24_last_snapshot = cur_hex
                be_words = " ".join(
                    f"{int.from_bytes(preview[i:i + 4], 'big'):08x}"
                    for i in range(0, 0x18, 4)
                )
                le_words = " ".join(
                    f"{int.from_bytes(preview[i:i + 4], 'little'):08x}"
                    for i in range(0, 0x18, 4)
                )
                print(
                    f"[RAW24-BUF] pc=JIT+{jit_off:#x} sp={sp:#x} slot={lo:#x} "
                    f"raw24={cur_hex[:48]} tail={cur_hex[48:]} "
                    f"be=[{be_words}] le=[{le_words}]",
                    flush=True,
                )

    def _inline_sha_mem_read_hook(self, uc, access, addr, size, value, user_data):
        watch = getattr(self, "_inline_sha_read_watch_range", None)
        if not watch:
            return
        lo, hi = watch
        if not (lo <= addr < hi):
            return
        cnt = getattr(self, "_inline_sha_read_count", 0) + 1
        self._inline_sha_read_count = cnt
        if cnt > 24:
            return
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if cnt == 1 and not getattr(self, "_inline_sha_msg_logged", False):
            self._inline_sha_msg_logged = True
            x19 = uc.reg_read(UC_ARM64_REG_X19)
            x26 = uc.reg_read(UC_ARM64_REG_X26)
            x27 = uc.reg_read(UC_ARM64_REG_X27)
            x29 = uc.reg_read(UC_ARM64_REG_X29)
            msg32 = self._dump_mem_hex_fallback(uc, lo, min(0x20, hi - lo))
            msg64 = self._dump_mem_hex_fallback(uc, lo, min(0x40, hi - lo))
            print(
                f"[INLINE-SHA-MSG] pc=JIT+{pc - JIT_BASE:#x} x0={lo:#x} "
                f"msg_len_observed=0x20 w29={x29 & 0xFFFFFFFF:#x} x26={x26:#x} "
                f"x27={x27:#x} x19={x19:#x} msg32={msg32} msg64={msg64}",
                flush=True,
            )
        block_base = max(lo, addr & ~0x3F)
        block_size = min(0x40, hi - block_base)
        block_hex = self._dump_mem_hex_fallback(uc, block_base, block_size)
        print(
            f"[INLINE-SHA-READ #{cnt}] pc=JIT+{pc - JIT_BASE:#x} addr={addr:#x} size={size} "
            f"watch=+0x{addr - lo:x} block@{block_base:#x}={block_hex}",
            flush=True,
        )

    def _inline_sha_mem_write_hook(self, uc, access, addr, size, value, user_data):
        watch = getattr(self, "_inline_sha_write_watch_range", None)
        if not watch:
            return
        lo, hi = watch
        if addr + size <= lo or addr >= hi:
            return
        cnt = getattr(self, "_inline_sha_write_count", 0) + 1
        self._inline_sha_write_count = cnt
        if cnt > 32:
            return
        pc = uc.reg_read(UC_ARM64_REG_PC)
        off = addr - lo
        block_base = max(lo, addr & ~0x3F)
        block_size = min(0x40, hi - block_base)
        block_hex = self._dump_mem_hex_fallback(uc, block_base, block_size)
        print(
            f"[INLINE-SHA-WRITE #{cnt}] pc=JIT+{pc - JIT_BASE:#x} addr={addr:#x} off=+0x{off:x} "
            f"size={size} value={value:#x} block@{block_base:#x}={block_hex}",
            flush=True,
        )

    def _sha_input_mem_write_hook(self, uc, access, addr, size, value, user_data):
        watch = getattr(self, "_sha_input_watch_range", None)
        if not watch:
            return
        lo, hi = watch
        if addr + size <= lo or addr >= hi:
            return
        cnt = getattr(self, "_sha_input_write_count", 0) + 1
        self._sha_input_write_count = cnt
        pc = uc.reg_read(UC_ARM64_REG_PC)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        off = addr - lo
        try:
            preview = bytearray(uc.mem_read(lo, hi - lo))
        except Exception:
            preview = bytearray(hi - lo)
        if 0 <= off < len(preview) and size <= 8:
            raw = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
            preview[off:off + size] = raw
        cur_hex = bytes(preview).hex()
        if cnt <= 24:
            print(
                f"[SHA32-WRITE #{cnt}] pc=JIT+{pc - JIT_BASE:#x} sp={sp:#x} "
                f"addr={addr:#x} off=+0x{off:x} size={size} value={value:#x} "
                f"buf={cur_hex}",
                flush=True,
            )
        if getattr(self, "_sha_input_last_snapshot", "") != cur_hex:
            self._sha_input_last_snapshot = cur_hex
            print(
                f"[SHA32-BUF] pc=JIT+{pc - JIT_BASE:#x} sp={sp:#x} slot={lo:#x} "
                f"data={cur_hex}",
                flush=True,
            )

    def _encoder_obj_needs_snapshot(self, uc, obj):
        """Heuristic: tokenProc built only the skeletal helper object.

        On the broken cert path the helper arriving at JIT entry has the
        challenge slot but the later vector/container family is still zeroed.
        The dormant snapshot builder provides those fields, so only swap when
        the native object is still obviously empty.
        """
        if not obj:
            return False
        # The skeletal helper still carries non-zero status words at +0xd0 and
        # +0xe0, so the old "all these offsets must be zero" heuristic never
        # fired. The signal we actually care about is whether the 24-byte
        # vector structs were populated.
        needs_snapshot = False
        for off in (0x80, 0x98, 0xB0, 0xC8):
            try:
                begin, cur, end = struct.unpack("<QQQ", bytes(uc.mem_read(obj + off, 0x18)))
            except Exception:
                return False
            if begin == 0 and cur == 0 and end == 0:
                needs_snapshot = True
        return needs_snapshot

    def _log_encoder_vector_state(self, uc, tag, obj):
        if not obj:
            print(f"[ENC-VEC {tag}] obj=0", flush=True)
            return
        parts = [f"obj={obj:#x}"]
        for off in (0x68, 0x70, 0x80, 0x88, 0x98, 0xB0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE4):
            try:
                data = bytes(uc.mem_read(obj + off, 0x18))
                parts.append(f"+{off:#x}={data.hex()}")
            except Exception as exc:
                parts.append(f"+{off:#x}=ERR({exc})")
        print(f"[ENC-VEC {tag}] " + " ".join(parts), flush=True)

    def _log_encoder_d0_probe(self, uc, off):
        x22 = uc.reg_read(UC_ARM64_REG_X22)
        x19 = uc.reg_read(UC_ARM64_REG_X19)
        x8 = uc.reg_read(UC_ARM64_REG_X8)
        x9 = uc.reg_read(UC_ARM64_REG_X9)
        sp = uc.reg_read(UC_ARM64_REG_SP)
        print(
            f"[ENC-D0 JIT+{off:#x}] x22={x22:#x} x19={x19:#x} x8={x8:#x} x9={x9:#x} sp={sp:#x}",
            flush=True,
        )
        self._log_encoder_vector_state(uc, f"JIT+{off:#x}", x22)

    def _dispatch_probe_hook(self, uc, addr, size, ud):
        self._last_pc = addr
        if addr == JIT_BASE + 0x1af35c:
            lr = uc.reg_read(UC_ARM64_REG_LR)
            if lr == JIT_BASE + 0x108464:
                self._log_1af35c_entry(uc)
        elif addr == JIT_BASE + 0x6be48:
            lr = uc.reg_read(UC_ARM64_REG_LR)
            if lr in (JIT_BASE + 0x108454, JIT_BASE + 0x108524):
                self._log_6be48_entry(uc)
        elif addr == JIT_BASE + 0x108464:
            self._log_1af35c_return(uc)
        elif addr == JIT_BASE + 0x108454:
            self._log_6be48_return(uc, 0x108454)
        elif addr == JIT_BASE + 0x108524:
            self._log_6be48_return(uc, 0x108524)
        elif addr in (
            JIT_BASE + 0x108994,
            JIT_BASE + 0x1089D8,
            JIT_BASE + 0x1089E0,
            JIT_BASE + 0x1089F8,
        ):
            self._log_encoder_d0_probe(uc, addr - JIT_BASE)
        if addr == JIT_ENCODER_FN and hasattr(self, '_challenge_hex'):
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            sp = uc.reg_read(UC_ARM64_REG_SP)
            if x2 and self._encoder_obj_needs_snapshot(uc, x2):
                snap_obj = self._build_encoder_object_from_snapshot(uc, x2)
                if snap_obj:
                    print(f"[ENC-SNAPSHOT-SWAP] x2 {x2:#x} -> {snap_obj:#x}", flush=True)
                    self._log_encoder_vector_state(uc, "PRE", x2)
                    uc.reg_write(UC_ARM64_REG_X2, snap_obj)
                    x2 = snap_obj
                    self._log_encoder_vector_state(uc, "POST", x2)
            if x2:
                try:
                    self._write_sso(uc, x2 + 0x50, self._challenge_hex.encode('ascii'))
                except Exception:
                    pass
                self._challenge_ctx_watch_base = x2 + 0x50
                self._challenge_ctx_watch_end = x2 + 0x6f
                self._challenge_ctx_read_log = []
                self._challenge_ctx_read_count = 0
                try:
                    print(
                        f"[ENC-CTX-CHAL] {self._describe_sso_slot(uc, x2 + 0x50)}",
                        flush=True,
                    )
                except Exception:
                    pass
                h = uc.hook_add(
                    UC_HOOK_MEM_READ,
                    self._challenge_ctx_mem_read_hook,
                    begin=x2 + 0x50,
                    end=x2 + 0x6f,
                )
                self._per_run_hooks.append(h)
                if not hasattr(self, '_obj68_watch_hook_installed'):
                    self._obj68_watch_hook_installed = True
                    self._obj68_watch_base = x2 + 0x68
                    self._obj68_write_count = 0
                    h = uc.hook_add(UC_HOOK_MEM_WRITE, self._obj68_mem_write_hook,
                                begin=x2 + 0x68, end=x2 + 0x6f)
                    self._per_run_hooks.append(h)
                if not hasattr(self, '_sp50_watch_hook_installed'):
                    self._sp50_watch_hook_installed = True
                    self._sp50_watch_base = sp + 0x50
                    self._sp50_write_count = 0
                    h = uc.hook_add(UC_HOOK_MEM_WRITE, self._sp50_mem_write_hook,
                                begin=sp + 0x50, end=sp + 0x6f)
                    self._per_run_hooks.append(h)
        # Log JIT encoder entry args once
        if addr == JIT_ENCODER_FN and not hasattr(self, '_encoder_entry_logged'):
            self._encoder_entry_logged = True
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            sp = uc.reg_read(UC_ARM64_REG_SP)
            print(f"[ENC-ENTRY] fx(x0={x0:#x}, x1={x1:#x}, x2={x2:#x}, x3={x3:#x}) sp={sp:#x}")
            # Dump encoder object fields to find the descriptor range
            if x2:
                try:
                    for off in range(0, 0xe8, 8):
                        val = struct.unpack("<Q", uc.mem_read(x2 + off, 8))[0]
                        if val != 0:
                            print(f"  [ENC-OBJ] x2+{off:#04x} = {val:#018x}")
                except Exception as e:
                    print(f"  [ENC-OBJ] dump error: {e}")
            # Dump session descriptor range
            if x1:
                try:
                    print(f"  [SRC-OBJ] x1+0x210 {self._describe_sso_slot(uc, x1 + 0x210)}")
                    for soff in [0x318, 0x320, 0x328, 0x330]:
                        val = struct.unpack("<Q", uc.mem_read(x1 + soff, 8))[0]
                        print(f"  [SESS] x1+{soff:#05x} = {val:#018x}")
                except Exception as e:
                    print(f"  [SESS] dump error: {e}")
            # Install memory read watchpoint on challenge area (sp+0x5f0..sp+0x650)
            # x23 = sp+0x578, so x23+0x88 = sp+0x600, challenge SSO at sp+0x620
            self._fx_sp = sp
            self._challenge_watch_base = sp + 0x5f0
            self._challenge_watch_end = sp + 0x650
            self._challenge_read_log = []
            h = uc.hook_add(UC_HOOK_MEM_READ, self._challenge_mem_read_hook,
                        begin=sp + 0x5f0, end=sp + 0x650)
            self._per_run_hooks.append(h)
            if not hasattr(self, '_1627_range_hook_installed'):
                self._1627_range_hook_installed = True
                self._1627_trace_active = False
                self._1627_exec_count = 0
                h = uc.hook_add(
                    UC_HOOK_CODE,
                    self._1627_exec_range_hook,
                    begin=JIT_BASE + 0x161f40,
                    end=JIT_BASE + 0x163364,
                )
                self._per_run_hooks.append(h)
            if not hasattr(self, '_1702_range_hook_installed'):
                self._1702_range_hook_installed = True
                self._1702_trace_active = False
                self._1702_exec_count = 0
                self._1702_entry_count = 0
                h = uc.hook_add(
                    UC_HOOK_CODE,
                    self._1702_exec_range_hook,
                    begin=JIT_BASE + 0x1702c8,
                    end=JIT_BASE + 0x170630,
                )
                self._per_run_hooks.append(h)
            # Also watch key branch points and post-CFF code
            self._fx_branch_probes = {}
            for probe_off in [0xceba0, 0x1cee54, 0x1cee58, 0x1cee5c, 0x1cee60, 0x1cee64, 0x1cee68, 0x1cee6c, 0x108448, 0x108450, 0x108458, 0x108528, 0x108530, 0x108538, 0x108d1c, 0x108d20, 0x108d24, 0x108f88, 0x108fa0, 0x108fa4, 0x108fcc, 0x1090c0,
                              0x1c3318, 0x1c87a4,  # CFF computation path decision (both hubs)
                              0x155ba4, 0x155bac, 0x155bb0,
                              0x155c30, 0x155c50, 0x155c6c, 0x155c70, 0x155c9c, 0x155d60, 0x155d64,
                              0x15657c, 0x1565a0, 0x1565ac, 0x1565b0, 0x1565f0, 0x1565f8,  # stage 2 format
                              0x1566dc,  # stage 2 format loop entry (sprintf fast-forward)
                              0x156064, 0x1560d8, 0x156100,
                              0x15a3bc, 0x15a62c, 0x15a670, 0x15aa00, 0x15af90, 0x15b178,
                              0x1c20f4, 0x1c2124, 0x1c2470, 0x1c8854, 0x1c2180,
                              0x1c50d4, 0x1c50d8,  # before/after bl 0x1c88a0
                              0x1c6314, 0x1c6318,  # before/after bl 0x1d126c
                              0x1c50dc, 0x1c631c,  # return value stores
                              0x1c7554, 0x1c7560,  # decision point
                              0x1c75e0, 0x1c7630,  # return 0 vs return 1
                              0x1d0ac0, 0x1d0ae0,  # 0x1c88a0 epilogue (mov w0,w19 / ret)
                              0x1d0ae4, 0x1d0b0c,  # 0x1c88a0 failure/success paths
                              0x1d2480, 0x1d24a4,  # 0x1d126c epilogue
                              0x1ce014, 0x1ce018,  # 0x1c88a0 empty collection check
                              0x1ce084, 0x1cec94,  # 0x1c88a0 iteration / direct success
                              0x1cee70, 0x1cee88,  # 0x1c88a0 ceba0 / loop exhaustion
                              0x1d1930, 0x1d190c,  # 0x1d126c result setters
                              0x1d1710, 0x1d20ac,  # 0x1d126c: set sp+28=1, copy sp+28→sp+24
                              0x1d212c,  # 0x1d126c CFF hub
                              0x1d2088, 0x1d2094,  # 0x1d126c: bl 0x1d8a54 and tst ret
                              0x1c3364, 0x1c3374,  # post-success CFF path to 0xce75c
                              0x1c32b4,  # cert CFF Hub1 dispatch
                              0x1c3374,  # cert CFF Hub1 bl 0xce75c
                              0x1c8738,  # cert post-success CFF hub
                              0x20ffec,  # potential hash fn
                              0x1702e8, 0x17039c, 0x1703a0, 0x170538, 0x17053c, 0x17061c, 0x170620,  # 0x1702c8 save/restore path
                              0x6af14, 0x6ae6c, 0x6aec8, 0x6aef8, 0x6b6b4, 0x6b6f8, 0x6b700, 0x6b738, 0x6b780, 0x6b794, 0x6b79c, 0x6b7b8,
                              0x177290, 0x1772c8, 0x1772cc, 0x1772f4,  # 0x177290 entry + source collection load
                              0x177654, 0x177664, 0x177670, 0x177680, 0x17768c, 0x1776b4, 0x1776c0, 0x177754, 0x177770, 0x1777d4,  # filter diagnostics for 0x177290 collection loop
                              0x177728, 0x177730, 0x177740, 0x177770, 0x17777c, 0x177790, 0x1777a0, 0x1777ac, 0x1777b4, 0x1777c0, 0x1777d4, 0x1777dc, 0x1777e4, 0x1777f0,  # upstream helper feeding 0x1629a8
                              0x177ebc, 0x177f04, 0x177f4c, 0x178040, 0x17804c, 0x1780cc, 0x1780d0, 0x178114, 0x1781c4, 0x178910, 0x1789cc, 0x1789d8, 0x178a30, 0x178b60, 0x178b70, 0x178b80, 0x178bfc,  # formatter helper + append path
                              0x178170, 0x1781a8,  # upstream helper finalize/return
                              0x108468, 0x108480, 0x108484, 0x108618, 0x108630, 0x10886c, 0x108fc0,  # mode-2 path in 0x10828c / sp+0x2f0 tracking
                              0x10935c, 0x10939c, 0x1093a0,  # post-append string merge/build
                              0x10e41c, 0x113454, 0x1134e8, 0x115a50, 0x115f24, 0x1173e4,  # later memcpy-heavy builder path
                              0x11cf7c, 0x11cf2c, 0x11cf84, 0x11ca30,  # hash write diagnostics
                              0x11cf90, 0x11cfa0, 0x11cfb0, 0x11cfc0, 0x109184,  # output write path in 0x10875c
                              0x11cae0, 0x11cae4, 0x11cb1c, 0x11cb28,  # 0x1627d8 call + sp+0x810→sp+0x560 copy
                              0x11cd1c, 0x121634, 0x121668, 0x12168c, 0x1218e8,  # comparison gate + inline SHA-256 path
                              0x149054, 0x14a4a4,  # feeder buffer build / finalized pre-SHA message
                              0x14b894, 0x14ba3c, 0x14cecc, 0x14d0e4, 0x14e5f8, 0x14f9f4,  # SHA32 source writer blocks
                              0x14fa14, 0x14fa24, 0x14fa38, 0x14fa54, 0x14fbb0, 0x14fc24,  # candidate inline SHA / decrypted vector path
                              0x14ff50, 0x1500b0, 0x1500c0,  # inline SHA helper entry/update/finalize callsites
                              0x1501a0, 0x1503ec, 0x150504, 0x1505b4,  # inline SHA state update/finalize/digest
                              0x56d04, 0x56d1c,  # bulk XOR decrypt fast-forward (outer + inner)
                              0x131290,  # strlen fast-forward
                              0x13138c, 0x1313e0, 0x1314d4, 0x131510, 0x131578,  # strlen-2/hex-parse/strlen-3a/3b/4 fast-forwards
                              0x132528, 0x132598, 0x132568, 0x1325ec, 0x13276c, 0x1329bc,  # XOR scrambler loops + post-scrambler
                              0x162628, 0x16220c, 0x1622cc,  # CFF 0x162628 hub + handler probes
                              0x1627d8, 0x1627f0, 0x162850,  # cold dispatcher / state handoff
                              0x1629a8, 0x162a74, 0x162a84, 0x162ae0, 0x162aec, 0x162b04, 0x162b9c, 0x162bcc, 0x162bf4,  # real helper entry / precheck / candidate setup
                              0x162c40, 0x162c44, 0x162c5c, 0x162d68,  # callback + state dispatcher
                              0x162eec, 0x163344,  # output write + return
                              0x16bb2c, 0x16bb34, 0x16bb38, 0x16bb40, 0x16bb84,  # unique post-SHA consumer chain
                              0x1654ec, 0x165548, 0x165588, 0x16565c, 0x16567c, 0x165690, 0x165694, 0x1656b8, 0x1656bc, 0x1656f0, 0x1658a8,  # post-precheck formatter/token path
                              0x1090d0, 0x1090d8, 0x109118, 0x109150, 0x109160, 0x109180,  # init path
                             ]:
                probe_addr = JIT_BASE + probe_off
                h = uc.hook_add(UC_HOOK_CODE, self._fx_flow_probe_hook,
                            begin=probe_addr, end=probe_addr + 4)
                self._per_run_hooks.append(h)
            # Temporary: wide trace for CFF 0x162628 dispatch path
            pass  # removed wide trace hook (too slow)

        # Debug: trace code path entering the output write area
            if not hasattr(self, '_output_area_traced'):
                self._output_area_traced = False
                def _trace_output_area(uc2, address, size, user_data):
                    off2 = address - JIT_BASE
                    if 0x11ce00 <= off2 <= 0x11d000:
                        if not hasattr(self, '_output_area_pcs'):
                            self._output_area_pcs = []
                        self._output_area_pcs.append(off2)
                        if len(self._output_area_pcs) <= 50:
                            print(f"[OUTPUT-AREA] JIT+{off2:#x}", flush=True)
                h = uc.hook_add(UC_HOOK_CODE, _trace_output_area,
                            begin=JIT_BASE + 0x11ce00, end=JIT_BASE + 0x11d000)
                self._per_run_hooks.append(h)
                self._output_area_traced = True
        if addr == JIT_BASE + 0x10886C and not hasattr(self, '_sp2f0_watch_installed'):
            sp = uc.reg_read(UC_ARM64_REG_SP)
            base = sp + 0x2F0
            self._sp2f0_watch_installed = True
            self._sp2f0_watch_range = (base, base + 0x10)
            self._sp2f0_write_count = 0
            print(
                f"[SP2F0-WATCH] base={base:#x} slot2f0={self._safe_mem_read_qword(uc, base) or 0:#x} "
                f"slot2f8={self._safe_mem_read_qword(uc, base + 8) or 0:#x}",
                flush=True,
            )
            h = uc.hook_add(
                UC_HOOK_MEM_WRITE,
                self._sp2f0_mem_write_hook,
                begin=base,
                end=base + 0x0F,
            )
            self._per_run_hooks.append(h)
        if addr == JIT_BASE + 0x10886C and not getattr(self, '_src48_watch_installed', False):
            sp = uc.reg_read(UC_ARM64_REG_SP)
            base = sp - 0x458
            self._src48_watch_installed = True
            self._src48_watch_range = (base, base + 0x30)
            self._src48_write_count = 0
            self._src48_memcpy_count = 0
            self._src48_raw_writes = bytearray(0x30)
            print(
                f"[SRC48-WATCH] base={base:#x} sp={sp:#x} cur={self._dump_mem_hex(uc, base, 0x30)}",
                flush=True,
            )
            h = uc.hook_add(
                UC_HOOK_MEM_WRITE,
                self._src48_mem_write_hook,
                begin=base,
                end=base + 0x2F,
            )
            self._per_run_hooks.append(h)
        if addr == JIT_BASE + 0x10886C and not getattr(self, '_sha_input_watch_installed', False):
            sp = uc.reg_read(UC_ARM64_REG_SP)
            base = sp + 0x8F0
            self._sha_input_watch_installed = True
            self._sha_input_watch_range = (base, base + 0x20)
            self._sha_input_write_count = 0
            self._sha_input_memcpy_count = 0
            self._sha_input_last_snapshot = ""
            print(
                f"[SHA32-WATCH] base={base:#x} sp={sp:#x} cur={self._dump_mem_hex(uc, base, 0x20)}",
                flush=True,
            )
            h = uc.hook_add(
                UC_HOOK_MEM_WRITE,
                self._sha_input_mem_write_hook,
                begin=base,
                end=base + 0x1F,
            )
            self._per_run_hooks.append(h)
        if addr == JIT_BASE + 0x108480 and not getattr(self, '_raw24_watch_installed', False):
            outbuf = uc.reg_read(UC_ARM64_REG_X8)
            base = outbuf - 0x42C
            self._raw24_watch_installed = True
            self._raw24_watch_range = (base, base + 0x20)
            self._raw24_write_count = 0
            self._raw24_last_snapshot = ""
            self._raw24_memcpy_count = 0
            print(
                f"[RAW24-WATCH] base={base:#x} outbuf={outbuf:#x} cur={self._dump_mem_hex(uc, base, 0x20)}",
                flush=True,
            )
            h = uc.hook_add(
                UC_HOOK_MEM_WRITE,
                self._raw24_mem_write_hook,
                begin=base,
                end=base + 0x1F,
            )
            self._per_run_hooks.append(h)
        if addr == JIT_BASE + 0x10886C and not getattr(self, '_raw24_watch_installed', False):
            sp = uc.reg_read(UC_ARM64_REG_SP)
            base = sp + 0x764
            self._raw24_watch_installed = True
            self._raw24_watch_range = (base, base + 0x20)
            self._raw24_write_count = 0
            self._raw24_last_snapshot = ""
            print(
                f"[RAW24-WATCH] base={base:#x} sp={sp:#x} cur={self._dump_mem_hex(uc, base, 0x20)}",
                flush=True,
            )
            h = uc.hook_add(
                UC_HOOK_MEM_WRITE,
                self._raw24_mem_write_hook,
                begin=base,
                end=base + 0x1F,
            )
            self._per_run_hooks.append(h)
        # Debug: trace CFF data reads at problematic addresses
        cff_off = addr - JIT_BASE
        if cff_off == 0x8c9c0:  # add x5, x5, #0x348 → then ldr x5, [x5]
            if not hasattr(self, '_dbg_8c9c0'):
                self._dbg_8c9c0 = 0
            self._dbg_8c9c0 += 1
            if self._dbg_8c9c0 <= 3:
                x5 = uc.reg_read(UC_ARM64_REG_X5)
                fp = uc.reg_read(UC_ARM64_REG_X29)
                fp_m80 = fp_m60 = 0
                try:
                    fp_m80 = struct.unpack("<Q", uc.mem_read(fp - 0x80, 8))[0]
                    fp_m60 = struct.unpack("<Q", uc.mem_read(fp - 0x60, 8))[0]
                except: pass
                # Also read session_obj[0x388] to see if it was corrupted
                sess_388 = 0
                sp_val = 0
                try:
                    sp_val = uc.reg_read(UC_ARM64_REG_SP)
                    sess_ptr_raw = struct.unpack("<Q", uc.mem_read(sp_val + 0x60, 8))[0]
                    sess_388 = struct.unpack("<Q", uc.mem_read(sess_ptr_raw + 0x388, 8))[0]
                except: pass
                print(f"[CFF-DBG 0x8c9c0 #{self._dbg_8c9c0}] x5={x5:#x} [fp-0x80]={fp_m80:#x} "
                      f"[fp-0x60]={fp_m60:#x} sess[0x388]={sess_388:#x}", flush=True)
        elif cff_off == 0x8c034:  # ldur x30, [fp, #-0x60] → linked list walk
            if not hasattr(self, '_dbg_8c034'):
                self._dbg_8c034 = 0
            self._dbg_8c034 += 1
            if self._dbg_8c034 <= 3:
                fp = uc.reg_read(UC_ARM64_REG_X29)
                fp_m60 = 0
                try:
                    fp_m60 = struct.unpack("<Q", uc.mem_read(fp - 0x60, 8))[0]
                except: pass
                v8 = v16 = 0
                if fp_m60 > 0x1000:
                    try:
                        v8 = struct.unpack("<Q", uc.mem_read(fp_m60 + 8, 8))[0]
                        v16 = struct.unpack("<Q", uc.mem_read(fp_m60 + 0x10, 8))[0]
                    except: pass
                print(f"[CFF-DBG 0x8c034 #{self._dbg_8c034}] [fp-0x60]={fp_m60:#x} "
                      f"[+8]={v8:#x} [+0x10]={v16:#x}", flush=True)
        self._record_x28_trace(uc, addr)
        self._record_dispatch_trace(uc, addr)

    def _post_cff_dispatch_hub_hook(self, uc, addr, size, ud):
        self._last_pc = addr
        self._record_x28_trace(uc, addr)

        fp = uc.reg_read(UC_ARM64_REG_X29)
        w8 = uc.reg_read(UC_ARM64_REG_X8) & 0xFFFFFFFF
        key = (fp, w8)
        if key == self._post_cff_dispatch_last_key:
            self._post_cff_dispatch_same_count += 1
        else:
            self._post_cff_dispatch_last_key = key
            self._post_cff_dispatch_same_count = 1

        if self._post_cff_dispatch_same_count == JIT_POST_CFF_LOOP_THRESHOLD:
            self._post_cff_dispatch_skips += 1
            print(
                f"[JIT-HUB-SKIP #{self._post_cff_dispatch_skips}] "
                f"hub={addr:#x} fp={fp:#x} w8={w8:#010x}"
            )
            self._force_return_from_stall(uc, addr, fp)
            self._post_cff_dispatch_last_key = None
            self._post_cff_dispatch_same_count = 0

    def _is_plausible_exec_target(self, addr):
        if addr in self.hooked_functions:
            return True
        if JIT_BASE <= addr < JIT_BASE + JIT_SIZE:
            return True
        if JIT_STUB_BASE <= addr < JIT_STUB_BASE + 0x1000:
            return True
        if 0x1000 <= addr < CODE_BASE + CODE_SIZE:
            return True
        if addr == self.PLT_FALLBACK:
            return True
        return False

    def _jit_invalid_indcall_hook(self, uc, addr, size, ud):
        self._last_pc = addr
        target = uc.reg_read(UC_ARM64_REG_X8)
        if self._is_plausible_exec_target(target):
            return

        sym_name, resolved = self._resolve_session_symbol(uc, uc.reg_read(UC_ARM64_REG_X1))
        self._jit_invalid_indcall_skips += 1
        if resolved:
            print(
                f"[JIT-INDCALL-RESOLVE #{self._jit_invalid_indcall_skips}] "
                f"pc={addr:#x} x8={target:#x} sym={sym_name!r} -> {resolved:#x}"
            )
            uc.reg_write(UC_ARM64_REG_X0, resolved)
            uc.reg_write(UC_ARM64_REG_PC, addr + 4)
            return

        print(
            f"[JIT-INDCALL-SKIP #{self._jit_invalid_indcall_skips}] "
            f"pc={addr:#x} x8={target:#x} x0={uc.reg_read(UC_ARM64_REG_X0):#x}"
        )
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, addr + 4)

    def _x28_probe_hook(self, uc, addr, size, ud):
        self._last_pc = addr
        self._stall_jit_count += 1
        if hasattr(self, '_stall_post_skip_count'):
            self._stall_post_skip_count += 1
            n = self._stall_post_skip_count
            if n in (1, 10, 100, 1000, 2000, 5000, 10000, 20000, 50000, 100000):
                print(f"[POST-SKIP] insn #{n} pc={addr:#x} "
                      f"fp={uc.reg_read(UC_ARM64_REG_X29):#x}")

        # General stall detector: sample every N instructions
        if self._stall_jit_count % self._stall_check_interval == 0:
            fp = uc.reg_read(UC_ARM64_REG_X29)
            page = addr & ~0xFFF  # 4KB page

            # Track FP-based stall
            if fp == self._stall_last_fp and fp != 0:
                self._stall_same_count += 1
            else:
                self._stall_last_fp = fp
                self._stall_same_count = 0

            # Track page-based stall (catches loops with sub-calls)
            if page == self._stall_last_page and page != 0:
                self._stall_page_count += 1
            else:
                self._stall_last_page = page
                self._stall_page_count = 0

            # Trigger on either FP or page stall
            trigger = max(self._stall_same_count, self._stall_page_count)
            if trigger >= self._stall_threshold:
                self._force_return_from_stall(uc, addr, fp)
                return

        self._record_x28_trace(uc, addr)

    # ---- Block hook (fast alternative to per-instruction hook) ----
    def _block_hook(self, uc, addr, size, ud):
        """Called once at the start of each basic block.
        Function entry points are always block boundaries, so this catches all hooked calls.
        Hooked function entries are patched with RET as safety net if PC redirect fails.
        """
        # Catch execution at low addresses (ELF headers, not real code)
        if addr < 0x1000:
            lr = uc.reg_read(UC_ARM64_REG_LR)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        if self._is_bad_jit_exec_addr(addr):
            lr = uc.reg_read(UC_ARM64_REG_LR)
            if not hasattr(self, '_jit_bad_exec_count'):
                self._jit_bad_exec_count = 0
            self._jit_bad_exec_count += 1
            if self._jit_bad_exec_count <= 8:
                print(
                    f"[JIT-DATA-EXEC #{self._jit_bad_exec_count}] "
                    f"pc={addr:#x} lr={lr:#x} -> return 0",
                    flush=True,
                )
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return

        redir = self._jit_stub_entry_redirects.get(addr)
        if redir is not None:
            uc.reg_write(UC_ARM64_REG_PC, redir)
            return

        if addr in self.hooked_functions:
            h = self.hooked_functions[addr]
            self.hook_count += 1
            lr = uc.reg_read(UC_ARM64_REG_LR)
            h(uc, uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1),
              uc.reg_read(UC_ARM64_REG_X2), uc.reg_read(UC_ARM64_REG_X8))
            uc.reg_write(UC_ARM64_REG_PC, lr)
            # Note: hooked entries are patched with RET as safety net

    def _install_blr_trampoline(self):
        """Patch BLR x8 at 0x20b548 to use a trampoline to JIT encoder.
        This replaces the per-instruction check at 0x20b548 used in _code_hook.
        """
        target = JIT_ENCODER_FN
        tramp_addr = 0x4FFF00
        # trampoline: LDR X16, [PC, #8]; BR X16; .quad target
        ldr_x16 = struct.pack("<I", 0x58000050)  # LDR X16, #8
        br_x16 = struct.pack("<I", 0xd61f0200)   # BR X16
        self.uc.mem_write(tramp_addr, ldr_x16 + br_x16 + struct.pack("<Q", target))
        # BL tramp_addr (preserves LR = 0x20b54c)
        bl_offset = tramp_addr - 0x20b548
        bl_insn = struct.pack("<I", 0x94000000 | ((bl_offset >> 2) & 0x3FFFFFF))
        self.uc.mem_write(0x20b548, bl_insn)
        self.log(f"Installed BLR x8 trampoline -> {target:#x}")

    # ---- Memory hook ----
    def _tbi_map_page(self, uc, addr):
        """Map an unmapped page. If the address has a tagged top byte (TBI),
        try to copy data from the untagged version of the address."""
        pg = addr & ~0xFFF
        if self._is_page_accessible(uc, pg):
            return True
        page_candidates = []
        for cand in self._candidate_ptrs(addr):
            cand_pg = cand & ~0xFFF
            if cand_pg not in page_candidates:
                page_candidates.append(cand_pg)

        for cand_pg in page_candidates:
            if cand_pg in self._live_region_page_data:
                return self._map_page_bytes(uc, pg, self._live_region_page_data[cand_pg])

        for cand_pg in page_candidates:
            if cand_pg == pg:
                continue
            if self._is_page_accessible(uc, cand_pg):
                try:
                    data = bytes(uc.mem_read(cand_pg, 0x1000))
                except Exception:
                    continue
                return self._map_page_bytes(uc, pg, data)

        return self._map_page_bytes(uc, pg, b"\x00" * 0x1000)

    def _mem_hook(self, uc, access, addr, size, val, ud):
        # If this is an instruction fetch from unmapped memory, redirect to LR
        if access == UC_MEM_FETCH_UNMAPPED:
            lr = uc.reg_read(UC_ARM64_REG_LR)
            in_jit = JIT_BASE <= lr < JIT_BASE + JIT_SIZE
            in_nmsscr = 0x5ee10 <= lr < 0x29c800
            if not hasattr(self, '_wild_fetch_count'):
                self._wild_fetch_count = 0
            self._wild_fetch_count += 1
            if self._wild_fetch_count <= 10:
                print(f"[WILD-EXEC #{self._wild_fetch_count}] pc={addr:#x} lr={lr:#x}", flush=True)
            if in_jit or in_nmsscr:
                uc.reg_write(UC_ARM64_REG_X0, 0)
                uc.reg_write(UC_ARM64_REG_PC, lr)
            else:
                if self._wild_fetch_count > 50:
                    uc.emu_stop()
            self._tbi_map_page(uc, addr)
            return True
        # Data access (read/write) to unmapped page
        pg = addr & ~0xFFF
        # Some live pointers arrive in encoded/tagged forms whose canonical page
        # is already mapped (for example 0x880002048 -> 0x80002048 or live-JIT
        # addresses rebased into the zero-backed JIT tail). Map those aliases
        # silently so the unmapped log reflects real coverage gaps only.
        for cand in self._candidate_ptrs(addr):
            cand_pg = cand & ~0xFFF
            if cand_pg == pg:
                continue
            if cand_pg in self._live_region_page_data or self._is_page_accessible(uc, cand_pg):
                return self._tbi_map_page(uc, addr)

        if not hasattr(self, '_unmapped_data_count'):
            self._unmapped_data_count = 0
        self._unmapped_data_count += 1
        if self._unmapped_data_count <= 20:
            pc = uc.reg_read(UC_ARM64_REG_PC)
            print(f"[UNMAPPED-DATA #{self._unmapped_data_count}] pc={pc:#x} addr={addr:#x} "
                  f"size={size} access={'WRITE' if access == 22 else 'READ'}", flush=True)
        ok = self._tbi_map_page(uc, addr)
        if not ok and self._unmapped_data_count <= 20:
            print(f"  -> MAP FAILED for {addr:#x}, returning False", flush=True)
        return ok

    # ---- Fast SVC-based dispatch (no per-instruction hook) ----
    def _install_svc_patches(self):
        """Replace first instruction of each hooked function with SVC #N.
        Also patches BLR x8 at 0x20b548 to branch directly to JIT encoder.
        Maps a RET-stub page for unknown external calls.
        """
        # Fill JIT stub area with MOV X0,#0; RET pairs FIRST (before SVC patches override)
        mov_x0_zero = struct.pack("<I", 0xAA1F03E0)  # MOV X0, XZR
        ret_insn = struct.pack("<I", 0xd65f03c0)
        if self.jit_data:
            stub_pair = mov_x0_zero + ret_insn
            ret_block = stub_pair * 512
            try:
                self.uc.mem_write(JIT_STUB_BASE, ret_block)
            except:
                pass

        # Assign SVC indices to hooked functions
        svc_idx = 1  # start at 1 (0 = real SVC from binary)
        for addr, handler in self.hooked_functions.items():
            if svc_idx >= 0xFFFF:
                break
            # Save original bytes
            try:
                orig = bytes(self.uc.mem_read(addr, 4))
            except:
                orig = b'\x00\x00\x00\x00'
            self._svc_originals[svc_idx] = (addr, orig)
            self._svc_handlers[svc_idx] = handler
            # Write SVC #N: encoding = 0xd4000001 | (imm16 << 5)
            svc_insn = struct.pack("<I", 0xd4000001 | (svc_idx << 5))
            try:
                self.uc.mem_write(addr, svc_insn)
            except:
                pass
            svc_idx += 1

        # Patch BLR x8 at 0x20b548 to jump to JIT encoder via trampoline.
        # BLR x8 becomes BL trampoline; trampoline does LDR x8, [PC+8]; BR x8
        # with the 64-bit target address stored after the branch sequence.
        if self.jit_data:
            target = JIT_ENCODER_FN
            # Place trampoline at a scratch address reachable from 0x20b548
            # SCRATCH_BASE (0x64000000) is too far. Use space at end of nmsscr code
            # (after BSS, before 0x500000 limit). Use 0x4FFF00.
            tramp_addr = 0x4FFF00
            # trampoline: LDR X16, [PC, #8]; BR X16; .quad target
            ldr_x16 = struct.pack("<I", 0x58000050)  # LDR X16, #8 (PC-relative)
            br_x16 = struct.pack("<I", 0xd61f0200)   # BR X16
            self.uc.mem_write(tramp_addr, ldr_x16 + br_x16 + struct.pack("<Q", target))
            # Now patch 0x20b548: BL tramp_addr (preserves LR = 0x20b54c for encoder's RET)
            bl_offset = tramp_addr - 0x20b548
            bl_insn = struct.pack("<I", 0x94000000 | ((bl_offset >> 2) & 0x3FFFFFF))
            self.uc.mem_write(0x20b548, bl_insn)
            self.log(f"Patched BLR x8 at 0x20b548 -> trampoline -> {target:#x}")

        self.log(f"Installed {svc_idx - 1} SVC patches (fast mode)")

        # Patch JIT PLT GOT entries to redirect external calls to emulator hooks.
        # The JIT module's PLT stubs at 0x54860+ load function pointers from
        # GOT entries at 0x446a50+ and branch to them. These GOT entries contain
        # device runtime addresses (libc, etc.) which are unmapped in the emulator.
        # Redirect them to a stub page that dispatches via SVC.
        if self.jit_data:
            self._patch_jit_plt_got(svc_idx)

    def _patch_jit_plt_got(self, svc_start_idx):
        """Patch JIT PLT GOT entries to redirect to SVC dispatch stubs."""
        # Allocate a stub page for JIT PLT redirects
        JIT_PLT_STUB_PAGE = 0x64100000  # In scratch area
        try:
            self.uc.mem_map(JIT_PLT_STUB_PAGE, 0x2000, UC_PROT_ALL)
        except:
            pass  # Already mapped

        # Map of JIT PLT function -> nmsscr hooked equivalent
        # JIT PLT GOT offset -> emulator handler
        plt_got_to_hook = {
            0x446a50: self._hook_malloc,      # malloc
            0x446b30: self._hook_free,         # free
            0x446e40: self._hook_memcpy,      # memcpy
            0x446ed0: self._hook_strlen,      # strlen
        }

        # Enumerate ALL JIT PLT entries and create SVC stubs for each
        jit_data = self.jit_data
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        plt_addr = 0x54860
        svc_idx = svc_start_idx
        plt_count = 0
        while plt_addr < 0x56000 and svc_idx < 0xFFFF:
            code = jit_data[plt_addr:plt_addr + 16]
            if len(code) < 16:
                break
            instrs = list(md.disasm(code, plt_addr))
            if len(instrs) < 4 or instrs[0].mnemonic != 'adrp' or instrs[3].mnemonic != 'br':
                break

            # Extract GOT offset
            adrp_val = int.from_bytes(code[0:4], 'little')
            ldr_val = int.from_bytes(code[4:8], 'little')
            immhi = (adrp_val >> 5) & 0x7FFFF
            immlo = (adrp_val >> 29) & 0x3
            page_off = ((immhi << 2) | immlo) << 12
            if page_off & (1 << 32):
                page_off -= (1 << 33)
            page_base = (plt_addr & ~0xFFF) + page_off
            imm12 = (ldr_val >> 10) & 0xFFF
            load_off = imm12 << 3
            got_off = page_base + load_off

            # Create SVC stub for this PLT entry
            stub_offset = plt_count * 8  # 2 instructions per stub
            stub_addr = JIT_PLT_STUB_PAGE + stub_offset

            # Determine handler
            handler = plt_got_to_hook.get(got_off)
            if handler is None:
                # Default: return 0 (like noop, but also handles malloc-like calls)
                handler = self._hook_jit_plt_default

            # Write SVC stub: SVC #N; RET
            svc_insn = struct.pack("<I", 0xd4000001 | (svc_idx << 5))
            ret_insn = struct.pack("<I", 0xd65f03c0)
            self.uc.mem_write(stub_addr, svc_insn + ret_insn)

            # Register handler
            self._svc_handlers[svc_idx] = handler
            self._svc_originals[svc_idx] = (stub_addr, b'\x00\x00\x00\x00')

            # Patch GOT entry to point to our stub
            got_emu_addr = JIT_BASE + got_off
            self.uc.mem_write(got_emu_addr, struct.pack("<Q", stub_addr))

            plt_count += 1
            svc_idx += 1
            plt_addr += 16

        print(f"[JIT-PLT] Patched {plt_count} PLT GOT entries (SVC {svc_start_idx}-{svc_idx-1})", flush=True)

    def _hook_jit_plt_default(self, uc, x0, x1, x2, x8):
        """Default handler for unidentified JIT PLT calls — return 0."""
        pc = uc.reg_read(UC_ARM64_REG_PC)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        print(f"[JIT-PLT-DEFAULT] pc={pc:#x} lr={lr:#x} x0={x0:#x} x1={x1:#x} x2={x2:#x}", flush=True)
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_blr_x8_redirect(self, uc, x0, x1, x2, x8):
        """Fallback for BLR x8 redirect when B is out of range."""
        uc.reg_write(UC_ARM64_REG_PC, JIT_ENCODER_FN)

    def _fast_intr_hook(self, uc, intno, ud):
        """Fast interrupt handler for SVC-patched functions."""
        if intno == 2:  # SVC
            pc = uc.reg_read(UC_ARM64_REG_PC)
            # PC is already past the SVC instruction
            try:
                insn = struct.unpack('<I', bytes(uc.mem_read(pc - 4, 4)))[0]
            except:
                return
            imm = (insn >> 5) & 0xFFFF

            if imm == 0:
                # Real SVC #0 from the binary (syscall)
                syscall_num = uc.reg_read(UC_ARM64_REG_X8)
                self._emulate_raw_syscall(uc, syscall_num)
                return

            handler = self._svc_handlers.get(imm)
            if handler:
                self.hook_count += 1
                lr = uc.reg_read(UC_ARM64_REG_LR)
                self._invoke_hook_preserving_callee_saved(uc, handler)
                uc.reg_write(UC_ARM64_REG_PC, lr)
            else:
                # Unknown SVC — treat as noop, return to caller
                lr = uc.reg_read(UC_ARM64_REG_LR)
                uc.reg_write(UC_ARM64_REG_X0, 0)
                uc.reg_write(UC_ARM64_REG_PC, lr)
        else:
            # Other interrupts (e.g., from HLT)
            uc.reg_write(UC_ARM64_REG_X0, 0)

    # ---- Memory management hooks ----
    def _hook_malloc(self, uc, x0, *a):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        sz = self._sanitize_alloc_size(x0 if x0 > 0 else 16, "MALLOC")
        addr = self.heap.malloc(sz)
        uc.mem_write(addr, b'\x00' * min(sz, 0x10000))
        uc.reg_write(UC_ARM64_REG_X0, addr)
        print(f"[MALLOC] sz={sz:#x} -> {addr:#x} lr={lr:#x}", flush=True)

    def _hook_free(self, uc, x0, *a):
        if x0:
            self.heap.free(x0)
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_memcpy(self, uc, x0, x1, x2, *a):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        if 0 < x2 < 0x1000000:
            src = self._resolve_mem_addr(uc, x1)
            dst = self._resolve_mem_addr(uc, x0)
            try:
                data = bytes(uc.mem_read(src, x2))
            except Exception:
                print(f"[MEMCPY] UNMAPPED src={src:#x} (raw x1={x1:#x}) sz={x2} "
                      f"lr={lr:#x} — zero-filling dst={dst:#x}", flush=True)
                data = b'\x00' * x2
            uc.mem_write(dst, data)
            self._record_recent_data_event(
                "memcpy",
                src=src,
                dst=dst,
                size=x2,
                lr=lr,
                pc=uc.reg_read(UC_ARM64_REG_PC),
                head=data,
            )
            watch = getattr(self, '_src48_watch_range', None)
            if watch is not None:
                lo, hi = watch
                src_end = src + len(data)
                if src < hi and src_end > lo:
                    overlap_lo = max(src, lo)
                    overlap_hi = min(src_end, hi)
                    seg = data[overlap_lo - src:overlap_hi - src]
                    recent = getattr(self, '_src48_recent_writes', [])[-8:]
                    recent_txt = "; ".join(
                        f"pc=JIT+{jit_off:#x} off=+0x{off:x} sz={sz} val={val:#x} sp={sp:#x}"
                        for jit_off, off, sz, val, sp in recent
                    )
                    print(
                        f"[SRC48-SRC-MEMCPY] src={src:#x} dst={dst:#x} sz={x2} lr={lr:#x} "
                        f"overlap=+0x{overlap_lo - lo:x}..+0x{overlap_hi - lo:x} "
                        f"seg={seg.hex()} cur={self._dump_mem_hex(uc, lo, 0x30)} "
                        f"recent=[{recent_txt}]",
                        flush=True,
                    )
                dst_end = dst + len(data)
                if dst < hi and dst_end > lo:
                    overlap_lo = max(dst, lo)
                    overlap_hi = min(dst_end, hi)
                    seg = data[overlap_lo - dst:overlap_hi - dst]
                    cnt = getattr(self, '_src48_memcpy_count', 0) + 1
                    self._src48_memcpy_count = cnt
                    print(
                        f"[SRC48-MEMCPY #{cnt}] dst={dst:#x} src={src:#x} sz={x2} "
                        f"lr={lr:#x} overlap=+0x{overlap_lo - lo:x}..+0x{overlap_hi - lo:x} "
                        f"seg={seg.hex()} cur={self._dump_mem_hex(uc, lo, 0x30)}",
                        flush=True,
                    )
            sha_watch = getattr(self, '_sha_input_watch_range', None)
            if sha_watch is not None:
                lo, hi = sha_watch
                src_end = src + len(data)
                if src < hi and src_end > lo:
                    overlap_lo = max(src, lo)
                    overlap_hi = min(src_end, hi)
                    seg = data[overlap_lo - src:overlap_hi - src]
                    print(
                        f"[SHA32-SRC-MEMCPY] src={src:#x} dst={dst:#x} sz={x2} lr={lr:#x} "
                        f"overlap=+0x{overlap_lo - lo:x}..+0x{overlap_hi - lo:x} "
                        f"seg={seg.hex()} cur={self._dump_mem_hex(uc, lo, 0x20)}",
                        flush=True,
                    )
                dst_end = dst + len(data)
                if dst < hi and dst_end > lo:
                    overlap_lo = max(dst, lo)
                    overlap_hi = min(dst_end, hi)
                    seg = data[overlap_lo - dst:overlap_hi - dst]
                    cnt = getattr(self, '_sha_input_memcpy_count', 0) + 1
                    self._sha_input_memcpy_count = cnt
                    print(
                        f"[SHA32-MEMCPY #{cnt}] dst={dst:#x} src={src:#x} sz={x2} lr={lr:#x} "
                        f"overlap=+0x{overlap_lo - lo:x}..+0x{overlap_hi - lo:x} "
                        f"seg={seg.hex()} cur={self._dump_mem_hex(uc, lo, 0x20)}",
                        flush=True,
                    )
            raw_watch = getattr(self, '_raw24_watch_range', None)
            if raw_watch is not None:
                lo, hi = raw_watch
                src_end = src + len(data)
                if src < hi and src_end > lo:
                    overlap_lo = max(src, lo)
                    overlap_hi = min(src_end, hi)
                    seg = data[overlap_lo - src:overlap_hi - src]
                    print(
                        f"[RAW24-SRC-MEMCPY] src={src:#x} dst={dst:#x} sz={x2} lr={lr:#x} "
                        f"overlap=+0x{overlap_lo - lo:x}..+0x{overlap_hi - lo:x} "
                        f"seg={seg.hex()} cur={self._dump_mem_hex(uc, lo, 0x20)}",
                        flush=True,
                    )
                dst_end = dst + len(data)
                if dst < hi and dst_end > lo:
                    overlap_lo = max(dst, lo)
                    overlap_hi = min(dst_end, hi)
                    seg = data[overlap_lo - dst:overlap_hi - dst]
                    cnt = getattr(self, '_raw24_memcpy_count', 0) + 1
                    self._raw24_memcpy_count = cnt
                    print(
                        f"[RAW24-MEMCPY #{cnt}] dst={dst:#x} src={src:#x} sz={x2} lr={lr:#x} "
                        f"overlap=+0x{overlap_lo - lo:x}..+0x{overlap_hi - lo:x} "
                        f"seg={seg.hex()} cur={self._dump_mem_hex(uc, lo, 0x20)}",
                        flush=True,
                    )
            if (
                x2 == 48
                and HEAP_BASE <= dst < HEAP_BASE + HEAP_SIZE
                and all(b in b"0123456789abcdefABCDEF" for b in data[:48])
            ):
                self._last_hex48_memcpy = bytes(data[:48])
                self._last_hex48_memcpy_dst = dst
                hex48_by_dst = getattr(self, "_hex48_memcpy_by_dst", None)
                if hex48_by_dst is None:
                    hex48_by_dst = {}
                    self._hex48_memcpy_by_dst = hex48_by_dst
                hex48_by_dst[dst] = bytes(data[:48])
                if len(hex48_by_dst) > 16:
                    oldest = next(iter(hex48_by_dst))
                    if oldest != dst:
                        hex48_by_dst.pop(oldest, None)
                print(
                    f"[MEMCPY-HEX48] dst={dst:#x} src={src:#x} lr={lr:#x} "
                    f"data={data[:48].decode('ascii', errors='replace')}",
                    flush=True,
                )
            if x2 <= 256:
                print(f"[MEMCPY] dst={x0:#x} src={x1:#x} sz={x2} lr={lr:#x} data={data[:64].hex()}", flush=True)
            else:
                print(f"[MEMCPY] dst={x0:#x} src={x1:#x} sz={x2} lr={lr:#x}", flush=True)
        else:
            print(f"[MEMCPY] dst={x0:#x} src={x1:#x} sz={x2} lr={lr:#x} SKIP(bad size)", flush=True)
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_memmove(self, uc, x0, x1, x2, *a):
        if 0 < x2 < 0x1000000:
            src = self._resolve_mem_addr(uc, x1)
            dst = self._resolve_mem_addr(uc, x0)
            data = bytes(uc.mem_read(src, x2))
            uc.mem_write(dst, data)
            self._record_recent_data_event(
                "memmove",
                src=src,
                dst=dst,
                size=x2,
                lr=uc.reg_read(UC_ARM64_REG_LR),
                pc=uc.reg_read(UC_ARM64_REG_PC),
                head=data,
            )
            sha_watch = getattr(self, '_sha_input_watch_range', None)
            if sha_watch is not None:
                lo, hi = sha_watch
                dst_end = dst + len(data)
                if dst < hi and dst_end > lo:
                    overlap_lo = max(dst, lo)
                    overlap_hi = min(dst_end, hi)
                    seg = data[overlap_lo - dst:overlap_hi - dst]
                    cnt = getattr(self, '_sha_input_memcpy_count', 0) + 1
                    self._sha_input_memcpy_count = cnt
                    print(
                        f"[SHA32-MEMMOVE #{cnt}] dst={dst:#x} src={src:#x} sz={x2} "
                        f"lr={uc.reg_read(UC_ARM64_REG_LR):#x} overlap=+0x{overlap_lo - lo:x}..+0x{overlap_hi - lo:x} "
                        f"seg={seg.hex()} cur={self._dump_mem_hex(uc, lo, 0x20)}",
                        flush=True,
                    )
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_strlen(self, uc, x0, *a):
        x0 = self._resolve_mem_addr(uc, x0)
        n = 0
        try:
            while n < 0x100000 and bytes(uc.mem_read(x0 + n, 1))[0]:
                n += 1
        except:
            pass
        uc.reg_write(UC_ARM64_REG_X0, n)

    def _hook_memset(self, uc, x0, x1, x2, *a):
        if 0 < x2 < 0x1000000:
            dst = self._resolve_mem_addr(uc, x0)
            uc.mem_write(dst, bytes([x1 & 0xFF]) * x2)
        uc.reg_write(UC_ARM64_REG_X0, x0)

    # ---- String operation hooks ----
    def _hook_string_assign(self, uc, x0, x1, x2, *a):
        if 0 < x2 < 0x1000000:
            self._write_sso(uc, x0, bytes(uc.mem_read(x1, x2)))
        else:
            if x1:
                n = 0
                try:
                    while n < 0x10000 and bytes(uc.mem_read(x1 + n, 1))[0]:
                        n += 1
                except:
                    pass
                self._write_sso(uc, x0, bytes(uc.mem_read(x1, n)) if n > 0 else b"")
            else:
                self._write_sso(uc, x0, b"")
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_string_append(self, uc, x0, x1, x2, *a):
        if 0 < x2 < 0x1000000:
            cur = self._read_sso(uc, x0)
            self._write_sso(uc, x0, cur + bytes(uc.mem_read(x1, x2)))
        elif x1:
            n = 0
            try:
                while n < 0x10000 and bytes(uc.mem_read(x1 + n, 1))[0]:
                    n += 1
            except:
                pass
            if n > 0:
                cur = self._read_sso(uc, x0)
                self._write_sso(uc, x0, cur + bytes(uc.mem_read(x1, n)))
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_string_resize(self, uc, x0, *a):
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_string_copy_assign(self, uc, x0, x1, x2, *a):
        # 0x601d0 is used as basic_string::operator= on wrapper/token return
        # paths. Treat x1 as a source string object and copy its contents
        # instead of splatting raw pointer-sized fields into the destination.
        src_data = b""
        if x1:
            try:
                src_data = self._read_sso(uc, x1)
            except Exception:
                src_data = b""
        if not src_data and x1 and 0 < x2 < 0x1000000:
            try:
                src_data = bytes(uc.mem_read(x1, x2))
            except Exception:
                src_data = b""
        self._write_sso(uc, x0, src_data)
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_string_find(self, uc, x0, *a):
        uc.reg_write(UC_ARM64_REG_X0, 0xFFFFFFFFFFFFFFFF)  # npos

    def _hook_string_substr(self, uc, x0, *a):
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_string_concat(self, uc, x0, *a):
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_string_create(self, uc, x0, *a):
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_string_erase(self, uc, x0, *a):
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_string_destroy(self, uc, x0, *a):
        try:
            h = bytes(uc.mem_read(x0, 24))
            if h[0] & 1:
                ptr = struct.unpack("<Q", h[16:24])[0]
                if ptr:
                    self.heap.free(ptr)
            uc.mem_write(x0, b'\x00' * 24)
        except:
            pass
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _clone_sso_object(self, uc, dst, src):
        src = self._resolve_mem_addr(uc, src)
        raw = bytes(uc.mem_read(src, 24))
        if (raw[0] & 1) == 0:
            uc.mem_write(dst, raw)
            return
        size = struct.unpack("<Q", raw[8:16])[0]
        data_ptr = struct.unpack("<Q", raw[16:24])[0]
        data_ptr = self._resolve_mem_addr(uc, data_ptr)
        data = b""
        if size and data_ptr:
            data = bytes(uc.mem_read(data_ptr, size))
        self._write_sso(uc, dst, data, force_long=True)

    def _hook_vector_string_copy_ctor(self, uc, x0, x1, *a):
        try:
            src_vec = self._resolve_mem_addr(uc, x1)
            begin = struct.unpack("<Q", uc.mem_read(src_vec + 0x00, 8))[0]
            end = struct.unpack("<Q", uc.mem_read(src_vec + 0x08, 8))[0]
            count_bytes = end - begin if end >= begin else 0
            count = count_bytes // 24 if count_bytes else 0

            if count <= 0:
                uc.mem_write(x0, b"\x00" * 24)
                uc.reg_write(UC_ARM64_REG_X0, x0)
                return

            dst_buf = self.heap.malloc(count * 24)
            uc.mem_write(dst_buf, b"\x00" * (count * 24))
            for i in range(count):
                self._clone_sso_object(uc, dst_buf + i * 24, begin + i * 24)

            vec = struct.pack("<QQQ", dst_buf, dst_buf + count * 24, dst_buf + count * 24)
            uc.mem_write(x0, vec)
        except Exception:
            try:
                uc.mem_write(x0, b"\x00" * 24)
            except Exception:
                pass
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_vector_string_destroy(self, uc, x0, *a):
        try:
            vec = self._resolve_mem_addr(uc, x0)
            begin = struct.unpack("<Q", uc.mem_read(vec + 0x00, 8))[0]
            end = struct.unpack("<Q", uc.mem_read(vec + 0x08, 8))[0]
            count_bytes = end - begin if end >= begin else 0
            count = count_bytes // 24 if count_bytes else 0
            for i in range(count):
                elem = self._resolve_mem_addr(uc, begin + i * 24)
                raw = bytes(uc.mem_read(elem, 24))
                if raw[0] & 1:
                    ptr = struct.unpack("<Q", raw[16:24])[0]
                    if ptr:
                        self.heap.free(ptr)
            if begin:
                self.heap.free(begin)
            uc.mem_write(vec, b"\x00" * 24)
        except Exception:
            pass
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_gmtime(self, uc, x0, *a):
        try:
            sec = self._fake_time_sec
            if x0 > 0x1000:
                try:
                    sec = struct.unpack("<q", uc.mem_read(x0, 8))[0]
                except Exception:
                    sec = self._fake_time_sec
            if sec <= 0:
                sec = self._fake_time_sec
            tm = time.gmtime(sec)
            zone_ptr = SCRATCH_BASE + 0x1FF00
            tm_ptr = SCRATCH_BASE + 0x1FF40
            uc.mem_write(zone_ptr, b"UTC\x00")
            buf = bytearray(64)
            struct.pack_into(
                "<9i",
                buf,
                0,
                tm.tm_sec,
                tm.tm_min,
                tm.tm_hour,
                tm.tm_mday,
                tm.tm_mon - 1,
                tm.tm_year - 1900,
                tm.tm_wday,
                tm.tm_yday - 1,
                tm.tm_isdst,
            )
            struct.pack_into("<q", buf, 40, 0)
            struct.pack_into("<Q", buf, 48, zone_ptr)
            uc.mem_write(tm_ptr, bytes(buf))
            uc.reg_write(UC_ARM64_REG_X0, tm_ptr)
        except Exception:
            uc.reg_write(UC_ARM64_REG_X0, 0)

    # ---- Other hooks ----
    def _hook_noop(self, uc, *a):
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_passthrough(self, uc, *a):
        return

    def _hook_aasset_open(self, uc, x0, x1, x2, *a):
        name = self._read_c_string(uc, x1)
        if not hasattr(self, '_jit_assets'):
            self._jit_assets = {}
        if not hasattr(self, '_jit_asset_log_count'):
            self._jit_asset_log_count = 0

        asset_data = b""
        asset_name = name.decode('utf-8', errors='ignore') if name else ""
        synthetic_assets = {
            # The cert CFF path resolves these descriptor names through the
            # AAssetManager-backed helper at 0xceba0 and expects a non-null
            # string payload back. In the emulator there is no APK asset pack,
            # so synthesize the minimal live-like payload when no host file is
            # present.
            "gamehack": b"gamehack",
            "gamespeeder": b"gamespeeder",
            "libaegis_l.so": b"libaegis_l.so",
        }
        if asset_name:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            candidates = [
                asset_name,
                os.path.join(base_dir, asset_name),
                os.path.join(base_dir, "assets", asset_name),
                os.path.join(base_dir, "output", "decrypted", asset_name),
            ]
            seen = set()
            for path in candidates:
                if path in seen:
                    continue
                seen.add(path)
                if os.path.isfile(path):
                    try:
                        with open(path, "rb") as f:
                            asset_data = f.read()
                        break
                    except Exception:
                        pass
            if not asset_data and name:
                host_path, virtual_data, _ = self._resolve_jit_host_or_virtual_path(name)
                if virtual_data is not None:
                    asset_data = virtual_data
                elif host_path and os.path.isfile(host_path):
                    try:
                        with open(host_path, "rb") as f:
                            asset_data = f.read()
                    except Exception:
                        pass
            if not asset_data:
                asset_data = synthetic_assets.get(asset_name, b"")

        handle = 0
        if asset_data:
            handle = self.heap.malloc(0x20)
            uc.mem_write(handle, b"\x00" * 0x20)
            self._jit_assets[handle] = {
                "name": asset_name,
                "data": asset_data,
                "off": 0,
            }

        self._jit_asset_log_count += 1
        if self._jit_asset_log_count <= 8:
            print(
                f"[AASSET-OPEN #{self._jit_asset_log_count}] name={name!r} "
                f"mode={x2:#x} -> {handle:#x}",
                flush=True,
            )
        uc.reg_write(UC_ARM64_REG_X0, handle)

    def _hook_aasset_get_length(self, uc, x0, *a):
        asset = getattr(self, '_jit_assets', {}).get(x0)
        uc.reg_write(UC_ARM64_REG_X0, 0 if asset is None else len(asset["data"]))

    def _hook_aasset_read(self, uc, x0, x1, x2, *a):
        asset = getattr(self, '_jit_assets', {}).get(x0)
        if asset is None or not x1 or x2 <= 0:
            uc.reg_write(UC_ARM64_REG_X0, 0)
            return
        off = asset["off"]
        data = asset["data"][off:off + x2]
        if data:
            try:
                uc.mem_write(x1, data)
            except Exception:
                uc.reg_write(UC_ARM64_REG_X0, 0)
                return
            asset["off"] = off + len(data)
        uc.reg_write(UC_ARM64_REG_X0, len(data))

    def _hook_aasset_close(self, uc, x0, *a):
        if hasattr(self, '_jit_assets'):
            self._jit_assets.pop(x0, None)
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _hook_output_obj_vcall(self, uc, x0, *a):
        """Finalize the encoder helper object.

        The binary builds an 0xe8-byte helper at 0x20a13c and later calls the
        vtable slot at [obj->vptr + 8] after formatting `obj+0xc8`. In the
        emulator this slot was a bare RET stub, so the formatted result never
        reached the caller-visible output object in x19.
        """
        out_addr = uc.reg_read(UC_ARM64_REG_X19)
        if x0:
            try:
                final_data = self._read_sso(uc, x0 + 0xC8)
            except Exception:
                final_data = b""
            if final_data and out_addr:
                self._write_sso(uc, out_addr, final_data)
        uc.reg_write(UC_ARM64_REG_X0, x0)

    def _hook_live_pthread_create(self, uc, x0, x1, x2, x8):
        """Best-effort stand-in for the live libc pthread_create callback.

        The live session descriptor points to bionic libc code that is only
        partially captured in the snapshot. The cert path uses it to register a
        background helper thread with entrypoint x2 and arg x3. The caller only
        consumes the integer return status, so emulate a successful create and
        publish a stable non-zero pthread_t value to *x0.
        """
        handle = self._fake_pthread_handles.get(x0)
        if handle is None:
            handle = self.heap.malloc(0x20)
            uc.mem_write(handle, b"\x00" * 0x20)
            self._fake_pthread_handles[x0] = handle
        if x0:
            try:
                uc.mem_write(x0, struct.pack("<Q", handle))
            except Exception:
                pass
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _resolve_live_callback_decode_target(self, uc, desc):
        slot58 = 0
        target = 0
        if self._live_session_regions_loaded and desc:
            try:
                slot58 = self._safe_mem_read_qword(uc, desc + 0x58)
            except Exception:
                slot58 = 0
            if slot58:
                target = slot58
            else:
                target = LIVE_PTHREAD_CREATE_STUB
        return target, slot58

    def _hook_decode_session_callback(self, uc, x0, x1, x2, x8):
        """Short-circuit the live callback decoder for snapshot-backed sessions.

        The native helper at 0x152850 obfuscates a callback pointer out of the
        live descriptor's scalar fields and tagged tables at +0x18/+0x20.
        That decode currently lands in partially captured bionic code
        (0x76ea989270 -> 0x76ea992450). For the live snapshot descriptor we
        already patch the intended callback slot at +0x58 to a local scratch
        hook, so return that slot directly instead of re-running the decoder.
        """
        target, slot58 = self._resolve_live_callback_decode_target(uc, x0)
        if not hasattr(self, '_decode_session_callback_logs'):
            self._decode_session_callback_logs = 0
        self._decode_session_callback_logs += 1
        if self._decode_session_callback_logs <= 8:
            print(
                f"[DECODE-CALLBACK #{self._decode_session_callback_logs}] "
                f"x0={x0:#x} x1={x1:#x} x2={x2:#x} x8={x8:#x} "
                f"slot58={slot58:#x} -> {target:#x}",
                flush=True,
            )
        uc.reg_write(UC_ARM64_REG_X0, target)

    def _live_callback_decode_hook(self, uc, addr, size, ud):
        self._last_pc = addr
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        target, slot58 = self._resolve_live_callback_decode_target(uc, x0)
        if not hasattr(self, '_live_callback_decode_logs'):
            self._live_callback_decode_logs = 0
        self._live_callback_decode_logs += 1
        if self._live_callback_decode_logs <= 8:
            print(
                f"[LIVE-CALLBACK-DECODE #{self._live_callback_decode_logs}] "
                f"pc={addr:#x} x0={x0:#x} slot58={slot58:#x} -> {target:#x} lr={lr:#x}",
                flush=True,
            )
        uc.reg_write(UC_ARM64_REG_X0, target)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _ensure_session_resolver_stub(self):
        if self._session_resolver_stub:
            return self._session_resolver_stub
        stub_addr = 0x64050080
        self.uc.mem_write(stub_addr, struct.pack("<I", 0xd65f03c0))
        self.hooked_functions[stub_addr] = self._hook_session_symbol_resolver
        self._session_resolver_stub = stub_addr
        return stub_addr

    def _seed_session_resolver_desc(self, uc, session_obj):
        desc = self._safe_mem_read_qword(uc, session_obj + 0x3A0)
        if not desc:
            return

        # When full live snapshot regions are loaded, session+0x3a0 already
        # points at a real descriptor object. Overwriting it with synthetic
        # resolver stubs corrupts the callback metadata that native code later
        # decodes via 0x152850. Preserve the live descriptor, but reroute the
        # uncaptured libc pthread_create callback slot to a local scratch hook.
        if self._live_session_regions_loaded:
            try:
                uc.mem_write(desc + 0x58, struct.pack("<Q", LIVE_PTHREAD_CREATE_STUB))
            except Exception:
                pass
            return

        resolver_stub = self._ensure_session_resolver_stub()

        def alloc_zero(sz):
            ptr = self.heap.malloc(sz)
            uc.mem_write(ptr, b'\x00' * sz)
            return ptr

        # Live x1+0x3a0 points to a small callback descriptor object, not an
        # empty heap blob. Seed the descriptor with the observed scalar fields
        # and route its function slots to a name-based resolver stub.
        vtbl_stub = alloc_zero(0x80)
        aux_a = alloc_zero(0x80)
        aux_b = alloc_zero(0x80)
        fields = {
            0x00: vtbl_stub,
            0x08: 0x1C000000E0,
            0x10: 0xFAEDD311FF3C5159,
            0x18: aux_a,
            0x20: aux_b,
            0x28: session_obj,
            0x30: resolver_stub,
            0x38: resolver_stub,
        }
        for off, value in fields.items():
            uc.mem_write(desc + off, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def _resolve_session_symbol(self, uc, sym_ptr):
        name = b""
        if sym_ptr:
            try:
                name = bytes(uc.mem_read(sym_ptr, 64)).split(b"\x00", 1)[0]
            except Exception:
                name = b""

        target = 0
        if name == b"fx":
            target = JIT_ENCODER_FN
        elif name:
            try:
                decoded = name.decode("ascii")
            except UnicodeDecodeError:
                decoded = ""
            if decoded:
                target = self._jit_symbol_stubs.get(decoded, 0)
                if target == 0 and decoded in {"dlopen", "dlsym", "dlclose", "dlerror"}:
                    target = self.PLT_FALLBACK
        return name, target

    def _hook_session_symbol_resolver(self, uc, x0, x1, x2, x8):
        _, target = self._resolve_session_symbol(uc, x1)
        uc.reg_write(UC_ARM64_REG_X0, target)

    def _hook_cxa_guard_acquire(self, uc, x0, *a):
        try:
            val = bytes(uc.mem_read(x0, 1))[0]
            if val == 1:
                uc.reg_write(UC_ARM64_REG_X0, 0)
                return
        except:
            pass
        uc.reg_write(UC_ARM64_REG_X0, 1)

    def _hook_cxa_throw(self, uc, x0, *a):
        self.log(f"__cxa_throw called at {self._last_pc:#x} - aborting")
        uc.emu_stop()

    def _hook_get_manager(self, uc, *a):
        # Return a session object based on encoder_snapshot x1 template
        if not hasattr(self, '_session_obj'):
            self._session_obj = self._build_session_object(uc)
        self._seed_encoder_builder_globals_from_template(uc)
        uc.reg_write(UC_ARM64_REG_X0, self._session_obj)

    def _read_c_string(self, uc, addr, limit=0x200, max_len=None):
        if not addr:
            return b""
        if max_len is not None:
            limit = max_len
        addr = self._resolve_mem_addr(uc, addr)
        out = bytearray()
        for i in range(limit):
            try:
                b = uc.mem_read(addr + i, 1)[0]
            except Exception:
                break
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def _load_session_desc_key_map(self, uc):
        if self._session_desc_key_map:
            return self._session_desc_key_map
        if not hasattr(self, '_session_obj'):
            return {}

        sess = self._session_obj
        map_addr = self._safe_mem_read_qword(uc, sess + 0x380) or 0
        desc = self._safe_mem_read_qword(uc, sess + 0x388) or 0
        begin = self._safe_mem_read_qword(uc, (desc & 0x0000FFFFFFFFFFFF) + 0x318) or 0
        end = self._safe_mem_read_qword(uc, (desc & 0x0000FFFFFFFFFFFF) + 0x320) or 0
        key_map = {}
        cur = begin & 0x0000FFFFFFFFFFFF
        end = end & 0x0000FFFFFFFFFFFF
        while cur and end and cur < end:
            # The descriptor table entries are libc++ string objects, not raw
            # char* pointers. Live snapshots store keys like "gamehack" inline
            # as 24-byte SSO records at cur/cur+0x18/..., so decode the string
            # object directly and only fall back to char* when needed.
            key = self._read_sso(uc, cur)
            if not key:
                key_ptr_tagged = self._safe_mem_read_qword(uc, cur) or 0
                key_ptr = key_ptr_tagged & 0x0000FFFFFFFFFFFF
                key = self._read_c_string(uc, key_ptr)
            if key:
                key_map[key] = cur
            cur += 0x18

        self._session_desc_map_addr = map_addr
        self._session_desc_key_map = key_map
        return key_map

    def _alloc_fake_tree_node(self, uc, container, key, value_ptr):
        cache_key = (container, key)
        for node, meta in self._jit_fake_tree_nodes.items():
            if meta["cache_key"] == cache_key:
                return node

        node = self.heap.malloc(0x20)
        uc.mem_write(node, b"\x00" * 0x20)
        uc.mem_write(node + 0x00, struct.pack("<Q", 0x4A54465245453100))
        uc.mem_write(node + 0x08, struct.pack("<Q", value_ptr))
        uc.mem_write(node + 0x10, struct.pack("<Q", container))
        self._jit_fake_tree_nodes[node] = {
            "cache_key": cache_key,
            "key": key,
            "value_ptr": value_ptr,
        }
        return node

    def _hook_jit_tree_find(self, uc, x0, x1, x2, *a):
        key = self._read_c_string(uc, x1)
        key_map = self._load_session_desc_key_map(uc)
        node = 0
        if key and key_map:
            map_addr = self._session_desc_map_addr
            if x0 in self._candidate_ptrs(map_addr):
                value_ptr = key_map.get(key, 0)
                if value_ptr:
                    node = self._alloc_fake_tree_node(uc, x0, key, value_ptr)
                if not hasattr(self, '_jit_tree_find_log_count'):
                    self._jit_tree_find_log_count = 0
                self._jit_tree_find_log_count += 1
                if self._jit_tree_find_log_count <= 5:
                    print(
                        f"[JIT-TREE-FIND #{self._jit_tree_find_log_count}] "
                        f"container={x0:#x} key={key!r} -> {node:#x}",
                        flush=True,
                    )
        uc.reg_write(UC_ARM64_REG_X0, node)

    def _hook_jit_tree_value(self, uc, x0, *a):
        meta = self._jit_fake_tree_nodes.get(x0)
        uc.reg_write(UC_ARM64_REG_X0, 0 if meta is None else meta["value_ptr"])

    def _fill_nmsscr_donor_gaps(self, usable_region_page_data):
        """Fill gaps in snapshot-captured nmsscr pages from nmsscr.dec.

        The bulk-XOR decrypt loop at JIT+0x56d1c needs contiguous donor pages
        from the nmsscr code region. The snapshot may have capture gaps; we fill
        them from the decrypted binary so the XOR transform produces correct data.
        """
        nmsscr_dec_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "output", "decrypted", "nmsscr.dec",
        )
        if not os.path.exists(nmsscr_dec_path):
            return

        # Detect nmsscr base from existing snapshot pages.
        # nmsscr code pages have dense non-zero ARM64 instructions.
        # We find pages in a known nmsscr offset range (0x80000-0x200000 = code section)
        # and infer the base.
        nmsscr_data = open(nmsscr_dec_path, "rb").read()
        nmsscr_size = len(nmsscr_data)

        # Try to find CRBASE by matching existing region pages against nmsscr.dec
        crbase = None
        for pg_addr, pg_data in usable_region_page_data.items():
            if len(pg_data) != 0x1000:
                continue
            # Try offsets in the code section (skip first 0x10000 and writable tail)
            for test_off in range(0x80000, min(0x200000, nmsscr_size - 0x1000), 0x1000):
                if nmsscr_data[test_off:test_off + 0x1000] == pg_data:
                    candidate = pg_addr - test_off
                    # Validate with a second page
                    for pg2_addr, pg2_data in usable_region_page_data.items():
                        if pg2_addr == pg_addr or len(pg2_data) != 0x1000:
                            continue
                        off2 = pg2_addr - candidate
                        if 0 <= off2 < nmsscr_size - 0x1000:
                            if nmsscr_data[off2:off2 + 0x1000] == pg2_data:
                                crbase = candidate
                                break
                    if crbase is not None:
                        break
            if crbase is not None:
                break

        if crbase is None:
            print("[DONOR-FILL] Could not detect nmsscr CRBASE from snapshot pages", flush=True)
            return

        print(f"[DONOR-FILL] Detected nmsscr CRBASE={crbase:#x}", flush=True)

        # Fill gaps: for every page in the nmsscr code range that's NOT in the
        # snapshot, inject data from nmsscr.dec.
        filled = 0
        for file_off in range(0, nmsscr_size, 0x1000):
            pg_addr = crbase + file_off
            if pg_addr in self._live_region_page_data:
                continue
            page_data = nmsscr_data[file_off:file_off + 0x1000]
            if len(page_data) < 0x1000:
                page_data = page_data + b'\x00' * (0x1000 - len(page_data))
            # Only fill code-section pages (skip writable data/bss at high offsets
            # that may differ at runtime)
            if file_off < 0x4B0000:
                self._live_region_page_data[pg_addr] = page_data
                filled += 1

        print(f"[DONOR-FILL] Injected {filled} nmsscr pages from nmsscr.dec (code range < 0x4B0000)", flush=True)

    def _build_session_object(self, uc):
        """Build a session object using live_jit_snapshot with full region data.
        Maps all captured device memory regions so pointer targets have real data."""
        import json
        self._session_desc_key_map = {}
        self._session_desc_map_addr = 0
        # Try rich live snapshot first, fall back to encoder_snapshot
        base_dir = os.path.dirname(os.path.abspath(__file__))
        live_snap_path = LIVE_JIT_SNAPSHOT_JSON_PATH
        enc_snap_path = os.path.join(base_dir, "encoder_snapshot.json")

        snap_path = live_snap_path if os.path.exists(live_snap_path) else enc_snap_path
        if not os.path.exists(snap_path):
            print("[SESSION] No snapshot found, using MANAGER_BASE")
            self._live_session_regions_loaded = False
            self._live_session_region_pages = 0
            return MANAGER_BASE

        with open(snap_path) as f:
            snap = json.load(f)
        x1_data = bytearray.fromhex(snap['mem']['x1']['hex'])
        obj_size = len(x1_data)
        regions = snap.get('regions', [])

        # Build page index from snapshot regions (untag addresses for emulator)
        region_page_data = {}  # untagged_page_addr -> hex_data
        for r in regions:
            addr = r['addr']
            hex_data = r.get('hex', '')
            if not hex_data:
                continue
            # Untag: clear top 16 bits so regions match untagged session pointers
            untagged_addr = addr & 0x0000FFFFFFFFFFFF
            pg = untagged_addr & ~0xFFF
            region_page_data[pg] = bytes.fromhex(hex_data)
        self._live_region_page_index = dict(region_page_data)

        # Map all snapshot regions into emulator memory
        # Skip pages already used by emulator (heap, stack, code, JIT) to avoid corruption
        mapped_region_pages = 0
        skipped_overlap = 0
        usable_region_page_data = {}
        for pg_addr, data in region_page_data.items():
            if pg_addr in self.mapped_pages:
                # Already mapped by emulator — don't overwrite (would corrupt heap/stack/etc.)
                skipped_overlap += 1
                continue
            try:
                uc.mem_map(pg_addr, 0x1000, UC_PROT_ALL)
            except Exception:
                pass  # already mapped from previous run
            try:
                uc.mem_write(pg_addr, data[:0x1000])
                self.mapped_pages.add(pg_addr)
                mapped_region_pages += 1
                usable_region_page_data[pg_addr] = data
            except Exception:
                pass
        if skipped_overlap:
            print(f"[SESSION] Skipped {skipped_overlap} region pages that overlap emulator memory")

        # Only keep pages we actually allowed into the emulator; skipped overlap pages
        # may alias heap/code/JIT ranges and must not be treated as valid snapshot targets.
        self._live_region_page_data = dict(usable_region_page_data)

        # Fill gaps in nmsscr-backed snapshot pages from nmsscr.dec.
        # The bulk-XOR decrypt at JIT+0x56d1c reads donor pages from the nmsscr
        # mapping. If the snapshot has gaps, fill them from the decrypted binary.
        self._fill_nmsscr_donor_gaps(usable_region_page_data)

        # Map any donor-filled pages that weren't in the original snapshot
        donor_mapped = 0
        for pg_addr, data in self._live_region_page_data.items():
            if pg_addr not in usable_region_page_data and pg_addr not in self.mapped_pages:
                try:
                    uc.mem_map(pg_addr, 0x1000)
                except Exception:
                    pass  # may already be mapped in a larger region
                try:
                    uc.mem_write(pg_addr, data[:0x1000])
                    self.mapped_pages.add(pg_addr)
                    donor_mapped += 1
                except Exception:
                    pass
        if donor_mapped:
            mapped_region_pages += donor_mapped
            print(f"[DONOR-FILL] Mapped {donor_mapped} donor pages into emulator",
                  flush=True)

        self._live_session_region_pages = mapped_region_pages
        self._live_session_regions_loaded = mapped_region_pages > 0

        # Allocate session object on heap
        obj = self.heap.malloc(obj_size + 0x100)
        uc.mem_write(obj, b'\x00' * (obj_size + 0x100))

        # Copy session data, untagging pointers so they point to mapped regions
        clean_data = bytearray(obj_size)
        ptr_fields = []
        ptr_mapped = 0
        ptr_stubbed = 0
        for off in range(0, obj_size, 8):
            val = int.from_bytes(x1_data[off:off+8], 'little')
            if val == 0:
                continue
            top16 = (val >> 48) & 0xFFFF
            top8 = (val >> 56) & 0xFF
            # Device pointers are in the 0x70_0000_0000–0x77_FFFF_FFFF range
            # (untagged 39–43 bit addresses) as well as tagged pointers with
            # top byte 0x73/0x76 or top16 0xb400.  The low-range check catches
            # addresses like 0x7473d0ea90 whose top8 is 0x00.
            untagged_low = val & 0x0000FFFFFFFFFFFF
            is_ptr = (top16 in (0xb400,) or
                      top8 in (0x73, 0x74, 0x75, 0x76) or
                      0x70_0000_0000 <= untagged_low < 0x78_0000_0000)
            if is_ptr:
                ptr_fields.append(off)
                # Untag the pointer (clear top 16 bits)
                untagged = val & 0x0000FFFFFFFFFFFF
                pg = untagged & ~0xFFF
                if pg in usable_region_page_data:
                    # Most session-object pointers are easier to execute when we
                    # store the untagged form directly. One important exception is
                    # obj+0x388: later nmsscr code compares that descriptor's
                    # header-derived sentinel against still-tagged in-page links,
                    # so preserve the original tag there to keep pointer
                    # comparisons consistent.
                    stored = val if off == 0x388 else untagged
                    struct.pack_into("<Q", clean_data, off, stored)
                    ptr_mapped += 1
                else:
                    # No region data — allocate zeroed stub as before
                    stub = self.heap.malloc(0x400)
                    uc.mem_write(stub, b'\x00' * 0x400)
                    struct.pack_into("<Q", clean_data, off, stub)
                    ptr_stubbed += 1
            else:
                clean_data[off:off+8] = x1_data[off:off+8]

        uc.mem_write(obj, bytes(clean_data))

        def read_snapshot_span(addr, size):
            out = bytearray()
            cur = addr & 0x0000FFFFFFFFFFFF
            remain = int(size)
            while remain > 0:
                pg = cur & ~0xFFF
                page = region_page_data.get(pg)
                if page is None:
                    break
                page_off = cur - pg
                take = min(remain, 0x1000 - page_off)
                chunk = page[page_off:page_off + take]
                if not chunk:
                    break
                out.extend(chunk)
                cur += len(chunk)
                remain -= len(chunk)
            return bytes(out)

        if self._live_session_regions_loaded:
            # The post-CFF helper at 0x177ebc exits early when these live
            # session strings are blank. Re-seed them verbatim from the snapshot
            # after pointer cleanup so skipped-overlap pages cannot collapse the
            # long-SSO payload into a zeroed stub.
            sso_88 = bytearray(x1_data[0x88:0x88 + 0x18])
            if len(sso_88) == 0x18:
                live_size = struct.unpack_from("<Q", sso_88, 8)[0]
                live_ptr = struct.unpack_from("<Q", sso_88, 16)[0] & 0x0000FFFFFFFFFFFF
                if live_size and live_ptr:
                    pg = live_ptr & ~0xFFF
                    target_ptr = live_ptr if pg in usable_region_page_data else 0
                    payload = read_snapshot_span(live_ptr, live_size)
                    if payload and target_ptr == 0:
                        target_ptr = self.heap.malloc(len(payload) + 1)
                        uc.mem_write(target_ptr, payload + b"\x00")
                    if target_ptr:
                        struct.pack_into("<Q", sso_88, 16, target_ptr)
                uc.mem_write(obj + 0x88, bytes(sso_88))

            sso_1f8 = x1_data[0x1F8:0x1F8 + 0x18]
            if len(sso_1f8) == 0x18:
                uc.mem_write(obj + 0x1F8, bytes(sso_1f8))

            # The live session snapshot carries the modern Android native-lib
            # path (/data/app/.../lib/arm64), but the downstream formatter at
            # 0x177ebc canonicalizes and compares against the legacy
            # /data/app-lib/<package> form. Normalize the synthetic session slot
            # so the compare block takes the real success path instead of
            # appending the diagnostic "(code : 2134873744)" entry.
            try:
                pkg = self._read_sso(uc, obj + 0x1F8)
                lib_path = self._read_sso(uc, obj + 0x88)
            except Exception:
                pkg = b""
                lib_path = b""
            if pkg and lib_path.startswith(b"/data/app/") and b"/lib/arm64" in lib_path:
                self._write_sso(uc, obj + 0x88, b"/data/app-lib/" + pkg, force_long=True)

        # Fix session key SSO at +0x210 (Android libc++ long SSO)
        # When live session regions are loaded, the snapshot already has the correct
        # session key via the SSO pointer chain. Don't overwrite with hardcoded key.
        if not self._live_session_regions_loaded:
            sk_hex = SESSION_KEY.hex().encode('ascii')
            sk_heap = self.heap.malloc(len(sk_hex) + 1)
            uc.mem_write(sk_heap, sk_hex + b'\x00')
            sso_210 = bytearray(24)
            cap = len(sk_hex) + 1
            struct.pack_into("<Q", sso_210, 0, (cap * 2) | 1)
            struct.pack_into("<Q", sso_210, 8, len(sk_hex))
            struct.pack_into("<Q", sso_210, 16, sk_heap)
            uc.mem_write(obj + 0x210, bytes(sso_210))

        # The live snapshot-backed session object stores real runtime pointers in
        # the 0x380..0x3a0 cluster. Do not clobber them with the manager-style raw
        # session key overlay; that turns valid pointers like obj+0x388 into the
        # repeated-key garbage seen in the cert CFF path.
        if not self._live_session_regions_loaded:
            raw_key = SESSION_KEY[4:] + SESSION_KEY
            uc.mem_write(obj + 0x380, raw_key[:24])

        # Fix score at +0x314
        uc.mem_write(obj + 0x314, struct.pack("<I", SCORE))

        # Fix device ID at +0x340
        uc.mem_write(obj + 0x340, struct.pack("<I", DEVICE_ID))

        self._seed_session_resolver_desc(uc, obj)

        print(f"[SESSION] Built session object at {obj:#x} ({obj_size} bytes, "
              f"{len(ptr_fields)} ptrs: {ptr_mapped} mapped, {ptr_stubbed} stubbed, "
              f"{mapped_region_pages} region pages loaded)")

        # Overlay fresh detection state from current device install if available
        self._overlay_current_session_capture(uc, obj)

        return obj

    def _overlay_current_session_capture(self, uc, obj):
        """Overlay fresh session/detection state from current_session_capture.json.

        Patches the emulator's session object and backing memory so that the
        cert computation uses the current install's per-device detection state
        instead of the stale manual7 snapshot.

        Actual capture format (produced by codex-nmss):
        {
            "owner_data_hex": "<4096-byte owner object hex>",
            "container": {"data_hex": "<container hex>", ...},
            "vectors": {
                "source": {"data_hex": "...", "records_0x140": N, ...},
                "cmp1":   {"data_hex": "...", "records_0x140": N, ...},
                "cmp2":   {"data_hex": "...", "records_0x140": N, ...}
            },
            "pages": [{"addr": "0x...", "data_hex": "..."}, ...]
        }
        """
        if not os.path.exists(CURRENT_SESSION_CAPTURE_PATH):
            return

        import json
        with open(CURRENT_SESSION_CAPTURE_PATH) as f:
            cap = json.load(f)

        print("[OVERLAY] Loading current session capture from "
              f"{CURRENT_SESSION_CAPTURE_PATH}", flush=True)

        # Extract device JIT base for SHA-256 address rebasing
        wrapper = cap.get("wrapper", {})
        if wrapper.get("base"):
            self._device_jit_base = int(wrapper["base"], 16) if isinstance(wrapper["base"], str) else wrapper["base"]
            print(f"[OVERLAY] Device JIT base: {self._device_jit_base:#x} "
                  f"(emu: {JIT_BASE:#x}, delta: {self._device_jit_base - JIT_BASE:#x})", flush=True)

        # --- Load device cert capture data (SHA input + detection buffer) ---
        # DISABLED: overlay data from old session (different session key).
        # The emulator should compute its own values matching the current SESSION_KEY.
        DEVICE_CERT_CAPTURE = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "device_cert_capture_CURRENT.json")
        if os.path.exists(DEVICE_CERT_CAPTURE):
            with open(DEVICE_CERT_CAPTURE) as dcf:
                dcc = json.load(dcf)
            # Inject device SHA-256 input (192 bytes)
            sha_hex = dcc.get("sha_input_192", "")
            if len(sha_hex) == 384:  # 192 bytes = 384 hex chars
                self._device_sha_input_192 = bytes.fromhex(sha_hex)
                print(f"[OVERLAY] Loaded device SHA input (192 bytes)", flush=True)
            # Inject device detection buffer (1040 ASCII chars)
            det_ascii = dcc.get("det_buf_ascii", "")
            if len(det_ascii) == 1040:
                self._device_det_buf_ascii = det_ascii
                print(f"[OVERLAY] Loaded device detection buffer (1040 chars)", flush=True)
            # Use device JIT base from capture if not already set
            if not hasattr(self, '_device_jit_base') and dcc.get("jit_base"):
                self._device_jit_base = int(dcc["jit_base"], 16)
                print(f"[OVERLAY] Device JIT base from cert capture: {self._device_jit_base:#x}", flush=True)
            # Write device SHA input directly into JIT memory so native SHA-256
            # code reads the correct values (SHA-256 FF is now disabled).
            if hasattr(self, '_device_sha_input_192'):
                sha_addr = JIT_BASE + 0x448478
                try:
                    uc.mem_write(sha_addr, self._device_sha_input_192)
                    print(f"[OVERLAY] Wrote device SHA input (192 bytes) to JIT+0x448478 ({sha_addr:#x})", flush=True)
                except Exception as e:
                    print(f"[OVERLAY] Failed to write SHA input to JIT memory: {e}", flush=True)
            # Load S1 sprintf overrides from capture
            s1_overrides = {}
            for idx in (1, 2, 3):
                key = f"s1_args_{idx}"
                val = dcc.get(key, "")
                if val and len(val) == 48:
                    s1_overrides[idx] = val.encode('ascii')
                    print(f"[OVERLAY] Loaded S1#{idx} override: {val}", flush=True)
            if s1_overrides:
                self._device_s1_overrides = s1_overrides
        else:
            print(f"[OVERLAY] No device_cert_capture.json found at {DEVICE_CERT_CAPTURE}", flush=True)

        # --- 1. Map extra pages from the capture ---
        # Only load pages that DON'T overlap with existing emulator memory.
        # Overlapping pages can corrupt heap/stack/code regions.
        # TODO: Re-enable page loading once vector-only overlay is verified
        pages_loaded = 0
        pages_skipped = 0
        for pg in cap.get("pages", []):
            hex_data = pg.get("data_hex") or pg.get("hex")
            if not hex_data:
                continue
            addr_raw = pg["addr"]
            pg_addr = int(addr_raw, 16) if isinstance(addr_raw, str) else addr_raw
            pg_addr = (pg_addr & 0x0000FFFFFFFFFFFF) & ~0xFFF
            pg_data = bytes.fromhex(hex_data)
            if pg_addr in self.mapped_pages:
                pages_skipped += 1
                continue
            try:
                uc.mem_map(pg_addr, 0x1000, UC_PROT_ALL)
            except Exception:
                pass
            try:
                uc.mem_write(pg_addr, pg_data[:0x1000])
                self.mapped_pages.add(pg_addr)
                pages_loaded += 1
            except Exception:
                pass
        if pages_loaded or pages_skipped:
            print(f"[OVERLAY] Pages: {pages_loaded} loaded, "
                  f"{pages_skipped} skipped (overlap)", flush=True)

        # --- 2. Overlay owner object fields ---
        owner_hex = cap.get("owner_data_hex", "")
        owner_data = bytes.fromhex(owner_hex) if owner_hex else None
        if owner_data:
            owner_size = len(owner_data)

            # Patch non-pointer scalar fields from capture data.
            # Known-scalar offsets that look like pointers but are actually
            # metadata (JIT module base/end stored as data, not dereferenced):
            KNOWN_SCALAR_OFFSETS = {0x320, 0x328, 0x330, 0x338}
            # Binary search: OVERLAY_SKIP env var = comma-separated hex offset
            # ranges to SKIP, e.g. "0x0b8-0x118,0x300-0x340"
            skip_ranges = []
            skip_env = os.environ.get("OVERLAY_SKIP", "")
            if skip_env:
                for part in skip_env.split(","):
                    part = part.strip()
                    if "-" in part:
                        lo, hi = part.split("-", 1)
                        skip_ranges.append((int(lo, 16), int(hi, 16)))
                    else:
                        v = int(part, 16)
                        skip_ranges.append((v, v + 8))
            patched = 0
            skipped_by_filter = 0
            for off in range(0, min(owner_size, 0x400), 8):
                cap_val = struct.unpack_from("<Q", owner_data, off)[0]
                if cap_val == 0:
                    continue
                # Check skip ranges
                if any(lo <= off < hi for lo, hi in skip_ranges):
                    skipped_by_filter += 1
                    continue
                if off in KNOWN_SCALAR_OFFSETS:
                    is_ptr = False
                else:
                    untagged = cap_val & 0x0000FFFFFFFFFFFF
                    top16 = (cap_val >> 48) & 0xFFFF
                    top8 = (cap_val >> 56) & 0xFF
                    is_ptr = (top16 == 0xb400 or
                              top8 in (0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79) or
                              0x70_0000_0000 <= untagged < 0x80_0000_0000)
                if not is_ptr:
                    uc.mem_write(obj + off, owner_data[off:off + 8])
                    patched += 1
            print(f"[OVERLAY] Owner scalar overlay: {patched} fields patched"
                  + (f" ({skipped_by_filter} skipped by OVERLAY_SKIP)" if skipped_by_filter else ""),
                  flush=True)

            # Patch +0x210 SSO — force current install's session key as long SSO.
            # Device uses FERUN short SSO here, but that triggers a cache-lookup
            # path that returns empty in the emulator.  The long-SSO session key
            # path computes the cert inline.  Must write explicitly because the
            # snapshot's +0x210 points to the OLD install's key.
            # Try to extract session key from capture data (owner+0x210 long SSO
            # pointing into a captured page).
            actual_sk = SESSION_KEY
            # Always use the configured SESSION_KEY — capture pages
            # contain an old session's key that would conflict.
            sk_hex = actual_sk.hex().upper().encode('ascii')  # 32-char hex
            sk_heap = self.heap.malloc(len(sk_hex) + 1)
            uc.mem_write(sk_heap, sk_hex + b'\x00')
            sso_210 = bytearray(24)
            sso_210[0] = 0x31  # tag: long SSO (bit0=1, capacity hint)
            struct.pack_into("<Q", sso_210, 8, len(sk_hex))   # size
            struct.pack_into("<Q", sso_210, 16, sk_heap)      # data ptr
            uc.mem_write(obj + 0x210, bytes(sso_210))
            print(f"[OVERLAY] Forced owner+0x210: long SSO session key "
                  f"{sk_hex.decode()} at {sk_heap:#x}", flush=True)

            # Patch +0x288 SSO (UDID — per-install device identity)
            if 0x2A0 <= owner_size:
                udid_sso = owner_data[0x288:0x2A0]
                uc.mem_write(obj + 0x288, udid_sso)
                udid_tag = udid_sso[0]
                if udid_tag and not (udid_tag & 1):
                    udid_len = udid_tag >> 1
                    udid_str = udid_sso[1:1 + udid_len].decode('ascii', errors='replace')
                    print(f"[OVERLAY] Patched owner+0x288 UDID: {udid_str}",
                          flush=True)

        # --- 2b. Overlay descriptor at owner+0x388 ---
        # DISABLED: patching the descriptor breaks CFF dispatch routing.
        # The snapshot's descriptor has proper internal pointers the CFF
        # code depends on. Replacing it with captured data (with device
        # pointers zeroed) corrupts the callback chain.
        # Re-enable selectively once we understand which fields are safe.
        desc388 = {}  # cap.get("desc_388", {}) — DISABLED: breaks CFF dispatch
        desc388_hex = desc388.get("hex", "")
        if desc388_hex:
            desc_data = bytes.fromhex(desc388_hex)
            desc_size = max(len(desc_data), 0x400)
            desc_addr = self.heap.malloc(desc_size)
            uc.mem_write(desc_addr, b"\x00" * desc_size)
            uc.mem_write(desc_addr, desc_data[:min(len(desc_data), desc_size)])

            # Patch desc+0xa0 SSO with captured APK path
            a0_hex = desc388.get("a0_hex", "")
            if a0_hex:
                a0_data = bytes.fromhex(a0_hex)
                a0_heap = self.heap.malloc(len(a0_data) + 1)
                uc.mem_write(a0_heap, a0_data + b"\x00")
                sso_a0 = bytearray(24)
                sso_a0[0] = 0x61  # long SSO tag
                struct.pack_into("<Q", sso_a0, 8, len(a0_data))
                struct.pack_into("<Q", sso_a0, 16, a0_heap)
                uc.mem_write(desc_addr + 0xa0, bytes(sso_a0))
                a0_str = desc388.get("a0_str", a0_data[:64].decode('ascii', 'replace'))
                print(f"[OVERLAY] Patched desc388+0xa0 APK path: {a0_str}",
                      flush=True)

            # Patch desc+0x318/0x320 range with captured detection names
            range_hex = desc388.get("range_hex", "")
            if range_hex:
                range_data = bytes.fromhex(range_hex)
                range_addr = self.heap.malloc(len(range_data) + 0x40)
                uc.mem_write(range_addr, range_data)
                uc.mem_write(desc_addr + 0x318, struct.pack("<Q", range_addr))
                uc.mem_write(desc_addr + 0x320,
                             struct.pack("<Q", range_addr + len(range_data)))
                print(f"[OVERLAY] Patched desc388+0x318/320 range: "
                      f"{len(range_data)} bytes at {range_addr:#x}", flush=True)

            # Zero out device pointers in descriptor
            for off in range(0, min(len(desc_data), desc_size) - 8, 8):
                if off in (0xa0, 0xa8, 0xb0,  # SSO fields — skip
                           0x318, 0x320):       # range — already patched
                    continue
                val = struct.unpack_from("<Q", desc_data, off)[0]
                val_clean = val & 0x0000FFFFFFFFFFFF
                if val_clean > 0x70000000000 and val_clean < 0x800000000000:
                    uc.mem_write(desc_addr + off, struct.pack("<Q", 0))

            # Write descriptor pointer to owner+0x388
            uc.mem_write(obj + 0x388, struct.pack("<Q", desc_addr))
            print(f"[OVERLAY] Patched owner+0x388 descriptor at {desc_addr:#x} "
                  f"({len(desc_data)} bytes)", flush=True)

        # --- 2c. Overlay descriptor at owner+0x3a0 ---
        # DISABLED: _seed_session_resolver_desc already configures +0x3a0.
        # Overwriting with raw device data (zeroed pointers) breaks callbacks.
        desc3a0 = {}  # cap.get("desc_3a0", {})
        desc3a0_hex = desc3a0.get("hex", "")
        if desc3a0_hex:
            d3a0_data = bytes.fromhex(desc3a0_hex)
            d3a0_size = max(len(d3a0_data), 0x400)
            d3a0_addr = self.heap.malloc(d3a0_size)
            uc.mem_write(d3a0_addr, b"\x00" * d3a0_size)
            uc.mem_write(d3a0_addr, d3a0_data[:min(len(d3a0_data), d3a0_size)])
            # Zero device pointers
            for off in range(0, min(len(d3a0_data), d3a0_size) - 8, 8):
                val = struct.unpack_from("<Q", d3a0_data, off)[0]
                val_clean = val & 0x0000FFFFFFFFFFFF
                if val_clean > 0x70000000000 and val_clean < 0x800000000000:
                    uc.mem_write(d3a0_addr + off, struct.pack("<Q", 0))
            uc.mem_write(obj + 0x3a0, struct.pack("<Q", d3a0_addr))
            print(f"[OVERLAY] Patched owner+0x3a0 descriptor at {d3a0_addr:#x} "
                  f"({len(d3a0_data)} bytes)", flush=True)

        # --- 2d. Overlay SSO heap data ---
        # DISABLED: patching +0x088/+0x0a0 SSOs breaks CFF routing.
        # These contain lib/APK paths that the CFF code uses for dispatch.
        # The snapshot's SSO pointers chain to valid heap data.
        sso_heaps = {}  # cap.get("sso_heaps", {})
        for sso_off_str, sso_hex in sso_heaps.items():
            try:
                sso_off = int(sso_off_str, 16)
            except ValueError:
                continue
            sso_data = bytes.fromhex(sso_hex)
            sso_heap_addr = self.heap.malloc(len(sso_data) + 1)
            uc.mem_write(sso_heap_addr, sso_data + b"\x00")
            # Read current SSO tag to preserve format
            cur_sso = bytes(uc.mem_read(obj + sso_off, 24))
            new_sso = bytearray(24)
            new_sso[0] = cur_sso[0] if (cur_sso[0] & 1) else 0x61
            struct.pack_into("<Q", new_sso, 8, len(sso_data))
            struct.pack_into("<Q", new_sso, 16, sso_heap_addr)
            uc.mem_write(obj + sso_off, bytes(new_sso))
            try:
                preview = sso_data[:60].decode('ascii', 'replace')
            except:
                preview = sso_data[:30].hex()
            print(f"[OVERLAY] Patched owner+0x{sso_off:03x} SSO: "
                  f"'{preview}' ({len(sso_data)} bytes)", flush=True)

        # --- 3. Allocate and populate detection container ---
        cont_hex = cap.get("container", {}).get("data_hex", "")
        if not cont_hex:
            print("[OVERLAY] No container data in capture, skipping", flush=True)
            return

        cont_data = bytes.fromhex(cont_hex)
        cont_size = max(len(cont_data), 0x5C0)
        cont_addr = self.heap.malloc(cont_size)
        uc.mem_write(cont_addr, b"\x00" * cont_size)
        uc.mem_write(cont_addr, cont_data[:min(len(cont_data), cont_size)])

        # --- 4. Allocate and populate detection vectors ---
        vectors = cap.get("vectors", {})

        def alloc_vector(vec_key, cont_begin_off, cont_end_off):
            """Allocate vector records on heap and patch container pointers."""
            vec = vectors.get(vec_key)
            if not vec:
                return 0
            vec_hex = vec.get("data_hex", "")
            if not vec_hex:
                return 0
            vec_data = bytes.fromhex(vec_hex)
            rec_count = vec.get("records_0x140", len(vec_data) // 0x140)
            actual = rec_count * 0x140
            actual = min(len(vec_data), actual)
            if actual == 0:
                return 0

            vec_addr = self.heap.malloc(actual + 0x100)  # padding
            uc.mem_write(vec_addr, vec_data[:actual])
            vec_end = vec_addr + actual

            uc.mem_write(cont_addr + cont_begin_off,
                         struct.pack("<Q", vec_addr))
            uc.mem_write(cont_addr + cont_end_off,
                         struct.pack("<Q", vec_end))
            print(f"[OVERLAY] {vec_key}: {rec_count} records ({actual:#x} bytes) "
                  f"at {vec_addr:#x}-{vec_end:#x}", flush=True)
            return rec_count

        # Zero out all device pointers in the container that we don't have
        # data for — prevents crashes when JIT code dereferences them.
        for off in range(0, min(len(cont_data), cont_size) - 8, 8):
            val = struct.unpack_from("<Q", cont_data, off)[0]
            val_clean = val & 0x0000FFFFFFFFFFFF
            if val_clean > 0x70000000000 and val_clean < 0x800000000000:
                # Device pointer — zero it unless we're about to overwrite it
                uc.mem_write(cont_addr + off, struct.pack("<Q", 0))

        n_src = alloc_vector("source", 0x10, 0x18)
        n_cmp1 = alloc_vector("cmp1", 0x588, 0x590)
        n_cmp2 = alloc_vector("cmp2", 0x5a0, 0x5a8)

        # Load vec_0x70 (container+0x70/+0x78) — 5 records at 0x130-byte stride
        vec70 = vectors.get("vec_0x70")
        if vec70:
            vec70_hex = vec70.get("data_hex", "")
            if vec70_hex:
                vec70_data = bytes.fromhex(vec70_hex)
                rec_count = vec70.get("records_0x130", len(vec70_data) // 0x130)
                vec70_span = rec_count * 0x130
                vec70_actual = min(len(vec70_data), vec70_span)
                vec70_addr = self.heap.malloc(vec70_actual + 0x100)
                uc.mem_write(vec70_addr, vec70_data[:vec70_actual])
                uc.mem_write(cont_addr + 0x70, struct.pack("<Q", vec70_addr))
                uc.mem_write(cont_addr + 0x78,
                             struct.pack("<Q", vec70_addr + vec70_actual))
                print(f"[OVERLAY] vec_0x70: {rec_count} records "
                      f"(0x130 stride, {vec70_actual:#x} bytes) "
                      f"at {vec70_addr:#x}", flush=True)

        # Load additional container vectors if provided.
        # Format: vectors.vec_0xNN with begin_off/end_off and data_hex
        for vkey, vdata in vectors.items():
            if not vkey.startswith("vec_0x") or vkey == "vec_0x70":
                continue
            off_str = vkey[4:]  # e.g. "0x40"
            try:
                begin_off = int(off_str, 16)
            except ValueError:
                continue
            end_off = begin_off + 8
            vhex = vdata.get("data_hex", "")
            if not vhex:
                continue
            vbytes = bytes.fromhex(vhex)
            stride = vdata.get("stride", 0x140)
            rec_key = f"records_0x{stride:x}" if stride != 0x140 else "records_0x140"
            n_recs = vdata.get(rec_key, vdata.get("records", len(vbytes) // stride))
            actual = min(len(vbytes), n_recs * stride)
            if actual == 0:
                continue
            va = self.heap.malloc(actual + 0x100)
            uc.mem_write(va, vbytes[:actual])
            uc.mem_write(cont_addr + begin_off, struct.pack("<Q", va))
            uc.mem_write(cont_addr + end_off, struct.pack("<Q", va + actual))
            print(f"[OVERLAY] {vkey}: {n_recs} records "
                  f"({stride:#x} stride, {actual:#x} bytes) "
                  f"at {va:#x}", flush=True)

        # --- 5. Patch owner+0x390 to point to our new container ---
        uc.mem_write(obj + 0x390, struct.pack("<Q", cont_addr))

        # Flag so COMPARE-VEC-FIX hooks at 0x1090d8/0x1091a8 skip overriding
        # the captured compare vectors with the source vector.
        if n_cmp1 or n_cmp2:
            self._overlay_compare_vectors_injected = True

        print(f"[OVERLAY] Detection container at {cont_addr:#x}, "
              f"owner+0x390 patched. Vectors: src={n_src}, "
              f"cmp1={n_cmp1}, cmp2={n_cmp2}", flush=True)

    def _read_capture_span(self, uc, addr, size):
        """Read `size` bytes starting at untagged `addr` from emulator memory.
        Falls back to reading page-by-page in case of unmapped gaps."""
        addr = addr & 0x0000FFFFFFFFFFFF
        out = bytearray()
        remain = int(size)
        cur = addr
        while remain > 0:
            try:
                chunk = min(remain, 0x1000 - (cur & 0xFFF))
                out.extend(uc.mem_read(cur, chunk))
                cur += chunk
                remain -= chunk
            except Exception:
                break
        return bytes(out) if len(out) == size else None

    def _build_encoder_object_from_snapshot(self, uc, orig_x2):
        """Build encoder object from live snapshot data.
        The nmsscr tokenProc entry is mid-function and skips challenge parsing,
        so the encoder object built by nmsscr is missing critical heap pointers
        and the challenge SSO. This rebuilds it from the snapshot template."""
        import json
        snap_path = LIVE_JIT_SNAPSHOT_JSON_PATH
        if not os.path.exists(snap_path):
            return None
        with open(snap_path) as f:
            snap = json.load(f)
        x2_snap = snap['mem'].get('x2')
        if not x2_snap:
            return None
        x2_data = bytearray.fromhex(x2_snap['hex'])
        obj_size = len(x2_data)

        # Allocate encoder object on heap
        enc_obj = self.heap.malloc(obj_size + 0x100)
        uc.mem_write(enc_obj, b'\x00' * (obj_size + 0x100))

        # Process: copy snapshot data, untagging heap pointers
        clean = bytearray(obj_size)
        for off in range(0, obj_size, 8):
            val = int.from_bytes(x2_data[off:off+8], 'little')
            if val == 0:
                continue
            top16 = (val >> 48) & 0xFFFF
            top8 = (val >> 56) & 0xFF
            is_heap = top16 == 0xb400
            is_code = 0x7000000000 <= val < 0x8000000000
            if is_heap:
                # Untag heap pointer — TBI handler will map tagged pages on demand
                untagged = val & 0x0000FFFFFFFFFFFF
                struct.pack_into("<Q", clean, off, untagged)
            elif is_code:
                # Rebase device code pointer to emulator address
                # Try nmsscr first
                rebased = None
                jit_runtime_size = self._jit_runtime_size()
                for base in self._jit_live_bases:
                    if base <= val < base + jit_runtime_size:
                        rebased = val - base + JIT_BASE
                        break
                if rebased is None and self.NMSSCR_LIVE_BASE <= val < self.NMSSCR_LIVE_BASE + 0x600000:
                    rebased = val - self.NMSSCR_LIVE_BASE + CODE_BASE
                if rebased is not None:
                    struct.pack_into("<Q", clean, off, rebased)
                else:
                    # Unknown code pointer — keep original (might fail)
                    clean[off:off+8] = x2_data[off:off+8]
            else:
                clean[off:off+8] = x2_data[off:off+8]

        # Patch challenge SSO at +0x50 (short SSO: byte[0]=len*2, bytes[1..]=data)
        ch = self._challenge_hex.encode('ascii')
        if len(ch) <= 22:
            sso = bytearray(24)
            sso[0] = len(ch) * 2
            sso[1:1+len(ch)] = ch
            clean[0x50:0x50+24] = sso

        uc.mem_write(enc_obj, bytes(clean))
        return enc_obj

    def _hook_get_session_key(self, uc, x0, x1, x2, x8):
        print(f"[SESSION-KEY-HOOK] Writing SESSION_KEY={SESSION_KEY.hex()} to x8={x8:#x}", flush=True)
        self._write_sso(uc, x8, SESSION_KEY)

    def _hook_get_string_by_index(self, uc, x0, x1, x2, x8):
        self._write_sso(uc, x8, b"\r\n" if x0 == 0x2c else b"")

    def _hook_sprintf(self, uc, x0, x1, x2, x8):
        try:
            fmt = bytes(uc.mem_read(x0, 64)).split(b'\x00')[0]
        except:
            fmt = b""
        if fmt == b'%p':
            result = f"{x1:#x}".encode()
        elif fmt == b'%d':
            val = x1 if x1 < 0x80000000 else x1 - 0x100000000
            result = f"{val}".encode()
        elif fmt == b'%u':
            result = f"{x1 & 0xFFFFFFFF}".encode()
        elif fmt == b'%x':
            result = f"{x1 & 0xFFFFFFFF:x}".encode()
        elif fmt == b'%X':
            result = f"{x1 & 0xFFFFFFFF:X}".encode()
        elif fmt == b'%02X':
            result = f"{x1 & 0xFF:02X}".encode()
        elif fmt == b'%02x':
            result = f"{x1 & 0xFF:02x}".encode()
        elif fmt == b'%s':
            n = 0
            try:
                while n < 256 and bytes(uc.mem_read(x1 + n, 1))[0]:
                    n += 1
                result = bytes(uc.mem_read(x1, n))
            except:
                result = b""
        else:
            result = b""
        self._write_sso(uc, x8, result)
        self.log(f"sprintf(fmt={fmt}, x1={x1:#x}) -> {result!r}")

    def _hook_clock(self, uc, x0, x1, *a):
        # Advance fake time by 1ms each call (matches native harness behavior)
        sec = self._fake_time_sec
        nsec = self._fake_time_nsec
        if x0 <= 0x1000 and x1 > 0x1000:
            # clock_gettime(clockid_t, struct timespec*)
            uc.mem_write(x1, struct.pack("<qq", sec, nsec))
        elif x0 > 0x1000:
            # gettimeofday(struct timeval*, ...)
            uc.mem_write(x0, struct.pack("<qq", sec, nsec // 1000))
        self._advance_fake_clock(1_000_000)  # 1ms step
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _advance_fake_clock(self, delta_nsec):
        self._fake_time_nsec += delta_nsec
        if self._fake_time_nsec >= 1_000_000_000:
            self._fake_time_sec += self._fake_time_nsec // 1_000_000_000
            self._fake_time_nsec %= 1_000_000_000

    def _reset_bionic_random(self):
        # Android bionic's rand/srand delegates to random/srandom, whose
        # default global state is TYPE_3 with a process-default seed of 1.
        self._rng_state = [0] * 31
        self._rng_fidx = 3
        self._rng_ridx = 0
        self._bionic_srandom_unlocked(1)

    def _bionic_srandom_unlocked(self, seed):
        seed &= 0xFFFFFFFF
        self._rng_state[0] = seed
        for i in range(1, 31):
            prev = self._rng_state[i - 1]
            hi = prev // 127773
            lo = prev % 127773
            val = 16807 * lo - 2836 * hi
            if val <= 0:
                val += 0x7FFFFFFF
            self._rng_state[i] = val & 0xFFFFFFFF
        self._rng_fidx = 3
        self._rng_ridx = 0
        for _ in range(10 * 31):
            self._bionic_random_unlocked()

    def _bionic_random_unlocked(self):
        val = (self._rng_state[self._rng_fidx] + self._rng_state[self._rng_ridx]) & 0xFFFFFFFF
        self._rng_state[self._rng_fidx] = val
        out = (val >> 1) & 0x7FFFFFFF
        self._rng_fidx += 1
        if self._rng_fidx >= 31:
            self._rng_fidx = 0
            self._rng_ridx += 1
        else:
            self._rng_ridx += 1
            if self._rng_ridx >= 31:
                self._rng_ridx = 0
        return out

    def _hook_rand(self, uc, x0, *a):
        self._rand_counter += 1
        uc.reg_write(UC_ARM64_REG_X0, self._bionic_random_unlocked())

    def _hook_srand(self, uc, x0, *a):
        seed = x0 & 0xFFFFFFFF
        lr = uc.reg_read(UC_ARM64_REG_LR)
        self._srand_counter += 1
        self._last_srand_seed = seed
        jit_off = lr - JIT_BASE if JIT_BASE <= lr < JIT_BASE + 0x300000 else None
        loc = f"JIT+{jit_off:#x}" if jit_off is not None else f"lr={lr:#x}"
        print(f"[SRAND] seed={seed:#x} ({seed}) from {loc}", flush=True)
        self._bionic_srandom_unlocked(seed)
        uc.reg_write(UC_ARM64_REG_X0, 0)

    def _rand_buffer_inject_hook(self, uc, addr, size, user_data):
        """At JIT+0x6a69c (post rand-fill loop), inject device buffer if available."""
        if self._device_rand_buffer is None:
            return
        x23 = uc.reg_read(UC_ARM64_REG_X23)
        ptr_bytes = uc.mem_read(x23 + 0x958, 8)
        ptr_val = int.from_bytes(ptr_bytes, 'little')
        if ptr_val != 0:
            uc.mem_write(ptr_val, self._device_rand_buffer)
            print(f"[BUFFER-INJECT] Overwrote 128 bytes at {ptr_val:#x}", flush=True)
            self._device_rand_buffer = None  # only inject once

    def _hook_time(self, uc, x0, *a):
        sec = self._fake_time_sec
        if x0 > 0x1000:
            uc.mem_write(x0, struct.pack("<q", sec))
        self._advance_fake_clock(1_000_000)
        uc.reg_write(UC_ARM64_REG_X0, sec)

    def _hook_getpid(self, uc, *a):
        uc.reg_write(UC_ARM64_REG_X0, 1337)

    def _hook_svc_wrapper(self, uc, x0, x1, x2, x8):
        uc.reg_write(UC_ARM64_REG_X0, 0)

    # ---- Detection hooks ----
    def _hook_det_chk(self, uc, x0, x1, x2, x8):
        det_values = {
            0x15: 0, 0x16: 0,
            0x1d: 35, 0x2a: 1,
            0x07: 0, 0x27: 0, 0x1f: 0, 0x0e: 0,
        }
        val = det_values.get(x1, 0)
        uc.reg_write(UC_ARM64_REG_X0, val)
        self.log(f"det_chk(type={x1:#x}) -> {val}")

    def _hook_sensor_chk(self, uc, x0, x1, x2, x8):
        val = 1 if x1 in (1, 2, 4) else 0
        uc.reg_write(UC_ARM64_REG_X0, val)
        self.log(f"sensor_chk(type={x1:#x}) -> {val}")

    # ---- sprintf fast-forward (Python implementation) ----
    def _sprintf_fast(self, uc, fmt, arg_ptr):
        """Python-side sprintf for the JIT's printf-style format loop.
        Reads args from arg_ptr (8-byte slots). Returns bytes or None on failure."""
        result = bytearray()
        i = 0
        arg_off = 0
        while i < len(fmt):
            if fmt[i] != '%':
                result.append(ord(fmt[i]))
                i += 1
                continue
            i += 1  # skip '%'
            if i >= len(fmt):
                break
            if fmt[i] == '%':
                result.append(ord('%'))
                i += 1
                continue
            # Parse flags, width, length modifier
            zero_pad = False
            width = 0
            long_mod = False
            while i < len(fmt) and fmt[i] == '0':
                zero_pad = True
                i += 1
            while i < len(fmt) and fmt[i].isdigit():
                width = width * 10 + int(fmt[i])
                i += 1
            if i < len(fmt) and fmt[i] == 'l':
                long_mod = True
                i += 1
            if i >= len(fmt):
                break
            spec = fmt[i]
            i += 1
            # Read arg (8-byte slot)
            try:
                raw = struct.unpack("<Q", uc.mem_read(arg_ptr + arg_off, 8))[0]
            except:
                raw = 0
            arg_off += 8
            if spec in ('X', 'x'):
                val = raw & 0xFFFFFFFF if not long_mod else raw
                s = format(val, 'X' if spec == 'X' else 'x')
                if zero_pad and width > len(s):
                    s = '0' * (width - len(s)) + s
                elif width > len(s):
                    s = ' ' * (width - len(s)) + s
                result.extend(s.encode())
            elif spec == 'd':
                val = raw & 0xFFFFFFFF if not long_mod else raw
                if not long_mod and val >= 0x80000000:
                    val -= 0x100000000
                s = str(val)
                if width > len(s):
                    pad = '0' if zero_pad else ' '
                    s = pad * (width - len(s)) + s
                result.extend(s.encode())
            elif spec == 's':
                try:
                    ptr = raw
                    s = self._read_c_string(uc, ptr, 1024)
                    result.extend(s)
                except:
                    pass
            elif spec == 'c':
                result.append(raw & 0xFF)
            else:
                # Unknown spec, just output literally
                result.extend(f'%{spec}'.encode())
                arg_off -= 8  # don't consume arg
        return bytes(result)

    # ---- Complex function stubs ----
    def _hook_sub_2070a8(self, uc, x0, x1, x2, x8):
        """
        sub_2070a8(tokenGen_obj, 1, 1) -> encoder state ptr.
        We create a minimal state object. The key thing is that sub_209dc4
        will read from this to resolve a function pointer.
        """
        state = self.heap.malloc(0x400)
        uc.mem_write(state, b'\x00' * 0x400)

        # The state object needs enough structure that sub_209dc4 can return
        # a valid function pointer. But since we hook sub_209dc4 too,
        # we just need a non-null pointer.
        self._cb_area = state

        # Store at global 0x4eae08 (tokenProc reads it back at 0x20abdc)
        uc.mem_write(0x4eae08, struct.pack("<Q", state))
        uc.reg_write(UC_ARM64_REG_X0, state)
        self.log(f"sub_2070a8() -> state={state:#x}")

    def _hook_sub_209dc4(self, uc, x0, x1, x2, x8):
        """
        sub_209dc4(x0, encoder_state_from_2070a8) -> function pointer.
        Returns the JIT encoder function 'fx' at JIT_BASE+0x10828c.
        This is the function that tokenProc calls via BLR x8 at 0x20b548.
        """
        uc.reg_write(UC_ARM64_REG_X0, self.ENCODER_DISPATCH_FN)
        self.log(f"sub_209dc4() -> JIT encoder at {self.ENCODER_DISPATCH_FN:#x}")

    # ---- SSO helpers ----
    def _write_sso(self, uc, addr, data, force_long=False):
        """Write a libc++ SSO string. Android layout:
        Short: byte[0] = len*2 (low bit 0), data at byte[1..22]
        Long:  [cap*2|1 at +0, size at +8, data_ptr at +16]"""
        buf = bytearray(24)
        if len(data) <= 22 and not force_long:
            buf[0] = len(data) * 2
            buf[1:1 + len(data)] = data
        else:
            hb = self.heap.malloc(len(data) + 1)
            uc.mem_write(hb, data + b'\x00')
            cap = len(data) + 1
            struct.pack_into("<Q", buf, 0, (cap * 2) | 1)  # cap with long flag
            struct.pack_into("<Q", buf, 8, len(data))       # size
            struct.pack_into("<Q", buf, 16, hb)             # data pointer
        uc.mem_write(addr, bytes(buf))

    def _read_sso(self, uc, addr):
        """Read a libc++ SSO string. Android layout:
        Short: byte[0] = len*2, data at byte[1..22]
        Long:  [cap*2|1 at +0, size at +8, data_ptr at +16]"""
        h = bytes(uc.mem_read(addr, 24))
        b0 = h[0]
        if (b0 & 1) == 0:
            n = b0 >> 1
            return h[1:1 + min(n, 22)]
        else:
            n = struct.unpack("<Q", h[8:16])[0]   # size at +8
            p = struct.unpack("<Q", h[16:24])[0]  # data_ptr at +16
            if 0 < n < 0x1000000 and p:
                try:
                    return bytes(uc.mem_read(p, n))
                except:
                    return b""
            return b""

    # ---- Main computation ----
    def _reinit_uc(self):
        """Create a fresh Unicorn instance and restore all memory from snapshots.
        This is the only reliable way to get deterministic state — Unicorn
        retains internal state (iCache, TLB, etc.) that cannot be fully reset.
        """
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        # Map all regions
        for base, size in [(CODE_BASE, CODE_SIZE), (STACK_BASE, STACK_SIZE),
                           (HEAP_BASE, HEAP_SIZE), (MANAGER_BASE, MANAGER_SIZE),
                           (TLS_BASE, TLS_SIZE), (CHALLENGE_BASE, 0x2000),
                           (SCRATCH_BASE, SCRATCH_SIZE)]:
            self.uc.mem_map(base, size, UC_PROT_ALL)
        if self.jit_data:
            self.uc.mem_map(JIT_BASE, self._jit_runtime_size(), UC_PROT_ALL)
        # Restore all memory from snapshots (same state as post-setup)
        for snap_attr in ['_code_text_snapshot', '_nmsscr_data_snapshot',
                          '_jit_rw_snapshot', '_jit_text_snapshot',
                          '_heap_snapshot', '_manager_snapshot',
                          '_stack_snapshot', '_tls_snapshot', '_scratch_snapshot']:
            snap = getattr(self, snap_attr, None)
            if snap:
                addr, data = snap
                self.uc.mem_write(addr, data)
        for addr, data in getattr(self, '_nmsscr_rw_overlay_snapshots', []):
            self.uc.mem_write(addr, data)
        # Re-seed mapped pages set
        self.mapped_pages = set(self._base_mapped_pages)
        self._seed_mapped_pages()
        # Re-install all permanent hooks on the new UC instance
        self._install_hooks()

    def compute_cert(self, challenge_hex):
        """
        Compute the full 48-char cert token for the given challenge.
        """
        # Restore ALL Python-side state from setup snapshot.
        if hasattr(self, '_setup_pystate_snapshot'):
            import copy as _copy
            _keep = getattr(self, '_setup_attr_keys', set()) | {
                '_setup_pystate_snapshot', '_setup_attr_keys',
                'uc', '_per_run_hooks',
                # Memory snapshots (heavy, don't copy)
                '_code_text_snapshot', '_jit_text_snapshot',
                '_jit_rw_snapshot', '_nmsscr_data_snapshot',
                '_nmsscr_rw_overlay_snapshots', '_manager_snapshot',
                '_stack_snapshot', '_tls_snapshot', '_scratch_snapshot',
                '_heap_snapshot', '_heap_allocator_snapshot',
                '_base_mapped_pages',
            }
            for attr in list(self.__dict__.keys()):
                if attr not in _keep:
                    delattr(self, attr)
            restored = _copy.deepcopy(self._setup_pystate_snapshot)
            for k, v in restored.items():
                setattr(self, k, v)
        # Create fresh Unicorn instance for deterministic execution
        self._reinit_uc()
        self._per_run_hooks = []
        self._challenge_hex = challenge_hex
        self.heap.reset()
        self.hook_count = 0
        self._rand_counter = 0
        self._srand_counter = 0
        self._last_srand_seed = None
        self._reset_bionic_random()
        self._fake_time_sec = 1_700_000_000
        self._fake_time_nsec = 123_456_789
        self._insn_count = 0
        self._cert_slow_forced = False
        self._cff_comp_path_forced = False
        self._last_pc = 0
        self._dispatch_trace.clear()
        self._dispatch_decision_trace.clear()
        self._x28_trace.clear()
        self._recent_data_events.clear()
        self._last_traced_x28 = None
        self._dispatch_hub_hits = 0
        self._dispatch_trace_seq = 0
        self._cert_post_cff_w26_trace.clear()
        self._cert_post_cff_last_w26 = None
        self._cert_cff_hub1_last_state = None
        self._cert_ce75c_minus_pending = False
        self._cert_post_cff_1c3374_state = None
        self._cert_post_cff_1c3374_hits = 0
        self._cert_post_cff_route_fix_applied = 0
        self._cert_native_post_callback_seed_hits = 0
        # mapped_pages already set by _reinit_uc()
        self._cb_area = 0
        self._cff_container_desc = 0  # reset for fresh allocation
        self._jit_stack_struct_seeded = False
        self._jit_inner_entry_logged = False
        self._jit_inner_entry_snapshot = None
        self._jit_cff_bridge_saved_x22 = {}
        self._post_cff_dispatch_last_key = None
        self._post_cff_dispatch_same_count = 0
        self._post_cff_dispatch_skips = 0
        self._jit_invalid_indcall_skips = 0
        self._jit_once_init_hits = 0
        self._cff_hub_count = 0
        self._jit_cff_frame_ctx = {}
        self._cff_current_return_lr = None
        self._cff_current_caller_sp = None
        self._cff_current_caller_fp = None
        self._jit_dl_iterate_phdr_calls = 0
        self._jit_cxa_atexit_calls = 0
        self._jit_cxa_atexit_trace.clear()
        self._jit_state_machine_calls = 0
        self._jit_state_machine_trace.clear()
        self._jit_state_machine_current = None
        self._second_cff_caller_trace.clear()
        self._second_cff_current_iter = None
        self._jit_raw_syscall_trace.clear()
        self._close_jit_fd_table()
        self._jit_tls_values.clear()
        self._jit_tls_next_key = 1
        self._jit_cxa_globals_key = 0
        self._post_cert_cleanup_bypass_active = False
        self._post_cert_cleanup_bypass_hits = 0
        self._xor_pack_last_src = 0
        self._live_region_page_data = {}
        self._live_region_page_index = {}
        self._live_session_regions_loaded = False
        self._live_session_region_pages = 0
        self._jit_fake_tree_nodes.clear()
        self._jit_assets = {}
        self._session_desc_key_map.clear()
        self._session_desc_map_addr = 0
        self._jit_tree_find_log_count = 0
        self._cff_last_state = None
        self._cff_same_count = 0
        self._stall_jit_count = 0
        self._stall_last_fp = 0
        self._stall_same_count = 0
        self._stall_skips = 0
        self._stall_last_page = 0
        self._md5_loop_hits = 0
        self._cert_wrapper_call_count = 0
        self._cert_wrapper_first_seen = False
        self._cert_wrapper_second_seen = False
        self._cert_wrapper_first_sp = None
        self._last_live_output_text = b""
        self._last_hex48_memcpy = b""
        self._last_hex48_memcpy_dst = 0
        self._hex48_memcpy_by_dst = {}
        self._src48_watch_installed = False
        self._src48_watch_range = None
        self._src48_write_count = 0
        self._src48_memcpy_count = 0
        self._src48_raw_writes = bytearray(0x30)
        self._src48_recent_writes = []
        self._src48_last_full_hex = ""
        self._raw24_watch_installed = False
        self._raw24_watch_range = None
        self._raw24_write_count = 0
        self._raw24_memcpy_count = 0
        self._raw24_last_snapshot = ""
        self._inline_sha_read_watch_installed = False
        self._inline_sha_read_watch_range = None
        self._inline_sha_read_count = 0
        self._inline_sha_write_watch_installed = False
        self._inline_sha_write_watch_range = None
        self._inline_sha_write_count = 0
        self._sha_input_watch_installed = False
        self._sha_input_watch_range = None
        self._sha_input_write_count = 0
        self._sha_input_memcpy_count = 0
        self._sha_input_last_snapshot = ""
        self._cert_feeder_last = None
        self._inline_sha_call_hits = 0
        self._inline_sha_probe_hits = 0
        self._inline_sha_tail_hits = 0
        self._inline_sha_state_hits = 0
        self._cert_wrapper_caller = None
        self._cert_wrapper_block_restore_pending = None
        self._cert_wrapper_skip_pending = None
        self._post_cert_skip_block_start = None
        self._1627_raw_writes = bytearray(32)
        self._1702_raw_writes = bytearray(16)
        self._cff_winddown_hits = 0
        self._stall_walk_fail_count = 0
        self._stall_page_count = 0
        self._stall_last_progress_block = 0
        self._stall_returned_lrs = {}
        self._cff_entry_total = 0
        self._cff_skip_total = 0
        self._cff_lr_hist = {}
        self._cff_natural_returns = []
        self._diag_dumped = False
        self._heap_trace_active = False
        self._heap_trace_log = []
        if hasattr(self, '_session_obj'):
            del self._session_obj
        self._trunc_source_lens = []
        self._trunc_source_data = []
        self._compare_record_lens = []
        self._trunc_logged = False
        self._challenge_ctx_watch_base = 0
        self._challenge_ctx_watch_end = 0
        self._challenge_ctx_read_log = []
        self._challenge_ctx_read_count = 0
        self._challenge_read_log = []
        self._challenge_read_count = 0
        self._unmapped_data_count = 0
        self._obj68_write_count = 0
        self._sp50_write_count = 0
        # Memory is already restored by _reinit_uc() above.

        # Build tokenProc's challenge wrapper object. Static disassembly at
        # 0x20ac0c..0x20b058 shows this entry does not consume a normal libc++
        # std::string header. It reads x1+0x8 as the challenge char* and x1+0x10
        # as a non-zero size/cap field, then copies the bytes into encoder
        # context+0x50. The JIT later reads the challenge from x2+0x50, not
        # from CHALLENGE_BASE directly.
        data = challenge_hex.encode('ascii')
        ch_addr = CHALLENGE_BASE
        ch_blob = self.heap.malloc(len(data) + 1)
        self.uc.mem_write(ch_blob, data + b'\x00')
        ch_buf = bytearray(24)
        struct.pack_into("<Q", ch_buf, 8, ch_blob)
        struct.pack_into("<Q", ch_buf, 16, len(data))
        self.uc.mem_write(ch_addr, bytes(ch_buf))

        # tokenGen singleton object
        tokengen_obj = self.heap.malloc(0x100)
        self.uc.mem_write(tokengen_obj, b'\x00' * 0x100)

        # Output object (indirect return via x8).  The live code uses x8 as a
        # C++ std::string object pointer with SSO layout.  The inner CFF function
        # at 0x108000 inherits it as x19 and accesses fields up to x19+0x17a0+
        # (x20 = x19 + 0x1000 + 0x7a0, then x20+0x8a8).  Allocate a full page.
        out_addr = SCRATCH_BASE + 0x80000
        self.uc.mem_write(out_addr, b'\x00' * 0x4000)

        sp = STACK_BASE + STACK_SIZE - 0x4000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_X29, sp)

        # tokenProc(tokenGen_singleton, challenge_std_string)
        self.uc.reg_write(UC_ARM64_REG_X0, tokengen_obj)
        self.uc.reg_write(UC_ARM64_REG_X1, ch_addr)
        self.uc.reg_write(UC_ARM64_REG_X8, out_addr)

        # Return address
        ret_addr = SCRATCH_BASE + 0x10000
        self.uc.mem_write(ret_addr, struct.pack("<I", 0xd65f03c0))
        self.uc.reg_write(UC_ARM64_REG_LR, ret_addr)

        # Clear all general-purpose registers not set above
        from unicorn.arm64_const import (UC_ARM64_REG_X2, UC_ARM64_REG_X3,
            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
            UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11, UC_ARM64_REG_X12,
            UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15, UC_ARM64_REG_X16,
            UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19, UC_ARM64_REG_X20,
            UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
            UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27, UC_ARM64_REG_X28)
        for reg in [UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4,
                    UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
                    UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11,
                    UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14,
                    UC_ARM64_REG_X15, UC_ARM64_REG_X16, UC_ARM64_REG_X17,
                    UC_ARM64_REG_X18, UC_ARM64_REG_X19, UC_ARM64_REG_X20,
                    UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
                    UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26,
                    UC_ARM64_REG_X27, UC_ARM64_REG_X28]:
            self.uc.reg_write(reg, 0)
        # Clear NEON registers (Q regs take integer values in Unicorn)
        for i in range(32):
            try:
                self.uc.reg_write(UC_ARM64_REG_Q0 + i, 0)
            except:
                pass
        # Reset condition flags and FP status to deterministic state.
        # Unicorn initializes NZCV to 0x40000000 (Z flag set); match that.
        self.uc.reg_write(UC_ARM64_REG_NZCV, 0x40000000)
        self.uc.reg_write(UC_ARM64_REG_FPCR, 0)
        self.uc.reg_write(UC_ARM64_REG_FPSR, 0)

        # --- S1 args buffer write watch ---
        # x25=0x7f3fafd0 for S1#1/#2, x25=0x7f3fa9a0 for S1#3.
        # Watch the full range covering all three buffers.
        self._s1_buf_writes = []  # list of (pc, addr, size, value_hex)
        _s1_watch_lo = sp - 0x1680  # below x25=0x7f3fa9a0 (sp-0x1660=0x7f3fa9a0)
        _s1_watch_hi = sp - 0x1000  # above x25=0x7f3fafd0+0x30 (sp-0x1000=0x7f3fb000)

        def _s1_buf_write_cb(uc, access, addr, size, value, user_data):
            pc = uc.reg_read(UC_ARM64_REG_PC)
            off = pc - JIT_BASE if JIT_BASE <= pc < JIT_BASE + JIT_RUNTIME_SIZE else pc
            self._s1_buf_writes.append((off, addr, size, value))

        from unicorn import UC_HOOK_MEM_WRITE
        h = self.uc.hook_add(UC_HOOK_MEM_WRITE, _s1_buf_write_cb,
                             begin=_s1_watch_lo, end=_s1_watch_hi)
        self._per_run_hooks.append(h)
        print(f"[S1-WATCH] installed write watch on {_s1_watch_lo:#x}-{_s1_watch_hi:#x}", flush=True)

        self._emu_start_time = time.time()
        try:
            self.uc.emu_start(0x20aad4, ret_addr,
                             timeout=300_000_000, count=self._max_insn)
        except UcError as e:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            sp_val = self.uc.reg_read(UC_ARM64_REG_SP)
            lr = self.uc.reg_read(UC_ARM64_REG_LR)
            x0 = self.uc.reg_read(UC_ARM64_REG_X0)
            x1 = self.uc.reg_read(UC_ARM64_REG_X1)
            x8 = self.uc.reg_read(UC_ARM64_REG_X8)
            print(f"  Error/timeout at PC={pc:#x} SP={sp_val:#x} LR={lr:#x}: {e}")
            print(f"  x0={x0:#x} x1={x1:#x} x8={x8:#x}")
            print(f"  Instructions executed: {self._insn_count}, hub_hits: {self._dispatch_hub_hits}")
            # Dump source vs compare record length summary on error/timeout path
            src_lens = getattr(self, '_trunc_source_lens', [])
            cmp_lens = getattr(self, '_compare_record_lens', [])
            if src_lens or cmp_lens:
                print(f"\n[LEN-SUMMARY] source_record_logical_lens={src_lens}  compare_record_logical_lens={cmp_lens}")
                src_set = set(src_lens)
                cmp_set = set(cmp_lens)
                overlap = src_set & cmp_set
                print(f"[LEN-SUMMARY] source_unique={sorted(src_set)} compare_unique={sorted(cmp_set)} overlap={sorted(overlap)}")
            self._dump_challenge_watch_summary()
            result = self._extract_result(out_addr)
            if not result:
                self._dump_dispatch_trace()
            return result

        self.log(f"Emulation complete. Instructions: {self._insn_count}, Hooks: {self.hook_count}")
        # Dump source vs compare record length summary
        src_lens = getattr(self, '_trunc_source_lens', [])
        cmp_lens = getattr(self, '_compare_record_lens', [])
        if src_lens or cmp_lens:
            print(f"\n[LEN-SUMMARY] source_record_logical_lens={src_lens}  compare_record_logical_lens={cmp_lens}")
            src_set = set(src_lens)
            cmp_set = set(cmp_lens)
            overlap = src_set & cmp_set
            print(f"[LEN-SUMMARY] source_unique={sorted(src_set)} compare_unique={sorted(cmp_set)} overlap={sorted(overlap)}")
        self._dump_challenge_watch_summary()
        result = self._extract_result(out_addr)
        if not result:
            self._dump_dispatch_trace()
        return result

    def _extract_result(self, out_addr):
        """Extract the result string from the output location."""
        # Priority 1: Check JIT encoder output at encoder_obj+0x68
        # The encoder writes its 48-char cert hex to ctx+0x68 (ctx = x19 from setup)
        for obj68_addr in [0x80003338, 0x800032d0 + 0x68]:
            try:
                raw = bytes(self.uc.mem_read(obj68_addr, 24))
                print(f"[EXTRACT-OBJ68-RAW] addr={obj68_addr:#x} raw={raw.hex()}", flush=True)
            except:
                pass
        # Also check saved JIT cert output from memcpy hook
        jit_cert = getattr(self, '_jit_cert_output', None)
        if jit_cert:
            print(f"[EXTRACT-JIT-CERT] saved={jit_cert}", flush=True)
            if len(jit_cert) >= 48 and all(c in '0123456789ABCDEFabcdef' for c in jit_cert[:48]):
                return jit_cert[:48].upper()
        for obj68_addr in [0x80003338, 0x800032d0 + 0x68]:
            try:
                raw = bytes(self.uc.mem_read(obj68_addr, 24))
                b0 = raw[0]
                if (b0 & 1) == 1:  # LONG SSO
                    n = struct.unpack("<Q", raw[8:16])[0]
                    p = struct.unpack("<Q", raw[16:24])[0]
                    print(f"[EXTRACT-OBJ68-SSO] addr={obj68_addr:#x} LONG n={n} ptr={p:#x}", flush=True)
                    if 0 < n < 0x1000000 and p > 0x1000:
                        try:
                            data = bytes(self.uc.mem_read(p, n))
                            txt = data.decode('ascii', errors='ignore').strip('\x00')
                            print(f"[EXTRACT-OBJ68-DATA] ptr={p:#x} data={txt[:60]!r}", flush=True)
                            if len(txt) >= 48 and all(c in '0123456789ABCDEFabcdef' for c in txt[:48]):
                                print(f"[EXTRACT-OBJ68] addr={obj68_addr:#x} -> {txt[:48]}", flush=True)
                                return txt[:48].upper()
                        except Exception as e:
                            print(f"[EXTRACT-OBJ68-ERR] ptr={p:#x} n={n} err={e}", flush=True)
                else:
                    sso = self._read_sso(self.uc, obj68_addr)
                    if sso:
                        txt = sso.decode('ascii', errors='ignore').strip('\x00')
                        if len(txt) >= 48 and all(c in '0123456789ABCDEFabcdef' for c in txt[:48]):
                            print(f"[EXTRACT-OBJ68] addr={obj68_addr:#x} -> {txt[:48]}", flush=True)
                            return txt[:48].upper()
            except Exception as e:
                print(f"[EXTRACT-OBJ68-OUTER-ERR] addr={obj68_addr:#x} err={e}", flush=True)

        live_output = getattr(self, '_last_live_output_text', b'')
        if live_output:
            txt = live_output.decode('ascii', errors='ignore').strip('\x00')
            if len(txt) >= 48 and all(c in '0123456789ABCDEFabcdef' for c in txt[:48]):
                print(f"[EXTRACT-LIVE-OUTPUT] {txt[:48]}", flush=True)
                return txt[:48].upper()

        memcpy_hex48 = getattr(self, '_last_hex48_memcpy', b'')
        if memcpy_hex48:
            txt = memcpy_hex48.decode('ascii', errors='ignore').strip('\x00')
            if len(txt) >= 48 and all(c in '0123456789ABCDEFabcdef' for c in txt[:48]):
                print(f"[EXTRACT-MEMCPY-HEX48] {txt[:48]}", flush=True)
                return txt[:48].upper()

        result = self._read_sso(self.uc, out_addr)
        if result:
            txt = result.decode('ascii', errors='ignore').strip('\x00')
            if len(txt) >= 48 and all(c in '0123456789ABCDEFabcdef' for c in txt[:48]):
                return txt[:48].upper()
            if txt:
                self.log(f"Output string (len={len(txt)}): {txt[:80]!r}")

        # Check the output struct area more broadly
        for off in [0, 8, 0x10, 0x18, 0x20]:
            try:
                data = self._read_sso(self.uc, out_addr + off)
                if data:
                    txt = data.decode('ascii', errors='ignore').strip('\x00')
                    if len(txt) >= 48 and all(c in '0123456789ABCDEFabcdef' for c in txt[:48]):
                        return txt[:48].upper()
            except:
                pass

        # Try extracting from saved 1627/1702 raw write data (the slot memory
        # may have been zeroed by cleanup, but the write hook saved values).
        raw_1627 = getattr(self, '_1627_raw_writes', None)
        raw_1702 = getattr(self, '_1702_raw_writes', None)
        if raw_1627 and any(b != 0 for b in raw_1627):
            print(f"[EXTRACT-1627-RAW] {bytes(raw_1627).hex()}", flush=True)
        if raw_1702 and any(b != 0 for b in raw_1702):
            print(f"[EXTRACT-1702-RAW] {bytes(raw_1702).hex()}", flush=True)
        # The cert token is 24 bytes = 48 hex chars. Try various combos of 1627+1702.
        if raw_1627 and any(b != 0 for b in raw_1627):
            # Try 1627 alone: first 24 bytes
            tok24 = bytes(raw_1627[:24]).hex().upper()
            if len(tok24) >= 48:
                print(f"[EXTRACT-1627-24] candidate: {tok24[:48]}", flush=True)
            # Try 1702(16) + 1627(8) or 1627(16) + 1702(8) etc.
            if raw_1702 and any(b != 0 for b in raw_1702):
                combo_a = bytes(raw_1702[:16]) + bytes(raw_1627[:8])
                combo_b = bytes(raw_1627[:16]) + bytes(raw_1702[:8])
                combo_c = bytes(raw_1702) + bytes(raw_1627[:8])
                combo_d = bytes(raw_1627[:8]) + bytes(raw_1702)
                for label, combo in [("1702+1627[:8]", combo_a), ("1627[:16]+1702[:8]", combo_b),
                                      ("1702+1627[:8]_v2", combo_c), ("1627[:8]+1702", combo_d)]:
                    if len(combo) >= 24:
                        print(f"[EXTRACT-COMBO {label}] {combo[:24].hex().upper()}", flush=True)

        # Try extracting from the stack region where sp+0x5a0/sp+0x6e0 had SSO slots
        sp = self.uc.reg_read(UC_ARM64_REG_SP)
        for sp_off in (0x5a0, 0x6e0, 0x420, 0x840, 0x980):
            try:
                sso = self._read_sso(self.uc, sp + sp_off)
                if sso:
                    txt = sso.decode('ascii', errors='ignore').strip('\x00')
                    if len(txt) >= 48 and all(c in '0123456789ABCDEFabcdef' for c in txt[:48]):
                        print(f"[EXTRACT-STACK] sp+{sp_off:#x}={txt[:48]}", flush=True)
                        return txt[:48].upper()
            except:
                pass

        # Scan heap for 48-char hex string result
        for off in range(0, min(self.heap.offset + 256, HEAP_SIZE), 16):
            addr = HEAP_BASE + off
            try:
                d = bytes(self.uc.mem_read(addr, 64))
                t = d.split(b'\x00')[0]
                if len(t) >= 48 and all(c in b'0123456789ABCDEFabcdef' for c in t[:48]):
                    return t[:48].decode('ascii').upper()
            except:
                pass

        return None


def compute_cert(challenge_hex: str) -> str:
    """
    Compute the 48-char cert token for the given challenge hex string.
    Uses Unicorn ARM64 emulation of the actual nmsscr.dec binary code.
    """
    emu = NMSSCertEmulator(verbose=False)
    emu.setup()
    result = emu.compute_cert(challenge_hex)
    return result if result else ""


def main():
    print("NMSS Cert Value Emulator - Full tokenProc (sub_20aad4) + JIT encoder")
    print("=" * 70)
    print(f"Binary: {BINARY_PATH}")
    print(f"JIT:    {JIT_PATH}")
    print(f"Session key: {SESSION_KEY.hex()}")
    jit_exists = os.path.exists(JIT_PATH)
    print(f"JIT module: {'FOUND' if jit_exists else 'NOT FOUND (will use nmsscr-only mode)'}")
    print()

    # First verify MD5 hash computation still works standalone
    print("Step 1: Verify MD5 (sanity check)...")
    for ch in ["0000000000000000", "FFFFFFFFFFFFFFFF"]:
        expected = hashlib.md5(ch.encode()).hexdigest().upper()
        print(f"  MD5({ch}) = {expected} (Python reference)")
    print()

    print("Step 2: Compute full cert tokens via emulation...")
    print()

    # Check if a specific challenge was given on the command line
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        # Run specific challenge(s)
        vectors = [(a, None) for a in args]
    else:
        vectors = TEST_VECTORS

    passed = 0
    total = len(vectors)
    for challenge, expected_token in vectors:
        emu = NMSSCertEmulator(verbose=("--verbose" in sys.argv or "-v" in sys.argv))
        emu.setup()
        t0 = time.time()
        result = emu.compute_cert(challenge)
        elapsed = time.time() - t0
        if result:
            if expected_token:
                match = result == expected_token
                status = "PASS" if match else "FAIL"
            else:
                status = "OK"
                match = True
            print(f"  {challenge} -> {result} [{status}] ({elapsed:.1f}s, {emu._insn_count} insns)")
            if expected_token and not match:
                print(f"    Expected: {expected_token}")
            if match:
                passed += 1
        else:
            print(f"  {challenge} -> None [FAIL] ({elapsed:.1f}s, {emu._insn_count} insns)")
            if expected_token:
                print(f"    Expected: {expected_token}")

    print(f"\n{passed}/{total} cert tokens computed")
    return passed


if __name__ == "__main__":
    main()
