#include <signal.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t flags;
    unsigned char simd[32][16];
    uint64_t tpidr_el0;
} JitContext;

typedef struct {
    uint32_t stop_code;
    uint32_t _pad;
    uint64_t start_pc;
    uint64_t final_pc;
    uint64_t steps;
    uint64_t compiled_blocks;
    uint64_t info_pc;
} AeonDynRuntimeResult;

extern void *aeon_dyn_runtime_create(uint64_t source_base, size_t source_size);
extern void aeon_dyn_runtime_destroy(void *handle);
extern uint32_t aeon_dyn_runtime_run_out(void *handle, JitContext *ctx, AeonDynRuntimeResult *out);
extern uint64_t aeon_dyn_runtime_resume_trampoline(void *handle, JitContext *ctx, AeonDynRuntimeResult *out);

static sigjmp_buf g_env;
static volatile sig_atomic_t g_trap_active = 0;
static uint64_t g_cont_a = 0;
static uint64_t g_cont_b = 0;

static uint32_t enc_movz_x(unsigned rd, uint16_t imm16, unsigned shift) {
    unsigned hw = (shift / 16U) & 0x3U;
    return 0xD2800000U | ((hw & 0x3U) << 21) | ((uint32_t)imm16 << 5) | (rd & 0x1fU);
}

static uint32_t enc_movk_x(unsigned rd, uint16_t imm16, unsigned shift) {
    unsigned hw = (shift / 16U) & 0x3U;
    return 0xF2800000U | ((hw & 0x3U) << 21) | ((uint32_t)imm16 << 5) | (rd & 0x1fU);
}

static uint32_t enc_br(unsigned rn) {
    return 0xD61F0000U | ((rn & 0x1fU) << 5);
}

static void emit_u32(unsigned char *buf, size_t *off, uint32_t word) {
    memcpy(buf + *off, &word, sizeof(word));
    *off += sizeof(word);
}

static void emit_load_imm64(unsigned char *buf, size_t *off, unsigned rd, uint64_t value) {
    emit_u32(buf, off, enc_movz_x(rd, (uint16_t)(value & 0xffffU), 0));
    emit_u32(buf, off, enc_movk_x(rd, (uint16_t)((value >> 16) & 0xffffU), 16));
    emit_u32(buf, off, enc_movk_x(rd, (uint16_t)((value >> 32) & 0xffffU), 32));
    emit_u32(buf, off, enc_movk_x(rd, (uint16_t)((value >> 48) & 0xffffU), 48));
}

static inline uint64_t current_sp(void) {
    uint64_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    return sp;
}

static uint64_t continuation(uint64_t a, uint64_t b) {
    g_cont_a = a;
    g_cont_b = b;
    siglongjmp(g_env, 1);
}

static void trap_resume_handler(int sig, siginfo_t *info, void *uctx_void) {
    (void)sig;
    (void)info;
    if (!g_trap_active) {
        return;
    }
    write(2, "trap_resume_handler\n", 20);
    ucontext_t *uc = (ucontext_t *)uctx_void;
    uint64_t *regs = uc->uc_mcontext.regs;
    JitContext *ctx = (JitContext *)(uintptr_t)regs[27];
    AeonDynRuntimeResult *out = (AeonDynRuntimeResult *)(uintptr_t)regs[28];
    if (ctx == NULL || out == NULL) {
        return;
    }
    for (int i = 0; i < 19; i++) {
        regs[i] = ctx->x[i];
    }
    regs[30] = regs[26];
    uc->uc_mcontext.sp = ctx->sp;
    uc->uc_mcontext.pc = out->final_pc;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = trap_resume_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }

    unsigned char code[64];
    size_t off = 0;
    emit_u32(code, &off, enc_movz_x(0, 0x11, 0));
    emit_u32(code, &off, enc_movz_x(1, 0x22, 0));
    emit_load_imm64(code, &off, 16, (uint64_t)(uintptr_t)&continuation);
    emit_u32(code, &off, enc_br(16));

    void *handle = aeon_dyn_runtime_create((uint64_t)(uintptr_t)code, off);
    if (handle == NULL) {
        fprintf(stderr, "aeon_dyn_runtime_create failed\n");
        return 2;
    }

    JitContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pc = (uint64_t)(uintptr_t)code;
    ctx.sp = current_sp();

    AeonDynRuntimeResult out;
    memset(&out, 0, sizeof(out));

    fprintf(stderr, "before direct run_out\n");
    uint32_t direct_stop = aeon_dyn_runtime_run_out(handle, &ctx, &out);
    fprintf(stderr,
            "after direct run_out stop=%u final_pc=0x%llx x0=0x%llx x1=0x%llx\n",
            direct_stop,
            (unsigned long long)out.final_pc,
            (unsigned long long)ctx.x[0],
            (unsigned long long)ctx.x[1]);
    if (direct_stop != 2 || ctx.x[0] != 0x11 || ctx.x[1] != 0x22) {
        fprintf(stderr, "direct run_out sanity failed\n");
        aeon_dyn_runtime_destroy(handle);
        return 3;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.pc = (uint64_t)(uintptr_t)code;
    ctx.sp = current_sp();
    memset(&out, 0, sizeof(out));
    g_cont_a = 0;
    g_cont_b = 0;

    if (sigsetjmp(g_env, 1) == 0) {
        fprintf(stderr, "before trampoline\n");
        g_trap_active = 1;
        (void)aeon_dyn_runtime_resume_trampoline(handle, &ctx, &out);
        g_trap_active = 0;
        fprintf(stderr, "unexpected normal return from trampoline\n");
        aeon_dyn_runtime_destroy(handle);
        return 4;
    }

    g_trap_active = 0;
    fprintf(stderr,
            "after longjmp cont_a=0x%llx cont_b=0x%llx stop=%u final_pc=0x%llx\n",
            (unsigned long long)g_cont_a,
            (unsigned long long)g_cont_b,
            out.stop_code,
            (unsigned long long)out.final_pc);
    aeon_dyn_runtime_destroy(handle);

    if (g_cont_a != 0x11 || g_cont_b != 0x22 || out.stop_code != 2) {
        fprintf(stderr, "resume verification failed\n");
        return 5;
    }

    puts("OK");
    return 0;
}
