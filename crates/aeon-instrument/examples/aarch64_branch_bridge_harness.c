#include <signal.h>
#include <stdio.h>
#include <stdint.h>
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

extern uint64_t aeon_dyn_runtime_branch_bridge(JitContext *ctx, uint64_t target);
extern size_t aeon_dyn_runtime_bridge_scratch_size(void);
extern uint64_t aeon_dyn_branch_bridge_stage;
extern uint64_t aeon_dyn_branch_bridge_last_target;

static uint64_t g_seen_a = 0;
static uint64_t g_seen_b = 0;
static uint64_t g_seen_tp = 0;
static uint64_t g_seen_x28 = 0;

static inline uint64_t current_sp(void) {
    uint64_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    return sp;
}

static inline uint64_t current_tp(void) {
    uint64_t tp;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    return tp;
}

static inline uint64_t current_x28(void) {
    uint64_t v;
    __asm__ volatile("mov %0, x28" : "=r"(v));
    return v;
}

__attribute__((noinline))
static uint64_t bridge_target(uint64_t a, uint64_t b) {
    g_seen_a = a;
    g_seen_b = b;
    g_seen_tp = current_tp();
    g_seen_x28 = current_x28();
    return a + b + 7;
}

static unsigned char g_sigstack[SIGSTKSZ];

static void segv_handler(int sig, siginfo_t *info, void *uctx) {
    (void)info;
    (void)uctx;
    char buf[256];
    int n = snprintf(buf,
                     sizeof(buf),
                     "SIGSEGV stage=%llu last_target=0x%llx seen_a=0x%llx seen_b=0x%llx seen_tp=0x%llx\n",
                     (unsigned long long)aeon_dyn_branch_bridge_stage,
                     (unsigned long long)aeon_dyn_branch_bridge_last_target,
                     (unsigned long long)g_seen_a,
                     (unsigned long long)g_seen_b,
                     (unsigned long long)g_seen_tp);
    if (n > 0) {
        write(2, buf, (size_t)n);
    }
    _Exit(128 + sig);
}

int main(void) {
    fprintf(stderr, "harness start\n");
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = g_sigstack;
    ss.ss_size = sizeof(g_sigstack);
    if (sigaltstack(&ss, NULL) != 0) {
        perror("sigaltstack");
        return 10;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        perror("sigaction");
        return 11;
    }
    fprintf(stderr, "signal installed\n");
    size_t scratch_size = aeon_dyn_runtime_bridge_scratch_size();
    unsigned char *slab = calloc(1, scratch_size + sizeof(JitContext));
    if (slab == NULL) {
        perror("calloc");
        return 12;
    }
    JitContext *ctx = (JitContext *)(slab + scratch_size);
    ctx->x[0] = 0x11;
    ctx->x[1] = 0x22;
    ctx->x[28] = 0x123456789abcdef0ULL;
    ctx->x[30] = 0xfeedfacecafebeefULL;
    ctx->sp = current_sp();
    ctx->tpidr_el0 = current_tp();
    fprintf(stderr, "before bridge\n");

    uint64_t next = aeon_dyn_runtime_branch_bridge(ctx, (uint64_t)(uintptr_t)&bridge_target);
    fprintf(stderr, "after bridge call\n");

    fprintf(stderr,
            "after branch bridge next=0x%llx ret_x0=0x%llx seen_a=0x%llx seen_b=0x%llx seen_tp=0x%llx\n",
            (unsigned long long)next,
            (unsigned long long)ctx->x[0],
            (unsigned long long)g_seen_a,
            (unsigned long long)g_seen_b,
            (unsigned long long)g_seen_tp);

    if (next != 0xfeedfacecafebeefULL) {
        fprintf(stderr, "wrong next target\n");
        return 1;
    }
    if (ctx->x[30] != 0xfeedfacecafebeefULL) {
        fprintf(stderr, "x30 not preserved in context\n");
        return 2;
    }
    if (ctx->x[0] != 0x3a) {
        fprintf(stderr, "wrong return value in x0\n");
        return 3;
    }
    if (g_seen_a != 0x11 || g_seen_b != 0x22) {
        fprintf(stderr, "target did not receive guest args\n");
        return 4;
    }
    if (g_seen_tp != ctx->tpidr_el0) {
        fprintf(stderr, "tpidr_el0 was not materialized\n");
        return 5;
    }
    if (g_seen_x28 != 0x123456789abcdef0ULL) {
        fprintf(stderr, "x28 was not materialized into the bridge target\n");
        return 6;
    }
    if (ctx->x[28] != 0x123456789abcdef0ULL) {
        fprintf(stderr, "x28 not preserved in context\n");
        return 7;
    }

    puts("OK");
    free(slab);
    return 0;
}
