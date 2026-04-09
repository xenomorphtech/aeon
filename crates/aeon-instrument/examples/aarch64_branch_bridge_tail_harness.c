#include <stdio.h>
#include <signal.h>
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

extern void *aeon_dyn_runtime_create(uint64_t source_base, size_t source_size);
extern void aeon_dyn_runtime_destroy(void *handle);
extern void aeon_dyn_runtime_set_code_range(void *handle, uint64_t start, uint64_t end);
extern uint64_t aeon_dyn_runtime_branch_bridge(JitContext *ctx, uint64_t target);
extern size_t aeon_dyn_runtime_bridge_scratch_size(void);
extern uint64_t aeon_dyn_branch_bridge_stage;
extern uint64_t aeon_dyn_branch_bridge_last_target;
extern uint64_t aeon_dyn_branch_bridge_saved_x30;
extern uint64_t aeon_dyn_branch_bridge_tail_mode;

static uint64_t g_seen_a = 0;
static uint64_t g_seen_b = 0;
static uint64_t g_cont_x0 = 0;
static uint64_t g_seen_x28 = 0;
static unsigned char g_sigstack[SIGSTKSZ];

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
    g_seen_x28 = current_x28();
    return a + b + 7;
}

__attribute__((noreturn))
void continuation_done(void) {
    fprintf(stderr,
            "continuation seen_a=0x%llx seen_b=0x%llx cont_x0=0x%llx\n",
            (unsigned long long)g_seen_a,
            (unsigned long long)g_seen_b,
            (unsigned long long)g_cont_x0);
    if (g_seen_a != 0x11 || g_seen_b != 0x22) {
        fprintf(stderr, "tail bridge target args wrong\n");
        exit(10);
    }
    if (g_cont_x0 != 0x3a) {
        fprintf(stderr, "tail bridge return value wrong\n");
        exit(11);
    }
    if (g_seen_x28 != 0x123456789abcdef0ULL) {
        fprintf(stderr, "tail bridge target x28 wrong\n");
        exit(12);
    }
    puts("OK");
    exit(0);
}

static void segv_handler(int sig, siginfo_t *info, void *uctx) {
    (void)uctx;
    char buf[512];
    int n = snprintf(
        buf,
        sizeof(buf),
        "SIGSEGV addr=%p stage=%llu last_target=0x%llx saved_x30=0x%llx tail=%llu seen_a=0x%llx seen_b=0x%llx cont_x0=0x%llx\n",
        info ? info->si_addr : NULL,
        (unsigned long long)aeon_dyn_branch_bridge_stage,
        (unsigned long long)aeon_dyn_branch_bridge_last_target,
        (unsigned long long)aeon_dyn_branch_bridge_saved_x30,
        (unsigned long long)aeon_dyn_branch_bridge_tail_mode,
        (unsigned long long)g_seen_a,
        (unsigned long long)g_seen_b,
        (unsigned long long)g_cont_x0);
    if (n > 0) {
        write(2, buf, (size_t)n);
    }
    _Exit(128 + sig);
}

void continuation_entry(void);
__asm__(
    ".text\n"
    ".align 2\n"
    ".global continuation_entry\n"
    "continuation_entry:\n"
    "  adrp x9, g_cont_x0\n"
    "  add  x9, x9, :lo12:g_cont_x0\n"
    "  str  x0, [x9]\n"
    "  b    continuation_done\n"
);

int main(void) {
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
    ctx->x[30] = (uint64_t)(uintptr_t)&continuation_entry;
    ctx->sp = current_sp();
    ctx->tpidr_el0 = current_tp();

    uint64_t cont = (uint64_t)(uintptr_t)&continuation_entry;
    uint64_t base = cont & ~0xfffULL;
    void *handle = aeon_dyn_runtime_create(base, 0x1000);
    if (handle == NULL) {
        fprintf(stderr, "create failed\n");
        return 1;
    }
    aeon_dyn_runtime_set_code_range(handle, base, base + 0x1000);

    fprintf(stderr, "before tail bridge\n");
    uint64_t next = aeon_dyn_runtime_branch_bridge(ctx, (uint64_t)(uintptr_t)&bridge_target);
    fprintf(stderr, "unexpected bridge return next=0x%llx\n", (unsigned long long)next);

    aeon_dyn_runtime_destroy(handle);
    free(slab);
    return 2;
}
