/*
 * deep_stack_aarch64.c — exercises deep call chains, many callee-saved
 * registers (x19-x28), large stack frames, and multiple function parameters.
 * Forces the compiler to spill callee-saved regs via STP/LDP with pre/post
 * index writeback.  Self-contained, result via main return value.
 */
#include <stdint.h>

static int64_t heavy_leaf(int64_t a, int64_t b, int64_t c,
                          int64_t d, int64_t e, int64_t f) {
    return (a * b - c) + (d ^ e) + f;
}

static int64_t mid_callee(int64_t x, int64_t y) {
    /* Use enough locals to force callee-saved register spills */
    int64_t a = x + 1;
    int64_t b = y + 2;
    int64_t c = a * b;
    int64_t d = heavy_leaf(a, b, c, x, y, 7);
    int64_t e = heavy_leaf(c, d, a, b, x, 13);
    return d + e + c;
}

static int64_t deep_chain(int64_t n, int64_t acc) {
    if (n <= 0) {
        return acc;
    }
    /* Preserve many values across the recursive call to force
       callee-saved register usage (x19-x28) */
    int64_t v1 = n * 3 + 1;
    int64_t v2 = acc ^ (n << 2);
    int64_t v3 = v1 + v2;
    int64_t v4 = mid_callee(v1, v2);

    int64_t sub = deep_chain(n - 1, acc + v4);

    /* Reference v1, v2, v3 after the call — they must survive */
    return sub + v1 + v2 + v3;
}

static int64_t wide_params(int64_t a, int64_t b, int64_t c,
                           int64_t d, int64_t e, int64_t f,
                           int64_t g, int64_t h) {
    /* 8 register-passed parameters, exercising x0-x7 */
    return (a + b) * (c - d) + (e ^ f) - (g & h);
}

int main(void) {
    int64_t r1 = deep_chain(5, 100);
    int64_t r2 = wide_params(1, 2, 3, 4, 5, 6, 7, 8);
    int64_t r3 = mid_callee(r1, r2);

    int64_t result = r1 + r2 + r3;
    return (int)((uint64_t)result & 0x7FFFFFFFU);
}
