/*
 * bitops_aarch64.c — exercises bitwise operations: AND, OR, XOR, NOT,
 * shifts (LSL, LSR, ASR), rotate-right, CLZ-like patterns, and
 * bit-field manipulation.  Self-contained, result via main return value.
 */
#include <stdint.h>

static uint32_t rotate_right(uint32_t value, int n) {
    n &= 31;
    return (value >> n) | (value << (32 - n));
}

static uint32_t mix_bits(uint32_t a, uint32_t b) {
    uint32_t x = (a & 0xFF00FF00U) | (b & 0x00FF00FFU);
    uint32_t y = (a | b) ^ (a & b);       /* same as a ^ b */
    return x + y;
}

static uint32_t leading_zero_approx(uint32_t v) {
    /* manual CLZ-like cascade — generates shifts and conditionals */
    uint32_t count = 0;
    if (!(v & 0xFFFF0000U)) { count += 16; v <<= 16; }
    if (!(v & 0xFF000000U)) { count += 8;  v <<= 8;  }
    if (!(v & 0xF0000000U)) { count += 4;  v <<= 4;  }
    if (!(v & 0xC0000000U)) { count += 2;  v <<= 2;  }
    if (!(v & 0x80000000U)) { count += 1; }
    return count;
}

static uint32_t bitfield_insert(uint32_t dst, uint32_t src, int pos, int width) {
    uint32_t mask = ((1U << width) - 1U) << pos;
    return (dst & ~mask) | ((src << pos) & mask);
}

static uint32_t arithmetic_shift_mix(int32_t val) {
    /* ASR preserves sign — mixing signed and unsigned shifts */
    int32_t a = val >> 3;      /* ASR */
    uint32_t b = (uint32_t)val >> 5;  /* LSR */
    return (uint32_t)a ^ b;
}

int main(void) {
    uint32_t a = 0xDEADBEEFU;
    uint32_t b = 0xCAFEBABEU;

    uint32_t r1 = rotate_right(a, 7);
    uint32_t r2 = rotate_right(b, 19);

    uint32_t m = mix_bits(r1, r2);

    uint32_t lz1 = leading_zero_approx(0x00003F00U);
    uint32_t lz2 = leading_zero_approx(0x80000000U);

    uint32_t bf = bitfield_insert(m, 0x1AU, 8, 5);

    uint32_t as_mix = arithmetic_shift_mix((int32_t)bf);

    uint32_t result = (r1 ^ r2) + m + lz1 + lz2 + bf + as_mix;
    result ^= ~result >> 16;
    return (int)(result & 0x7FFFFFFFU);
}
