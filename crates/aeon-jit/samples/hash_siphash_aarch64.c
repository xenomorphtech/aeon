/*
 * hash_siphash_aarch64.c — SipHash-2-4 (64-bit output).
 * Exercises: 64-bit rotations, XOR, add, byte loads, shift patterns.
 * Self-contained, result via main return value.
 */
#include <stdint.h>
#include <stddef.h>

static uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void sipround(uint64_t *v0, uint64_t *v1, uint64_t *v2, uint64_t *v3) {
    *v0 += *v1; *v1 = rotl64(*v1, 13); *v1 ^= *v0; *v0 = rotl64(*v0, 32);
    *v2 += *v3; *v3 = rotl64(*v3, 16); *v3 ^= *v2;
    *v0 += *v3; *v3 = rotl64(*v3, 21); *v3 ^= *v0;
    *v2 += *v1; *v1 = rotl64(*v1, 17); *v1 ^= *v2; *v2 = rotl64(*v2, 32);
}

static uint64_t siphash_2_4(const uint8_t *msg, size_t len,
                             uint64_t k0, uint64_t k1) {
    uint64_t v0 = k0 ^ 0x736F6D6570736575ULL;
    uint64_t v1 = k1 ^ 0x646F72616E646F6DULL;
    uint64_t v2 = k0 ^ 0x6C7967656E657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    /* Process full 8-byte blocks */
    size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; i++) {
        uint64_t m = 0;
        for (int j = 0; j < 8; j++) {
            m |= (uint64_t)msg[i * 8 + j] << (j * 8);
        }
        v3 ^= m;
        sipround(&v0, &v1, &v2, &v3);
        sipround(&v0, &v1, &v2, &v3);
        v0 ^= m;
    }

    /* Process remaining bytes + length tag */
    uint64_t m = (uint64_t)(len & 0xFF) << 56;
    const uint8_t *tail = msg + blocks * 8;
    size_t rem = len & 7;
    for (size_t i = 0; i < rem; i++) {
        m |= (uint64_t)tail[i] << (i * 8);
    }

    v3 ^= m;
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    v0 ^= m;

    /* Finalization */
    v2 ^= 0xFF;
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

int main(void) {
    static const uint8_t msg1[] = "aeon-jit roundtrip test";
    static const uint8_t msg2[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};

    uint64_t h1 = siphash_2_4(msg1, sizeof(msg1) - 1,
                               0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL);
    uint64_t h2 = siphash_2_4(msg2, sizeof(msg2),
                               0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL);

    uint32_t result = (uint32_t)(h1 ^ (h1 >> 32)) ^ (uint32_t)(h2 ^ (h2 >> 32));
    return (int)(result & 0x7FFFFFFFU);
}
