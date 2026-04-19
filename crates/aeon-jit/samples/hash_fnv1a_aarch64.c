/*
 * hash_fnv1a_aarch64.c — FNV-1a hash (32-bit and 64-bit variants).
 * Exercises: loops, XOR, multiply, byte array access, shifts.
 * Self-contained, result via main return value.
 */
#include <stdint.h>
#include <stddef.h>

#define FNV1A_32_OFFSET 0x811C9DC5U
#define FNV1A_32_PRIME  0x01000193U
#define FNV1A_64_OFFSET 0xCBF29CE484222325ULL
#define FNV1A_64_PRIME  0x00000100000001B3ULL

static uint32_t fnv1a_32(const uint8_t *data, size_t len) {
    uint32_t hash = FNV1A_32_OFFSET;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= FNV1A_32_PRIME;
    }
    return hash;
}

static uint64_t fnv1a_64(const uint8_t *data, size_t len) {
    uint64_t hash = FNV1A_64_OFFSET;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= FNV1A_64_PRIME;
    }
    return hash;
}

static uint32_t fold_64_to_32(uint64_t h) {
    /* XOR-fold 64 bits down to 32 */
    return (uint32_t)(h ^ (h >> 32));
}

int main(void) {
    static const uint8_t msg1[] = "The quick brown fox";
    static const uint8_t msg2[] = {
        0x00, 0xFF, 0x55, 0xAA, 0x0F, 0xF0, 0x33, 0xCC,
        0x01, 0x80, 0x7F, 0xFE
    };
    static const uint8_t msg3[] = "";

    uint32_t h1 = fnv1a_32(msg1, sizeof(msg1) - 1);
    uint32_t h2 = fnv1a_32(msg2, sizeof(msg2));
    uint32_t h3 = fnv1a_32(msg3, 0);

    uint64_t h4 = fnv1a_64(msg1, sizeof(msg1) - 1);
    uint64_t h5 = fnv1a_64(msg2, sizeof(msg2));

    uint32_t result = h1 ^ h2 ^ h3 ^ fold_64_to_32(h4) ^ fold_64_to_32(h5);
    return (int)(result & 0x7FFFFFFFU);
}
