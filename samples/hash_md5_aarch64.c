/*
 * hash_md5_aarch64.c — MD5 from scratch (RFC 1321).
 * Exercises: rotations, XOR/AND/OR/NOT, array indexing, 32-bit add.
 * Self-contained, result via main return value.
 */
#include <stdint.h>
#include <stddef.h>

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

/* Pre-computed T[i] = floor(2^32 * abs(sin(i+1))) */
static const uint32_t T[64] = {
    0xD76AA478U, 0xE8C7B756U, 0x242070DBU, 0xC1BDCEEEU,
    0xF57C0FAFU, 0x4787C62AU, 0xA8304613U, 0xFD469501U,
    0x698098D8U, 0x8B44F7AFU, 0xFFFF5BB1U, 0x895CD7BEU,
    0x6B901122U, 0xFD987193U, 0xA679438EU, 0x49B40821U,
    0xF61E2562U, 0xC040B340U, 0x265E5A51U, 0xE9B6C7AAU,
    0xD62F105DU, 0x02441453U, 0xD8A1E681U, 0xE7D3FBC8U,
    0x21E1CDE6U, 0xC33707D6U, 0xF4D50D87U, 0x455A14EDU,
    0xA9E3E905U, 0xFCEFA3F8U, 0x676F02D9U, 0x8D2A4C8AU,
    0xFFFA3942U, 0x8771F681U, 0x6D9D6122U, 0xFDE5380CU,
    0xA4BEEA44U, 0x4BDECFA9U, 0xF6BB4B60U, 0xBEBFBC70U,
    0x289B7EC6U, 0xEAA127FAU, 0xD4EF3085U, 0x04881D05U,
    0xD9D4D039U, 0xE6DB99E5U, 0x1FA27CF8U, 0xC4AC5665U,
    0xF4292244U, 0x432AFF97U, 0xAB9423A7U, 0xFC93A039U,
    0x655B59C3U, 0x8F0CCC92U, 0xFFEFF47DU, 0x85845DD1U,
    0x6FA87E4FU, 0xFE2CE6E0U, 0xA3014314U, 0x4E0811A1U,
    0xF7537E82U, 0xBD3AF235U, 0x2AD7D2BBU, 0xEB86D391U,
};

static const int S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static void md5_block(uint32_t state[4], const uint8_t block[64]) {
    uint32_t M[16];
    /* Parse as 16 little-endian 32-bit words */
    for (int i = 0; i < 16; i++) {
        M[i] = ((uint32_t)block[i * 4 + 0])
             | ((uint32_t)block[i * 4 + 1] << 8)
             | ((uint32_t)block[i * 4 + 2] << 16)
             | ((uint32_t)block[i * 4 + 3] << 24);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    for (int i = 0; i < 64; i++) {
        uint32_t f_val;
        int g;
        if (i < 16) {
            f_val = md5_f(b, c, d);
            g = i;
        } else if (i < 32) {
            f_val = md5_g(b, c, d);
            g = (5 * i + 1) & 15;
        } else if (i < 48) {
            f_val = md5_h(b, c, d);
            g = (3 * i + 5) & 15;
        } else {
            f_val = md5_i(b, c, d);
            g = (7 * i) & 15;
        }

        uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f_val + T[i] + M[g], S[i]);
        a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5(const uint8_t *msg, size_t len, uint32_t digest[4]) {
    digest[0] = 0x67452301U;
    digest[1] = 0xEFCDAB89U;
    digest[2] = 0x98BADCFEU;
    digest[3] = 0x10325476U;

    size_t i = 0;
    while (i + 64 <= len) {
        md5_block(digest, msg + i);
        i += 64;
    }

    /* Pad */
    uint8_t pad[128];
    size_t rem = len - i;
    for (size_t j = 0; j < rem; j++) pad[j] = msg[i + j];
    pad[rem] = 0x80;
    for (size_t j = rem + 1; j < 128; j++) pad[j] = 0;

    size_t pad_len = (rem < 56) ? 64 : 128;
    uint64_t bit_len = (uint64_t)len * 8;
    /* Little-endian length */
    pad[pad_len - 8] = (uint8_t)(bit_len);
    pad[pad_len - 7] = (uint8_t)(bit_len >> 8);
    pad[pad_len - 6] = (uint8_t)(bit_len >> 16);
    pad[pad_len - 5] = (uint8_t)(bit_len >> 24);
    pad[pad_len - 4] = (uint8_t)(bit_len >> 32);
    pad[pad_len - 3] = (uint8_t)(bit_len >> 40);
    pad[pad_len - 2] = (uint8_t)(bit_len >> 48);
    pad[pad_len - 1] = (uint8_t)(bit_len >> 56);

    md5_block(digest, pad);
    if (pad_len == 128) {
        md5_block(digest, pad + 64);
    }
}

int main(void) {
    static const uint8_t msg[] = "aeon-jit roundtrip test";
    uint32_t digest[4];
    md5(msg, sizeof(msg) - 1, digest);

    uint32_t result = digest[0] ^ digest[1] ^ digest[2] ^ digest[3];
    return (int)(result & 0x7FFFFFFFU);
}
