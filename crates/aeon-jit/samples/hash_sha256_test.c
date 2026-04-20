/*
 * Standalone test harness for SHA-256 tracing
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t big_sigma0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static uint32_t big_sigma1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static uint32_t small_sigma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static uint32_t small_sigma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

static const uint32_t K[64] = {
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
    0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
    0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
    0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
    0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
    0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
    0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
    0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
    0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
    0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
    0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
    0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
    0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
    0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
    0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U,
};

static void sha256_block(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];

    /* Parse message block into 16 big-endian words */
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4 + 0] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] << 8)
             | ((uint32_t)block[i * 4 + 3]);
    }

    /* Extend to 64 words */
    for (int i = 16; i < 64; i++) {
        W[i] = small_sigma1(W[i - 2]) + W[i - 7]
             + small_sigma0(W[i - 15]) + W[i - 16];
    }

    /* Initialize working variables */
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    /* 64 rounds */
    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + big_sigma1(e) + ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = big_sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }

    /* Commit */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
        0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
    };

    size_t msg_len = len;
    uint8_t block[64];

    /* Process complete blocks */
    while (len >= 64) {
        sha256_block(state, msg);
        msg += 64;
        len -= 64;
    }

    /* Padding */
    memcpy(block, msg, len);
    block[len++] = 0x80;
    if (len > 56) {
        memset(block + len, 0, 64 - len);
        sha256_block(state, block);
        len = 0;
    }
    memset(block + len, 0, 56 - len);

    /* Append length */
    uint64_t bit_len = msg_len * 8;
    block[56] = (bit_len >> 56) & 0xFF;
    block[57] = (bit_len >> 48) & 0xFF;
    block[58] = (bit_len >> 40) & 0xFF;
    block[59] = (bit_len >> 32) & 0xFF;
    block[60] = (bit_len >> 24) & 0xFF;
    block[61] = (bit_len >> 16) & 0xFF;
    block[62] = (bit_len >> 8) & 0xFF;
    block[63] = bit_len & 0xFF;

    sha256_block(state, block);

    /* Output */
    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = (state[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        out[i * 4 + 3] = state[i] & 0xFF;
    }
}

int main(int argc, char *argv[]) {
    /* Test input: "hello world" */
    const uint8_t input[] = "hello world";
    uint8_t output[32];

    sha256(input, sizeof(input) - 1, output);

    /* Return first 4 bytes as exit code for verification */
    return (output[0] << 24) | (output[1] << 16) | (output[2] << 8) | output[3];
}
