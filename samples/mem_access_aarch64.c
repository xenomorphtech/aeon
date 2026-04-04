/*
 * mem_access_aarch64.c — exercises diverse memory addressing modes:
 * byte/half/word/doubleword loads/stores, sign-extending loads (LDRSB,
 * LDRSH, LDRSW), stack-relative addressing, and patterns that trigger
 * pre/post-index writeback (STP/LDP on prologue/epilogue paths).
 * Self-contained, result via main return value.
 */
#include <stdint.h>
#include <stddef.h>

static int64_t sign_extend_bytes(const int8_t *buf, size_t len) {
    /* LDRSB — sign-extending byte loads */
    int64_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc += buf[i];  /* sign-extended to 64-bit */
    }
    return acc;
}

static int64_t sign_extend_halves(const int16_t *buf, size_t len) {
    /* LDRSH — sign-extending halfword loads */
    int64_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc += buf[i];
    }
    return acc;
}

static int64_t sign_extend_words(const int32_t *buf, size_t len) {
    /* LDRSW — sign-extending word loads */
    int64_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc += buf[i];
    }
    return acc;
}

static void fill_buffer_u8(uint8_t *dst, size_t len, uint8_t seed) {
    /* STRB — byte stores with incrementing pointer (post-index pattern) */
    for (size_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)(seed + (uint8_t)i * 3);
    }
}

static void fill_buffer_u16(uint16_t *dst, size_t len, uint16_t seed) {
    /* STRH — halfword stores */
    for (size_t i = 0; i < len; i++) {
        dst[i] = (uint16_t)(seed + (uint16_t)i * 7);
    }
}

static uint64_t read_mixed_sizes(const void *base) {
    /* Mix of byte, half, word, doubleword loads from same buffer */
    const uint8_t *p = (const uint8_t *)base;
    uint8_t  b = p[0];
    uint16_t h = *(const uint16_t *)(p + 2);
    uint32_t w = *(const uint32_t *)(p + 4);
    uint64_t d = *(const uint64_t *)(p + 8);
    return (uint64_t)b + (uint64_t)h + (uint64_t)w + d;
}

static int64_t callee_saved_spill(int64_t a, int64_t b, int64_t c,
                                  int64_t d, int64_t e) {
    /* Force many callee-saved regs to be live across the inner call,
       triggering STP/LDP pre/post-index in prologue/epilogue */
    int64_t v1 = a + b;
    int64_t v2 = c - d;
    int64_t v3 = v1 * v2;
    int64_t v4 = e + v3;
    int64_t v5 = v1 ^ v4;

    /* Call through sign_extend_words to force a spill point */
    int32_t tmp_arr[3] = {(int32_t)v1, (int32_t)v2, (int32_t)v3};
    int64_t inner = sign_extend_words(tmp_arr, 3);

    /* All of v1-v5 are live after the call */
    return v1 + v2 + v3 + v4 + v5 + inner;
}

int main(void) {
    int8_t sbytes[] = {-10, 20, -30, 40, -50, 60, -70, 80};
    int64_t se_b = sign_extend_bytes(sbytes, 8);

    int16_t shalves[] = {-1000, 2000, -3000, 4000};
    int64_t se_h = sign_extend_halves(shalves, 4);

    int32_t swords[] = {-100000, 200000, -300000};
    int64_t se_w = sign_extend_words(swords, 3);

    uint8_t buf8[16];
    fill_buffer_u8(buf8, 16, 42);
    uint64_t sum8 = 0;
    for (int i = 0; i < 16; i++) sum8 += buf8[i];

    uint16_t buf16[8];
    fill_buffer_u16(buf16, 8, 100);
    uint64_t sum16 = 0;
    for (int i = 0; i < 8; i++) sum16 += buf16[i];

    /* Build a 16-byte buffer for mixed-size reads */
    uint8_t mixed[16];
    for (int i = 0; i < 16; i++) mixed[i] = (uint8_t)(i + 1);
    uint64_t mix_val = read_mixed_sizes(mixed);

    int64_t spill = callee_saved_spill(10, 20, 30, 40, 50);

    int64_t result = se_b + se_h + se_w + (int64_t)sum8 + (int64_t)sum16
                     + (int64_t)mix_val + spill;
    return (int)(((uint64_t)result) & 0x7FFFFFFFU);
}
