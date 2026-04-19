/*
 * memory_patterns_aarch64.c — comprehensive memory access patterns:
 * various addressing modes (immediate, register, post-index, pre-index),
 * different sizes (8/16/32/64-bit), sign extensions, and pointer arithmetic.
 * Self-contained, result via main return value.
 */
#include <stdint.h>

static int test_byte_access(void) {
    /* Test LDRB, STRB, LDRSB for sign extension */
    uint8_t buffer[8] = {0xFF, 0x7F, 0x00, 0x01, 0x80, 0x42, 0x10, 0x20};
    int result = 0;

    /* Load unsigned byte */
    result += buffer[0];  /* 0xFF = 255 */
    result += buffer[2];  /* 0x00 = 0 */

    /* Sign-extended byte load simulation */
    int8_t sb = (int8_t)buffer[0];  /* 0xFF = -1 */
    result += (sb > 0) ? 100 : 50;

    return result;
}

static int test_halfword_access(void) {
    /* Test LDRH, STRH, LDRSH for 16-bit access */
    uint16_t data[4] = {0xFFFF, 0x7FFF, 0x0000, 0x8000};
    int result = 0;

    result += data[0];  /* 0xFFFF = 65535 */
    result += data[1];  /* 0x7FFF = 32767 */

    /* Sign-extended halfword */
    int16_t sh = (int16_t)data[3];  /* 0x8000 = -32768 */
    result += (sh < 0) ? 100 : 50;

    return result;
}

static int test_word_and_doubleword(void) {
    /* Test LDR/STR with 32-bit and 64-bit */
    uint32_t words[2] = {0xDEADBEEF, 0xCAFEBABE};
    uint64_t qword = 0x0123456789ABCDEF;

    int result = 0;
    result += (words[0] >> 24) & 0xFF;  /* 0xDE = 222 */
    result += (words[1] >> 24) & 0xFF;  /* 0xCA = 202 */
    result += (uint32_t)(qword >> 32) & 0xFF;  /* 0x01 = 1 */

    return result;
}

static int test_array_indexing(void) {
    /* Test register-based indexing and address arithmetic */
    int arr[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int result = 0;

    for (int i = 0; i < 10; i++) {
        result += arr[i];
    }

    return result;
}

static int test_struct_access(void) {
    /* Test offset-based field access */
    struct Point {
        int x;
        int y;
        int z;
    };

    struct Point points[3] = {
        {10, 20, 30},
        {40, 50, 60},
        {70, 80, 90}
    };

    int result = 0;
    for (int i = 0; i < 3; i++) {
        result += points[i].x + points[i].y + points[i].z;
    }

    return result;
}

static int test_pointer_arithmetic(void) {
    /* Test pointer offsets and indirect addressing */
    int values[5] = {100, 200, 300, 400, 500};
    int *p = values;
    int result = 0;

    /* Direct access */
    result += *p;  /* 100 */
    p++;
    result += *p;  /* 200 */
    p += 2;
    result += *p;  /* 400 */

    return result;
}

static int test_multi_level_arrays(void) {
    /* Test 2D array access patterns */
    int matrix[4][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12},
        {13, 14, 15, 16}
    };

    int result = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            result += matrix[i][j];
        }
    }

    return result;
}

static int test_mixed_sizes(void) {
    /* Test accessing mixed-size data in same buffer */
    union MixedData {
        uint8_t bytes[8];
        uint16_t words[4];
        uint32_t dwords[2];
        uint64_t qword;
    };

    union MixedData data;
    data.qword = 0x0102030405060708ULL;

    int result = 0;
    result += data.bytes[0] + data.bytes[1] + data.bytes[7];  /* 1 + 2 + 8 = 11 */
    result += (data.words[1] >> 8) & 0xFF;  /* 5 */
    result += (data.dwords[0]) & 0xFF;  /* 8 */

    return result;
}

int main(void) {
    int r1 = test_byte_access();       /* 255 + 0 + 50 = 305 */
    int r2 = test_halfword_access();   /* 65535 + 32767 + 100 = 98402 */
    int r3 = test_word_and_doubleword();  /* 222 + 202 + 1 = 425 */
    int r4 = test_array_indexing();    /* 1+2+...+10 = 55 */
    int r5 = test_struct_access();     /* (10+20+30) + (40+50+60) + (70+80+90) = 450 */
    int r6 = test_pointer_arithmetic();  /* 100 + 200 + 400 = 700 */
    int r7 = test_multi_level_arrays();  /* sum of 1..16 = 136 */
    int r8 = test_mixed_sizes();       /* 11 + 5 + 8 = 24 */

    int total = r1 + r2 + r3 + r4 + r5 + r6 + r7 + r8;
    return total;
}
