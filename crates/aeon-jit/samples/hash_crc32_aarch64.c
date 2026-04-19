/*
 * hash_crc32_aarch64.c — table-less CRC32 (ISO 3309 polynomial 0xEDB88320).
 * Exercises: loops, XOR, shifts (LSR), conditional branches, byte array access.
 * Self-contained, result via main return value.
 */
#include <stdint.h>
#include <stddef.h>

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            if (crc & 1U) {
                crc = (crc >> 1) ^ 0xEDB88320U;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static uint32_t crc32_combine(uint32_t a, uint32_t b) {
    /* Mix two CRC values — exercises bitwise ops */
    return a ^ ((b << 5) | (b >> 27)) ^ 0xFFFFFFFFU;
}

int main(void) {
    static const uint8_t msg1[] = "Hello, CRC32!";
    static const uint8_t msg2[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    uint32_t c1 = crc32_update(0, msg1, sizeof(msg1) - 1);
    uint32_t c2 = crc32_update(0, msg2, sizeof(msg2));
    uint32_t c3 = crc32_update(c1, msg2, sizeof(msg2));

    uint32_t result = crc32_combine(c1, c2) ^ c3;
    return (int)(result & 0x7FFFFFFFU);
}
