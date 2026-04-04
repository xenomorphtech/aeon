#include <stddef.h>
#include <stdint.h>

static uint32_t mix_step(uint32_t acc, uint8_t byte, uint32_t bias) {
    uint32_t value = acc ^ (uint32_t)byte;
    if ((value & 1U) != 0) {
        return (value << 2) - bias;
    }
    return (value >> 1) + (bias * 3U);
}

static uint32_t fold_local(uint32_t seed) {
    uint8_t local[5] = {9, 4, 1, 7, 3};
    uint32_t acc = seed;
    for (size_t i = 0; i < sizeof(local); ++i) {
        acc = mix_step(acc, local[i], (uint32_t)i + 5U);
    }
    return acc;
}

int main(void) {
    uint32_t left = fold_local(0x2345U);
    uint32_t right = fold_local(0x1357U);
    return (int)((left ^ (right << 1)) + (left & 0xffU));
}
