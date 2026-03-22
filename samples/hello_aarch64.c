#include <stddef.h>
#include <stdint.h>

static uint32_t checksum(const uint8_t *data, size_t len) {
    uint32_t acc = 0x1234;
    for (size_t i = 0; i < len; ++i) {
        acc = (acc << 3) ^ (acc >> 1) ^ data[i];
    }
    return acc;
}

static const char *select_message(uint32_t value) {
    if (value == 0x1234) {
        return "config.json";
    }
    if ((value & 1U) != 0) {
        return "plugin enabled";
    }
    return "plugin disabled";
}

int main(void) {
    static const uint8_t payload[] = {1, 2, 3, 4, 5, 6};
    uint32_t value = checksum(payload, sizeof(payload));
    const char *message = select_message(value);
    return (int)(value ^ (uint32_t)message[0]);
}
