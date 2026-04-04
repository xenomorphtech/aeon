#include <stdint.h>

static int rec_mix(int n) {
    if (n <= 1) {
        return n + 3;
    }
    return rec_mix(n - 1) ^ (rec_mix(n - 2) + (n * 5));
}

static int adjust(int value) {
    if ((value & 1) == 0) {
        return value + 11;
    }
    return value - 7;
}

int main(void) {
    int left = rec_mix(5);
    int right = rec_mix(3);
    return adjust(left) + right;
}
