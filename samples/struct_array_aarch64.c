/*
 * struct_array_aarch64.c — exercises stack-allocated structs, field access
 * at various offsets, array indexing with byte/half/word granularity,
 * and pointer arithmetic patterns.  Self-contained, result via main return value.
 */
#include <stdint.h>
#include <stddef.h>

struct point {
    int32_t x;
    int32_t y;
    int32_t z;
};

struct record {
    uint8_t  tag;
    uint16_t id;
    uint32_t value;
    int32_t  delta;
};

static int32_t dot_product(struct point a, struct point b) {
    return a.x * b.x + a.y * b.y + a.z * b.z;
}

static struct point scale_point(struct point p, int32_t factor) {
    struct point result;
    result.x = p.x * factor;
    result.y = p.y * factor;
    result.z = p.z * factor;
    return result;
}

static uint32_t sum_array_u8(const uint8_t *arr, size_t len) {
    uint32_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc += arr[i];
    }
    return acc;
}

static int32_t sum_array_i16(const int16_t *arr, size_t len) {
    int32_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc += arr[i];
    }
    return acc;
}

static uint32_t process_records(const struct record *recs, size_t count) {
    uint32_t acc = 0;
    for (size_t i = 0; i < count; i++) {
        if (recs[i].tag == 1) {
            acc += recs[i].value;
        } else if (recs[i].tag == 2) {
            acc -= (uint32_t)recs[i].delta;
        } else {
            acc ^= recs[i].id;
        }
    }
    return acc;
}

int main(void) {
    struct point p1 = {3, -7, 12};
    struct point p2 = {-4, 5, 8};

    int32_t dp = dot_product(p1, p2);
    struct point scaled = scale_point(p1, 3);
    int32_t dp2 = dot_product(scaled, p2);

    uint8_t bytes[] = {10, 20, 30, 40, 50, 60, 70, 80};
    uint32_t byte_sum = sum_array_u8(bytes, sizeof(bytes));

    int16_t halves[] = {100, -200, 300, -400, 500};
    int32_t half_sum = sum_array_i16(halves, 5);

    struct record recs[4];
    recs[0] = (struct record){1, 100, 5000, 0};
    recs[1] = (struct record){2, 200, 0, 150};
    recs[2] = (struct record){3, 300, 0, 0};
    recs[3] = (struct record){1, 400, 8000, 0};

    uint32_t rec_val = process_records(recs, 4);

    int32_t result = dp + dp2 + (int32_t)byte_sum + half_sum + (int32_t)rec_val;
    result += scaled.x + scaled.y + scaled.z;
    return (int)(((uint32_t)result) & 0x7FFFFFFFU);
}
