/*
 * conditionals_aarch64.c — comprehensive conditional branch coverage:
 * all 14 ARM64 flag conditions (eq, ne, cs, cc, mi, pl, vs, vc, hi, ls, ge, lt, gt, le),
 * nested if-else chains, switch-like patterns, and conditional arithmetic.
 * Self-contained, result via main return value.
 */
#include <stdint.h>

static int test_eq_ne(int a, int b) {
    /* Test EQ and NE conditions */
    int result = 0;
    if (a == b) {
        result += 100;
    }
    if (a != b) {
        result += 50;
    }
    return result;
}

static int test_mi_pl(int a) {
    /* Test MI (minus/negative) and PL (plus/positive) */
    int result = 0;
    if (a < 0) {  /* MI branch */
        result += 10;
    }
    if (a >= 0) {  /* PL branch */
        result += 20;
    }
    return result;
}

static int test_cs_cc(uint32_t a, uint32_t b) {
    /* Test CS (carry set/unsigned >=) and CC (carry clear/unsigned <) */
    int result = 0;
    if (a >= b) {  /* CS branch */
        result += 30;
    }
    if (a < b) {  /* CC branch */
        result += 15;
    }
    return result;
}

static int test_vs_vc(int a, int b) {
    /* Test VS (signed overflow) and VC (no overflow) */
    int result = 0;
    int32_t x = (int32_t)a;
    int32_t y = (int32_t)b;
    int32_t sum = x + y;

    /* Simple heuristic: test overflow in addition */
    if ((x > 0 && y > 0 && sum < 0) || (x < 0 && y < 0 && sum > 0)) {
        result += 200;  /* overflow detected */
    } else {
        result += 100;  /* no overflow */
    }
    return result;
}

static int test_hi_ls(uint32_t a, uint32_t b) {
    /* Test HI (unsigned >) and LS (unsigned <=) */
    int result = 0;
    if (a > b) {  /* HI branch */
        result += 40;
    }
    if (a <= b) {  /* LS branch */
        result += 20;
    }
    return result;
}

static int test_ge_lt_signed(int a, int b) {
    /* Test GE (signed >=) and LT (signed <) */
    int result = 0;
    if (a >= b) {  /* GE branch */
        result += 60;
    }
    if (a < b) {  /* LT branch */
        result += 30;
    }
    return result;
}

static int test_gt_le_signed(int a, int b) {
    /* Test GT (signed >) and LE (signed <=) */
    int result = 0;
    if (a > b) {  /* GT branch */
        result += 70;
    }
    if (a <= b) {  /* LE branch */
        result += 35;
    }
    return result;
}

static int nested_conditionals(int a, int b, int c) {
    /* Deeply nested if-else chains */
    int result = 0;

    if (a > 0) {
        if (b > 0) {
            if (c > 0) {
                result += 1000;
            } else {
                result += 500;
            }
        } else {
            if (c > 0) {
                result += 300;
            } else {
                result += 150;
            }
        }
    } else {
        if (b > 0) {
            result += 200;
        } else {
            result += 100;
        }
    }

    return result;
}

static int conditional_arithmetic(int x, int y) {
    /* Use conditional selects (CSEL/CSINC) for arithmetic */
    int max_val = (x > y) ? x : y;
    int min_val = (x < y) ? x : y;
    int abs_diff = (x > y) ? (x - y) : (y - x);

    return max_val + min_val + abs_diff;
}

int main(void) {
    int r1 = test_eq_ne(5, 5);        /* should be 100 */
    int r2 = test_eq_ne(5, 3);        /* should be 50 */

    int r3 = test_mi_pl(-10);         /* should be 10 */
    int r4 = test_mi_pl(20);          /* should be 20 */

    int r5 = test_cs_cc(100, 50);     /* 100 >= 50, should be 30 */
    int r6 = test_cs_cc(30, 60);      /* 30 < 60, should be 15 */

    int r7 = test_vs_vc(10, 20);      /* no overflow, should be 100 */
    int r8 = test_vs_vc(-10, -20);    /* no overflow, should be 100 */

    int r9 = test_hi_ls(100, 80);     /* 100 > 80, should be 40 */
    int r10 = test_hi_ls(50, 100);    /* 50 <= 100, should be 20 */

    int r11 = test_ge_lt_signed(10, 5);   /* 10 >= 5, should be 60 */
    int r12 = test_ge_lt_signed(3, 7);    /* 3 < 7, should be 30 */

    int r13 = test_gt_le_signed(20, 15);  /* 20 > 15, should be 70 */
    int r14 = test_gt_le_signed(10, 10);  /* 10 <= 10, should be 35 */

    int r15 = nested_conditionals(5, 3, 2);   /* a>0, b>0, c>0 = 1000 */
    int r16 = nested_conditionals(-1, 2, 3);  /* a<=0, b>0 = 200 */

    int r17 = conditional_arithmetic(10, 5);  /* max=10, min=5, diff=5, sum=20 */

    int total = r1 + r2 + r3 + r4 + r5 + r6 + r7 + r8 + r9 + r10 +
                r11 + r12 + r13 + r14 + r15 + r16 + r17;
    return total;
}
