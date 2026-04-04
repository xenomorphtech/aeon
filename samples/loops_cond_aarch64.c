/*
 * loops_cond_aarch64.c — exercises nested loops, do-while, if/else chains,
 * conditional select (CSEL/CSINC), and comparison-driven branching patterns.
 * Self-contained, result via main return value.
 */
#include <stdint.h>

static int collatz_steps(int n) {
    /* do-while style loop with mixed conditionals */
    int steps = 0;
    while (n != 1 && steps < 200) {
        if ((n & 1) == 0) {
            n = n >> 1;
        } else {
            n = 3 * n + 1;
        }
        steps++;
    }
    return steps;
}

static int nested_sum(int rows, int cols) {
    /* nested for-loops with conditional accumulation — the modulo triggers
       a widening-multiply (SMULL) pattern for division by constant */
    int sum = 0;
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            int val = r * cols + c;
            if (val % 3 == 0) {
                sum += val;
            } else if (val % 3 == 1) {
                sum -= val >> 1;
            } else {
                sum ^= val;
            }
        }
    }
    return sum;
}

static int select_chain(int a, int b, int c) {
    /* generates CSEL / CSINC patterns */
    int result;
    if (a > b) {
        result = a - b;
    } else if (a == b) {
        result = c;
    } else {
        result = b - a + 1;
    }

    /* ternary-style conditional — usually becomes CSEL */
    int bonus = (result > 10) ? result * 2 : result + 5;
    return bonus;
}

static int countdown_do_while(int start) {
    /* ensures at least one iteration — do-while pattern */
    int acc = 0;
    int n = start;
    do {
        acc += n;
        n -= 3;
    } while (n > 0);
    return acc;
}

int main(void) {
    int c1 = collatz_steps(27);   /* 111 steps */
    int c2 = collatz_steps(7);    /* 16 steps */

    int ns = nested_sum(8, 6);

    int s1 = select_chain(15, 9, 42);
    int s2 = select_chain(5, 5, 42);
    int s3 = select_chain(3, 10, 42);

    int dw = countdown_do_while(20);

    int result = c1 + c2 + ns + s1 + s2 + s3 + dw;
    return result;
}
