/*
 * advanced_loops_aarch64.c — stress test for complex loop patterns:
 * nested loops with early exit (break/continue), while-loop with
 * modification inside, loop-unrolling friendly patterns, and
 * accumulation across multiple loop levels.
 * Self-contained, result via main return value.
 */
#include <stdint.h>

static int find_first_prime(int start, int limit) {
    /* while loop with early return — tests loop termination via ret */
    int n = start;
    while (n < limit) {
        if (n < 2) {
            n++;
            continue;
        }
        int is_prime = 1;
        int d = 2;
        while (d * d <= n) {
            if (n % d == 0) {
                is_prime = 0;
                break;
            }
            d++;
        }
        if (is_prime) {
            return n;
        }
        n++;
    }
    return -1;
}

static int nested_loop_sum_with_break(int limit) {
    /* multiple break statements from different nesting levels */
    int sum = 0;
    for (int i = 0; i < limit; i++) {
        for (int j = 0; j < limit - i; j++) {
            if (i * j > 200) {
                break;
            }
            sum += i * j;
            if (sum > 5000) {
                break;
            }
        }
    }
    return sum;
}

static int continue_pattern(int n) {
    /* while loop with continue — skips loop body for certain conditions */
    int sum = 0;
    int i = 0;
    while (i < n) {
        i++;
        if ((i & 1) == 0) {  /* skip even numbers */
            continue;
        }
        if (i % 5 == 0) {    /* skip multiples of 5 */
            continue;
        }
        sum += i;
    }
    return sum;
}

static int loop_variable_modification(void) {
    /* loop counter modified in loop body — tests register pressure */
    int sum = 0;
    for (int i = 1; i <= 10; i++) {
        sum += i;
        if (i == 3) {
            i += 2;  /* skip ahead */
        }
        if (i == 7) {
            i++;  /* another skip */
        }
    }
    return sum;
}

static int three_level_nested(int depth) {
    /* deep nesting: 3-level nested loop with conditionals */
    int result = 0;
    for (int i = 0; i < depth && i < 5; i++) {
        for (int j = 0; j < depth - i && j < 4; j++) {
            for (int k = 0; k < 3; k++) {
                if ((i + j + k) % 2 == 0) {
                    result += i + j + k;
                } else {
                    result -= k;
                }
            }
        }
    }
    return result;
}

int main(void) {
    int p1 = find_first_prime(10, 50);    /* should be 11 */
    int p2 = find_first_prime(20, 100);   /* should be 23 */

    int nlsb = nested_loop_sum_with_break(15);

    int cp = continue_pattern(30);

    int lvm = loop_variable_modification();

    int tln = three_level_nested(10);

    int result = p1 + p2 + nlsb + cp + lvm + tln;
    return result;
}
