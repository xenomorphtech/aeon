#include <stdio.h>

int main() {
    int x = 42;
    int result = 0;
    if (x > 40) {
        result = x * 2;
    } else {
        result = x;
    }
    printf("%d\n", result);  // Expected: 84
    return 0;
}
