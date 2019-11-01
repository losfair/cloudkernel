#include "./kernel.h"
#include <stdio.h>

int kDebugLog(const char *data, size_t n) {
    for(int i = 0; i < n; i++) putchar(data[i]);
    putchar('\n');
    return n;
}