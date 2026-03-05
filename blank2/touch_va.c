#include <stdint.h>
#include <stdio.h>
#include <x86intrin.h>

int main() {
    volatile char *p = (volatile char*)0x00007844e4202000;

    for (long i = 0; i < 5000000; i++) {
        _mm_clflush((void*)p);
        *p;
    }

    return 0;
}
