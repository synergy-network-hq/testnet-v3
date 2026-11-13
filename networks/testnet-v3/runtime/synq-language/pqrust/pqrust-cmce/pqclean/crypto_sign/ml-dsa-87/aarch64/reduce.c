
#include "params.h"
#include "reduce.h"
#include <stdint.h>

int32_t montgomery_reduce(int64_t a) {
    int32_t t;

    t = (int32_t)((uint64_t)a * (uint64_t)DILITHIUM_QINV);
    t = (a - (int64_t)t * DILITHIUM_Q) >> 32;
    return t;
}

int32_t reduce32(int32_t a) {
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * DILITHIUM_Q;
    return t;
}

int32_t caddq(int32_t a) {
    a += (a >> 31) & DILITHIUM_Q;
    return a;
}

int32_t freeze(int32_t a) {
    a = reduce32(a);
    a = caddq(a);
    return a;
}