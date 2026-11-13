#include "params.h"
#include "reduce.h"
#include <stdint.h>

int32_t PQCLEAN_MLDSA44_CLEAN_montgomery_reduce(int64_t a) {
    int32_t t;

    t = (int32_t)((uint64_t)a * (uint64_t)QINV);
    t = (a - (int64_t)t * Q) >> 32;
    return t;
}

int32_t PQCLEAN_MLDSA44_CLEAN_reduce32(int32_t a) {
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * Q;
    return t;
}

int32_t PQCLEAN_MLDSA44_CLEAN_caddq(int32_t a) {
    a += (a >> 31) & Q;
    return a;
}

int32_t PQCLEAN_MLDSA44_CLEAN_freeze(int32_t a) {
    a = PQCLEAN_MLDSA44_CLEAN_reduce32(a);
    a = PQCLEAN_MLDSA44_CLEAN_caddq(a);
    return a;
}