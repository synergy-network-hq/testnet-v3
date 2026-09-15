#include "params.h"
#include "rounding.h"
#include <stdint.h>

int32_t PQCLEAN_MLDSA44_CLEAN_power2round(int32_t *a0, int32_t a)  {
    int32_t a1;

    a1 = (a + (1 << (D - 1)) - 1) >> D;
    *a0 = a - (a1 << D);
    return a1;
}

int32_t PQCLEAN_MLDSA44_CLEAN_decompose(int32_t *a0, int32_t a) {
    int32_t a1;

    a1  = (a + 127) >> 7;
    a1  = (a1 * 11275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;

    *a0  = a - a1 * 2 * GAMMA2;
    *a0 -= (((Q - 1) / 2 - *a0) >> 31) & Q;
    return a1;
}

unsigned int PQCLEAN_MLDSA44_CLEAN_make_hint(int32_t a0, int32_t a1) {
    if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0)) {
        return 1;
    }

    return 0;
}

int32_t PQCLEAN_MLDSA44_CLEAN_use_hint(int32_t a, unsigned int hint) {
    int32_t a0, a1;

    a1 = PQCLEAN_MLDSA44_CLEAN_decompose(&a0, a);
    if (hint == 0) {
        return a1;
    }

    if (a0 > 0) {
        if (a1 == 43) {
            return 0;
        }
        return a1 + 1;
    }
    if (a1 == 0) {
        return 43;
    }
    return a1 - 1;
}