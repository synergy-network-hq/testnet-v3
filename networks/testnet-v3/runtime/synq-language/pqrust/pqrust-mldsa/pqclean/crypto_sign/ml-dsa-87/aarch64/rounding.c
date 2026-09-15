
#include "params.h"
#include "rounding.h"
#include <stdint.h>

int32_t power2round(int32_t *a0, int32_t a)  {
    int32_t a1;

    a1 = (a + (1 << (D - 1)) - 1) >> D;
    *a0 = a - (a1 << D);
    return a1;
}

int32_t decompose(int32_t *a0, int32_t a) {
    int32_t a1;

    a1  = (a + 127) >> 7;

    a1  = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;

    *a0  = a - a1 * 2 * GAMMA2;
    *a0 -= (((DILITHIUM_Q - 1) / 2 - *a0) >> 31) & DILITHIUM_Q;
    return a1;
}

unsigned int make_hint(int32_t a0, int32_t a1) {
    if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0)) {
        return 1;
    }

    return 0;
}

int32_t use_hint(int32_t a, unsigned int hint) {
    int32_t a0, a1;

    a1 = decompose(&a0, a);
    if (hint == 0) {
        return a1;
    }

    if (a0 > 0) {
        return (a1 + 1) & 15;
    } else {
        return (a1 - 1) & 15;
    }

}