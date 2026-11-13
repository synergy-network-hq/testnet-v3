#include "compat.h"
#include "verify.h"
#include <stddef.h>
#include <stdint.h>

int PQCLEAN_MLKEM512_CLEAN_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    uint8_t r = 0;

    for (i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }

    return (-(uint64_t)r) >> 63;
}

void PQCLEAN_MLKEM512_CLEAN_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    size_t i;

    PQCLEAN_PREVENT_BRANCH_HACK(b);

    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (r[i] ^ x[i]);
    }
}

void PQCLEAN_MLKEM512_CLEAN_cmov_int16(int16_t *r, int16_t v, uint16_t b) {
    b = -b;
    *r ^= b & ((*r) ^ v);
}