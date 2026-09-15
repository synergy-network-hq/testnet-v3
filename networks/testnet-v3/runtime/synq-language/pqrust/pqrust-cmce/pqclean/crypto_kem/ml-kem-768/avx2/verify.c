#include "compat.h"
#include "verify.h"
#include <immintrin.h>
#include <stdint.h>
#include <stdlib.h>

int PQCLEAN_MLKEM768_AVX2_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    uint64_t r;
    __m256i f, g, h;

    h = _mm256_setzero_si256();
    for (i = 0; i < len / 32; i++) {
        f = _mm256_loadu_si256((__m256i *)&a[32 * i]);
        g = _mm256_loadu_si256((__m256i *)&b[32 * i]);
        f = _mm256_xor_si256(f, g);
        h = _mm256_or_si256(h, f);
    }
    r = 1 - _mm256_testz_si256(h, h);

    a += 32 * i;
    b += 32 * i;
    len -= 32 * i;
    for (i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }

    r = (-r) >> 63;
    return r;
}

void PQCLEAN_MLKEM768_AVX2_cmov(uint8_t *restrict r, const uint8_t *x, size_t len, uint8_t b) {
    size_t i;
    __m256i xvec, rvec, bvec;

    PQCLEAN_PREVENT_BRANCH_HACK(b);

    bvec = _mm256_set1_epi64x(-(uint64_t)b);
    for (i = 0; i < len / 32; i++) {
        rvec = _mm256_loadu_si256((__m256i *)&r[32 * i]);
        xvec = _mm256_loadu_si256((__m256i *)&x[32 * i]);
        rvec = _mm256_blendv_epi8(rvec, xvec, bvec);
        _mm256_storeu_si256((__m256i *)&r[32 * i], rvec);
    }

    r += 32 * i;
    x += 32 * i;
    len -= 32 * i;
    for (i = 0; i < len; i++) {
        r[i] ^= -b & (x[i] ^ r[i]);
    }
}