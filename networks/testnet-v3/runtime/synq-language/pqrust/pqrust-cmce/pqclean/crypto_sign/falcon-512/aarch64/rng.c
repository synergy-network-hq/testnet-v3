
#include <assert.h>
#include <stdio.h>
#include "inner.h"

int PQCLEAN_FALCON512_AARCH64_get_seed(void *seed, size_t len) {
    unsigned char tmp[48];
    for (size_t i = 0; i < len; i++) {
        tmp[i] = (unsigned char) i;
    }
    memcpy(seed, tmp, len);
    return 1;
}

void
PQCLEAN_FALCON512_AARCH64_prng_init(prng *p, inner_shake256_context *src) {

    uint8_t tmp[56];
    uint64_t th, tl;
    int i;

    inner_shake256_extract(src, tmp, 56);
    for (i = 0; i < 14; i ++) {
        uint32_t w;

        w = (uint32_t)tmp[(i << 2) + 0]
            | ((uint32_t)tmp[(i << 2) + 1] << 8)
            | ((uint32_t)tmp[(i << 2) + 2] << 16)
            | ((uint32_t)tmp[(i << 2) + 3] << 24);
        *(uint32_t *)(p->state.d + (i << 2)) = w;
    }
    tl = *(uint32_t *)(p->state.d + 48);
    th = *(uint32_t *)(p->state.d + 52);
    *(uint64_t *)(p->state.d + 48) = tl + (th << 32);
    PQCLEAN_FALCON512_AARCH64_prng_refill(p);
}

void
PQCLEAN_FALCON512_AARCH64_prng_refill(prng *p) {

    static const uint32_t CW[] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    uint64_t cc;
    size_t u;

    cc = *(uint64_t *)(p->state.d + 48);
    for (u = 0; u < 8; u ++) {
        uint32_t state[16];
        size_t v;
        int i;

        memcpy(&state[0], CW, sizeof CW);
        memcpy(&state[4], p->state.d, 48);
        state[14] ^= (uint32_t)cc;
        state[15] ^= (uint32_t)(cc >> 32);
        for (i = 0; i < 10; i ++) {

#define QROUND(a, b, c, d)   do { \
        state[a] += state[b]; \
        state[d] ^= state[a]; \
        state[d] = (state[d] << 16) | (state[d] >> 16); \
        state[c] += state[d]; \
        state[b] ^= state[c]; \
        state[b] = (state[b] << 12) | (state[b] >> 20); \
        state[a] += state[b]; \
        state[d] ^= state[a]; \
        state[d] = (state[d] <<  8) | (state[d] >> 24); \
        state[c] += state[d]; \
        state[b] ^= state[c]; \
        state[b] = (state[b] <<  7) | (state[b] >> 25); \
    } while (0)

            QROUND( 0,  4,  8, 12);
            QROUND( 1,  5,  9, 13);
            QROUND( 2,  6, 10, 14);
            QROUND( 3,  7, 11, 15);
            QROUND( 0,  5, 10, 15);
            QROUND( 1,  6, 11, 12);
            QROUND( 2,  7,  8, 13);
            QROUND( 3,  4,  9, 14);

#undef QROUND

        }

        for (v = 0; v < 4; v ++) {
            state[v] += CW[v];
        }
        for (v = 4; v < 14; v ++) {
            state[v] += ((uint32_t *)p->state.d)[v - 4];
        }
        state[14] += ((uint32_t *)p->state.d)[10]
                     ^ (uint32_t)cc;
        state[15] += ((uint32_t *)p->state.d)[11]
                     ^ (uint32_t)(cc >> 32);
        cc ++;

        for (v = 0; v < 16; v ++) {
            p->buf.d[(u << 2) + (v << 5) + 0] =
                (uint8_t)state[v];
            p->buf.d[(u << 2) + (v << 5) + 1] =
                (uint8_t)(state[v] >> 8);
            p->buf.d[(u << 2) + (v << 5) + 2] =
                (uint8_t)(state[v] >> 16);
            p->buf.d[(u << 2) + (v << 5) + 3] =
                (uint8_t)(state[v] >> 24);
        }
    }
    *(uint64_t *)(p->state.d + 48) = cc;

    p->ptr = 0;
}

void
PQCLEAN_FALCON512_AARCH64_prng_get_bytes(prng *p, void *dst, size_t len) {
    uint8_t *buf;

    buf = dst;
    while (len > 0) {
        size_t clen;

        clen = (sizeof p->buf.d) - p->ptr;
        if (clen > len) {
            clen = len;
        }
        memcpy(buf, p->buf.d, clen);
        buf += clen;
        len -= clen;
        p->ptr += clen;
        if (p->ptr == sizeof p->buf.d) {
            PQCLEAN_FALCON512_AARCH64_prng_refill(p);
        }
    }
}