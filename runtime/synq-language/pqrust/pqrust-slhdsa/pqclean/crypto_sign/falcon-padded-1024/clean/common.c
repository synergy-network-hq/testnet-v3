
#include "inner.h"

void
PQCLEAN_FALCONPADDED1024_CLEAN_hash_to_point_vartime(
    inner_shake256_context *sc,
    uint16_t *x, unsigned logn) {

    size_t n;

    n = (size_t)1 << logn;
    while (n > 0) {
        uint8_t buf[2];
        uint32_t w;

        inner_shake256_extract(sc, (void *)buf, sizeof buf);
        w = ((unsigned)buf[0] << 8) | (unsigned)buf[1];
        if (w < 61445) {
            while (w >= 12289) {
                w -= 12289;
            }
            *x ++ = (uint16_t)w;
            n --;
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_CLEAN_hash_to_point_ct(
    inner_shake256_context *sc,
    uint16_t *x, unsigned logn, uint8_t *tmp) {

    static const uint16_t overtab[] = {
        0, 
        65,
        67,
        71,
        77,
        86,
        100,
        122,
        154,
        205,
        287
    };

    unsigned n, n2, u, m, p, over;
    uint16_t *tt1, tt2[63];

    n = 1U << logn;
    n2 = n << 1;
    over = overtab[logn];
    m = n + over;
    tt1 = (uint16_t *)tmp;
    for (u = 0; u < m; u ++) {
        uint8_t buf[2];
        uint32_t w, wr;

        inner_shake256_extract(sc, buf, sizeof buf);
        w = ((uint32_t)buf[0] << 8) | (uint32_t)buf[1];
        wr = w - ((uint32_t)24578 & (((w - 24578) >> 31) - 1));
        wr = wr - ((uint32_t)24578 & (((wr - 24578) >> 31) - 1));
        wr = wr - ((uint32_t)12289 & (((wr - 12289) >> 31) - 1));
        wr |= ((w - 61445) >> 31) - 1;
        if (u < n) {
            x[u] = (uint16_t)wr;
        } else if (u < n2) {
            tt1[u - n] = (uint16_t)wr;
        } else {
            tt2[u - n2] = (uint16_t)wr;
        }
    }

    for (p = 1; p <= over; p <<= 1) {
        unsigned v;

        v = 0;
        for (u = 0; u < m; u ++) {
            uint16_t *s, *d;
            unsigned j, sv, dv, mk;

            if (u < n) {
                s = &x[u];
            } else if (u < n2) {
                s = &tt1[u - n];
            } else {
                s = &tt2[u - n2];
            }
            sv = *s;

            j = u - v;

            mk = (sv >> 15) - 1U;
            v -= mk;

            if (u < p) {
                continue;
            }

            if ((u - p) < n) {
                d = &x[u - p];
            } else if ((u - p) < n2) {
                d = &tt1[(u - p) - n];
            } else {
                d = &tt2[(u - p) - n2];
            }
            dv = *d;

            mk &= -(((j & p) + 0x1FF) >> 9);

            *s = (uint16_t)(sv ^ (mk & (sv ^ dv)));
            *d = (uint16_t)(dv ^ (mk & (sv ^ dv)));
        }
    }
}

static const uint32_t l2bound[] = {
    0,    
    101498,
    208714,
    428865,
    892039,
    1852696,
    3842630,
    7959734,
    16468416,
    34034726,
    70265242
};

int
PQCLEAN_FALCONPADDED1024_CLEAN_is_short(
    const int16_t *s1, const int16_t *s2, unsigned logn) {

    size_t n, u;
    uint32_t s, ng;

    n = (size_t)1 << logn;
    s = 0;
    ng = 0;
    for (u = 0; u < n; u ++) {
        int32_t z;

        z = s1[u];
        s += (uint32_t)(z * z);
        ng |= s;
        z = s2[u];
        s += (uint32_t)(z * z);
        ng |= s;
    }
    s |= -(ng >> 31);

    return s <= l2bound[logn];
}

int
PQCLEAN_FALCONPADDED1024_CLEAN_is_short_half(
    uint32_t sqn, const int16_t *s2, unsigned logn) {
    size_t n, u;
    uint32_t ng;

    n = (size_t)1 << logn;
    ng = -(sqn >> 31);
    for (u = 0; u < n; u ++) {
        int32_t z;

        z = s2[u];
        sqn += (uint32_t)(z * z);
        ng |= sqn;
    }
    sqn |= -(ng >> 31);

    return sqn <= l2bound[logn];
}