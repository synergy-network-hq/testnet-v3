
#include "inner.h"

size_t
PQCLEAN_FALCONPADDED512_AVX2_modq_encode(
    void *out, size_t max_out_len,
    const uint16_t *x, unsigned logn) {
    size_t n, out_len, u;
    uint8_t *buf;
    uint32_t acc;
    int acc_len;

    n = (size_t)1 << logn;
    for (u = 0; u < n; u ++) {
        if (x[u] >= 12289) {
            return 0;
        }
    }
    out_len = ((n * 14) + 7) >> 3;
    if (out == NULL) {
        return out_len;
    }
    if (out_len > max_out_len) {
        return 0;
    }
    buf = out;
    acc = 0;
    acc_len = 0;
    for (u = 0; u < n; u ++) {
        acc = (acc << 14) | x[u];
        acc_len += 14;
        while (acc_len >= 8) {
            acc_len -= 8;
            *buf ++ = (uint8_t)(acc >> acc_len);
        }
    }
    if (acc_len > 0) {
        *buf = (uint8_t)(acc << (8 - acc_len));
    }
    return out_len;
}

size_t
PQCLEAN_FALCONPADDED512_AVX2_modq_decode(
    uint16_t *x, unsigned logn,
    const void *in, size_t max_in_len) {
    size_t n, in_len, u;
    const uint8_t *buf;
    uint32_t acc;
    int acc_len;

    n = (size_t)1 << logn;
    in_len = ((n * 14) + 7) >> 3;
    if (in_len > max_in_len) {
        return 0;
    }
    buf = in;
    acc = 0;
    acc_len = 0;
    u = 0;
    while (u < n) {
        acc = (acc << 8) | (*buf ++);
        acc_len += 8;
        if (acc_len >= 14) {
            unsigned w;

            acc_len -= 14;
            w = (acc >> acc_len) & 0x3FFF;
            if (w >= 12289) {
                return 0;
            }
            x[u ++] = (uint16_t)w;
        }
    }
    if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) {
        return 0;
    }
    return in_len;
}

size_t
PQCLEAN_FALCONPADDED512_AVX2_trim_i16_encode(
    void *out, size_t max_out_len,
    const int16_t *x, unsigned logn, unsigned bits) {
    size_t n, u, out_len;
    int minv, maxv;
    uint8_t *buf;
    uint32_t acc, mask;
    unsigned acc_len;

    n = (size_t)1 << logn;
    maxv = (1 << (bits - 1)) - 1;
    minv = -maxv;
    for (u = 0; u < n; u ++) {
        if (x[u] < minv || x[u] > maxv) {
            return 0;
        }
    }
    out_len = ((n * bits) + 7) >> 3;
    if (out == NULL) {
        return out_len;
    }
    if (out_len > max_out_len) {
        return 0;
    }
    buf = out;
    acc = 0;
    acc_len = 0;
    mask = ((uint32_t)1 << bits) - 1;
    for (u = 0; u < n; u ++) {
        acc = (acc << bits) | ((uint16_t)x[u] & mask);
        acc_len += bits;
        while (acc_len >= 8) {
            acc_len -= 8;
            *buf ++ = (uint8_t)(acc >> acc_len);
        }
    }
    if (acc_len > 0) {
        *buf ++ = (uint8_t)(acc << (8 - acc_len));
    }
    return out_len;
}

size_t
PQCLEAN_FALCONPADDED512_AVX2_trim_i16_decode(
    int16_t *x, unsigned logn, unsigned bits,
    const void *in, size_t max_in_len) {
    size_t n, in_len;
    const uint8_t *buf;
    size_t u;
    uint32_t acc, mask1, mask2;
    unsigned acc_len;

    n = (size_t)1 << logn;
    in_len = ((n * bits) + 7) >> 3;
    if (in_len > max_in_len) {
        return 0;
    }
    buf = in;
    u = 0;
    acc = 0;
    acc_len = 0;
    mask1 = ((uint32_t)1 << bits) - 1;
    mask2 = (uint32_t)1 << (bits - 1);
    while (u < n) {
        acc = (acc << 8) | *buf ++;
        acc_len += 8;
        while (acc_len >= bits && u < n) {
            uint32_t w;

            acc_len -= bits;
            w = (acc >> acc_len) & mask1;
            w |= -(w & mask2);
            if (w == -mask2) {

                return 0;
            }
            w |= -(w & mask2);
            x[u ++] = (int16_t) * (int32_t *)&w;
        }
    }
    if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) {

        return 0;
    }
    return in_len;
}

size_t
PQCLEAN_FALCONPADDED512_AVX2_trim_i8_encode(
    void *out, size_t max_out_len,
    const int8_t *x, unsigned logn, unsigned bits) {
    size_t n, u, out_len;
    int minv, maxv;
    uint8_t *buf;
    uint32_t acc, mask;
    unsigned acc_len;

    n = (size_t)1 << logn;
    maxv = (1 << (bits - 1)) - 1;
    minv = -maxv;
    for (u = 0; u < n; u ++) {
        if (x[u] < minv || x[u] > maxv) {
            return 0;
        }
    }
    out_len = ((n * bits) + 7) >> 3;
    if (out == NULL) {
        return out_len;
    }
    if (out_len > max_out_len) {
        return 0;
    }
    buf = out;
    acc = 0;
    acc_len = 0;
    mask = ((uint32_t)1 << bits) - 1;
    for (u = 0; u < n; u ++) {
        acc = (acc << bits) | ((uint8_t)x[u] & mask);
        acc_len += bits;
        while (acc_len >= 8) {
            acc_len -= 8;
            *buf ++ = (uint8_t)(acc >> acc_len);
        }
    }
    if (acc_len > 0) {
        *buf ++ = (uint8_t)(acc << (8 - acc_len));
    }
    return out_len;
}

size_t
PQCLEAN_FALCONPADDED512_AVX2_trim_i8_decode(
    int8_t *x, unsigned logn, unsigned bits,
    const void *in, size_t max_in_len) {
    size_t n, in_len;
    const uint8_t *buf;
    size_t u;
    uint32_t acc, mask1, mask2;
    unsigned acc_len;

    n = (size_t)1 << logn;
    in_len = ((n * bits) + 7) >> 3;
    if (in_len > max_in_len) {
        return 0;
    }
    buf = in;
    u = 0;
    acc = 0;
    acc_len = 0;
    mask1 = ((uint32_t)1 << bits) - 1;
    mask2 = (uint32_t)1 << (bits - 1);
    while (u < n) {
        acc = (acc << 8) | *buf ++;
        acc_len += 8;
        while (acc_len >= bits && u < n) {
            uint32_t w;

            acc_len -= bits;
            w = (acc >> acc_len) & mask1;
            w |= -(w & mask2);
            if (w == -mask2) {

                return 0;
            }
            x[u ++] = (int8_t) * (int32_t *)&w;
        }
    }
    if ((acc & (((uint32_t)1 << acc_len) - 1)) != 0) {

        return 0;
    }
    return in_len;
}

size_t
PQCLEAN_FALCONPADDED512_AVX2_comp_encode(
    void *out, size_t max_out_len,
    const int16_t *x, unsigned logn) {
    uint8_t *buf;
    size_t n, u, v;
    uint32_t acc;
    unsigned acc_len;

    n = (size_t)1 << logn;
    buf = out;

    for (u = 0; u < n; u ++) {
        if (x[u] < -2047 || x[u] > +2047) {
            return 0;
        }
    }

    acc = 0;
    acc_len = 0;
    v = 0;
    for (u = 0; u < n; u ++) {
        int t;
        unsigned w;

        acc <<= 1;
        t = x[u];
        if (t < 0) {
            t = -t;
            acc |= 1;
        }
        w = (unsigned)t;

        acc <<= 7;
        acc |= w & 127u;
        w >>= 7;

        acc_len += 8;

        acc <<= (w + 1);
        acc |= 1;
        acc_len += w + 1;

        while (acc_len >= 8) {
            acc_len -= 8;
            if (buf != NULL) {
                if (v >= max_out_len) {
                    return 0;
                }
                buf[v] = (uint8_t)(acc >> acc_len);
            }
            v ++;
        }
    }

    if (acc_len > 0) {
        if (buf != NULL) {
            if (v >= max_out_len) {
                return 0;
            }
            buf[v] = (uint8_t)(acc << (8 - acc_len));
        }
        v ++;
    }

    return v;
}

size_t
PQCLEAN_FALCONPADDED512_AVX2_comp_decode(
    int16_t *x, unsigned logn,
    const void *in, size_t max_in_len) {
    const uint8_t *buf;
    size_t n, u, v;
    uint32_t acc;
    unsigned acc_len;

    n = (size_t)1 << logn;
    buf = in;
    acc = 0;
    acc_len = 0;
    v = 0;
    for (u = 0; u < n; u ++) {
        unsigned b, s, m;

        if (v >= max_in_len) {
            return 0;
        }
        acc = (acc << 8) | (uint32_t)buf[v ++];
        b = acc >> acc_len;
        s = b & 128;
        m = b & 127;

        for (;;) {
            if (acc_len == 0) {
                if (v >= max_in_len) {
                    return 0;
                }
                acc = (acc << 8) | (uint32_t)buf[v ++];
                acc_len = 8;
            }
            acc_len --;
            if (((acc >> acc_len) & 1) != 0) {
                break;
            }
            m += 128;
            if (m > 2047) {
                return 0;
            }
        }

        if (s && m == 0) {
            return 0;
        }
        if (s) {
            x[u] = (int16_t) - m;
        } else {
            x[u] = (int16_t)m;
        }
    }

    if ((acc & ((1u << acc_len) - 1u)) != 0) {
        return 0;
    }

    return v;
}

const uint8_t PQCLEAN_FALCONPADDED512_AVX2_max_fg_bits[] = {
    0, 
    8,
    8,
    8,
    8,
    8,
    7,
    7,
    6,
    6,
    5
};

const uint8_t PQCLEAN_FALCONPADDED512_AVX2_max_FG_bits[] = {
    0, 
    8,
    8,
    8,
    8,
    8,
    8,
    8,
    8,
    8,
    8
};

const uint8_t PQCLEAN_FALCONPADDED512_AVX2_max_sig_bits[] = {
    0, 
    10,
    11,
    11,
    12,
    12,
    12,
    12,
    12,
    12,
    12
};