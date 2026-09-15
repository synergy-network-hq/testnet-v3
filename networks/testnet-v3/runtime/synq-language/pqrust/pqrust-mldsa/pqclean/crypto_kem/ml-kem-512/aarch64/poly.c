
#include <arm_neon.h>
#include "params.h"
#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "cbd.h"
#include "symmetric.h"
#include "verify.h"

void poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const int16_t a[KYBER_N]) {
    unsigned int i, j;
    int16_t u;
    uint32_t d0;
    uint8_t t[8];

    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {

            u  = a[8 * i + j];
            u += (u >> 15) & KYBER_Q;

            d0 = u << 4;
            d0 += 1665;
            d0 *= 80635;
            d0 >>= 28;
            t[j] = d0 & 0xf;
        }

        r[0] = t[0] | (t[1] << 4);
        r[1] = t[2] | (t[3] << 4);
        r[2] = t[4] | (t[5] << 4);
        r[3] = t[6] | (t[7] << 4);
        r += 4;
    }
}

void poly_decompress(int16_t r[KYBER_N], const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]) {
    unsigned int i;

    for (i = 0; i < KYBER_N / 2; i++) {
        r[2 * i + 0] = (((uint16_t)(a[0] & 15) * KYBER_Q) + 8) >> 4;
        r[2 * i + 1] = (((uint16_t)(a[0] >> 4) * KYBER_Q) + 8) >> 4;
        a += 1;
    }
}

void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const int16_t a[KYBER_N]) {
    unsigned int i;
    uint16_t t0, t1;

    for (i = 0; i < KYBER_N / 2; i++) {

        t0  = a[2 * i];
        t0 += ((int16_t)t0 >> 15) & KYBER_Q;
        t1 = a[2 * i + 1];
        t1 += ((int16_t)t1 >> 15) & KYBER_Q;
        r[3 * i + 0] = (t0 >> 0);
        r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
        r[3 * i + 2] = (t1 >> 4);
    }
}

void poly_frombytes(int16_t r[KYBER_N], const uint8_t a[KYBER_POLYBYTES]) {
    uint8x16x3_t neon_buf;
    uint16x8x4_t tmp;
    int16x8x4_t value;
    uint16x8_t const_0xfff;
    const_0xfff = vdupq_n_u16(0xfff);

    unsigned int i, j = 0;
    for (i = 0; i < KYBER_POLYBYTES; i += 48) {
        neon_buf = vld3q_u8(&a[i]);

        tmp.val[0] = (uint16x8_t)vzip1q_u8(neon_buf.val[0], neon_buf.val[1]);
        tmp.val[1] = (uint16x8_t)vzip2q_u8(neon_buf.val[0], neon_buf.val[1]);

        tmp.val[0] = vandq_u16(tmp.val[0], const_0xfff);
        tmp.val[1] = vandq_u16(tmp.val[1], const_0xfff);

        tmp.val[2] = (uint16x8_t)vzip1q_u8(neon_buf.val[1], neon_buf.val[2]);
        tmp.val[3] = (uint16x8_t)vzip2q_u8(neon_buf.val[1], neon_buf.val[2]);

        tmp.val[2] = vshrq_n_u16(tmp.val[2], 4);
        tmp.val[3] = vshrq_n_u16(tmp.val[3], 4);

        value.val[0] = (int16x8_t)vzip1q_u16(tmp.val[0], tmp.val[2]);
        value.val[1] = (int16x8_t)vzip2q_u16(tmp.val[0], tmp.val[2]);
        value.val[2] = (int16x8_t)vzip1q_u16(tmp.val[1], tmp.val[3]);
        value.val[3] = (int16x8_t)vzip2q_u16(tmp.val[1], tmp.val[3]);

        vst1q_s16_x4(r + j, value);
        j += 32;
    }
}

void poly_frommsg(int16_t r[KYBER_N], const uint8_t msg[KYBER_INDCPA_MSGBYTES])  {
    size_t i, j;

    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            r[8 * i + j] = 0;
            cmov_int16(r + 8 * i + j, ((KYBER_Q + 1) / 2), (msg[i] >> j) & 1);
        }
    }
}

void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const int16_t a[KYBER_N]) {
    unsigned int i, j;
    uint32_t t;

    for (i = 0; i < KYBER_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t  = a[8 * i + j];

            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            t &= 1;
            msg[i] |= t << j;
        }
    }
}