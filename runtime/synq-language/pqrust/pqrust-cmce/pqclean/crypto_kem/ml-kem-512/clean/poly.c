#include "cbd.h"
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "reduce.h"
#include "symmetric.h"
#include "verify.h"
#include <stdint.h>

void PQCLEAN_MLKEM512_CLEAN_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a) {
    unsigned int i, j;
    int16_t u;
    uint32_t d0;
    uint8_t t[8];

    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {

            u  = a->coeffs[8 * i + j];
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

void PQCLEAN_MLKEM512_CLEAN_poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]) {
    size_t i;

    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2 * i + 0] = (((uint16_t)(a[0] & 15) * KYBER_Q) + 8) >> 4;
        r->coeffs[2 * i + 1] = (((uint16_t)(a[0] >> 4) * KYBER_Q) + 8) >> 4;
        a += 1;
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a) {
    size_t i;
    uint16_t t0, t1;

    for (i = 0; i < KYBER_N / 2; i++) {

        t0  = a->coeffs[2 * i];
        t0 += ((int16_t)t0 >> 15) & KYBER_Q;
        t1 = a->coeffs[2 * i + 1];
        t1 += ((int16_t)t1 >> 15) & KYBER_Q;
        r[3 * i + 0] = (uint8_t)(t0 >> 0);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]) {
    size_t i;
    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2 * i]   = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]) {
    size_t i, j;

    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            r->coeffs[8 * i + j] = 0;
            PQCLEAN_MLKEM512_CLEAN_cmov_int16(r->coeffs + 8 * i + j, ((KYBER_Q + 1) / 2), (msg[i] >> j) & 1);
        }
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a) {
    unsigned int i, j;
    uint32_t t;

    for (i = 0; i < KYBER_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t  = a->coeffs[8 * i + j];

            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            t &= 1;
            msg[i] |= t << j;
        }
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
    prf(buf, sizeof(buf), seed, nonce);
    PQCLEAN_MLKEM512_CLEAN_poly_cbd_eta1(r, buf);
}

void PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t buf[KYBER_ETA2 * KYBER_N / 4];
    prf(buf, sizeof(buf), seed, nonce);
    PQCLEAN_MLKEM512_CLEAN_poly_cbd_eta2(r, buf);
}

void PQCLEAN_MLKEM512_CLEAN_poly_ntt(poly *r) {
    PQCLEAN_MLKEM512_CLEAN_ntt(r->coeffs);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(r);
}

void PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(poly *r) {
    PQCLEAN_MLKEM512_CLEAN_invntt(r->coeffs);
}

void PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(poly *r, const poly *a, const poly *b) {
    size_t i;
    for (i = 0; i < KYBER_N / 4; i++) {
        PQCLEAN_MLKEM512_CLEAN_basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], PQCLEAN_MLKEM512_CLEAN_zetas[64 + i]);
        PQCLEAN_MLKEM512_CLEAN_basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2], -PQCLEAN_MLKEM512_CLEAN_zetas[64 + i]);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_tomont(poly *r) {
    size_t i;
    const int16_t f = (1ULL << 32) % KYBER_Q;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = PQCLEAN_MLKEM512_CLEAN_montgomery_reduce((int32_t)r->coeffs[i] * f);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_reduce(poly *r) {
    size_t i;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = PQCLEAN_MLKEM512_CLEAN_barrett_reduce(r->coeffs[i]);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_add(poly *r, const poly *a, const poly *b) {
    size_t i;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_sub(poly *r, const poly *a, const poly *b) {
    size_t i;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}