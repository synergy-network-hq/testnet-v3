#include "align.h"
#include "cbd.h"
#include "indcpa.h"
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "rejsample.h"
#include "symmetric.h"
#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES]) {
    PQCLEAN_MLKEM1024_AVX2_polyvec_tobytes(r, pk);
    memcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
    PQCLEAN_MLKEM1024_AVX2_polyvec_frombytes(pk, packedpk);
    memcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
    PQCLEAN_MLKEM1024_AVX2_polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
    PQCLEAN_MLKEM1024_AVX2_polyvec_frombytes(sk, packedsk);
}

static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v) {
    PQCLEAN_MLKEM1024_AVX2_polyvec_compress(r, b);
    PQCLEAN_MLKEM1024_AVX2_poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES]) {
    PQCLEAN_MLKEM1024_AVX2_polyvec_decompress(b, c);
    PQCLEAN_MLKEM1024_AVX2_poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while (ctr < len && pos <= buflen - 3) { 
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q) {
            r[ctr++] = val0;
        }
        if (ctr < len && val1 < KYBER_Q) {
            r[ctr++] = val1;
        }
    }

    return ctr;
}

#define gen_a(A,B)  PQCLEAN_MLKEM1024_AVX2_gen_matrix(A,B,0)
#define gen_at(A,B) PQCLEAN_MLKEM1024_AVX2_gen_matrix(A,B,1)

void PQCLEAN_MLKEM1024_AVX2_gen_matrix(polyvec *a, const uint8_t seed[32], int transposed) {
    unsigned int i, ctr0, ctr1, ctr2, ctr3;
    ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS * SHAKE128_RATE) buf[4];
    __m256i f;
    keccakx4_state state;

    for (i = 0; i < 4; i++) {
        f = _mm256_loadu_si256((__m256i *)seed);
        _mm256_store_si256(buf[0].vec, f);
        _mm256_store_si256(buf[1].vec, f);
        _mm256_store_si256(buf[2].vec, f);
        _mm256_store_si256(buf[3].vec, f);

        if (transposed) {
            buf[0].coeffs[32] = i;
            buf[0].coeffs[33] = 0;
            buf[1].coeffs[32] = i;
            buf[1].coeffs[33] = 1;
            buf[2].coeffs[32] = i;
            buf[2].coeffs[33] = 2;
            buf[3].coeffs[32] = i;
            buf[3].coeffs[33] = 3;
        } else {
            buf[0].coeffs[32] = 0;
            buf[0].coeffs[33] = i;
            buf[1].coeffs[32] = 1;
            buf[1].coeffs[33] = i;
            buf[2].coeffs[32] = 2;
            buf[2].coeffs[33] = i;
            buf[3].coeffs[32] = 3;
            buf[3].coeffs[33] = i;
        }

        PQCLEAN_MLKEM1024_AVX2_shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
        PQCLEAN_MLKEM1024_AVX2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

        ctr0 = PQCLEAN_MLKEM1024_AVX2_rej_uniform_avx(a[i].vec[0].coeffs, buf[0].coeffs);
        ctr1 = PQCLEAN_MLKEM1024_AVX2_rej_uniform_avx(a[i].vec[1].coeffs, buf[1].coeffs);
        ctr2 = PQCLEAN_MLKEM1024_AVX2_rej_uniform_avx(a[i].vec[2].coeffs, buf[2].coeffs);
        ctr3 = PQCLEAN_MLKEM1024_AVX2_rej_uniform_avx(a[i].vec[3].coeffs, buf[3].coeffs);

        while (ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
            PQCLEAN_MLKEM1024_AVX2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

            ctr0 += rej_uniform(a[i].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
            ctr1 += rej_uniform(a[i].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
            ctr2 += rej_uniform(a[i].vec[2].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
            ctr3 += rej_uniform(a[i].vec[3].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
        }

        PQCLEAN_MLKEM1024_AVX2_poly_nttunpack(&a[i].vec[0]);
        PQCLEAN_MLKEM1024_AVX2_poly_nttunpack(&a[i].vec[1]);
        PQCLEAN_MLKEM1024_AVX2_poly_nttunpack(&a[i].vec[2]);
        PQCLEAN_MLKEM1024_AVX2_poly_nttunpack(&a[i].vec[3]);
    }
}

void PQCLEAN_MLKEM1024_AVX2_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    polyvec a[KYBER_K], e, pkpv, skpv;

    memcpy(buf, coins, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = KYBER_K;
    hash_g(buf, buf, KYBER_SYMBYTES + 1);

    gen_a(a, publicseed);

    PQCLEAN_MLKEM1024_AVX2_poly_getnoise_eta1_4x(skpv.vec + 0, skpv.vec + 1, skpv.vec + 2, skpv.vec + 3, noiseseed,  0, 1, 2, 3);
    PQCLEAN_MLKEM1024_AVX2_poly_getnoise_eta1_4x(e.vec + 0, e.vec + 1, e.vec + 2, e.vec + 3, noiseseed, 4, 5, 6, 7);

    PQCLEAN_MLKEM1024_AVX2_polyvec_ntt(&skpv);
    PQCLEAN_MLKEM1024_AVX2_polyvec_reduce(&skpv);
    PQCLEAN_MLKEM1024_AVX2_polyvec_ntt(&e);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM1024_AVX2_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        PQCLEAN_MLKEM1024_AVX2_poly_tomont(&pkpv.vec[i]);
    }

    PQCLEAN_MLKEM1024_AVX2_polyvec_add(&pkpv, &pkpv, &e);
    PQCLEAN_MLKEM1024_AVX2_polyvec_reduce(&pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

void PQCLEAN_MLKEM1024_AVX2_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                                       const uint8_t m[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                       const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    polyvec sp, pkpv, ep, at[KYBER_K], b;
    poly v, k, epp;

    unpack_pk(&pkpv, seed, pk);
    PQCLEAN_MLKEM1024_AVX2_poly_frommsg(&k, m);
    gen_at(at, seed);

    PQCLEAN_MLKEM1024_AVX2_poly_getnoise_eta1_4x(sp.vec + 0, sp.vec + 1, sp.vec + 2, sp.vec + 3, coins, 0, 1, 2, 3);
    PQCLEAN_MLKEM1024_AVX2_poly_getnoise_eta1_4x(ep.vec + 0, ep.vec + 1, ep.vec + 2, ep.vec + 3, coins, 4, 5, 6, 7);
    PQCLEAN_MLKEM1024_AVX2_poly_getnoise_eta2(&epp, coins, 8);

    PQCLEAN_MLKEM1024_AVX2_polyvec_ntt(&sp);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM1024_AVX2_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    }
    PQCLEAN_MLKEM1024_AVX2_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

    PQCLEAN_MLKEM1024_AVX2_polyvec_invntt_tomont(&b);
    PQCLEAN_MLKEM1024_AVX2_poly_invntt_tomont(&v);

    PQCLEAN_MLKEM1024_AVX2_polyvec_add(&b, &b, &ep);
    PQCLEAN_MLKEM1024_AVX2_poly_add(&v, &v, &epp);
    PQCLEAN_MLKEM1024_AVX2_poly_add(&v, &v, &k);
    PQCLEAN_MLKEM1024_AVX2_polyvec_reduce(&b);
    PQCLEAN_MLKEM1024_AVX2_poly_reduce(&v);

    pack_ciphertext(c, &b, &v);
}

void PQCLEAN_MLKEM1024_AVX2_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t c[KYBER_INDCPA_BYTES],
                                       const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec b, skpv;
    poly v, mp;

    unpack_ciphertext(&b, &v, c);
    unpack_sk(&skpv, sk);

    PQCLEAN_MLKEM1024_AVX2_polyvec_ntt(&b);
    PQCLEAN_MLKEM1024_AVX2_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    PQCLEAN_MLKEM1024_AVX2_poly_invntt_tomont(&mp);

    PQCLEAN_MLKEM1024_AVX2_poly_sub(&mp, &v, &mp);
    PQCLEAN_MLKEM1024_AVX2_poly_reduce(&mp);

    PQCLEAN_MLKEM1024_AVX2_poly_tomsg(m, &mp);
}