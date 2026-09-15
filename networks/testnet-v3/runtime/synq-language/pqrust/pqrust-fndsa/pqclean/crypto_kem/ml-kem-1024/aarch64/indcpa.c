
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "rejsample.h"
#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"

#include "NTT_params.h"
#include "ntt.h"

static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    int16_t pk[KYBER_K][KYBER_N],
                    const uint8_t seed[KYBER_SYMBYTES]) {
    polyvec_tobytes(r, pk);
    memcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

static void unpack_pk(int16_t pk[KYBER_K][KYBER_N],
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
    polyvec_frombytes(pk, packedpk);
    memcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], int16_t sk[KYBER_K][KYBER_N]) {
    polyvec_tobytes(r, sk);
}

static void unpack_sk(int16_t sk[KYBER_K][KYBER_N], const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec_frombytes(sk, packedsk);
}

static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], int16_t b[KYBER_K][KYBER_N], int16_t *v) {
    polyvec_compress(r, b);
    poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void unpack_ciphertext(int16_t b[KYBER_K][KYBER_N], int16_t *v, const uint8_t c[KYBER_INDCPA_BYTES]) {
    polyvec_decompress(b, c);
    poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

void gen_matrix(int16_t a[KYBER_K][KYBER_K][KYBER_N], const uint8_t seed[KYBER_SYMBYTES], int transposed) {
    unsigned int ctr0, ctr1, k;
    unsigned int buflen, off;
    uint8_t buf0[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2],
            buf1[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
    neon_xof_state state;

    for (unsigned int i = 0; i < KYBER_K; i++) {
        for (unsigned int j = 0; j < KYBER_K; j += 2) {
            if (transposed) {
                neon_xof_absorb(&state, seed, i, i, j, j + 1);
            } else {
                neon_xof_absorb(&state, seed, j, j + 1, i, i);
            }

            neon_xof_squeezeblocks(buf0, buf1, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr0 = neon_rej_uniform(&(a[i][j][0]), buf0);
            ctr1 = neon_rej_uniform(&(a[i][j + 1][0]), buf1);

            while (ctr0 < KYBER_N || ctr1 < KYBER_N) {
                off = buflen % 3;
                for (k = 0; k < off; k++) {
                    buf0[k] = buf0[buflen - off + k];
                    buf1[k] = buf1[buflen - off + k];
                }
                neon_xof_squeezeblocks(buf0 + off, buf1 + off, 1, &state);

                buflen = off + XOF_BLOCKBYTES;
                ctr0 += rej_uniform(&(a[i][j][0]) + ctr0, KYBER_N - ctr0, buf0, buflen);
                ctr1 += rej_uniform(&(a[i][j + 1][0]) + ctr1, KYBER_N - ctr1, buf1, buflen);
            }
        }
    }
}

void indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    int16_t a[KYBER_K][KYBER_K][KYBER_N];
    int16_t e[KYBER_K][KYBER_N];
    int16_t pkpv[KYBER_K][KYBER_N];
    int16_t skpv[KYBER_K][KYBER_N];
    int16_t skpv_asymmetric[KYBER_K][KYBER_N >> 1];

    memcpy(buf, coins, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = KYBER_K;
    hash_g(buf, buf, KYBER_SYMBYTES + 1);

    gen_a(a, publicseed);

    neon_poly_getnoise_eta1_2x(&(skpv[0][0]), &(skpv[1][0]), noiseseed, 0, 1);
    neon_poly_getnoise_eta1_2x(&(skpv[2][0]), &(skpv[3][0]), noiseseed, 2, 3);
    neon_poly_getnoise_eta1_2x(&(e[0][0]), &(e[1][0]), noiseseed, 4, 5);
    neon_poly_getnoise_eta1_2x(&(e[2][0]), &(e[3][0]), noiseseed, 6, 7);

    neon_polyvec_ntt(skpv);
    neon_polyvec_ntt(e);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM1024_AARCH64__asm_point_mul_extended(&(skpv_asymmetric[i][0]), &(skpv[i][0]), pre_asymmetric_table_Q1_extended, asymmetric_const);
    }

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM1024_AARCH64__asm_asymmetric_mul_montgomery(&(a[i][0][0]), &(skpv[0][0]), &(skpv_asymmetric[0][0]), asymmetric_const, pkpv[i]);
    }

    neon_polyvec_add_reduce(pkpv, e);

    pack_sk(sk, skpv);
    pack_pk(pk, pkpv, publicseed);
}

void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    int16_t at[KYBER_K][KYBER_K][KYBER_N];
    int16_t sp[KYBER_K][KYBER_N];
    int16_t sp_asymmetric[KYBER_K][KYBER_N >> 1];
    int16_t pkpv[KYBER_K][KYBER_N];
    int16_t ep[KYBER_K][KYBER_N];
    int16_t b[KYBER_K][KYBER_N];
    int16_t v[KYBER_N];
    int16_t k[KYBER_N];
    int16_t epp[KYBER_N];

    unpack_pk(pkpv, seed, pk);
    poly_frommsg(k, m);
    gen_at(at, seed);

    neon_poly_getnoise_eta1_2x(&(sp[0][0]), &(sp[1][0]), coins, 0, 1);
    neon_poly_getnoise_eta1_2x(&(sp[2][0]), &(sp[3][0]), coins, 2, 3);
    neon_poly_getnoise_eta1_2x(&(ep[0][0]), &(ep[1][0]), coins, 4, 5);
    neon_poly_getnoise_eta1_2x(&(ep[2][0]), &(ep[3][0]), coins, 6, 7);
    neon_poly_getnoise_eta2(&(epp[0]), coins, 8);

    neon_polyvec_ntt(sp);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM1024_AARCH64__asm_point_mul_extended(&(sp_asymmetric[i][0]), &(sp[i][0]), pre_asymmetric_table_Q1_extended, asymmetric_const);
    }

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM1024_AARCH64__asm_asymmetric_mul(&(at[i][0][0]), &(sp[0][0]), &(sp_asymmetric[0][0]), asymmetric_const, b[i]);
    }

    PQCLEAN_MLKEM1024_AARCH64__asm_asymmetric_mul(&(pkpv[0][0]), &(sp[0][0]), &(sp_asymmetric[0][0]), asymmetric_const, v);

    neon_polyvec_invntt_to_mont(b);
    invntt(v);

    neon_polyvec_add_reduce(b, ep);

    neon_poly_add_add_reduce(v, epp, k);

    pack_ciphertext(c, b, v);
}

void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    unsigned int i;
    int16_t b[KYBER_K][KYBER_N];
    int16_t b_asymmetric[KYBER_K][KYBER_N >> 1];
    int16_t skpv[KYBER_K][KYBER_N];
    int16_t v[KYBER_N];
    int16_t mp[KYBER_N];

    unpack_ciphertext(b, v, c);
    unpack_sk(skpv, sk);

    neon_polyvec_ntt(b);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM1024_AARCH64__asm_point_mul_extended(&(b_asymmetric[i][0]), &(b[i][0]), pre_asymmetric_table_Q1_extended, asymmetric_const);
    }

    PQCLEAN_MLKEM1024_AARCH64__asm_asymmetric_mul(&(skpv[0][0]), &(b[0][0]), &(b_asymmetric[0][0]), asymmetric_const, mp);

    invntt(mp);

    neon_poly_sub_reduce(v, mp);

    poly_tomsg(m, v);
}