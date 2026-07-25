#include "indcpa.h"
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes(r, pk);
    memcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_frombytes(pk, packedpk);
    memcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_frombytes(sk, packedsk);
}

static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_compress(r, b);
    PQCLEAN_MLKEM512_CLEAN_poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_decompress(b, c);
    PQCLEAN_MLKEM512_CLEAN_poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
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

#define gen_a(A,B)  PQCLEAN_MLKEM512_CLEAN_gen_matrix(A,B,0)
#define gen_at(A,B) PQCLEAN_MLKEM512_CLEAN_gen_matrix(A,B,1)

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

void PQCLEAN_MLKEM512_CLEAN_gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed) {
    unsigned int ctr, i, j;
    unsigned int buflen;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_K; j++) {
            if (transposed) {
                xof_absorb(&state, seed, (uint8_t)i, (uint8_t)j);
            } else {
                xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);
            }

            xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

            while (ctr < KYBER_N) {
                xof_squeezeblocks(buf, 1, &state);
                buflen = XOF_BLOCKBYTES;
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
            }
            xof_ctx_release(&state);
        }
    }
}

void PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[KYBER_K], e, pkpv, skpv;

    memcpy(buf, coins, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = KYBER_K;
    hash_g(buf, buf, KYBER_SYMBYTES + 1);

    gen_a(a, publicseed);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    }
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
    }

    PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&skpv);
    PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&e);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        PQCLEAN_MLKEM512_CLEAN_poly_tomont(&pkpv.vec[i]);
    }

    PQCLEAN_MLKEM512_CLEAN_polyvec_add(&pkpv, &pkpv, &e);
    PQCLEAN_MLKEM512_CLEAN_polyvec_reduce(&pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

void PQCLEAN_MLKEM512_CLEAN_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                                       const uint8_t m[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                       const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[KYBER_K], b;
    poly v, k, epp;

    unpack_pk(&pkpv, seed, pk);
    PQCLEAN_MLKEM512_CLEAN_poly_frommsg(&k, m);
    gen_at(at, seed);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(sp.vec + i, coins, nonce++);
    }
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta2(ep.vec + i, coins, nonce++);
    }
    PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta2(&epp, coins, nonce++);

    PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&sp);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    }

    PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

    PQCLEAN_MLKEM512_CLEAN_polyvec_invntt_tomont(&b);
    PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&v);

    PQCLEAN_MLKEM512_CLEAN_polyvec_add(&b, &b, &ep);
    PQCLEAN_MLKEM512_CLEAN_poly_add(&v, &v, &epp);
    PQCLEAN_MLKEM512_CLEAN_poly_add(&v, &v, &k);
    PQCLEAN_MLKEM512_CLEAN_polyvec_reduce(&b);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&v);

    pack_ciphertext(c, &b, &v);
}

void PQCLEAN_MLKEM512_CLEAN_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t c[KYBER_INDCPA_BYTES],
                                       const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec b, skpv;
    poly v, mp;

    unpack_ciphertext(&b, &v, c);
    unpack_sk(&skpv, sk);

    PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&b);
    PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&mp);

    PQCLEAN_MLKEM512_CLEAN_poly_sub(&mp, &v, &mp);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&mp);

    PQCLEAN_MLKEM512_CLEAN_poly_tomsg(m, &mp);
}