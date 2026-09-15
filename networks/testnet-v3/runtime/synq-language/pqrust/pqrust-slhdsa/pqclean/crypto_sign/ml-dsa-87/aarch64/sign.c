
#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "sign.h"
#include "symmetric.h"
#include <stdint.h>

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    randombytes(seedbuf, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = K;
    seedbuf[SEEDBYTES + 1] = L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);

    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    polyvec_matrix_expand(mat, rho);

    polyvecl_uniform_eta(&s1, rhoprime, 0);
    polyveck_uniform_eta(&s2, rhoprime, L);

    s1hat = s1;
    polyvecl_ntt(&s1hat);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);

    polyveck_add(&t1, &t1, &s2);

    polyveck_caddq(&t1);
    polyveck_power2round(&t1, &t0, &t1);
    pack_pk(pk, rho, &t1);

    shake256(tr, TRBYTES, pk, DILITHIUM_CRYPTO_PUBLICKEYBYTES);
    pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

int crypto_sign_signature_ctx(uint8_t *sig,
                              size_t *siglen,
                              const uint8_t *m,
                              size_t mlen,
                              const uint8_t *ctx,
                              size_t ctxlen,
                              const uint8_t *sk) {
    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    if (ctxlen > 255) {
        return -1;
    }

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + RNDBYTES;
    rhoprime = mu + CRHBYTES;
    unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    mu[0] = 0;
    mu[1] = ctxlen;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    randombytes(rnd, RNDBYTES);
    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

    polyvec_matrix_expand(mat, rho);
    polyvecl_ntt(&s1);
    polyveck_ntt(&s2);
    polyveck_ntt(&t0);

rej:

    polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    z = y;
    polyvecl_ntt(&z);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);

    polyveck_caddq(&w1);
    polyveck_decompose(&w1, &w0, &w1);
    polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    poly_challenge(&cp, sig);
    poly_ntt(&cp);

    polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    polyvecl_invntt_tomont(&z);
    polyvecl_add(&z, &z, &y);
    polyvecl_reduce(&z);
    if (polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej;
    }

    polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    polyveck_invntt_tomont(&h);
    polyveck_sub(&w0, &w0, &h);
    polyveck_reduce(&w0);
    if (polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej;
    }

    polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    polyveck_invntt_tomont(&h);
    polyveck_reduce(&h);
    if (polyveck_chknorm(&h, GAMMA2)) {
        goto rej;
    }

    polyveck_add(&w0, &w0, &h);
    n = polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        goto rej;
    }

    pack_sig(sig, sig, &z, &h);
    *siglen = DILITHIUM_CRYPTO_BYTES;
    return 0;
}

int crypto_sign_ctx(uint8_t *sm,
                    size_t *smlen,
                    const uint8_t *m,
                    size_t mlen,
                    const uint8_t *ctx,
                    size_t ctxlen,
                    const uint8_t *sk) {
    int ret;
    size_t i;

    for (i = 0; i < mlen; ++i) {
        sm[DILITHIUM_CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    }
    ret = crypto_sign_signature_ctx(sm, smlen, sm + DILITHIUM_CRYPTO_BYTES, mlen, ctx, ctxlen, sk);
    *smlen += mlen;
    return ret;
}

int crypto_sign_verify_ctx(const uint8_t *sig,
                           size_t siglen,
                           const uint8_t *m,
                           size_t mlen,
                           const uint8_t *ctx,
                           size_t ctxlen,
                           const uint8_t *pk) {
    unsigned int i;
    uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES];
    uint8_t c2[CTILDEBYTES];
    poly cp;
    polyvecl mat[K], z;
    polyveck t1, w1, h;
    shake256incctx state;

    if (ctxlen > 255 || siglen != DILITHIUM_CRYPTO_BYTES) {
        return -1;
    }

    unpack_pk(rho, &t1, pk);
    if (unpack_sig(c, &z, &h, sig)) {
        return -1;
    }
    if (polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        return -1;
    }

    shake256(mu, TRBYTES, pk, DILITHIUM_CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, TRBYTES);
    mu[0] = 0;
    mu[1] = ctxlen;
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    poly_challenge(&cp, c);
    polyvec_matrix_expand(mat, rho);

    polyvecl_ntt(&z);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    poly_ntt(&cp);
    polyveck_shiftl(&t1);
    polyveck_ntt(&t1);
    polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    polyveck_sub(&w1, &w1, &t1);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);

    polyveck_caddq(&w1);
    polyveck_use_hint(&w1, &w1, &h);
    polyveck_pack_w1(buf, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    for (i = 0; i < CTILDEBYTES; ++i) {
        if (c[i] != c2[i]) {
            return -1;
        }
    }

    return 0;
}

int crypto_sign_open_ctx(uint8_t *m,
                         size_t *mlen,
                         const uint8_t *sm,
                         size_t smlen,
                         const uint8_t *ctx,
                         size_t ctxlen,
                         const uint8_t *pk) {
    size_t i;

    if (smlen < DILITHIUM_CRYPTO_BYTES) {
        goto badsig;
    }

    *mlen = smlen - DILITHIUM_CRYPTO_BYTES;
    if (crypto_sign_verify_ctx(sm, DILITHIUM_CRYPTO_BYTES, sm + DILITHIUM_CRYPTO_BYTES, *mlen, ctx, ctxlen, pk)) {
        goto badsig;
    } else {

        for (i = 0; i < *mlen; ++i) {
            m[i] = sm[DILITHIUM_CRYPTO_BYTES + i];
        }
        return 0;
    }

badsig:

    *mlen = 0;
    for (i = 0; i < smlen; ++i) {
        m[i] = 0;
    }

    return -1;
}

int PQCLEAN_MLDSA87_AARCH64_crypto_sign_signature(uint8_t *sig,
        size_t *siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *sk) {
    return PQCLEAN_MLDSA87_AARCH64_crypto_sign_signature_ctx(sig, siglen, m, mlen, NULL, 0, sk);
}

int PQCLEAN_MLDSA87_AARCH64_crypto_sign(uint8_t *sm,
                                        size_t *smlen,
                                        const uint8_t *m,
                                        size_t mlen,
                                        const uint8_t *sk) {
    return PQCLEAN_MLDSA87_AARCH64_crypto_sign_ctx(sm, smlen, m, mlen, NULL, 0, sk);
}

int PQCLEAN_MLDSA87_AARCH64_crypto_sign_verify(const uint8_t *sig,
        size_t siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *pk) {
    return PQCLEAN_MLDSA87_AARCH64_crypto_sign_verify_ctx(sig, siglen, m, mlen, NULL, 0, pk);
}

int PQCLEAN_MLDSA87_AARCH64_crypto_sign_open(uint8_t *m,
        size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk) {
    return PQCLEAN_MLDSA87_AARCH64_crypto_sign_open_ctx(m, mlen, sm, smlen, NULL, 0, pk);
}