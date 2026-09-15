
#include <stddef.h>
#include <string.h>

#include "api.h"
#include "inner.h"

#define NONCELEN   40

#include "randombytes.h"

int
PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk) {
    union {
        uint8_t b[28 * FALCON_N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[FALCON_N], g[FALCON_N], F[FALCON_N];
    uint16_t h[FALCON_N];
    unsigned char seed[48];
    inner_shake256_context rng;
    size_t u, v;

    randombytes(seed, sizeof seed);
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, sizeof seed);
    inner_shake256_flip(&rng);
    PQCLEAN_FALCONPADDED512_AARCH64_keygen(&rng, f, g, F, NULL, h, FALCON_LOGN, tmp.b);
    inner_shake256_ctx_release(&rng);

    sk[0] = 0x50 + FALCON_LOGN;
    u = 1;
    v = PQCLEAN_FALCONPADDED512_AARCH64_trim_i8_encode(
            sk + u, PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES - u,
            f, PQCLEAN_FALCONPADDED512_AARCH64_max_fg_bits[FALCON_LOGN]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCONPADDED512_AARCH64_trim_i8_encode(
            sk + u, PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES - u,
            g, PQCLEAN_FALCONPADDED512_AARCH64_max_fg_bits[FALCON_LOGN]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCONPADDED512_AARCH64_trim_i8_encode(
            sk + u, PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES - u,
            F, PQCLEAN_FALCONPADDED512_AARCH64_max_FG_bits[FALCON_LOGN]);
    if (v == 0) {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }

    pk[0] = 0x00 + FALCON_LOGN;
    v = PQCLEAN_FALCONPADDED512_AARCH64_modq_encode(
            pk + 1, PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_PUBLICKEYBYTES - 1,
            h, FALCON_LOGN);
    if (v != PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }

    return 0;
}

static int
do_sign(uint8_t *nonce, uint8_t *sigbuf, size_t sigbuflen,
        const uint8_t *m, size_t mlen, const uint8_t *sk) {
    union {
        uint8_t b[72 * FALCON_N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[FALCON_N], g[FALCON_N], F[FALCON_N], G[FALCON_N];
    struct {
        int16_t sig[FALCON_N];
        uint16_t hm[FALCON_N];
    } r;
    unsigned char seed[48];
    inner_shake256_context sc;
    size_t u, v;

    if (sk[0] != 0x50 + FALCON_LOGN) {
        return -1;
    }
    u = 1;
    v = PQCLEAN_FALCONPADDED512_AARCH64_trim_i8_decode(
            f, PQCLEAN_FALCONPADDED512_AARCH64_max_fg_bits[FALCON_LOGN],
            sk + u, PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCONPADDED512_AARCH64_trim_i8_decode(
            g, PQCLEAN_FALCONPADDED512_AARCH64_max_fg_bits[FALCON_LOGN],
            sk + u, PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCONPADDED512_AARCH64_trim_i8_decode(
            F, PQCLEAN_FALCONPADDED512_AARCH64_max_FG_bits[FALCON_LOGN],
            sk + u, PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }
    if (!PQCLEAN_FALCONPADDED512_AARCH64_complete_private(G, f, g, F, tmp.b)) {
        return -1;
    }

    randombytes(nonce, NONCELEN);

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCONPADDED512_AARCH64_hash_to_point_ct(&sc, r.hm, FALCON_LOGN, tmp.b);
    inner_shake256_ctx_release(&sc);

    randombytes(seed, sizeof seed);
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, seed, sizeof seed);
    inner_shake256_flip(&sc);

    for (;;) {
        PQCLEAN_FALCONPADDED512_AARCH64_sign_dyn(r.sig, &sc, f, g, F, G, r.hm, tmp.b);
        v = PQCLEAN_FALCONPADDED512_AARCH64_comp_encode(sigbuf, sigbuflen, r.sig);
        if (v != 0) {
            inner_shake256_ctx_release(&sc);
            memset(sigbuf + v, 0, sigbuflen - v);
            return 0;
        }
    }
}

static int
do_verify(
    const uint8_t *nonce, const uint8_t *sigbuf, size_t sigbuflen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    union {
        uint8_t b[2 * FALCON_N];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int16_t h[FALCON_N];
    int16_t hm[FALCON_N];
    int16_t sig[FALCON_N];
    inner_shake256_context sc;
    size_t v;

    if (pk[0] != 0x00 + FALCON_LOGN) {
        return -1;
    }
    if (PQCLEAN_FALCONPADDED512_AARCH64_modq_decode( (uint16_t *) h,
            pk + 1, PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_PUBLICKEYBYTES - 1, FALCON_LOGN)
            != PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }

    if (sigbuflen == 0) {
        return -1;
    }

    v = PQCLEAN_FALCONPADDED512_AARCH64_comp_decode(sig, sigbuf, sigbuflen);
    if (v == 0) {
        return -1;
    }
    if (v != sigbuflen) {
        if (sigbuflen == PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES - NONCELEN - 1) {
            while (v < sigbuflen) {
                if (sigbuf[v++] != 0) {
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }

    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCONPADDED512_AARCH64_hash_to_point_ct(&sc, (uint16_t *) hm, FALCON_LOGN, tmp.b);
    inner_shake256_ctx_release(&sc);

    if (!PQCLEAN_FALCONPADDED512_AARCH64_verify_raw(hm, sig, h, (int16_t *) tmp.b)) {
        return -1;
    }
    return 0;
}

int
PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk) {
    size_t vlen;

    vlen = PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES - NONCELEN - 1;
    if (do_sign(sig + 1, sig + 1 + NONCELEN, vlen, m, mlen, sk) < 0) {
        return -1;
    }
    sig[0] = 0x30 + FALCON_LOGN;
    *siglen = 1 + NONCELEN + vlen;
    return 0;
}

int
PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    if (siglen < 1 + NONCELEN) {
        return -1;
    }
    if (sig[0] != 0x30 + FALCON_LOGN) {
        return -1;
    }
    return do_verify(sig + 1,
                     sig + 1 + NONCELEN, siglen - 1 - NONCELEN, m, mlen, pk);
}

int
PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk) {
    uint8_t *sigbuf;
    size_t sigbuflen;

    memmove(sm + PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES, m, mlen);
    sigbuf = sm + 1 + NONCELEN;
    sigbuflen = PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES - NONCELEN - 1;
    if (do_sign(sm + 1, sigbuf, sigbuflen, m, mlen, sk) < 0) {
        return -1;
    }
    sm[0] = 0x30 + FALCON_LOGN;
    sigbuflen ++;
    *smlen = mlen + NONCELEN + sigbuflen;
    return 0;
}

int
PQCLEAN_FALCONPADDED512_AARCH64_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk) {
    const uint8_t *sigbuf;
    size_t pmlen, sigbuflen;

    if (smlen < PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES) {
        return -1;
    }
    sigbuflen = PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES - NONCELEN - 1;
    pmlen = smlen - PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES;
    if (sm[0] != 0x30 + FALCON_LOGN) {
        return -1;
    }
    sigbuf = sm + 1 + NONCELEN;

    if (do_verify(sm + 1, sigbuf, sigbuflen,
                  sm + PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES, pmlen, pk) < 0) {
        return -1;
    }

    memmove(m, sm + PQCLEAN_FALCONPADDED512_AARCH64_CRYPTO_BYTES, pmlen);
    *mlen = pmlen;
    return 0;
}