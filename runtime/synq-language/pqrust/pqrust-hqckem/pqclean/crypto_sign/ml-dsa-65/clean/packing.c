#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"

void PQCLEAN_MLDSA65_CLEAN_pack_pk(uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES],
                                   const uint8_t rho[SEEDBYTES],
                                   const polyveck *t1) {
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i) {
        pk[i] = rho[i];
    }
    pk += SEEDBYTES;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
    }
}

void PQCLEAN_MLDSA65_CLEAN_unpack_pk(uint8_t rho[SEEDBYTES],
                                     polyveck *t1,
                                     const uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES]) {
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i) {
        rho[i] = pk[i];
    }
    pk += SEEDBYTES;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
    }
}

void PQCLEAN_MLDSA65_CLEAN_pack_sk(uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES],
                                   const uint8_t rho[SEEDBYTES],
                                   const uint8_t tr[TRBYTES],
                                   const uint8_t key[SEEDBYTES],
                                   const polyveck *t0,
                                   const polyvecl *s1,
                                   const polyveck *s2) {
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i) {
        sk[i] = rho[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i) {
        sk[i] = key[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i) {
        sk[i] = tr[i];
    }
    sk += TRBYTES;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s1->vec[i]);
    }
    sk += L * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s2->vec[i]);
    }
    sk += K * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
    }
}

void PQCLEAN_MLDSA65_CLEAN_unpack_sk(uint8_t rho[SEEDBYTES],
                                     uint8_t tr[TRBYTES],
                                     uint8_t key[SEEDBYTES],
                                     polyveck *t0,
                                     polyvecl *s1,
                                     polyveck *s2,
                                     const uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES]) {
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i) {
        rho[i] = sk[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i) {
        key[i] = sk[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i) {
        tr[i] = sk[i];
    }
    sk += TRBYTES;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyeta_unpack(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES);
    }
    sk += L * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyeta_unpack(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES);
    }
    sk += K * POLYETA_PACKEDBYTES;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
    }
}

void PQCLEAN_MLDSA65_CLEAN_pack_sig(uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES],
                                    const uint8_t c[CTILDEBYTES],
                                    const polyvecl *z,
                                    const polyveck *h) {
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES; ++i) {
        sig[i] = c[i];
    }
    sig += CTILDEBYTES;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyz_pack(sig + i * POLYZ_PACKEDBYTES, &z->vec[i]);
    }
    sig += L * POLYZ_PACKEDBYTES;

    for (i = 0; i < OMEGA + K; ++i) {
        sig[i] = 0;
    }

    k = 0;
    for (i = 0; i < K; ++i) {
        for (j = 0; j < N; ++j) {
            if (h->vec[i].coeffs[j] != 0) {
                sig[k++] = (uint8_t) j;
            }
        }

        sig[OMEGA + i] = (uint8_t) k;
    }
}

int PQCLEAN_MLDSA65_CLEAN_unpack_sig(uint8_t c[CTILDEBYTES],
                                     polyvecl *z,
                                     polyveck *h,
                                     const uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES]) {
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES; ++i) {
        c[i] = sig[i];
    }
    sig += CTILDEBYTES;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyz_unpack(&z->vec[i], sig + i * POLYZ_PACKEDBYTES);
    }
    sig += L * POLYZ_PACKEDBYTES;

    k = 0;
    for (i = 0; i < K; ++i) {
        for (j = 0; j < N; ++j) {
            h->vec[i].coeffs[j] = 0;
        }

        if (sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA) {
            return 1;
        }

        for (j = k; j < sig[OMEGA + i]; ++j) {

            if (j > k && sig[j] <= sig[j - 1]) {
                return 1;
            }
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[OMEGA + i];
    }

    for (j = k; j < OMEGA; ++j) {
        if (sig[j]) {
            return 1;
        }
    }

    return 0;
}