#ifndef PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_API_H
#define PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_ALGNAME "SPHINCS+-shake-192f-simple"

#define PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES 96
#define PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES 48
#define PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_BYTES          35664

#define PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_CRYPTO_SEEDBYTES      72

size_t PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_secretkeybytes(void);

size_t PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_publickeybytes(void);

size_t PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_bytes(void);

size_t PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_seedbytes(void);

int PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk,
        const uint8_t *seed);

int PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

int PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int PQCLEAN_SPHINCSSHAKE192FSIMPLE_AVX2_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);
#endif