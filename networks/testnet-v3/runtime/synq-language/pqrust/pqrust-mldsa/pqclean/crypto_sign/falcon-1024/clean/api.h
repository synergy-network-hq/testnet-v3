#ifndef PQCLEAN_FALCON1024_CLEAN_API_H
#define PQCLEAN_FALCON1024_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES   2305
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES   1793
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES            1462

#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_ALGNAME          "Falcon-1024"

#define PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES      1280 

int PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk);

int PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

int PQCLEAN_FALCON1024_CLEAN_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif