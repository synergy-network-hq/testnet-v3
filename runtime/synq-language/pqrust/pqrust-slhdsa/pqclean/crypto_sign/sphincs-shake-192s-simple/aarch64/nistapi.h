#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define CRYPTO_ALGNAME "SPHINCS+"

#define CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES
#define CRYPTO_SEEDBYTES (3*SPX_N)

#define crypto_sign_secretkeybytes SPX_NAMESPACE(crypto_sign_secretkeybytes)
size_t crypto_sign_secretkeybytes(void);

#define crypto_sign_publickeybytes SPX_NAMESPACE(crypto_sign_publickeybytes)
size_t crypto_sign_publickeybytes(void);

#define crypto_sign_bytes SPX_NAMESPACE(crypto_sign_bytes)
size_t crypto_sign_bytes(void);

#define crypto_sign_seedbytes SPX_NAMESPACE(crypto_sign_seedbytes)
size_t crypto_sign_seedbytes(void);

#define crypto_sign_seed_keypair SPX_NAMESPACE(crypto_sign_seed_keypair)
int crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk,
                             const uint8_t *seed);

#define crypto_sign_keypair SPX_NAMESPACE(crypto_sign_keypair)
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

#define crypto_sign_signature SPX_NAMESPACE(crypto_sign_signature)
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk);

#define crypto_sign_verify SPX_NAMESPACE(crypto_sign_verify)
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk);

#define crypto_sign SPX_NAMESPACE(crypto_sign)
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);

#define crypto_sign_open SPX_NAMESPACE(crypto_sign_open)
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

#endif