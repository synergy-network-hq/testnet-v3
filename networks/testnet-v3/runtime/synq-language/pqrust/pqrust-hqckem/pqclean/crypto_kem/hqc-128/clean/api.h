#ifndef PQCLEAN_HQC128_CLEAN_API_H
#define PQCLEAN_HQC128_CLEAN_API_H

#include <stdint.h>

#define PQCLEAN_HQC128_CLEAN_CRYPTO_ALGNAME                      "HQC-128"

#define PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES               2305
#define PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES               2249
#define PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES                        64
#define PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES              4433

int PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int PQCLEAN_HQC128_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int PQCLEAN_HQC128_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif