#ifndef PQCLEAN_HQC192_CLEAN_API_H
#define PQCLEAN_HQC192_CLEAN_API_H

#include <stdint.h>

#define PQCLEAN_HQC192_CLEAN_CRYPTO_ALGNAME                      "HQC-192"

#define PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES               4586
#define PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES               4522
#define PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES                        64
#define PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES              8978

int PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int PQCLEAN_HQC192_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int PQCLEAN_HQC192_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif