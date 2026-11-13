#ifndef PQCLEAN_HQC256_CLEAN_API_H
#define PQCLEAN_HQC256_CLEAN_API_H

#include <stdint.h>

#define PQCLEAN_HQC256_CLEAN_CRYPTO_ALGNAME                      "HQC-256"

#define PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES               7317
#define PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES               7245
#define PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES                        64
#define PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES              14421

int PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int PQCLEAN_HQC256_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int PQCLEAN_HQC256_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif