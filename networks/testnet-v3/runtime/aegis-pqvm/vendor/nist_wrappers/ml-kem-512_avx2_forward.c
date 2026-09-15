#include <stdint.h>

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int PQCLEAN_MLKEM512_AVX2_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
  return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
}

int PQCLEAN_MLKEM512_AVX2_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int PQCLEAN_MLKEM512_AVX2_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
}


