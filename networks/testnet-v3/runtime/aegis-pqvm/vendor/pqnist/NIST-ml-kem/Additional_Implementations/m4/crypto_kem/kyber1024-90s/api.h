#ifndef API_H
#define API_H

#include "params.h"

#define CRYPTO_SECRETKEYBYTES  MLKEM_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  MLKEM_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES MLKEM_CIPHERTEXTBYTES
#define CRYPTO_BYTES           MLKEM_SSBYTES

#define CRYPTO_ALGNAME "MLKEM1024"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
