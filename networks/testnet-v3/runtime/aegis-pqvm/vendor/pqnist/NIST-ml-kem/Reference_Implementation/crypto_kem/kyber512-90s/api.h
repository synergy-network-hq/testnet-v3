#ifndef API_H
#define API_H

#include "params.h"

#define CRYPTO_SECRETKEYBYTES  MLKEM_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  MLKEM_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES MLKEM_CIPHERTEXTBYTES
#define CRYPTO_BYTES           MLKEM_SSBYTES

#if   (MLKEM_K == 2)
#ifdef MLKEM_90S
#define CRYPTO_ALGNAME "MLKEM512-90s"
#else
#define CRYPTO_ALGNAME "MLKEM512"
#endif
#elif (MLKEM_K == 3)
#ifdef MLKEM_90S
#define CRYPTO_ALGNAME "MLKEM768-90s"
#else
#define CRYPTO_ALGNAME "MLKEM768"
#endif
#elif (MLKEM_K == 4)
#ifdef MLKEM_90S
#define CRYPTO_ALGNAME "MLKEM1024-90s"
#else
#define CRYPTO_ALGNAME "MLKEM1024"
#endif
#endif

#define crypto_kem_keypair MLKEM_NAMESPACE(_keypair)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_kem_enc MLKEM_NAMESPACE(_enc)
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

#define crypto_kem_dec MLKEM_NAMESPACE(_dec)
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

#endif
