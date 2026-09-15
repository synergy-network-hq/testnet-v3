#ifndef PQCLEAN_MLKEM512_AARCH64_PARAMS_H
#define PQCLEAN_MLKEM512_AARCH64_PARAMS_H

/*
 * This file is licensed
 * under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.html) or
 * public domain at https://github.com/pq-crystals/
  
  mlkem =~  =~ /tree/master/ref
 */

#define MLKEM_NAMESPACE(s) PQCLEAN_MLKEM512_AARCH64_##s

/* Don't change parameters below this line */
#define MLKEM_N 256
#define MLKEM_Q 3329

#define MLKEM_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define MLKEM_SSBYTES  32   /* size in bytes of shared key */

#define MLKEM_POLYBYTES     384
#define MLKEM_POLYVECBYTES  (MLKEM_K * MLKEM_POLYBYTES)

#define MLKEM_K 2
#define MLKEM_ETA1 3
#define MLKEM_POLYCOMPRESSEDBYTES    128
#define MLKEM_POLYVECCOMPRESSEDBYTES (MLKEM_K * 320)

#define MLKEM_ETA2 2

#define MLKEM_INDCPA_MSGBYTES       (MLKEM_SYMBYTES)
#define MLKEM_INDCPA_PUBLICKEYBYTES (MLKEM_POLYVECBYTES + MLKEM_SYMBYTES)
#define MLKEM_INDCPA_SECRETKEYBYTES (MLKEM_POLYVECBYTES)
#define MLKEM_INDCPA_BYTES          (MLKEM_POLYVECCOMPRESSEDBYTES + MLKEM_POLYCOMPRESSEDBYTES)

#define MLKEM_PUBLICKEYBYTES  (MLKEM_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define MLKEM_SECRETKEYBYTES  (MLKEM_INDCPA_SECRETKEYBYTES + MLKEM_INDCPA_PUBLICKEYBYTES + 2*MLKEM_SYMBYTES)
#define MLKEM_CIPHERTEXTBYTES (MLKEM_INDCPA_BYTES)

#endif
