#ifndef PQCLEAN_MLKEM512_AARCH64_INDCPA_H
#define PQCLEAN_MLKEM512_AARCH64_INDCPA_H

/*
 * This file is licensed
 * under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.html) or
 * public domain at https://github.com/pq-crystals/
  
  mlkem =~  =~ /tree/master/ref
 */

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define gen_matrix MLKEM_NAMESPACE(gen_matrix)
void gen_matrix(int16_t a[MLKEM_K][MLKEM_K][MLKEM_N], const uint8_t seed[MLKEM_SYMBYTES], int transposed);
#define indcpa_keypair_derand MLKEM_NAMESPACE(indcpa_keypair_derand)
void indcpa_keypair_derand(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[MLKEM_SYMBYTES]);

#define indcpa_enc MLKEM_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[MLKEM_SYMBYTES]);

#define indcpa_dec MLKEM_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES]);

#endif
