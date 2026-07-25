#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define gen_matrix MLKEM_NAMESPACE(_gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[MLKEM_SYMBYTES], int transposed);
#define indcpa_keypair MLKEM_NAMESPACE(_indcpa_keypair)
void indcpa_keypair(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES]);

#define indcpa_enc MLKEM_NAMESPACE(_indcpa_enc)
void indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[MLKEM_SYMBYTES]);

#define indcpa_dec MLKEM_NAMESPACE(_indcpa_dec)
void indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES]);

#endif
