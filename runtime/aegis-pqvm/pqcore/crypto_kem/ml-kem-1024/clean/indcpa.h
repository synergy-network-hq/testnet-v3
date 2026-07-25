#ifndef PQCLEAN_MLKEM1024_CLEAN_INDCPA_H
#define PQCLEAN_MLKEM1024_CLEAN_INDCPA_H
#include "params.h"
#include "polyvec.h"
#include <stdint.h>

void PQCLEAN_MLKEM1024_CLEAN_gen_matrix(polyvec *a, const uint8_t seed[MLKEM_SYMBYTES], int transposed);

void PQCLEAN_MLKEM1024_CLEAN_indcpa_keypair_derand(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
        uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[MLKEM_SYMBYTES]);

void PQCLEAN_MLKEM1024_CLEAN_indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],
                                        const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                                        const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                                        const uint8_t coins[MLKEM_SYMBYTES]);

void PQCLEAN_MLKEM1024_CLEAN_indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
                                        const uint8_t c[MLKEM_INDCPA_BYTES],
                                        const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES]);

#endif
