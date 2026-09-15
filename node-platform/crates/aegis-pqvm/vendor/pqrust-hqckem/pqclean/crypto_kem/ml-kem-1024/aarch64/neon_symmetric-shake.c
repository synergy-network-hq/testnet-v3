
#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "keccak2x/fips202x2.h"
#include "symmetric.h"

void neon_kyber_shake128_absorb(keccakx2_state *state,
                                const uint8_t seed[KYBER_SYMBYTES],
                                uint8_t x1, uint8_t x2,
                                uint8_t y1, uint8_t y2) {
    unsigned int i;
    uint8_t extseed1[KYBER_SYMBYTES + 2 + 6];
    uint8_t extseed2[KYBER_SYMBYTES + 2 + 6];

    for (i = 0; i < KYBER_SYMBYTES; i++) {
        extseed1[i] = seed[i];
        extseed2[i] = seed[i];
    }
    extseed1[KYBER_SYMBYTES  ] = x1;
    extseed1[KYBER_SYMBYTES + 1] = y1;

    extseed2[KYBER_SYMBYTES  ] = x2;
    extseed2[KYBER_SYMBYTES + 1] = y2;

    shake128x2_absorb(state, extseed1, extseed2, KYBER_SYMBYTES + 2);
}

void neon_kyber_shake256_prf(uint8_t *out1, uint8_t *out2,
                             size_t outlen,
                             const uint8_t key[KYBER_SYMBYTES],
                             uint8_t nonce1, uint8_t nonce2) {
    unsigned int i;
    uint8_t extkey1[KYBER_SYMBYTES + 1];
    uint8_t extkey2[KYBER_SYMBYTES + 1];

    for (i = 0; i < KYBER_SYMBYTES; i++) {
        extkey1[i] = key[i];
        extkey2[i] = key[i];
    }

    extkey1[i] = nonce1;
    extkey2[i] = nonce2;

    shake256x2(out1, out2, outlen, extkey1, extkey2, sizeof(extkey1));
}