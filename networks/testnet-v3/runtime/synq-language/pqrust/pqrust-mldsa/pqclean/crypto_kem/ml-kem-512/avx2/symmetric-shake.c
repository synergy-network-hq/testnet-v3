#include "fips202.h"
#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void PQCLEAN_MLKEM512_AVX2_kyber_shake128_absorb(xof_state *state,
        const uint8_t seed[KYBER_SYMBYTES],
        uint8_t x,
        uint8_t y) {
    uint8_t extseed[KYBER_SYMBYTES + 2];

    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;

    shake128_absorb(state, extseed, sizeof(extseed));
}

void PQCLEAN_MLKEM512_AVX2_kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 1];

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;

    shake256(out, outlen, extkey, sizeof(extkey));
}

void PQCLEAN_MLKEM512_AVX2_kyber_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    shake256incctx s;

    shake256_inc_init(&s);
    shake256_inc_absorb(&s, key, KYBER_SYMBYTES);
    shake256_inc_absorb(&s, input, KYBER_CIPHERTEXTBYTES);
    shake256_inc_finalize(&s);
    shake256_inc_squeeze(out, KYBER_SSBYTES, &s);
    shake256_inc_ctx_release(&s);
}