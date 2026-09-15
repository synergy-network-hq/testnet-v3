#include "domains.h"
#include "fips202.h"
#include "shake_prng.h"

void PQCLEAN_HQC256_CLEAN_seedexpander_init(seedexpander_state *state, const uint8_t *seed, size_t seedlen) {
    uint8_t domain = SEEDEXPANDER_DOMAIN;
    shake256_inc_init(state);
    shake256_inc_absorb(state, seed, seedlen);
    shake256_inc_absorb(state, &domain, 1);
    shake256_inc_finalize(state);
}

void PQCLEAN_HQC256_CLEAN_seedexpander(seedexpander_state *state, uint8_t *output, size_t outlen) {
    const size_t bsize = sizeof(uint64_t);
    const size_t remainder = outlen % bsize;
    uint8_t tmp[sizeof(uint64_t)];
    shake256_inc_squeeze(output, outlen - remainder, state);
    if (remainder != 0) {
        shake256_inc_squeeze(tmp, bsize, state);
        output += outlen - remainder;
        for (uint8_t i = 0; i < remainder; i++) {
            output[i] = tmp[i];
        }
    }
}

void PQCLEAN_HQC256_CLEAN_seedexpander_release(seedexpander_state *state) {
    shake256_inc_ctx_release(state);
}