#include "shake_ds.h"

void PQCLEAN_HQC128_CLEAN_shake256_512_ds(shake256incctx *state, uint8_t *output, const uint8_t *input, size_t inlen, uint8_t domain) {

    shake256_inc_init(state);

    shake256_inc_absorb(state, input, inlen);

    shake256_inc_absorb(state, &domain, 1);

    shake256_inc_finalize(state);

    shake256_inc_squeeze(output, 512 / 8, state);

    shake256_inc_ctx_release(state);
}