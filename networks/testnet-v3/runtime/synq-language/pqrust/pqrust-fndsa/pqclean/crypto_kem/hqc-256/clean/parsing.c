#include "parameters.h"
#include "parsing.h"
#include "vector.h"
#include <stdint.h>
#include <string.h>

static uint64_t load8(const uint8_t *in) {
    uint64_t ret = in[7];

    for (int8_t i = 6; i >= 0; --i) {
        ret <<= 8;
        ret |= in[i];
    }

    return ret;
}

void PQCLEAN_HQC256_CLEAN_load8_arr(uint64_t *out64, size_t outlen, const uint8_t *in8, size_t inlen) {
    size_t index_in = 0;
    size_t index_out = 0;

    if (inlen >= 8 && outlen >= 1) {
        while (index_out < outlen && index_in + 8 <= inlen) {
            out64[index_out] = load8(in8 + index_in);

            index_in += 8;
            index_out += 1;
        }
    }

    if (index_in >= inlen || index_out >= outlen) {
        return;
    }
    out64[index_out] = in8[inlen - 1];
    for (int8_t i = (int8_t)(inlen - index_in) - 2; i >= 0; --i) {
        out64[index_out] <<= 8;
        out64[index_out] |= in8[index_in + i];
    }
}

void PQCLEAN_HQC256_CLEAN_store8_arr(uint8_t *out8, size_t outlen, const uint64_t *in64, size_t inlen) {
    for (size_t index_out = 0, index_in = 0; index_out < outlen && index_in < inlen;) {
        out8[index_out] = (in64[index_in] >> ((index_out % 8) * 8)) & 0xFF;
        ++index_out;
        if (index_out % 8 == 0) {
            ++index_in;
        }
    }
}

void PQCLEAN_HQC256_CLEAN_hqc_secret_key_to_string(uint8_t *sk, const uint8_t *sk_seed, const uint8_t *sigma, const uint8_t *pk) {
    memcpy(sk, sk_seed, SEED_BYTES);
    memcpy(sk + SEED_BYTES, sigma, VEC_K_SIZE_BYTES);
    memcpy(sk + SEED_BYTES + VEC_K_SIZE_BYTES, pk, PUBLIC_KEY_BYTES);
}

void PQCLEAN_HQC256_CLEAN_hqc_secret_key_from_string(uint64_t *x, uint64_t *y, uint8_t *sigma, uint8_t *pk, const uint8_t *sk) {
    seedexpander_state sk_seedexpander;

    memcpy(sigma, sk + SEED_BYTES, VEC_K_SIZE_BYTES);
    PQCLEAN_HQC256_CLEAN_seedexpander_init(&sk_seedexpander, sk, SEED_BYTES);

    PQCLEAN_HQC256_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, x, PARAM_OMEGA);
    PQCLEAN_HQC256_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, y, PARAM_OMEGA);
    memcpy(pk, sk + SEED_BYTES + VEC_K_SIZE_BYTES, PUBLIC_KEY_BYTES);

    PQCLEAN_HQC256_CLEAN_seedexpander_release(&sk_seedexpander);
}

void PQCLEAN_HQC256_CLEAN_hqc_public_key_to_string(uint8_t *pk, const uint8_t *pk_seed, const uint64_t *s) {
    memcpy(pk, pk_seed, SEED_BYTES);
    PQCLEAN_HQC256_CLEAN_store8_arr(pk + SEED_BYTES, VEC_N_SIZE_BYTES, s, VEC_N_SIZE_64);
}

void PQCLEAN_HQC256_CLEAN_hqc_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk) {
    seedexpander_state pk_seedexpander;

    PQCLEAN_HQC256_CLEAN_seedexpander_init(&pk_seedexpander, pk, SEED_BYTES);
    PQCLEAN_HQC256_CLEAN_vect_set_random(&pk_seedexpander, h);

    PQCLEAN_HQC256_CLEAN_load8_arr(s, VEC_N_SIZE_64, pk + SEED_BYTES, VEC_N_SIZE_BYTES);

    PQCLEAN_HQC256_CLEAN_seedexpander_release(&pk_seedexpander);
}

void PQCLEAN_HQC256_CLEAN_hqc_ciphertext_to_string(uint8_t *ct, const uint64_t *u, const uint64_t *v, const uint8_t *salt) {
    PQCLEAN_HQC256_CLEAN_store8_arr(ct, VEC_N_SIZE_BYTES, u, VEC_N_SIZE_64);
    PQCLEAN_HQC256_CLEAN_store8_arr(ct + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, v, VEC_N1N2_SIZE_64);
    memcpy(ct + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, salt, SALT_SIZE_BYTES);
}

void PQCLEAN_HQC256_CLEAN_hqc_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *salt, const uint8_t *ct) {
    PQCLEAN_HQC256_CLEAN_load8_arr(u, VEC_N_SIZE_64, ct, VEC_N_SIZE_BYTES);
    PQCLEAN_HQC256_CLEAN_load8_arr(v, VEC_N1N2_SIZE_64, ct + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES);
    memcpy(salt, ct + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, SALT_SIZE_BYTES);
}