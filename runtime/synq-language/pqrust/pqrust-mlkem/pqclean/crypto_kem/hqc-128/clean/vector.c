#include "parameters.h"
#include "parsing.h"
#include "randombytes.h"
#include "vector.h"
#include <stdint.h>
#include <string.h>

static uint32_t m_val[75] = { 243079, 243093, 243106, 243120, 243134, 243148, 243161, 243175, 243189, 243203, 243216, 243230, 243244, 243258, 243272, 243285, 243299, 243313, 243327, 243340, 243354, 243368, 243382, 243396, 243409, 243423, 243437, 243451, 243465, 243478, 243492, 243506, 243520, 243534, 243547, 243561, 243575, 243589, 243603, 243616, 243630, 243644, 243658, 243672, 243686, 243699, 243713, 243727, 243741, 243755, 243769, 243782, 243796, 243810, 243824, 243838, 243852, 243865, 243879, 243893, 243907, 243921, 243935, 243949, 243962, 243976, 243990, 244004, 244018, 244032, 244046, 244059, 244073, 244087, 244101 };

static inline uint32_t compare_u32(uint32_t v1, uint32_t v2) {
    return 1 ^ ((uint32_t)((v1 - v2) | (v2 - v1)) >> 31);
}

static uint64_t single_bit_mask(uint32_t pos) {
    uint64_t ret = 0;
    uint64_t mask = 1;
    uint64_t tmp;

    for (size_t i = 0; i < 64; ++i) {
        tmp = pos - i;
        tmp = 0 - (1 - ((uint64_t)(tmp | (0 - tmp)) >> 63));
        ret |= mask & tmp;
        mask <<= 1;
    }

    return ret;
}

static inline uint32_t cond_sub(uint32_t r, uint32_t n) {
    uint32_t mask;
    r -= n;
    mask = 0 - (r >> 31);
    return r + (n & mask);
}

static inline uint32_t reduce(uint32_t a, size_t i) {
    uint32_t q, n, r;
    q = ((uint64_t) a * m_val[i]) >> 32;
    n = (uint32_t)(PARAM_N - i);
    r = a - q * n;
    return cond_sub(r, n);
}

void PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(seedexpander_state *ctx, uint64_t *v, uint16_t weight) {
    uint8_t rand_bytes[4 * PARAM_OMEGA_R] = {0}; 
    uint32_t support[PARAM_OMEGA_R] = {0};
    uint32_t index_tab [PARAM_OMEGA_R] = {0};
    uint64_t bit_tab [PARAM_OMEGA_R] = {0};
    uint32_t pos, found, mask32, tmp;
    uint64_t mask64, val;

    PQCLEAN_HQC128_CLEAN_seedexpander(ctx, rand_bytes, 4 * weight);

    for (size_t i = 0; i < weight; ++i) {
        support[i] = rand_bytes[4 * i];
        support[i] |= rand_bytes[4 * i + 1] << 8;
        support[i] |= (uint32_t)rand_bytes[4 * i + 2] << 16;
        support[i] |= (uint32_t)rand_bytes[4 * i + 3] << 24;
        support[i] = (uint32_t)(i + reduce(support[i], i)); 
    }

    for (size_t i = (weight - 1); i-- > 0;) {
        found = 0;

        for (size_t j = i + 1; j < weight; ++j) {
            found |= compare_u32(support[j], support[i]);
        }

        mask32 = 0 - found;
        support[i] = (mask32 & i) ^ (~mask32 & support[i]);
    }

    for (size_t i = 0; i < weight; ++i) {
        index_tab[i] = support[i] >> 6;
        pos = support[i] & 0x3f;
        bit_tab[i] = single_bit_mask(pos); 
    }

    for (size_t i = 0; i < VEC_N_SIZE_64; ++i) {
        val = 0;
        for (size_t j = 0; j < weight; ++j) {
            tmp = (uint32_t)(i - index_tab[j]);
            tmp = 1 ^ ((uint32_t)(tmp | (0 - tmp)) >> 31);
            mask64 = 0 - (uint64_t)tmp;
            val |= (bit_tab[j] & mask64);
        }
        v[i] |= val;
    }
}

void PQCLEAN_HQC128_CLEAN_vect_set_random(seedexpander_state *ctx, uint64_t *v) {
    uint8_t rand_bytes[VEC_N_SIZE_BYTES] = {0};

    PQCLEAN_HQC128_CLEAN_seedexpander(ctx, rand_bytes, VEC_N_SIZE_BYTES);

    PQCLEAN_HQC128_CLEAN_load8_arr(v, VEC_N_SIZE_64, rand_bytes, VEC_N_SIZE_BYTES);
    v[VEC_N_SIZE_64 - 1] &= RED_MASK;
}

void PQCLEAN_HQC128_CLEAN_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        o[i] = v1[i] ^ v2[i];
    }
}

uint8_t PQCLEAN_HQC128_CLEAN_vect_compare(const uint8_t *v1, const uint8_t *v2, size_t size) {
    uint16_t r = 0x0100;

    for (size_t i = 0; i < size; i++) {
        r |= v1[i] ^ v2[i];
    }

    return (r - 1) >> 8;
}

void PQCLEAN_HQC128_CLEAN_vect_resize(uint64_t *o, uint32_t size_o, const uint64_t *v, uint32_t size_v) {
    uint64_t mask = 0x7FFFFFFFFFFFFFFF;
    size_t val = 0;
    if (size_o < size_v) {

        if (size_o % 64) {
            val = 64 - (size_o % 64);
        }

        memcpy(o, v, VEC_N1N2_SIZE_BYTES);

        for (size_t i = 0; i < val; ++i) {
            o[VEC_N1N2_SIZE_64 - 1] &= (mask >> i);
        }
    } else {
        memcpy(o, v, 8 * CEIL_DIVIDE(size_v, 64));
    }
}