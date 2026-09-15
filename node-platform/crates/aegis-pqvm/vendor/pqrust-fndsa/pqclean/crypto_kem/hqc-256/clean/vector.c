#include "parameters.h"
#include "parsing.h"
#include "randombytes.h"
#include "vector.h"
#include <stdint.h>
#include <string.h>

static uint32_t m_val[149] = { 74517, 74518, 74520, 74521, 74522, 74524, 74525, 74526, 74527, 74529, 74530, 74531, 74533, 74534, 74535, 74536, 74538, 74539, 74540, 74542, 74543, 74544, 74545, 74547, 74548, 74549, 74551, 74552, 74553, 74555, 74556, 74557, 74558, 74560, 74561, 74562, 74564, 74565, 74566, 74567, 74569, 74570, 74571, 74573, 74574, 74575, 74577, 74578, 74579, 74580, 74582, 74583, 74584, 74586, 74587, 74588, 74590, 74591, 74592, 74593, 74595, 74596, 74597, 74599, 74600, 74601, 74602, 74604, 74605, 74606, 74608, 74609, 74610, 74612, 74613, 74614, 74615, 74617, 74618, 74619, 74621, 74622, 74623, 74625, 74626, 74627, 74628, 74630, 74631, 74632, 74634, 74635, 74636, 74637, 74639, 74640, 74641, 74643, 74644, 74645, 74647, 74648, 74649, 74650, 74652, 74653, 74654, 74656, 74657, 74658, 74660, 74661, 74662, 74663, 74665, 74666, 74667, 74669, 74670, 74671, 74673, 74674, 74675, 74676, 74678, 74679, 74680, 74682, 74683, 74684, 74685, 74687, 74688, 74689, 74691, 74692, 74693, 74695, 74696, 74697, 74698, 74700, 74701, 74702, 74704, 74705, 74706, 74708, 74709 };

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

void PQCLEAN_HQC256_CLEAN_vect_set_random_fixed_weight(seedexpander_state *ctx, uint64_t *v, uint16_t weight) {
    uint8_t rand_bytes[4 * PARAM_OMEGA_R] = {0}; 
    uint32_t support[PARAM_OMEGA_R] = {0};
    uint32_t index_tab [PARAM_OMEGA_R] = {0};
    uint64_t bit_tab [PARAM_OMEGA_R] = {0};
    uint32_t pos, found, mask32, tmp;
    uint64_t mask64, val;

    PQCLEAN_HQC256_CLEAN_seedexpander(ctx, rand_bytes, 4 * weight);

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

void PQCLEAN_HQC256_CLEAN_vect_set_random(seedexpander_state *ctx, uint64_t *v) {
    uint8_t rand_bytes[VEC_N_SIZE_BYTES] = {0};

    PQCLEAN_HQC256_CLEAN_seedexpander(ctx, rand_bytes, VEC_N_SIZE_BYTES);

    PQCLEAN_HQC256_CLEAN_load8_arr(v, VEC_N_SIZE_64, rand_bytes, VEC_N_SIZE_BYTES);
    v[VEC_N_SIZE_64 - 1] &= RED_MASK;
}

void PQCLEAN_HQC256_CLEAN_vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        o[i] = v1[i] ^ v2[i];
    }
}

uint8_t PQCLEAN_HQC256_CLEAN_vect_compare(const uint8_t *v1, const uint8_t *v2, size_t size) {
    uint16_t r = 0x0100;

    for (size_t i = 0; i < size; i++) {
        r |= v1[i] ^ v2[i];
    }

    return (r - 1) >> 8;
}

void PQCLEAN_HQC256_CLEAN_vect_resize(uint64_t *o, uint32_t size_o, const uint64_t *v, uint32_t size_v) {
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