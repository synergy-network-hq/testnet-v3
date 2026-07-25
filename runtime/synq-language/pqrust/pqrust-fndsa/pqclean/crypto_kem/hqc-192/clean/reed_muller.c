#include "parameters.h"
#include "reed_muller.h"
#include <stdint.h>
#include <string.h>

#define MULTIPLICITY                   CEIL_DIVIDE(PARAM_N2, 128)

#define BIT0MASK(x) (uint32_t)(-((x) & 1))

static void encode(uint64_t *cword, uint8_t message) {
    uint32_t first_word;

    first_word = BIT0MASK(message >> 7);

    first_word ^= BIT0MASK(message >> 0) & 0xaaaaaaaa;
    first_word ^= BIT0MASK(message >> 1) & 0xcccccccc;
    first_word ^= BIT0MASK(message >> 2) & 0xf0f0f0f0;
    first_word ^= BIT0MASK(message >> 3) & 0xff00ff00;
    first_word ^= BIT0MASK(message >> 4) & 0xffff0000;

    cword[0] = first_word;

    first_word ^= BIT0MASK(message >> 5);
    cword[0] |= (uint64_t)first_word << 32;
    first_word ^= BIT0MASK(message >> 6);
    cword[1] = (uint64_t)first_word << 32;
    first_word ^= BIT0MASK(message >> 5);
    cword[1] |= first_word;
}

static void hadamard(uint16_t src[128], uint16_t dst[128]) {

    uint16_t *p1 = src;
    uint16_t *p2 = dst;
    uint16_t *p3;
    for (size_t pass = 0; pass < 7; ++pass) {
        for (size_t i = 0; i < 64; ++i) {
            p2[i] = p1[2 * i] + p1[2 * i + 1];
            p2[i + 64] = p1[2 * i] - p1[2 * i + 1];
        }

        p3 = p1;
        p1 = p2;
        p2 = p3;
    }
}

static void expand_and_sum(uint16_t dest[128], const uint64_t src[2 * MULTIPLICITY]) {

    for (size_t part = 0; part < 2; ++part) {
        for (size_t bit = 0; bit < 64; ++bit) {
            dest[part * 64 + bit] = ((src[part] >> bit) & 1);
        }
    }

    for (size_t copy = 1; copy < MULTIPLICITY; ++copy) {
        for (size_t part = 0; part < 2; ++part) {
            for (size_t bit = 0; bit < 64; ++bit) {
                dest[part * 64 + bit] += (uint16_t) ((src[2 * copy + part] >> bit) & 1);
            }
        }
    }
}

static uint8_t find_peaks(const uint16_t transform[128]) {
    uint16_t peak_abs = 0;
    uint16_t peak = 0;
    uint16_t pos = 0;
    uint16_t t, abs, mask;
    for (uint16_t i = 0; i < 128; ++i) {
        t = transform[i];
        abs = t ^ ((uint16_t)(-(t >> 15)) & (t ^ -t)); 
        mask = -(((uint16_t)(peak_abs - abs)) >> 15);
        peak ^= mask & (peak ^ t);
        pos ^= mask & (pos ^ i);
        peak_abs ^= mask & (peak_abs ^ abs);
    }

    pos |= 128 & (uint16_t)((peak >> 15) - 1);
    return (uint8_t) pos;
}

void PQCLEAN_HQC192_CLEAN_reed_muller_encode(uint64_t *cdw, const uint8_t *msg) {
    for (size_t i = 0; i < VEC_N1_SIZE_BYTES; ++i) {

        encode(&cdw[2 * i * MULTIPLICITY], msg[i]);

        for (size_t copy = 1; copy < MULTIPLICITY; ++copy) {
            memcpy(&cdw[2 * i * MULTIPLICITY + 2 * copy], &cdw[2 * i * MULTIPLICITY], 16);
        }
    }
}

void PQCLEAN_HQC192_CLEAN_reed_muller_decode(uint8_t *msg, const uint64_t *cdw) {
    uint16_t expanded[128];
    uint16_t transform[128];
    for (size_t i = 0; i < VEC_N1_SIZE_BYTES; ++i) {

        expand_and_sum(expanded, &cdw[2 * i * MULTIPLICITY]);

        hadamard(expanded, transform);

        transform[0] -= 64 * MULTIPLICITY;

        msg[i] = find_peaks(transform);
    }
}