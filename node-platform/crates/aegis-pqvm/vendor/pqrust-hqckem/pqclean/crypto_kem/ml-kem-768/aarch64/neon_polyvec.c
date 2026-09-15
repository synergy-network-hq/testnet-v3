
#include <arm_neon.h>
#include "params.h"
#include "reduce.h"
#include "ntt.h"
#include "poly.h"
#include "polyvec.h"

#include "NTT_params.h"

#define _V (((1U << 26) + KYBER_Q / 2) / KYBER_Q)

void neon_polyvec_ntt(int16_t r[KYBER_K][KYBER_N]) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        neon_poly_ntt(r[i]);
    }
}

void neon_polyvec_invntt_to_mont(int16_t r[KYBER_K][KYBER_N]) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        neon_poly_invntt_tomont(r[i]);
    }
}

void neon_polyvec_add_reduce(int16_t c[KYBER_K][KYBER_N], const int16_t a[KYBER_K][KYBER_N]) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {

        neon_poly_add_reduce(c[i], a[i]);
    }
}