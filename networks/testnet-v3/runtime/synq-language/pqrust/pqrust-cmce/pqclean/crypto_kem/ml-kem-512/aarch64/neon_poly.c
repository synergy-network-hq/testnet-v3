
#include <arm_neon.h>
#include "params.h"
#include "poly.h"
#include "ntt.h"
#include "cbd.h"
#include "symmetric.h"

void neon_poly_getnoise_eta1_2x(int16_t vec1[KYBER_N], int16_t vec2[KYBER_N],
                                const uint8_t seed[KYBER_SYMBYTES],
                                uint8_t nonce1, uint8_t nonce2) {
    uint8_t buf1[KYBER_ETA1 * KYBER_N / 4],
            buf2[KYBER_ETA1 * KYBER_N / 4];
    neon_prf(buf1, buf2, sizeof(buf1), seed, nonce1, nonce2);
    poly_cbd_eta1(vec1, buf1);
    poly_cbd_eta1(vec2, buf2);
}

void neon_poly_getnoise_eta2_2x(int16_t vec1[KYBER_N], int16_t vec2[KYBER_N],
                                const uint8_t seed[KYBER_SYMBYTES],
                                uint8_t nonce1, uint8_t nonce2) {
    uint8_t buf1[KYBER_ETA2 * KYBER_N / 4],
            buf2[KYBER_ETA2 * KYBER_N / 4];
    neon_prf(buf1, buf2, sizeof(buf1), seed, nonce1, nonce2);
    poly_cbd_eta2(vec1, buf1);
    poly_cbd_eta2(vec2, buf2);
}

void neon_poly_getnoise_eta2(int16_t r[KYBER_N],
                             const uint8_t seed[KYBER_SYMBYTES],
                             uint8_t nonce) {
    uint8_t buf[KYBER_ETA2 * KYBER_N / 4];
    prf(buf, sizeof(buf), seed, nonce);
    poly_cbd_eta2(r, buf);
}

void neon_poly_ntt(int16_t r[KYBER_N]) {
    ntt(r);
}

void neon_poly_invntt_tomont(int16_t r[KYBER_N]) {
    invntt(r);
}

extern void PQCLEAN_MLKEM512_AARCH64__asm_add_reduce(int16_t *, const int16_t *);
void neon_poly_add_reduce(int16_t c[KYBER_N], const int16_t a[KYBER_N]) {
    PQCLEAN_MLKEM512_AARCH64__asm_add_reduce(c, a);
}

extern void PQCLEAN_MLKEM512_AARCH64__asm_add_add_reduce(int16_t *, const int16_t *, const int16_t *);
void neon_poly_add_add_reduce(int16_t c[KYBER_N], const int16_t a[KYBER_N], const int16_t b[KYBER_N]) {
    PQCLEAN_MLKEM512_AARCH64__asm_add_add_reduce(c, a, b);
}

extern void PQCLEAN_MLKEM512_AARCH64__asm_sub_reduce(int16_t *, const int16_t *);
void neon_poly_sub_reduce(int16_t c[KYBER_N], const int16_t a[KYBER_N]) {
    PQCLEAN_MLKEM512_AARCH64__asm_sub_reduce(c, a);
}