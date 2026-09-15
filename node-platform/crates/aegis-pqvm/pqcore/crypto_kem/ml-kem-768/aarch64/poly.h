#ifndef PQCLEAN_MLKEM768_AARCH64_POLY_H
#define PQCLEAN_MLKEM768_AARCH64_POLY_H

/*
 * This file is licensed
 * under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.html)
 * at https://github.com/GMUCERG/PQC_NEON/blob/main/neon/
  
  mlkem =~  =~  or
 * public domain at https://github.com/cothan/
  
  mlkem =~  =~ /blob/master/neon
 */

#include <stdint.h>
#include "params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
    int16_t coeffs[MLKEM_N];
} poly;

#define poly_compress MLKEM_NAMESPACE(poly_compress)
void poly_compress(uint8_t r[MLKEM_POLYCOMPRESSEDBYTES], const int16_t a[MLKEM_N]);
#define poly_decompress MLKEM_NAMESPACE(poly_decompress)
void poly_decompress(int16_t r[MLKEM_N], const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES]);

#define poly_tobytes MLKEM_NAMESPACE(poly_tobytes)
void poly_tobytes(uint8_t r[MLKEM_POLYBYTES], const int16_t a[MLKEM_N]);

#define poly_frommsg MLKEM_NAMESPACE(poly_frommsg)
void poly_frommsg(int16_t r[MLKEM_N], const uint8_t msg[MLKEM_INDCPA_MSGBYTES]) ;
#define poly_tomsg MLKEM_NAMESPACE(poly_tomsg)
void poly_tomsg(uint8_t msg[MLKEM_INDCPA_MSGBYTES], const int16_t a[MLKEM_N]);

// NEON

#define neon_poly_reduce MLKEM_NAMESPACE(poly_reduce)
void neon_poly_reduce(int16_t c[MLKEM_N]);
#define neon_poly_add_reduce MLKEM_NAMESPACE(poly_add_reduce_csubq)
void neon_poly_add_reduce(int16_t c[MLKEM_N], const int16_t a[MLKEM_N]);

#define neon_poly_sub_reduce MLKEM_NAMESPACE(poly_sub_reduce_csubq)
void neon_poly_sub_reduce(int16_t c[MLKEM_N], const int16_t a[MLKEM_N]);

#define neon_poly_add_add_reduce MLKEM_NAMESPACE(poly_add_add_reduce_csubq)
void neon_poly_add_add_reduce(int16_t c[MLKEM_N], const int16_t a[MLKEM_N], const int16_t b[MLKEM_N]);

#define neon_poly_getnoise_eta1_2x MLKEM_NAMESPACE(poly_getnoise_eta1_2x)
void neon_poly_getnoise_eta1_2x(int16_t vec1[MLKEM_N], int16_t vec2[MLKEM_N],
                                const uint8_t seed[MLKEM_SYMBYTES],
                                uint8_t nonce1, uint8_t nonce2);

#define neon_poly_getnoise_eta2_2x MLKEM_NAMESPACE(poly_getnoise_eta2_2x)
void neon_poly_getnoise_eta2_2x(int16_t vec1[MLKEM_N], int16_t vec2[MLKEM_N],
                                const uint8_t seed[MLKEM_SYMBYTES],
                                uint8_t nonce1, uint8_t nonce2);

#define neon_poly_getnoise_eta2 MLKEM_NAMESPACE(poly_getnoise_eta2)
void neon_poly_getnoise_eta2(int16_t r[MLKEM_N],
                             const uint8_t seed[MLKEM_SYMBYTES],
                             uint8_t nonce);

#define poly_frombytes MLKEM_NAMESPACE(poly_frombytes)
void poly_frombytes(int16_t r[MLKEM_N], const uint8_t a[MLKEM_POLYBYTES]);

#define neon_poly_ntt MLKEM_NAMESPACE(neon_poly_ntt)
void neon_poly_ntt(int16_t r[MLKEM_N]);

#define neon_poly_invntt_tomont MLKEM_NAMESPACE(neon_poly_invntt_tomont)
void neon_poly_invntt_tomont(int16_t r[MLKEM_N]);

#endif
