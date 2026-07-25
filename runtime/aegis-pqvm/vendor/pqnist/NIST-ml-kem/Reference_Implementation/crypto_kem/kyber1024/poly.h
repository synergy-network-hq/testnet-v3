#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[MLKEM_N];
} poly;

#define poly_compress MLKEM_NAMESPACE(_poly_compress)
void poly_compress(uint8_t r[MLKEM_POLYCOMPRESSEDBYTES], poly *a);
#define poly_decompress MLKEM_NAMESPACE(_poly_decompress)
void poly_decompress(poly *r, const uint8_t a[MLKEM_POLYCOMPRESSEDBYTES]);

#define poly_tobytes MLKEM_NAMESPACE(_poly_tobytes)
void poly_tobytes(uint8_t r[MLKEM_POLYBYTES], poly *a);
#define poly_frombytes MLKEM_NAMESPACE(_poly_frombytes)
void poly_frombytes(poly *r, const uint8_t a[MLKEM_POLYBYTES]);

#define poly_frommsg MLKEM_NAMESPACE(_poly_frommsg)
void poly_frommsg(poly *r, const uint8_t msg[MLKEM_INDCPA_MSGBYTES]);
#define poly_tomsg MLKEM_NAMESPACE(_poly_tomsg)
void poly_tomsg(uint8_t msg[MLKEM_INDCPA_MSGBYTES], poly *r);

#define poly_getnoise_eta1 MLKEM_NAMESPACE(_poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const uint8_t seed[MLKEM_SYMBYTES], uint8_t nonce);

#define poly_getnoise_eta2 MLKEM_NAMESPACE(_poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const uint8_t seed[MLKEM_SYMBYTES], uint8_t nonce);

#define poly_ntt MLKEM_NAMESPACE(_poly_ntt)
void poly_ntt(poly *r);
#define poly_invntt_tomont MLKEM_NAMESPACE(_poly_invntt_tomont)
void poly_invntt_tomont(poly *r);
#define poly_basemul_montgomery MLKEM_NAMESPACE(_poly_basemul_montgomery)
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
#define poly_tomont MLKEM_NAMESPACE(_poly_tomont)
void poly_tomont(poly *r);

#define poly_reduce MLKEM_NAMESPACE(_poly_reduce)
void poly_reduce(poly *r);
#define poly_csubq MLKEM_NAMESPACE(_poly_csubq)
void poly_csubq(poly *r);

#define poly_add MLKEM_NAMESPACE(_poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
#define poly_sub MLKEM_NAMESPACE(_poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
