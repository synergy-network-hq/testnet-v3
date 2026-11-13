#ifndef PQCLEAN_MLKEM1024_AVX2_CBD_H
#define PQCLEAN_MLKEM1024_AVX2_CBD_H
#include "params.h"
#include "poly.h"
#include <immintrin.h>
#include <stdint.h>

void PQCLEAN_MLKEM1024_AVX2_poly_cbd_eta1(poly *r, const __m256i buf[MLKEM_ETA1 * MLKEM_N / 128 + 1]);

void PQCLEAN_MLKEM1024_AVX2_poly_cbd_eta2(poly *r, const __m256i buf[MLKEM_ETA2 * MLKEM_N / 128]);

#endif
