#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#define ntt_avx MLKEM_NAMESPACE(_ntt_avx)
void ntt_avx(int16_t *r, const int16_t *qdata);
#define invntt_avx MLKEM_NAMESPACE(_invntt_avx)
void invntt_avx(int16_t *r, const int16_t *qdata);

#define nttpack_avx MLKEM_NAMESPACE(_nttpack_avx)
void nttpack_avx(int16_t *r, const int16_t *qdata);
#define nttunpack_avx MLKEM_NAMESPACE(_nttunpack_avx)
void nttunpack_avx(int16_t *r, const int16_t *qdata);

#define basemul_avx MLKEM_NAMESPACE(_basemul_avx)
void basemul_avx(int16_t *r,
                 const int16_t *a,
                 const int16_t *b,
                 const int16_t *qdata);

#define ntttobytes_avx MLKEM_NAMESPACE(_ntttobytes_avx)
void ntttobytes_avx(uint8_t *r, const int16_t *a, const int16_t *qdata);
#define nttfrombytes_avx MLKEM_NAMESPACE(_nttfrombytes_avx)
void nttfrombytes_avx(int16_t *r, const uint8_t *a, const int16_t *qdata);

#endif
