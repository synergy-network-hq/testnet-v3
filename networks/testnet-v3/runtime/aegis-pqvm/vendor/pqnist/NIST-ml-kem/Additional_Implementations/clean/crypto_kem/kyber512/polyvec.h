#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

typedef struct {
    poly vec[MLKEM_K];
} polyvec;

#define polyvec_compress MLKEM_NAMESPACE(_polyvec_compress)
void polyvec_compress(uint8_t r[MLKEM_POLYVECCOMPRESSEDBYTES], polyvec *a);
#define polyvec_decompress MLKEM_NAMESPACE(_polyvec_decompress)
void polyvec_decompress(polyvec *r,
                        const uint8_t a[MLKEM_POLYVECCOMPRESSEDBYTES]);

#define polyvec_tobytes MLKEM_NAMESPACE(_polyvec_tobytes)
void polyvec_tobytes(uint8_t r[MLKEM_POLYVECBYTES], polyvec *a);
#define polyvec_frombytes MLKEM_NAMESPACE(_polyvec_frombytes)
void polyvec_frombytes(polyvec *r, const uint8_t a[MLKEM_POLYVECBYTES]);

#define polyvec_ntt MLKEM_NAMESPACE(_polyvec_ntt)
void polyvec_ntt(polyvec *r);
#define polyvec_invntt_tomont MLKEM_NAMESPACE(_polyvec_invntt_tomont)
void polyvec_invntt_tomont(polyvec *r);

#define polyvec_pointwise_acc_montgomery \
    MLKEM_NAMESPACE(_polyvec_pointwise_acc_montgomery)
void polyvec_pointwise_acc_montgomery(poly *r,
                                      const polyvec *a,
                                      const polyvec *b);

#define polyvec_reduce MLKEM_NAMESPACE(_polyvec_reduce)
void polyvec_reduce(polyvec *r);
#define polyvec_csubq MLKEM_NAMESPACE(_polyvec_csubq)
void polyvec_csubq(polyvec *r);

#define polyvec_add MLKEM_NAMESPACE(_polyvec_add)
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
