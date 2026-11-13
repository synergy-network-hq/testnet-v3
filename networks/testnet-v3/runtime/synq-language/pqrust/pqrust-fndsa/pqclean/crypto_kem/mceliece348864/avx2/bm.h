#ifndef BM_H
#define BM_H

#include "namespace.h"

#define bm CRYPTO_NAMESPACE(bm)

#include "vec128.h"

void bm(uint64_t out[GFBITS], vec128 in[GFBITS]);

#endif