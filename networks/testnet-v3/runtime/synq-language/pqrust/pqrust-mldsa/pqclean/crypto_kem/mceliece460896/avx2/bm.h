#ifndef BM_H
#define BM_H

#include "namespace.h"

#define bm CRYPTO_NAMESPACE(bm)

#include "vec128.h"
#include "vec256.h"

void bm(vec128 *out, vec256 *in);

#endif