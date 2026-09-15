#ifndef BM_H
#define BM_H

#include "gf.h"
#include "namespace.h"

#define bm CRYPTO_NAMESPACE(bm)

void bm(gf *out, gf *s);

#endif