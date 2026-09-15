#ifndef TRANSPOSE_H
#define TRANSPOSE_H

#include "namespace.h"

#define transpose_64x64 CRYPTO_NAMESPACE(transpose_64x64)

#include <inttypes.h>

void transpose_64x64(uint64_t *out, const uint64_t *in);

#endif