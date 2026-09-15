#ifndef PQCLEAN_MLDSA44_AARCH64_REDUCE_H
#define PQCLEAN_MLDSA44_AARCH64_REDUCE_H

#include "params.h"
#include <stdint.h>

#define DILITHIUM_QINV 58728449 

#define montgomery_reduce DILITHIUM_NAMESPACE(montgomery_reduce)
int32_t montgomery_reduce(int64_t a);

#define reduce32 DILITHIUM_NAMESPACE(reduce32)
int32_t reduce32(int32_t a);

#define caddq DILITHIUM_NAMESPACE(caddq)
int32_t caddq(int32_t a);

#define freeze DILITHIUM_NAMESPACE(freeze)
int32_t freeze(int32_t a);

#endif