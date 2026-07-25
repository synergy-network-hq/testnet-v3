#ifndef PQCLEAN_MLDSA44_CLEAN_REDUCE_H
#define PQCLEAN_MLDSA44_CLEAN_REDUCE_H
#include "params.h"
#include <stdint.h>

#define MONT (-4186625) 
#define QINV 58728449 

int32_t PQCLEAN_MLDSA44_CLEAN_montgomery_reduce(int64_t a);

int32_t PQCLEAN_MLDSA44_CLEAN_reduce32(int32_t a);

int32_t PQCLEAN_MLDSA44_CLEAN_caddq(int32_t a);

int32_t PQCLEAN_MLDSA44_CLEAN_freeze(int32_t a);

#endif