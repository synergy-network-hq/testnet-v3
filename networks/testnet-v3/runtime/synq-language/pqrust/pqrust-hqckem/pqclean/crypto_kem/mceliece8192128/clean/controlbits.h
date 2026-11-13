#ifndef CONTROLBITS_H
#define CONTROLBITS_H

#include "namespace.h"

#define controlbitsfrompermutation CRYPTO_NAMESPACE(controlbitsfrompermutation)

#include <inttypes.h>

extern void controlbitsfrompermutation(unsigned char *out, const int16_t *pi, long long w, long long n);

#endif