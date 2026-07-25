#ifndef FFT_H
#define FFT_H

#include "namespace.h"

#define fft CRYPTO_NAMESPACE(fft)

#include "params.h"
#include "vec128.h"
#include "vec256.h"
#include <stdint.h>

void fft(vec256 out[][GFBITS], uint64_t *in);

#endif