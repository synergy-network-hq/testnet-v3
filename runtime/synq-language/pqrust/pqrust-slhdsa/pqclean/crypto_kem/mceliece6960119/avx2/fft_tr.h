#ifndef FFT_TR_H
#define FFT_TR_H

#include "namespace.h"

#define fft_tr CRYPTO_NAMESPACE(fft_tr)

#include "params.h"
#include "vec256.h"

void fft_tr(vec256 *out, vec256 in[][ GFBITS ]);

#endif