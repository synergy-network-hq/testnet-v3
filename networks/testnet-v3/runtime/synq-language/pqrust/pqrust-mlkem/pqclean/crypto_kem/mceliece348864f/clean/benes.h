#ifndef BENES_H
#define BENES_H

#include "namespace.h"

#define apply_benes CRYPTO_NAMESPACE(apply_benes)
#define support_gen CRYPTO_NAMESPACE(support_gen)

#include "gf.h"

void apply_benes(unsigned char *r, const unsigned char *bits, int rev);
void support_gen(gf *s, const unsigned char *c);

#endif