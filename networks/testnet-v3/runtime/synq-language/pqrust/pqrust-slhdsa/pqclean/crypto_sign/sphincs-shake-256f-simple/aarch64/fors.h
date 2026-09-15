#ifndef SPX_FORS_H
#define SPX_FORS_H

#include <stdint.h>

#include "context.h"
#include "params.h"

#define fors_sign SPX_NAMESPACE(fors_sign)
void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const spx_ctx *ctx,
               const uint32_t fors_addr[8]);

#define fors_pk_from_sig SPX_NAMESPACE(fors_pk_from_sig)
void fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const spx_ctx *ctx,
                      const uint32_t fors_addr[8]);

#endif