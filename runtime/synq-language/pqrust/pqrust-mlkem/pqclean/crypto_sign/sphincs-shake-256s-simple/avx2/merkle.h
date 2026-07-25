#ifndef MERKLE_H_
#define MERKLE_H_

#include <stdint.h>

#include "context.h"
#include "params.h"

#define merkle_sign SPX_NAMESPACE(merkle_sign)
void merkle_sign(uint8_t *sig, unsigned char *root,
                 const spx_ctx *ctx,
                 uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf);

#define merkle_gen_root SPX_NAMESPACE(merkle_gen_root)
void merkle_gen_root(unsigned char *root, const spx_ctx *ctx);

#endif 