#ifndef SPX_UTILS_H
#define SPX_UTILS_H

#include <stdint.h>

#include "compat.h"
#include "context.h"
#include "params.h"

#define ull_to_bytes SPX_NAMESPACE(ull_to_bytes)
void ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in);
#define u32_to_bytes SPX_NAMESPACE(u32_to_bytes)
void u32_to_bytes(unsigned char *out, uint32_t in);

#define bytes_to_ull SPX_NAMESPACE(bytes_to_ull)
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen);

#define compute_root SPX_NAMESPACE(compute_root)
void compute_root(unsigned char *root, const unsigned char *leaf,
                  uint32_t leaf_idx, uint32_t idx_offset,
                  const unsigned char *auth_path, uint32_t tree_height,
                  const spx_ctx *ctx, uint32_t addr[8]);

#define treehash SPX_NAMESPACE(treehash)
void treehash(unsigned char *root, unsigned char *auth_path,
              const spx_ctx *ctx,
              uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
              void (*gen_leaf)(
                  unsigned char * ,
                  const spx_ctx *ctx ,
                  uint32_t , const uint32_t[8] ),
              uint32_t tree_addr[8]);

#endif