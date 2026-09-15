#ifndef SPX_UTILSX4_H
#define SPX_UTILSX4_H

#include <stdint.h>

#include "context.h"
#include "params.h"

#define treehashx1 SPX_NAMESPACE(treehashx1)
void treehashx1(unsigned char *root, unsigned char *auth_path,
                const spx_ctx *ctx,
                uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
                void (*gen_leaf)(
                    unsigned char * ,
                    const spx_ctx * ,
                    uint32_t addr_idx, void *info),
                uint32_t tree_addrx4[8], void *info);

#endif