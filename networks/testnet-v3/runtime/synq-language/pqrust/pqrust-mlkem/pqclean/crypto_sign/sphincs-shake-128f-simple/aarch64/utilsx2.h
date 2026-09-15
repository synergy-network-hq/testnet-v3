#ifndef SPX_UTILSX2_H
#define SPX_UTILSX2_H

#include <stdint.h>

#include "context.h"
#include "params.h"

#define treehashx2 SPX_NAMESPACE(treehashx2)
void treehashx2(unsigned char *root, unsigned char *auth_path,
                const spx_ctx *ctx,
                uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
                void (*gen_leafx2)(
                    unsigned char * ,
                    const spx_ctx * ,
                    uint32_t addr_idx, void *info),
                uint32_t tree_addrx2[2 * 8], void *info);

#endif