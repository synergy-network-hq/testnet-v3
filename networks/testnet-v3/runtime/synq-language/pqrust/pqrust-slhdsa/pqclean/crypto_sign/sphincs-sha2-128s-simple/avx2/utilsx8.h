#ifndef SPX_UTILSX8_H
#define SPX_UTILSX8_H

#include <stdint.h>

#include "params.h"

#define treehashx8 SPX_NAMESPACE(treehashx8)
void treehashx8(unsigned char *root, unsigned char *auth_path,
                const spx_ctx *ctx,
                uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
                void (*gen_leafx8)(
                    unsigned char * ,
                    const spx_ctx * ,
                    uint32_t addr_idx, void *info),
                uint32_t tree_addrx8[8 * 8], void *info);

#endif