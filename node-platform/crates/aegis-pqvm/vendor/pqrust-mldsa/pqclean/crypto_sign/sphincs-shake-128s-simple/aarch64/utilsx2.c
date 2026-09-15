#include <stdint.h>
#include <string.h>

#include "utilsx2.h"

#include "address.h"
#include "context.h"
#include "params.h"
#include "thashx2.h"

void treehashx2(unsigned char *root, unsigned char *auth_path,
                const spx_ctx *ctx,
                uint32_t leaf_idx, uint32_t idx_offset,
                uint32_t tree_height,
                void (*gen_leafx2)(
                    unsigned char * ,
                    const spx_ctx *,
                    uint32_t idx, void *info),
                uint32_t tree_addrx2[2 * 8],
                void *info) {

    unsigned char stackx2[tree_height * 2 * SPX_N];
    uint32_t left_adj = 0, prev_left_adj = 0; 

    uint32_t idx;
    uint32_t max_idx = (1 << (tree_height - 1)) - 1;
    for (idx = 0;; idx++) {
        unsigned char current[2 * SPX_N]; 
        gen_leafx2( current, ctx, (2 * idx) + idx_offset,
                    info );

        uint32_t internal_idx_offset = idx_offset;
        uint32_t internal_idx = idx;
        uint32_t internal_leaf = leaf_idx;
        uint32_t h;     
        for (h = 0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {

            if (h >= tree_height - 1) {
                if (h == tree_height) {

                    memcpy( root, &current[1 * SPX_N], SPX_N );
                    return;
                }

                prev_left_adj = left_adj;
                left_adj = 2 - (1 << (tree_height - h - 1));
            }

            if (h == tree_height) {

                memcpy( root, &current[1 * SPX_N], SPX_N );
                return;
            }

            if ((((internal_idx << 1) ^ internal_leaf) & ~0x1U) == 0) {
                memcpy( &auth_path[ h * SPX_N ],
                        &current[(((internal_leaf & 1) ^ 1) + prev_left_adj) * SPX_N],
                        SPX_N );
            }

            if ((internal_idx & 1) == 0 && idx < max_idx) {
                break;
            }

            uint8_t j;
            internal_idx_offset >>= 1;
            for (j = 0; j < 2; j++) {
                set_tree_height(tree_addrx2 + (j * 8), h + 1);
                set_tree_index(tree_addrx2 + (j * 8),
                               ((2 / 2) * (internal_idx & ~1U)) + j - left_adj + internal_idx_offset );
            }
            unsigned char *left = &stackx2[h * 2 * SPX_N];
            thashx2( &current[0 * SPX_N],
                     &current[1 * SPX_N],
                     &left   [0 * SPX_N],
                     &current[0 * SPX_N],
                     2, ctx, tree_addrx2);
        }

        memcpy( &stackx2[h * 2 * SPX_N], current, 2 * SPX_N);
    }
}