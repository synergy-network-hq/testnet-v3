#include <stdint.h>
#include <string.h>

#include "context.h"
#include "utils.h"
#include "utilsx8.h"

#include "address.h"
#include "params.h"
#include "thashx8.h"

void treehashx8(unsigned char *root, unsigned char *auth_path,
                const spx_ctx *ctx,
                uint32_t leaf_idx, uint32_t idx_offset,
                uint32_t tree_height,
                void (*gen_leafx8)(
                    unsigned char * ,
                    const spx_ctx *,
                    uint32_t idx, void *info),
                uint32_t tree_addrx8[8 * 8],
                void *info) {

    PQCLEAN_VLA(unsigned char, stackx8, tree_height * 8 * SPX_N);
    uint32_t left_adj = 0, prev_left_adj = 0; 

    uint32_t idx;
    uint32_t max_idx = ((uint32_t)1 << (tree_height - 3)) - 1;
    for (idx = 0;; idx++) {
        unsigned char current[8 * SPX_N]; 
        gen_leafx8( current, ctx, (8 * idx) + idx_offset,
                    info );

        uint32_t internal_idx_offset = idx_offset;
        uint32_t internal_idx = idx;
        uint32_t internal_leaf = leaf_idx;
        uint32_t h;     
        for (h = 0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {

            if (h >= tree_height - 3) {
                if (h == tree_height) {

                    memcpy( root, &current[7 * SPX_N], SPX_N );
                    return;
                }

                prev_left_adj = left_adj;
                left_adj = (uint32_t)(8 - (1 << (tree_height - h - 1)));
            }

            if (h == tree_height) {

                memcpy( root, &current[7 * SPX_N], SPX_N );
                return;
            }

            if ((((internal_idx << 3) ^ internal_leaf) & ~0x7U) == 0) {
                memcpy( &auth_path[ h * SPX_N ],
                        &current[(((internal_leaf & 7) ^ 1) + prev_left_adj) * SPX_N],
                        SPX_N );
            }

            if ((internal_idx & 1) == 0 && idx < max_idx) {
                break;
            }

            uint32_t j;
            internal_idx_offset >>= 1;
            for (j = 0; j < 8; j++) {
                set_tree_height(tree_addrx8 + (j * 8), h + 1);
                set_tree_index(tree_addrx8 + (j * 8),
                               ((8 / 2) * (internal_idx & ~1U)) + j - left_adj + internal_idx_offset );
            }
            unsigned char *left = &stackx8[h * 8 * SPX_N];
            thashx8( &current[0 * SPX_N],
                     &current[1 * SPX_N],
                     &current[2 * SPX_N],
                     &current[3 * SPX_N],
                     &current[4 * SPX_N],
                     &current[5 * SPX_N],
                     &current[6 * SPX_N],
                     &current[7 * SPX_N],
                     &left   [0 * SPX_N],
                     &left   [2 * SPX_N],
                     &left   [4 * SPX_N],
                     &left   [6 * SPX_N],
                     &current[0 * SPX_N],
                     &current[2 * SPX_N],
                     &current[4 * SPX_N],
                     &current[6 * SPX_N],
                     2, ctx, tree_addrx8);
        }

        memcpy( &stackx8[h * 8 * SPX_N], current, 8 * SPX_N);
    }
}