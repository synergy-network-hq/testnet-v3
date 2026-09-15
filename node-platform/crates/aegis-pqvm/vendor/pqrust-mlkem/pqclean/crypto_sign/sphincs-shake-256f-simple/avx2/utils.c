#include <stdint.h>
#include <string.h>

#include "utils.h"

#include "address.h"
#include "context.h"
#include "params.h"
#include "thash.h"

void ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in) {
    int i;

    for (i = (signed int)outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

void u32_to_bytes(unsigned char *out, uint32_t in) {
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen) {
    unsigned long long retval = 0;
    unsigned int i;

    for (i = 0; i < inlen; i++) {
        retval |= ((unsigned long long)in[i]) << (8 * (inlen - 1 - i));
    }
    return retval;
}

void compute_root(unsigned char *root, const unsigned char *leaf,
                  uint32_t leaf_idx, uint32_t idx_offset,
                  const unsigned char *auth_path, uint32_t tree_height,
                  const spx_ctx *ctx, uint32_t addr[8]) {
    uint32_t i;
    unsigned char buffer[2 * SPX_N];

    if (leaf_idx & 1) {
        memcpy(buffer + SPX_N, leaf, SPX_N);
        memcpy(buffer, auth_path, SPX_N);
    } else {
        memcpy(buffer, leaf, SPX_N);
        memcpy(buffer + SPX_N, auth_path, SPX_N);
    }
    auth_path += SPX_N;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;

        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        if (leaf_idx & 1) {
            thash(buffer + SPX_N, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, SPX_N);
        } else {
            thash(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + SPX_N, auth_path, SPX_N);
        }
        auth_path += SPX_N;
    }

    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    thash(root, buffer, 2, ctx, addr);
}

void treehash(unsigned char *root, unsigned char *auth_path, const spx_ctx *ctx,
              uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
              void (*gen_leaf)(
                  unsigned char * ,
                  const spx_ctx * ,
                  uint32_t , const uint32_t[8] ),
              uint32_t tree_addr[8]) {
    PQCLEAN_VLA(uint8_t, stack, (tree_height + 1)*SPX_N);
    PQCLEAN_VLA(unsigned int, heights, tree_height + 1);
    unsigned int offset = 0;
    uint32_t idx;
    uint32_t tree_idx;

    for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {

        gen_leaf(stack + (offset * SPX_N), ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + ((offset - 1)*SPX_N), SPX_N);
        }

        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {

            tree_idx = (idx >> (heights[offset - 1] + 1));

            set_tree_height(tree_addr, heights[offset - 1] + 1);
            set_tree_index(tree_addr,
                           tree_idx + (idx_offset >> (heights[offset - 1] + 1)));

            thash(stack + ((offset - 2)*SPX_N),
                  stack + ((offset - 2)*SPX_N), 2, ctx, tree_addr);
            offset--;

            heights[offset - 1]++;

            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + (heights[offset - 1]*SPX_N),
                       stack + ((offset - 1)*SPX_N), SPX_N);
            }
        }
    }
    memcpy(root, stack, SPX_N);
}