#include <stdint.h>

#include "fors.h"

#include "address.h"
#include "context.h"
#include "hash.h"
#include "hashx2.h"
#include "params.h"
#include "thash.h"
#include "thashx2.h"
#include "utils.h"
#include "utilsx2.h"

static void fors_gen_sk(unsigned char *sk, const spx_ctx *ctx,
                        uint32_t fors_leaf_addr[8]) {
    prf_addr(sk, ctx, fors_leaf_addr);
}

static void fors_gen_skx2(unsigned char *sk0,
                          unsigned char *sk1,
                          const spx_ctx *ctx,
                          uint32_t fors_leaf_addrx2[2 * 8]) {
    prf_addrx2(sk0, sk1,
               ctx, fors_leaf_addrx2);
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const spx_ctx *ctx,
                            uint32_t fors_leaf_addr[8]) {
    thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

static void fors_sk_to_leafx2(unsigned char *leaf0,
                              unsigned char *leaf1,
                              const unsigned char *sk0,
                              const unsigned char *sk1,
                              const spx_ctx *ctx,
                              uint32_t fors_leaf_addrx2[2 * 8]) {
    thashx2(leaf0, leaf1,
            sk0, sk1,
            1, ctx, fors_leaf_addrx2);
}

struct fors_gen_leaf_info {
    uint32_t leaf_addrx[2 * 8];
};

static void fors_gen_leafx2(unsigned char *leaf,
                            const spx_ctx *ctx,
                            uint32_t addr_idx, void *info) {
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addrx2 = fors_info->leaf_addrx;
    unsigned int j;

    for (j = 0; j < 2; j++) {
        set_tree_index(fors_leaf_addrx2 + (j * 8), addr_idx + j);
        set_type(fors_leaf_addrx2 + (j * 8), SPX_ADDR_TYPE_FORSPRF);
    }

    fors_gen_skx2(leaf + (0 * SPX_N),
                  leaf + (1 * SPX_N),
                  ctx, fors_leaf_addrx2);

    for (j = 0; j < 2; j++) {
        set_type(fors_leaf_addrx2 + (j * 8), SPX_ADDR_TYPE_FORSTREE);
    }

    fors_sk_to_leafx2(leaf + (0 * SPX_N),
                      leaf + (1 * SPX_N),
                      leaf + (0 * SPX_N),
                      leaf + (1 * SPX_N),
                      ctx, fors_leaf_addrx2);
}

static void message_to_indices(uint32_t *indices, const unsigned char *m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= (uint32_t)(((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j);
            offset++;
        }
    }
}

void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const spx_ctx *ctx,
               const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    uint32_t fors_tree_addr[2 * 8] = {0};
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    for (i = 0; i < 2; i++) {
        copy_keypair_addr(fors_tree_addr + (8 * i), fors_addr);
        set_type(fors_tree_addr + (8 * i), SPX_ADDR_TYPE_FORSTREE);
        copy_keypair_addr(fors_leaf_addr + (8 * i), fors_addr);
    }
    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);
        fors_gen_sk(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N;

        treehashx2(roots + (i * SPX_N), sig, ctx,
                   indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leafx2,
                   fors_tree_addr, &fors_info);

        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}

void fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const spx_ctx *ctx,
                      const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    unsigned char leaf[SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N;

        compute_root(roots + (i * SPX_N), leaf, indices[i], idx_offset,
                     sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}