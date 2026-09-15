#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "fors.h"
#include "hash.h"
#include "merkle.h"
#include "nistapi.h"
#include "params.h"
#include "randombytes.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

size_t crypto_sign_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

size_t crypto_sign_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

size_t crypto_sign_bytes(void) {
    return CRYPTO_BYTES;
}

size_t crypto_sign_seedbytes(void) {
    return CRYPTO_SEEDBYTES;
}

int crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk,
                             const uint8_t *seed) {
    spx_ctx ctx;

    memcpy(sk, seed, CRYPTO_SEEDBYTES);

    memcpy(pk, sk + (2 * SPX_N), SPX_N);

    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);

    initialize_hash_function(&ctx);

    merkle_gen_root(sk + (3 * SPX_N), &ctx);

    free_hash_function(&ctx);

    memcpy(pk + SPX_N, sk + (3 * SPX_N), SPX_N);

    return 0;
}

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seed[CRYPTO_SEEDBYTES];
    randombytes(seed, CRYPTO_SEEDBYTES);
    crypto_sign_seed_keypair(pk, sk, seed);

    return 0;
}

int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk) {
    spx_ctx ctx;

    const uint8_t *sk_prf = sk + SPX_N;
    const uint8_t *pk = sk + (2 * SPX_N);

    uint8_t optrand[SPX_N];
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t root[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    randombytes(optrand, SPX_N);

    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    free_hash_function(&ctx);

    *siglen = SPX_BYTES;

    return 0;
}

int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk) {
    spx_ctx ctx;
    const uint8_t *pub_root = pk + SPX_N;
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t wots_pk[SPX_WOTS_BYTES];
    uint8_t root[SPX_N];
    uint8_t leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES;

        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    free_hash_function(&ctx);

    if (memcmp(root, pub_root, SPX_N) != 0) {
        return -1;
    }

    return 0;
}

int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk) {
    size_t siglen;

    crypto_sign_signature(sm, &siglen, m, mlen, sk);

    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}

int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk) {

    if (smlen < SPX_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - SPX_BYTES;

    if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, *mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    memmove(m, sm + SPX_BYTES, *mlen);

    return 0;
}