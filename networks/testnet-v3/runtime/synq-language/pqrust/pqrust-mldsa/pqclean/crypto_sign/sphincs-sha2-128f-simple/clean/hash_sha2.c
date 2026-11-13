#include <stdint.h>
#include <string.h>

#include "context.h"
#include "hash.h"
#include "params.h"
#include "sha2.h"
#include "sha2_offsets.h"
#include "utils.h"

#define SPX_SHAX_OUTPUT_BYTES SPX_SHA256_OUTPUT_BYTES
#define SPX_SHAX_BLOCK_BYTES SPX_SHA256_BLOCK_BYTES
#define shaX_inc_init sha256_inc_init
#define shaX_inc_blocks sha256_inc_blocks
#define shaX_inc_finalize sha256_inc_finalize
#define shaX sha256
#define mgf1_X mgf1_256
#define shaXstate sha256ctx

void mgf1_256(unsigned char *out, unsigned long outlen,
              const unsigned char *in, unsigned long inlen) {
    PQCLEAN_VLA(uint8_t, inbuf, inlen + 4);
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint32_t i;

    memcpy(inbuf, in, inlen);

    for (i = 0; (i + 1) * SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sha256(out, inbuf, inlen + 4);
        out += SPX_SHA256_OUTPUT_BYTES;
    }

    if (outlen > i * SPX_SHA256_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, i);
        sha256(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - (i * SPX_SHA256_OUTPUT_BYTES));
    }
}

void mgf1_512(unsigned char *out, unsigned long outlen,
              const unsigned char *in, unsigned long inlen) {
    PQCLEAN_VLA(uint8_t, inbuf, inlen + 4);
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    uint32_t i;

    memcpy(inbuf, in, inlen);

    for (i = 0; (i + 1) * SPX_SHA512_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sha512(out, inbuf, inlen + 4);
        out += SPX_SHA512_OUTPUT_BYTES;
    }

    if (outlen > i * SPX_SHA512_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, i);
        sha512(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - (i * SPX_SHA512_OUTPUT_BYTES));
    }
}

void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8]) {
    sha256ctx sha2_state;
    unsigned char buf[SPX_SHA256_ADDR_BYTES + SPX_N];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];

    sha256_inc_ctx_clone(&sha2_state, &ctx->state_seeded);

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, ctx->sk_seed, SPX_N);

    sha256_inc_finalize(outbuf, &sha2_state, buf, SPX_SHA256_ADDR_BYTES + SPX_N);

    memcpy(out, outbuf, SPX_N);
}

void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, size_t mlen,
                        const spx_ctx *ctx) {
    (void)ctx;

    unsigned char buf[SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES];
    shaXstate state;
    int i;

    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x36, SPX_SHAX_BLOCK_BYTES - SPX_N);

    shaX_inc_init(&state);
    shaX_inc_blocks(&state, buf, 1);

    memcpy(buf, optrand, SPX_N);

    if (SPX_N + mlen < SPX_SHAX_BLOCK_BYTES) {
        memcpy(buf + SPX_N, m, mlen);
        shaX_inc_finalize(buf + SPX_SHAX_BLOCK_BYTES, &state,
                          buf, mlen + SPX_N);
    }

    else {
        memcpy(buf + SPX_N, m, SPX_SHAX_BLOCK_BYTES - SPX_N);
        shaX_inc_blocks(&state, buf, 1);

        m += SPX_SHAX_BLOCK_BYTES - SPX_N;
        mlen -= SPX_SHAX_BLOCK_BYTES - SPX_N;
        shaX_inc_finalize(buf + SPX_SHAX_BLOCK_BYTES, &state, m, mlen);
    }

    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x5c, SPX_SHAX_BLOCK_BYTES - SPX_N);

    shaX(buf, buf, SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES);
    memcpy(R, buf, SPX_N);
}

void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, size_t mlen,
                  const spx_ctx *ctx) {
    (void)ctx;
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char seed[(2 * SPX_N) + SPX_SHAX_OUTPUT_BYTES];

#define SPX_INBLOCKS (((SPX_N + SPX_PK_BYTES + SPX_SHAX_BLOCK_BYTES - 1) & \
                       -SPX_SHAX_BLOCK_BYTES) / SPX_SHAX_BLOCK_BYTES)
    unsigned char inbuf[SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES];

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    shaXstate state;

    shaX_inc_init(&state);

    memcpy(inbuf, R, SPX_N);
    memcpy(inbuf + SPX_N, pk, SPX_PK_BYTES);

    if (SPX_N + SPX_PK_BYTES + mlen < SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES) {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m, mlen);
        shaX_inc_finalize(seed + (2 * SPX_N), &state, inbuf, SPX_N + SPX_PK_BYTES + mlen);
    }

    else {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m,
               (SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES) - SPX_N - SPX_PK_BYTES);
        shaX_inc_blocks(&state, inbuf, SPX_INBLOCKS);

        m += SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
        mlen -= SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
        shaX_inc_finalize(seed + (2 * SPX_N), &state, m, mlen);
    }

    memcpy(seed, R, SPX_N);
    memcpy(seed + SPX_N, pk, SPX_N);

    mgf1_X(bufp, SPX_DGST_BYTES, seed, (2 * SPX_N) + SPX_SHAX_OUTPUT_BYTES);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}