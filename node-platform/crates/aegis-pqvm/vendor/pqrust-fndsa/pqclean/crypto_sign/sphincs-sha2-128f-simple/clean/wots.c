#include <stdint.h>
#include <string.h>

#include "wots.h"
#include "context.h"

#include "address.h"
#include "params.h"
#include "thash.h"
#include "utils.h"

static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const spx_ctx *ctx, uint32_t addr[8]) {
    uint32_t i;

    memcpy(out, in, SPX_N);

    for (i = start; i < (start + steps) && i < SPX_WOTS_W; i++) {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
    }
}

static void base_w(uint32_t *output, const int out_len,
                   const unsigned char *input) {
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W - 1);
        out++;
    }
}

static void wots_checksum(uint32_t *csum_base_w,
                          const uint32_t *msg_base_w) {
    unsigned int csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    unsigned int i;

    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

void chain_lengths(uint32_t *lengths, const unsigned char *msg) {
    base_w(lengths, SPX_WOTS_LEN1, msg);
    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8]) {
    uint32_t lengths[SPX_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(pk + (i * SPX_N), sig + (i * SPX_N),
                  lengths[i], SPX_WOTS_W - 1 - lengths[i], ctx, addr);
    }
}