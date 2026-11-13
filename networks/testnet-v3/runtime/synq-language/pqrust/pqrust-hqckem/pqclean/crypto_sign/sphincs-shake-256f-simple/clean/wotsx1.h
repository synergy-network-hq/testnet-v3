#ifndef WOTSX1_H_
#define WOTSX1_H_

#include <string.h>

#include "context.h"
#include "params.h"

struct leaf_info_x1 {
    unsigned char *wots_sig;
    uint32_t wots_sign_leaf; 
    uint32_t *wots_steps;
    uint32_t leaf_addr[8];
    uint32_t pk_addr[8];
};

#define INITIALIZE_LEAF_INFO_X1(info, addr, step_buffer) { \
        (info).wots_sig = 0;             \
        (info).wots_sign_leaf = ~0;      \
        (info).wots_steps = step_buffer; \
        memcpy( &(info).leaf_addr[0], (addr), 32 ); \
        memcpy( &(info).pk_addr[0], (addr), 32 ); \
    }

#define wots_gen_leafx1 SPX_NAMESPACE(wots_gen_leafx1)
void wots_gen_leafx1(unsigned char *dest,
                     const spx_ctx *ctx,
                     uint32_t leaf_idx, void *v_info);

#endif 