#ifndef WOTSX2_H_
#define WOTSX2_H_

#include "params.h"
#include <string.h>

struct leaf_info_x2 {
    unsigned char *wots_sig;
    uint32_t wots_sign_leaf; 
    uint32_t *wots_steps;
    uint32_t leaf_addr[2 * 8];
    uint32_t pk_addr[2 * 8];
};

#define INITIALIZE_LEAF_INFO_X2(info, addr, step_buffer) { \
        (info).wots_sig = 0;             \
        (info).wots_sign_leaf = ~0;      \
        (info).wots_steps = step_buffer; \
        int i;                         \
        for (i=0; i<2; i++) {          \
            memcpy( &(info).leaf_addr[8*i], addr, 32 ); \
            memcpy( &(info).pk_addr[8*i], addr, 32 ); \
        } \
    }

#define wots_gen_leafx2 SPX_NAMESPACE(wots_gen_leafx2)
void wots_gen_leafx2(unsigned char *dest,
                     const spx_ctx *ctx,
                     uint32_t leaf_idx, void *v_info);

#endif 