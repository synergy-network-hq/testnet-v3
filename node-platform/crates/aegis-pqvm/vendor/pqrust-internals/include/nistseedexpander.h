#ifndef NISTSEEDEXPANDER_H
#define NISTSEEDEXPANDER_H

#include <stddef.h>
#include <stdint.h>

#define NISTSEEDEXPANDER_SEED_LEN 32

#define RNG_SUCCESS     ( 0)
#define RNG_BAD_MAXLEN  (-1)
#define RNG_BAD_OUTBUF  (-2)
#define RNG_BAD_REQ_LEN (-3)

typedef struct {
    uint8_t buffer[16];
    size_t  buffer_pos;
    size_t  length_remaining;
    uint8_t key[NISTSEEDEXPANDER_SEED_LEN];
    uint8_t ctr[16];
} AES_XOF_struct;

int
seedexpander_init(AES_XOF_struct *ctx,
                  const uint8_t *seed,
                  const uint8_t *diversifier,
                  size_t maxlen);

int
seedexpander(AES_XOF_struct *ctx, uint8_t *x, size_t xlen);

#endif 