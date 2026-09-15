#ifndef FALCON_INNER_H__
#define FALCON_INNER_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static inline unsigned
set_fpu_cw(unsigned x) {
    return x;
}

#include "fips202.h"

#define inner_shake256_context                shake256incctx
#define inner_shake256_init(sc)               shake256_inc_init(sc)
#define inner_shake256_inject(sc, in, len)    shake256_inc_absorb(sc, in, len)
#define inner_shake256_flip(sc)               shake256_inc_finalize(sc)
#define inner_shake256_extract(sc, out, len)  shake256_inc_squeeze(out, len, sc)
#define inner_shake256_ctx_release(sc)        shake256_inc_ctx_release(sc)

size_t PQCLEAN_FALCONPADDED1024_CLEAN_modq_encode(void *out, size_t max_out_len,
        const uint16_t *x, unsigned logn);
size_t PQCLEAN_FALCONPADDED1024_CLEAN_trim_i16_encode(void *out, size_t max_out_len,
        const int16_t *x, unsigned logn, unsigned bits);
size_t PQCLEAN_FALCONPADDED1024_CLEAN_trim_i8_encode(void *out, size_t max_out_len,
        const int8_t *x, unsigned logn, unsigned bits);
size_t PQCLEAN_FALCONPADDED1024_CLEAN_comp_encode(void *out, size_t max_out_len,
        const int16_t *x, unsigned logn);

size_t PQCLEAN_FALCONPADDED1024_CLEAN_modq_decode(uint16_t *x, unsigned logn,
        const void *in, size_t max_in_len);
size_t PQCLEAN_FALCONPADDED1024_CLEAN_trim_i16_decode(int16_t *x, unsigned logn, unsigned bits,
        const void *in, size_t max_in_len);
size_t PQCLEAN_FALCONPADDED1024_CLEAN_trim_i8_decode(int8_t *x, unsigned logn, unsigned bits,
        const void *in, size_t max_in_len);
size_t PQCLEAN_FALCONPADDED1024_CLEAN_comp_decode(int16_t *x, unsigned logn,
        const void *in, size_t max_in_len);

extern const uint8_t PQCLEAN_FALCONPADDED1024_CLEAN_max_fg_bits[];
extern const uint8_t PQCLEAN_FALCONPADDED1024_CLEAN_max_FG_bits[];

extern const uint8_t PQCLEAN_FALCONPADDED1024_CLEAN_max_sig_bits[];

void PQCLEAN_FALCONPADDED1024_CLEAN_hash_to_point_vartime(inner_shake256_context *sc,
        uint16_t *x, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_hash_to_point_ct(inner_shake256_context *sc,
        uint16_t *x, unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCONPADDED1024_CLEAN_is_short(const int16_t *s1, const int16_t *s2, unsigned logn);

int PQCLEAN_FALCONPADDED1024_CLEAN_is_short_half(uint32_t sqn, const int16_t *s2, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_to_ntt_monty(uint16_t *h, unsigned logn);

int PQCLEAN_FALCONPADDED1024_CLEAN_verify_raw(const uint16_t *c0, const int16_t *s2,
        const uint16_t *h, unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCONPADDED1024_CLEAN_compute_public(uint16_t *h,
        const int8_t *f, const int8_t *g, unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCONPADDED1024_CLEAN_complete_private(int8_t *G,
        const int8_t *f, const int8_t *g, const int8_t *F,
        unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCONPADDED1024_CLEAN_is_invertible(
    const int16_t *s2, unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCONPADDED1024_CLEAN_count_nttzero(const int16_t *sig, unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCONPADDED1024_CLEAN_verify_recover(uint16_t *h,
        const uint16_t *c0, const int16_t *s1, const int16_t *s2,
        unsigned logn, uint8_t *tmp);

#include "fpr.h"

int PQCLEAN_FALCONPADDED1024_CLEAN_get_seed(void *seed, size_t seed_len);

typedef struct {
    union {
        uint8_t d[512]; 
        uint64_t dummy_u64;
    } buf;
    size_t ptr;
    union {
        uint8_t d[256];
        uint64_t dummy_u64;
    } state;
    int type;
} prng;

void PQCLEAN_FALCONPADDED1024_CLEAN_prng_init(prng *p, inner_shake256_context *src);

void PQCLEAN_FALCONPADDED1024_CLEAN_prng_refill(prng *p);

void PQCLEAN_FALCONPADDED1024_CLEAN_prng_get_bytes(prng *p, void *dst, size_t len);

static inline uint64_t
prng_get_u64(prng *p) {
    size_t u;

    u = p->ptr;
    if (u >= (sizeof p->buf.d) - 9) {
        PQCLEAN_FALCONPADDED1024_CLEAN_prng_refill(p);
        u = 0;
    }
    p->ptr = u + 8;

    return (uint64_t)p->buf.d[u + 0]
           | ((uint64_t)p->buf.d[u + 1] << 8)
           | ((uint64_t)p->buf.d[u + 2] << 16)
           | ((uint64_t)p->buf.d[u + 3] << 24)
           | ((uint64_t)p->buf.d[u + 4] << 32)
           | ((uint64_t)p->buf.d[u + 5] << 40)
           | ((uint64_t)p->buf.d[u + 6] << 48)
           | ((uint64_t)p->buf.d[u + 7] << 56);
}

static inline unsigned
prng_get_u8(prng *p) {
    unsigned v;

    v = p->buf.d[p->ptr ++];
    if (p->ptr == sizeof p->buf.d) {
        PQCLEAN_FALCONPADDED1024_CLEAN_prng_refill(p);
    }
    return v;
}

void PQCLEAN_FALCONPADDED1024_CLEAN_FFT(fpr *f, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_iFFT(fpr *f, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_add(fpr *a, const fpr *b, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_sub(fpr *a, const fpr *b, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_neg(fpr *a, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_adj_fft(fpr *a, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_mul_fft(fpr *a, const fpr *b, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_muladj_fft(fpr *a, const fpr *b, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_mulselfadj_fft(fpr *a, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_mulconst(fpr *a, fpr x, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_div_fft(fpr *a, const fpr *b, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_invnorm2_fft(fpr *d,
        const fpr *a, const fpr *b, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_add_muladj_fft(fpr *d,
        const fpr *F, const fpr *G,
        const fpr *f, const fpr *g, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_mul_autoadj_fft(fpr *a,
        const fpr *b, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_div_autoadj_fft(fpr *a,
        const fpr *b, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_LDL_fft(const fpr *g00,
        fpr *g01, fpr *g11, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_LDLmv_fft(fpr *d11, fpr *l10,
        const fpr *g00, const fpr *g01,
        const fpr *g11, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_split_fft(fpr *f0, fpr *f1,
        const fpr *f, unsigned logn);

void PQCLEAN_FALCONPADDED1024_CLEAN_poly_merge_fft(fpr *f,
        const fpr *f0, const fpr *f1, unsigned logn);

#define FALCON_KEYGEN_TEMP_1      136
#define FALCON_KEYGEN_TEMP_2      272
#define FALCON_KEYGEN_TEMP_3      224
#define FALCON_KEYGEN_TEMP_4      448
#define FALCON_KEYGEN_TEMP_5      896
#define FALCON_KEYGEN_TEMP_6     1792
#define FALCON_KEYGEN_TEMP_7     3584
#define FALCON_KEYGEN_TEMP_8     7168
#define FALCON_KEYGEN_TEMP_9    14336
#define FALCON_KEYGEN_TEMP_10   28672

void PQCLEAN_FALCONPADDED1024_CLEAN_keygen(inner_shake256_context *rng,
        int8_t *f, int8_t *g, int8_t *F, int8_t *G, uint16_t *h,
        unsigned logn, uint8_t *tmp);

void PQCLEAN_FALCONPADDED1024_CLEAN_expand_privkey(fpr *expanded_key,
        const int8_t *f, const int8_t *g, const int8_t *F, const int8_t *G,
        unsigned logn, uint8_t *tmp);

void PQCLEAN_FALCONPADDED1024_CLEAN_sign_tree(int16_t *sig, inner_shake256_context *rng,
        const fpr *expanded_key,
        const uint16_t *hm, unsigned logn, uint8_t *tmp);

void PQCLEAN_FALCONPADDED1024_CLEAN_sign_dyn(int16_t *sig, inner_shake256_context *rng,
        const int8_t *f, const int8_t *g,
        const int8_t *F, const int8_t *G,
        const uint16_t *hm, unsigned logn, uint8_t *tmp);

typedef struct {
    prng p;
    fpr sigma_min;
} sampler_context;

int PQCLEAN_FALCONPADDED1024_CLEAN_sampler(void *ctx, fpr mu, fpr isigma);

int PQCLEAN_FALCONPADDED1024_CLEAN_gaussian0_sampler(prng *p);

#endif