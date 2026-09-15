#ifndef FALCON_INNER_H__
#define FALCON_INNER_H__

#include "params.h"

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

size_t PQCLEAN_FALCON512_AARCH64_modq_encode(void *out, size_t max_out_len,
        const uint16_t *x, unsigned logn);
size_t PQCLEAN_FALCON512_AARCH64_trim_i16_encode(void *out, size_t max_out_len,
        const int16_t *x, unsigned logn, unsigned bits);
size_t PQCLEAN_FALCON512_AARCH64_trim_i8_encode(void *out, size_t max_out_len, const int8_t *x, uint8_t bits);
size_t PQCLEAN_FALCON512_AARCH64_comp_encode(void *out, size_t max_out_len, const int16_t *x);

size_t PQCLEAN_FALCON512_AARCH64_modq_decode(uint16_t *x, const void *in,
        size_t max_in_len, unsigned logn);
size_t PQCLEAN_FALCON512_AARCH64_trim_i16_decode(int16_t *x, unsigned logn, unsigned bits,
        const void *in, size_t max_in_len);
size_t PQCLEAN_FALCON512_AARCH64_trim_i8_decode(int8_t *x, unsigned bits, const void *in, size_t max_in_len);
size_t PQCLEAN_FALCON512_AARCH64_comp_decode(int16_t *x, const void *in, size_t max_in_len);

extern const uint8_t PQCLEAN_FALCON512_AARCH64_max_fg_bits[];
extern const uint8_t PQCLEAN_FALCON512_AARCH64_max_FG_bits[];

extern const uint8_t PQCLEAN_FALCON512_AARCH64_max_sig_bits[];

void PQCLEAN_FALCON512_AARCH64_hash_to_point_vartime(inner_shake256_context *sc,
        uint16_t *x, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_hash_to_point_ct(inner_shake256_context *sc,
        uint16_t *x, unsigned logn, uint8_t *tmp);

int PQCLEAN_FALCON512_AARCH64_is_short(const int16_t *s1, const int16_t *s2);

int PQCLEAN_FALCON512_AARCH64_is_short_tmp(int16_t *s1tmp, int16_t *s2tmp,
        const int16_t *hm, const double *t0,
        const double *t1);

void PQCLEAN_FALCON512_AARCH64_to_ntt(int16_t *h);

void PQCLEAN_FALCON512_AARCH64_to_ntt_monty(int16_t *h);

int PQCLEAN_FALCON512_AARCH64_verify_raw(const int16_t *c0, const int16_t *s2,
        int16_t *h, int16_t *tmp);

int PQCLEAN_FALCON512_AARCH64_compute_public(int16_t *h, const int8_t *f,
        const int8_t *g, int16_t *tmp);

int PQCLEAN_FALCON512_AARCH64_complete_private(int8_t *G, const int8_t *f,
        const int8_t *g, const int8_t *F,
        uint8_t *tmp);

int PQCLEAN_FALCON512_AARCH64_is_invertible(const int16_t *s2, uint8_t *tmp);

int PQCLEAN_FALCON512_AARCH64_count_nttzero(const int16_t *sig, uint8_t *tmp);

int PQCLEAN_FALCON512_AARCH64_verify_recover(int16_t *h, const int16_t *c0,
        const int16_t *s1, const int16_t *s2,
        uint8_t *tmp);

#include "fpr.h"

int PQCLEAN_FALCON512_AARCH64_get_seed(void *seed, size_t seed_len);

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

void PQCLEAN_FALCON512_AARCH64_prng_init(prng *p, inner_shake256_context *src);

void PQCLEAN_FALCON512_AARCH64_prng_refill(prng *p);

void PQCLEAN_FALCON512_AARCH64_prng_get_bytes(prng *p, void *dst, size_t len);

static inline uint64_t
prng_get_u64(prng *p) {
    size_t u;

    u = p->ptr;
    if (u >= (sizeof p->buf.d) - 9) {
        PQCLEAN_FALCON512_AARCH64_prng_refill(p);
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
        PQCLEAN_FALCON512_AARCH64_prng_refill(p);
    }
    return v;
}

void PQCLEAN_FALCON512_AARCH64_FFT(fpr *f, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_iFFT(fpr *f, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_add(fpr *c, const fpr *restrict a, const fpr *restrict b, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_sub(fpr *c, const fpr *restrict a, const fpr *restrict b, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_neg(fpr *c, const fpr *restrict a, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_adj_fft(fpr *c, const fpr *restrict a, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_mul_fft(fpr *c, const fpr *a, const fpr *restrict b, unsigned logn);
void PQCLEAN_FALCON512_AARCH64_poly_mul_add_fft(fpr *c, const fpr *a, const fpr *restrict b, const fpr *restrict d, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_muladj_fft(fpr *d, fpr *a, const fpr *restrict b, unsigned logn);
void PQCLEAN_FALCON512_AARCH64_poly_muladj_add_fft(fpr *c, fpr *d,
        const fpr *a, const fpr *restrict b, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_mulselfadj_fft(fpr *c, const fpr *restrict a, unsigned logn);
void PQCLEAN_FALCON512_AARCH64_poly_mulselfadj_add_fft(fpr *c, const fpr *restrict d, const fpr *restrict a, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_mulconst(fpr *c, const fpr *a, const fpr x, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_div_fft(fpr *restrict c, const fpr *restrict a, const fpr *restrict b, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_invnorm2_fft(fpr *restrict d,
        const fpr *restrict a, const fpr *restrict b, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_add_muladj_fft(fpr *restrict d,
        const fpr *restrict F, const fpr *restrict G,
        const fpr *restrict f, const fpr *restrict g, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_mul_autoadj_fft(fpr *c, const fpr *a, const fpr *restrict b, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_div_autoadj_fft(fpr *c, const fpr *a, const fpr *restrict b, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_LDL_fft(const fpr *restrict g00,
        fpr *restrict g01, fpr *restrict g11, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_LDLmv_fft(fpr *restrict d11, fpr *restrict l10,
        const fpr *restrict g00, const fpr *restrict g01,
        const fpr *restrict g11, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_split_fft(fpr *restrict f0, fpr *restrict f1,
        const fpr *restrict f, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_merge_fft(fpr *restrict f,
        const fpr *restrict f0, const fpr *restrict f1, unsigned logn);

void PQCLEAN_FALCON512_AARCH64_poly_fpr_of_s16(fpr *t0, const uint16_t *hm, const unsigned falcon_n);

fpr PQCLEAN_FALCON512_AARCH64_compute_bnorm(const fpr *rt1, const fpr *rt2);

int32_t PQCLEAN_FALCON512_AARCH64_poly_small_sqnorm(const int8_t *f); 

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

void PQCLEAN_FALCON512_AARCH64_keygen(inner_shake256_context *rng,
                                      int8_t *f, int8_t *g, int8_t *F, int8_t *G, uint16_t *h,
                                      unsigned logn, uint8_t *tmp);

void PQCLEAN_FALCON512_AARCH64_expand_privkey(fpr *restrict expanded_key,
        const int8_t *f, const int8_t *g, const int8_t *F, const int8_t *G,
        uint8_t *restrict tmp);

void PQCLEAN_FALCON512_AARCH64_sign_tree(int16_t *sig, inner_shake256_context *rng,
        const fpr *restrict expanded_key,
        const uint16_t *hm, uint8_t *tmp);

void PQCLEAN_FALCON512_AARCH64_sign_dyn(int16_t *sig, inner_shake256_context *rng,
                                        const int8_t *restrict f, const int8_t *restrict g,
                                        const int8_t *restrict F, const int8_t *restrict G,
                                        const uint16_t *hm, uint8_t *tmp);

typedef struct {
    prng p;
    fpr sigma_min;
} sampler_context;

int PQCLEAN_FALCON512_AARCH64_sampler(void *ctx, fpr mu, fpr isigma);

int PQCLEAN_FALCON512_AARCH64_gaussian0_sampler(prng *p);

#endif