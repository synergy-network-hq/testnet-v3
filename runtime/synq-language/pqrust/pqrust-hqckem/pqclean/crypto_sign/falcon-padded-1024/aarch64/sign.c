
#include "inner.h"
#include "macrof.h"
#include "macrofx4.h"
#include "util.h"
#include <arm_neon.h>

#define MKN(logn)   ((size_t)1 << (logn))

static inline unsigned
ffLDL_treesize(unsigned logn) {

    return (logn + 1) << logn;
}

static void
ffLDL_fft_inner(fpr *restrict tree,
                fpr *restrict g0, fpr *restrict g1, unsigned logn, fpr *restrict tmp) {
    size_t n, hn;

    n = MKN(logn);
    if (n == 1) {
        tree[0] = g0[0];
        return;
    }
    hn = n >> 1;

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_LDLmv_fft(tmp, tree, g0, g1, g0, logn);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(g1, g1 + hn, g0, logn);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(g0, g0 + hn, tmp, logn);

    ffLDL_fft_inner(tree + n,
                    g1, g1 + hn, logn - 1, tmp);
    ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1),
                    g0, g0 + hn, logn - 1, tmp);
}

static void
ffLDL_fft(fpr *restrict tree, const fpr *restrict g00,
          const fpr *restrict g01, const fpr *restrict g11,
          unsigned logn, fpr *restrict tmp) {
    size_t n, hn;
    fpr *d00, *d11;

    n = MKN(logn);
    if (n == 1) {
        tree[0] = g00[0];
        return;
    }
    hn = n >> 1;
    d00 = tmp;
    d11 = tmp + n;
    tmp += n << 1;

    memcpy(d00, g00, n * sizeof * g00);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_LDLmv_fft(d11, tree, g00, g01, g11, logn);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(tmp, tmp + hn, d00, logn);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(d00, d00 + hn, d11, logn);
    memcpy(d11, tmp, n * sizeof * tmp);

    ffLDL_fft_inner(tree + n, d11, d11 + hn, logn - 1, tmp);
    ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1), d00, d00 + hn, logn - 1, tmp);

}

static void
ffLDL_binary_normalize(fpr *tree, unsigned orig_logn, unsigned logn) {

    size_t n;

    n = MKN(logn);
    if (n == 1) {

        tree[0] = fpr_mul(fpr_sqrt(tree[0]), fpr_inv_sigma_10);
    } else {
        ffLDL_binary_normalize(tree + n, orig_logn, logn - 1);
        ffLDL_binary_normalize(tree + n + ffLDL_treesize(logn - 1),
                               orig_logn, logn - 1);
    }
}

static inline size_t
skoff_b00(unsigned logn) {
    (void)logn;
    return 0;
}

static inline size_t
skoff_b01(unsigned logn) {
    return MKN(logn);
}

static inline size_t
skoff_b10(unsigned logn) {
    return 2 * MKN(logn);
}

static inline size_t
skoff_b11(unsigned logn) {
    return 3 * MKN(logn);
}

static inline size_t
skoff_tree(unsigned logn) {
    return 4 * MKN(logn);
}

void
PQCLEAN_FALCONPADDED1024_AARCH64_expand_privkey(fpr *restrict expanded_key,
        const int8_t *f, const int8_t *g,
        const int8_t *F, const int8_t *G,
        uint8_t *restrict tmp) {
    fpr *rf, *rg, *rF, *rG;
    fpr *b00, *b01, *b10, *b11;
    fpr *g00, *g01, *g11, *gxx;
    fpr *tree;

    b00 = expanded_key + skoff_b00(FALCON_LOGN);
    b01 = expanded_key + skoff_b01(FALCON_LOGN);
    b10 = expanded_key + skoff_b10(FALCON_LOGN);
    b11 = expanded_key + skoff_b11(FALCON_LOGN);
    tree = expanded_key + skoff_tree(FALCON_LOGN);

    rg = b00;
    rf = b01;
    rG = b10;
    rF = b11;

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(rg, g, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(rg, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(rf, f, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(rf, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_neg(rf, rf, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(rG, G, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(rG, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(rF, F, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(rF, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_neg(rF, rF, FALCON_LOGN);

    g00 = (fpr *)tmp;
    g01 = g00 + FALCON_N;
    g11 = g01 + FALCON_N;
    gxx = g11 + FALCON_N;

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulselfadj_fft(g00, b00, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulselfadj_add_fft(g00, g00, b01, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_muladj_fft(g01, b00, b10, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_muladj_add_fft(g01, g01, b01, b11, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulselfadj_fft(g11, b10, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulselfadj_add_fft(g11, g11, b11, FALCON_LOGN);

    ffLDL_fft(tree, g00, g01, g11, FALCON_LOGN, gxx);

    ffLDL_binary_normalize(tree, FALCON_LOGN, FALCON_LOGN);
}

typedef int (*samplerZ)(void *ctx, fpr mu, fpr sigma);

static void
ffSampling_fft_dyntree(samplerZ samp, void *samp_ctx,
                       fpr *restrict t0, fpr *restrict t1,
                       fpr *restrict g00, fpr *restrict g01, fpr *restrict g11,
                       unsigned orig_logn, unsigned logn, fpr *restrict tmp) {
    size_t n, hn;
    fpr *z0, *z1;

    if (logn == 0) {
        fpr leaf;

        leaf = g00[0];
        leaf = fpr_mul(fpr_sqrt(leaf), fpr_inv_sigma_10);
        t0[0] = fpr_of(samp(samp_ctx, t0[0], leaf));
        t1[0] = fpr_of(samp(samp_ctx, t1[0], leaf));
        return;
    }

    n = (size_t)1 << logn;
    hn = n >> 1;

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_LDL_fft(g00, g01, g11, logn);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(tmp, tmp + hn, g00, logn);
    memcpy(g00, tmp, n * sizeof * tmp);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(tmp, tmp + hn, g11, logn);
    memcpy(g11, tmp, n * sizeof * tmp);
    memcpy(tmp, g01, n * sizeof * g01);
    memcpy(g01, g00, hn * sizeof * g00);
    memcpy(g01 + hn, g11, hn * sizeof * g00);

    z1 = tmp + n;
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(z1, z1 + hn, t1, logn);
    ffSampling_fft_dyntree(samp, samp_ctx, z1, z1 + hn,
                           g11, g11 + hn, g01 + hn, orig_logn, logn - 1, z1 + n);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_merge_fft(tmp + (n << 1), z1, z1 + hn, logn);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_sub(z1, t1, tmp + (n << 1), logn);
    memcpy(t1, tmp + (n << 1), n * sizeof * tmp);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_add_fft(t0, t0, tmp, z1, logn);

    z0 = tmp;
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(z0, z0 + hn, t0, logn);
    ffSampling_fft_dyntree(samp, samp_ctx, z0, z0 + hn,
                           g00, g00 + hn, g01, orig_logn, logn - 1, z0 + n);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_merge_fft(t0, z0, z0 + hn, logn);
}

static void
ffSampling_fft(samplerZ samp, void *samp_ctx,
               fpr *restrict z0, fpr *restrict z1,
               const fpr *restrict tree,
               const fpr *restrict t0, const fpr *restrict t1, unsigned logn,
               fpr *restrict tmp) {
    size_t n, hn;
    const fpr *tree0, *tree1;

    if (logn == 2) {
        fpr x0, x1, y0, y1, w0, w1, w2, w3, sigma;
        fpr a_re, a_im, b_re, b_im, c_re, c_im;

        tree0 = tree + 4;
        tree1 = tree + 8;

        a_re = t1[0];
        a_im = t1[2];
        b_re = t1[1];
        b_im = t1[3];
        c_re = fpr_add(a_re, b_re);
        c_im = fpr_add(a_im, b_im);
        w0 = fpr_half(c_re);
        w1 = fpr_half(c_im);
        c_re = fpr_sub(a_re, b_re);
        c_im = fpr_sub(a_im, b_im);
        w2 = fpr_mul(fpr_add(c_re, c_im), fpr_invsqrt8);
        w3 = fpr_mul(fpr_sub(c_im, c_re), fpr_invsqrt8);

        x0 = w2;
        x1 = w3;
        sigma = tree1[3];
        w2 = fpr_of(samp(samp_ctx, x0, sigma));
        w3 = fpr_of(samp(samp_ctx, x1, sigma));
        a_re = fpr_sub(x0, w2);
        a_im = fpr_sub(x1, w3);
        b_re = tree1[0];
        b_im = tree1[1];
        c_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
        c_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
        x0 = fpr_add(c_re, w0);
        x1 = fpr_add(c_im, w1);
        sigma = tree1[2];
        w0 = fpr_of(samp(samp_ctx, x0, sigma));
        w1 = fpr_of(samp(samp_ctx, x1, sigma));

        a_re = w0;
        a_im = w1;
        b_re = w2;
        b_im = w3;
        c_re = fpr_mul(fpr_sub(b_re, b_im), fpr_invsqrt2);
        c_im = fpr_mul(fpr_add(b_re, b_im), fpr_invsqrt2);
        z1[0] = w0 = fpr_add(a_re, c_re);
        z1[2] = w2 = fpr_add(a_im, c_im);
        z1[1] = w1 = fpr_sub(a_re, c_re);
        z1[3] = w3 = fpr_sub(a_im, c_im);

        w0 = fpr_sub(t1[0], w0);
        w1 = fpr_sub(t1[1], w1);
        w2 = fpr_sub(t1[2], w2);
        w3 = fpr_sub(t1[3], w3);

        a_re = w0;
        a_im = w2;
        b_re = tree[0];
        b_im = tree[2];
        w0 = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
        w2 = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
        a_re = w1;
        a_im = w3;
        b_re = tree[1];
        b_im = tree[3];
        w1 = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
        w3 = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));

        w0 = fpr_add(w0, t0[0]);
        w1 = fpr_add(w1, t0[1]);
        w2 = fpr_add(w2, t0[2]);
        w3 = fpr_add(w3, t0[3]);

        a_re = w0;
        a_im = w2;
        b_re = w1;
        b_im = w3;
        c_re = fpr_add(a_re, b_re);
        c_im = fpr_add(a_im, b_im);
        w0 = fpr_half(c_re);
        w1 = fpr_half(c_im);
        c_re = fpr_sub(a_re, b_re);
        c_im = fpr_sub(a_im, b_im);
        w2 = fpr_mul(fpr_add(c_re, c_im), fpr_invsqrt8);
        w3 = fpr_mul(fpr_sub(c_im, c_re), fpr_invsqrt8);

        x0 = w2;
        x1 = w3;
        sigma = tree0[3];
        w2 = y0 = fpr_of(samp(samp_ctx, x0, sigma));
        w3 = y1 = fpr_of(samp(samp_ctx, x1, sigma));
        a_re = fpr_sub(x0, y0);
        a_im = fpr_sub(x1, y1);
        b_re = tree0[0];
        b_im = tree0[1];
        c_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
        c_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
        x0 = fpr_add(c_re, w0);
        x1 = fpr_add(c_im, w1);
        sigma = tree0[2];
        w0 = fpr_of(samp(samp_ctx, x0, sigma));
        w1 = fpr_of(samp(samp_ctx, x1, sigma));

        a_re = w0;
        a_im = w1;
        b_re = w2;
        b_im = w3;
        c_re = fpr_mul(fpr_sub(b_re, b_im), fpr_invsqrt2);
        c_im = fpr_mul(fpr_add(b_re, b_im), fpr_invsqrt2);
        z0[0] = fpr_add(a_re, c_re);
        z0[2] = fpr_add(a_im, c_im);
        z0[1] = fpr_sub(a_re, c_re);
        z0[3] = fpr_sub(a_im, c_im);

        return;
    }

    if (logn == 1) {
        fpr x0, x1, y0, y1, sigma;
        fpr a_re, a_im, b_re, b_im, c_re, c_im;

        x0 = t1[0];
        x1 = t1[1];
        sigma = tree[3];
        z1[0] = y0 = fpr_of(samp(samp_ctx, x0, sigma));
        z1[1] = y1 = fpr_of(samp(samp_ctx, x1, sigma));
        a_re = fpr_sub(x0, y0);
        a_im = fpr_sub(x1, y1);
        b_re = tree[0];
        b_im = tree[1];
        c_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
        c_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
        x0 = fpr_add(c_re, t0[0]);
        x1 = fpr_add(c_im, t0[1]);
        sigma = tree[2];
        z0[0] = fpr_of(samp(samp_ctx, x0, sigma));
        z0[1] = fpr_of(samp(samp_ctx, x1, sigma));

        return;
    }

    n = (size_t)1 << logn;
    hn = n >> 1;
    tree0 = tree + n;
    tree1 = tree + n + ffLDL_treesize(logn - 1);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(z1, z1 + hn, t1, logn);
    ffSampling_fft(samp, samp_ctx, tmp, tmp + hn,
                   tree1, z1, z1 + hn, logn - 1, tmp + n);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_merge_fft(z1, tmp, tmp + hn, logn);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_sub(tmp, t1, z1, logn);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_add_fft(tmp, t0, tmp, tree, logn);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_split_fft(z0, z0 + hn, tmp, logn);
    ffSampling_fft(samp, samp_ctx, tmp, tmp + hn,
                   tree0, z0, z0 + hn, logn - 1, tmp + n);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_merge_fft(z0, tmp, tmp + hn, logn);
}

static int
do_sign_tree(samplerZ samp, void *samp_ctx, int16_t *s2,
             const fpr *restrict expanded_key,
             const uint16_t *hm, fpr *restrict tmp) {
    fpr *t0, *t1, *tx, *ty;
    const fpr *b00, *b01, *b10, *b11, *tree;
    fpr ni;
    int16_t *s1tmp, *s2tmp;

    t0 = tmp;
    t1 = t0 + FALCON_N;
    b00 = expanded_key + skoff_b00(FALCON_LOGN);
    b01 = expanded_key + skoff_b01(FALCON_LOGN);
    b10 = expanded_key + skoff_b10(FALCON_LOGN);
    b11 = expanded_key + skoff_b11(FALCON_LOGN);
    tree = expanded_key + skoff_tree(FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_fpr_of_s16(t0, hm, FALCON_N);

    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(t0, FALCON_LOGN);
    ni = fpr_inverse_of_q;
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_fft(t1, t0, b01, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulconst(t1, t1, fpr_neg(ni), FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_fft(t0, t0, b11, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulconst(t0, t0, ni, FALCON_LOGN);

    tx = t1 + FALCON_N;
    ty = tx + FALCON_N;

    ffSampling_fft(samp, samp_ctx, tx, ty, tree, t0, t1, FALCON_LOGN, ty + FALCON_N);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_fft(t0, tx, b00, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_add_fft(t0, t0, ty, b10, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_iFFT(t0, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_fft(t1, tx, b01, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_add_fft(t1, t1, ty, b11, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_iFFT(t1, FALCON_LOGN);

    s1tmp = (int16_t *)tx;
    s2tmp = (int16_t *)tmp;

    if (PQCLEAN_FALCONPADDED1024_AARCH64_is_short_tmp(s1tmp, s2tmp, (int16_t *) hm, t0, t1)) {
        memcpy(s2, s2tmp, FALCON_N * sizeof * s2);
        memcpy(tmp, s1tmp, FALCON_N * sizeof * s1tmp);
        return 1;
    }
    return 0;
}

static int
do_sign_dyn(samplerZ samp, void *samp_ctx, int16_t *s2,
            const int8_t *restrict f, const int8_t *restrict g,
            const int8_t *restrict F, const int8_t *restrict G,
            const uint16_t *hm, fpr *restrict tmp) {
    fpr *t0, *t1, *tx, *ty;
    fpr *b00, *b01, *b10, *b11, *g00, *g01, *g11;
    fpr ni;
    int16_t *s1tmp, *s2tmp;

    b00 = tmp;
    b01 = b00 + FALCON_N;
    b10 = b01 + FALCON_N;
    b11 = b10 + FALCON_N;
    t0 = b11 + FALCON_N;
    t1 = t0 + FALCON_N;

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(b00, g, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(b00, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(b01, f, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(b01, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_neg(b01, b01, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(b10, G, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(b10, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(b11, F, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(b11, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_neg(b11, b11, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_muladj_fft(t1, b00, b10, FALCON_LOGN);   

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulselfadj_fft(t0, b01, FALCON_LOGN);    
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulselfadj_fft(b00, b00, FALCON_LOGN);   
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_add(b00, b00, t0, FALCON_LOGN);      

    memcpy(t0, b01, FALCON_N * sizeof * b01);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_muladj_add_fft(b01, t1, b01, b11, FALCON_LOGN);  

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulselfadj_fft(b10, b10, FALCON_LOGN);   
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulselfadj_add_fft(b10, b10, b11, FALCON_LOGN);    

    g00 = b00;
    g01 = b01;
    g11 = b10;
    b01 = t0;
    t0 = b01 + FALCON_N;
    t1 = t0 + FALCON_N;

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_fpr_of_s16(t0, hm, FALCON_N);

    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(t0, FALCON_LOGN);
    ni = fpr_inverse_of_q;
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_fft(t1, t0, b01, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulconst(t1, t1, fpr_neg(ni), FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_fft(t0, t0, b11, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mulconst(t0, t0, ni, FALCON_LOGN);

    memcpy(b11, t0, FALCON_N * 2 * sizeof * t0);
    t0 = g11 + FALCON_N;
    t1 = t0 + FALCON_N;

    ffSampling_fft_dyntree(samp, samp_ctx,
                           t0, t1, g00, g01, g11, FALCON_LOGN, FALCON_LOGN, t1 + FALCON_N);

    b00 = tmp;
    b01 = b00 + FALCON_N;
    b10 = b01 + FALCON_N;
    b11 = b10 + FALCON_N;
    memmove(b11 + FALCON_N, t0, FALCON_N * 2 * sizeof * t0);
    t0 = b11 + FALCON_N;
    t1 = t0 + FALCON_N;

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(b00, g, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(b00, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(b01, f, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(b01, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_neg(b01, b01, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(b10, G, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(b10, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_smallints_to_fpr(b11, F, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_FFT(b11, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_neg(b11, b11, FALCON_LOGN);

    tx = t1 + FALCON_N;
    ty = tx + FALCON_N;

    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_fft(tx, t0, b00, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_fft(ty, t0, b01, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_add_fft(t0, tx, t1, b10, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_poly_mul_add_fft(t1, ty, t1, b11, FALCON_LOGN);

    PQCLEAN_FALCONPADDED1024_AARCH64_iFFT(t0, FALCON_LOGN);
    PQCLEAN_FALCONPADDED1024_AARCH64_iFFT(t1, FALCON_LOGN);

    s1tmp = (int16_t *)tx;
    s2tmp = (int16_t *)tmp;

    if (PQCLEAN_FALCONPADDED1024_AARCH64_is_short_tmp(s1tmp, s2tmp, (int16_t *) hm, t0, t1)) {
        memcpy(s2, s2tmp, FALCON_N * sizeof * s2);
        memcpy(tmp, s1tmp, FALCON_N * sizeof * s1tmp);
        return 1;
    }
    return 0;
}

void
PQCLEAN_FALCONPADDED1024_AARCH64_sign_tree(int16_t *sig, inner_shake256_context *rng,
        const fpr *restrict expanded_key,
        const uint16_t *hm, uint8_t *tmp) {
    fpr *ftmp;

    ftmp = (fpr *)tmp;
    for (;;) {

        sampler_context spc;
        samplerZ samp;
        void *samp_ctx;

        spc.sigma_min = fpr_sigma_min_10;
        PQCLEAN_FALCONPADDED1024_AARCH64_prng_init(&spc.p, rng);
        samp = PQCLEAN_FALCONPADDED1024_AARCH64_sampler;
        samp_ctx = &spc;

        if (do_sign_tree(samp, samp_ctx, sig, expanded_key, hm, ftmp)) {
            break;
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AARCH64_sign_dyn(int16_t *sig, inner_shake256_context *rng,
        const int8_t *restrict f, const int8_t *restrict g,
        const int8_t *restrict F, const int8_t *restrict G,
        const uint16_t *hm, uint8_t *tmp) {
    fpr *ftmp;

    ftmp = (fpr *)tmp;
    for (;;) {

        sampler_context spc;
        samplerZ samp;
        void *samp_ctx;

        spc.sigma_min = fpr_sigma_min_10;
        PQCLEAN_FALCONPADDED1024_AARCH64_prng_init(&spc.p, rng);
        samp = PQCLEAN_FALCONPADDED1024_AARCH64_sampler;
        samp_ctx = &spc;

        if (do_sign_dyn(samp, samp_ctx, sig, f, g, F, G, hm, ftmp)) {
            break;
        }
    }
}