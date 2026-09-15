
#include "inner.h"

#define MKN(logn)   ((size_t)1 << (logn))

static inline unsigned
ffLDL_treesize(unsigned logn) {

    return (logn + 1) << logn;
}

static void
ffLDL_fft_inner(fpr *tree,
                fpr *g0, fpr *g1, unsigned logn, fpr *tmp) {
    size_t n, hn;

    n = MKN(logn);
    if (n == 1) {
        tree[0] = g0[0];
        return;
    }
    hn = n >> 1;

    PQCLEAN_FALCON1024_AVX2_poly_LDLmv_fft(tmp, tree, g0, g1, g0, logn);

    PQCLEAN_FALCON1024_AVX2_poly_split_fft(g1, g1 + hn, g0, logn);
    PQCLEAN_FALCON1024_AVX2_poly_split_fft(g0, g0 + hn, tmp, logn);

    ffLDL_fft_inner(tree + n,
                    g1, g1 + hn, logn - 1, tmp);
    ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1),
                    g0, g0 + hn, logn - 1, tmp);
}

static void
ffLDL_fft(fpr *tree, const fpr *g00,
          const fpr *g01, const fpr *g11,
          unsigned logn, fpr *tmp) {
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
    PQCLEAN_FALCON1024_AVX2_poly_LDLmv_fft(d11, tree, g00, g01, g11, logn);

    PQCLEAN_FALCON1024_AVX2_poly_split_fft(tmp, tmp + hn, d00, logn);
    PQCLEAN_FALCON1024_AVX2_poly_split_fft(d00, d00 + hn, d11, logn);
    memcpy(d11, tmp, n * sizeof * tmp);
    ffLDL_fft_inner(tree + n,
                    d11, d11 + hn, logn - 1, tmp);
    ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1),
                    d00, d00 + hn, logn - 1, tmp);
}

static void
ffLDL_binary_normalize(fpr *tree, unsigned orig_logn, unsigned logn) {

    size_t n;

    n = MKN(logn);
    if (n == 1) {

        tree[0] = fpr_mul(fpr_sqrt(tree[0]), fpr_inv_sigma[orig_logn]);
    } else {
        ffLDL_binary_normalize(tree + n, orig_logn, logn - 1);
        ffLDL_binary_normalize(tree + n + ffLDL_treesize(logn - 1),
                               orig_logn, logn - 1);
    }
}

static void
smallints_to_fpr(fpr *r, const int8_t *t, unsigned logn) {
    size_t n, u;

    n = MKN(logn);
    for (u = 0; u < n; u ++) {
        r[u] = fpr_of(t[u]);
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
PQCLEAN_FALCON1024_AVX2_expand_privkey(fpr *expanded_key,
                                       const int8_t *f, const int8_t *g,
                                       const int8_t *F, const int8_t *G,
                                       unsigned logn, uint8_t *tmp) {
    size_t n;
    fpr *rf, *rg, *rF, *rG;
    fpr *b00, *b01, *b10, *b11;
    fpr *g00, *g01, *g11, *gxx;
    fpr *tree;

    n = MKN(logn);
    b00 = expanded_key + skoff_b00(logn);
    b01 = expanded_key + skoff_b01(logn);
    b10 = expanded_key + skoff_b10(logn);
    b11 = expanded_key + skoff_b11(logn);
    tree = expanded_key + skoff_tree(logn);

    rf = b01;
    rg = b00;
    rF = b11;
    rG = b10;

    smallints_to_fpr(rf, f, logn);
    smallints_to_fpr(rg, g, logn);
    smallints_to_fpr(rF, F, logn);
    smallints_to_fpr(rG, G, logn);

    PQCLEAN_FALCON1024_AVX2_FFT(rf, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(rg, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(rF, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(rG, logn);
    PQCLEAN_FALCON1024_AVX2_poly_neg(rf, logn);
    PQCLEAN_FALCON1024_AVX2_poly_neg(rF, logn);

    g00 = (fpr *)tmp;
    g01 = g00 + n;
    g11 = g01 + n;
    gxx = g11 + n;

    memcpy(g00, b00, n * sizeof * b00);
    PQCLEAN_FALCON1024_AVX2_poly_mulselfadj_fft(g00, logn);
    memcpy(gxx, b01, n * sizeof * b01);
    PQCLEAN_FALCON1024_AVX2_poly_mulselfadj_fft(gxx, logn);
    PQCLEAN_FALCON1024_AVX2_poly_add(g00, gxx, logn);

    memcpy(g01, b00, n * sizeof * b00);
    PQCLEAN_FALCON1024_AVX2_poly_muladj_fft(g01, b10, logn);
    memcpy(gxx, b01, n * sizeof * b01);
    PQCLEAN_FALCON1024_AVX2_poly_muladj_fft(gxx, b11, logn);
    PQCLEAN_FALCON1024_AVX2_poly_add(g01, gxx, logn);

    memcpy(g11, b10, n * sizeof * b10);
    PQCLEAN_FALCON1024_AVX2_poly_mulselfadj_fft(g11, logn);
    memcpy(gxx, b11, n * sizeof * b11);
    PQCLEAN_FALCON1024_AVX2_poly_mulselfadj_fft(gxx, logn);
    PQCLEAN_FALCON1024_AVX2_poly_add(g11, gxx, logn);

    ffLDL_fft(tree, g00, g01, g11, logn, gxx);

    ffLDL_binary_normalize(tree, logn, logn);
}

typedef int (*samplerZ)(void *ctx, fpr mu, fpr sigma);

static void
ffSampling_fft_dyntree(samplerZ samp, void *samp_ctx,
                       fpr *t0, fpr *t1,
                       fpr *g00, fpr *g01, fpr *g11,
                       unsigned orig_logn, unsigned logn, fpr *tmp) {
    size_t n, hn;
    fpr *z0, *z1;

    if (logn == 0) {
        fpr leaf;

        leaf = g00[0];
        leaf = fpr_mul(fpr_sqrt(leaf), fpr_inv_sigma[orig_logn]);
        t0[0] = fpr_of(samp(samp_ctx, t0[0], leaf));
        t1[0] = fpr_of(samp(samp_ctx, t1[0], leaf));
        return;
    }

    n = (size_t)1 << logn;
    hn = n >> 1;

    PQCLEAN_FALCON1024_AVX2_poly_LDL_fft(g00, g01, g11, logn);

    PQCLEAN_FALCON1024_AVX2_poly_split_fft(tmp, tmp + hn, g00, logn);
    memcpy(g00, tmp, n * sizeof * tmp);
    PQCLEAN_FALCON1024_AVX2_poly_split_fft(tmp, tmp + hn, g11, logn);
    memcpy(g11, tmp, n * sizeof * tmp);
    memcpy(tmp, g01, n * sizeof * g01);
    memcpy(g01, g00, hn * sizeof * g00);
    memcpy(g01 + hn, g11, hn * sizeof * g00);

    z1 = tmp + n;
    PQCLEAN_FALCON1024_AVX2_poly_split_fft(z1, z1 + hn, t1, logn);
    ffSampling_fft_dyntree(samp, samp_ctx, z1, z1 + hn,
                           g11, g11 + hn, g01 + hn, orig_logn, logn - 1, z1 + n);
    PQCLEAN_FALCON1024_AVX2_poly_merge_fft(tmp + (n << 1), z1, z1 + hn, logn);

    memcpy(z1, t1, n * sizeof * t1);
    PQCLEAN_FALCON1024_AVX2_poly_sub(z1, tmp + (n << 1), logn);
    memcpy(t1, tmp + (n << 1), n * sizeof * tmp);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(tmp, z1, logn);
    PQCLEAN_FALCON1024_AVX2_poly_add(t0, tmp, logn);

    z0 = tmp;
    PQCLEAN_FALCON1024_AVX2_poly_split_fft(z0, z0 + hn, t0, logn);
    ffSampling_fft_dyntree(samp, samp_ctx, z0, z0 + hn,
                           g00, g00 + hn, g01, orig_logn, logn - 1, z0 + n);
    PQCLEAN_FALCON1024_AVX2_poly_merge_fft(t0, z0, z0 + hn, logn);
}

static void
ffSampling_fft(samplerZ samp, void *samp_ctx,
               fpr *z0, fpr *z1,
               const fpr *tree,
               const fpr *t0, const fpr *t1, unsigned logn,
               fpr *tmp) {
    size_t n, hn;
    const fpr *tree0, *tree1;

    if (logn == 2) {
        fpr w0, w1, w2, w3, sigma;
        __m128d ww0, ww1, wa, wb, wc, wd;
        __m128d wy0, wy1, wz0, wz1;
        __m128d half, invsqrt8, invsqrt2, neghi, neglo;
        int si0, si1, si2, si3;

        tree0 = tree + 4;
        tree1 = tree + 8;

        half = _mm_set1_pd(0.5);
        invsqrt8 = _mm_set1_pd(0.353553390593273762200422181052);
        invsqrt2 = _mm_set1_pd(0.707106781186547524400844362105);
        neghi = _mm_set_pd(-0.0, 0.0);
        neglo = _mm_set_pd(0.0, -0.0);

        ww0 = _mm_loadu_pd(&t1[0].v);
        ww1 = _mm_loadu_pd(&t1[2].v);
        wa = _mm_unpacklo_pd(ww0, ww1);
        wb = _mm_unpackhi_pd(ww0, ww1);
        wc = _mm_add_pd(wa, wb);
        ww0 = _mm_mul_pd(wc, half);
        wc = _mm_sub_pd(wa, wb);
        wd = _mm_xor_pd(_mm_permute_pd(wc, 1), neghi);
        ww1 = _mm_mul_pd(_mm_add_pd(wc, wd), invsqrt8);

        w2.v = _mm_cvtsd_f64(ww1);
        w3.v = _mm_cvtsd_f64(_mm_permute_pd(ww1, 1));
        wa = ww1;
        sigma = tree1[3];
        si2 = samp(samp_ctx, w2, sigma);
        si3 = samp(samp_ctx, w3, sigma);
        ww1 = _mm_set_pd((double)si3, (double)si2);
        wa = _mm_sub_pd(wa, ww1);
        wb = _mm_loadu_pd(&tree1[0].v);
        wc = _mm_mul_pd(wa, wb);
        wd = _mm_mul_pd(wa, _mm_permute_pd(wb, 1));
        wa = _mm_unpacklo_pd(wc, wd);
        wb = _mm_unpackhi_pd(wc, wd);
        ww0 = _mm_add_pd(ww0, _mm_add_pd(wa, _mm_xor_pd(wb, neglo)));
        w0.v = _mm_cvtsd_f64(ww0);
        w1.v = _mm_cvtsd_f64(_mm_permute_pd(ww0, 1));
        sigma = tree1[2];
        si0 = samp(samp_ctx, w0, sigma);
        si1 = samp(samp_ctx, w1, sigma);
        ww0 = _mm_set_pd((double)si1, (double)si0);

        wc = _mm_mul_pd(
                 _mm_set_pd((double)(si2 + si3), (double)(si2 - si3)),
                 invsqrt2);
        wa = _mm_add_pd(ww0, wc);
        wb = _mm_sub_pd(ww0, wc);
        ww0 = _mm_unpacklo_pd(wa, wb);
        ww1 = _mm_unpackhi_pd(wa, wb);
        _mm_storeu_pd(&z1[0].v, ww0);
        _mm_storeu_pd(&z1[2].v, ww1);

        wy0 = _mm_sub_pd(_mm_loadu_pd(&t1[0].v), ww0);
        wy1 = _mm_sub_pd(_mm_loadu_pd(&t1[2].v), ww1);
        wz0 = _mm_loadu_pd(&tree[0].v);
        wz1 = _mm_loadu_pd(&tree[2].v);
        ww0 = _mm_sub_pd(_mm_mul_pd(wy0, wz0), _mm_mul_pd(wy1, wz1));
        ww1 = _mm_add_pd(_mm_mul_pd(wy0, wz1), _mm_mul_pd(wy1, wz0));
        ww0 = _mm_add_pd(ww0, _mm_loadu_pd(&t0[0].v));
        ww1 = _mm_add_pd(ww1, _mm_loadu_pd(&t0[2].v));

        wa = _mm_unpacklo_pd(ww0, ww1);
        wb = _mm_unpackhi_pd(ww0, ww1);
        wc = _mm_add_pd(wa, wb);
        ww0 = _mm_mul_pd(wc, half);
        wc = _mm_sub_pd(wa, wb);
        wd = _mm_xor_pd(_mm_permute_pd(wc, 1), neghi);
        ww1 = _mm_mul_pd(_mm_add_pd(wc, wd), invsqrt8);

        w2.v = _mm_cvtsd_f64(ww1);
        w3.v = _mm_cvtsd_f64(_mm_permute_pd(ww1, 1));
        wa = ww1;
        sigma = tree0[3];
        si2 = samp(samp_ctx, w2, sigma);
        si3 = samp(samp_ctx, w3, sigma);
        ww1 = _mm_set_pd((double)si3, (double)si2);
        wa = _mm_sub_pd(wa, ww1);
        wb = _mm_loadu_pd(&tree0[0].v);
        wc = _mm_mul_pd(wa, wb);
        wd = _mm_mul_pd(wa, _mm_permute_pd(wb, 1));
        wa = _mm_unpacklo_pd(wc, wd);
        wb = _mm_unpackhi_pd(wc, wd);
        ww0 = _mm_add_pd(ww0, _mm_add_pd(wa, _mm_xor_pd(wb, neglo)));
        w0.v = _mm_cvtsd_f64(ww0);
        w1.v = _mm_cvtsd_f64(_mm_permute_pd(ww0, 1));
        sigma = tree0[2];
        si0 = samp(samp_ctx, w0, sigma);
        si1 = samp(samp_ctx, w1, sigma);
        ww0 = _mm_set_pd((double)si1, (double)si0);

        wc = _mm_mul_pd(
                 _mm_set_pd((double)(si2 + si3), (double)(si2 - si3)),
                 invsqrt2);
        wa = _mm_add_pd(ww0, wc);
        wb = _mm_sub_pd(ww0, wc);
        ww0 = _mm_unpacklo_pd(wa, wb);
        ww1 = _mm_unpackhi_pd(wa, wb);
        _mm_storeu_pd(&z0[0].v, ww0);
        _mm_storeu_pd(&z0[2].v, ww1);

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

    PQCLEAN_FALCON1024_AVX2_poly_split_fft(z1, z1 + hn, t1, logn);
    ffSampling_fft(samp, samp_ctx, tmp, tmp + hn,
                   tree1, z1, z1 + hn, logn - 1, tmp + n);
    PQCLEAN_FALCON1024_AVX2_poly_merge_fft(z1, tmp, tmp + hn, logn);

    memcpy(tmp, t1, n * sizeof * t1);
    PQCLEAN_FALCON1024_AVX2_poly_sub(tmp, z1, logn);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(tmp, tree, logn);
    PQCLEAN_FALCON1024_AVX2_poly_add(tmp, t0, logn);

    PQCLEAN_FALCON1024_AVX2_poly_split_fft(z0, z0 + hn, tmp, logn);
    ffSampling_fft(samp, samp_ctx, tmp, tmp + hn,
                   tree0, z0, z0 + hn, logn - 1, tmp + n);
    PQCLEAN_FALCON1024_AVX2_poly_merge_fft(z0, tmp, tmp + hn, logn);
}

static int
do_sign_tree(samplerZ samp, void *samp_ctx, int16_t *s2,
             const fpr *expanded_key,
             const uint16_t *hm,
             unsigned logn, fpr *tmp) {
    size_t n, u;
    fpr *t0, *t1, *tx, *ty;
    const fpr *b00, *b01, *b10, *b11, *tree;
    fpr ni;
    uint32_t sqn, ng;
    int16_t *s1tmp, *s2tmp;

    n = MKN(logn);
    t0 = tmp;
    t1 = t0 + n;
    b00 = expanded_key + skoff_b00(logn);
    b01 = expanded_key + skoff_b01(logn);
    b10 = expanded_key + skoff_b10(logn);
    b11 = expanded_key + skoff_b11(logn);
    tree = expanded_key + skoff_tree(logn);

    for (u = 0; u < n; u ++) {
        t0[u] = fpr_of(hm[u]);

    }

    PQCLEAN_FALCON1024_AVX2_FFT(t0, logn);
    ni = fpr_inverse_of_q;
    memcpy(t1, t0, n * sizeof * t0);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(t1, b01, logn);
    PQCLEAN_FALCON1024_AVX2_poly_mulconst(t1, fpr_neg(ni), logn);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(t0, b11, logn);
    PQCLEAN_FALCON1024_AVX2_poly_mulconst(t0, ni, logn);

    tx = t1 + n;
    ty = tx + n;

    ffSampling_fft(samp, samp_ctx, tx, ty, tree, t0, t1, logn, ty + n);

    memcpy(t0, tx, n * sizeof * tx);
    memcpy(t1, ty, n * sizeof * ty);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(tx, b00, logn);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(ty, b10, logn);
    PQCLEAN_FALCON1024_AVX2_poly_add(tx, ty, logn);
    memcpy(ty, t0, n * sizeof * t0);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(ty, b01, logn);

    memcpy(t0, tx, n * sizeof * tx);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(t1, b11, logn);
    PQCLEAN_FALCON1024_AVX2_poly_add(t1, ty, logn);

    PQCLEAN_FALCON1024_AVX2_iFFT(t0, logn);
    PQCLEAN_FALCON1024_AVX2_iFFT(t1, logn);

    s1tmp = (int16_t *)tx;
    sqn = 0;
    ng = 0;
    for (u = 0; u < n; u ++) {
        int32_t z;

        z = (int32_t)hm[u] - (int32_t)fpr_rint(t0[u]);
        sqn += (uint32_t)(z * z);
        ng |= sqn;
        s1tmp[u] = (int16_t)z;
    }
    sqn |= -(ng >> 31);

    s2tmp = (int16_t *)tmp;
    for (u = 0; u < n; u ++) {
        s2tmp[u] = (int16_t) - fpr_rint(t1[u]);
    }
    if (PQCLEAN_FALCON1024_AVX2_is_short_half(sqn, s2tmp, logn)) {
        memcpy(s2, s2tmp, n * sizeof * s2);
        memcpy(tmp, s1tmp, n * sizeof * s1tmp);
        return 1;
    }
    return 0;
}

static int
do_sign_dyn(samplerZ samp, void *samp_ctx, int16_t *s2,
            const int8_t *f, const int8_t *g,
            const int8_t *F, const int8_t *G,
            const uint16_t *hm, unsigned logn, fpr *tmp) {
    size_t n, u;
    fpr *t0, *t1, *tx, *ty;
    fpr *b00, *b01, *b10, *b11, *g00, *g01, *g11;
    fpr ni;
    uint32_t sqn, ng;
    int16_t *s1tmp, *s2tmp;

    n = MKN(logn);

    b00 = tmp;
    b01 = b00 + n;
    b10 = b01 + n;
    b11 = b10 + n;
    smallints_to_fpr(b01, f, logn);
    smallints_to_fpr(b00, g, logn);
    smallints_to_fpr(b11, F, logn);
    smallints_to_fpr(b10, G, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(b01, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(b00, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(b11, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(b10, logn);
    PQCLEAN_FALCON1024_AVX2_poly_neg(b01, logn);
    PQCLEAN_FALCON1024_AVX2_poly_neg(b11, logn);

    t0 = b11 + n;
    t1 = t0 + n;

    memcpy(t0, b01, n * sizeof * b01);
    PQCLEAN_FALCON1024_AVX2_poly_mulselfadj_fft(t0, logn);    

    memcpy(t1, b00, n * sizeof * b00);
    PQCLEAN_FALCON1024_AVX2_poly_muladj_fft(t1, b10, logn);   
    PQCLEAN_FALCON1024_AVX2_poly_mulselfadj_fft(b00, logn);   
    PQCLEAN_FALCON1024_AVX2_poly_add(b00, t0, logn);      
    memcpy(t0, b01, n * sizeof * b01);
    PQCLEAN_FALCON1024_AVX2_poly_muladj_fft(b01, b11, logn);  
    PQCLEAN_FALCON1024_AVX2_poly_add(b01, t1, logn);      

    PQCLEAN_FALCON1024_AVX2_poly_mulselfadj_fft(b10, logn);   
    memcpy(t1, b11, n * sizeof * b11);
    PQCLEAN_FALCON1024_AVX2_poly_mulselfadj_fft(t1, logn);    
    PQCLEAN_FALCON1024_AVX2_poly_add(b10, t1, logn);      

    g00 = b00;
    g01 = b01;
    g11 = b10;
    b01 = t0;
    t0 = b01 + n;
    t1 = t0 + n;

    for (u = 0; u < n; u ++) {
        t0[u] = fpr_of(hm[u]);

    }

    PQCLEAN_FALCON1024_AVX2_FFT(t0, logn);
    ni = fpr_inverse_of_q;
    memcpy(t1, t0, n * sizeof * t0);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(t1, b01, logn);
    PQCLEAN_FALCON1024_AVX2_poly_mulconst(t1, fpr_neg(ni), logn);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(t0, b11, logn);
    PQCLEAN_FALCON1024_AVX2_poly_mulconst(t0, ni, logn);

    memcpy(b11, t0, n * 2 * sizeof * t0);
    t0 = g11 + n;
    t1 = t0 + n;

    ffSampling_fft_dyntree(samp, samp_ctx,
                           t0, t1, g00, g01, g11, logn, logn, t1 + n);

    b00 = tmp;
    b01 = b00 + n;
    b10 = b01 + n;
    b11 = b10 + n;
    memmove(b11 + n, t0, n * 2 * sizeof * t0);
    t0 = b11 + n;
    t1 = t0 + n;
    smallints_to_fpr(b01, f, logn);
    smallints_to_fpr(b00, g, logn);
    smallints_to_fpr(b11, F, logn);
    smallints_to_fpr(b10, G, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(b01, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(b00, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(b11, logn);
    PQCLEAN_FALCON1024_AVX2_FFT(b10, logn);
    PQCLEAN_FALCON1024_AVX2_poly_neg(b01, logn);
    PQCLEAN_FALCON1024_AVX2_poly_neg(b11, logn);
    tx = t1 + n;
    ty = tx + n;

    memcpy(tx, t0, n * sizeof * t0);
    memcpy(ty, t1, n * sizeof * t1);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(tx, b00, logn);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(ty, b10, logn);
    PQCLEAN_FALCON1024_AVX2_poly_add(tx, ty, logn);
    memcpy(ty, t0, n * sizeof * t0);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(ty, b01, logn);

    memcpy(t0, tx, n * sizeof * tx);
    PQCLEAN_FALCON1024_AVX2_poly_mul_fft(t1, b11, logn);
    PQCLEAN_FALCON1024_AVX2_poly_add(t1, ty, logn);
    PQCLEAN_FALCON1024_AVX2_iFFT(t0, logn);
    PQCLEAN_FALCON1024_AVX2_iFFT(t1, logn);

    s1tmp = (int16_t *)tx;
    sqn = 0;
    ng = 0;
    for (u = 0; u < n; u ++) {
        int32_t z;

        z = (int32_t)hm[u] - (int32_t)fpr_rint(t0[u]);
        sqn += (uint32_t)(z * z);
        ng |= sqn;
        s1tmp[u] = (int16_t)z;
    }
    sqn |= -(ng >> 31);

    s2tmp = (int16_t *)tmp;
    for (u = 0; u < n; u ++) {
        s2tmp[u] = (int16_t) - fpr_rint(t1[u]);
    }
    if (PQCLEAN_FALCON1024_AVX2_is_short_half(sqn, s2tmp, logn)) {
        memcpy(s2, s2tmp, n * sizeof * s2);
        memcpy(tmp, s1tmp, n * sizeof * s1tmp);
        return 1;
    }
    return 0;
}

int
PQCLEAN_FALCON1024_AVX2_gaussian0_sampler(prng *p) {

    static const union {
        uint16_t u16[16];
        __m256i ymm[1];
    } rhi15 = {
        {
            0x51FB, 0x2A69, 0x113E, 0x0568,
            0x014A, 0x003B, 0x0008, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000
        }
    };

    static const union {
        uint64_t u64[20];
        __m256i ymm[5];
    } rlo57 = {
        {
            0x1F42ED3AC391802, 0x12B181F3F7DDB82,
            0x1CDD0934829C1FF, 0x1754377C7994AE4,
            0x1846CAEF33F1F6F, 0x14AC754ED74BD5F,
            0x024DD542B776AE4, 0x1A1FFDC65AD63DA,
            0x01F80D88A7B6428, 0x001C3FDB2040C69,
            0x00012CF24D031FB, 0x00000949F8B091F,
            0x0000003665DA998, 0x00000000EBF6EBB,
            0x0000000002F5D7E, 0x000000000007098,
            0x0000000000000C6, 0x000000000000001,
            0x000000000000000, 0x000000000000000
        }
    };

    uint64_t lo;
    unsigned hi;
    __m256i xhi, rhi, gthi, eqhi, eqm;
    __m256i xlo, gtlo0, gtlo1, gtlo2, gtlo3, gtlo4;
    __m128i t, zt;
    int r;

    lo = prng_get_u64(p);
    hi = prng_get_u8(p);
    hi = (hi << 7) | (unsigned)(lo >> 57);
    lo &= 0x1FFFFFFFFFFFFFF;

    xhi = _mm256_broadcastw_epi16(_mm_cvtsi32_si128((int)hi));
    rhi = _mm256_loadu_si256(&rhi15.ymm[0]);
    gthi = _mm256_cmpgt_epi16(rhi, xhi);
    eqhi = _mm256_cmpeq_epi16(rhi, xhi);

    t = _mm_srli_epi16(_mm256_castsi256_si128(gthi), 15);
    zt = _mm_setzero_si128();
    t = _mm_hadd_epi16(t, zt);
    t = _mm_hadd_epi16(t, zt);
    t = _mm_hadd_epi16(t, zt);
    r = _mm_cvtsi128_si32(t);

    #if defined(__x86_64__) || defined(_M_X64)
    xlo = _mm256_broadcastq_epi64(_mm_cvtsi64_si128(*(int64_t *)&lo));
    #else
    {
        uint32_t e0, e1;
        int32_t f0, f1;

        e0 = (uint32_t)lo;
        e1 = (uint32_t)(lo >> 32);
        f0 = *(int32_t *)&e0;
        f1 = *(int32_t *)&e1;
        xlo = _mm256_set_epi32(f1, f0, f1, f0, f1, f0, f1, f0);
    }
    #endif
    gtlo0 = _mm256_cmpgt_epi64(_mm256_loadu_si256(&rlo57.ymm[0]), xlo);
    gtlo1 = _mm256_cmpgt_epi64(_mm256_loadu_si256(&rlo57.ymm[1]), xlo);
    gtlo2 = _mm256_cmpgt_epi64(_mm256_loadu_si256(&rlo57.ymm[2]), xlo);
    gtlo3 = _mm256_cmpgt_epi64(_mm256_loadu_si256(&rlo57.ymm[3]), xlo);
    gtlo4 = _mm256_cmpgt_epi64(_mm256_loadu_si256(&rlo57.ymm[4]), xlo);

    gtlo0 = _mm256_and_si256(gtlo0, _mm256_cvtepi16_epi64(
                                 _mm256_castsi256_si128(eqhi)));
    gtlo1 = _mm256_and_si256(gtlo1, _mm256_cvtepi16_epi64(
                                 _mm256_castsi256_si128(_mm256_bsrli_epi128(eqhi, 8))));
    eqm = _mm256_permute4x64_epi64(eqhi, 0xFF);
    gtlo2 = _mm256_and_si256(gtlo2, eqm);
    gtlo3 = _mm256_and_si256(gtlo3, eqm);
    gtlo4 = _mm256_and_si256(gtlo4, eqm);

    gtlo0 = _mm256_or_si256(gtlo0, gtlo1);
    gtlo0 = _mm256_add_epi64(
                _mm256_add_epi64(gtlo0, gtlo2),
                _mm256_add_epi64(gtlo3, gtlo4));
    t = _mm_add_epi64(
            _mm256_castsi256_si128(gtlo0),
            _mm256_extracti128_si256(gtlo0, 1));
    t = _mm_add_epi64(t, _mm_srli_si128(t, 8));
    r -= _mm_cvtsi128_si32(t);

    return r;

}

static int
BerExp(prng *p, fpr x, fpr ccs) {
    int s, i;
    fpr r;
    uint32_t sw, w;
    uint64_t z;

    s = (int)fpr_trunc(fpr_mul(x, fpr_inv_log2));
    r = fpr_sub(x, fpr_mul(fpr_of(s), fpr_log2));

    sw = (uint32_t)s;
    sw ^= (sw ^ 63) & -((63 - sw) >> 31);
    s = (int)sw;

    z = ((fpr_expm_p63(r, ccs) << 1) - 1) >> s;

    i = 64;
    do {
        i -= 8;
        w = prng_get_u8(p) - ((uint32_t)(z >> i) & 0xFF);
    } while (!w && i > 0);
    return (int)(w >> 31);
}

int
PQCLEAN_FALCON1024_AVX2_sampler(void *ctx, fpr mu, fpr isigma) {
    sampler_context *spc;
    int s;
    fpr r, dss, ccs;

    spc = ctx;

    s = (int)fpr_floor(mu);
    r = fpr_sub(mu, fpr_of(s));

    dss = fpr_half(fpr_sqr(isigma));

    ccs = fpr_mul(isigma, spc->sigma_min);

    for (;;) {
        int z0, z, b;
        fpr x;

        z0 = PQCLEAN_FALCON1024_AVX2_gaussian0_sampler(&spc->p);
        b = (int)prng_get_u8(&spc->p) & 1;
        z = b + ((b << 1) - 1) * z0;

        x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(z), r)), dss);
        x = fpr_sub(x, fpr_mul(fpr_of(z0 * z0), fpr_inv_2sqrsigma0));
        if (BerExp(&spc->p, x, ccs)) {

            return s + z;
        }
    }
}

void
PQCLEAN_FALCON1024_AVX2_sign_tree(int16_t *sig, inner_shake256_context *rng,
                                  const fpr *expanded_key,
                                  const uint16_t *hm, unsigned logn, uint8_t *tmp) {
    fpr *ftmp;

    ftmp = (fpr *)tmp;
    for (;;) {

        sampler_context spc;
        samplerZ samp;
        void *samp_ctx;

        spc.sigma_min = fpr_sigma_min[logn];
        PQCLEAN_FALCON1024_AVX2_prng_init(&spc.p, rng);
        samp = PQCLEAN_FALCON1024_AVX2_sampler;
        samp_ctx = &spc;

        if (do_sign_tree(samp, samp_ctx, sig,
                         expanded_key, hm, logn, ftmp)) {
            break;
        }
    }
}

void
PQCLEAN_FALCON1024_AVX2_sign_dyn(int16_t *sig, inner_shake256_context *rng,
                                 const int8_t *f, const int8_t *g,
                                 const int8_t *F, const int8_t *G,
                                 const uint16_t *hm, unsigned logn, uint8_t *tmp) {
    fpr *ftmp;

    ftmp = (fpr *)tmp;
    for (;;) {

        sampler_context spc;
        samplerZ samp;
        void *samp_ctx;

        spc.sigma_min = fpr_sigma_min[logn];
        PQCLEAN_FALCON1024_AVX2_prng_init(&spc.p, rng);
        samp = PQCLEAN_FALCON1024_AVX2_sampler;
        samp_ctx = &spc;

        if (do_sign_dyn(samp, samp_ctx, sig,
                        f, g, F, G, hm, logn, ftmp)) {
            break;
        }
    }
}