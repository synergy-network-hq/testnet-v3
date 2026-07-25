
#include "inner.h"

#define FPC_ADD(d_re, d_im, a_re, a_im, b_re, b_im)   do { \
        fpr fpct_re, fpct_im; \
        fpct_re = fpr_add(a_re, b_re); \
        fpct_im = fpr_add(a_im, b_im); \
        (d_re) = fpct_re; \
        (d_im) = fpct_im; \
    } while (0)

#define FPC_SUB(d_re, d_im, a_re, a_im, b_re, b_im)   do { \
        fpr fpct_re, fpct_im; \
        fpct_re = fpr_sub(a_re, b_re); \
        fpct_im = fpr_sub(a_im, b_im); \
        (d_re) = fpct_re; \
        (d_im) = fpct_im; \
    } while (0)

#define FPC_MUL(d_re, d_im, a_re, a_im, b_re, b_im)   do { \
        fpr fpct_a_re, fpct_a_im; \
        fpr fpct_b_re, fpct_b_im; \
        fpr fpct_d_re, fpct_d_im; \
        fpct_a_re = (a_re); \
        fpct_a_im = (a_im); \
        fpct_b_re = (b_re); \
        fpct_b_im = (b_im); \
        fpct_d_re = fpr_sub( \
                             fpr_mul(fpct_a_re, fpct_b_re), \
                             fpr_mul(fpct_a_im, fpct_b_im)); \
        fpct_d_im = fpr_add( \
                             fpr_mul(fpct_a_re, fpct_b_im), \
                             fpr_mul(fpct_a_im, fpct_b_re)); \
        (d_re) = fpct_d_re; \
        (d_im) = fpct_d_im; \
    } while (0)

#define FPC_SQR(d_re, d_im, a_re, a_im)   do { \
        fpr fpct_a_re, fpct_a_im; \
        fpr fpct_d_re, fpct_d_im; \
        fpct_a_re = (a_re); \
        fpct_a_im = (a_im); \
        fpct_d_re = fpr_sub(fpr_sqr(fpct_a_re), fpr_sqr(fpct_a_im)); \
        fpct_d_im = fpr_double(fpr_mul(fpct_a_re, fpct_a_im)); \
        (d_re) = fpct_d_re; \
        (d_im) = fpct_d_im; \
    } while (0)

#define FPC_INV(d_re, d_im, a_re, a_im)   do { \
        fpr fpct_a_re, fpct_a_im; \
        fpr fpct_d_re, fpct_d_im; \
        fpr fpct_m; \
        fpct_a_re = (a_re); \
        fpct_a_im = (a_im); \
        fpct_m = fpr_add(fpr_sqr(fpct_a_re), fpr_sqr(fpct_a_im)); \
        fpct_m = fpr_inv(fpct_m); \
        fpct_d_re = fpr_mul(fpct_a_re, fpct_m); \
        fpct_d_im = fpr_mul(fpr_neg(fpct_a_im), fpct_m); \
        (d_re) = fpct_d_re; \
        (d_im) = fpct_d_im; \
    } while (0)

#define FPC_DIV(d_re, d_im, a_re, a_im, b_re, b_im)   do { \
        fpr fpct_a_re, fpct_a_im; \
        fpr fpct_b_re, fpct_b_im; \
        fpr fpct_d_re, fpct_d_im; \
        fpr fpct_m; \
        fpct_a_re = (a_re); \
        fpct_a_im = (a_im); \
        fpct_b_re = (b_re); \
        fpct_b_im = (b_im); \
        fpct_m = fpr_add(fpr_sqr(fpct_b_re), fpr_sqr(fpct_b_im)); \
        fpct_m = fpr_inv(fpct_m); \
        fpct_b_re = fpr_mul(fpct_b_re, fpct_m); \
        fpct_b_im = fpr_mul(fpr_neg(fpct_b_im), fpct_m); \
        fpct_d_re = fpr_sub( \
                             fpr_mul(fpct_a_re, fpct_b_re), \
                             fpr_mul(fpct_a_im, fpct_b_im)); \
        fpct_d_im = fpr_add( \
                             fpr_mul(fpct_a_re, fpct_b_im), \
                             fpr_mul(fpct_a_im, fpct_b_re)); \
        (d_re) = fpct_d_re; \
        (d_im) = fpct_d_im; \
    } while (0)

void
PQCLEAN_FALCONPADDED1024_AVX2_FFT(fpr *f, unsigned logn) {

    unsigned u;
    size_t t, n, hn, m;

    n = (size_t)1 << logn;
    hn = n >> 1;
    t = hn;
    for (u = 1, m = 2; u < logn; u ++, m <<= 1) {
        size_t ht, hm, i1, j1;

        ht = t >> 1;
        hm = m >> 1;
        for (i1 = 0, j1 = 0; i1 < hm; i1 ++, j1 += t) {
            size_t j, j2;

            j2 = j1 + ht;
            if (ht >= 4) {
                __m256d s_re, s_im;

                s_re = _mm256_set1_pd(
                           fpr_gm_tab[((m + i1) << 1) + 0].v);
                s_im = _mm256_set1_pd(
                           fpr_gm_tab[((m + i1) << 1) + 1].v);
                for (j = j1; j < j2; j += 4) {
                    __m256d x_re, x_im, y_re, y_im;
                    __m256d z_re, z_im;

                    x_re = _mm256_loadu_pd(&f[j].v);
                    x_im = _mm256_loadu_pd(&f[j + hn].v);
                    z_re = _mm256_loadu_pd(&f[j + ht].v);
                    z_im = _mm256_loadu_pd(&f[j + ht + hn].v);
                    y_re = FMSUB(z_re, s_re,
                                 _mm256_mul_pd(z_im, s_im));
                    y_im = FMADD(z_re, s_im,
                                 _mm256_mul_pd(z_im, s_re));
                    _mm256_storeu_pd(&f[j].v,
                                     _mm256_add_pd(x_re, y_re));
                    _mm256_storeu_pd(&f[j + hn].v,
                                     _mm256_add_pd(x_im, y_im));
                    _mm256_storeu_pd(&f[j + ht].v,
                                     _mm256_sub_pd(x_re, y_re));
                    _mm256_storeu_pd(&f[j + ht + hn].v,
                                     _mm256_sub_pd(x_im, y_im));
                }
            } else {
                fpr s_re, s_im;

                s_re = fpr_gm_tab[((m + i1) << 1) + 0];
                s_im = fpr_gm_tab[((m + i1) << 1) + 1];
                for (j = j1; j < j2; j ++) {
                    fpr x_re, x_im, y_re, y_im;

                    x_re = f[j];
                    x_im = f[j + hn];
                    y_re = f[j + ht];
                    y_im = f[j + ht + hn];
                    FPC_MUL(y_re, y_im,
                            y_re, y_im, s_re, s_im);
                    FPC_ADD(f[j], f[j + hn],
                            x_re, x_im, y_re, y_im);
                    FPC_SUB(f[j + ht], f[j + ht + hn],
                            x_re, x_im, y_re, y_im);
                }
            }
        }
        t = ht;
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_iFFT(fpr *f, unsigned logn) {

    size_t u, n, hn, t, m;

    n = (size_t)1 << logn;
    t = 1;
    m = n;
    hn = n >> 1;
    for (u = logn; u > 1; u --) {
        size_t hm, dt, i1, j1;

        hm = m >> 1;
        dt = t << 1;
        for (i1 = 0, j1 = 0; j1 < hn; i1 ++, j1 += dt) {
            size_t j, j2;

            j2 = j1 + t;
            if (t >= 4) {
                __m256d s_re, s_im;

                s_re = _mm256_set1_pd(
                           fpr_gm_tab[((hm + i1) << 1) + 0].v);
                s_im = _mm256_set1_pd(
                           fpr_gm_tab[((hm + i1) << 1) + 1].v);
                for (j = j1; j < j2; j += 4) {
                    __m256d x_re, x_im, y_re, y_im;
                    __m256d z_re, z_im;

                    x_re = _mm256_loadu_pd(&f[j].v);
                    x_im = _mm256_loadu_pd(&f[j + hn].v);
                    y_re = _mm256_loadu_pd(&f[j + t].v);
                    y_im = _mm256_loadu_pd(&f[j + t + hn].v);
                    _mm256_storeu_pd(&f[j].v,
                                     _mm256_add_pd(x_re, y_re));
                    _mm256_storeu_pd(&f[j + hn].v,
                                     _mm256_add_pd(x_im, y_im));
                    x_re = _mm256_sub_pd(y_re, x_re);
                    x_im = _mm256_sub_pd(x_im, y_im);
                    z_re = FMSUB(x_im, s_im,
                                 _mm256_mul_pd(x_re, s_re));
                    z_im = FMADD(x_re, s_im,
                                 _mm256_mul_pd(x_im, s_re));
                    _mm256_storeu_pd(&f[j + t].v, z_re);
                    _mm256_storeu_pd(&f[j + t + hn].v, z_im);
                }
            } else {
                fpr s_re, s_im;

                s_re = fpr_gm_tab[((hm + i1) << 1) + 0];
                s_im = fpr_neg(fpr_gm_tab[((hm + i1) << 1) + 1]);
                for (j = j1; j < j2; j ++) {
                    fpr x_re, x_im, y_re, y_im;

                    x_re = f[j];
                    x_im = f[j + hn];
                    y_re = f[j + t];
                    y_im = f[j + t + hn];
                    FPC_ADD(f[j], f[j + hn],
                            x_re, x_im, y_re, y_im);
                    FPC_SUB(x_re, x_im,
                            x_re, x_im, y_re, y_im);
                    FPC_MUL(f[j + t], f[j + t + hn],
                            x_re, x_im, s_re, s_im);
                }
            }
        }
        t = dt;
        m = hm;
    }

    if (logn > 0) {
        fpr ni;

        ni = fpr_p2_tab[logn];
        for (u = 0; u < n; u ++) {
            f[u] = fpr_mul(f[u], ni);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_add(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    if (n >= 4) {
        for (u = 0; u < n; u += 4) {
            _mm256_storeu_pd(&a[u].v,
                             _mm256_add_pd(
                                 _mm256_loadu_pd(&a[u].v),
                                 _mm256_loadu_pd(&b[u].v)));
        }
    } else {
        for (u = 0; u < n; u ++) {
            a[u] = fpr_add(a[u], b[u]);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_sub(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    if (n >= 4) {
        for (u = 0; u < n; u += 4) {
            _mm256_storeu_pd(&a[u].v,
                             _mm256_sub_pd(
                                 _mm256_loadu_pd(&a[u].v),
                                 _mm256_loadu_pd(&b[u].v)));
        }
    } else {
        for (u = 0; u < n; u ++) {
            a[u] = fpr_sub(a[u], b[u]);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_neg(fpr *a, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    if (n >= 4) {
        __m256d s;

        s = _mm256_set1_pd(-0.0);
        for (u = 0; u < n; u += 4) {
            _mm256_storeu_pd(&a[u].v,
                             _mm256_xor_pd(_mm256_loadu_pd(&a[u].v), s));
        }
    } else {
        for (u = 0; u < n; u ++) {
            a[u] = fpr_neg(a[u]);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_adj_fft(fpr *a, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    if (n >= 8) {
        __m256d s;

        s = _mm256_set1_pd(-0.0);
        for (u = (n >> 1); u < n; u += 4) {
            _mm256_storeu_pd(&a[u].v,
                             _mm256_xor_pd(_mm256_loadu_pd(&a[u].v), s));
        }
    } else {
        for (u = (n >> 1); u < n; u ++) {
            a[u] = fpr_neg(a[u]);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_mul_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        for (u = 0; u < hn; u += 4) {
            __m256d a_re, a_im, b_re, b_im, c_re, c_im;

            a_re = _mm256_loadu_pd(&a[u].v);
            a_im = _mm256_loadu_pd(&a[u + hn].v);
            b_re = _mm256_loadu_pd(&b[u].v);
            b_im = _mm256_loadu_pd(&b[u + hn].v);
            c_re = FMSUB(
                       a_re, b_re, _mm256_mul_pd(a_im, b_im));
            c_im = FMADD(
                       a_re, b_im, _mm256_mul_pd(a_im, b_re));
            _mm256_storeu_pd(&a[u].v, c_re);
            _mm256_storeu_pd(&a[u + hn].v, c_im);
        }
    } else {
        for (u = 0; u < hn; u ++) {
            fpr a_re, a_im, b_re, b_im;

            a_re = a[u];
            a_im = a[u + hn];
            b_re = b[u];
            b_im = b[u + hn];
            FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_muladj_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        for (u = 0; u < hn; u += 4) {
            __m256d a_re, a_im, b_re, b_im, c_re, c_im;

            a_re = _mm256_loadu_pd(&a[u].v);
            a_im = _mm256_loadu_pd(&a[u + hn].v);
            b_re = _mm256_loadu_pd(&b[u].v);
            b_im = _mm256_loadu_pd(&b[u + hn].v);
            c_re = FMADD(
                       a_re, b_re, _mm256_mul_pd(a_im, b_im));
            c_im = FMSUB(
                       a_im, b_re, _mm256_mul_pd(a_re, b_im));
            _mm256_storeu_pd(&a[u].v, c_re);
            _mm256_storeu_pd(&a[u + hn].v, c_im);
        }
    } else {
        for (u = 0; u < hn; u ++) {
            fpr a_re, a_im, b_re, b_im;

            a_re = a[u];
            a_im = a[u + hn];
            b_re = b[u];
            b_im = fpr_neg(b[u + hn]);
            FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_mulselfadj_fft(fpr *a, unsigned logn) {

    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        __m256d zero;

        zero = _mm256_setzero_pd();
        for (u = 0; u < hn; u += 4) {
            __m256d a_re, a_im;

            a_re = _mm256_loadu_pd(&a[u].v);
            a_im = _mm256_loadu_pd(&a[u + hn].v);
            _mm256_storeu_pd(&a[u].v,
                             FMADD(a_re, a_re,
                                   _mm256_mul_pd(a_im, a_im)));
            _mm256_storeu_pd(&a[u + hn].v, zero);
        }
    } else {
        for (u = 0; u < hn; u ++) {
            fpr a_re, a_im;

            a_re = a[u];
            a_im = a[u + hn];
            a[u] = fpr_add(fpr_sqr(a_re), fpr_sqr(a_im));
            a[u + hn] = fpr_zero;
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_mulconst(fpr *a, fpr x, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    if (n >= 4) {
        __m256d x4;

        x4 = _mm256_set1_pd(x.v);
        for (u = 0; u < n; u += 4) {
            _mm256_storeu_pd(&a[u].v,
                             _mm256_mul_pd(x4, _mm256_loadu_pd(&a[u].v)));
        }
    } else {
        for (u = 0; u < n; u ++) {
            a[u] = fpr_mul(a[u], x);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_div_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        __m256d one;

        one = _mm256_set1_pd(1.0);
        for (u = 0; u < hn; u += 4) {
            __m256d a_re, a_im, b_re, b_im, c_re, c_im, t;

            a_re = _mm256_loadu_pd(&a[u].v);
            a_im = _mm256_loadu_pd(&a[u + hn].v);
            b_re = _mm256_loadu_pd(&b[u].v);
            b_im = _mm256_loadu_pd(&b[u + hn].v);
            t = _mm256_div_pd(one,
                              FMADD(b_re, b_re,
                                    _mm256_mul_pd(b_im, b_im)));
            b_re = _mm256_mul_pd(b_re, t);
            b_im = _mm256_mul_pd(b_im, t);
            c_re = FMADD(
                       a_re, b_re, _mm256_mul_pd(a_im, b_im));
            c_im = FMSUB(
                       a_im, b_re, _mm256_mul_pd(a_re, b_im));
            _mm256_storeu_pd(&a[u].v, c_re);
            _mm256_storeu_pd(&a[u + hn].v, c_im);
        }
    } else {
        for (u = 0; u < hn; u ++) {
            fpr a_re, a_im, b_re, b_im;

            a_re = a[u];
            a_im = a[u + hn];
            b_re = b[u];
            b_im = b[u + hn];
            FPC_DIV(a[u], a[u + hn], a_re, a_im, b_re, b_im);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_invnorm2_fft(fpr *d,
        const fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        __m256d one;

        one = _mm256_set1_pd(1.0);
        for (u = 0; u < hn; u += 4) {
            __m256d a_re, a_im, b_re, b_im, dv;

            a_re = _mm256_loadu_pd(&a[u].v);
            a_im = _mm256_loadu_pd(&a[u + hn].v);
            b_re = _mm256_loadu_pd(&b[u].v);
            b_im = _mm256_loadu_pd(&b[u + hn].v);
            dv = _mm256_div_pd(one,
                               _mm256_add_pd(
                                   FMADD(a_re, a_re,
                                         _mm256_mul_pd(a_im, a_im)),
                                   FMADD(b_re, b_re,
                                         _mm256_mul_pd(b_im, b_im))));
            _mm256_storeu_pd(&d[u].v, dv);
        }
    } else {
        for (u = 0; u < hn; u ++) {
            fpr a_re, a_im;
            fpr b_re, b_im;

            a_re = a[u];
            a_im = a[u + hn];
            b_re = b[u];
            b_im = b[u + hn];
            d[u] = fpr_inv(fpr_add(
                               fpr_add(fpr_sqr(a_re), fpr_sqr(a_im)),
                               fpr_add(fpr_sqr(b_re), fpr_sqr(b_im))));
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_add_muladj_fft(fpr *d,
        const fpr *F, const fpr *G,
        const fpr *f, const fpr *g, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        for (u = 0; u < hn; u += 4) {
            __m256d F_re, F_im, G_re, G_im;
            __m256d f_re, f_im, g_re, g_im;
            __m256d a_re, a_im, b_re, b_im;

            F_re = _mm256_loadu_pd(&F[u].v);
            F_im = _mm256_loadu_pd(&F[u + hn].v);
            G_re = _mm256_loadu_pd(&G[u].v);
            G_im = _mm256_loadu_pd(&G[u + hn].v);
            f_re = _mm256_loadu_pd(&f[u].v);
            f_im = _mm256_loadu_pd(&f[u + hn].v);
            g_re = _mm256_loadu_pd(&g[u].v);
            g_im = _mm256_loadu_pd(&g[u + hn].v);

            a_re = FMADD(F_re, f_re,
                         _mm256_mul_pd(F_im, f_im));
            a_im = FMSUB(F_im, f_re,
                         _mm256_mul_pd(F_re, f_im));
            b_re = FMADD(G_re, g_re,
                         _mm256_mul_pd(G_im, g_im));
            b_im = FMSUB(G_im, g_re,
                         _mm256_mul_pd(G_re, g_im));
            _mm256_storeu_pd(&d[u].v,
                             _mm256_add_pd(a_re, b_re));
            _mm256_storeu_pd(&d[u + hn].v,
                             _mm256_add_pd(a_im, b_im));
        }
    } else {
        for (u = 0; u < hn; u ++) {
            fpr F_re, F_im, G_re, G_im;
            fpr f_re, f_im, g_re, g_im;
            fpr a_re, a_im, b_re, b_im;

            F_re = F[u];
            F_im = F[u + hn];
            G_re = G[u];
            G_im = G[u + hn];
            f_re = f[u];
            f_im = f[u + hn];
            g_re = g[u];
            g_im = g[u + hn];

            FPC_MUL(a_re, a_im, F_re, F_im, f_re, fpr_neg(f_im));
            FPC_MUL(b_re, b_im, G_re, G_im, g_re, fpr_neg(g_im));
            d[u] = fpr_add(a_re, b_re);
            d[u + hn] = fpr_add(a_im, b_im);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_mul_autoadj_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        for (u = 0; u < hn; u += 4) {
            __m256d a_re, a_im, bv;

            a_re = _mm256_loadu_pd(&a[u].v);
            a_im = _mm256_loadu_pd(&a[u + hn].v);
            bv = _mm256_loadu_pd(&b[u].v);
            _mm256_storeu_pd(&a[u].v,
                             _mm256_mul_pd(a_re, bv));
            _mm256_storeu_pd(&a[u + hn].v,
                             _mm256_mul_pd(a_im, bv));
        }
    } else {
        for (u = 0; u < hn; u ++) {
            a[u] = fpr_mul(a[u], b[u]);
            a[u + hn] = fpr_mul(a[u + hn], b[u]);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_div_autoadj_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        __m256d one;

        one = _mm256_set1_pd(1.0);
        for (u = 0; u < hn; u += 4) {
            __m256d ib, a_re, a_im;

            ib = _mm256_div_pd(one, _mm256_loadu_pd(&b[u].v));
            a_re = _mm256_loadu_pd(&a[u].v);
            a_im = _mm256_loadu_pd(&a[u + hn].v);
            _mm256_storeu_pd(&a[u].v, _mm256_mul_pd(a_re, ib));
            _mm256_storeu_pd(&a[u + hn].v, _mm256_mul_pd(a_im, ib));
        }
    } else {
        for (u = 0; u < hn; u ++) {
            fpr ib;

            ib = fpr_inv(b[u]);
            a[u] = fpr_mul(a[u], ib);
            a[u + hn] = fpr_mul(a[u + hn], ib);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_LDL_fft(
    const fpr *g00,
    fpr *g01, fpr *g11, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        __m256d one;

        one = _mm256_set1_pd(1.0);
        for (u = 0; u < hn; u += 4) {
            __m256d g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
            __m256d t, mu_re, mu_im, xi_re, xi_im;

            g00_re = _mm256_loadu_pd(&g00[u].v);
            g00_im = _mm256_loadu_pd(&g00[u + hn].v);
            g01_re = _mm256_loadu_pd(&g01[u].v);
            g01_im = _mm256_loadu_pd(&g01[u + hn].v);
            g11_re = _mm256_loadu_pd(&g11[u].v);
            g11_im = _mm256_loadu_pd(&g11[u + hn].v);

            t = _mm256_div_pd(one,
                              FMADD(g00_re, g00_re,
                                    _mm256_mul_pd(g00_im, g00_im)));
            g00_re = _mm256_mul_pd(g00_re, t);
            g00_im = _mm256_mul_pd(g00_im, t);
            mu_re = FMADD(g01_re, g00_re,
                          _mm256_mul_pd(g01_im, g00_im));
            mu_im = FMSUB(g01_re, g00_im,
                          _mm256_mul_pd(g01_im, g00_re));
            xi_re = FMSUB(mu_re, g01_re,
                          _mm256_mul_pd(mu_im, g01_im));
            xi_im = FMADD(mu_im, g01_re,
                          _mm256_mul_pd(mu_re, g01_im));
            _mm256_storeu_pd(&g11[u].v,
                             _mm256_sub_pd(g11_re, xi_re));
            _mm256_storeu_pd(&g11[u + hn].v,
                             _mm256_add_pd(g11_im, xi_im));
            _mm256_storeu_pd(&g01[u].v, mu_re);
            _mm256_storeu_pd(&g01[u + hn].v, mu_im);
        }
    } else {
        for (u = 0; u < hn; u ++) {
            fpr g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
            fpr mu_re, mu_im;

            g00_re = g00[u];
            g00_im = g00[u + hn];
            g01_re = g01[u];
            g01_im = g01[u + hn];
            g11_re = g11[u];
            g11_im = g11[u + hn];
            FPC_DIV(mu_re, mu_im, g01_re, g01_im, g00_re, g00_im);
            FPC_MUL(g01_re, g01_im,
                    mu_re, mu_im, g01_re, fpr_neg(g01_im));
            FPC_SUB(g11[u], g11[u + hn],
                    g11_re, g11_im, g01_re, g01_im);
            g01[u] = mu_re;
            g01[u + hn] = fpr_neg(mu_im);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_LDLmv_fft(
    fpr *d11, fpr *l10,
    const fpr *g00, const fpr *g01,
    const fpr *g11, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    if (n >= 8) {
        __m256d one;

        one = _mm256_set1_pd(1.0);
        for (u = 0; u < hn; u += 4) {
            __m256d g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
            __m256d t, mu_re, mu_im, xi_re, xi_im;

            g00_re = _mm256_loadu_pd(&g00[u].v);
            g00_im = _mm256_loadu_pd(&g00[u + hn].v);
            g01_re = _mm256_loadu_pd(&g01[u].v);
            g01_im = _mm256_loadu_pd(&g01[u + hn].v);
            g11_re = _mm256_loadu_pd(&g11[u].v);
            g11_im = _mm256_loadu_pd(&g11[u + hn].v);

            t = _mm256_div_pd(one,
                              FMADD(g00_re, g00_re,
                                    _mm256_mul_pd(g00_im, g00_im)));
            g00_re = _mm256_mul_pd(g00_re, t);
            g00_im = _mm256_mul_pd(g00_im, t);
            mu_re = FMADD(g01_re, g00_re,
                          _mm256_mul_pd(g01_im, g00_im));
            mu_im = FMSUB(g01_re, g00_im,
                          _mm256_mul_pd(g01_im, g00_re));
            xi_re = FMSUB(mu_re, g01_re,
                          _mm256_mul_pd(mu_im, g01_im));
            xi_im = FMADD(mu_im, g01_re,
                          _mm256_mul_pd(mu_re, g01_im));
            _mm256_storeu_pd(&d11[u].v,
                             _mm256_sub_pd(g11_re, xi_re));
            _mm256_storeu_pd(&d11[u + hn].v,
                             _mm256_add_pd(g11_im, xi_im));
            _mm256_storeu_pd(&l10[u].v, mu_re);
            _mm256_storeu_pd(&l10[u + hn].v, mu_im);
        }
    } else {
        for (u = 0; u < hn; u ++) {
            fpr g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
            fpr mu_re, mu_im;

            g00_re = g00[u];
            g00_im = g00[u + hn];
            g01_re = g01[u];
            g01_im = g01[u + hn];
            g11_re = g11[u];
            g11_im = g11[u + hn];
            FPC_DIV(mu_re, mu_im, g01_re, g01_im, g00_re, g00_im);
            FPC_MUL(g01_re, g01_im,
                    mu_re, mu_im, g01_re, fpr_neg(g01_im));
            FPC_SUB(d11[u], d11[u + hn],
                    g11_re, g11_im, g01_re, g01_im);
            l10[u] = mu_re;
            l10[u + hn] = fpr_neg(mu_im);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_split_fft(
    fpr *f0, fpr *f1,
    const fpr *f, unsigned logn) {

    size_t n, hn, qn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    qn = hn >> 1;

    if (n >= 8) {
        __m256d half, sv;

        half = _mm256_set1_pd(0.5);
        sv = _mm256_set_pd(-0.0, 0.0, -0.0, 0.0);
        for (u = 0; u < qn; u += 2) {
            __m256d ab_re, ab_im, ff0, ff1, ff2, ff3, gmt;

            ab_re = _mm256_loadu_pd(&f[(u << 1)].v);
            ab_im = _mm256_loadu_pd(&f[(u << 1) + hn].v);
            ff0 = _mm256_mul_pd(_mm256_hadd_pd(ab_re, ab_im), half);
            ff0 = _mm256_permute4x64_pd(ff0, 0xD8);
            _mm_storeu_pd(&f0[u].v,
                          _mm256_extractf128_pd(ff0, 0));
            _mm_storeu_pd(&f0[u + qn].v,
                          _mm256_extractf128_pd(ff0, 1));

            ff1 = _mm256_mul_pd(_mm256_hsub_pd(ab_re, ab_im), half);
            gmt = _mm256_loadu_pd(&fpr_gm_tab[(u + hn) << 1].v);
            ff2 = _mm256_shuffle_pd(ff1, ff1, 0x5);
            ff3 = _mm256_hadd_pd(
                      _mm256_mul_pd(ff1, gmt),
                      _mm256_xor_pd(_mm256_mul_pd(ff2, gmt), sv));
            ff3 = _mm256_permute4x64_pd(ff3, 0xD8);
            _mm_storeu_pd(&f1[u].v,
                          _mm256_extractf128_pd(ff3, 0));
            _mm_storeu_pd(&f1[u + qn].v,
                          _mm256_extractf128_pd(ff3, 1));
        }
    } else {
        f0[0] = f[0];
        f1[0] = f[hn];

        for (u = 0; u < qn; u ++) {
            fpr a_re, a_im, b_re, b_im;
            fpr t_re, t_im;

            a_re = f[(u << 1) + 0];
            a_im = f[(u << 1) + 0 + hn];
            b_re = f[(u << 1) + 1];
            b_im = f[(u << 1) + 1 + hn];

            FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
            f0[u] = fpr_half(t_re);
            f0[u + qn] = fpr_half(t_im);

            FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
            FPC_MUL(t_re, t_im, t_re, t_im,
                    fpr_gm_tab[((u + hn) << 1) + 0],
                    fpr_neg(fpr_gm_tab[((u + hn) << 1) + 1]));
            f1[u] = fpr_half(t_re);
            f1[u + qn] = fpr_half(t_im);
        }
    }
}

void
PQCLEAN_FALCONPADDED1024_AVX2_poly_merge_fft(
    fpr *f,
    const fpr *f0, const fpr *f1, unsigned logn) {
    size_t n, hn, qn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    qn = hn >> 1;

    if (n >= 16) {
        for (u = 0; u < qn; u += 4) {
            __m256d a_re, a_im, b_re, b_im, c_re, c_im;
            __m256d gm1, gm2, g_re, g_im;
            __m256d t_re, t_im, u_re, u_im;
            __m256d tu1_re, tu2_re, tu1_im, tu2_im;

            a_re = _mm256_loadu_pd(&f0[u].v);
            a_im = _mm256_loadu_pd(&f0[u + qn].v);
            c_re = _mm256_loadu_pd(&f1[u].v);
            c_im = _mm256_loadu_pd(&f1[u + qn].v);

            gm1 = _mm256_loadu_pd(&fpr_gm_tab[(u + hn) << 1].v);
            gm2 = _mm256_loadu_pd(&fpr_gm_tab[(u + 2 + hn) << 1].v);
            g_re = _mm256_unpacklo_pd(gm1, gm2);
            g_im = _mm256_unpackhi_pd(gm1, gm2);
            g_re = _mm256_permute4x64_pd(g_re, 0xD8);
            g_im = _mm256_permute4x64_pd(g_im, 0xD8);

            b_re = FMSUB(
                       c_re, g_re, _mm256_mul_pd(c_im, g_im));
            b_im = FMADD(
                       c_re, g_im, _mm256_mul_pd(c_im, g_re));

            t_re = _mm256_add_pd(a_re, b_re);
            t_im = _mm256_add_pd(a_im, b_im);
            u_re = _mm256_sub_pd(a_re, b_re);
            u_im = _mm256_sub_pd(a_im, b_im);

            tu1_re = _mm256_unpacklo_pd(t_re, u_re);
            tu2_re = _mm256_unpackhi_pd(t_re, u_re);
            tu1_im = _mm256_unpacklo_pd(t_im, u_im);
            tu2_im = _mm256_unpackhi_pd(t_im, u_im);
            _mm256_storeu_pd(&f[(u << 1)].v,
                             _mm256_permute2f128_pd(tu1_re, tu2_re, 0x20));
            _mm256_storeu_pd(&f[(u << 1) + 4].v,
                             _mm256_permute2f128_pd(tu1_re, tu2_re, 0x31));
            _mm256_storeu_pd(&f[(u << 1) + hn].v,
                             _mm256_permute2f128_pd(tu1_im, tu2_im, 0x20));
            _mm256_storeu_pd(&f[(u << 1) + 4 + hn].v,
                             _mm256_permute2f128_pd(tu1_im, tu2_im, 0x31));
        }
    } else {
        f[0] = f0[0];
        f[hn] = f1[0];

        for (u = 0; u < qn; u ++) {
            fpr a_re, a_im, b_re, b_im;
            fpr t_re, t_im;

            a_re = f0[u];
            a_im = f0[u + qn];
            FPC_MUL(b_re, b_im, f1[u], f1[u + qn],
                    fpr_gm_tab[((u + hn) << 1) + 0],
                    fpr_gm_tab[((u + hn) << 1) + 1]);
            FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
            f[(u << 1) + 0] = t_re;
            f[(u << 1) + 0 + hn] = t_im;
            FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
            f[(u << 1) + 1] = t_re;
            f[(u << 1) + 1 + hn] = t_im;
        }
    }
}