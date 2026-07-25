
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
PQCLEAN_FALCONPADDED512_CLEAN_FFT(fpr *f, unsigned logn) {

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
            fpr s_re, s_im;

            s_re = fpr_gm_tab[((m + i1) << 1) + 0];
            s_im = fpr_gm_tab[((m + i1) << 1) + 1];
            for (j = j1; j < j2; j ++) {
                fpr x_re, x_im, y_re, y_im;

                x_re = f[j];
                x_im = f[j + hn];
                y_re = f[j + ht];
                y_im = f[j + ht + hn];
                FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
                FPC_ADD(f[j], f[j + hn],
                        x_re, x_im, y_re, y_im);
                FPC_SUB(f[j + ht], f[j + ht + hn],
                        x_re, x_im, y_re, y_im);
            }
        }
        t = ht;
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_iFFT(fpr *f, unsigned logn) {

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
                FPC_SUB(x_re, x_im, x_re, x_im, y_re, y_im);
                FPC_MUL(f[j + t], f[j + t + hn],
                        x_re, x_im, s_re, s_im);
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
PQCLEAN_FALCONPADDED512_CLEAN_poly_add(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    for (u = 0; u < n; u ++) {
        a[u] = fpr_add(a[u], b[u]);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_sub(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    for (u = 0; u < n; u ++) {
        a[u] = fpr_sub(a[u], b[u]);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_neg(fpr *a, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    for (u = 0; u < n; u ++) {
        a[u] = fpr_neg(a[u]);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_adj_fft(fpr *a, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    for (u = (n >> 1); u < n; u ++) {
        a[u] = fpr_neg(a[u]);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_mul_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    for (u = 0; u < hn; u ++) {
        fpr a_re, a_im, b_re, b_im;

        a_re = a[u];
        a_im = a[u + hn];
        b_re = b[u];
        b_im = b[u + hn];
        FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_muladj_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    for (u = 0; u < hn; u ++) {
        fpr a_re, a_im, b_re, b_im;

        a_re = a[u];
        a_im = a[u + hn];
        b_re = b[u];
        b_im = fpr_neg(b[u + hn]);
        FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_mulselfadj_fft(fpr *a, unsigned logn) {

    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    for (u = 0; u < hn; u ++) {
        fpr a_re, a_im;

        a_re = a[u];
        a_im = a[u + hn];
        a[u] = fpr_add(fpr_sqr(a_re), fpr_sqr(a_im));
        a[u + hn] = fpr_zero;
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_mulconst(fpr *a, fpr x, unsigned logn) {
    size_t n, u;

    n = (size_t)1 << logn;
    for (u = 0; u < n; u ++) {
        a[u] = fpr_mul(a[u], x);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_div_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    for (u = 0; u < hn; u ++) {
        fpr a_re, a_im, b_re, b_im;

        a_re = a[u];
        a_im = a[u + hn];
        b_re = b[u];
        b_im = b[u + hn];
        FPC_DIV(a[u], a[u + hn], a_re, a_im, b_re, b_im);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_invnorm2_fft(fpr *d,
        const fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
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

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_add_muladj_fft(fpr *d,
        const fpr *F, const fpr *G,
        const fpr *f, const fpr *g, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
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

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_mul_autoadj_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    for (u = 0; u < hn; u ++) {
        a[u] = fpr_mul(a[u], b[u]);
        a[u + hn] = fpr_mul(a[u + hn], b[u]);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_div_autoadj_fft(
    fpr *a, const fpr *b, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    for (u = 0; u < hn; u ++) {
        fpr ib;

        ib = fpr_inv(b[u]);
        a[u] = fpr_mul(a[u], ib);
        a[u + hn] = fpr_mul(a[u + hn], ib);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_LDL_fft(
    const fpr *g00,
    fpr *g01, fpr *g11, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
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
        FPC_MUL(g01_re, g01_im, mu_re, mu_im, g01_re, fpr_neg(g01_im));
        FPC_SUB(g11[u], g11[u + hn], g11_re, g11_im, g01_re, g01_im);
        g01[u] = mu_re;
        g01[u + hn] = fpr_neg(mu_im);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_LDLmv_fft(
    fpr *d11, fpr *l10,
    const fpr *g00, const fpr *g01,
    const fpr *g11, unsigned logn) {
    size_t n, hn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
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
        FPC_MUL(g01_re, g01_im, mu_re, mu_im, g01_re, fpr_neg(g01_im));
        FPC_SUB(d11[u], d11[u + hn], g11_re, g11_im, g01_re, g01_im);
        l10[u] = mu_re;
        l10[u + hn] = fpr_neg(mu_im);
    }
}

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_split_fft(
    fpr *f0, fpr *f1,
    const fpr *f, unsigned logn) {

    size_t n, hn, qn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    qn = hn >> 1;

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

void
PQCLEAN_FALCONPADDED512_CLEAN_poly_merge_fft(
    fpr *f,
    const fpr *f0, const fpr *f1, unsigned logn) {
    size_t n, hn, qn, u;

    n = (size_t)1 << logn;
    hn = n >> 1;
    qn = hn >> 1;

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