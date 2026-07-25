#include "consts.h"
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <stdint.h>

#define UNUSED(x) (void)x

void PQCLEAN_MLDSA44_AVX2_polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
    PQCLEAN_MLDSA44_AVX2_polyvec_matrix_expand_row0(&mat[0], NULL, rho);
    PQCLEAN_MLDSA44_AVX2_polyvec_matrix_expand_row1(&mat[1], NULL, rho);
    PQCLEAN_MLDSA44_AVX2_polyvec_matrix_expand_row2(&mat[2], NULL, rho);
    PQCLEAN_MLDSA44_AVX2_polyvec_matrix_expand_row3(&mat[3], NULL, rho);
}

void PQCLEAN_MLDSA44_AVX2_polyvec_matrix_expand_row0(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    UNUSED(rowb);
    PQCLEAN_MLDSA44_AVX2_poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 0, 1, 2, 3);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[0]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[1]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[2]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[3]);
}

void PQCLEAN_MLDSA44_AVX2_polyvec_matrix_expand_row1(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    UNUSED(rowb);
    PQCLEAN_MLDSA44_AVX2_poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 256, 257, 258, 259);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[0]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[1]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[2]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[3]);
}

void PQCLEAN_MLDSA44_AVX2_polyvec_matrix_expand_row2(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    UNUSED(rowb);
    PQCLEAN_MLDSA44_AVX2_poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 512, 513, 514, 515);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[0]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[1]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[2]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[3]);
}

void PQCLEAN_MLDSA44_AVX2_polyvec_matrix_expand_row3(polyvecl *rowa, polyvecl *rowb, const uint8_t rho[SEEDBYTES]) {
    UNUSED(rowb);
    PQCLEAN_MLDSA44_AVX2_poly_uniform_4x(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2], &rowa->vec[3], rho, 768, 769, 770, 771);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[0]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[1]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[2]);
    PQCLEAN_MLDSA44_AVX2_poly_nttunpack(&rowa->vec[3]);
}

void PQCLEAN_MLDSA44_AVX2_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_uniform_gamma1(&v->vec[i], seed, L * nonce + i);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyvecl_reduce(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_reduce(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyvecl_ntt(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_ntt(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyvecl_invntt_tomont(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_invntt_tomont(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v) {
    PQCLEAN_MLDSA44_AVX2_pointwise_acc_avx(w->vec, u->vec->vec, v->vec->vec, PQCLEAN_MLDSA44_AVX2_qdata.vec);
}

int PQCLEAN_MLDSA44_AVX2_polyvecl_chknorm(const polyvecl *v, int32_t bound)  {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        if (PQCLEAN_MLDSA44_AVX2_poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }

    return 0;
}

void PQCLEAN_MLDSA44_AVX2_polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_reduce(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_reduce(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_caddq(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_caddq(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_shiftl(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_shiftl(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_ntt(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_ntt(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_invntt_tomont(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_invntt_tomont(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

int PQCLEAN_MLDSA44_AVX2_polyveck_chknorm(const polyveck *v, int32_t bound) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        if (PQCLEAN_MLDSA44_AVX2_poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }

    return 0;
}

void PQCLEAN_MLDSA44_AVX2_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

unsigned int PQCLEAN_MLDSA44_AVX2_polyveck_make_hint(uint8_t *hint, const polyveck *v0, const polyveck *v1) {
    unsigned int i, n = 0;

    for (i = 0; i < K; ++i) {
        n += PQCLEAN_MLDSA44_AVX2_poly_make_hint(&hint[n], &v0->vec[i], &v1->vec[i]);
    }

    return n;
}

void PQCLEAN_MLDSA44_AVX2_polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_poly_use_hint(&w->vec[i], &v->vec[i], &h->vec[i]);
    }
}

void PQCLEAN_MLDSA44_AVX2_polyveck_pack_w1(uint8_t r[K * POLYW1_PACKEDBYTES], const polyveck *w1) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA44_AVX2_polyw1_pack(&r[i * POLYW1_PACKEDBYTES], &w1->vec[i]);
    }
}