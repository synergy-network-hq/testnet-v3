#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <stdint.h>

void PQCLEAN_MLDSA87_CLEAN_polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
    unsigned int i, j;

    for (i = 0; i < K; ++i) {
        for (j = 0; j < L; ++j) {
            PQCLEAN_MLDSA87_CLEAN_poly_uniform(&mat[i].vec[j], rho, (uint16_t) ((i << 8) + j));
        }
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_uniform_gamma1(&v->vec[i], seed, (uint16_t) (L * nonce + i));
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyvecl_reduce(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_reduce(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyvecl_ntt(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_ntt(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyvecl_invntt_tomont(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_invntt_tomont(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyvecl_pointwise_acc_montgomery(poly *w,
        const polyvecl *u,
        const polyvecl *v) {
    unsigned int i;
    poly t;

    PQCLEAN_MLDSA87_CLEAN_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (i = 1; i < L; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        PQCLEAN_MLDSA87_CLEAN_poly_add(w, w, &t);
    }
}

int PQCLEAN_MLDSA87_CLEAN_polyvecl_chknorm(const polyvecl *v, int32_t bound)  {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        if (PQCLEAN_MLDSA87_CLEAN_poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }

    return 0;
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_reduce(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_reduce(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_caddq(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_caddq(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_shiftl(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_shiftl(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_ntt(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_ntt(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_invntt_tomont(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_invntt_tomont(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

int PQCLEAN_MLDSA87_CLEAN_polyveck_chknorm(const polyveck *v, int32_t bound) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        if (PQCLEAN_MLDSA87_CLEAN_poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }

    return 0;
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

unsigned int PQCLEAN_MLDSA87_CLEAN_polyveck_make_hint(polyveck *h,
        const polyveck *v0,
        const polyveck *v1) {
    unsigned int i, s = 0;

    for (i = 0; i < K; ++i) {
        s += PQCLEAN_MLDSA87_CLEAN_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    }

    return s;
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_poly_use_hint(&w->vec[i], &v->vec[i], &h->vec[i]);
    }
}

void PQCLEAN_MLDSA87_CLEAN_polyveck_pack_w1(uint8_t r[K * POLYW1_PACKEDBYTES], const polyveck *w1) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        PQCLEAN_MLDSA87_CLEAN_polyw1_pack(&r[i * POLYW1_PACKEDBYTES], &w1->vec[i]);
    }
}