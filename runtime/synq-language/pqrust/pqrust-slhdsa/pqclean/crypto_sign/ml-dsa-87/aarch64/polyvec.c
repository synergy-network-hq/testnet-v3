
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "ntt.h"
#include "reduce.h"
#include <stdint.h>

void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
    unsigned int i, j;

    for (j = 0; j < L; ++j) {
        for (i = 0; i < K; i += 2) {
            poly_uniformx2(&mat[i + 0].vec[j], &mat[i + 1].vec[j], rho, (uint16_t) ((i << 8) + j), (uint16_t) (((i + 1) << 8) + j));
        }
    }
}

void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
    }
}

void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L - 1; i += 2) {
        poly_uniform_gamma1x2(&v->vec[i + 0], &v->vec[i + 1], seed, (uint16_t) (L * nonce + i + 0), (uint16_t) (L * nonce + i + 1));
    }
    if (L & 1) {
        poly_uniform_gamma1(&v->vec[i], seed, (uint16_t) (L * nonce + L - 1));
    }
}

void polyvecl_reduce(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        poly_reduce(&v->vec[i]);
    }
}

void polyvecl_freeze(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        poly_freeze(&v->vec[i]);
    }
}

void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void polyvecl_ntt(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        poly_ntt(&v->vec[i]);
    }
}

void polyvecl_invntt_tomont(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        poly_invntt_tomont(&v->vec[i]);
    }
}

void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

extern void PQCLEAN_MLDSA87_AARCH64__asm_polyvecl_pointwise_acc_montgomery(int32_t *, const int32_t *, const int32_t *, const int32_t *);
void polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v) {
    PQCLEAN_MLDSA87_AARCH64__asm_polyvecl_pointwise_acc_montgomery(w->coeffs, u->vec[0].coeffs, v->vec[0].coeffs, constants);
}

int polyvecl_chknorm(const polyvecl *v, int32_t bound)  {
    unsigned int i;

    for (i = 0; i < L; ++i) {
        if (poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }

    return 0;
}

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_uniform_eta(&v->vec[i], seed, nonce++);
    }

}

void polyveck_reduce(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_reduce(&v->vec[i]);
    }
}

void polyveck_caddq(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_caddq(&v->vec[i]);
    }
}

void polyveck_freeze(polyveck *v)  {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_freeze(&v->vec[i]);
    }
}

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void polyveck_shiftl(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_shiftl(&v->vec[i]);
    }
}

void polyveck_ntt(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_ntt(&v->vec[i]);
    }
}

void polyveck_invntt_tomont(polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_invntt_tomont(&v->vec[i]);
    }
}

void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

int polyveck_chknorm(const polyveck *v, int32_t bound) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        if (poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }

    return 0;
}

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1) {
    unsigned int i, s = 0;

    for (i = 0; i < K; ++i) {
        s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    }

    return s;
}

void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
    }
}

void polyveck_pack_w1(uint8_t r[K * POLYW1_PACKEDBYTES], const polyveck *w1) {
    unsigned int i;

    for (i = 0; i < K; ++i) {
        polyw1_pack(&r[i * POLYW1_PACKEDBYTES], &w1->vec[i]);
    }
}