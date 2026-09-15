
#include "inner.h"
#include "poly.h"

void PQCLEAN_FALCON1024_AARCH64_to_ntt(int16_t *h) {
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(h, NTT_NONE);
}

void PQCLEAN_FALCON1024_AARCH64_to_ntt_monty(int16_t *h) {
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(h, NTT_MONT);
}

int PQCLEAN_FALCON1024_AARCH64_verify_raw(const int16_t *c0, const int16_t *s2,
        int16_t *h, int16_t *tmp) {
    int16_t *tt = tmp;

    memcpy(tt, s2, sizeof(int16_t) * FALCON_N);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(h, NTT_NONE);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(tt, NTT_MONT_INV);
    PQCLEAN_FALCON1024_AARCH64_poly_montmul_ntt(tt, h);
    PQCLEAN_FALCON1024_AARCH64_poly_invntt(tt, INVNTT_NONE);
    PQCLEAN_FALCON1024_AARCH64_poly_sub_barrett(tt, c0, tt);

    return PQCLEAN_FALCON1024_AARCH64_is_short(tt, s2);
}

int PQCLEAN_FALCON1024_AARCH64_compute_public(int16_t *h, const int8_t *f, const int8_t *g, int16_t *tmp) {
    int16_t *tt = tmp;

    PQCLEAN_FALCON1024_AARCH64_poly_int8_to_int16(h, g);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(h, NTT_NONE);

    PQCLEAN_FALCON1024_AARCH64_poly_int8_to_int16(tt, f);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(tt, NTT_MONT);

    if (PQCLEAN_FALCON1024_AARCH64_poly_compare_with_zero(tt)) {
        return 0;
    }
    PQCLEAN_FALCON1024_AARCH64_poly_div_12289(h, tt);

    PQCLEAN_FALCON1024_AARCH64_poly_invntt(h, INVNTT_NINV);

    PQCLEAN_FALCON1024_AARCH64_poly_convert_to_unsigned(h);

    return 1;
}

int PQCLEAN_FALCON1024_AARCH64_complete_private(int8_t *G, const int8_t *f,
        const int8_t *g, const int8_t *F,
        uint8_t *tmp) {
    int16_t *t1, *t2;

    t1 = (int16_t *)tmp;
    t2 = t1 + FALCON_N;

    PQCLEAN_FALCON1024_AARCH64_poly_int8_to_int16(t1, g);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(t1, NTT_NONE);

    PQCLEAN_FALCON1024_AARCH64_poly_int8_to_int16(t2, F);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(t2, NTT_MONT);

    PQCLEAN_FALCON1024_AARCH64_poly_montmul_ntt(t1, t2);

    PQCLEAN_FALCON1024_AARCH64_poly_int8_to_int16(t2, f);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(t2, NTT_MONT);

    if (PQCLEAN_FALCON1024_AARCH64_poly_compare_with_zero(t2)) {
        return 0;
    }
    PQCLEAN_FALCON1024_AARCH64_poly_div_12289(t1, t2);

    PQCLEAN_FALCON1024_AARCH64_poly_invntt(t1, INVNTT_NINV);

    if (PQCLEAN_FALCON1024_AARCH64_poly_int16_to_int8(G, t1)) {
        return 0;
    }
    return 1;
}

int PQCLEAN_FALCON1024_AARCH64_is_invertible(const int16_t *s2, uint8_t *tmp) {
    int16_t *tt = (int16_t *)tmp;
    uint16_t r;

    memcpy(tt, s2, sizeof(int16_t) * FALCON_N);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(tt, NTT_MONT);

    r = PQCLEAN_FALCON1024_AARCH64_poly_compare_with_zero(tt);

    return (int)(1u - (r >> 15));
}

int PQCLEAN_FALCON1024_AARCH64_verify_recover(int16_t *h, const int16_t *c0,
        const int16_t *s1, const int16_t *s2,
        uint8_t *tmp) {
    int16_t *tt = (int16_t *)tmp;
    uint16_t r;

    PQCLEAN_FALCON1024_AARCH64_poly_sub_barrett(h, c0, s1);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(h, NTT_NONE);

    memcpy(tt, s2, sizeof(int16_t) * FALCON_N);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(tt, NTT_MONT);
    r = PQCLEAN_FALCON1024_AARCH64_poly_compare_with_zero(tt);
    PQCLEAN_FALCON1024_AARCH64_poly_div_12289(h, tt);

    PQCLEAN_FALCON1024_AARCH64_poly_invntt(h, INVNTT_NINV);

    r = (uint16_t) (~r & (uint16_t) - PQCLEAN_FALCON1024_AARCH64_is_short(s1, s2));
    return (int)(r >> 15);
}

int PQCLEAN_FALCON1024_AARCH64_count_nttzero(const int16_t *sig, uint8_t *tmp) {
    int16_t *s2 = (int16_t *)tmp;

    memcpy(s2, sig, sizeof(int16_t) * FALCON_N);
    PQCLEAN_FALCON1024_AARCH64_poly_ntt(s2, NTT_MONT);

    int r = PQCLEAN_FALCON1024_AARCH64_poly_compare_with_zero(s2);

    return r;
}