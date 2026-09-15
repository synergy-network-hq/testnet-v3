#include "code.h"
#include "gf2x.h"
#include "hqc.h"
#include "parameters.h"
#include "parsing.h"
#include "randombytes.h"
#include "shake_prng.h"
#include "vector.h"
#include <stdint.h>

void PQCLEAN_HQC256_CLEAN_hqc_pke_keygen(uint8_t *pk, uint8_t *sk) {
    seedexpander_state sk_seedexpander;
    seedexpander_state pk_seedexpander;
    uint8_t sk_seed[SEED_BYTES] = {0};
    uint8_t sigma[VEC_K_SIZE_BYTES] = {0};
    uint8_t pk_seed[SEED_BYTES] = {0};
    uint64_t x[VEC_N_SIZE_64] = {0};
    uint64_t y[VEC_N_SIZE_64] = {0};
    uint64_t h[VEC_N_SIZE_64] = {0};
    uint64_t s[VEC_N_SIZE_64] = {0};

    randombytes(sk_seed, SEED_BYTES);
    randombytes(sigma, VEC_K_SIZE_BYTES);
    PQCLEAN_HQC256_CLEAN_seedexpander_init(&sk_seedexpander, sk_seed, SEED_BYTES);

    randombytes(pk_seed, SEED_BYTES);
    PQCLEAN_HQC256_CLEAN_seedexpander_init(&pk_seedexpander, pk_seed, SEED_BYTES);

    PQCLEAN_HQC256_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, x, PARAM_OMEGA);
    PQCLEAN_HQC256_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, y, PARAM_OMEGA);

    PQCLEAN_HQC256_CLEAN_vect_set_random(&pk_seedexpander, h);
    PQCLEAN_HQC256_CLEAN_vect_mul(s, y, h);
    PQCLEAN_HQC256_CLEAN_vect_add(s, x, s, VEC_N_SIZE_64);

    PQCLEAN_HQC256_CLEAN_hqc_public_key_to_string(pk, pk_seed, s);
    PQCLEAN_HQC256_CLEAN_hqc_secret_key_to_string(sk, sk_seed, sigma, pk);

    PQCLEAN_HQC256_CLEAN_seedexpander_release(&pk_seedexpander);
    PQCLEAN_HQC256_CLEAN_seedexpander_release(&sk_seedexpander);
}

void PQCLEAN_HQC256_CLEAN_hqc_pke_encrypt(uint64_t *u, uint64_t *v, uint8_t *m, uint8_t *theta, const uint8_t *pk) {
    seedexpander_state vec_seedexpander;
    uint64_t h[VEC_N_SIZE_64] = {0};
    uint64_t s[VEC_N_SIZE_64] = {0};
    uint64_t r1[VEC_N_SIZE_64] = {0};
    uint64_t r2[VEC_N_SIZE_64] = {0};
    uint64_t e[VEC_N_SIZE_64] = {0};
    uint64_t tmp1[VEC_N_SIZE_64] = {0};
    uint64_t tmp2[VEC_N_SIZE_64] = {0};

    PQCLEAN_HQC256_CLEAN_seedexpander_init(&vec_seedexpander, theta, SEED_BYTES);

    PQCLEAN_HQC256_CLEAN_hqc_public_key_from_string(h, s, pk);

    PQCLEAN_HQC256_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, r1, PARAM_OMEGA_R);
    PQCLEAN_HQC256_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, r2, PARAM_OMEGA_R);
    PQCLEAN_HQC256_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, e, PARAM_OMEGA_E);

    PQCLEAN_HQC256_CLEAN_vect_mul(u, r2, h);
    PQCLEAN_HQC256_CLEAN_vect_add(u, r1, u, VEC_N_SIZE_64);

    PQCLEAN_HQC256_CLEAN_code_encode(v, m);
    PQCLEAN_HQC256_CLEAN_vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);

    PQCLEAN_HQC256_CLEAN_vect_mul(tmp2, r2, s);
    PQCLEAN_HQC256_CLEAN_vect_add(tmp2, e, tmp2, VEC_N_SIZE_64);
    PQCLEAN_HQC256_CLEAN_vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);
    PQCLEAN_HQC256_CLEAN_vect_resize(v, PARAM_N1N2, tmp2, PARAM_N);

    PQCLEAN_HQC256_CLEAN_seedexpander_release(&vec_seedexpander);
}

uint8_t PQCLEAN_HQC256_CLEAN_hqc_pke_decrypt(uint8_t *m, uint8_t *sigma, const uint64_t *u, const uint64_t *v, const uint8_t *sk) {
    uint64_t x[VEC_N_SIZE_64] = {0};
    uint64_t y[VEC_N_SIZE_64] = {0};
    uint8_t pk[PUBLIC_KEY_BYTES] = {0};
    uint64_t tmp1[VEC_N_SIZE_64] = {0};
    uint64_t tmp2[VEC_N_SIZE_64] = {0};

    PQCLEAN_HQC256_CLEAN_hqc_secret_key_from_string(x, y, sigma, pk, sk);

    PQCLEAN_HQC256_CLEAN_vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);
    PQCLEAN_HQC256_CLEAN_vect_mul(tmp2, y, u);
    PQCLEAN_HQC256_CLEAN_vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);

    PQCLEAN_HQC256_CLEAN_code_decode(m, tmp2);

    return 0;
}