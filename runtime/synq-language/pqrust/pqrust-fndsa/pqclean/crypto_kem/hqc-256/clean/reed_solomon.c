#include "fft.h"
#include "gf.h"
#include "parameters.h"
#include "reed_solomon.h"
#include <stdint.h>
#include <string.h>

void PQCLEAN_HQC256_CLEAN_reed_solomon_encode(uint8_t *cdw, const uint8_t *msg) {
    uint8_t gate_value = 0;

    uint16_t tmp[PARAM_G] = {0};
    uint16_t PARAM_RS_POLY [] = {RS_POLY_COEFS};

    memset(cdw, 0, PARAM_N1);

    for (size_t i = 0; i < PARAM_K; ++i) {
        gate_value = msg[PARAM_K - 1 - i] ^ cdw[PARAM_N1 - PARAM_K - 1];

        for (size_t j = 0; j < PARAM_G; ++j) {
            tmp[j] = PQCLEAN_HQC256_CLEAN_gf_mul(gate_value, PARAM_RS_POLY[j]);
        }

        for (size_t k = PARAM_N1 - PARAM_K - 1; k; --k) {
            cdw[k] = (uint8_t)(cdw[k - 1] ^ tmp[k]);
        }

        cdw[0] = (uint8_t)tmp[0];
    }

    memcpy(cdw + PARAM_N1 - PARAM_K, msg, PARAM_K);
}

static void compute_syndromes(uint16_t *syndromes, uint8_t *cdw) {
    for (size_t i = 0; i < 2 * PARAM_DELTA; ++i) {
        for (size_t j = 1; j < PARAM_N1; ++j) {
            syndromes[i] ^= PQCLEAN_HQC256_CLEAN_gf_mul(cdw[j], alpha_ij_pow[i][j - 1]);
        }
        syndromes[i] ^= cdw[0];
    }
}

static uint16_t compute_elp(uint16_t *sigma, const uint16_t *syndromes) {
    uint16_t deg_sigma = 0;
    uint16_t deg_sigma_p = 0;
    uint16_t deg_sigma_copy = 0;
    uint16_t sigma_copy[PARAM_DELTA + 1] = {0};
    uint16_t X_sigma_p[PARAM_DELTA + 1] = {0, 1};
    uint16_t pp = (uint16_t) -1; 
    uint16_t d_p = 1;
    uint16_t d = syndromes[0];

    uint16_t mask1, mask2, mask12;
    uint16_t deg_X, deg_X_sigma_p;
    uint16_t dd;
    uint16_t mu;

    uint16_t i;

    sigma[0] = 1;
    for (mu = 0; (mu < (2 * PARAM_DELTA)); ++mu) {

        memcpy(sigma_copy, sigma, 2 * (PARAM_DELTA));
        deg_sigma_copy = deg_sigma;

        dd = PQCLEAN_HQC256_CLEAN_gf_mul(d, PQCLEAN_HQC256_CLEAN_gf_inverse(d_p));

        for (i = 1; (i <= mu + 1) && (i <= PARAM_DELTA); ++i) {
            sigma[i] ^= PQCLEAN_HQC256_CLEAN_gf_mul(dd, X_sigma_p[i]);
        }

        deg_X = mu - pp;
        deg_X_sigma_p = deg_X + deg_sigma_p;

        mask1 = -((uint16_t) - d >> 15);

        mask2 = -((uint16_t) (deg_sigma - deg_X_sigma_p) >> 15);

        mask12 = mask1 & mask2;
        deg_sigma ^= mask12 & (deg_X_sigma_p ^ deg_sigma);

        if (mu == (2 * PARAM_DELTA - 1)) {
            break;
        }

        pp ^= mask12 & (mu ^ pp);
        d_p ^= mask12 & (d ^ d_p);
        for (i = PARAM_DELTA; i; --i) {
            X_sigma_p[i] = (mask12 & sigma_copy[i - 1]) ^ (~mask12 & X_sigma_p[i - 1]);
        }

        deg_sigma_p ^= mask12 & (deg_sigma_copy ^ deg_sigma_p);
        d = syndromes[mu + 1];

        for (i = 1; (i <= mu + 1) && (i <= PARAM_DELTA); ++i) {
            d ^= PQCLEAN_HQC256_CLEAN_gf_mul(sigma[i], syndromes[mu + 1 - i]);
        }
    }

    return deg_sigma;
}

static void compute_roots(uint8_t *error, uint16_t *sigma) {
    uint16_t w[1 << PARAM_M] = {0};

    PQCLEAN_HQC256_CLEAN_fft(w, sigma, PARAM_DELTA + 1);
    PQCLEAN_HQC256_CLEAN_fft_retrieve_error_poly(error, w);
}

static void compute_z_poly(uint16_t *z, const uint16_t *sigma, uint16_t degree, const uint16_t *syndromes) {
    size_t i, j;
    uint16_t mask;

    z[0] = 1;

    for (i = 1; i < PARAM_DELTA + 1; ++i) {
        mask = -((uint16_t) (i - degree - 1) >> 15);
        z[i] = mask & sigma[i];
    }

    z[1] ^= syndromes[0];

    for (i = 2; i <= PARAM_DELTA; ++i) {
        mask = -((uint16_t) (i - degree - 1) >> 15);
        z[i] ^= mask & syndromes[i - 1];

        for (j = 1; j < i; ++j) {
            z[i] ^= mask & PQCLEAN_HQC256_CLEAN_gf_mul(sigma[j], syndromes[i - j - 1]);
        }
    }
}

static void compute_error_values(uint16_t *error_values, const uint16_t *z, const uint8_t *error) {
    uint16_t beta_j[PARAM_DELTA] = {0};
    uint16_t e_j[PARAM_DELTA] = {0};

    uint16_t delta_counter;
    uint16_t delta_real_value;
    uint16_t found;
    uint16_t mask1;
    uint16_t mask2;
    uint16_t tmp1;
    uint16_t tmp2;
    uint16_t inverse;
    uint16_t inverse_power_j;

    delta_counter = 0;
    for (size_t i = 0; i < PARAM_N1; i++) {
        found = 0;
        mask1 = (uint16_t) (-((int32_t)error[i]) >> 31); 
        for (size_t j = 0; j < PARAM_DELTA; j++) {
            mask2 = ~((uint16_t) (-((int32_t) j ^ delta_counter) >> 31)); 
            beta_j[j] += mask1 & mask2 & gf_exp[i];
            found += mask1 & mask2 & 1;
        }
        delta_counter += found;
    }
    delta_real_value = delta_counter;

    for (size_t i = 0; i < PARAM_DELTA; ++i) {
        tmp1 = 1;
        tmp2 = 1;
        inverse = PQCLEAN_HQC256_CLEAN_gf_inverse(beta_j[i]);
        inverse_power_j = 1;

        for (size_t j = 1; j <= PARAM_DELTA; ++j) {
            inverse_power_j = PQCLEAN_HQC256_CLEAN_gf_mul(inverse_power_j, inverse);
            tmp1 ^= PQCLEAN_HQC256_CLEAN_gf_mul(inverse_power_j, z[j]);
        }
        for (size_t k = 1; k < PARAM_DELTA; ++k) {
            tmp2 = PQCLEAN_HQC256_CLEAN_gf_mul(tmp2, (1 ^ PQCLEAN_HQC256_CLEAN_gf_mul(inverse, beta_j[(i + k) % PARAM_DELTA])));
        }
        mask1 = (uint16_t) (((int16_t) i - delta_real_value) >> 15); 
        e_j[i] = mask1 & PQCLEAN_HQC256_CLEAN_gf_mul(tmp1, PQCLEAN_HQC256_CLEAN_gf_inverse(tmp2));
    }

    delta_counter = 0;
    for (size_t i = 0; i < PARAM_N1; ++i) {
        found = 0;
        mask1 = (uint16_t) (-((int32_t)error[i]) >> 31); 
        for (size_t j = 0; j < PARAM_DELTA; j++) {
            mask2 = ~((uint16_t) (-((int32_t) j ^ delta_counter) >> 31)); 
            error_values[i] += mask1 & mask2 & e_j[j];
            found += mask1 & mask2 & 1;
        }
        delta_counter += found;
    }
}

static void correct_errors(uint8_t *cdw, const uint16_t *error_values) {
    for (size_t i = 0; i < PARAM_N1; ++i) {
        cdw[i] ^= error_values[i];
    }
}

void PQCLEAN_HQC256_CLEAN_reed_solomon_decode(uint8_t *msg, uint8_t *cdw) {
    uint16_t syndromes[2 * PARAM_DELTA] = {0};
    uint16_t sigma[1 << PARAM_FFT] = {0};
    uint8_t error[1 << PARAM_M] = {0};
    uint16_t z[PARAM_N1] = {0};
    uint16_t error_values[PARAM_N1] = {0};
    uint16_t deg;

    compute_syndromes(syndromes, cdw);

    deg = compute_elp(sigma, syndromes);

    compute_roots(error, sigma);

    compute_z_poly(z, sigma, deg, syndromes);

    compute_error_values(error_values, z, error);

    correct_errors(cdw, error_values);

    memcpy(msg, cdw + (PARAM_G - 1), PARAM_K);

}