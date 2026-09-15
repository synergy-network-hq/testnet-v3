#ifndef HQC_PARAMETERS_H
#define HQC_PARAMETERS_H

#include "api.h"

#define CEIL_DIVIDE(a, b)  (((a)+(b)-1)/(b)) 

#define PARAM_N                                                             57637
#define PARAM_N1                                90
#define PARAM_N2                                640
#define PARAM_N1N2                              57600
#define PARAM_OMEGA                             131
#define PARAM_OMEGA_E                           149
#define PARAM_OMEGA_R                           149

#define SECRET_KEY_BYTES                        PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES
#define PUBLIC_KEY_BYTES                        PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES
#define SHARED_SECRET_BYTES                     PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES
#define CIPHERTEXT_BYTES                        PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES

#define VEC_N_SIZE_BYTES                        CEIL_DIVIDE(PARAM_N, 8)
#define VEC_K_SIZE_BYTES                        PARAM_K
#define VEC_N1_SIZE_BYTES                       PARAM_N1
#define VEC_N1N2_SIZE_BYTES                     CEIL_DIVIDE(PARAM_N1N2, 8)

#define VEC_N_SIZE_64                           CEIL_DIVIDE(PARAM_N, 64)
#define VEC_K_SIZE_64                           CEIL_DIVIDE(PARAM_K, 8)
#define VEC_N1_SIZE_64                          CEIL_DIVIDE(PARAM_N1, 8)
#define VEC_N1N2_SIZE_64                        CEIL_DIVIDE(PARAM_N1N2, 64)

#define PARAM_DELTA                             29
#define PARAM_M                                 8
#define PARAM_GF_POLY                           0x11D
#define PARAM_GF_POLY_WT                      5
#define PARAM_GF_POLY_M2                        4
#define PARAM_GF_MUL_ORDER                      255
#define PARAM_K                                 32
#define PARAM_G                                 59
#define PARAM_FFT                               5
#define RS_POLY_COEFS 49,167,49,39,200,121,124,91,240,63,148,71,150,123,87,101,32,215,159,71,201,115,97,210,186,183,141,217,123,12,31,243,180,219,152,239,99,141,4,246,191,144,8,232,47,27,141,178,130,64,124,47,39,188,216,48,199,187,1

#define RED_MASK                                0x1fffffffff
#define SHAKE256_512_BYTES                    64
#define SEED_BYTES                              40
#define SALT_SIZE_BYTES                       16

#endif