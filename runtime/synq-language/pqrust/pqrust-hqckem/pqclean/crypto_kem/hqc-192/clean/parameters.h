#ifndef HQC_PARAMETERS_H
#define HQC_PARAMETERS_H

#include "api.h"

#define CEIL_DIVIDE(a, b)  (((a)+(b)-1)/(b)) 

#define PARAM_N                                                             35851
#define PARAM_N1                                56
#define PARAM_N2                                640
#define PARAM_N1N2                              35840
#define PARAM_OMEGA                             100
#define PARAM_OMEGA_E                           114
#define PARAM_OMEGA_R                           114

#define SECRET_KEY_BYTES                        PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES
#define PUBLIC_KEY_BYTES                        PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES
#define SHARED_SECRET_BYTES                     PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES
#define CIPHERTEXT_BYTES                        PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES

#define VEC_N_SIZE_BYTES                        CEIL_DIVIDE(PARAM_N, 8)
#define VEC_K_SIZE_BYTES                        PARAM_K
#define VEC_N1_SIZE_BYTES                       PARAM_N1
#define VEC_N1N2_SIZE_BYTES                     CEIL_DIVIDE(PARAM_N1N2, 8)

#define VEC_N_SIZE_64                           CEIL_DIVIDE(PARAM_N, 64)
#define VEC_K_SIZE_64                           CEIL_DIVIDE(PARAM_K, 8)
#define VEC_N1_SIZE_64                          CEIL_DIVIDE(PARAM_N1, 8)
#define VEC_N1N2_SIZE_64                        CEIL_DIVIDE(PARAM_N1N2, 64)

#define PARAM_DELTA                             16
#define PARAM_M                                 8
#define PARAM_GF_POLY                           0x11D
#define PARAM_GF_POLY_WT                      5
#define PARAM_GF_POLY_M2                        4
#define PARAM_GF_MUL_ORDER                      255
#define PARAM_K                                 24
#define PARAM_G                                 33
#define PARAM_FFT                               5
#define RS_POLY_COEFS 45,216,239,24,253,104,27,40,107,50,163,210,227,134,224,158,119,13,158,1,238,164,82,43,15,232,246,142,50,189,29,232,1

#define RED_MASK                                0x7ff
#define SHAKE256_512_BYTES                    64
#define SEED_BYTES                              40
#define SALT_SIZE_BYTES                       16

#endif