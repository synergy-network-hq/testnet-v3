#ifndef NTT_CONSTS
#define NTT_CONSTS

#include <stdint.h>

extern const int16_t PQCLEAN_FALCONPADDED512_AARCH64_qmvq[8];

extern const int16_t PQCLEAN_FALCONPADDED512_AARCH64_ntt_br[];
extern const int16_t PQCLEAN_FALCONPADDED512_AARCH64_ntt_qinv_br[];

extern const int16_t PQCLEAN_FALCONPADDED512_AARCH64_invntt_br[];
extern const int16_t PQCLEAN_FALCONPADDED512_AARCH64_invntt_qinv_br[];

#endif