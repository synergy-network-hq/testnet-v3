#ifndef PQCLEAN_MLKEM768_CLEAN_CBD_H
#define PQCLEAN_MLKEM768_CLEAN_CBD_H
#include "params.h"
#include "poly.h"
#include <stdint.h>

void PQCLEAN_MLKEM768_CLEAN_poly_cbd_eta1(poly *r, const uint8_t buf[MLKEM_ETA1 * MLKEM_N / 4]);

void PQCLEAN_MLKEM768_CLEAN_poly_cbd_eta2(poly *r, const uint8_t buf[MLKEM_ETA2 * MLKEM_N / 4]);

#endif
