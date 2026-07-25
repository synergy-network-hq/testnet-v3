#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

#define cbd_eta1 MLKEM_NAMESPACE(_cbd_eta1)
void cbd_eta1(poly *r, const uint8_t buf[MLKEM_ETA1*MLKEM_N/4]);

#define cbd_eta2 MLKEM_NAMESPACE(_cbd_eta2)
void cbd_eta2(poly *r, const uint8_t buf[MLKEM_ETA2*MLKEM_N/4]);

#endif
