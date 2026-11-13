#include "code.h"
#include "parameters.h"
#include "reed_muller.h"
#include "reed_solomon.h"
#include <stdint.h>

void PQCLEAN_HQC256_CLEAN_code_encode(uint64_t *em, const uint8_t *m) {
    uint8_t tmp[VEC_N1_SIZE_BYTES] = {0};

    PQCLEAN_HQC256_CLEAN_reed_solomon_encode(tmp, m);
    PQCLEAN_HQC256_CLEAN_reed_muller_encode(em, tmp);

}

void PQCLEAN_HQC256_CLEAN_code_decode(uint8_t *m, const uint64_t *em) {
    uint8_t tmp[VEC_N1_SIZE_BYTES] = {0};

    PQCLEAN_HQC256_CLEAN_reed_muller_decode(tmp, em);
    PQCLEAN_HQC256_CLEAN_reed_solomon_decode(m, tmp);

}