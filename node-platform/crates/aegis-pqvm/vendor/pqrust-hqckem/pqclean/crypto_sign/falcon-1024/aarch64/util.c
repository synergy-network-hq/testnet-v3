
#include "inner.h"
#include "macrofx4.h"
#include "util.h"

void PQCLEAN_FALCON1024_AARCH64_smallints_to_fpr(fpr *r, const int8_t *t, const unsigned logn) {
    float64x2x4_t neon_flo64, neon_fhi64;
    int64x2x4_t neon_lo64, neon_hi64;
    int32x4_t neon_lo32[2], neon_hi32[2];
    int16x8_t neon_lo16, neon_hi16;
    int8x16_t neon_8;

    const unsigned falcon_n =  1 << logn;

    for (unsigned i = 0; i < falcon_n; i += 16) {
        neon_8 = vld1q_s8(&t[i]);

        neon_lo16 = vmovl_s8(vget_low_s8(neon_8));
        neon_hi16 = vmovl_high_s8(neon_8);

        neon_lo32[0] = vmovl_s16(vget_low_s16(neon_lo16));
        neon_lo32[1] = vmovl_high_s16(neon_lo16);
        neon_hi32[0] = vmovl_s16(vget_low_s16(neon_hi16));
        neon_hi32[1] = vmovl_high_s16(neon_hi16);

        neon_lo64.val[0] = vmovl_s32(vget_low_s32(neon_lo32[0]));
        neon_lo64.val[1] = vmovl_high_s32(neon_lo32[0]);
        neon_lo64.val[2] = vmovl_s32(vget_low_s32(neon_lo32[1]));
        neon_lo64.val[3] = vmovl_high_s32(neon_lo32[1]);

        neon_hi64.val[0] = vmovl_s32(vget_low_s32(neon_hi32[0]));
        neon_hi64.val[1] = vmovl_high_s32(neon_hi32[0]);
        neon_hi64.val[2] = vmovl_s32(vget_low_s32(neon_hi32[1]));
        neon_hi64.val[3] = vmovl_high_s32(neon_hi32[1]);

        vfcvtx4(neon_flo64, neon_lo64);
        vfcvtx4(neon_fhi64, neon_hi64);

        vstorex4(&r[i], neon_flo64);
        vstorex4(&r[i + 8], neon_fhi64);
    }
}