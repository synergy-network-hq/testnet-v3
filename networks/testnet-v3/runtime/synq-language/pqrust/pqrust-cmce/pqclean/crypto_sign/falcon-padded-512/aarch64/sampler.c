
#include "inner.h"
#include <arm_neon.h>

int
PQCLEAN_FALCONPADDED512_AARCH64_gaussian0_sampler(prng *p) {

    static const uint32_t dist[] = {
        10745844u,  3068844u,  3741698u,
        5559083u,  1580863u,  8248194u,
        2260429u, 13669192u,  2736639u,
        708981u,  4421575u, 10046180u,
        169348u,  7122675u,  4136815u,
        30538u, 13063405u,  7650655u,
        4132u, 14505003u,  7826148u,
        417u, 16768101u, 11363290u,
        31u,  8444042u,  8086568u,
        1u, 12844466u,   265321u,
        0u,  1232676u, 13644283u,
        0u,    38047u,  9111839u,
        0u,      870u,  6138264u,
        0u,       14u, 12545723u,
        0u,        0u,  3104126u,
        0u,        0u,    28824u,
        0u,        0u,      198u,
        0u,        0u,        1u
    };

    uint32_t v0, v1, v2, hi;
    uint64_t lo;
    int z;

    lo = prng_get_u64(p);
    hi = prng_get_u8(p);
    v0 = (uint32_t)lo & 0xFFFFFF;
    v1 = (uint32_t)(lo >> 24) & 0xFFFFFF;
    v2 = (uint32_t)(lo >> 48) | (hi << 16);

    uint32x4x3_t w;
    uint32x4_t x0, x1, x2, cc0, cc1, cc2, zz;
    uint32x2x3_t wh;
    uint32x2_t cc0h, cc1h, cc2h, zzh;
    x0 = vdupq_n_u32(v0);
    x1 = vdupq_n_u32(v1);
    x2 = vdupq_n_u32(v2);

    w = vld3q_u32(&dist[0]);
    cc0 = vsubq_u32(x0, w.val[2]);
    cc1 = vsubq_u32(x1, w.val[1]);
    cc2 = vsubq_u32(x2, w.val[0]);
    cc1 = (uint32x4_t)vsraq_n_s32((int32x4_t)cc1, (int32x4_t)cc0, 31);
    cc2 = (uint32x4_t)vsraq_n_s32((int32x4_t)cc2, (int32x4_t)cc1, 31);
    zz = vshrq_n_u32(cc2, 31);

    w = vld3q_u32(&dist[12]);
    cc0 = vsubq_u32(x0, w.val[2]);
    cc1 = vsubq_u32(x1, w.val[1]);
    cc2 = vsubq_u32(x2, w.val[0]);
    cc1 = (uint32x4_t)vsraq_n_s32((int32x4_t)cc1, (int32x4_t)cc0, 31);
    cc2 = (uint32x4_t)vsraq_n_s32((int32x4_t)cc2, (int32x4_t)cc1, 31);
    zz = vsraq_n_u32(zz, cc2, 31);

    w = vld3q_u32(&dist[24]);
    cc0 = vsubq_u32(x0, w.val[2]);
    cc1 = vsubq_u32(x1, w.val[1]);
    cc2 = vsubq_u32(x2, w.val[0]);
    cc1 = (uint32x4_t)vsraq_n_s32((int32x4_t)cc1, (int32x4_t)cc0, 31);
    cc2 = (uint32x4_t)vsraq_n_s32((int32x4_t)cc2, (int32x4_t)cc1, 31);
    zz = vsraq_n_u32(zz, cc2, 31);

    w = vld3q_u32(&dist[36]);
    cc0 = vsubq_u32(x0, w.val[2]);
    cc1 = vsubq_u32(x1, w.val[1]);
    cc2 = vsubq_u32(x2, w.val[0]);
    cc1 = (uint32x4_t)vsraq_n_s32((int32x4_t)cc1, (int32x4_t)cc0, 31);
    cc2 = (uint32x4_t)vsraq_n_s32((int32x4_t)cc2, (int32x4_t)cc1, 31);
    zz = vsraq_n_u32(zz, cc2, 31);

    wh = vld3_u32(&dist[48]);
    cc0h = vsub_u32(vget_low_u32(x0), wh.val[2]);
    cc1h = vsub_u32(vget_low_u32(x1), wh.val[1]);
    cc2h = vsub_u32(vget_low_u32(x2), wh.val[0]);
    cc1h = (uint32x2_t)vsra_n_s32((int32x2_t)cc1h, (int32x2_t)cc0h, 31);
    cc2h = (uint32x2_t)vsra_n_s32((int32x2_t)cc2h, (int32x2_t)cc1h, 31);
    zzh = vshr_n_u32(cc2h, 31);

    z = (int) (vaddvq_u32(zz) + vaddv_u32(zzh));
    return z;
}

static int
BerExp(prng *p, fpr x, fpr ccs) {
    int s, i;
    fpr r;
    uint32_t sw, w;
    uint64_t z;

    s = (int)fpr_trunc(fpr_mul(x, fpr_inv_log2));
    r = fpr_sub(x, fpr_mul(fpr_of(s), fpr_log2));

    sw = (uint32_t)s;
    sw ^= (sw ^ 63) & -((63 - sw) >> 31);
    s = (int)sw;

    z = ((fpr_expm_p63(r, ccs) << 1) - 1) >> s;

    i = 64;
    do {
        i -= 8;
        w = prng_get_u8(p) - ((uint32_t)(z >> i) & 0xFF);
    } while (!w && i > 0);
    return (int)(w >> 31);
}

int
PQCLEAN_FALCONPADDED512_AARCH64_sampler(void *ctx, fpr mu, fpr isigma) {
    sampler_context *spc;
    int s;
    fpr r, dss, ccs;

    spc = ctx;

    s = (int)fpr_floor(mu);
    r = fpr_sub(mu, fpr_of(s));

    dss = fpr_half(fpr_sqr(isigma));

    ccs = fpr_mul(isigma, spc->sigma_min);

    for (;;) {
        int z0, z, b;
        fpr x;

        z0 = PQCLEAN_FALCONPADDED512_AARCH64_gaussian0_sampler(&spc->p);
        b = (int)prng_get_u8(&spc->p) & 1;
        z = b + ((b << 1) - 1) * z0;

        x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(z), r)), dss);
        x = fpr_sub(x, fpr_mul(fpr_of(z0 * z0), fpr_inv_2sqrsigma0));
        if (BerExp(&spc->p, x, ccs)) {

            return s + z;
        }
    }
}