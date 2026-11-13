
#include "inner.h"
#include "macrofx4.h"
#include "macrous.h"

void PQCLEAN_FALCON1024_AARCH64_hash_to_point_vartime(
    inner_shake256_context *sc,
    uint16_t *x, unsigned logn) {

    size_t n;

    n = (size_t)1 << logn;
    while (n > 0) {
        uint8_t buf[2];
        uint32_t w;

        inner_shake256_extract(sc, (void *)buf, sizeof buf);
        w = ((unsigned)buf[0] << 8) | (unsigned)buf[1];
        if (w < 5 * FALCON_Q) {
            while (w >= FALCON_Q) {
                w -= FALCON_Q;
            }
            *x++ = (uint16_t)w;
            n--;
        }
    }
}

void PQCLEAN_FALCON1024_AARCH64_hash_to_point_ct(
    inner_shake256_context *sc,
    uint16_t *x, unsigned logn, uint8_t *tmp) {

    static const uint16_t overtab[] = {
        0, 
        65,
        67,
        71,
        77,
        86,
        100,
        122,
        154,
        205,
        287
    };

    unsigned n, n2, u, m, p, over;
    uint16_t *tt1, tt2[63];

    n = 1U << logn;
    n2 = n << 1;
    over = overtab[logn];
    m = n + over;
    tt1 = (uint16_t *)tmp;
    for (u = 0; u < m; u++) {
        uint8_t buf[2];
        uint32_t w, wr;

        inner_shake256_extract(sc, buf, sizeof buf);
        w = ((uint32_t)buf[0] << 8) | (uint32_t)buf[1];
        wr = w - ((uint32_t)24578 & (((w - 24578) >> 31) - 1));
        wr = wr - ((uint32_t)24578 & (((wr - 24578) >> 31) - 1));
        wr = wr - ((uint32_t)12289 & (((wr - 12289) >> 31) - 1));
        wr |= ((w - 61445) >> 31) - 1;
        if (u < n) {
            x[u] = (uint16_t)wr;
        } else if (u < n2) {
            tt1[u - n] = (uint16_t)wr;
        } else {
            tt2[u - n2] = (uint16_t)wr;
        }
    }

    for (p = 1; p <= over; p <<= 1) {
        unsigned v;

        v = 0;
        for (u = 0; u < m; u++) {
            uint16_t *s, *d;
            unsigned j, sv, dv, mk;

            if (u < n) {
                s = &x[u];
            } else if (u < n2) {
                s = &tt1[u - n];
            } else {
                s = &tt2[u - n2];
            }
            sv = *s;

            j = u - v;

            mk = (sv >> 15) - 1U;
            v -= mk;

            if (u < p) {
                continue;
            }

            if ((u - p) < n) {
                d = &x[u - p];
            } else if ((u - p) < n2) {
                d = &tt1[(u - p) - n];
            } else {
                d = &tt2[(u - p) - n2];
            }
            dv = *d;

            mk &= -(((j & p) + 0x1FF) >> 9);

            *s = (uint16_t)(sv ^ (mk & (sv ^ dv)));
            *d = (uint16_t)(dv ^ (mk & (sv ^ dv)));
        }
    }
}

static const uint32_t l2bound[] = {
    0, 
    101498,
    208714,
    428865,
    892039,
    1852696,
    3842630,
    7959734,
    16468416,
    34034726,
    70265242
};

int PQCLEAN_FALCON1024_AARCH64_is_short(const int16_t *s1, const int16_t *s2) {

    int16x8x4_t neon_s1, neon_s2, neon_s3, neon_s4; 
    int32x4_t neon_s, neon_sh;                      
    int32x2_t tmp;
    uint32_t s;
    neon_s = vdupq_n_s32(0);
    neon_sh = vdupq_n_s32(0);

    for (unsigned u = 0; u < FALCON_N; u += 128) {
        vload_s16_x4(neon_s1, &s1[u]);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s1.val[0]), vget_low_s16(neon_s1.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s1.val[1]), vget_low_s16(neon_s1.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s1.val[2]), vget_low_s16(neon_s1.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s1.val[3]), vget_low_s16(neon_s1.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_s1.val[0], neon_s1.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s1.val[1], neon_s1.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s1.val[2], neon_s1.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s1.val[3], neon_s1.val[3]);

        vload_s16_x4(neon_s2, &s1[u + 32]);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s2.val[0]), vget_low_s16(neon_s2.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s2.val[1]), vget_low_s16(neon_s2.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s2.val[2]), vget_low_s16(neon_s2.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s2.val[3]), vget_low_s16(neon_s2.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_s2.val[0], neon_s2.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s2.val[1], neon_s2.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s2.val[2], neon_s2.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s2.val[3], neon_s2.val[3]);

        vload_s16_x4(neon_s3, &s1[u + 64]);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s3.val[0]), vget_low_s16(neon_s3.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s3.val[1]), vget_low_s16(neon_s3.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s3.val[2]), vget_low_s16(neon_s3.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s3.val[3]), vget_low_s16(neon_s3.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_s3.val[0], neon_s3.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s3.val[1], neon_s3.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s3.val[2], neon_s3.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s3.val[3], neon_s3.val[3]);

        vload_s16_x4(neon_s4, &s1[u + 96]);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s4.val[0]), vget_low_s16(neon_s4.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s4.val[1]), vget_low_s16(neon_s4.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s4.val[2]), vget_low_s16(neon_s4.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s4.val[3]), vget_low_s16(neon_s4.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_s4.val[0], neon_s4.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s4.val[1], neon_s4.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s4.val[2], neon_s4.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s4.val[3], neon_s4.val[3]);
    }
    for (unsigned u = 0; u < FALCON_N; u += 128) {
        vload_s16_x4(neon_s1, &s2[u]);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s1.val[0]), vget_low_s16(neon_s1.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s1.val[1]), vget_low_s16(neon_s1.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s1.val[2]), vget_low_s16(neon_s1.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s1.val[3]), vget_low_s16(neon_s1.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_s1.val[0], neon_s1.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s1.val[1], neon_s1.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s1.val[2], neon_s1.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s1.val[3], neon_s1.val[3]);

        vload_s16_x4(neon_s2, &s2[u + 32]);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s2.val[0]), vget_low_s16(neon_s2.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s2.val[1]), vget_low_s16(neon_s2.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s2.val[2]), vget_low_s16(neon_s2.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s2.val[3]), vget_low_s16(neon_s2.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_s2.val[0], neon_s2.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s2.val[1], neon_s2.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s2.val[2], neon_s2.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s2.val[3], neon_s2.val[3]);

        vload_s16_x4(neon_s3, &s2[u + 64]);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s3.val[0]), vget_low_s16(neon_s3.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s3.val[1]), vget_low_s16(neon_s3.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s3.val[2]), vget_low_s16(neon_s3.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s3.val[3]), vget_low_s16(neon_s3.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_s3.val[0], neon_s3.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s3.val[1], neon_s3.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s3.val[2], neon_s3.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s3.val[3], neon_s3.val[3]);

        vload_s16_x4(neon_s4, &s2[u + 96]);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s4.val[0]), vget_low_s16(neon_s4.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s4.val[1]), vget_low_s16(neon_s4.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s4.val[2]), vget_low_s16(neon_s4.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_s4.val[3]), vget_low_s16(neon_s4.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_s4.val[0], neon_s4.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s4.val[1], neon_s4.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s4.val[2], neon_s4.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_s4.val[3], neon_s4.val[3]);
    }

    neon_s = vhaddq_s32(neon_s, neon_sh);

    tmp = vqadd_s32(vget_low_s32(neon_s), vget_high_s32(neon_s));

    s = (uint32_t) vqadds_s32(vget_lane_s32(tmp, 0), vget_lane_s32(tmp, 1));

    return s <= l2bound[FALCON_LOGN];
}

int PQCLEAN_FALCON1024_AARCH64_is_short_tmp(int16_t *s1tmp, int16_t *s2tmp,
        const int16_t *hm, const fpr *t0,
        const fpr *t1) {

    int16x8x4_t neon_hm, neon_ts;                         
    float64x2x4_t neon_tf0, neon_tf1, neon_tf2, neon_tf3; 
    int64x2x4_t neon_ts0, neon_ts1, neon_ts2, neon_ts3;   
    int32x4x4_t neon_ts4, neon_ts5;                       
    int32x4_t neon_s, neon_sh;                            
    int32x2_t tmp;
    uint32_t s;

    neon_s = vdupq_n_s32(0);
    neon_sh = vdupq_n_s32(0);

    for (int i = 0; i < FALCON_N; i += 32) {
        vloadx4(neon_tf0, &t0[i]);
        vloadx4(neon_tf1, &t0[i + 8]);
        vfrintx4(neon_ts0, neon_tf0);
        vfrintx4(neon_ts1, neon_tf1);

        neon_ts4.val[0] = vmovn_high_s64(vmovn_s64(neon_ts0.val[0]), neon_ts0.val[1]);
        neon_ts4.val[1] = vmovn_high_s64(vmovn_s64(neon_ts0.val[2]), neon_ts0.val[3]);
        neon_ts4.val[2] = vmovn_high_s64(vmovn_s64(neon_ts1.val[0]), neon_ts1.val[1]);
        neon_ts4.val[3] = vmovn_high_s64(vmovn_s64(neon_ts1.val[2]), neon_ts1.val[3]);

        vloadx4(neon_tf2, &t0[i + 16]);
        vloadx4(neon_tf3, &t0[i + 24]);
        vfrintx4(neon_ts2, neon_tf2);
        vfrintx4(neon_ts3, neon_tf3);

        neon_ts5.val[0] = vmovn_high_s64(vmovn_s64(neon_ts2.val[0]), neon_ts2.val[1]);
        neon_ts5.val[1] = vmovn_high_s64(vmovn_s64(neon_ts2.val[2]), neon_ts2.val[3]);
        neon_ts5.val[2] = vmovn_high_s64(vmovn_s64(neon_ts3.val[0]), neon_ts3.val[1]);
        neon_ts5.val[3] = vmovn_high_s64(vmovn_s64(neon_ts3.val[2]), neon_ts3.val[3]);

        neon_ts.val[0] = vmovn_high_s32(vmovn_s32(neon_ts4.val[0]), neon_ts4.val[1]);
        neon_ts.val[1] = vmovn_high_s32(vmovn_s32(neon_ts4.val[2]), neon_ts4.val[3]);
        neon_ts.val[2] = vmovn_high_s32(vmovn_s32(neon_ts5.val[0]), neon_ts5.val[1]);
        neon_ts.val[3] = vmovn_high_s32(vmovn_s32(neon_ts5.val[2]), neon_ts5.val[3]);

        vload_s16_x4(neon_hm, &hm[i]);
        neon_hm.val[0] = vsubq_s16(neon_hm.val[0], neon_ts.val[0]);
        neon_hm.val[1] = vsubq_s16(neon_hm.val[1], neon_ts.val[1]);
        neon_hm.val[2] = vsubq_s16(neon_hm.val[2], neon_ts.val[2]);
        neon_hm.val[3] = vsubq_s16(neon_hm.val[3], neon_ts.val[3]);
        vstore_s16_x4(&s1tmp[i], neon_hm);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_hm.val[0]), vget_low_s16(neon_hm.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_hm.val[1]), vget_low_s16(neon_hm.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_hm.val[2]), vget_low_s16(neon_hm.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_hm.val[3]), vget_low_s16(neon_hm.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_hm.val[0], neon_hm.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_hm.val[1], neon_hm.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_hm.val[2], neon_hm.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_hm.val[3], neon_hm.val[3]);
    }

    for (int i = 0; i < FALCON_N; i += 32) {
        vloadx4(neon_tf0, &t1[i]);
        vloadx4(neon_tf1, &t1[i + 8]);

        vfrintx4(neon_ts0, neon_tf0);
        vfrintx4(neon_ts1, neon_tf1);

        neon_ts4.val[0] = vmovn_high_s64(vmovn_s64(neon_ts0.val[0]), neon_ts0.val[1]);
        neon_ts4.val[1] = vmovn_high_s64(vmovn_s64(neon_ts0.val[2]), neon_ts0.val[3]);
        neon_ts4.val[2] = vmovn_high_s64(vmovn_s64(neon_ts1.val[0]), neon_ts1.val[1]);
        neon_ts4.val[3] = vmovn_high_s64(vmovn_s64(neon_ts1.val[2]), neon_ts1.val[3]);

        vloadx4(neon_tf2, &t1[i + 16]);
        vloadx4(neon_tf3, &t1[i + 24]);

        vfrintx4(neon_ts2, neon_tf2);
        vfrintx4(neon_ts3, neon_tf3);

        neon_ts5.val[0] = vmovn_high_s64(vmovn_s64(neon_ts2.val[0]), neon_ts2.val[1]);
        neon_ts5.val[1] = vmovn_high_s64(vmovn_s64(neon_ts2.val[2]), neon_ts2.val[3]);
        neon_ts5.val[2] = vmovn_high_s64(vmovn_s64(neon_ts3.val[0]), neon_ts3.val[1]);
        neon_ts5.val[3] = vmovn_high_s64(vmovn_s64(neon_ts3.val[2]), neon_ts3.val[3]);

        neon_ts.val[0] = vmovn_high_s32(vmovn_s32(neon_ts4.val[0]), neon_ts4.val[1]);
        neon_ts.val[1] = vmovn_high_s32(vmovn_s32(neon_ts4.val[2]), neon_ts4.val[3]);
        neon_ts.val[2] = vmovn_high_s32(vmovn_s32(neon_ts5.val[0]), neon_ts5.val[1]);
        neon_ts.val[3] = vmovn_high_s32(vmovn_s32(neon_ts5.val[2]), neon_ts5.val[3]);

        neon_ts.val[0] = vnegq_s16(neon_ts.val[0]);
        neon_ts.val[1] = vnegq_s16(neon_ts.val[1]);
        neon_ts.val[2] = vnegq_s16(neon_ts.val[2]);
        neon_ts.val[3] = vnegq_s16(neon_ts.val[3]);
        vstore_s16_x4(&s2tmp[i], neon_ts);

        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_ts.val[0]), vget_low_s16(neon_ts.val[0]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_ts.val[1]), vget_low_s16(neon_ts.val[1]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_ts.val[2]), vget_low_s16(neon_ts.val[2]));
        neon_s = vqdmlal_s16(neon_s, vget_low_s16(neon_ts.val[3]), vget_low_s16(neon_ts.val[3]));

        neon_sh = vqdmlal_high_s16(neon_sh, neon_ts.val[0], neon_ts.val[0]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_ts.val[1], neon_ts.val[1]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_ts.val[2], neon_ts.val[2]);
        neon_sh = vqdmlal_high_s16(neon_sh, neon_ts.val[3], neon_ts.val[3]);
    }

    neon_s = vhaddq_s32(neon_s, neon_sh);

    tmp = vqadd_s32(vget_low_s32(neon_s), vget_high_s32(neon_s));

    s = (uint32_t) vqadds_s32(vget_lane_s32(tmp, 0), vget_lane_s32(tmp, 1));

    return s <= l2bound[FALCON_LOGN];
}

int32_t PQCLEAN_FALCON1024_AARCH64_poly_small_sqnorm(const int8_t *f) {
    int8x16x4_t a;
    int16x8x4_t b, c;
    int32x4_t norm, norm_sh;

    norm = vdupq_n_s32(0);
    norm_sh = vdupq_n_s32(0);

    for (int i = 0; i < FALCON_N; i += 64) {
        a = vld1q_s8_x4(&f[0]);

        b.val[0] = vmovl_s8(vget_low_s8(a.val[0]));
        b.val[1] = vmovl_high_s8(a.val[0]);
        b.val[2] = vmovl_s8(vget_low_s8(a.val[1]));
        b.val[3] = vmovl_high_s8(a.val[1]);

        c.val[0] = vmovl_s8(vget_low_s8(a.val[2]));
        c.val[1] = vmovl_high_s8(a.val[2]);
        c.val[2] = vmovl_s8(vget_low_s8(a.val[3]));
        c.val[3] = vmovl_high_s8(a.val[3]);

        norm = vqdmlal_s16(norm, vget_low_s16(b.val[0]), vget_low_s16(b.val[0]));
        norm = vqdmlal_s16(norm, vget_low_s16(b.val[1]), vget_low_s16(b.val[1]));
        norm = vqdmlal_s16(norm, vget_low_s16(b.val[2]), vget_low_s16(b.val[2]));
        norm = vqdmlal_s16(norm, vget_low_s16(b.val[3]), vget_low_s16(b.val[3]));

        norm = vqdmlal_high_s16(norm, b.val[0], b.val[0]);
        norm = vqdmlal_high_s16(norm, b.val[1], b.val[1]);
        norm = vqdmlal_high_s16(norm, b.val[2], b.val[2]);
        norm = vqdmlal_high_s16(norm, b.val[3], b.val[3]);

        norm_sh = vqdmlal_s16(norm_sh, vget_low_s16(c.val[0]), vget_low_s16(c.val[0]));
        norm_sh = vqdmlal_s16(norm_sh, vget_low_s16(c.val[1]), vget_low_s16(c.val[1]));
        norm_sh = vqdmlal_s16(norm_sh, vget_low_s16(c.val[2]), vget_low_s16(c.val[2]));
        norm_sh = vqdmlal_s16(norm_sh, vget_low_s16(c.val[3]), vget_low_s16(c.val[3]));

        norm_sh = vqdmlal_high_s16(norm_sh, c.val[0], c.val[0]);
        norm_sh = vqdmlal_high_s16(norm_sh, c.val[1], c.val[1]);
        norm_sh = vqdmlal_high_s16(norm_sh, c.val[2], c.val[2]);
        norm_sh = vqdmlal_high_s16(norm_sh, c.val[3], c.val[3]);
    }

    norm = vhaddq_s32(norm, norm_sh);

    int32x2_t tmp;
    tmp = vqadd_s32(vget_low_s32(norm), vget_high_s32(norm));

    int32_t s;
    s = vqadds_s32(vget_lane_s32(tmp, 0), vget_lane_s32(tmp, 1));

    return s;
}