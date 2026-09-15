
#include "inner.h"
#include "macrous.h"
#include "ntt_consts.h"
#include "poly.h"

#include <arm_neon.h>

void PQCLEAN_FALCONPADDED512_AARCH64_poly_ntt(int16_t a[FALCON_N], ntt_domain_t mont) {

    int16x8x4_t v0, v1, v2, v3; 
    int16x8x4_t zl, zh, t, t2;  
    int16x8x2_t zlh, zhh;       
    int16x8_t neon_qmvq;        
    const int16_t *ptr_ntt_br = PQCLEAN_FALCONPADDED512_AARCH64_ntt_br;
    const int16_t *ptr_ntt_qinv_br = PQCLEAN_FALCONPADDED512_AARCH64_ntt_qinv_br;

    neon_qmvq = vld1q_s16(PQCLEAN_FALCONPADDED512_AARCH64_qmvq);
    zl.val[0] = vld1q_s16(ptr_ntt_br);
    zh.val[0] = vld1q_s16(ptr_ntt_qinv_br);
    ptr_ntt_br += 8;
    ptr_ntt_qinv_br += 8;

    for (unsigned j = 0; j < 128; j += 32) {
        vload_s16_x4(v0, &a[j]);
        vload_s16_x4(v1, &a[j + 128]);
        vload_s16_x4(v2, &a[j + 256]);
        vload_s16_x4(v3, &a[j + 384]);

        ctbf_bri_top_x4(v2, zl.val[0], zh.val[0], 1, 1, 1, 1, neon_qmvq, t);
        ctbf_bri_top_x4(v3, zl.val[0], zh.val[0], 1, 1, 1, 1, neon_qmvq, t2);

        ctbf_bot_x4(v0, v2, t);
        ctbf_bot_x4(v1, v3, t2);

        ctbf_bri_top_x4(v1, zl.val[0], zh.val[0], 2, 2, 2, 2, neon_qmvq, t);
        ctbf_bri_top_x4(v3, zl.val[0], zh.val[0], 3, 3, 3, 3, neon_qmvq, t2);

        ctbf_bot_x4(v0, v1, t);
        ctbf_bot_x4(v2, v3, t2);

        barrett_x4(v0, neon_qmvq, t);
        barrett_x4(v1, neon_qmvq, t);
        barrett_x4(v2, neon_qmvq, t2);
        barrett_x4(v3, neon_qmvq, t2);

        vstore_s16_x4(&a[j], v0);
        vstore_s16_x4(&a[j + 128], v1);
        vstore_s16_x4(&a[j + 256], v2);
        vstore_s16_x4(&a[j + 384], v3);
    }

    for (unsigned j = 0; j < FALCON_N; j += 128) {
        vload_s16_x4(v0, &a[j]);
        vload_s16_x4(v1, &a[j + 32]);
        vload_s16_x4(v2, &a[j + 64]);
        vload_s16_x4(v3, &a[j + 96]);

        vload_s16_x2(zlh, ptr_ntt_br);
        vload_s16_x2(zhh, ptr_ntt_qinv_br);
        ptr_ntt_br += 16;
        ptr_ntt_qinv_br += 16;

        ctbf_bri_top_x4(v2, zlh.val[0], zhh.val[0], 0, 0, 0, 0, neon_qmvq, t);
        ctbf_bri_top_x4(v3, zlh.val[0], zhh.val[0], 0, 0, 0, 0, neon_qmvq, t2);

        ctbf_bot_x4(v0, v2, t);
        ctbf_bot_x4(v1, v3, t2);

        ctbf_bri_top_x4(v1, zlh.val[0], zhh.val[0], 1, 1, 1, 1, neon_qmvq, t);
        ctbf_bri_top_x4(v3, zlh.val[0], zhh.val[0], 2, 2, 2, 2, neon_qmvq, t2);

        ctbf_bot_x4(v0, v1, t);
        ctbf_bot_x4(v2, v3, t2);

        barrett_x4(v0, neon_qmvq, t);
        barrett_x4(v1, neon_qmvq, t);
        barrett_x4(v2, neon_qmvq, t2);
        barrett_x4(v3, neon_qmvq, t2);

        ctbf_bri_top(v0.val[2], zlh.val[0], zhh.val[0], 3, neon_qmvq, t.val[0]);
        ctbf_bri_top(v0.val[3], zlh.val[0], zhh.val[0], 3, neon_qmvq, t.val[1]);
        ctbf_bri_top(v1.val[2], zlh.val[0], zhh.val[0], 4, neon_qmvq, t.val[2]);
        ctbf_bri_top(v1.val[3], zlh.val[0], zhh.val[0], 4, neon_qmvq, t.val[3]);

        ctbf_bri_top(v2.val[2], zlh.val[0], zhh.val[0], 5, neon_qmvq, t2.val[0]);
        ctbf_bri_top(v2.val[3], zlh.val[0], zhh.val[0], 5, neon_qmvq, t2.val[1]);
        ctbf_bri_top(v3.val[2], zlh.val[0], zhh.val[0], 6, neon_qmvq, t2.val[2]);
        ctbf_bri_top(v3.val[3], zlh.val[0], zhh.val[0], 6, neon_qmvq, t2.val[3]);

        ctbf_bot(v0.val[0], v0.val[2], t.val[0]);
        ctbf_bot(v0.val[1], v0.val[3], t.val[1]);
        ctbf_bot(v1.val[0], v1.val[2], t.val[2]);
        ctbf_bot(v1.val[1], v1.val[3], t.val[3]);

        ctbf_bot(v2.val[0], v2.val[2], t2.val[0]);
        ctbf_bot(v2.val[1], v2.val[3], t2.val[1]);
        ctbf_bot(v3.val[0], v3.val[2], t2.val[2]);
        ctbf_bot(v3.val[1], v3.val[3], t2.val[3]);

        ctbf_bri_top(v0.val[1], zlh.val[0], zhh.val[0], 7, neon_qmvq, t.val[0]);
        ctbf_bri_top(v0.val[3], zlh.val[1], zhh.val[1], 0, neon_qmvq, t.val[1]);
        ctbf_bri_top(v1.val[1], zlh.val[1], zhh.val[1], 1, neon_qmvq, t.val[2]);
        ctbf_bri_top(v1.val[3], zlh.val[1], zhh.val[1], 2, neon_qmvq, t.val[3]);

        ctbf_bri_top(v2.val[1], zlh.val[1], zhh.val[1], 3, neon_qmvq, t2.val[0]);
        ctbf_bri_top(v2.val[3], zlh.val[1], zhh.val[1], 4, neon_qmvq, t2.val[1]);
        ctbf_bri_top(v3.val[1], zlh.val[1], zhh.val[1], 5, neon_qmvq, t2.val[2]);
        ctbf_bri_top(v3.val[3], zlh.val[1], zhh.val[1], 6, neon_qmvq, t2.val[3]);

        ctbf_bot(v0.val[0], v0.val[1], t.val[0]);
        ctbf_bot(v0.val[2], v0.val[3], t.val[1]);
        ctbf_bot(v1.val[0], v1.val[1], t.val[2]);
        ctbf_bot(v1.val[2], v1.val[3], t.val[3]);

        ctbf_bot(v2.val[0], v2.val[1], t2.val[0]);
        ctbf_bot(v2.val[2], v2.val[3], t2.val[1]);
        ctbf_bot(v3.val[0], v3.val[1], t2.val[2]);
        ctbf_bot(v3.val[2], v3.val[3], t2.val[3]);

        barrett_x4(v0, neon_qmvq, t);
        barrett_x4(v1, neon_qmvq, t);
        barrett_x4(v2, neon_qmvq, t2);
        barrett_x4(v3, neon_qmvq, t2);

        arrange(t, v0, 0, 2, 1, 3, 0, 1, 2, 3);
        v0 = t;
        arrange(t, v1, 0, 2, 1, 3, 0, 1, 2, 3);
        v1 = t;
        arrange(t2, v2, 0, 2, 1, 3, 0, 1, 2, 3);
        v2 = t2;
        arrange(t2, v3, 0, 2, 1, 3, 0, 1, 2, 3);
        v3 = t2;

        vload_s16_x4(zl, ptr_ntt_br);
        vload_s16_x4(zh, ptr_ntt_qinv_br);
        ptr_ntt_br += 32;
        ptr_ntt_qinv_br += 32;

        ctbf_br_top(v0.val[1], zl.val[0], zh.val[0], neon_qmvq, t.val[0]);
        ctbf_br_top(v1.val[1], zl.val[1], zh.val[1], neon_qmvq, t.val[1]);
        ctbf_br_top(v2.val[1], zl.val[2], zh.val[2], neon_qmvq, t.val[2]);
        ctbf_br_top(v3.val[1], zl.val[3], zh.val[3], neon_qmvq, t.val[3]);

        ctbf_bot(v0.val[0], v0.val[1], t.val[0]);
        ctbf_bot(v1.val[0], v1.val[1], t.val[1]);
        ctbf_bot(v2.val[0], v2.val[1], t.val[2]);
        ctbf_bot(v3.val[0], v3.val[1], t.val[3]);

        vload_s16_x4(zl, ptr_ntt_br);
        vload_s16_x4(zh, ptr_ntt_qinv_br);
        ptr_ntt_br += 32;
        ptr_ntt_qinv_br += 32;

        ctbf_br_top(v0.val[3], zl.val[0], zh.val[0], neon_qmvq, t.val[0]);
        ctbf_br_top(v1.val[3], zl.val[1], zh.val[1], neon_qmvq, t.val[1]);
        ctbf_br_top(v2.val[3], zl.val[2], zh.val[2], neon_qmvq, t.val[2]);
        ctbf_br_top(v3.val[3], zl.val[3], zh.val[3], neon_qmvq, t.val[3]);

        ctbf_bot(v0.val[2], v0.val[3], t.val[0]);
        ctbf_bot(v1.val[2], v1.val[3], t.val[1]);
        ctbf_bot(v2.val[2], v2.val[3], t.val[2]);
        ctbf_bot(v3.val[2], v3.val[3], t.val[3]);

        transpose(v0, t);
        transpose(v1, t);
        transpose(v2, t2);
        transpose(v3, t2);

        vload_s16_x4(zl, ptr_ntt_br);
        vload_s16_x4(zh, ptr_ntt_qinv_br);
        ptr_ntt_br += 32;
        ptr_ntt_qinv_br += 32;

        ctbf_br_top(v0.val[2], zl.val[0], zh.val[0], neon_qmvq, t.val[0]);
        ctbf_br_top(v0.val[3], zl.val[0], zh.val[0], neon_qmvq, t.val[1]);
        ctbf_br_top(v1.val[2], zl.val[1], zh.val[1], neon_qmvq, t.val[2]);
        ctbf_br_top(v1.val[3], zl.val[1], zh.val[1], neon_qmvq, t.val[3]);

        ctbf_bot(v0.val[0], v0.val[2], t.val[0]);
        ctbf_bot(v0.val[1], v0.val[3], t.val[1]);
        ctbf_bot(v1.val[0], v1.val[2], t.val[2]);
        ctbf_bot(v1.val[1], v1.val[3], t.val[3]);

        ctbf_br_top(v2.val[2], zl.val[2], zh.val[2], neon_qmvq, t.val[0]);
        ctbf_br_top(v2.val[3], zl.val[2], zh.val[2], neon_qmvq, t.val[1]);
        ctbf_br_top(v3.val[2], zl.val[3], zh.val[3], neon_qmvq, t.val[2]);
        ctbf_br_top(v3.val[3], zl.val[3], zh.val[3], neon_qmvq, t.val[3]);

        ctbf_bot(v2.val[0], v2.val[2], t.val[0]);
        ctbf_bot(v2.val[1], v2.val[3], t.val[1]);
        ctbf_bot(v3.val[0], v3.val[2], t.val[2]);
        ctbf_bot(v3.val[1], v3.val[3], t.val[3]);

        barrett_x4(v0, neon_qmvq, t);
        barrett_x4(v1, neon_qmvq, t);
        barrett_x4(v2, neon_qmvq, t2);
        barrett_x4(v3, neon_qmvq, t2);

        vload_s16_x4(zl, ptr_ntt_br);
        vload_s16_x4(zh, ptr_ntt_qinv_br);
        ptr_ntt_br += 32;
        ptr_ntt_qinv_br += 32;

        ctbf_br_top(v0.val[1], zl.val[0], zh.val[0], neon_qmvq, t.val[0]);
        ctbf_br_top(v1.val[1], zl.val[1], zh.val[1], neon_qmvq, t.val[1]);
        ctbf_br_top(v2.val[1], zl.val[2], zh.val[2], neon_qmvq, t.val[2]);
        ctbf_br_top(v3.val[1], zl.val[3], zh.val[3], neon_qmvq, t.val[3]);

        ctbf_bot(v0.val[0], v0.val[1], t.val[0]);
        ctbf_bot(v1.val[0], v1.val[1], t.val[1]);
        ctbf_bot(v2.val[0], v2.val[1], t.val[2]);
        ctbf_bot(v3.val[0], v3.val[1], t.val[3]);

        vload_s16_x4(zl, ptr_ntt_br);
        vload_s16_x4(zh, ptr_ntt_qinv_br);
        ptr_ntt_br += 32;
        ptr_ntt_qinv_br += 32;

        ctbf_br_top(v0.val[3], zl.val[0], zh.val[0], neon_qmvq, t.val[0]);
        ctbf_br_top(v1.val[3], zl.val[1], zh.val[1], neon_qmvq, t.val[1]);
        ctbf_br_top(v2.val[3], zl.val[2], zh.val[2], neon_qmvq, t.val[2]);
        ctbf_br_top(v3.val[3], zl.val[3], zh.val[3], neon_qmvq, t.val[3]);

        ctbf_bot(v0.val[2], v0.val[3], t.val[0]);
        ctbf_bot(v1.val[2], v1.val[3], t.val[1]);
        ctbf_bot(v2.val[2], v2.val[3], t.val[2]);
        ctbf_bot(v3.val[2], v3.val[3], t.val[3]);

        if (mont == NTT_MONT) {

            barmuli_mont_x8(v0, v1, neon_qmvq, t, t2);
            barmuli_mont_x8(v2, v3, neon_qmvq, t, t2);
        } else if (mont == NTT_MONT_INV) {
            barmuli_mont_ninv_x8(v0, v1, neon_qmvq, t, t2);
            barmuli_mont_ninv_x8(v2, v3, neon_qmvq, t, t2);
        }

        vstore_s16_4(&a[j], v0);
        vstore_s16_4(&a[j + 32], v1);
        vstore_s16_4(&a[j + 64], v2);
        vstore_s16_4(&a[j + 96], v3);
    }
}

void PQCLEAN_FALCONPADDED512_AARCH64_poly_invntt(int16_t a[FALCON_N], invntt_domain_t ninv) {

    int16x8x4_t v0, v1, v2, v3; 
    int16x8x4_t zl, zh, t, t2;  
    int16x8x2_t zlh, zhh;       
    int16x8_t neon_qmvq;        
    const int16_t *ptr_invntt_br = PQCLEAN_FALCONPADDED512_AARCH64_invntt_br;
    const int16_t *ptr_invntt_qinv_br = PQCLEAN_FALCONPADDED512_AARCH64_invntt_qinv_br;

    neon_qmvq = vld1q_s16(PQCLEAN_FALCONPADDED512_AARCH64_qmvq);
    unsigned j;

    for (j = 0; j < FALCON_N; j += 128) {
        vload_s16_4(v0, &a[j]);
        vload_s16_4(v1, &a[j + 32]);
        vload_s16_4(v2, &a[j + 64]);
        vload_s16_4(v3, &a[j + 96]);

        gsbf_top(v0.val[0], v0.val[1], t.val[0]);
        gsbf_top(v1.val[0], v1.val[1], t.val[1]);
        gsbf_top(v2.val[0], v2.val[1], t.val[2]);
        gsbf_top(v3.val[0], v3.val[1], t.val[3]);

        gsbf_top(v0.val[2], v0.val[3], t2.val[0]);
        gsbf_top(v1.val[2], v1.val[3], t2.val[1]);
        gsbf_top(v2.val[2], v2.val[3], t2.val[2]);
        gsbf_top(v3.val[2], v3.val[3], t2.val[3]);

        vload_s16_x2(zlh, ptr_invntt_br);
        vload_s16_x2(zhh, ptr_invntt_qinv_br);
        ptr_invntt_br += 16;
        ptr_invntt_qinv_br += 16;

        gsbf_br_bot(v0.val[1], zlh.val[0], zhh.val[0], neon_qmvq, t.val[0]);
        gsbf_br_bot(v1.val[1], zlh.val[1], zhh.val[1], neon_qmvq, t.val[1]);

        vload_s16_x2(zlh, ptr_invntt_br);
        vload_s16_x2(zhh, ptr_invntt_qinv_br);
        ptr_invntt_br += 16;
        ptr_invntt_qinv_br += 16;

        gsbf_br_bot(v2.val[1], zlh.val[0], zhh.val[0], neon_qmvq, t.val[2]);
        gsbf_br_bot(v3.val[1], zlh.val[1], zhh.val[1], neon_qmvq, t.val[3]);

        vload_s16_x4(zl, ptr_invntt_br);
        vload_s16_x4(zh, ptr_invntt_qinv_br);
        ptr_invntt_br += 32;
        ptr_invntt_qinv_br += 32;

        gsbf_br_bot(v0.val[3], zl.val[0], zh.val[0], neon_qmvq, t2.val[0]);
        gsbf_br_bot(v1.val[3], zl.val[1], zh.val[1], neon_qmvq, t2.val[1]);
        gsbf_br_bot(v2.val[3], zl.val[2], zh.val[2], neon_qmvq, t2.val[2]);
        gsbf_br_bot(v3.val[3], zl.val[3], zh.val[3], neon_qmvq, t2.val[3]);

        barrett(v0.val[0], neon_qmvq, t.val[0]);
        barrett(v1.val[0], neon_qmvq, t.val[1]);
        barrett(v2.val[0], neon_qmvq, t.val[2]);
        barrett(v3.val[0], neon_qmvq, t.val[3]);

        vload_s16_x2(zlh, ptr_invntt_br);
        vload_s16_x2(zhh, ptr_invntt_qinv_br);
        ptr_invntt_br += 16;
        ptr_invntt_qinv_br += 16;

        gsbf_top(v0.val[0], v0.val[2], t.val[0]);
        gsbf_top(v0.val[1], v0.val[3], t.val[1]);
        gsbf_top(v1.val[0], v1.val[2], t.val[2]);
        gsbf_top(v1.val[1], v1.val[3], t.val[3]);

        gsbf_top(v2.val[0], v2.val[2], t2.val[0]);
        gsbf_top(v2.val[1], v2.val[3], t2.val[1]);
        gsbf_top(v3.val[0], v3.val[2], t2.val[2]);
        gsbf_top(v3.val[1], v3.val[3], t2.val[3]);

        gsbf_br_bot(v0.val[2], zlh.val[0], zhh.val[0], neon_qmvq, t.val[0]);
        gsbf_br_bot(v0.val[3], zlh.val[0], zhh.val[0], neon_qmvq, t.val[1]);
        gsbf_br_bot(v1.val[2], zlh.val[1], zhh.val[1], neon_qmvq, t.val[2]);
        gsbf_br_bot(v1.val[3], zlh.val[1], zhh.val[1], neon_qmvq, t.val[3]);

        vload_s16_x2(zlh, ptr_invntt_br);
        vload_s16_x2(zhh, ptr_invntt_qinv_br);
        ptr_invntt_br += 16;
        ptr_invntt_qinv_br += 16;

        gsbf_br_bot(v2.val[2], zlh.val[0], zhh.val[0], neon_qmvq, t2.val[0]);
        gsbf_br_bot(v2.val[3], zlh.val[0], zhh.val[0], neon_qmvq, t2.val[1]);
        gsbf_br_bot(v3.val[2], zlh.val[1], zhh.val[1], neon_qmvq, t2.val[2]);
        gsbf_br_bot(v3.val[3], zlh.val[1], zhh.val[1], neon_qmvq, t2.val[3]);

        barrett_x4(v0, neon_qmvq, t);
        barrett_x4(v1, neon_qmvq, t);
        barrett_x4(v2, neon_qmvq, t2);
        barrett_x4(v3, neon_qmvq, t2);

        transpose(v0, t);
        transpose(v1, t);
        transpose(v2, t2);
        transpose(v3, t2);

        vload_s16_x2(zlh, ptr_invntt_br);
        vload_s16_x2(zhh, ptr_invntt_qinv_br);
        ptr_invntt_br += 16;
        ptr_invntt_qinv_br += 16;

        gsbf_top(v0.val[0], v0.val[1], t.val[0]);
        gsbf_top(v1.val[0], v1.val[1], t.val[1]);
        gsbf_top(v2.val[0], v2.val[1], t.val[2]);
        gsbf_top(v3.val[0], v3.val[1], t.val[3]);

        gsbf_top(v0.val[2], v0.val[3], t2.val[0]);
        gsbf_top(v1.val[2], v1.val[3], t2.val[1]);
        gsbf_top(v2.val[2], v2.val[3], t2.val[2]);
        gsbf_top(v3.val[2], v3.val[3], t2.val[3]);

        gsbf_br_bot(v0.val[1], zlh.val[0], zhh.val[0], neon_qmvq, t.val[0]);
        gsbf_br_bot(v1.val[1], zlh.val[1], zhh.val[1], neon_qmvq, t.val[1]);

        vload_s16_x2(zlh, ptr_invntt_br);
        vload_s16_x2(zhh, ptr_invntt_qinv_br);
        ptr_invntt_br += 16;
        ptr_invntt_qinv_br += 16;

        gsbf_br_bot(v2.val[1], zlh.val[0], zhh.val[0], neon_qmvq, t.val[2]);
        gsbf_br_bot(v3.val[1], zlh.val[1], zhh.val[1], neon_qmvq, t.val[3]);

        vload_s16_x4(zl, ptr_invntt_br);
        vload_s16_x4(zh, ptr_invntt_qinv_br);
        ptr_invntt_br += 32;
        ptr_invntt_qinv_br += 32;

        gsbf_br_bot(v0.val[3], zl.val[0], zh.val[0], neon_qmvq, t2.val[0]);
        gsbf_br_bot(v1.val[3], zl.val[1], zh.val[1], neon_qmvq, t2.val[1]);
        gsbf_br_bot(v2.val[3], zl.val[2], zh.val[2], neon_qmvq, t2.val[2]);
        gsbf_br_bot(v3.val[3], zl.val[3], zh.val[3], neon_qmvq, t2.val[3]);

        arrange(t, v0, 0, 1, 2, 3, 0, 2, 1, 3);
        v0 = t;

        arrange(t, v1, 0, 1, 2, 3, 0, 2, 1, 3);
        v1 = t;

        arrange(t2, v2, 0, 1, 2, 3, 0, 2, 1, 3);
        v2 = t2;

        arrange(t2, v3, 0, 1, 2, 3, 0, 2, 1, 3);
        v3 = t2;

        vload_s16_x2(zlh, ptr_invntt_br);
        vload_s16_x2(zhh, ptr_invntt_qinv_br);
        ptr_invntt_br += 16;
        ptr_invntt_qinv_br += 16;

        gsbf_top(v0.val[0], v0.val[1], t.val[0]);
        gsbf_top(v0.val[2], v0.val[3], t.val[1]);
        gsbf_top(v1.val[0], v1.val[1], t.val[2]);
        gsbf_top(v1.val[2], v1.val[3], t.val[3]);

        gsbf_top(v2.val[0], v2.val[1], t2.val[0]);
        gsbf_top(v2.val[2], v2.val[3], t2.val[1]);
        gsbf_top(v3.val[0], v3.val[1], t2.val[2]);
        gsbf_top(v3.val[2], v3.val[3], t2.val[3]);

        gsbf_bri_bot(v0.val[1], zlh.val[0], zhh.val[0], 0, neon_qmvq, t.val[0]);
        gsbf_bri_bot(v0.val[3], zlh.val[0], zhh.val[0], 1, neon_qmvq, t.val[1]);
        gsbf_bri_bot(v1.val[1], zlh.val[0], zhh.val[0], 2, neon_qmvq, t.val[2]);
        gsbf_bri_bot(v1.val[3], zlh.val[0], zhh.val[0], 3, neon_qmvq, t.val[3]);

        gsbf_bri_bot(v2.val[1], zlh.val[0], zhh.val[0], 4, neon_qmvq, t2.val[0]);
        gsbf_bri_bot(v2.val[3], zlh.val[0], zhh.val[0], 5, neon_qmvq, t2.val[1]);
        gsbf_bri_bot(v3.val[1], zlh.val[0], zhh.val[0], 6, neon_qmvq, t2.val[2]);
        gsbf_bri_bot(v3.val[3], zlh.val[0], zhh.val[0], 7, neon_qmvq, t2.val[3]);

        barrett(v0.val[0], neon_qmvq, t.val[0]);
        barrett(v1.val[0], neon_qmvq, t.val[1]);
        barrett(v2.val[0], neon_qmvq, t.val[2]);
        barrett(v3.val[0], neon_qmvq, t.val[3]);

        gsbf_top(v0.val[0], v0.val[2], t.val[0]);
        gsbf_top(v0.val[1], v0.val[3], t.val[1]);
        gsbf_top(v1.val[0], v1.val[2], t.val[2]);
        gsbf_top(v1.val[1], v1.val[3], t.val[3]);

        gsbf_top(v2.val[0], v2.val[2], t2.val[0]);
        gsbf_top(v2.val[1], v2.val[3], t2.val[1]);
        gsbf_top(v3.val[0], v3.val[2], t2.val[2]);
        gsbf_top(v3.val[1], v3.val[3], t2.val[3]);

        gsbf_bri_bot(v0.val[2], zlh.val[1], zhh.val[1], 0, neon_qmvq, t.val[0]);
        gsbf_bri_bot(v0.val[3], zlh.val[1], zhh.val[1], 0, neon_qmvq, t.val[1]);
        gsbf_bri_bot(v1.val[2], zlh.val[1], zhh.val[1], 1, neon_qmvq, t.val[2]);
        gsbf_bri_bot(v1.val[3], zlh.val[1], zhh.val[1], 1, neon_qmvq, t.val[3]);

        gsbf_bri_bot(v2.val[2], zlh.val[1], zhh.val[1], 2, neon_qmvq, t2.val[0]);
        gsbf_bri_bot(v2.val[3], zlh.val[1], zhh.val[1], 2, neon_qmvq, t2.val[1]);
        gsbf_bri_bot(v3.val[2], zlh.val[1], zhh.val[1], 3, neon_qmvq, t2.val[2]);
        gsbf_bri_bot(v3.val[3], zlh.val[1], zhh.val[1], 3, neon_qmvq, t2.val[3]);

        barrett_x4(v0, neon_qmvq, t);
        barrett_x4(v1, neon_qmvq, t);
        barrett_x4(v2, neon_qmvq, t2);
        barrett_x4(v3, neon_qmvq, t2);

        gsbf_top_x4(v0, v1, t);
        gsbf_top_x4(v2, v3, t2);

        gsbf_bri_bot_x4(v1, zlh.val[1], zhh.val[1], 4, 4, 4, 4, neon_qmvq, t);
        gsbf_bri_bot_x4(v3, zlh.val[1], zhh.val[1], 5, 5, 5, 5, neon_qmvq, t2);

        gsbf_top_x4(v0, v2, t);
        gsbf_top_x4(v1, v3, t2);

        gsbf_bri_bot_x4(v2, zlh.val[1], zhh.val[1], 6, 6, 6, 6, neon_qmvq, t);
        gsbf_bri_bot_x4(v3, zlh.val[1], zhh.val[1], 6, 6, 6, 6, neon_qmvq, t2);

        vstore_s16_x4(&a[j], v0);
        vstore_s16_x4(&a[j + 32], v1);
        vstore_s16_x4(&a[j + 64], v2);
        vstore_s16_x4(&a[j + 96], v3);
    }

    zl.val[0] = vld1q_s16(ptr_invntt_br);
    zh.val[0] = vld1q_s16(ptr_invntt_qinv_br);

    for (j = 0; j < 64; j += 32) {
        vload_s16_x4(v0, &a[j]);
        vload_s16_x4(v1, &a[j + 128]);
        vload_s16_x4(v2, &a[j + 256]);
        vload_s16_x4(v3, &a[j + 384]);

        barrett_x4(v0, neon_qmvq, t);
        barrett_x4(v1, neon_qmvq, t);
        barrett_x4(v2, neon_qmvq, t2);
        barrett_x4(v3, neon_qmvq, t2);

        gsbf_top_x4(v0, v1, t);
        gsbf_top_x4(v2, v3, t2);

        gsbf_bri_bot_x4(v1, zl.val[0], zh.val[0], 0, 0, 0, 0, neon_qmvq, t);
        gsbf_bri_bot_x4(v3, zl.val[0], zh.val[0], 1, 1, 1, 1, neon_qmvq, t2);

        gsbf_top_x4(v0, v2, t);
        gsbf_top_x4(v1, v3, t2);

        if (ninv == INVNTT_NINV) {
            gsbf_bri_bot_x4(v2, zl.val[0], zh.val[0], 2, 2, 2, 2, neon_qmvq, t);
            gsbf_bri_bot_x4(v3, zl.val[0], zh.val[0], 2, 2, 2, 2, neon_qmvq, t2);
            barmul_invntt_x4(v0, zl.val[0], zh.val[0], 3, neon_qmvq, t);
            barmul_invntt_x4(v1, zl.val[0], zh.val[0], 3, neon_qmvq, t2);
        } else {
            gsbf_bri_bot_x4(v2, zl.val[0], zh.val[0], 4, 4, 4, 4, neon_qmvq, t);
            gsbf_bri_bot_x4(v3, zl.val[0], zh.val[0], 4, 4, 4, 4, neon_qmvq, t2);
        }

        barrett_x4(v0, neon_qmvq, t);
        barrett_x4(v1, neon_qmvq, t);

        vstore_s16_x4(&a[j], v0);
        vstore_s16_x4(&a[j + 128], v1);
        vstore_s16_x4(&a[j + 256], v2);
        vstore_s16_x4(&a[j + 384], v3);
    }
    for (; j < 128; j += 32) {
        vload_s16_x4(v0, &a[j]);
        vload_s16_x4(v1, &a[j + 128]);
        vload_s16_x4(v2, &a[j + 256]);
        vload_s16_x4(v3, &a[j + 384]);

        gsbf_top_x4(v0, v1, t);
        gsbf_top_x4(v2, v3, t2);

        gsbf_bri_bot_x4(v1, zl.val[0], zh.val[0], 0, 0, 0, 0, neon_qmvq, t);
        gsbf_bri_bot_x4(v3, zl.val[0], zh.val[0], 1, 1, 1, 1, neon_qmvq, t2);

        barrett_x4(v0, neon_qmvq, t);
        barrett_x4(v1, neon_qmvq, t);
        barrett_x4(v2, neon_qmvq, t2);
        barrett_x4(v3, neon_qmvq, t2);

        gsbf_top_x4(v0, v2, t);
        gsbf_top_x4(v1, v3, t2);

        if (ninv == INVNTT_NINV) {
            gsbf_bri_bot_x4(v2, zl.val[0], zh.val[0], 2, 2, 2, 2, neon_qmvq, t);
            gsbf_bri_bot_x4(v3, zl.val[0], zh.val[0], 2, 2, 2, 2, neon_qmvq, t2);
            barmul_invntt_x4(v0, zl.val[0], zh.val[0], 3, neon_qmvq, t);
            barmul_invntt_x4(v1, zl.val[0], zh.val[0], 3, neon_qmvq, t2);
        } else {
            gsbf_bri_bot_x4(v2, zl.val[0], zh.val[0], 4, 4, 4, 4, neon_qmvq, t);
            gsbf_bri_bot_x4(v3, zl.val[0], zh.val[0], 4, 4, 4, 4, neon_qmvq, t2);
        }

        vstore_s16_x4(&a[j], v0);
        vstore_s16_x4(&a[j + 128], v1);
        vstore_s16_x4(&a[j + 256], v2);
        vstore_s16_x4(&a[j + 384], v3);
    }
}

void PQCLEAN_FALCONPADDED512_AARCH64_poly_montmul_ntt(int16_t f[FALCON_N], const int16_t g[FALCON_N]) {

    int16x8x4_t a, b, c, d, e1, e2, t, k; 
    int16x8_t neon_qmvm;                  
    neon_qmvm = vld1q_s16(PQCLEAN_FALCONPADDED512_AARCH64_qmvq);

    for (int i = 0; i < FALCON_N; i += 64) {
        vload_s16_x4(a, &f[i]);
        vload_s16_x4(b, &g[i]);
        vload_s16_x4(c, &f[i + 32]);
        vload_s16_x4(d, &g[i + 32]);

        montmul_x8(e1, e2, a, b, c, d, neon_qmvm, t, k);

        vstore_s16_x4(&f[i], e1);
        vstore_s16_x4(&f[i + 32], e2);
    }
}