
#include <arm_neon.h>
#include <stdint.h>
#include "params.h"
#include "cbd.h"

#define vload2(c, ptr) c = vld2q_u8(ptr);

#define vstore4(ptr, c) vst4q_s16(ptr, c);

#define vsr8(c, a, n) c = vshrq_n_u8(a, n);

#define vand8(c, a, b) c = vandq_u8(a, b);

#define vadd8(c, a, b) c = vaddq_u8(a, b);

#define vsubll8(c, a, b) c = (int16x8_t)vsubl_u8(a, b);

#define vsublh8(c, a, b) c = (int16x8_t)vsubl_high_u8(a, b);

static
void neon_cbd2(int16_t *r, const uint8_t buf[2 * KYBER_N / 4]) {
    uint8x16x2_t t, d;      
    uint8x16x2_t a, b;      
    int16x8x4_t res1, res2; 

    uint8x16_t const_0x55, const_0x3; 
    const_0x55 = vdupq_n_u8(0x55);
    const_0x3 = vdupq_n_u8(0x3);

    unsigned int j = 0;
    for (unsigned int i = 0; i < KYBER_N / 2; i += 16 * 2) {

        vload2(t, &buf[i]);

        vand8(d.val[0], t.val[0], const_0x55);
        vand8(d.val[1], t.val[1], const_0x55);

        vsr8(t.val[0], t.val[0], 1);
        vsr8(t.val[1], t.val[1], 1);
        vand8(t.val[0], t.val[0], const_0x55);
        vand8(t.val[1], t.val[1], const_0x55);

        vadd8(d.val[0], d.val[0], t.val[0]);
        vadd8(d.val[1], d.val[1], t.val[1]);

        vand8(a.val[0], d.val[0], const_0x3);
        vand8(a.val[1], d.val[1], const_0x3);

        vsr8(b.val[0], d.val[0], 2);
        vsr8(b.val[1], d.val[1], 2);

        vand8(b.val[0], b.val[0], const_0x3);
        vand8(b.val[1], b.val[1], const_0x3);

        vsubll8(res1.val[0], vget_low_u8(a.val[0]), vget_low_u8(b.val[0]));
        vsubll8(res1.val[2], vget_low_u8(a.val[1]), vget_low_u8(b.val[1]));

        vsublh8(res2.val[0], a.val[0], b.val[0]);
        vsublh8(res2.val[2], a.val[1], b.val[1]);

        vsr8(a.val[0], d.val[0], 4);
        vsr8(a.val[1], d.val[1], 4);

        vand8(a.val[0], a.val[0], const_0x3);
        vand8(a.val[1], a.val[1], const_0x3);

        vsr8(b.val[0], d.val[0], 6);
        vsr8(b.val[1], d.val[1], 6);

        vsubll8(res1.val[1], vget_low_u8(a.val[0]), vget_low_u8(b.val[0]));
        vsubll8(res1.val[3], vget_low_u8(a.val[1]), vget_low_u8(b.val[1]));

        vsublh8(res2.val[1], a.val[0], b.val[0]);
        vsublh8(res2.val[3], a.val[1], b.val[1]);

        vstore4(&r[j], res1);
        j += 32;
        vstore4(&r[j], res2);
        j += 32;
    }
}

void poly_cbd_eta1(int16_t *r, const uint8_t buf[KYBER_ETA1 * KYBER_N / 4]) {
    neon_cbd2(r, buf);
}

void poly_cbd_eta2(int16_t *r, const uint8_t buf[KYBER_ETA2 * KYBER_N / 4]) {
    neon_cbd2(r, buf);
}