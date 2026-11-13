
#include <arm_neon.h>

#define vload(c, addr) c = vld1q_f64(addr);

#define vload2(c, addr) c = vld2q_f64(addr);

#define vload4(c, addr) c = vld4q_f64(addr);

#define vstore(addr, c) vst1q_f64(addr, c);

#define vstore2(addr, c) vst2q_f64(addr, c);

#define vstore4(addr, c) vst4q_f64(addr, c);

#define vloadx2(c, addr) c = vld1q_f64_x2(addr);

#define vloadx3(c, addr) c = vld1q_f64_x3(addr);

#define vstorex2(addr, c) vst1q_f64_x2(addr, c);

#define vfsub(c, a, b) c = vsubq_f64(a, b);

#define vfadd(c, a, b) c = vaddq_f64(a, b);

#define vfmul(c, a, b) c = vmulq_f64(a, b);

#define vfmuln(c, a, n) c = vmulq_n_f64(a, n);

#define vswap(c, a) c = vextq_f64(a, a, 1);

#define vfmul_lane(c, a, b, i) c = vmulq_laneq_f64(a, b, i);

#define vfinv(c, a) c = vdivq_f64(vdupq_n_f64(1.0), a);

#define vfneg(c, a) c = vnegq_f64(a);

#define transpose_f64(a, b, t, ia, ib, it)        \
    t.val[it] = a.val[ia];                        \
    a.val[ia] = vzip1q_f64(a.val[ia], b.val[ib]); \
    b.val[ib] = vzip2q_f64(t.val[it], b.val[ib]);

#define vfcaddj(c, a, b) c = vcaddq_rot90_f64(a, b);

#define vfcsubj(c, a, b) c = vcaddq_rot270_f64(a, b);

#define vfcmla(c, a, b) c = vcmlaq_f64(c, a, b);

#define vfcmla_90(c, a, b) c = vcmlaq_rot90_f64(c, a, b);

#define vfcmla_180(c, a, b) c = vcmlaq_rot180_f64(c, a, b);

#define vfcmla_270(c, a, b) c = vcmlaq_rot270_f64(c, a, b);

#define FPC_CMUL(c, a, b)         \
    c = vmulq_laneq_f64(b, a, 0); \
    c = vcmlaq_rot90_f64(c, a, b);

#define FPC_CMUL_CONJ(c, a, b)    \
    c = vmulq_laneq_f64(a, b, 0); \
    c = vcmlaq_rot270_f64(c, b, a);

#define vfmla(d, c, a, b) d = vfmaq_f64(c, a, b);

#define vfmls(d, c, a, b) d = vfmsq_f64(c, a, b);

#define vfmla_lane(d, c, a, b, i) d = vfmaq_laneq_f64(c, a, b, i);

#define vfmls_lane(d, c, a, b, i) d = vfmsq_laneq_f64(c, a, b, i);