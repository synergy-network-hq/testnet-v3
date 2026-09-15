
#include <math.h>

typedef struct {
    double v;
} fpr;

static inline fpr
FPR(double v) {
    fpr x;

    x.v = v;
    return x;
}

static inline fpr
fpr_of(int64_t i) {
    return FPR((double)i);
}

static const fpr fpr_q = { 12289.0 };
static const fpr fpr_inverse_of_q = { 1.0 / 12289.0 };
static const fpr fpr_inv_2sqrsigma0 = { .150865048875372721532312163019 };
static const fpr fpr_inv_sigma[] = {
    { 0.0 }, 
    { 0.0069054793295940891952143765991630516 },
    { 0.0068102267767177975961393730687908629 },
    { 0.0067188101910722710707826117910434131 },
    { 0.0065883354370073665545865037227681924 },
    { 0.0064651781207602900738053897763485516 },
    { 0.0063486788828078995327741182928037856 },
    { 0.0062382586529084374473367528433697537 },
    { 0.0061334065020930261548984001431770281 },
    { 0.0060336696681577241031668062510953022 },
    { 0.0059386453095331159950250124336477482 }
};
static const fpr fpr_sigma_min[] = {
    { 0.0 }, 
    { 1.1165085072329102588881898380334015 },
    { 1.1321247692325272405718031785357108 },
    { 1.1475285353733668684571123112513188 },
    { 1.1702540788534828939713084716509250 },
    { 1.1925466358390344011122170489094133 },
    { 1.2144300507766139921088487776957699 },
    { 1.2359260567719808790104525941706723 },
    { 1.2570545284063214162779743112075080 },
    { 1.2778336969128335860256340575729042 },
    { 1.2982803343442918539708792538826807 }
};
static const fpr fpr_log2 = { 0.69314718055994530941723212146 };
static const fpr fpr_inv_log2 = { 1.4426950408889634073599246810 };
static const fpr fpr_bnorm_max = { 16822.4121 };
static const fpr fpr_zero = { 0.0 };
static const fpr fpr_one = { 1.0 };
static const fpr fpr_two = { 2.0 };
static const fpr fpr_onehalf = { 0.5 };
static const fpr fpr_invsqrt2 = { 0.707106781186547524400844362105 };
static const fpr fpr_invsqrt8 = { 0.353553390593273762200422181052 };
static const fpr fpr_ptwo31 = { 2147483648.0 };
static const fpr fpr_ptwo31m1 = { 2147483647.0 };
static const fpr fpr_mtwo31m1 = { -2147483647.0 };
static const fpr fpr_ptwo63m1 = { 9223372036854775807.0 };
static const fpr fpr_mtwo63m1 = { -9223372036854775807.0 };
static const fpr fpr_ptwo63 = { 9223372036854775808.0 };

static inline int64_t
fpr_rint(fpr x) {

    int64_t sx, tx, rp, rn, m;
    uint32_t ub;

    sx = (int64_t)(x.v - 1.0);
    tx = (int64_t)x.v;
    rp = (int64_t)(x.v + 4503599627370496.0) - 4503599627370496;
    rn = (int64_t)(x.v - 4503599627370496.0) + 4503599627370496;

    m = sx >> 63;
    rn &= m;
    rp &= ~m;

    ub = (uint32_t)((uint64_t)tx >> 52);
    m = -(int64_t)((((ub + 1) & 0xFFF) - 2) >> 31);
    rp &= m;
    rn &= m;
    tx &= ~m;

    return tx | rn | rp;
}

static inline int64_t
fpr_floor(fpr x) {
    int64_t r;

    r = (int64_t)x.v;
    return r - (x.v < (double)r);
}

static inline int64_t
fpr_trunc(fpr x) {
    return (int64_t)x.v;
}

static inline fpr
fpr_add(fpr x, fpr y) {
    return FPR(x.v + y.v);
}

static inline fpr
fpr_sub(fpr x, fpr y) {
    return FPR(x.v - y.v);
}

static inline fpr
fpr_neg(fpr x) {
    return FPR(-x.v);
}

static inline fpr
fpr_half(fpr x) {
    return FPR(x.v * 0.5);
}

static inline fpr
fpr_double(fpr x) {
    return FPR(x.v + x.v);
}

static inline fpr
fpr_mul(fpr x, fpr y) {
    return FPR(x.v * y.v);
}

static inline fpr
fpr_sqr(fpr x) {
    return FPR(x.v * x.v);
}

static inline fpr
fpr_inv(fpr x) {
    return FPR(1.0 / x.v);
}

static inline fpr
fpr_div(fpr x, fpr y) {
    return FPR(x.v / y.v);
}

static inline void
fpr_sqrt_avx2(double *t) {
    __m128d x;

    x = _mm_load1_pd(t);
    x = _mm_sqrt_pd(x);
    _mm_storel_pd(t, x);
}

static inline fpr
fpr_sqrt(fpr x) {

    fpr_sqrt_avx2(&x.v);
    return x;
}

static inline int
fpr_lt(fpr x, fpr y) {
    return x.v < y.v;
}

static inline uint64_t
fpr_expm_p63(fpr x, fpr ccs) {

    static const union {
        double d[12];
        __m256d v[3];
    } c = {
        {
            0.999999999999994892974086724280,
            0.500000000000019206858326015208,
            0.166666666666984014666397229121,
            0.041666666666110491190622155955,
            0.008333333327800835146903501993,
            0.001388888894063186997887560103,
            0.000198412739277311890541063977,
            0.000024801566833585381209939524,
            0.000002755586350219122514855659,
            0.000000275607356160477811864927,
            0.000000025299506379442070029551,
            0.000000002073772366009083061987
        }
    };

    double d1, d2, d4, d8, y;
    __m256d d14, d58, d9c;

    d1 = -x.v;
    d2 = d1 * d1;
    d4 = d2 * d2;
    d8 = d4 * d4;
    d14 = _mm256_set_pd(d4, d2 * d1, d2, d1);
    d58 = _mm256_mul_pd(d14, _mm256_set1_pd(d4));
    d9c = _mm256_mul_pd(d14, _mm256_set1_pd(d8));
    d14 = _mm256_mul_pd(d14, _mm256_loadu_pd(&c.d[0]));
    d58 = FMADD(d58, _mm256_loadu_pd(&c.d[4]), d14);
    d9c = FMADD(d9c, _mm256_loadu_pd(&c.d[8]), d58);
    d9c = _mm256_hadd_pd(d9c, d9c);
    y = 1.0 + _mm_cvtsd_f64(_mm256_castpd256_pd128(d9c)) 
        + _mm_cvtsd_f64(_mm256_extractf128_pd(d9c, 1));
    y *= ccs.v;

    return (uint64_t)(int64_t)(y * fpr_ptwo63.v);

}

#define fpr_gm_tab   PQCLEAN_FALCON1024_AVX2_fpr_gm_tab
extern const fpr fpr_gm_tab[];

#define fpr_p2_tab   PQCLEAN_FALCON1024_AVX2_fpr_p2_tab
extern const fpr fpr_p2_tab[];