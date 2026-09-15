
typedef uint64_t fpr;

static inline uint64_t
fpr_ursh(uint64_t x, int n) {
    x ^= (x ^ (x >> 32)) & -(uint64_t)(n >> 5);
    return x >> (n & 31);
}

static inline int64_t
fpr_irsh(int64_t x, int n) {
    x ^= (x ^ (x >> 32)) & -(int64_t)(n >> 5);
    return x >> (n & 31);
}

static inline uint64_t
fpr_ulsh(uint64_t x, int n) {
    x ^= (x ^ (x << 32)) & -(uint64_t)(n >> 5);
    return x << (n & 31);
}

static inline fpr
FPR(int s, int e, uint64_t m) {
    fpr x;
    uint32_t t;
    unsigned f;

    e += 1076;
    t = (uint32_t)e >> 31;
    m &= (uint64_t)t - 1;

    t = (uint32_t)(m >> 54);
    e &= -(int)t;

    x = (((uint64_t)s << 63) | (m >> 2)) + ((uint64_t)(uint32_t)e << 52);

    f = (unsigned)m & 7U;
    x += (0xC8U >> f) & 1;
    return x;
}

#define fpr_scaled   PQCLEAN_FALCONPADDED512_CLEAN_fpr_scaled
fpr fpr_scaled(int64_t i, int sc);

static inline fpr
fpr_of(int64_t i) {
    return fpr_scaled(i, 0);
}

static const fpr fpr_q = 4667981563525332992;
static const fpr fpr_inverse_of_q = 4545632735260551042;
static const fpr fpr_inv_2sqrsigma0 = 4594603506513722306;
static const fpr fpr_inv_sigma[] = {
    0,  
    4574611497772390042,
    4574501679055810265,
    4574396282908341804,
    4574245855758572086,
    4574103865040221165,
    4573969550563515544,
    4573842244705920822,
    4573721358406441454,
    4573606369665796042,
    4573496814039276259
};
static const fpr fpr_sigma_min[] = {
    0,  
    4607707126469777035,
    4607777455861499430,
    4607846828256951418,
    4607949175006100261,
    4608049571757433526,
    4608148125896792003,
    4608244935301382692,
    4608340089478362016,
    4608433670533905013,
    4608525754002622308
};
static const fpr fpr_log2 = 4604418534313441775;
static const fpr fpr_inv_log2 = 4609176140021203710;
static const fpr fpr_bnorm_max = 4670353323383631276;
static const fpr fpr_zero = 0;
static const fpr fpr_one = 4607182418800017408;
static const fpr fpr_two = 4611686018427387904;
static const fpr fpr_onehalf = 4602678819172646912;
static const fpr fpr_invsqrt2 = 4604544271217802189;
static const fpr fpr_invsqrt8 = 4600040671590431693;
static const fpr fpr_ptwo31 = 4746794007248502784;
static const fpr fpr_ptwo31m1 = 4746794007244308480;
static const fpr fpr_mtwo31m1 = 13970166044099084288U;
static const fpr fpr_ptwo63m1 = 4890909195324358656;
static const fpr fpr_mtwo63m1 = 14114281232179134464U;
static const fpr fpr_ptwo63 = 4890909195324358656;

static inline int64_t
fpr_rint(fpr x) {
    uint64_t m, d;
    int e;
    uint32_t s, dd, f;

    m = ((x << 10) | ((uint64_t)1 << 62)) & (((uint64_t)1 << 63) - 1);
    e = 1085 - ((int)(x >> 52) & 0x7FF);

    m &= -(uint64_t)((uint32_t)(e - 64) >> 31);
    e &= 63;

    d = fpr_ulsh(m, 63 - e);
    dd = (uint32_t)d | ((uint32_t)(d >> 32) & 0x1FFFFFFF);
    f = (uint32_t)(d >> 61) | ((dd | -dd) >> 31);
    m = fpr_ursh(m, e) + (uint64_t)((0xC8U >> f) & 1U);

    s = (uint32_t)(x >> 63);
    return ((int64_t)m ^ -(int64_t)s) + (int64_t)s;
}

static inline int64_t
fpr_floor(fpr x) {
    uint64_t t;
    int64_t xi;
    int e, cc;

    e = (int)(x >> 52) & 0x7FF;
    t = x >> 63;
    xi = (int64_t)(((x << 10) | ((uint64_t)1 << 62))
                   & (((uint64_t)1 << 63) - 1));
    xi = (xi ^ -(int64_t)t) + (int64_t)t;
    cc = 1085 - e;

    xi = fpr_irsh(xi, cc & 63);

    xi ^= (xi ^ -(int64_t)t) & -(int64_t)((uint32_t)(63 - cc) >> 31);
    return xi;
}

static inline int64_t
fpr_trunc(fpr x) {
    uint64_t t, xu;
    int e, cc;

    e = (int)(x >> 52) & 0x7FF;
    xu = ((x << 10) | ((uint64_t)1 << 62)) & (((uint64_t)1 << 63) - 1);
    cc = 1085 - e;
    xu = fpr_ursh(xu, cc & 63);

    xu &= -(uint64_t)((uint32_t)(cc - 64) >> 31);

    t = x >> 63;
    xu = (xu ^ -t) + t;
    return *(int64_t *)&xu;
}

#define fpr_add   PQCLEAN_FALCONPADDED512_CLEAN_fpr_add
fpr fpr_add(fpr x, fpr y);

static inline fpr
fpr_sub(fpr x, fpr y) {
    y ^= (uint64_t)1 << 63;
    return fpr_add(x, y);
}

static inline fpr
fpr_neg(fpr x) {
    x ^= (uint64_t)1 << 63;
    return x;
}

static inline fpr
fpr_half(fpr x) {

    uint32_t t;

    x -= (uint64_t)1 << 52;
    t = (((uint32_t)(x >> 52) & 0x7FF) + 1) >> 11;
    x &= (uint64_t)t - 1;
    return x;
}

static inline fpr
fpr_double(fpr x) {

    x += (uint64_t)((((unsigned)(x >> 52) & 0x7FFU) + 0x7FFU) >> 11) << 52;
    return x;
}

#define fpr_mul   PQCLEAN_FALCONPADDED512_CLEAN_fpr_mul
fpr fpr_mul(fpr x, fpr y);

static inline fpr
fpr_sqr(fpr x) {
    return fpr_mul(x, x);
}

#define fpr_div   PQCLEAN_FALCONPADDED512_CLEAN_fpr_div
fpr fpr_div(fpr x, fpr y);

static inline fpr
fpr_inv(fpr x) {
    return fpr_div(4607182418800017408u, x);
}

#define fpr_sqrt   PQCLEAN_FALCONPADDED512_CLEAN_fpr_sqrt
fpr fpr_sqrt(fpr x);

static inline int
fpr_lt(fpr x, fpr y) {

    int cc0, cc1;
    int64_t sx;
    int64_t sy;

    sx = *(int64_t *)&x;
    sy = *(int64_t *)&y;
    sy &= ~((sx ^ sy) >> 63); 

    cc0 = (int)((sx - sy) >> 63) & 1; 
    cc1 = (int)((sy - sx) >> 63) & 1; 

    return cc0 ^ ((cc0 ^ cc1) & (int)((x & y) >> 63));
}

#define fpr_expm_p63   PQCLEAN_FALCONPADDED512_CLEAN_fpr_expm_p63
uint64_t fpr_expm_p63(fpr x, fpr ccs);

#define fpr_gm_tab   PQCLEAN_FALCONPADDED512_CLEAN_fpr_gm_tab
extern const fpr fpr_gm_tab[];

#define fpr_p2_tab   PQCLEAN_FALCONPADDED512_CLEAN_fpr_p2_tab
extern const fpr fpr_p2_tab[];