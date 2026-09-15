
#include "compat.h"
#include "controlbits.h"
#include "crypto_declassify.h"
#include "int32_sort.h"
#include <string.h>
typedef int16_t int16;
typedef int32_t int32;
#include "crypto_int32.h"
#define int32_min crypto_int32_min
#include "crypto_int16.h"

static void cbrecursion(unsigned char *out, long long pos, long long step, const int16 *pi, long long w, long long n, int32 *temp) {
#define A temp
#define B (temp+n)
#define q ((int16 *) (temp+n+n/4))

    long long x, y, i, j, k;

    if (w == 1) {
        out[pos >> 3] ^= pi[0] << (pos & 7);
        return;
    }

    for (x = 0; x < n; ++x) {
        A[x] = ((pi[x] ^ 1) << 16) | pi[x ^ 1];
    }
    int32_sort(A, n); 

    for (x = 0; x < n; ++x) {
        int32 Ax = A[x];
        int32 px = Ax & 0xffff;
        int32 cx = int32_min(px, (int32)x);
        B[x] = ((px) << 16) | cx;
    }

    for (x = 0; x < n; ++x) {
        A[x] = (int32)((((uint32_t)A[x]) << 16) | x);    
    }
    int32_sort(A, n); 

    for (x = 0; x < n; ++x) {
        A[x] = (((uint32_t)A[x]) << 16) + (B[x] >> 16);    
    }
    int32_sort(A, n); 

    if (w <= 10) {
        for (x = 0; x < n; ++x) {
            B[x] = ((A[x] & 0xffff) << 10) | (B[x] & 0x3ff);
        }

        for (i = 1; i < w - 1; ++i) {

            for (x = 0; x < n; ++x) {
                A[x] = (int32)(((B[x] & ~0x3ff) << 6) | x);    
            }
            int32_sort(A, n); 

            for (x = 0; x < n; ++x) {
                A[x] = ((uint32_t)A[x] << 20) | B[x];
            } 
            int32_sort(A, n); 

            for (x = 0; x < n; ++x) {
                int32 ppcpx = A[x] & 0xfffff;
                int32 ppcx = (A[x] & 0xffc00) | (B[x] & 0x3ff);
                B[x] = int32_min(ppcx, ppcpx);
            }
        }
        for (x = 0; x < n; ++x) {
            B[x] &= 0x3ff;
        }
    } else {
        for (x = 0; x < n; ++x) {
            B[x] = (((uint32_t)A[x]) << 16) | (B[x] & 0xffff);
        }

        for (i = 1; i < w - 1; ++i) {

            for (x = 0; x < n; ++x) {
                A[x] = (int32)((B[x] & ~0xffff) | x);
            }
            int32_sort(A, n); 

            for (x = 0; x < n; ++x) {
                A[x] = (((uint32_t)A[x]) << 16) | (B[x] & 0xffff);
            }

            if (i < w - 2) {
                for (x = 0; x < n; ++x) {
                    B[x] = (A[x] & ~0xffff) | (B[x] >> 16);
                }

                int32_sort(B, n); 
                for (x = 0; x < n; ++x) {
                    B[x] = (((uint32_t)B[x]) << 16) | (A[x] & 0xffff);
                }

            }

            int32_sort(A, n);

            for (x = 0; x < n; ++x) {
                int32 cpx = (B[x] & ~0xffff) | (A[x] & 0xffff);
                B[x] = int32_min(B[x], cpx);
            }
        }
        for (x = 0; x < n; ++x) {
            B[x] &= 0xffff;
        }
    }

    for (x = 0; x < n; ++x) {
        A[x] = (int32)((((int32)pi[x]) << 16) + x);
    }
    int32_sort(A, n); 

    for (j = 0; j < n / 2; ++j) {
        x = 2 * j;
        int32 fj = B[x] & 1; 
        int32 Fx = (int32)(x + fj); 
        int32 Fx1 = Fx ^ 1; 

        out[pos >> 3] ^= fj << (pos & 7);
        pos += step;

        B[x] = ((uint32_t)A[x] << 16) | Fx;
        B[x + 1] = ((uint32_t)A[x + 1] << 16) | Fx1;
    }

    int32_sort(B, n); 

    pos += (2 * w - 3) * step * (n / 2);

    for (k = 0; k < n / 2; ++k) {
        y = 2 * k;
        int32 lk = B[y] & 1; 
        int32 Ly = (int32)(y + lk); 
        int32 Ly1 = Ly ^ 1; 

        out[pos >> 3] ^= lk << (pos & 7);
        pos += step;

        A[y] = (Ly << 16) | (B[y] & 0xffff);
        A[y + 1] = (Ly1 << 16) | (B[y + 1] & 0xffff);
    }

    int32_sort(A, n); 

    pos -= (2 * w - 2) * step * (n / 2);

    for (j = 0; j < n / 2; ++j) {
        q[j] = (A[2 * j] & 0xffff) >> 1;
        q[j + n / 2] = (A[2 * j + 1] & 0xffff) >> 1;
    }

    cbrecursion(out, pos, step * 2, q, w - 1, n / 2, temp);
    cbrecursion(out, pos + step, step * 2, q + n / 2, w - 1, n / 2, temp);
}

static void layer(int16_t *p, const unsigned char *cb, int s, int n) {
    int i, j;
    int stride = 1 << (uint8_t)(s & 0x1F);
    int index = 0;
    int16_t d, m;

    for (i = 0; i < n; i += stride * 2) {
        for (j = 0; j < stride; j++) {
            d = p[ i + j ] ^ p[ i + j + stride ];
            m = (cb[ index >> 3 ] >> (index & 7)) & 1;
            m = -m;
            d &= m;
            p[ i + j ] ^= d;
            p[ i + j + stride ] ^= d;
            index++;
        }
    }
}

void controlbitsfrompermutation(unsigned char *out, const int16 *pi, long long w, long long n) {
    PQCLEAN_VLA(int32, temp, (size_t)(2 * n));
    PQCLEAN_VLA(int16, pi_test, (size_t)n);
    int16 diff;
    int i;
    unsigned char *ptr;

    memset(temp, 0, (size_t)n * 2);
    memset(pi_test, 0, (size_t)n);

    while (1) {
        memset(out, 0, (size_t)((((2 * w - 1)*n / 2) + 7) / 8));
        cbrecursion(out, 0, 1, pi, w, n, temp);

        for (i = 0; i < n; i++) {
            pi_test[i] = (int16)i;
        }

        ptr = out;
        for (i = 0; i < w; i++) {
            layer(pi_test, ptr, i, (int32)n);
            ptr += n >> 4;
        }

        for (i = (int)(w - 2); i >= 0; i--) {
            layer(pi_test, ptr, i, (int32)n);
            ptr += n >> 4;
        }

        diff = 0;
        for (i = 0; i < n; i++) {
            diff |= pi[i] ^ pi_test[i];
        }

        diff = crypto_int16_nonzero_mask(diff);
        crypto_declassify(&diff, sizeof diff);
        if (diff == 0) {
            break;
        }
    }
}