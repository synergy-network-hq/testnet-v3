#ifndef  PQCLEAN_COMMON_COMPAT_H
#define PQCLEAN_COMMON_COMPAT_H

#define UNALIGNED_VECTOR_POLYFILL_GCC \
    typedef float __m256_u __attribute__ ((__vector_size__ (32), __may_alias__, __aligned__ (1))); \
    typedef double __m256d_u __attribute__ ((__vector_size__ (32), __may_alias__, __aligned__ (1))); \
    typedef long long __m256i_u __attribute__ ((__vector_size__ (32), __may_alias__, __aligned__ (1)));

#if defined(__GNUC__) && !defined(__clang__)

#if defined __GNUC_MINOR__ && ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((7) << 16) + (1))
#else

UNALIGNED_VECTOR_POLYFILL_GCC
#endif

#elif defined(__GNUC__) && defined(__clang__)

#  if __clang__major__ < 9

UNALIGNED_VECTOR_POLYFILL_GCC
#  endif

#elif defined(_MSC_VER)

#define __m256_u    __m256
#define __m256d_u   __m256d
#define __m256i_u   __m256i

#else
#error UNSUPPORTED COMPILER!?!?
#endif 

#ifdef _MSC_VER

# include <malloc.h>

# define PQCLEAN_VLA(__t,__x,__s) __t *__x = (__t*)_alloca((__s)*sizeof(__t))
#else
# define PQCLEAN_VLA(__t,__x,__s) __t __x[__s]
#endif

#if defined(__GNUC__) || defined(__clang__)

# define PQCLEAN_PREVENT_BRANCH_HACK(b)  __asm__("" : "+r"(b) : );
#else
# define PQCLEAN_PREVENT_BRANCH_HACK(b)
#endif

#endif 