#ifndef PQCLEAN_MLDSA65_AVX2_CDECL_H
#define PQCLEAN_MLDSA65_AVX2_CDECL_H

#define _8XQ          0
#define _8XQINV       8
#define _8XDIV_QINV  16
#define _8XDIV       24
#define _ZETAS_QINV  32
#define _ZETAS      328

#define _cdecl(s) _##s
#define cdecl(s) s

#endif