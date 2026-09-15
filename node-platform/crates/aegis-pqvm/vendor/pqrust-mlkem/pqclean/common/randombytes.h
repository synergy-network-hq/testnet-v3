#ifndef PQCLEAN_RANDOMBYTES_H
#define PQCLEAN_RANDOMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifdef _WIN32

#include <crtdefs.h>
#else
#include <unistd.h>
#endif 

#define randombytes     PQCLEAN_randombytes
int randombytes(uint8_t *output, size_t n);

#ifdef __cplusplus
}
#endif

#endif 