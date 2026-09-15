
#if defined(__linux__)
#define _GNU_SOURCE
#endif 

#include "randombytes.h"

#if defined(_WIN32)

#include <windows.h>
#include <wincrypt.h> 
#endif 

#if defined(__linux__)

#define RNDGETENTCNT 0x80045200

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(SSIZE_MAX)
#define SSIZE_MAX (SIZE_MAX / 2 - 1)
#endif 

#endif 

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))

#include <sys/param.h>
#if defined(BSD)
#include <stdlib.h>
#endif
#endif

#if defined(__EMSCRIPTEN__)
#include <assert.h>
#include <emscripten.h>
#include <errno.h>
#include <stdbool.h>
#endif 

#if defined(_WIN32)
static int randombytes_win32_randombytes(void *buf, const size_t n) {
    HCRYPTPROV ctx;
    BOOL tmp;

    tmp = CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT);
    if (tmp == FALSE) {
        return -1;
    }

    tmp = CryptGenRandom(ctx, (DWORD)n, (BYTE *)buf);
    if (tmp == FALSE) {
        return -1;
    }

    tmp = CryptReleaseContext(ctx, 0);
    if (tmp == FALSE) {
        return -1;
    }

    return 0;
}
#endif 

#if defined(__linux__) && defined(SYS_getrandom)
static int randombytes_linux_randombytes_getrandom(void *buf, size_t n) {

    size_t offset = 0, chunk;
    long int ret;
    while (n > 0) {

        chunk = n <= 33554431 ? n : 33554431;
        do {
            ret = syscall(SYS_getrandom, (char *)buf + offset, chunk, 0);
        } while (ret == -1 && errno == EINTR);
        if (ret < 0) {
            return (int) ret;
        }
        offset += (size_t) ret;
        n -= (size_t) ret;
    }
    assert(n == 0);
    return 0;
}
#endif 

#if defined(__linux__) && !defined(SYS_getrandom)
static int randombytes_linux_read_entropy_ioctl(int device, int *entropy) {
    return ioctl(device, RNDGETENTCNT, entropy);
}

static int randombytes_linux_read_entropy_proc(FILE *stream, int *entropy) {
    int retcode;
    do {
        rewind(stream);
        retcode = fscanf(stream, "%d", entropy);
    } while (retcode != 1 && errno == EINTR);
    if (retcode != 1) {
        return -1;
    }
    return 0;
}

static int randombytes_linux_wait_for_entropy(int device) {

    enum { IOCTL,
           PROC
         } strategy = IOCTL;
    const int bits = 128;
    struct pollfd pfd;
    int fd;
    FILE *proc_file;
    int retcode,
        retcode_error = 0; 
    int entropy = 0;

    retcode = randombytes_linux_read_entropy_ioctl(device, &entropy);
    if (retcode != 0 && errno == ENOTTY) {

        strategy = PROC;

        proc_file = fopen("/proc/sys/kernel/random/entropy_avail", "r");
    } else if (retcode != 0) {

        return -1;
    }
    if (entropy >= bits) {
        return 0;
    }

    do {
        fd = open("/dev/random", O_RDONLY);
    } while (fd == -1 && errno == EINTR); 
    if (fd == -1) {

        return -1;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    for (;;) {
        retcode = poll(&pfd, 1, -1);
        if (retcode == -1 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        } else if (retcode == 1) {
            if (strategy == IOCTL) {
                retcode =
                    randombytes_linux_read_entropy_ioctl(device, &entropy);
            } else if (strategy == PROC) {
                retcode =
                    randombytes_linux_read_entropy_proc(proc_file, &entropy);
            } else {
                return -1; 
            }

            if (retcode != 0) {

                retcode_error = retcode;
                break;
            }
            if (entropy >= bits) {
                break;
            }
        } else {

            retcode_error = -1;
            break;
        }
    }
    do {
        retcode = close(fd);
    } while (retcode == -1 && errno == EINTR);
    if (strategy == PROC) {
        do {
            retcode = fclose(proc_file);
        } while (retcode == -1 && errno == EINTR);
    }
    if (retcode_error != 0) {
        return retcode_error;
    }
    return retcode;
}

static int randombytes_linux_randombytes_urandom(void *buf, size_t n) {
    int fd;
    size_t offset = 0, count;
    ssize_t tmp;
    do {
        fd = open("/dev/urandom", O_RDONLY);
    } while (fd == -1 && errno == EINTR);
    if (fd == -1) {
        return -1;
    }
    if (randombytes_linux_wait_for_entropy(fd) == -1) {
        return -1;
    }

    while (n > 0) {
        count = n <= SSIZE_MAX ? n : SSIZE_MAX;
        tmp = read(fd, (char *)buf + offset, count);
        if (tmp == -1 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }
        if (tmp == -1) {
            return -1; 
        }
        offset += tmp;
        n -= tmp;
    }
    assert(n == 0);
    return 0;
}
#endif 

#if defined(BSD)
static int randombytes_bsd_randombytes(void *buf, size_t n) {
    arc4random_buf(buf, n);
    return 0;
}
#endif 

#if defined(__EMSCRIPTEN__)
static int randombytes_js_randombytes_nodejs(void *buf, size_t n) {
    const int ret = EM_ASM_INT({
        var crypto;
        try {
            crypto = require('crypto');
        } catch (error) {
            return -2;
        }
        try {
            writeArrayToMemory(crypto.randomBytes($1), $0);
            return 0;
        } catch (error) {
            return -1;
        }
    },
    buf, n);
    switch (ret) {
    case 0:
        return 0;
    case -1:
        errno = EINVAL;
        return -1;
    case -2:
        errno = ENOSYS;
        return -1;
    }
    assert(false); 
}
#endif 

int randombytes(uint8_t *buf, size_t n) {
    #if defined(__EMSCRIPTEN__)
    return randombytes_js_randombytes_nodejs(buf, n);
    #elif defined(__linux__)
    #if defined(SYS_getrandom)

    return randombytes_linux_randombytes_getrandom(buf, n);
    #else

    return randombytes_linux_randombytes_urandom(buf, n);
    #endif
    #elif defined(BSD)

    return randombytes_bsd_randombytes(buf, n);
    #elif defined(_WIN32)

    return randombytes_win32_randombytes(buf, n);
    #else
#error "randombytes(...) is not supported on this platform"
    #endif
}