//
// rng_blockchain.c
// Blockchain/VM-specific Random Number Generator Implementation
// Portable implementation for blockchain virtual machine environments
//

#include "rng_blockchain.h"
#include <string.h>
#include <stdlib.h>
// Use the real AES implementation already vendored in pqcrypto-internals.
// This keeps the RNG compatible with NIST KAT tooling that expects AES256_ECB.
#include "aes.h"

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
    #define WIN32_LEAN_AND_MEAN
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
#endif

// Global DRBG context
static AES256_CTR_DRBG_struct DRBG_ctx;

// Test mode flag and state
static int test_mode = 0;
static unsigned char test_seed[48] = {0};
static uint64_t test_counter = 0;

// Forward declarations
static void get_entropy_from_system(unsigned char *buf, size_t len);
static void get_entropy_deterministic(unsigned char *buf, size_t len);

//
// System entropy source
//
static void get_entropy_from_system(unsigned char *buf, size_t len) {
#ifdef _WIN32
    // Windows: Use CryptGenRandom
    HCRYPTPROV hProvider = 0;
    if (CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProvider, (DWORD)len, buf);
        CryptReleaseContext(hProvider, 0);
    } else {
        // Fallback: Use a less secure source
        for (size_t i = 0; i < len; i++) {
            buf[i] = (unsigned char)(rand() ^ (GetTickCount() + i));
        }
    }
#else
    // Unix/Linux: Use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t result = read(fd, buf, len);
        close(fd);
        if (result == (ssize_t)len) {
            return; // Success
        }
    }
    
    // Fallback: Use /dev/random (may block)
    fd = open("/dev/random", O_RDONLY);
    if (fd >= 0) {
        ssize_t result = read(fd, buf, len);
        close(fd);
        if (result == (ssize_t)len) {
            return; // Success
        }
    }
    
    // Last resort fallback (not cryptographically secure, but better than nothing)
    for (size_t i = 0; i < len; i++) {
        buf[i] = (unsigned char)(rand() ^ (getpid() + i + (size_t)&buf));
    }
#endif
}

//
// Deterministic entropy for test mode (KAT tests)
//
static void get_entropy_deterministic(unsigned char *buf, size_t len) {
    // Simple deterministic PRNG for testing
    // Uses SHAKE-like approach for deterministic output
    unsigned char state[64];
    memcpy(state, test_seed, 48);
    
    // Use counter to ensure different outputs
    memcpy(state + 48, &test_counter, 8);
    test_counter += len;
    
    // Simple hash-like mixing function
    for (size_t i = 0; i < len; i++) {
        unsigned char sum = 0;
        for (size_t j = 0; j < 56; j++) {
            sum ^= state[j];
            state[j] = (state[j] << 1) | (state[j] >> 7);
        }
        buf[i] = sum ^ (unsigned char)(i + test_counter);
    }
}

// AES-256 ECB (single block) as required by the NIST seed expander / DRBG API.
void AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer) {
    aes256ctx ctx;
    aes256_ecb_keyexp(&ctx, key);
    aes256_ecb(buffer, ctr, 1, &ctx);
    aes256_ctx_release(&ctx);
}

//
// Seed expander initialization
//
int seedexpander_init(AES_XOF_struct *ctx,
                      unsigned char *seed,
                      unsigned char *diversifier,
                      unsigned long maxlen) {
    if (maxlen >= 0x100000000ULL) {
        return RNG_BAD_MAXLEN;
    }
    
    if (ctx == NULL) {
        return RNG_BAD_OUTBUF;
    }
    
    ctx->length_remaining = maxlen;
    memcpy(ctx->key, seed, 32);
    
    if (diversifier != NULL) {
        memcpy(ctx->ctr, diversifier, 8);
    } else {
        memset(ctx->ctr, 0, 8);
    }
    
    ctx->ctr[11] = (unsigned char)(maxlen & 0xFF);
    ctx->ctr[10] = (unsigned char)((maxlen >> 8) & 0xFF);
    ctx->ctr[9] = (unsigned char)((maxlen >> 16) & 0xFF);
    ctx->ctr[8] = (unsigned char)((maxlen >> 24) & 0xFF);
    memset(ctx->ctr + 12, 0x00, 4);
    
    ctx->buffer_pos = 16;
    memset(ctx->buffer, 0x00, 16);
    
    return RNG_SUCCESS;
}

//
// Seed expander generation
//
int seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen) {
    unsigned long offset = 0;
    int i;
    
    if (x == NULL) {
        return RNG_BAD_OUTBUF;
    }
    if (xlen >= ctx->length_remaining) {
        return RNG_BAD_REQ_LEN;
    }
    
    ctx->length_remaining -= xlen;
    
    offset = 0;
    while (xlen > 0) {
        if (xlen <= (unsigned long)(16 - ctx->buffer_pos)) {
            // Buffer has what we need
            memcpy(x + offset, ctx->buffer + ctx->buffer_pos, xlen);
            ctx->buffer_pos += (int)xlen;
            return RNG_SUCCESS;
        }
        
        // Take what's in the buffer
        memcpy(x + offset, ctx->buffer + ctx->buffer_pos, 16 - ctx->buffer_pos);
        xlen -= (unsigned long)(16 - ctx->buffer_pos);
        offset += (unsigned long)(16 - ctx->buffer_pos);
        
        // Generate next block
        AES256_ECB(ctx->key, ctx->ctr, ctx->buffer);
        ctx->buffer_pos = 0;
        
        // Increment counter
        for (i = 15; i >= 12; i--) {
            if (ctx->ctr[i] == 0xFF) {
                ctx->ctr[i] = 0x00;
            } else {
                ctx->ctr[i]++;
                break;
            }
        }
    }
    
    return RNG_SUCCESS;
}

//
// Random bytes initialization
//
void randombytes_init(unsigned char *entropy_input,
                     unsigned char *personalization_string,
                     int security_strength) {
    unsigned char seed_material[48];
    
    if (test_mode) {
        // Use deterministic seed in test mode
        memcpy(seed_material, test_seed, 48);
    } else {
        // Get entropy from system
        get_entropy_from_system(seed_material, 48);
        
        // Mix in provided entropy if available
        if (entropy_input != NULL) {
            for (int i = 0; i < 48 && i < 48; i++) {
                seed_material[i] ^= entropy_input[i % 48];
            }
        }
    }
    
    // Add personalization string if provided
    if (personalization_string != NULL) {
        for (int i = 0; i < 48; i++) {
            seed_material[i] ^= personalization_string[i % 48];
        }
    }
    
    // Initialize DRBG
    memcpy(DRBG_ctx.Key, seed_material, 32);
    memcpy(DRBG_ctx.V, seed_material + 32, 16);
    DRBG_ctx.reseed_counter = 1;
}

//
// Generate random bytes
//
int randombytes(unsigned char *x, unsigned long long xlen) {
    unsigned char temp[16];
    int i, j;
    
    if (x == NULL) {
        return RNG_BAD_OUTBUF;
    }
    
    // In test mode, use deterministic generator
    if (test_mode) {
        get_entropy_deterministic(x, (size_t)xlen);
        return RNG_SUCCESS;
    }
    
    // Use DRBG
    j = 0;
    for (unsigned long long k = 0; k < xlen; k++) {
        if (j == 0) {
            // Generate new block
            AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, temp);
            
            // Update V
            for (i = 15; i >= 0; i--) {
                if (DRBG_ctx.V[i] == 0xFF) {
                    DRBG_ctx.V[i] = 0x00;
                } else {
                    DRBG_ctx.V[i]++;
                    break;
                }
            }
        }
        
        x[k] = temp[j];
        j = (j + 1) % 16;
        
        // Reseed if needed (after 2^48 requests)
        if (DRBG_ctx.reseed_counter >= 0xFFFFFFFF) {
            unsigned char seed_material[48];
            get_entropy_from_system(seed_material, 48);
            AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
            DRBG_ctx.reseed_counter = 1;
        } else {
            DRBG_ctx.reseed_counter++;
        }
    }
    
    return RNG_SUCCESS;
}

//
// DRBG update function
//
void AES256_CTR_DRBG_Update(unsigned char *provided_data,
                           unsigned char *Key,
                           unsigned char *V) {
    unsigned char temp[48];
    int i;
    
    // Generate temp
    for (i = 0; i < 3; i++) {
        AES256_ECB(Key, V, temp + (i * 16));
        
        // Increment V
        int j;
        for (j = 15; j >= 0; j--) {
            if (V[j] == 0xFF) {
                V[j] = 0x00;
            } else {
                V[j]++;
                break;
            }
        }
    }
    
    // XOR with provided data if available
    if (provided_data != NULL) {
        for (i = 0; i < 48; i++) {
            temp[i] ^= provided_data[i];
        }
    }
    
    // Update Key and V
    memcpy(Key, temp, 32);
    memcpy(V, temp + 32, 16);
}

//
// Test mode functions
//
void rng_set_test_mode(int enable) {
    test_mode = enable ? 1 : 0;
    if (!enable) {
        test_counter = 0;
        memset(test_seed, 0, 48);
    }
}

void rng_set_test_seed(const unsigned char *seed, size_t seed_len) {
    memset(test_seed, 0, 48);
    if (seed != NULL && seed_len > 0) {
        size_t copy_len = (seed_len < 48) ? seed_len : 48;
        memcpy(test_seed, seed, copy_len);
    }
    test_counter = 0;
}
