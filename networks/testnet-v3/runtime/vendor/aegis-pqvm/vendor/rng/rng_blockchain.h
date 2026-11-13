//
// rng_blockchain.h
// Blockchain/VM-specific Random Number Generator
// Implements NIST RNG API for blockchain virtual machine environments
//

#ifndef RNG_BLOCKCHAIN_H
#define RNG_BLOCKCHAIN_H

#include <stddef.h>
#include <stdint.h>

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

// AES XOF structure for seed expansion
typedef struct {
    unsigned char   buffer[16];
    int             buffer_pos;
    unsigned long   length_remaining;
    unsigned char   key[32];
    unsigned char   ctr[16];
} AES_XOF_struct;

// AES256 CTR DRBG structure
typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
} AES256_CTR_DRBG_struct;

// External AES256_ECB function (to be implemented or linked)
void AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer);

// Seed expander functions
int seedexpander_init(AES_XOF_struct *ctx,
                      unsigned char *seed,
                      unsigned char *diversifier,
                      unsigned long maxlen);

int seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen);

// Random bytes functions
void randombytes_init(unsigned char *entropy_input,
                     unsigned char *personalization_string,
                     int security_strength);

int randombytes(unsigned char *x, unsigned long long xlen);

// DRBG update function
void AES256_CTR_DRBG_Update(unsigned char *provided_data,
                           unsigned char *Key,
                           unsigned char *V);

// Test mode: deterministic RNG for KAT tests
void rng_set_test_mode(int enable);
void rng_set_test_seed(const unsigned char *seed, size_t seed_len);

#endif /* RNG_BLOCKCHAIN_H */
