#include "indcpa.h"
#include "kem.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk,
        uint8_t *sk,
        const uint8_t *coins) {
    PQCLEAN_MLKEM768_CLEAN_indcpa_keypair_derand(pk, sk, coins);
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);

    memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
    return 0;
}

int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk,
        uint8_t *sk) {
    uint8_t coins[2 * KYBER_SYMBYTES];
    randombytes(coins, 2 * KYBER_SYMBYTES);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, coins);
    return 0;
}

int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct,
        uint8_t *ss,
        const uint8_t *pk,
        const uint8_t *coins) {
    uint8_t buf[2 * KYBER_SYMBYTES];

    uint8_t kr[2 * KYBER_SYMBYTES];

    memcpy(buf, coins, KYBER_SYMBYTES);

    hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    PQCLEAN_MLKEM768_CLEAN_indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

    memcpy(ss, kr, KYBER_SYMBYTES);
    return 0;
}

int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct,
        uint8_t *ss,
        const uint8_t *pk) {
    uint8_t coins[KYBER_SYMBYTES];
    randombytes(coins, KYBER_SYMBYTES);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss, pk, coins);
    return 0;
}

int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss,
        const uint8_t *ct,
        const uint8_t *sk) {
    int fail;
    uint8_t buf[2 * KYBER_SYMBYTES];

    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES + KYBER_SYMBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

    PQCLEAN_MLKEM768_CLEAN_indcpa_dec(buf, ct, sk);

    memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    PQCLEAN_MLKEM768_CLEAN_indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

    fail = PQCLEAN_MLKEM768_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct);

    PQCLEAN_MLKEM768_CLEAN_cmov(ss, kr, KYBER_SYMBYTES, (uint8_t) (1 - fail));

    return 0;
}