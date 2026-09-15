#include <stddef.h>
#include <stdint.h>
#include "kem.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"
#include "indcpa.h"

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure MLKEM key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    size_t i;
    indcpa_keypair(pk, sk);
    for (i = 0; i < MLKEM_INDCPA_PUBLICKEYBYTES; i++) {
        sk[i + MLKEM_INDCPA_SECRETKEYBYTES] = pk[i];
    }
    hash_h(sk + MLKEM_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES, pk, MLKEM_PUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject */
    randombytes(sk + MLKEM_SECRETKEYBYTES - MLKEM_SYMBYTES, MLKEM_SYMBYTES);
    return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct: pointer to output cipher text
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk) {
    uint8_t buf[2 * MLKEM_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * MLKEM_SYMBYTES];

    randombytes(buf, MLKEM_SYMBYTES);
    /* Don't release system RNG output */
    hash_h(buf, buf, MLKEM_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(buf + MLKEM_SYMBYTES, pk, MLKEM_PUBLICKEYBYTES);
    hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

    /* coins are in kr+MLKEM_SYMBYTES */
    indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr + MLKEM_SYMBYTES, ct, MLKEM_CIPHERTEXTBYTES);
    /* hash concatenation of pre-k and H(c) to k */
    kdf(ss, kr, 2 * MLKEM_SYMBYTES);
    return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const unsigned char *sk: pointer to input private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk) {
    size_t i;
    int fail;
    uint8_t buf[2 * MLKEM_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * MLKEM_SYMBYTES];
    uint8_t cmp[MLKEM_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + MLKEM_INDCPA_SECRETKEYBYTES;

    indcpa_dec(buf, ct, sk);

    /* Multitarget countermeasure for coins + contributory KEM */
    for (i = 0; i < MLKEM_SYMBYTES; i++) {
        buf[MLKEM_SYMBYTES + i] = sk[MLKEM_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES + i];
    }
    hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

    /* coins are in kr+MLKEM_SYMBYTES */
    indcpa_enc(cmp, buf, pk, kr + MLKEM_SYMBYTES);

    fail = verify(ct, cmp, MLKEM_CIPHERTEXTBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr + MLKEM_SYMBYTES, ct, MLKEM_CIPHERTEXTBYTES);

    /* Overwrite pre-k with z on re-encryption failure */
    cmov(kr, sk + MLKEM_SECRETKEYBYTES - MLKEM_SYMBYTES, MLKEM_SYMBYTES, fail);

    /* hash concatenation of pre-k and H(c) to k */
    kdf(ss, kr, 2 * MLKEM_SYMBYTES);
    return 0;
}
