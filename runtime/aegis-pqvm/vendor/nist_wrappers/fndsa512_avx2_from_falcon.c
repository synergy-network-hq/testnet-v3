#include <stddef.h>
#include <stdint.h>

int PQCLEAN_FALCON512_AVX2_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_FALCON512_AVX2_crypto_sign(
    uint8_t *sm,
    size_t *smlen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk);
int PQCLEAN_FALCON512_AVX2_crypto_sign_open(
    uint8_t *m,
    size_t *mlen,
    const uint8_t *sm,
    size_t smlen,
    const uint8_t *pk);
int PQCLEAN_FALCON512_AVX2_crypto_sign_signature(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk);
int PQCLEAN_FALCON512_AVX2_crypto_sign_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk);

int PQCLEAN_FNDSA512_AVX2_crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCON512_AVX2_crypto_sign_keypair(pk, sk);
}

int PQCLEAN_FNDSA512_AVX2_crypto_sign(
    uint8_t *sm,
    size_t *smlen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk) {
    return PQCLEAN_FALCON512_AVX2_crypto_sign(sm, smlen, m, mlen, sk);
}

int PQCLEAN_FNDSA512_AVX2_crypto_sign_open(
    uint8_t *m,
    size_t *mlen,
    const uint8_t *sm,
    size_t smlen,
    const uint8_t *pk) {
    return PQCLEAN_FALCON512_AVX2_crypto_sign_open(m, mlen, sm, smlen, pk);
}

int PQCLEAN_FNDSA512_AVX2_crypto_sign_signature(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk) {
    return PQCLEAN_FALCON512_AVX2_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

int PQCLEAN_FNDSA512_AVX2_crypto_sign_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk) {
    return PQCLEAN_FALCON512_AVX2_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
