// WASM-compatible randombytes implementation
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Simple PRNG for demonstration - in production use proper entropy
static uint64_t prng_state = 1;

void randombytes(uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        // Simple LCG: X_{n+1} = (a * X_n + c) mod m
        prng_state = prng_state * 1664525ULL + 1013904223ULL;
        out[i] = (uint8_t)(prng_state & 0xFF);
    }
}
