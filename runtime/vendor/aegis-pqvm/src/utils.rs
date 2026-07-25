use alloc::vec::Vec;
use rand::{rngs::OsRng, RngCore};
use sha3::{Digest, Sha3_256};

/// Compare two slices in constant time.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Zeroize a mutable byte slice.
pub fn zeroize(buf: &mut [u8]) {
    for byte in buf {
        *byte = 0;
    }
}

/// Generate cryptographically secure random bytes.
pub fn secure_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Validate that the buffer matches the expected length.
pub fn ensure_key_length(buf: &[u8], expected: usize) -> Result<(), &'static str> {
    if buf.len() == expected {
        Ok(())
    } else {
        Err("unexpected key length")
    }
}

/// Produce a SHA3-256 digest for self-test assertions.
pub fn sha3_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

// ---------------------------------------------------------------------------
// C-ABI RNG shims (for NIST reference C code under vendor/pqnist)
// ---------------------------------------------------------------------------
//
// Some NIST reference implementations include `rng.h` and call `randombytes()`
// directly (instead of PQClean's macro indirection to PQCRYPTO_RUST_randombytes).
// We provide a single process-wide implementation here, backed by
// pqcrypto-internals/getrandom.
//
// IMPORTANT: This is a narrow compatibility layer. Higher-level Aegis license/
// platform RNG policies should live elsewhere.

#[no_mangle]
pub unsafe extern "C" fn randombytes(buf: *mut u8, len: libc::c_ulonglong) -> libc::c_int {
    // pqcrypto_internals::PQCRYPTO_RUST_randombytes uses `size_t`.
    pqcrypto_internals::PQCRYPTO_RUST_randombytes(buf, len as libc::size_t)
}

#[no_mangle]
pub unsafe extern "C" fn randombytes_init(
    _entropy_input: *mut u8,
    _personalization_string: *mut u8,
    _security_strength: libc::c_int,
) {
    // NIST KAT generators use this to seed a deterministic DRBG.
    // For production builds we use OS entropy via `getrandom`, so this is a no-op.
}
