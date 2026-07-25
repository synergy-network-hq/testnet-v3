use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use tiny_keccak::{Hasher, Sha3};

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
        // SAFETY: `byte` comes from a valid mutable slice element.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Generate cryptographically secure random bytes.
pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>, getrandom::Error> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
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
    let mut hasher = Sha3::v256();
    hasher.update(data);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

// ---------------------------------------------------------------------------
// C-ABI RNG shims (for NIST reference C code under vendor/pqnist)
// ---------------------------------------------------------------------------
//
// Some NIST reference implementations include `rng.h` and call `randombytes()`
// directly (instead of PQClean's macro indirection to PQRUST_RUST_randombytes).
// We provide a single process-wide implementation here, backed by
// pqrust-internals/getrandom.

#[no_mangle]
/// Fill `buf` with `len` random bytes from the process RNG backend.
///
/// # Safety
///
/// `buf` must be valid for writes of at least `len` bytes. The pointer may be
/// null only when `len == 0`.
pub unsafe extern "C" fn randombytes(buf: *mut u8, len: libc::c_ulonglong) -> libc::c_int {
    // pqrust_internals::PQRUST_RUST_randombytes uses `size_t`.
    pqrust_internals::PQRUST_RUST_randombytes(buf, len as libc::size_t)
}

#[no_mangle]
/// Initialize RNG state for compatibility with NIST-style APIs.
///
/// # Safety
///
/// Callers must pass pointers that are valid for the corresponding expected
/// buffer sizes when non-null. This implementation does not dereference them
/// and behaves as a no-op.
pub unsafe extern "C" fn randombytes_init(
    _entropy_input: *mut u8,
    _personalization_string: *mut u8,
    _security_strength: libc::c_int,
) {
    // NIST KAT generators use this to seed a deterministic DRBG.
    // For production builds we use OS entropy via `getrandom`, so this is a no-op.
}
