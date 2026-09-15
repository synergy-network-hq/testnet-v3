//! # HQC (hqc128) Shim
//!
//! Real implementation using the `pqcrypto-hqc` crate (via the `pqcrypto`
//! facade, same pattern as kyber.rs/mceliece.rs). Previously this module
//! returned fixed-size zeroed keys/ciphertext/shared-secret vectors -- fixed
//! to perform genuine key generation, encapsulation, and decapsulation.
//!
//! NOTE on sizes: the original stub's byte constants (secret key 2289,
//! ciphertext 4481, shared secret 32) did not match the real HQC-128
//! parameter set and have been corrected here to the real PQClean HQC-128
//! `api.h` values (secret key 2305, ciphertext 4433, shared secret 64).
//!
//! NOTE on decapsulation failure behavior: unlike Kyber/McEliece (which
//! implement full implicit rejection and always return -- just with a
//! non-matching shared secret -- on a mismatched key/ciphertext), this
//! version of `pqcrypto-hqc`'s FFI binding uses an internal `assert_eq!`
//! that PANICS if the underlying C decapsulate call reports a validation
//! failure. To avoid ever crashing the whole compiler/VM process on a
//! malformed or mismatched decapsulation attempt, `decaps` below catches
//! that panic and returns a zeroed shared secret instead, matching the
//! "malformed input returns a safe default, never panics" convention used
//! by the other pqc-shims modules (see dilithium.rs/falcon.rs/sphincs.rs).

use pqcrypto::kem::hqc128;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// hqc128 public key size in bytes
pub const HQC_PUBLIC_KEY_BYTES: usize = 2249;
/// hqc128 secret key size in bytes
pub const HQC_SECRET_KEY_BYTES: usize = 2305;
/// hqc128 ciphertext size in bytes
pub const HQC_CIPHERTEXT_BYTES: usize = 4433;
/// hqc128 shared secret size in bytes
pub const HQC_SHARED_SECRET_BYTES: usize = 64;

/// Generates a real HQC-128 keypair.
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = hqc128::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Encapsulates a shared secret using the recipient's public key.
/// Returns (ciphertext, shared_secret), matching the existing shim
/// signature (same ordering as kyber.rs/mceliece.rs).
pub fn encaps(pk_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk = match hqc128::PublicKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => {
            return (
                vec![0u8; HQC_CIPHERTEXT_BYTES],
                vec![0u8; HQC_SHARED_SECRET_BYTES],
            )
        }
    };
    let (shared_secret, ciphertext) = hqc128::encapsulate(&pk);
    (
        ciphertext.as_bytes().to_vec(),
        shared_secret.as_bytes().to_vec(),
    )
}

/// Decapsulates a shared secret using the recipient's secret key.
/// Malformed inputs, or a ciphertext/secret-key pair that fails the
/// underlying implementation's validation (which panics rather than
/// returning an error -- see module docs above), safely return a zeroed
/// shared secret instead of crashing the process.
pub fn decaps(ct_bytes: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
    let sk = match hqc128::SecretKey::from_bytes(sk_bytes) {
        Ok(k) => k,
        Err(_) => return vec![0u8; HQC_SHARED_SECRET_BYTES],
    };
    let ct = match hqc128::Ciphertext::from_bytes(ct_bytes) {
        Ok(c) => c,
        Err(_) => return vec![0u8; HQC_SHARED_SECRET_BYTES],
    };

    match catch_unwind(AssertUnwindSafe(|| hqc128::decapsulate(&ct, &sk))) {
        Ok(shared_secret) => shared_secret.as_bytes().to_vec(),
        Err(_) => vec![0u8; HQC_SHARED_SECRET_BYTES],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_encaps_decaps_roundtrip() {
        let (pk, sk) = keygen();
        assert_eq!(pk.len(), HQC_PUBLIC_KEY_BYTES);
        assert_eq!(sk.len(), HQC_SECRET_KEY_BYTES);

        let (ct, ss1) = encaps(&pk);
        assert_eq!(ct.len(), HQC_CIPHERTEXT_BYTES);
        assert_eq!(ss1.len(), HQC_SHARED_SECRET_BYTES);

        let ss2 = decaps(&ct, &sk);
        assert_eq!(
            ss1, ss2,
            "shared secrets from both sides of the exchange must match"
        );
    }

    #[test]
    fn decaps_with_wrong_secret_key_does_not_panic_or_match() {
        let (pk, _sk) = keygen();
        let (_other_pk, wrong_sk) = keygen();

        let (ct, ss1) = encaps(&pk);
        // This is expected to hit the underlying implementation's internal
        // validation panic, which `decaps` catches and turns into a safe
        // zeroed default -- the key behavior under test is that the process
        // does not crash, and the result never falsely matches ss1.
        let ss2 = decaps(&ct, &wrong_sk);
        assert_ne!(
            ss1, ss2,
            "decapsulating with an unrelated secret key must not produce the same shared secret"
        );
    }
}
