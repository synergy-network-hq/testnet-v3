//! # Classic McEliece (mceliece348864) Shim
//!
//! Real implementation using the `pqcrypto-classicmceliece` crate (via the
//! `pqcrypto` facade, same pattern as kyber.rs). Previously this module
//! returned fixed-size zeroed keys/ciphertext/shared-secret vectors -- fixed
//! to perform genuine key generation, encapsulation, and decapsulation.

use pqcrypto::kem::mceliece348864;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

/// mceliece348864 public key size in bytes
pub const MCELIECE_PUBLIC_KEY_BYTES: usize = 261120;
/// mceliece348864 secret key size in bytes
pub const MCELIECE_SECRET_KEY_BYTES: usize = 6492;
/// mceliece348864 ciphertext size in bytes
pub const MCELIECE_CIPHERTEXT_BYTES: usize = 96;
/// mceliece348864 shared secret size in bytes
pub const MCELIECE_SHARED_SECRET_BYTES: usize = 32;

/// Generates a real Classic McEliece (mceliece348864) keypair.
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = mceliece348864::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Encapsulates a shared secret using the recipient's public key.
/// Returns (ciphertext, shared_secret) to match the existing shim
/// signature used by mceliece/hqc callers (kyber.rs and this module share
/// the (ciphertext, shared_secret) tuple ordering).
pub fn encaps(pk_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk = match mceliece348864::PublicKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => {
            return (
                vec![0u8; MCELIECE_CIPHERTEXT_BYTES],
                vec![0u8; MCELIECE_SHARED_SECRET_BYTES],
            )
        }
    };
    let (shared_secret, ciphertext) = mceliece348864::encapsulate(&pk);
    (
        ciphertext.as_bytes().to_vec(),
        shared_secret.as_bytes().to_vec(),
    )
}

/// Decapsulates a shared secret using the recipient's secret key.
pub fn decaps(ct_bytes: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
    let sk = match mceliece348864::SecretKey::from_bytes(sk_bytes) {
        Ok(k) => k,
        Err(_) => return vec![0u8; MCELIECE_SHARED_SECRET_BYTES],
    };
    let ct = match mceliece348864::Ciphertext::from_bytes(ct_bytes) {
        Ok(c) => c,
        Err(_) => return vec![0u8; MCELIECE_SHARED_SECRET_BYTES],
    };
    let shared_secret = mceliece348864::decapsulate(&ct, &sk);
    shared_secret.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_encaps_decaps_roundtrip() {
        let (pk, sk) = keygen();
        assert_eq!(pk.len(), MCELIECE_PUBLIC_KEY_BYTES);
        assert_eq!(sk.len(), MCELIECE_SECRET_KEY_BYTES);

        let (ct, ss1) = encaps(&pk);
        assert_eq!(ct.len(), MCELIECE_CIPHERTEXT_BYTES);
        assert_eq!(ss1.len(), MCELIECE_SHARED_SECRET_BYTES);

        let ss2 = decaps(&ct, &sk);
        assert_eq!(
            ss1, ss2,
            "shared secrets from both sides of the exchange must match"
        );
    }

    #[test]
    fn decaps_with_wrong_secret_key_does_not_match() {
        let (pk, _sk) = keygen();
        let (_other_pk, wrong_sk) = keygen();

        let (ct, ss1) = encaps(&pk);
        let ss2 = decaps(&ct, &wrong_sk);
        assert_ne!(
            ss1, ss2,
            "decapsulating with an unrelated secret key must not produce the same shared secret"
        );
    }
}
