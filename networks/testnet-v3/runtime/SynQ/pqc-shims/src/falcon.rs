//! # Falcon-512 Shim
//!
//! Real implementation using the `pqcrypto-falcon` crate's Falcon-512
//! parameter set. Previously this module returned zeroed keys/signatures
//! and hardcoded `true` for verify() — fixed to perform genuine key
//! generation, signing, and verification.

use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

pub const FALCON_PUBLIC_KEY_BYTES: usize = falcon512::public_key_bytes();
pub const FALCON_SECRET_KEY_BYTES: usize = falcon512::secret_key_bytes();
pub const FALCON_SIGNATURE_BYTES: usize = falcon512::signature_bytes();

/// Generates a real Falcon-512 keypair.
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = falcon512::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Signs a message with a real Falcon-512 secret key.
pub fn sign(msg: &[u8], sk: &[u8]) -> Vec<u8> {
    let secret_key = match falcon512::SecretKey::from_bytes(sk) {
        Ok(k) => k,
        Err(_) => return vec![0u8; FALCON_SIGNATURE_BYTES],
    };
    let signed = falcon512::sign(msg, &secret_key);
    signed.as_bytes().to_vec()
}

/// Verifies a real Falcon-512 signed message against a public key.
/// Malformed inputs safely return `false` rather than panicking.
pub fn verify(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
    let public_key = match falcon512::PublicKey::from_bytes(pk) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signed_message = match falcon512::SignedMessage::from_bytes(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    match falcon512::open(&signed_message, &public_key) {
        Ok(recovered_msg) => recovered_msg == msg,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_sign_verify_roundtrip() {
        let (pk, sk) = keygen();
        let msg = b"synergy network falcon test message";
        let sig = sign(msg, &sk);
        assert!(verify(msg, &sig, &pk));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let (pk, sk) = keygen();
        let msg = b"synergy network falcon test message";
        let mut sig = sign(msg, &sk);
        let len = sig.len();
        sig[len - 1] ^= 0xFF;
        assert!(!verify(msg, &sig, &pk));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let (pk, sk) = keygen();
        let msg = b"synergy network falcon test message";
        let sig = sign(msg, &sk);
        assert!(!verify(b"a different message entirely", &sig, &pk));
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let (_pk, sk) = keygen();
        let (other_pk, _other_sk) = keygen();
        let msg = b"synergy network falcon test message";
        let sig = sign(msg, &sk);
        assert!(!verify(msg, &sig, &other_pk));
    }

    #[test]
    fn malformed_inputs_return_safe_defaults_not_panic() {
        assert!(!verify(b"msg", &[0u8; 4], &[0u8; 4]));
        assert_eq!(sign(b"msg", &[0u8; 4]).len(), FALCON_SIGNATURE_BYTES);
    }
}
