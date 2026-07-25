//! # Kyber PQC Implementation
//!
//! Real CRYSTALS-Kyber implementation using the pqcrypto crate.
//! Provides key encapsulation mechanism for quantum-resistant security.

use pqcrypto::kem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

/// Kyber-768 public key size in bytes
pub const KYBER_PUBLIC_KEY_BYTES: usize = 1184;
/// Kyber-768 secret key size in bytes
pub const KYBER_SECRET_KEY_BYTES: usize = 2400;
/// Kyber-768 ciphertext size in bytes
pub const KYBER_CIPHERTEXT_BYTES: usize = 1088;
/// Kyber-768 shared secret size in bytes
pub const KYBER_SHARED_SECRET_BYTES: usize = 32;

/// Generate a Kyber-768 keypair for key encapsulation
pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (pk, sk) = mlkem768::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

/// Encapsulate a shared secret using the recipient's public key
pub fn encaps(pk_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pk = mlkem768::PublicKey::from_bytes(pk_bytes)
        .map_err(|e| format!("Failed to create public key: {:?}", e))?;

    let (shared_secret, ciphertext) = mlkem768::encapsulate(&pk);
    Ok((
        ciphertext.as_bytes().to_vec(),
        shared_secret.as_bytes().to_vec(),
    ))
}

/// Decapsulate a shared secret using the recipient's secret key
pub fn decaps(ct_bytes: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| format!("Failed to create secret key: {:?}", e))?;

    let ct = mlkem768::Ciphertext::from_bytes(ct_bytes)
        .map_err(|e| format!("Failed to create ciphertext: {:?}", e))?;

    let shared_secret = mlkem768::decapsulate(&ct, &sk);
    Ok(shared_secret.as_bytes().to_vec())
}
