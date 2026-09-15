//! Core mldsa implementation.
//!
//! This module provides the mldsa (ML-DSA) post-quantum digital signature algorithm implementation.
//! Uses the `pqrust-mldsa` backend (mldsa Level 3 / mldsa87) for all cryptographic operations
//! and exposes key functions as WebAssembly (WASM) bindings for JavaScript/TypeScript use.

use pqrust_mldsa::mldsa87::{PublicKey, SecretKey, detached_sign, keypair, DetachedSignature, verify_detached_signature};
use pqrust_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
use wasm_bindgen::prelude::*;
use super::utils::*;

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::{String, ToString}};
#[cfg(feature = "std")]
use std::{vec::Vec, string::{String, ToString}};

/// Represents a mldsa key pair (public and secret keys).
#[wasm_bindgen]
pub struct mldsaKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[wasm_bindgen]
impl mldsaKeyPair {
    /// Returns the public key as bytes.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }
    /// Returns the secret key as bytes.
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.sk.clone()
    }
    /// Returns the length of the public key in bytes.
    #[wasm_bindgen]
    pub fn public_key_length(&self) -> usize {
        self.pk.len()
    }
    /// Returns the length of the secret key in bytes.
    #[wasm_bindgen]
    pub fn secret_key_length(&self) -> usize {
        self.sk.len()
    }
}

/// Generate a new mldsa keypair (ML-DSA, mldsa87).
#[wasm_bindgen]
pub fn mldsa_keygen() -> Result<mldsaKeyPair, JsValue> {
    mldsa_keygen_native().map_err(|e| JsValue::from_str(&e))
}

/// Create a mldsa signature over a message using the provided secret key.
#[wasm_bindgen]
pub fn mldsa_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    mldsa_sign_native(secret_key, message).map_err(|e| JsValue::from_str(&e))
}

/// Verify a mldsa signature over a message using the provided public key.
#[wasm_bindgen]
pub fn mldsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    mldsa_verify_native(public_key, message, signature)
}

// Native Functions (without wasm_bindgen attributes)
/// Generate a new mldsa keypair (ML-DSA, mldsa87) - Native version.
pub fn mldsa_keygen_native() -> Result<mldsaKeyPair, String> {
    let (pk, sk) = keypair();
    let keypair = mldsaKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    };
    Ok(keypair)
}

/// Create a mldsa signature over a message using the provided secret key - Native version.
pub fn mldsa_sign_native(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    validate_secret_key_length(secret_key)?;
    let sk = SecretKey::from_bytes(secret_key).map_err(|_| "Invalid secret key".to_string())?;
    let sig = detached_sign(message, &sk);
    Ok(sig.as_bytes().to_vec())
}

/// Verify a mldsa signature over a message using the provided public key - Native version.
pub fn mldsa_verify_native(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if validate_public_key_length(public_key).is_err() {
        return false;
    }
    if validate_signature_length(signature).is_err() {
        return false;
    }
    let pk = match PublicKey::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match DetachedSignature::from_bytes(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    verify_detached_signature(&sig, message, &pk).is_ok()
}
