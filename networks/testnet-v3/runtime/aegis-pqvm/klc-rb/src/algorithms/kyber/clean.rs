//! Core mlkem implementation.
//!
//! This module provides the core mlkem post-quantum key encapsulation mechanism (KEM)
//! implementation. It uses the `pqrust-mlkem` backend for cryptographic
//! operations and exposes key functions as WebAssembly (WASM) bindings for use
//! in JavaScript/TypeScript environments.

use pqrust_mlkem::mlkem768::{PublicKey, SecretKey, Ciphertext, encapsulate, decapsulate, keypair};
use pqrust_traits::kem::{PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _};
use wasm_bindgen::prelude::*;

use super::utils::*;

// Import Vec and format! for no_std compatibility
#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, format, string::{String, ToString}};

#[cfg(feature = "std")]
use std::{vec::Vec, string::{String, ToString}};

/// Represents a mlkem key pair, containing both the public and secret keys.
/// These keys are essential for performing cryptographic operations such as
/// encapsulating and decapsulating shared secrets.
#[wasm_bindgen]
pub struct mlkemKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[wasm_bindgen]
impl mlkemKeyPair {
    /// Returns the public key component of the mlkem key pair.
    /// The public key is used by the sender to encapsulate a shared secret.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }

    /// Returns the secret key component of the mlkem key pair.
    /// The secret key is used by the recipient to decapsulate the shared secret.
    /// It should be kept confidential.
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

/// Represents the output of the mlkem encapsulation process, containing
/// both the ciphertext and the encapsulated shared secret.
#[wasm_bindgen]
pub struct mlkemEncapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl mlkemEncapsulated {
    /// Returns the ciphertext generated during encapsulation.
    /// This ciphertext is sent to the recipient for decapsulation.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    /// Returns the shared secret derived during encapsulation.
    /// This secret is used for symmetric encryption.
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }

    /// Returns the length of the ciphertext in bytes.
    #[wasm_bindgen]
    pub fn ciphertext_length(&self) -> usize {
        self.ciphertext.len()
    }

    /// Returns the length of the shared secret in bytes.
    #[wasm_bindgen]
    pub fn shared_secret_length(&self) -> usize {
        self.shared_secret.len()
    }
}

/// Generates a new mlkem key pair.
///
/// This function uses the `pqrust-mlkem` backend to generate a fresh
/// public and secret key pair for the mlkem KEM scheme.
///
/// # Returns
///
/// A `Result<mlkemKeyPair, JsValue>` which is:
/// - `Ok(mlkemKeyPair)` containing the newly generated public and secret keys.
/// - `Err(JsValue)` if the key generation process fails.
#[wasm_bindgen]
pub fn mlkem_keygen() -> Result<mlkemKeyPair, JsValue> {
    mlkem_keygen_native().map_err(|e| JsValue::from_str(&e))
}

/// Encapsulates a shared secret using the provided mlkem public key.
///
/// This function takes a recipient's public key and generates a ciphertext
/// and a shared secret. The ciphertext is sent to the recipient, who can
/// then decapsulate it to recover the same shared secret.
///
/// # Arguments
///
/// * `public_key` - A byte slice representing the recipient's mlkem public key.
///
/// # Returns
///
/// A `Result<mlkemEncapsulated, JsValue>` which is:
/// - `Ok(mlkemEncapsulated)` containing the generated ciphertext and shared secret.
/// - `Err(JsValue)` if the public key is invalid or encapsulation fails.
#[wasm_bindgen]
pub fn mlkem_encapsulate(public_key: &[u8]) -> Result<mlkemEncapsulated, JsValue> {
    mlkem_encapsulate_native(public_key).map_err(|e| JsValue::from_str(&e))
}

/// Decapsulates a shared secret using the provided mlkem secret key and ciphertext.
///
/// This function takes the recipient's secret key and the ciphertext received
/// from the sender, and recovers the shared secret. If the ciphertext is invalid
/// or tampered with, implicit rejection is performed, returning a random shared secret.
///
/// # Arguments
///
/// * `secret_key` - A byte slice representing the recipient's mlkem secret key.
/// * `ciphertext` - A byte slice representing the ciphertext received from the sender.
///
/// # Returns
///
/// A `Result<Vec<u8>, JsValue>` which is:
/// - `Ok(Vec<u8>)` containing the decapsulated shared secret.
/// - `Err(JsValue)` if the secret key or ciphertext are invalid, or decapsulation fails.
#[wasm_bindgen]
pub fn mlkem_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    mlkem_decapsulate_native(secret_key, ciphertext).map_err(|e| JsValue::from_str(&e))
}

// Native Functions (without wasm_bindgen attributes)
/// Generates a new mlkem key pair - Native version.
///
/// # Returns
///
/// A `Result<mlkemKeyPair, String>` which is:
/// - `Ok(mlkemKeyPair)` containing the newly generated public and secret keys.
/// - `Err(String)` if the key generation process fails.
pub fn mlkem_keygen_native() -> Result<mlkemKeyPair, String> {
    let (pk, sk) = keypair();
    let keypair = mlkemKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    };
    Ok(keypair)
}

/// Encapsulates a shared secret using the provided mlkem public key - Native version.
///
/// # Arguments
///
/// * `public_key` - A byte slice representing the recipient's mlkem public key.
///
/// # Returns
///
/// A `Result<mlkemEncapsulated, String>` which is:
/// - `Ok(mlkemEncapsulated)` containing the generated ciphertext and shared secret.
/// - `Err(String)` if the public key is invalid or encapsulation fails.
pub fn mlkem_encapsulate_native(public_key: &[u8]) -> Result<mlkemEncapsulated, String> {
    validate_public_key_length(public_key)?;

    let pk = PublicKey::from_bytes(public_key)
        .map_err(|e| format!("Invalid public key: {:?}", e))?;
    let (ss, ct) = encapsulate(&pk);
    Ok(mlkemEncapsulated {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

/// Decapsulates a shared secret using the provided mlkem secret key and ciphertext - Native version.
///
/// # Arguments
///
/// * `secret_key` - A byte slice representing the recipient's mlkem secret key.
/// * `ciphertext` - A byte slice representing the ciphertext received from the sender.
///
/// # Returns
///
/// A `Result<Vec<u8>, String>` which is:
/// - `Ok(Vec<u8>)` containing the decapsulated shared secret.
/// - `Err(String)` if the secret key or ciphertext are invalid, or decapsulation fails.
pub fn mlkem_decapsulate_native(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    validate_secret_key_length(secret_key)?;
    validate_ciphertext_length(ciphertext)?;

    let sk = SecretKey::from_bytes(secret_key)
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    let ct = Ciphertext::from_bytes(ciphertext)
        .map_err(|e| format!("Invalid ciphertext: {:?}", e))?;
    let ss = decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}
