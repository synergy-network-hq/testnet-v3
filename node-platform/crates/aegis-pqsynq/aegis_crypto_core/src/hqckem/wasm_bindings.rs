//! WASM bindings for HQC operations.

use wasm_bindgen::prelude::*;
use super::utils::*;

// HQC-128 WASM bindings
/// WASM-exposed function to get the HQC-128 public key length.
#[wasm_bindgen]
pub fn hqc128_public_key_length() -> usize {
    super::utils::hqc128_public_key_length()
}

/// WASM-exposed function to get the HQC-128 secret key length.
#[wasm_bindgen]
pub fn hqc128_secret_key_length() -> usize {
    super::utils::hqc128_secret_key_length()
}

/// WASM-exposed function to get the HQC-128 ciphertext length.
#[wasm_bindgen]
pub fn hqc128_ciphertext_length() -> usize {
    super::utils::hqc128_ciphertext_length()
}

/// WASM-exposed function to get the HQC-128 shared secret length.
#[wasm_bindgen]
pub fn hqc128_shared_secret_length() -> usize {
    super::utils::hqc128_shared_secret_length()
}

/// WASM-exposed function to validate an HQC-128 public key length.
#[wasm_bindgen]
pub fn hqc128_validate_public_key(key: &[u8]) -> bool {
    validate_hqc128_public_key_length(key).is_ok()
}

/// WASM-exposed function to validate an HQC-128 secret key length.
#[wasm_bindgen]
pub fn hqc128_validate_secret_key(key: &[u8]) -> bool {
    validate_hqc128_secret_key_length(key).is_ok()
}

/// WASM-exposed function to validate an HQC-128 ciphertext length.
#[wasm_bindgen]
pub fn hqc128_validate_ciphertext(ciphertext: &[u8]) -> bool {
    validate_hqc128_ciphertext_length(ciphertext).is_ok()
}

// HQC-192 WASM bindings
/// WASM-exposed function to get the HQC-192 public key length.
#[wasm_bindgen]
pub fn hqc192_public_key_length() -> usize {
    super::utils::hqc192_public_key_length()
}

/// WASM-exposed function to get the HQC-192 secret key length.
#[wasm_bindgen]
pub fn hqc192_secret_key_length() -> usize {
    super::utils::hqc192_secret_key_length()
}

/// WASM-exposed function to get the HQC-192 ciphertext length.
#[wasm_bindgen]
pub fn hqc192_ciphertext_length() -> usize {
    super::utils::hqc192_ciphertext_length()
}

/// WASM-exposed function to get the HQC-192 shared secret length.
#[wasm_bindgen]
pub fn hqc192_shared_secret_length() -> usize {
    super::utils::hqc192_shared_secret_length()
}

/// WASM-exposed function to validate an HQC-192 public key length.
#[wasm_bindgen]
pub fn hqc192_validate_public_key(key: &[u8]) -> bool {
    validate_hqc192_public_key_length(key).is_ok()
}

/// WASM-exposed function to validate an HQC-192 secret key length.
#[wasm_bindgen]
pub fn hqc192_validate_secret_key(key: &[u8]) -> bool {
    validate_hqc192_secret_key_length(key).is_ok()
}

/// WASM-exposed function to validate an HQC-192 ciphertext length.
#[wasm_bindgen]
pub fn hqc192_validate_ciphertext(ciphertext: &[u8]) -> bool {
    validate_hqc192_ciphertext_length(ciphertext).is_ok()
}

// HQC-256 WASM bindings
/// WASM-exposed function to get the HQC-256 public key length.
#[wasm_bindgen]
pub fn hqc256_public_key_length() -> usize {
    super::utils::hqc256_public_key_length()
}

/// WASM-exposed function to get the HQC-256 secret key length.
#[wasm_bindgen]
pub fn hqc256_secret_key_length() -> usize {
    super::utils::hqc256_secret_key_length()
}

/// WASM-exposed function to get the HQC-256 ciphertext length.
#[wasm_bindgen]
pub fn hqc256_ciphertext_length() -> usize {
    super::utils::hqc256_ciphertext_length()
}

/// WASM-exposed function to get the HQC-256 shared secret length.
#[wasm_bindgen]
pub fn hqc256_shared_secret_length() -> usize {
    super::utils::hqc256_shared_secret_length()
}

/// WASM-exposed function to validate an HQC-256 public key length.
#[wasm_bindgen]
pub fn hqc256_validate_public_key(key: &[u8]) -> bool {
    validate_hqc256_public_key_length(key).is_ok()
}

/// WASM-exposed function to validate an HQC-256 secret key length.
#[wasm_bindgen]
pub fn hqc256_validate_secret_key(key: &[u8]) -> bool {
    validate_hqc256_secret_key_length(key).is_ok()
}

/// WASM-exposed function to validate an HQC-256 ciphertext length.
#[wasm_bindgen]
pub fn hqc256_validate_ciphertext(ciphertext: &[u8]) -> bool {
    validate_hqc256_ciphertext_length(ciphertext).is_ok()
}
