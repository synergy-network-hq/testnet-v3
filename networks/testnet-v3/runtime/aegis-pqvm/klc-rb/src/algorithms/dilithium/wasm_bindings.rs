//! WASM bindings for mldsa operations.

use wasm_bindgen::prelude::*;
use super::utils::*;

/// WASM-exposed function to get the mldsa public key length.
#[wasm_bindgen]
pub fn mldsa_public_key_length() -> usize {
    public_key_length()
}

/// WASM-exposed function to get the mldsa secret key length.
#[wasm_bindgen]
pub fn mldsa_secret_key_length() -> usize {
    secret_key_length()
}

/// WASM-exposed function to get the mldsa signature length.
#[wasm_bindgen]
pub fn mldsa_signature_length() -> usize {
    signature_length()
}

/// WASM-exposed function to validate a mldsa public key length.
#[wasm_bindgen]
pub fn mldsa_validate_public_key(key: &[u8]) -> bool {
    validate_public_key_length(key).is_ok()
}

/// WASM-exposed function to validate a mldsa secret key length.
#[wasm_bindgen]
pub fn mldsa_validate_secret_key(key: &[u8]) -> bool {
    validate_secret_key_length(key).is_ok()
}

/// WASM-exposed function to validate a mldsa signature length.
#[wasm_bindgen]
pub fn mldsa_validate_signature(signature: &[u8]) -> bool {
    validate_signature_length(signature).is_ok()
}
