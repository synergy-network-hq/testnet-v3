//! WASM bindings for mlkem operations.

use wasm_bindgen::prelude::*;
use super::utils::*;

/// WASM-exposed function to get the mlkem public key length.
#[wasm_bindgen]
pub fn mlkem_public_key_length() -> usize {
    public_key_length()
}

/// WASM-exposed function to get the mlkem secret key length.
#[wasm_bindgen]
pub fn mlkem_secret_key_length() -> usize {
    secret_key_length()
}

/// WASM-exposed function to get the mlkem ciphertext length.
#[wasm_bindgen]
pub fn mlkem_ciphertext_length() -> usize {
    ciphertext_length()
}

/// WASM-exposed function to get the mlkem shared secret length.
#[wasm_bindgen]
pub fn mlkem_shared_secret_length() -> usize {
    shared_secret_length()
}

/// WASM-exposed function to validate a mlkem public key length.
#[wasm_bindgen]
pub fn mlkem_validate_public_key(key: &[u8]) -> bool {
    validate_public_key_length(key).is_ok()
}

/// WASM-exposed function to validate a mlkem secret key length.
#[wasm_bindgen]
pub fn mlkem_validate_secret_key(key: &[u8]) -> bool {
    validate_secret_key_length(key).is_ok()
}

/// WASM-exposed function to validate a mlkem ciphertext length.
#[wasm_bindgen]
pub fn mlkem_validate_ciphertext(ciphertext: &[u8]) -> bool {
    validate_ciphertext_length(ciphertext).is_ok()
}

/// WASM-exposed function to validate a mlkem shared secret length.
#[wasm_bindgen]
pub fn mlkem_validate_shared_secret(shared_secret: &[u8]) -> bool {
    validate_shared_secret_length(shared_secret).is_ok()
}
