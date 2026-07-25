//! WASM bindings for Classic McEliece operations.

use wasm_bindgen::prelude::*;
use super::utils::*;

// WASM-exposed length functions for 128-bit security
/// WASM-exposed function to get the Classic McEliece 128-bit public key length.
#[wasm_bindgen]
pub fn classicmceliece128_public_key_length() -> usize {
    public_key_length_128()
}

/// WASM-exposed function to get the Classic McEliece 128-bit secret key length.
#[wasm_bindgen]
pub fn classicmceliece128_secret_key_length() -> usize {
    secret_key_length_128()
}

/// WASM-exposed function to get the Classic McEliece 128-bit ciphertext length.
#[wasm_bindgen]
pub fn classicmceliece128_ciphertext_length() -> usize {
    ciphertext_length_128()
}

/// WASM-exposed function to get the Classic McEliece 128-bit shared secret length.
#[wasm_bindgen]
pub fn classicmceliece128_shared_secret_length() -> usize {
    shared_secret_length_128()
}

// WASM-exposed length functions for 192-bit security
/// WASM-exposed function to get the Classic McEliece 192-bit public key length.
#[wasm_bindgen]
pub fn classicmceliece192_public_key_length() -> usize {
    public_key_length_192()
}

/// WASM-exposed function to get the Classic McEliece 192-bit secret key length.
#[wasm_bindgen]
pub fn classicmceliece192_secret_key_length() -> usize {
    secret_key_length_192()
}

/// WASM-exposed function to get the Classic McEliece 192-bit ciphertext length.
#[wasm_bindgen]
pub fn classicmceliece192_ciphertext_length() -> usize {
    ciphertext_length_192()
}

/// WASM-exposed function to get the Classic McEliece 192-bit shared secret length.
#[wasm_bindgen]
pub fn classicmceliece192_shared_secret_length() -> usize {
    shared_secret_length_192()
}

// WASM-exposed length functions for 256-bit security
/// WASM-exposed function to get the Classic McEliece 256-bit public key length.
#[wasm_bindgen]
pub fn classicmceliece256_public_key_length() -> usize {
    public_key_length_256()
}

/// WASM-exposed function to get the Classic McEliece 256-bit secret key length.
#[wasm_bindgen]
pub fn classicmceliece256_secret_key_length() -> usize {
    secret_key_length_256()
}

/// WASM-exposed function to get the Classic McEliece 256-bit ciphertext length.
#[wasm_bindgen]
pub fn classicmceliece256_ciphertext_length() -> usize {
    ciphertext_length_256()
}

/// WASM-exposed function to get the Classic McEliece 256-bit shared secret length.
#[wasm_bindgen]
pub fn classicmceliece256_shared_secret_length() -> usize {
    shared_secret_length_256()
}

// WASM-exposed validation functions for 128-bit security
/// WASM-exposed function to validate a Classic McEliece 128-bit public key length.
#[wasm_bindgen]
pub fn classicmceliece128_validate_public_key(key: &[u8]) -> bool {
    validate_public_key_length_128(key).is_ok()
}

/// WASM-exposed function to validate a Classic McEliece 128-bit secret key length.
#[wasm_bindgen]
pub fn classicmceliece128_validate_secret_key(key: &[u8]) -> bool {
    validate_secret_key_length_128(key).is_ok()
}

/// WASM-exposed function to validate a Classic McEliece 128-bit ciphertext length.
#[wasm_bindgen]
pub fn classicmceliece128_validate_ciphertext(ciphertext: &[u8]) -> bool {
    validate_ciphertext_length_128(ciphertext).is_ok()
}

/// WASM-exposed function to validate a Classic McEliece 128-bit shared secret length.
#[wasm_bindgen]
pub fn classicmceliece128_validate_shared_secret(shared_secret: &[u8]) -> bool {
    validate_shared_secret_length_128(shared_secret).is_ok()
}

// WASM-exposed validation functions for 192-bit security
/// WASM-exposed function to validate a Classic McEliece 192-bit public key length.
#[wasm_bindgen]
pub fn classicmceliece192_validate_public_key(key: &[u8]) -> bool {
    validate_public_key_length_192(key).is_ok()
}

/// WASM-exposed function to validate a Classic McEliece 192-bit secret key length.
#[wasm_bindgen]
pub fn classicmceliece192_validate_secret_key(key: &[u8]) -> bool {
    validate_secret_key_length_192(key).is_ok()
}

/// WASM-exposed function to validate a Classic McEliece 192-bit ciphertext length.
#[wasm_bindgen]
pub fn classicmceliece192_validate_ciphertext(ciphertext: &[u8]) -> bool {
    validate_ciphertext_length_192(ciphertext).is_ok()
}

/// WASM-exposed function to validate a Classic McEliece 192-bit shared secret length.
#[wasm_bindgen]
pub fn classicmceliece192_validate_shared_secret(shared_secret: &[u8]) -> bool {
    validate_shared_secret_length_192(shared_secret).is_ok()
}

// WASM-exposed validation functions for 256-bit security
/// WASM-exposed function to validate a Classic McEliece 256-bit public key length.
#[wasm_bindgen]
pub fn classicmceliece256_validate_public_key(key: &[u8]) -> bool {
    validate_public_key_length_256(key).is_ok()
}

/// WASM-exposed function to validate a Classic McEliece 256-bit secret key length.
#[wasm_bindgen]
pub fn classicmceliece256_validate_secret_key(key: &[u8]) -> bool {
    validate_secret_key_length_256(key).is_ok()
}

/// WASM-exposed function to validate a Classic McEliece 256-bit ciphertext length.
#[wasm_bindgen]
pub fn classicmceliece256_validate_ciphertext(ciphertext: &[u8]) -> bool {
    validate_ciphertext_length_256(ciphertext).is_ok()
}

/// WASM-exposed function to validate a Classic McEliece 256-bit shared secret length.
#[wasm_bindgen]
pub fn classicmceliece256_validate_shared_secret(shared_secret: &[u8]) -> bool {
    validate_shared_secret_length_256(shared_secret).is_ok()
}
