// src/hash.rs
//! Cryptographic hash utilities: SHA3-256, SHA3-512, BLAKE3.
use base64::{engine::general_purpose, Engine as _};
use blake3;
use sha3::{Digest, Sha3_256, Sha3_512};
use std::{string::String, vec::Vec};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// Compute SHA3-256 digest.
#[cfg(feature = "wasm")]
wasm_bindgen! {
    pub fn sha3_256_hash(data: &[u8]) -> Vec<u8> {
        let mut h = Sha3_256::new();
        h.update(data);
        h.finalize().to_vec()
    }
}

#[cfg(not(feature = "wasm"))]
pub fn sha3_256_hash(data: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().to_vec()
}

// Compute SHA3-256 digest and return hex.
#[cfg(feature = "wasm")]
wasm_bindgen! {
    pub fn sha3_256_hash_hex(data: &[u8]) -> String {
        hex::encode(sha3_256_hash(data))
    }
}

#[cfg(not(feature = "wasm"))]
pub fn sha3_256_hash_hex(data: &[u8]) -> String {
    hex::encode(sha3_256_hash(data))
}

// Compute SHA3-256 digest and return Base64.
#[cfg(feature = "wasm")]
wasm_bindgen! {
    pub fn sha3_256_hash_base64(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(sha3_256_hash(data))
    }
}

#[cfg(not(feature = "wasm"))]
pub fn sha3_256_hash_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(sha3_256_hash(data))
}

// Compute SHA3-512 digest.
#[cfg(feature = "wasm")]
wasm_bindgen! {
    pub fn sha3_512_hash(data: &[u8]) -> Vec<u8> {
        let mut h = Sha3_512::new();
        h.update(data);
        h.finalize().to_vec()
    }
}

#[cfg(not(feature = "wasm"))]
pub fn sha3_512_hash(data: &[u8]) -> Vec<u8> {
    let mut h = Sha3_512::new();
    h.update(data);
    h.finalize().to_vec()
}

// Compute SHA3-512 digest and return hex.
#[cfg(feature = "wasm")]
wasm_bindgen! {
    pub fn sha3_512_hash_hex(data: &[u8]) -> String {
        hex::encode(sha3_512_hash(data))
    }
}

#[cfg(not(feature = "wasm"))]
pub fn sha3_512_hash_hex(data: &[u8]) -> String {
    hex::encode(sha3_512_hash(data))
}

// Compute SHA3-512 digest and return Base64.
#[cfg(feature = "wasm")]
wasm_bindgen! {
    pub fn sha3_512_hash_base64(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(sha3_512_hash(data))
    }
}

#[cfg(not(feature = "wasm"))]
pub fn sha3_512_hash_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(sha3_512_hash(data))
}

// Compute BLAKE3 digest.
#[cfg(feature = "wasm")]
wasm_bindgen! {
    pub fn blake3_hash(data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }
}

#[cfg(not(feature = "wasm"))]
pub fn blake3_hash(data: &[u8]) -> Vec<u8> {
    blake3::hash(data).as_bytes().to_vec()
}

// Compute BLAKE3 digest and return hex.
#[cfg(feature = "wasm")]
wasm_bindgen! {
    pub fn blake3_hash_hex(data: &[u8]) -> String {
        hex::encode(blake3_hash(data))
    }
}

#[cfg(not(feature = "wasm"))]
pub fn blake3_hash_hex(data: &[u8]) -> String {
    hex::encode(blake3_hash(data))
}

// Compute BLAKE3 digest and return Base64.
#[cfg(feature = "wasm")]
wasm_bindgen! {
    pub fn blake3_hash_base64(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(blake3_hash(data))
    }
}

#[cfg(not(feature = "wasm"))]
pub fn blake3_hash_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(blake3_hash(data))
}
