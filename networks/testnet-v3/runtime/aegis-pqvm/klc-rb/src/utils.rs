// src/utils.rs
//! Utility functions: hex ↔ bytes.
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use std::{ vec::Vec, string::String, format };

// Decode hex string to bytes.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn hex_to_bytes(hex_string: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(hex_string).map_err(|e| format!("Failed to decode hex string: {}", e).into())
}

#[cfg(not(feature = "wasm"))]
pub fn hex_to_bytes(hex_string: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_string).map_err(|e| format!("Failed to decode hex string: {}", e))
}

// Encode bytes to hex string.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(not(feature = "wasm"))]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
