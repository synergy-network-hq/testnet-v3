// Minimal AEGIS WASM for Node.js
// Only includes core functionality to avoid dependency issues

use wasm_bindgen::prelude::*;

// Basic functionality without external dependencies
#[wasm_bindgen]
pub fn aegis_version() -> String {
    "AEGIS 0.1.0 Minimal Node.js Build".to_string()
}

#[wasm_bindgen]
pub fn is_nodejs_environment() -> bool {
    // Simple check for Node.js environment
    js_sys::global()
        .dyn_into::<js_sys::Object>()
        .ok()
        .and_then(|global| js_sys::Reflect::get(&global, &"process".into()).ok())
        .and_then(|process| js_sys::Reflect::get(&process, &"versions".into()).ok())
        .and_then(|versions| js_sys::Reflect::get(&versions, &"node".into()).ok())
        .is_some()
}

#[wasm_bindgen]
pub fn get_environment_info() -> JsValue {
    let info = js_sys::Object::new();

    // Check Node.js
    let is_nodejs = is_nodejs_environment();
    js_sys::Reflect::set(&info, &"is_nodejs".into(), &is_nodejs.into()).unwrap();

    // Get basic info
    if is_nodejs {
        js_sys::Reflect::set(&info, &"environment".into(), &"nodejs".into()).unwrap();
    } else {
        js_sys::Reflect::set(&info, &"environment".into(), &"browser".into()).unwrap();
    }

    info.into()
}

// Simple hash function (no external dependencies)
#[wasm_bindgen]
pub fn simple_hash(data: &[u8]) -> Vec<u8> {
    let mut hash = vec![0u8; 32];
    for (i, &byte) in data.iter().enumerate() {
        let idx = i % 32;
        hash[idx] = hash[idx].wrapping_add(byte).wrapping_add(i as u8);
    }
    hash
}

// Simple base64 encoding (no external dependencies)
#[wasm_bindgen]
pub fn simple_base64_encode(data: &[u8]) -> String {
    base64::encode(data)
}

// Simple base64 decoding (no external dependencies)
#[wasm_bindgen]
pub fn simple_base64_decode(data: &str) -> Result<Vec<u8>, JsValue> {
    base64::decode(data).map_err(|e| JsValue::from_str(&format!("Base64 decode error: {}", e)))
}

// Initialize function
#[wasm_bindgen(start)]
pub fn main() {
    // Set up panic hook for better error messages
    console_error_panic_hook::set_once();
}
