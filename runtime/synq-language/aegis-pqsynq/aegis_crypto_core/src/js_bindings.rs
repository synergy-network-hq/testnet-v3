// src/js_bindings.rs
//! JavaScript/WebAssembly bindings for Aegis Crypto Core.

#[cfg(target_arch = "wasm32")]
mod wasm_bindings {
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsValue;
    #[cfg(not(feature = "std"))]
    extern crate alloc;
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;

    // Import hash & util functions
    use crate::hash::{
        blake3_hash, blake3_hash_base64, blake3_hash_hex, sha3_256_hash, sha3_256_hash_base64,
        sha3_256_hash_hex, sha3_512_hash, sha3_512_hash_base64, sha3_512_hash_hex,
    };
    use crate::utils::{bytes_to_hex, hex_to_bytes};

    // Import NIST WASM functions when features are enabled
    #[cfg(feature = "nist-wasm")]
    use crate::nist_wasm_mlkem::{
        nist_mlkem_decapsulate, nist_mlkem_encapsulate, nist_mlkem_keygen, nist_mlkem_variants,
        NistMlkemEncapsulated, NistMlkemKeyPair,
    };

    #[cfg(feature = "nist-wasm")]
    use crate::nist_wasm_mldsa::{
        nist_mldsa_keygen, nist_mldsa_sign, nist_mldsa_variants, nist_mldsa_verify,
        NistMldsaKeyPair,
    };

    #[cfg(feature = "nist-wasm")]
    use crate::wasm_loader::{
        get_wasm_info, init_wasm_loader, is_wasm_supported, load_mldsa_modules, load_mlkem_modules,
    };

    // … KEM & signature bindings (unchanged) …

    // ===== Hash functions =====
    #[wasm_bindgen(js_name = sha3_256)]
    pub fn sha3_256_js(data: &[u8]) -> Vec<u8> {
        sha3_256_hash(data)
    }
    #[wasm_bindgen(js_name = sha3_256_hex)]
    pub fn sha3_256_hex_js(data: &[u8]) -> String {
        sha3_256_hash_hex(data)
    }
    #[wasm_bindgen(js_name = sha3_256_base64)]
    pub fn sha3_256_base64_js(data: &[u8]) -> String {
        sha3_256_hash_base64(data)
    }

    #[wasm_bindgen(js_name = sha3_512)]
    pub fn sha3_512_js(data: &[u8]) -> Vec<u8> {
        sha3_512_hash(data)
    }
    #[wasm_bindgen(js_name = sha3_512_hex)]
    pub fn sha3_512_hex_js(data: &[u8]) -> String {
        sha3_512_hash_hex(data)
    }
    #[wasm_bindgen(js_name = sha3_512_base64)]
    pub fn sha3_512_base64_js(data: &[u8]) -> String {
        sha3_512_hash_base64(data)
    }

    #[wasm_bindgen(js_name = blake3)]
    pub fn blake3_js(data: &[u8]) -> Vec<u8> {
        blake3_hash(data)
    }
    #[wasm_bindgen(js_name = blake3_hex)]
    pub fn blake3_hex_js(data: &[u8]) -> String {
        blake3_hash_hex(data)
    }
    #[wasm_bindgen(js_name = blake3_base64)]
    pub fn blake3_base64_js(data: &[u8]) -> String {
        blake3_hash_base64(data)
    }

    // ===== NIST Reference ML-KEM WASM functions =====
    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = nistMlkemKeygen)]
    pub async fn nist_mlkem_keygen_js(variant: &str) -> Result<NistMlkemKeyPair, JsValue> {
        nist_mlkem_keygen(variant).await
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = nistMlkemEncapsulate)]
    pub async fn nist_mlkem_encapsulate_js(
        variant: &str,
        public_key: &[u8],
    ) -> Result<NistMlkemEncapsulated, JsValue> {
        nist_mlkem_encapsulate(variant, public_key).await
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = nistMlkemDecapsulate)]
    pub async fn nist_mlkem_decapsulate_js(
        variant: &str,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        nist_mlkem_decapsulate(variant, secret_key, ciphertext).await
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = nistMlkemVariants)]
    pub fn nist_mlkem_variants_js() -> JsValue {
        nist_mlkem_variants()
    }

    // ===== NIST Reference ML-DSA WASM functions =====
    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = nistMldsaKeygen)]
    pub async fn nist_mldsa_keygen_js(variant: &str) -> Result<NistMldsaKeyPair, JsValue> {
        nist_mldsa_keygen(variant).await
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = nistMldsaSign)]
    pub async fn nist_mldsa_sign_js(
        variant: &str,
        secret_key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        nist_mldsa_sign(variant, secret_key, message).await
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = nistMldsaVerify)]
    pub async fn nist_mldsa_verify_js(
        variant: &str,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, JsValue> {
        nist_mldsa_verify(variant, public_key, signature, message).await
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = nistMldsaVariants)]
    pub fn nist_mldsa_variants_js() -> JsValue {
        nist_mldsa_variants()
    }

    // ===== WASM Loader functions =====
    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = initWasmLoader)]
    pub fn init_wasm_loader_js() -> JsValue {
        init_wasm_loader().into()
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = loadMlkemModules)]
    pub async fn load_mlkem_modules_js() -> Result<JsValue, JsValue> {
        load_mlkem_modules().await
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = loadMldsaModules)]
    pub async fn load_mldsa_modules_js() -> Result<JsValue, JsValue> {
        load_mldsa_modules().await
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = isWasmSupported)]
    pub fn is_wasm_supported_js() -> bool {
        is_wasm_supported()
    }

    #[cfg(feature = "nist-wasm")]
    #[wasm_bindgen(js_name = getWasmInfo)]
    pub fn get_wasm_info_js() -> JsValue {
        get_wasm_info()
    }

    // ===== Utility =====
    #[wasm_bindgen(js_name = hexToBytes)]
    pub fn hex_to_bytes_js(hex_str: &str) -> Result<Vec<u8>, JsValue> {
        hex_to_bytes(hex_str)
    }
    #[wasm_bindgen(js_name = bytesToHex)]
    pub fn bytes_to_hex_js(bytes: &[u8]) -> String {
        bytes_to_hex(bytes)
    }
}
