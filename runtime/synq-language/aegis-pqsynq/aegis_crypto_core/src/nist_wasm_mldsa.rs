//! NIST Reference ML-DSA WASM Implementation
//!
//! This module provides ML-DSA implementations using the NIST reference code
//! compiled to WASM. It dynamically loads the external WASM files and provides
//! a unified interface for all security levels.

use js_sys::{Object, Reflect, Uint8Array, WebAssembly};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use web_sys::{Request, RequestInit, RequestMode, Response};

use std::vec::Vec;

/// Represents an ML-DSA key pair (public and secret keys).
#[wasm_bindgen]
pub struct NistMldsaKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[wasm_bindgen]
impl NistMldsaKeyPair {
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

/// ML-DSA security level variants
#[derive(Debug, Clone, Copy)]
pub enum MldsaVariant {
    MLDSA2,
    MLDSA3,
    MLDSA5,
    MLDSA2AES,
    MLDSA3AES,
    MLDSA5AES,
}

impl MldsaVariant {
    fn wasm_filename(&self) -> &'static str {
        match self {
            MldsaVariant::MLDSA2 => "mldsa44_ref.wasm",
            MldsaVariant::MLDSA3 => "mldsa65_ref.wasm",
            MldsaVariant::MLDSA5 => "mldsa87_ref.wasm",
            MldsaVariant::MLDSA2AES => "mldsa44_ref.wasm",
            MldsaVariant::MLDSA3AES => "mldsa65_ref.wasm",
            MldsaVariant::MLDSA5AES => "mldsa87_ref.wasm",
        }
    }

    fn public_key_length(&self) -> usize {
        match self {
            MldsaVariant::MLDSA2 => 1312,
            MldsaVariant::MLDSA3 => 1952,
            MldsaVariant::MLDSA5 => 2592,
            MldsaVariant::MLDSA2AES => 1312,
            MldsaVariant::MLDSA3AES => 1952,
            MldsaVariant::MLDSA5AES => 2592,
        }
    }

    fn secret_key_length(&self) -> usize {
        match self {
            MldsaVariant::MLDSA2 => 2544,
            MldsaVariant::MLDSA3 => 4016,
            MldsaVariant::MLDSA5 => 4880,
            MldsaVariant::MLDSA2AES => 2544,
            MldsaVariant::MLDSA3AES => 4016,
            MldsaVariant::MLDSA5AES => 4880,
        }
    }

    fn signature_length(&self) -> usize {
        match self {
            MldsaVariant::MLDSA2 => 2420,
            MldsaVariant::MLDSA3 => 3293,
            MldsaVariant::MLDSA5 => 4595,
            MldsaVariant::MLDSA2AES => 2420,
            MldsaVariant::MLDSA3AES => 3293,
            MldsaVariant::MLDSA5AES => 4595,
        }
    }

    #[allow(dead_code)]
    fn display_name(&self) -> &'static str {
        match self {
            MldsaVariant::MLDSA2 => "ML-DSA-2",
            MldsaVariant::MLDSA3 => "ML-DSA-3",
            MldsaVariant::MLDSA5 => "ML-DSA-5",
            MldsaVariant::MLDSA2AES => "ML-DSA-2-AES",
            MldsaVariant::MLDSA3AES => "ML-DSA-3-AES",
            MldsaVariant::MLDSA5AES => "ML-DSA-5-AES",
        }
    }
}

/// WASM module loader for ML-DSA
pub struct MldsaWasmLoader {
    module: Option<WebAssembly::Instance>,
    variant: MldsaVariant,
}

impl MldsaWasmLoader {
    /// Create a new WASM loader for the specified ML-DSA variant
    pub fn new(variant: MldsaVariant) -> Self {
        Self {
            module: None,
            variant,
        }
    }

    /// Load the WASM module for the specified variant
    pub async fn load_module(&mut self) -> Result<(), JsValue> {
        let filename = self.variant.wasm_filename();
        let base_path = "/pqwasm/refimp/";
        let full_path = if base_path.ends_with('/') {
            format!("{}{}", base_path, filename)
        } else {
            format!("{}/{}", base_path, filename)
        };

        // Fetch and instantiate the WASM module
        let instance = self.fetch_and_instantiate(&full_path).await?;
        self.module = Some(instance);
        Ok(())
    }

    /// Fetch and instantiate a WASM module
    async fn fetch_and_instantiate(&self, url: &str) -> Result<WebAssembly::Instance, JsValue> {
        // Create a fetch request
        let opts = RequestInit::new();
        opts.set_method("GET");
        opts.set_mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(url, &opts)?;

        // Fetch the WASM file
        let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window found"))?;
        let fetch_promise = window.fetch_with_request(&request);

        // Convert to async/await
        let response: Response = wasm_bindgen_futures::JsFuture::from(fetch_promise)
            .await?
            .dyn_into()?;

        if !response.ok() {
            return Err(JsValue::from_str(&format!(
                "Failed to fetch WASM file: {}",
                response.status()
            )));
        }

        // Get the response as an array buffer
        let array_buffer_promise = response.array_buffer()?;
        let array_buffer: js_sys::ArrayBuffer =
            wasm_bindgen_futures::JsFuture::from(array_buffer_promise)
                .await?
                .dyn_into()?;

        // Convert to Uint8Array and then to &[u8]
        let wasm_bytes = Uint8Array::new(&array_buffer);
        let wasm_slice = wasm_bytes.to_vec();

        // Instantiate the WASM module
        let instantiate_promise =
            WebAssembly::instantiate_buffer(&wasm_slice, &js_sys::Object::new());
        let result = wasm_bindgen_futures::JsFuture::from(instantiate_promise).await?;

        // Extract the instance
        let instance = Reflect::get(&result, &"instance".into())?;
        let instance: WebAssembly::Instance = instance.dyn_into()?;

        Ok(instance)
    }

    /// Check if the module is loaded
    pub fn is_loaded(&self) -> bool {
        self.module.is_some()
    }

    /// Get the loaded module
    pub fn get_module(&self) -> Option<&WebAssembly::Instance> {
        self.module.as_ref()
    }

    /// Call the key generation function on the loaded WASM module
    pub fn call_keygen(&self, pk: &mut [u8], sk: &mut [u8]) -> Result<i32, JsValue> {
        let module = self
            .module
            .as_ref()
            .ok_or_else(|| JsValue::from_str("WASM module not loaded"))?;

        // Get the crypto_sign_keypair function
        let keygen_func = Reflect::get(module, &"crypto_sign_keypair".into())?;
        let keygen_func: js_sys::Function = keygen_func.dyn_into()?;

        // Create Uint8Array views for the output buffers
        let pk_array = unsafe { Uint8Array::view(pk) };
        let sk_array = unsafe { Uint8Array::view(sk) };

        // Call the function
        let result = keygen_func.call2(module, &pk_array.into(), &sk_array.into())?;
        let result: i32 = result.as_f64().unwrap_or(0.0) as i32;

        Ok(result)
    }

    /// Call the signing function on the loaded WASM module
    pub fn call_sign(
        &self,
        sm: &mut [u8],
        smlen: &mut [u8],
        msg: &[u8],
        sk: &[u8],
    ) -> Result<i32, JsValue> {
        let module = self
            .module
            .as_ref()
            .ok_or_else(|| JsValue::from_str("WASM module not loaded"))?;

        // Get the crypto_sign function
        let sign_func = Reflect::get(module, &"crypto_sign".into())?;
        let sign_func: js_sys::Function = sign_func.dyn_into()?;

        // Create Uint8Array views for the buffers
        let sm_array = unsafe { Uint8Array::view(sm) };
        let smlen_array = unsafe { Uint8Array::view(smlen) };
        let msg_array = unsafe { Uint8Array::view(msg) };
        let sk_array = unsafe { Uint8Array::view(sk) };

        // Call the function using apply with an array of arguments
        let args = js_sys::Array::new();
        args.push(&sm_array.into());
        args.push(&smlen_array.into());
        args.push(&msg_array.into());
        args.push(&sk_array.into());

        let result = sign_func.apply(&wasm_bindgen::JsValue::NULL, &args)?;
        let result: i32 = result.as_f64().unwrap_or(0.0) as i32;

        Ok(result)
    }

    /// Call the verification function on the loaded WASM module
    pub fn call_verify(
        &self,
        m: &mut [u8],
        mlen: &mut [u8],
        sm: &[u8],
        pk: &[u8],
    ) -> Result<i32, JsValue> {
        let module = self
            .module
            .as_ref()
            .ok_or_else(|| JsValue::from_str("WASM module not loaded"))?;

        // Get the crypto_sign_open function
        let verify_func = Reflect::get(module, &"crypto_sign_open".into())?;
        let verify_func: js_sys::Function = verify_func.dyn_into()?;

        // Create Uint8Array views for the buffers
        let m_array = unsafe { Uint8Array::view(m) };
        let mlen_array = unsafe { Uint8Array::view(mlen) };
        let sm_array = unsafe { Uint8Array::view(sm) };
        let pk_array = unsafe { Uint8Array::view(pk) };

        // Call the function using apply with an array of arguments
        let args = js_sys::Array::new();
        args.push(&m_array.into());
        args.push(&mlen_array.into());
        args.push(&sm_array.into());
        args.push(&pk_array.into());

        let result = verify_func.apply(&wasm_bindgen::JsValue::NULL, &args)?;
        let result: i32 = result.as_f64().unwrap_or(0.0) as i32;

        Ok(result)
    }
}

/// Generate a new ML-DSA keypair using the NIST reference implementation
#[wasm_bindgen]
pub async fn nist_mldsa_keygen(variant: &str) -> Result<NistMldsaKeyPair, JsValue> {
    let variant_enum = match variant {
        "ML-DSA-2" | "mldsa2" | "ml-dsa2" => MldsaVariant::MLDSA2,
        "ML-DSA-3" | "mldsa3" | "ml-dsa3" => MldsaVariant::MLDSA3,
        "ML-DSA-5" | "mldsa5" | "ml-dsa5" => MldsaVariant::MLDSA5,
        "ML-DSA-2-AES" | "mldsa2aes" | "ml-dsa2-aes" => MldsaVariant::MLDSA2AES,
        "ML-DSA-3-AES" | "mldsa3aes" | "ml-dsa3-aes" => MldsaVariant::MLDSA3AES,
        "ML-DSA-5-AES" | "mldsa5aes" | "ml-dsa5-aes" => MldsaVariant::MLDSA5AES,
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unsupported ML-DSA variant: {}",
                variant
            )));
        }
    };

    // Create and load the WASM loader
    let mut loader = MldsaWasmLoader::new(variant_enum);
    loader.load_module().await?;

    // Allocate buffers for the keypair
    let pk_len = variant_enum.public_key_length();
    let sk_len = variant_enum.secret_key_length();
    let mut pk = vec![0u8; pk_len];
    let mut sk = vec![0u8; sk_len];

    // Call the key generation function
    let result = loader.call_keygen(&mut pk, &mut sk)?;
    if result != 0 {
        return Err(JsValue::from_str(&format!(
            "Key generation failed with error code: {}",
            result
        )));
    }

    Ok(NistMldsaKeyPair { pk, sk })
}

/// Sign a message using the NIST reference ML-DSA implementation
#[wasm_bindgen]
pub async fn nist_mldsa_sign(
    variant: &str,
    secret_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let variant_enum = match variant {
        "ML-DSA-2" | "mldsa2" | "ml-dsa2" => MldsaVariant::MLDSA2,
        "ML-DSA-3" | "mldsa3" | "ml-dsa3" => MldsaVariant::MLDSA3,
        "ML-DSA-5" | "mldsa5" | "ml-dsa5" => MldsaVariant::MLDSA5,
        "ML-DSA-2-AES" | "mldsa2aes" | "ml-dsa2-aes" => MldsaVariant::MLDSA2AES,
        "ML-DSA-3-AES" | "mldsa3aes" | "ml-dsa3-aes" => MldsaVariant::MLDSA3AES,
        "ML-DSA-5-AES" | "mldsa5aes" | "ml-dsa5-aes" => MldsaVariant::MLDSA5AES,
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unsupported ML-DSA variant: {}",
                variant
            )));
        }
    };

    // Validate secret key length
    if secret_key.len() != variant_enum.secret_key_length() {
        return Err(JsValue::from_str(&format!(
            "Invalid secret key length. Expected {} bytes, got {} bytes",
            variant_enum.secret_key_length(),
            secret_key.len()
        )));
    }

    // Create and load the WASM loader
    let mut loader = MldsaWasmLoader::new(variant_enum);
    loader.load_module().await?;

    // Allocate buffers for the signature output
    // The signature includes both the signature and the message
    let sig_len = variant_enum.signature_length();
    let total_len = sig_len + message.len();
    let mut sm = vec![0u8; total_len];
    let mut smlen = vec![0u8; 8]; // 8 bytes for length

    // Call the signing function
    let result = loader.call_sign(&mut sm, &mut smlen, message, secret_key)?;
    if result != 0 {
        return Err(JsValue::from_str(&format!(
            "Signing failed with error code: {}",
            result
        )));
    }

    // Extract the actual signature length from smlen
    let _actual_len = if smlen.len() >= 8 {
        u64::from_le_bytes([
            smlen[0], smlen[1], smlen[2], smlen[3], smlen[4], smlen[5], smlen[6], smlen[7],
        ]) as usize
    } else {
        total_len
    };

    // Return the signature (first sig_len bytes)
    Ok(sm[..sig_len].to_vec())
}

/// Verify a signature using the NIST reference ML-DSA implementation
#[wasm_bindgen]
pub async fn nist_mldsa_verify(
    variant: &str,
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<bool, JsValue> {
    let variant_enum = match variant {
        "ML-DSA-2" | "mldsa2" | "ml-dsa2" => MldsaVariant::MLDSA2,
        "ML-DSA-3" | "mldsa3" | "ml-dsa3" => MldsaVariant::MLDSA3,
        "ML-DSA-5" | "mldsa5" | "ml-dsa5" => MldsaVariant::MLDSA5,
        "ML-DSA-2-AES" | "mldsa2aes" | "ml-dsa2-aes" => MldsaVariant::MLDSA2AES,
        "ML-DSA-3-AES" | "mldsa3aes" | "ml-dsa3-aes" => MldsaVariant::MLDSA3AES,
        "ML-DSA-5-AES" | "mldsa5aes" | "ml-dsa5-aes" => MldsaVariant::MLDSA5AES,
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unsupported ML-DSA variant: {}",
                variant
            )));
        }
    };

    // Validate public key length
    if public_key.len() != variant_enum.public_key_length() {
        return Err(JsValue::from_str(&format!(
            "Invalid public key length. Expected {} bytes, got {} bytes",
            variant_enum.public_key_length(),
            public_key.len()
        )));
    }

    // Validate signature length
    if signature.len() != variant_enum.signature_length() {
        return Err(JsValue::from_str(&format!(
            "Invalid signature length. Expected {} bytes, got {} bytes",
            variant_enum.signature_length(),
            signature.len()
        )));
    }

    // Create and load the WASM loader
    let mut loader = MldsaWasmLoader::new(variant_enum);
    loader.load_module().await?;

    // Allocate buffers for the verification output
    let mut m = vec![0u8; message.len()];
    let mut mlen = vec![0u8; 8]; // 8 bytes for length

    // Create the signed message (signature + message)
    let mut sm = Vec::new();
    sm.extend_from_slice(signature);
    sm.extend_from_slice(message);

    // Call the verification function
    let result = loader.call_verify(&mut m, &mut mlen, &sm, public_key)?;

    // Return true if verification succeeded (result == 0), false otherwise
    Ok(result == 0)
}

/// Get information about the supported ML-DSA variants
#[wasm_bindgen]
pub fn nist_mldsa_variants() -> JsValue {
    let variants = js_sys::Array::new();

    let mldsa2 = Object::new();
    Reflect::set(&mldsa2, &"name".into(), &"ML-DSA-2".into()).unwrap();
    Reflect::set(&mldsa2, &"public_key_length".into(), &(1312u32).into()).unwrap();
    Reflect::set(&mldsa2, &"secret_key_length".into(), &(2544u32).into()).unwrap();
    Reflect::set(&mldsa2, &"signature_length".into(), &(2420u32).into()).unwrap();
    Reflect::set(&mldsa2, &"hash_function".into(), &"SHAKE-256".into()).unwrap();
    variants.push(&mldsa2);

    let mldsa3 = Object::new();
    Reflect::set(&mldsa3, &"name".into(), &"ML-DSA-3".into()).unwrap();
    Reflect::set(&mldsa3, &"public_key_length".into(), &(1952u32).into()).unwrap();
    Reflect::set(&mldsa3, &"secret_key_length".into(), &(4016u32).into()).unwrap();
    Reflect::set(&mldsa3, &"signature_length".into(), &(3293u32).into()).unwrap();
    Reflect::set(&mldsa3, &"hash_function".into(), &"SHAKE-256".into()).unwrap();
    variants.push(&mldsa3);

    let mldsa5 = Object::new();
    Reflect::set(&mldsa5, &"name".into(), &"ML-DSA-5".into()).unwrap();
    Reflect::set(&mldsa5, &"public_key_length".into(), &(2592u32).into()).unwrap();
    Reflect::set(&mldsa5, &"secret_key_length".into(), &(4880u32).into()).unwrap();
    Reflect::set(&mldsa5, &"signature_length".into(), &(4595u32).into()).unwrap();
    Reflect::set(&mldsa5, &"hash_function".into(), &"SHAKE-256".into()).unwrap();
    variants.push(&mldsa5);

    let mldsa2aes = Object::new();
    Reflect::set(&mldsa2aes, &"name".into(), &"ML-DSA-2-AES".into()).unwrap();
    Reflect::set(&mldsa2aes, &"public_key_length".into(), &(1312u32).into()).unwrap();
    Reflect::set(&mldsa2aes, &"secret_key_length".into(), &(2544u32).into()).unwrap();
    Reflect::set(&mldsa2aes, &"signature_length".into(), &(2420u32).into()).unwrap();
    Reflect::set(&mldsa2aes, &"hash_function".into(), &"AES-256".into()).unwrap();
    variants.push(&mldsa2aes);

    let mldsa3aes = Object::new();
    Reflect::set(&mldsa3aes, &"name".into(), &"ML-DSA-3-AES".into()).unwrap();
    Reflect::set(&mldsa3aes, &"public_key_length".into(), &(1952u32).into()).unwrap();
    Reflect::set(&mldsa3aes, &"secret_key_length".into(), &(4016u32).into()).unwrap();
    Reflect::set(&mldsa3aes, &"signature_length".into(), &(3293u32).into()).unwrap();
    Reflect::set(&mldsa3aes, &"hash_function".into(), &"AES-256".into()).unwrap();
    variants.push(&mldsa3aes);

    let mldsa5aes = Object::new();
    Reflect::set(&mldsa5aes, &"name".into(), &"ML-DSA-5-AES".into()).unwrap();
    Reflect::set(&mldsa5aes, &"public_key_length".into(), &(2592u32).into()).unwrap();
    Reflect::set(&mldsa5aes, &"secret_key_length".into(), &(4880u32).into()).unwrap();
    Reflect::set(&mldsa5aes, &"signature_length".into(), &(4595u32).into()).unwrap();
    Reflect::set(&mldsa5aes, &"hash_function".into(), &"AES-256".into()).unwrap();
    variants.push(&mldsa5aes);

    variants.into()
}
