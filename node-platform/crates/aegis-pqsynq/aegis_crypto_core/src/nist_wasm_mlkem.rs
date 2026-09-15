//! NIST Reference ML-KEM WASM Implementation
//!
//! This module provides ML-KEM implementations using the NIST reference code
//! compiled to WASM. It dynamically loads the external WASM files and provides
//! a unified interface for all security levels.

use js_sys::{Function, Object, Reflect, Uint8Array, WebAssembly};
use std::vec::Vec;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use web_sys::{Request, RequestInit, RequestMode, Response};

/// Represents an ML-KEM key pair (public and secret keys).
#[wasm_bindgen]
pub struct NistMlkemKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[wasm_bindgen]
impl NistMlkemKeyPair {
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

/// Represents an ML-KEM encapsulated shared secret.
#[wasm_bindgen]
pub struct NistMlkemEncapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl NistMlkemEncapsulated {
    /// Returns the ciphertext as bytes.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    /// Returns the shared secret as bytes.
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

/// ML-KEM security level variants
#[derive(Debug, Clone, Copy)]
pub enum MlkemVariant {
    MLKEM512,
    MLKEM768,
    MLKEM1024,
}

impl MlkemVariant {
    fn wasm_filename(&self) -> &'static str {
        match self {
            MlkemVariant::MLKEM512 => "mlkem512_ref.wasm",
            MlkemVariant::MLKEM768 => "mlkem768_ref.wasm",
            MlkemVariant::MLKEM1024 => "mlkem1024_ref.wasm",
        }
    }

    fn public_key_length(&self) -> usize {
        match self {
            MlkemVariant::MLKEM512 => 800,
            MlkemVariant::MLKEM768 => 1184,
            MlkemVariant::MLKEM1024 => 1568,
        }
    }

    fn secret_key_length(&self) -> usize {
        match self {
            MlkemVariant::MLKEM512 => 1632,
            MlkemVariant::MLKEM768 => 2400,
            MlkemVariant::MLKEM1024 => 3168,
        }
    }

    fn ciphertext_length(&self) -> usize {
        match self {
            MlkemVariant::MLKEM512 => 768,
            MlkemVariant::MLKEM768 => 1088,
            MlkemVariant::MLKEM1024 => 1568,
        }
    }

    fn shared_secret_length(&self) -> usize {
        32 // All ML-KEM variants use 32-byte shared secrets
    }
}

/// WASM module loader for ML-KEM
pub struct MlkemWasmLoader {
    module: Option<WebAssembly::Instance>,
    variant: MlkemVariant,
}

impl MlkemWasmLoader {
    /// Create a new WASM loader for the specified ML-KEM variant
    pub fn new(variant: MlkemVariant) -> Self {
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

        // Get the crypto_kem_keypair function
        let keygen_func = Reflect::get(module, &"crypto_kem_keypair".into())?;
        let keygen_func: Function = keygen_func.dyn_into()?;

        // Create Uint8Array views for the output buffers
        let pk_array = unsafe { Uint8Array::view(pk) };
        let sk_array = unsafe { Uint8Array::view(sk) };

        // Call the function using apply with an array of arguments
        let args = js_sys::Array::new();
        args.push(&pk_array.into());
        args.push(&sk_array.into());

        let result = keygen_func.apply(&wasm_bindgen::JsValue::NULL, &args)?;
        let result: i32 = result.as_f64().unwrap_or(0.0) as i32;

        Ok(result)
    }

    /// Call the encapsulation function on the loaded WASM module
    pub fn call_encapsulate(
        &self,
        ct: &mut [u8],
        ss: &mut [u8],
        pk: &[u8],
    ) -> Result<i32, JsValue> {
        let module = self
            .module
            .as_ref()
            .ok_or_else(|| JsValue::from_str("WASM module not loaded"))?;

        // Get the crypto_kem_enc function
        let enc_func = Reflect::get(module, &"crypto_kem_enc".into())?;
        let enc_func: Function = enc_func.dyn_into()?;

        // Create Uint8Array views for the buffers
        let ct_array = unsafe { Uint8Array::view(ct) };
        let ss_array = unsafe { Uint8Array::view(ss) };
        let pk_array = unsafe { Uint8Array::view(pk) };

        // Call the function using apply with an array of arguments
        let args = js_sys::Array::new();
        args.push(&ct_array.into());
        args.push(&ss_array.into());
        args.push(&pk_array.into());

        let result = enc_func.apply(&wasm_bindgen::JsValue::NULL, &args)?;
        let result: i32 = result.as_f64().unwrap_or(0.0) as i32;

        Ok(result)
    }

    /// Call the decapsulation function on the loaded WASM module
    pub fn call_decapsulate(&self, ss: &mut [u8], ct: &[u8], sk: &[u8]) -> Result<i32, JsValue> {
        let module = self
            .module
            .as_ref()
            .ok_or_else(|| JsValue::from_str("WASM module not loaded"))?;

        // Get the crypto_kem_dec function
        let dec_func = Reflect::get(module, &"crypto_kem_dec".into())?;
        let dec_func: Function = dec_func.dyn_into()?;

        // Create Uint8Array views for the buffers
        let ss_array = unsafe { Uint8Array::view(ss) };
        let ct_array = unsafe { Uint8Array::view(ct) };
        let sk_array = unsafe { Uint8Array::view(sk) };

        // Call the function using apply with an array of arguments
        let args = js_sys::Array::new();
        args.push(&ss_array.into());
        args.push(&ct_array.into());
        args.push(&sk_array.into());

        let result = dec_func.apply(&wasm_bindgen::JsValue::NULL, &args)?;
        let result: i32 = result.as_f64().unwrap_or(0.0) as i32;

        Ok(result)
    }
}

/// Generate a new ML-KEM keypair using the NIST reference implementation
#[wasm_bindgen]
pub async fn nist_mlkem_keygen(variant: &str) -> Result<NistMlkemKeyPair, JsValue> {
    let variant_enum = match variant {
        "ML-KEM-512" | "mlkem512" => MlkemVariant::MLKEM512,
        "ML-KEM-768" | "mlkem768" => MlkemVariant::MLKEM768,
        "ML-KEM-1024" | "mlkem1024" => MlkemVariant::MLKEM1024,
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unsupported ML-KEM variant: {}",
                variant
            )));
        }
    };

    // Create and load the WASM loader
    let mut loader = MlkemWasmLoader::new(variant_enum);
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

    Ok(NistMlkemKeyPair { pk, sk })
}

/// Encapsulate a shared secret using the NIST reference ML-KEM implementation
#[wasm_bindgen]
pub async fn nist_mlkem_encapsulate(
    variant: &str,
    public_key: &[u8],
) -> Result<NistMlkemEncapsulated, JsValue> {
    let variant_enum = match variant {
        "ML-KEM-512" | "mlkem512" => MlkemVariant::MLKEM512,
        "ML-KEM-768" | "mlkem768" => MlkemVariant::MLKEM768,
        "ML-KEM-1024" | "mlkem1024" => MlkemVariant::MLKEM1024,
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unsupported ML-KEM variant: {}",
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

    // Create and load the WASM loader
    let mut loader = MlkemWasmLoader::new(variant_enum);
    loader.load_module().await?;

    // Allocate buffers for the output
    let ct_len = variant_enum.ciphertext_length();
    let ss_len = variant_enum.shared_secret_length();
    let mut ciphertext = vec![0u8; ct_len];
    let mut shared_secret = vec![0u8; ss_len];

    // Call the encapsulation function
    let result = loader.call_encapsulate(&mut ciphertext, &mut shared_secret, public_key)?;
    if result != 0 {
        return Err(JsValue::from_str(&format!(
            "Encapsulation failed with error code: {}",
            result
        )));
    }

    Ok(NistMlkemEncapsulated {
        ciphertext,
        shared_secret,
    })
}

/// Decapsulate a shared secret using the NIST reference ML-KEM implementation
#[wasm_bindgen]
pub async fn nist_mlkem_decapsulate(
    variant: &str,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let variant_enum = match variant {
        "ML-KEM-512" | "mlkem512" => MlkemVariant::MLKEM512,
        "ML-KEM-768" | "mlkem768" => MlkemVariant::MLKEM768,
        "ML-KEM-1024" | "mlkem1024" => MlkemVariant::MLKEM1024,
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unsupported ML-KEM variant: {}",
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

    // Validate ciphertext length
    if ciphertext.len() != variant_enum.ciphertext_length() {
        return Err(JsValue::from_str(&format!(
            "Invalid ciphertext length. Expected {} bytes, got {} bytes",
            variant_enum.ciphertext_length(),
            ciphertext.len()
        )));
    }

    // Create and load the WASM loader
    let mut loader = MlkemWasmLoader::new(variant_enum);
    loader.load_module().await?;

    // Allocate buffer for the shared secret
    let ss_len = variant_enum.shared_secret_length();
    let mut shared_secret = vec![0u8; ss_len];

    // Call the decapsulation function
    let result = loader.call_decapsulate(&mut shared_secret, ciphertext, secret_key)?;
    if result != 0 {
        return Err(JsValue::from_str(&format!(
            "Decapsulation failed with error code: {}",
            result
        )));
    }

    Ok(shared_secret)
}

/// Get information about the supported ML-KEM variants
#[wasm_bindgen]
pub fn nist_mlkem_variants() -> JsValue {
    let variants = js_sys::Array::new();

    let mlkem512 = Object::new();
    Reflect::set(&mlkem512, &"name".into(), &"ML-KEM-512".into()).unwrap();
    Reflect::set(&mlkem512, &"public_key_length".into(), &(800u32).into()).unwrap();
    Reflect::set(&mlkem512, &"secret_key_length".into(), &(1632u32).into()).unwrap();
    Reflect::set(&mlkem512, &"ciphertext_length".into(), &(768u32).into()).unwrap();
    Reflect::set(&mlkem512, &"shared_secret_length".into(), &(32u32).into()).unwrap();
    variants.push(&mlkem512);

    let mlkem768 = Object::new();
    Reflect::set(&mlkem768, &"name".into(), &"ML-KEM-768".into()).unwrap();
    Reflect::set(&mlkem768, &"public_key_length".into(), &(1184u32).into()).unwrap();
    Reflect::set(&mlkem768, &"secret_key_length".into(), &(2400u32).into()).unwrap();
    Reflect::set(&mlkem768, &"ciphertext_length".into(), &(1088u32).into()).unwrap();
    Reflect::set(&mlkem768, &"shared_secret_length".into(), &(32u32).into()).unwrap();
    variants.push(&mlkem768);

    let mlkem1024 = Object::new();
    Reflect::set(&mlkem1024, &"name".into(), &"ML-KEM-1024".into()).unwrap();
    Reflect::set(&mlkem1024, &"public_key_length".into(), &(1568u32).into()).unwrap();
    Reflect::set(&mlkem1024, &"secret_key_length".into(), &(3168u32).into()).unwrap();
    Reflect::set(&mlkem1024, &"ciphertext_length".into(), &(1568u32).into()).unwrap();
    Reflect::set(&mlkem1024, &"shared_secret_length".into(), &(32u32).into()).unwrap();
    variants.push(&mlkem1024);

    variants.into()
}
