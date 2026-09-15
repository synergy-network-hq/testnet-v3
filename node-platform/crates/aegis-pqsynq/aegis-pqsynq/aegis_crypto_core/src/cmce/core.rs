//! Core Classic McEliece implementation.
//!
//! Provides the core Classic McEliece post-quantum KEM scheme implementation using pqrust.
//! WASM bindings are provided for JavaScript/TypeScript interop.

use wasm_bindgen::prelude::*;
use pqrust_traits::kem::{ PublicKey, SecretKey, Ciphertext, SharedSecret };
use super::utils::*;

#[cfg(not(feature = "std"))]
use alloc::{ vec::Vec, string::{String, ToString} };
#[cfg(feature = "std")]
use std::{ vec::Vec, string::{String, ToString} };

use pqrust_cmce::mceliece348864;
use pqrust_cmce::mceliece460896;
use pqrust_cmce::mceliece6688128;

// Generic (non-WASM) structs
pub struct ClassicMcElieceKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl ClassicMcElieceKeyPair {
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self { public_key, secret_key }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}

pub struct ClassicMcElieceEncapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

impl ClassicMcElieceEncapsulated {
    pub fn new(ciphertext: Vec<u8>, shared_secret: Vec<u8>) -> Self {
        Self { ciphertext, shared_secret }
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}


/// Classic McEliece 128-bit security key pair.
#[wasm_bindgen]
pub struct ClassicMcEliece128KeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl ClassicMcEliece128KeyPair {
    /// Returns the public key bytes.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    /// Returns the secret key bytes.
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
    /// Public key length.
    #[wasm_bindgen]
    pub fn public_key_length(&self) -> usize {
        self.public_key.len()
    }
    /// Secret key length.
    #[wasm_bindgen]
    pub fn secret_key_length(&self) -> usize {
        self.secret_key.len()
    }
}

/// Encapsulation result for 128-bit security.
#[wasm_bindgen]
pub struct ClassicMcEliece128Encapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl ClassicMcEliece128Encapsulated {
    /// Returns the ciphertext bytes.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    /// Returns the shared secret bytes.
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
    /// Ciphertext length.
    #[wasm_bindgen]
    pub fn ciphertext_length(&self) -> usize {
        self.ciphertext.len()
    }
    /// Shared secret length.
    #[wasm_bindgen]
    pub fn shared_secret_length(&self) -> usize {
        self.shared_secret.len()
    }
}

/// Classic McEliece 192-bit security key pair.
#[wasm_bindgen]
pub struct ClassicMcEliece192KeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}
#[wasm_bindgen]
impl ClassicMcEliece192KeyPair {
    /// Returns the public key bytes.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    /// Returns the secret key bytes.
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
    /// Public key length.
    #[wasm_bindgen]
    pub fn public_key_length(&self) -> usize {
        self.public_key.len()
    }
    /// Secret key length.
    #[wasm_bindgen]
    pub fn secret_key_length(&self) -> usize {
        self.secret_key.len()
    }
}

/// Encapsulation result for 192-bit security.
#[wasm_bindgen]
pub struct ClassicMcEliece192Encapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl ClassicMcEliece192Encapsulated {
    /// Returns the ciphertext bytes.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    /// Returns the shared secret bytes.
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
    /// Ciphertext length.
    #[wasm_bindgen]
    pub fn ciphertext_length(&self) -> usize {
        self.ciphertext.len()
    }
    /// Shared secret length.
    #[wasm_bindgen]
    pub fn shared_secret_length(&self) -> usize {
        self.shared_secret.len()
    }
}

/// Classic McEliece 256-bit security key pair.
#[wasm_bindgen]
pub struct ClassicMcEliece256KeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl ClassicMcEliece256KeyPair {
    /// Returns the public key bytes.
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    /// Returns the secret key bytes.
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
    /// Public key length.
    #[wasm_bindgen]
    pub fn public_key_length(&self) -> usize {
        self.public_key.len()
    }
    /// Secret key length.
    #[wasm_bindgen]
    pub fn secret_key_length(&self) -> usize {
        self.secret_key.len()
    }
}

/// Encapsulation result for 256-bit security.
#[wasm_bindgen]
pub struct ClassicMcEliece256Encapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl ClassicMcEliece256Encapsulated {
    /// Returns the ciphertext bytes.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    /// Returns the shared secret bytes.
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
    /// Ciphertext length.
    #[wasm_bindgen]
    pub fn ciphertext_length(&self) -> usize {
        self.ciphertext.len()
    }
    /// Shared secret length.
    #[wasm_bindgen]
    pub fn shared_secret_length(&self) -> usize {
        self.shared_secret.len()
    }
}

// ---- WASM Bindings ----

/// Generates a Classic McEliece 128-bit security key pair.
#[wasm_bindgen]
pub fn classicmceliece128_keygen() -> Result<ClassicMcEliece128KeyPair, JsValue> {
    let keypair = classicmceliece128_keygen_native().map_err(|e| JsValue::from_str(&e))?;
    Ok(ClassicMcEliece128KeyPair {
        public_key: keypair.public_key().to_vec(),
        secret_key: keypair.secret_key().to_vec(),
    })
}

/// Encapsulates a shared secret using a Classic McEliece 128-bit public key.
#[wasm_bindgen]
pub fn classicmceliece128_encapsulate(public_key: &[u8]) -> Result<ClassicMcEliece128Encapsulated, JsValue> {
    let encapsulated = classicmceliece128_encapsulate_native(public_key).map_err(|e| JsValue::from_str(&e))?;
    Ok(ClassicMcEliece128Encapsulated {
        ciphertext: encapsulated.ciphertext().to_vec(),
        shared_secret: encapsulated.shared_secret().to_vec(),
    })
}

/// Decapsulates a shared secret using a Classic McEliece 128-bit secret key.
#[wasm_bindgen]
pub fn classicmceliece128_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    classicmceliece128_decapsulate_native(secret_key, ciphertext).map_err(|e| JsValue::from_str(&e))
}

/// Generates a Classic McEliece 192-bit security key pair.
#[wasm_bindgen]
pub fn classicmceliece192_keygen() -> Result<ClassicMcEliece192KeyPair, JsValue> {
    let keypair = classicmceliece192_keygen_native().map_err(|e| JsValue::from_str(&e))?;
    Ok(ClassicMcEliece192KeyPair {
        public_key: keypair.public_key().to_vec(),
        secret_key: keypair.secret_key().to_vec(),
    })
}

/// Encapsulates a shared secret using a Classic McEliece 192-bit public key.
#[wasm_bindgen]
pub fn classicmceliece192_encapsulate(public_key: &[u8]) -> Result<ClassicMcEliece192Encapsulated, JsValue> {
    let encapsulated = classicmceliece192_encapsulate_native(public_key).map_err(|e| JsValue::from_str(&e))?;
    Ok(ClassicMcEliece192Encapsulated {
        ciphertext: encapsulated.ciphertext().to_vec(),
        shared_secret: encapsulated.shared_secret().to_vec(),
    })
}

/// Decapsulates a shared secret using a Classic McEliece 192-bit secret key.
#[wasm_bindgen]
pub fn classicmceliece192_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    classicmceliece192_decapsulate_native(secret_key, ciphertext).map_err(|e| JsValue::from_str(&e))
}

/// Generates a Classic McEliece 256-bit security key pair.
#[wasm_bindgen]
pub fn classicmceliece256_keygen() -> Result<ClassicMcEliece256KeyPair, JsValue> {
    let keypair = classicmceliece256_keygen_native().map_err(|e| JsValue::from_str(&e))?;
    Ok(ClassicMcEliece256KeyPair {
        public_key: keypair.public_key().to_vec(),
        secret_key: keypair.secret_key().to_vec(),
    })
}

/// Encapsulates a shared secret using a Classic McEliece 256-bit public key.
#[wasm_bindgen]
pub fn classicmceliece256_encapsulate(public_key: &[u8]) -> Result<ClassicMcEliece256Encapsulated, JsValue> {
    let encapsulated = classicmceliece256_encapsulate_native(public_key).map_err(|e| JsValue::from_str(&e))?;
    Ok(ClassicMcEliece256Encapsulated {
        ciphertext: encapsulated.ciphertext().to_vec(),
        shared_secret: encapsulated.shared_secret().to_vec(),
    })
}

/// Decapsulates a shared secret using a Classic McEliece 256-bit secret key.
#[wasm_bindgen]
pub fn classicmceliece256_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    classicmceliece256_decapsulate_native(secret_key, ciphertext).map_err(|e| JsValue::from_str(&e))
}

// ---- Native KEM functions ----

/// Generates a Classic McEliece 128-bit security key pair (native version).
pub fn classicmceliece128_keygen_native() -> Result<ClassicMcElieceKeyPair, String> {
    let (pk, sk) = mceliece348864::keypair();
    Ok(ClassicMcElieceKeyPair::new(pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

/// Encapsulates a shared secret using a Classic McEliece 128-bit public key (native version).
pub fn classicmceliece128_encapsulate_native(public_key: &[u8]) -> Result<ClassicMcElieceEncapsulated, String> {
    validate_public_key_length_128(public_key)?;
    let pk = mceliece348864::PublicKey::from_bytes(public_key).map_err(|_| "Invalid public key".to_string())?;
    let (ss, ct) = mceliece348864::encapsulate(&pk);
    Ok(ClassicMcElieceEncapsulated::new(ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

/// Decapsulates a shared secret using a Classic McEliece 128-bit secret key (native version).
pub fn classicmceliece128_decapsulate_native(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    validate_secret_key_length_128(secret_key)?;
    validate_ciphertext_length_128(ciphertext)?;
    let sk = mceliece348864::SecretKey::from_bytes(secret_key).map_err(|_| "Invalid secret key".to_string())?;
    let ct = mceliece348864::Ciphertext::from_bytes(ciphertext).map_err(|_| "Invalid ciphertext".to_string())?;
    let ss = mceliece348864::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

/// Generates a Classic McEliece 192-bit security key pair (native version).
pub fn classicmceliece192_keygen_native() -> Result<ClassicMcElieceKeyPair, String> {
    let (pk, sk) = mceliece460896::keypair();
    Ok(ClassicMcElieceKeyPair::new(pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

/// Encapsulates a shared secret using a Classic McEliece 192-bit public key (native version).
pub fn classicmceliece192_encapsulate_native(public_key: &[u8]) -> Result<ClassicMcElieceEncapsulated, String> {
    validate_public_key_length_192(public_key)?;
    let pk = mceliece460896::PublicKey::from_bytes(public_key).map_err(|_| "Invalid public key".to_string())?;
    let (ss, ct) = mceliece460896::encapsulate(&pk);
    Ok(ClassicMcElieceEncapsulated::new(ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

/// Decapsulates a shared secret using a Classic McEliece 192-bit secret key (native version).
pub fn classicmceliece192_decapsulate_native(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    validate_secret_key_length_192(secret_key)?;
    validate_ciphertext_length_192(ciphertext)?;
    let sk = mceliece460896::SecretKey::from_bytes(secret_key).map_err(|_| "Invalid secret key".to_string())?;
    let ct = mceliece460896::Ciphertext::from_bytes(ciphertext).map_err(|_| "Invalid ciphertext".to_string())?;
    let ss = mceliece460896::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

/// Generates a Classic McEliece 256-bit security key pair (native version).
pub fn classicmceliece256_keygen_native() -> Result<ClassicMcElieceKeyPair, String> {
    let (pk, sk) = mceliece6688128::keypair();
    Ok(ClassicMcElieceKeyPair::new(pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

/// Encapsulates a shared secret using a Classic McEliece 256-bit public key (native version).
pub fn classicmceliece256_encapsulate_native(public_key: &[u8]) -> Result<ClassicMcElieceEncapsulated, String> {
    validate_public_key_length_256(public_key)?;
    let pk = mceliece6688128::PublicKey::from_bytes(public_key).map_err(|_| "Invalid public key".to_string())?;
    let (ss, ct) = mceliece6688128::encapsulate(&pk);
    Ok(ClassicMcElieceEncapsulated::new(ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

/// Decapsulates a shared secret using a Classic McEliece 256-bit secret key (native version).
pub fn classicmceliece256_decapsulate_native(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    validate_secret_key_length_256(secret_key)?;
    validate_ciphertext_length_256(ciphertext)?;
    let sk = mceliece6688128::SecretKey::from_bytes(secret_key).map_err(|_| "Invalid secret key".to_string())?;
    let ct = mceliece6688128::Ciphertext::from_bytes(ciphertext).map_err(|_| "Invalid ciphertext".to_string())?;
    let ss = mceliece6688128::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

/// Test function for Classic McEliece 256-bit KEM, callable from binaries.
/// This function panics if the test fails.
pub fn test_classicmceliece256_encaps_and_decaps() {
    // Generate a recipient key pair
    let keypair = classicmceliece256_keygen_native().expect("keygen 256 failed");
    let public_key = keypair.public_key();
    let secret_key = keypair.secret_key();

    // Encapsulate a shared secret
    let encapsulated = classicmceliece256_encapsulate_native(&public_key).expect("encapsulation 256 should succeed");
    let ciphertext = encapsulated.ciphertext();
    let shared_secret_enc = encapsulated.shared_secret();

    // Decapsulate the shared secret
    let shared_secret_dec = classicmceliece256_decapsulate_native(&secret_key, &ciphertext).expect("decapsulation 256 should succeed");

    assert_eq!(shared_secret_enc, shared_secret_dec, "Shared secrets for 256 should match");

    // Tamper with ciphertext
    let mut tampered_ct = ciphertext.to_vec();
    tampered_ct[0] ^= 0x01;

    // Decapsulation with tampered ciphertext should still succeed but produce a different secret
    let tampered_secret_res = classicmceliece256_decapsulate_native(&secret_key, &tampered_ct);
    assert!(tampered_secret_res.is_ok(), "Decapsulation of tampered ciphertext for 256 should not fail");
    let tampered_secret = tampered_secret_res.unwrap();
    assert_ne!(*shared_secret_enc, tampered_secret, "Decapsulation of tampered ciphertext for 256 should produce a different secret");
}
