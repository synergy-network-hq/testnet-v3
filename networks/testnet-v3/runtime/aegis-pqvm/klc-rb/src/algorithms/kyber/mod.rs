//! This module provides the mlkem post-quantum key encapsulation mechanism (KEM)
//! implementation. It uses the `pqrust-mlkem` backend for cryptographic
//! operations and exposes key functions as WebAssembly (WASM) bindings for use
//! in JavaScript/TypeScript environments.

pub mod traits;

use pqrust_mlkem::{
    mlkem512::{keypair as keypair512, encapsulate as encapsulate512, decapsulate as decapsulate512, PublicKey as PublicKey512, SecretKey as SecretKey512, Ciphertext as Ciphertext512, SharedSecret as SharedSecret512},
    mlkem768::{keypair as keypair768, encapsulate as encapsulate768, decapsulate as decapsulate768, PublicKey as PublicKey768, SecretKey as SecretKey768, Ciphertext as Ciphertext768, SharedSecret as SharedSecret768},
    mlkem1024::{keypair as keypair1024, encapsulate as encapsulate1024, decapsulate as decapsulate1024, PublicKey as PublicKey1024, SecretKey as SecretKey1024, Ciphertext as Ciphertext1024, SharedSecret as SharedSecret1024},
};
// Note: pqrust_traits doesn't export Error/Result, using standard types

pub type mlkem512PublicKey = PublicKey512;
pub type mlkem512SecretKey = SecretKey512;
pub type mlkem512Ciphertext = Ciphertext512;
pub type mlkem512SharedSecret = SharedSecret512;

pub type mlkem768PublicKey = PublicKey768;
pub type mlkem768SecretKey = SecretKey768;
pub type mlkem768Ciphertext = Ciphertext768;
pub type mlkem768SharedSecret = SharedSecret768;

pub type mlkem1024PublicKey = PublicKey1024;
pub type mlkem1024SecretKey = SecretKey1024;
pub type mlkem1024Ciphertext = Ciphertext1024;
pub type mlkem1024SharedSecret = SharedSecret1024;

// Dedicated functions for each level
pub fn mlkem512_keypair() -> (mlkem512PublicKey, mlkem512SecretKey) {
    keypair512()
}

pub fn mlkem512_encapsulate(pk: &mlkem512PublicKey) -> (mlkem512Ciphertext, mlkem512SharedSecret) {
    encapsulate512(pk)
}

pub fn mlkem512_decapsulate(sk: &mlkem512SecretKey, ct: &mlkem512Ciphertext) -> mlkem512SharedSecret {
    decapsulate512(sk, ct)
}

// Similar for 768 and 1024
pub fn mlkem768_keypair() -> (mlkem768PublicKey, mlkem768SecretKey) {
    keypair768()
}

pub fn mlkem768_encapsulate(pk: &mlkem768PublicKey) -> (mlkem768Ciphertext, mlkem768SharedSecret) {
    encapsulate768(pk)
}

pub fn mlkem768_decapsulate(sk: &mlkem768SecretKey, ct: &mlkem768Ciphertext) -> mlkem768SharedSecret {
    decapsulate768(sk, ct)
}

pub fn mlkem1024_keypair() -> (mlkem1024PublicKey, mlkem1024SecretKey) {
    keypair1024()
}

pub fn mlkem1024_encapsulate(pk: &mlkem1024PublicKey) -> (mlkem1024Ciphertext, mlkem1024SharedSecret) {
    encapsulate1024(pk)
}

pub fn mlkem1024_decapsulate(sk: &mlkem1024SecretKey, ct: &mlkem1024Ciphertext) -> mlkem1024SharedSecret {
    decapsulate1024(sk, ct)
}

// Avoid trait-based conversions to prevent dup trait crate issues in benches
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Represents a mlkem key pair, containing both the public and secret keys.
/// These keys are essential for performing cryptographic operations such as
/// encapsulating and decapsulating shared secrets.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct mlkemKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl mlkemKeyPair {
    /// Returns the public key component of the mlkem key pair.
    /// The public key is used by the sender to encapsulate a shared secret.
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }

    /// Returns the secret key component of the mlkem key pair.
    /// The secret key is used by the recipient to decapsulate the shared secret.
    /// It should be kept confidential.
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn secret_key(&self) -> Vec<u8> {
        self.sk.clone()
    }
}

/// Represents the output of the mlkem encapsulation process, containing
/// both the ciphertext and the encapsulated shared secret.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct mlkemEncapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl mlkemEncapsulated {
    /// Returns the ciphertext generated during encapsulation.
    /// This ciphertext is sent to the recipient for decapsulation.
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    /// Returns the shared secret derived during encapsulation.
    /// This secret is used for symmetric encryption.
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

// Legacy functions (for backward compatibility - default to ML-KEM-768)
/// Generates a new mlkem key pair (ML-KEM-768).
///
/// This function uses the `pqrust-mlkem` backend to generate a fresh
/// public and secret key pair for the mlkem KEM scheme.
///
/// # Returns
///
/// A `mlkemKeyPair` containing the newly generated public and secret keys.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mlkem_keygen() -> mlkemKeyPair {
    let (pk, sk) = mlkem768_keypair();
    mlkemKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

/// Encapsulates a shared secret using the provided mlkem public key (ML-KEM-768).
///
/// This function takes a recipient's public key and generates a ciphertext
/// and a shared secret. The ciphertext is sent to the recipient, who can
/// then decapsulate it to recover the same shared secret.
///
/// # Arguments
///
/// * `public_key` - A byte slice representing the recipient's mlkem public key.
///
/// # Returns
///
/// A `Result<mlkemEncapsulated, Box<dyn std::error::Error>>` which is:
/// - `Ok(mlkemEncapsulated)` containing the generated ciphertext and shared secret.
/// - `Err(JsValue)` if the public key is invalid.
pub fn mlkem_encapsulate(public_key: &[u8]) -> Result<mlkemEncapsulated, Box<dyn std::error::Error>> {
    use pqrust_traits::kem::PublicKey as _;
    let pk = mlkem768PublicKey::from_bytes(public_key)
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)) as Box<dyn std::error::Error>)?;
    let (ct, ss) = mlkem768_encapsulate(&pk);
    Ok(mlkemEncapsulated {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

/// Decapsulates a shared secret using the provided mlkem secret key and ciphertext (ML-KEM-768).
///
/// This function takes a recipient's secret key and a ciphertext from the sender,
/// and recovers the shared secret that was encapsulated.
///
/// # Arguments
///
/// * `secret_key` - A byte slice representing the recipient's mlkem secret key.
/// * `ciphertext` - A byte slice representing the ciphertext from the sender.
///
/// # Returns
///
/// A `Result<Vec<u8>, Box<dyn std::error::Error>>` which is:
/// - `Ok(Vec<u8>)` containing the recovered shared secret.
/// - `Err(JsValue)` if the secret key or ciphertext is invalid.
pub fn mlkem_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use pqrust_traits::kem::{SecretKey as _, Ciphertext as _, SharedSecret as _};
    let sk = mlkem768SecretKey::from_bytes(secret_key)
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)) as Box<dyn std::error::Error>)?;
    let ct = mlkem768Ciphertext::from_bytes(ciphertext)
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)) as Box<dyn std::error::Error>)?;
    let ss = mlkem768_decapsulate(&sk, &ct);
    Ok(ss.as_bytes().to_vec())
}

// Native functions (for testing and non-WASM environments)
#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem512_keygen_native() -> mlkemKeyPair {
    let (pk, sk) = mlkem512_keypair();
    mlkemKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem512_encapsulate_native(public_key: &[u8]) -> Result<mlkemEncapsulated, String> {
    let pk = mlkem512PublicKey::from_bytes(public_key)
        .map_err(|_| "Invalid public key format".to_string())?;
    let (ss, ct) = mlkem512_encapsulate(&pk)
        .map_err(|e| e.to_string())?;
    Ok(mlkemEncapsulated {
        ciphertext: ct.into(),
        shared_secret: ss.into(),
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem512_decapsulate_native(
    secret_key: &[u8],
    ciphertext: &[u8]
) -> Result<Vec<u8>, String> {
    let sk = mlkem512SecretKey::from_bytes(secret_key)
        .map_err(|_| "Invalid secret key format".to_string())?;
    let ct = mlkem512Ciphertext::from_bytes(ciphertext)
        .map_err(|_| "Invalid ciphertext format".to_string())?;
    let ss = mlkem512_decapsulate(&sk, &ct)
        .map_err(|e| e.to_string())?;
    Ok(ss.into())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem768_keygen_native() -> mlkemKeyPair {
    let (pk, sk) = mlkem768_keypair();
    mlkemKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem768_encapsulate_native(public_key: &[u8]) -> Result<mlkemEncapsulated, String> {
    use pqrust_mlkem::mlkem768 as m768;
    use pqrust_mlkem::ffi as ffi768;

    if public_key.len() != m768::public_key_bytes() {
        return Err(format!(
            "Invalid public key length: got {}, expected {}",
            public_key.len(),
            m768::public_key_bytes()
        ));
    }

    let mut ct = vec![0u8; m768::ciphertext_bytes()];
    let mut ss = vec![0u8; m768::shared_secret_bytes()];

    let rc = unsafe {
        ffi768::PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(
            ct.as_mut_ptr(),
            ss.as_mut_ptr(),
            public_key.as_ptr(),
        )
    };
    if rc != 0 {
        return Err("encapsulation failed".to_string());
    }

    Ok(mlkemEncapsulated { ciphertext: ct, shared_secret: ss })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem768_decapsulate_native(
    secret_key: &[u8],
    ciphertext: &[u8]
) -> Result<Vec<u8>, String> {
    use pqrust_mlkem::mlkem768 as m768;
    use pqrust_mlkem::ffi as ffi768;

    if secret_key.len() != m768::secret_key_bytes() {
        return Err(format!(
            "Invalid secret key length: got {}, expected {}",
            secret_key.len(),
            m768::secret_key_bytes()
        ));
    }
    if ciphertext.len() != m768::ciphertext_bytes() {
        return Err(format!(
            "Invalid ciphertext length: got {}, expected {}",
            ciphertext.len(),
            m768::ciphertext_bytes()
        ));
    }

    let mut ss = vec![0u8; m768::shared_secret_bytes()];
    let rc = unsafe {
        ffi768::PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
            ss.as_mut_ptr(),
            ciphertext.as_ptr(),
            secret_key.as_ptr(),
        )
    };
    if rc != 0 {
        return Err("decapsulation failed".to_string());
    }
    Ok(ss)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem1024_keygen_native() -> mlkemKeyPair {
    let (pk, sk) = mlkem1024_keypair();
    mlkemKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem1024_encapsulate_native(public_key: &[u8]) -> Result<mlkemEncapsulated, String> {
    let pk = mlkem1024PublicKey::from_bytes(public_key)
        .map_err(|_| "Invalid public key format".to_string())?;
    let (ss, ct) = mlkem1024_encapsulate(&pk)
        .map_err(|e| e.to_string())?;
    Ok(mlkemEncapsulated {
        ciphertext: ct.into(),
        shared_secret: ss.into(),
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem1024_decapsulate_native(
    secret_key: &[u8],
    ciphertext: &[u8]
) -> Result<Vec<u8>, String> {
    let sk = mlkem1024SecretKey::from_bytes(secret_key)
        .map_err(|_| "Invalid secret key format".to_string())?;
    let ct = mlkem1024Ciphertext::from_bytes(ciphertext)
        .map_err(|_| "Invalid ciphertext format".to_string())?;
    let ss = mlkem1024_decapsulate(&sk, &ct)
        .map_err(|e| e.to_string())?;
    Ok(ss.into())
}

// Legacy native functions (for backward compatibility)
#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem_keygen_native() -> mlkemKeyPair {
    mlkem768_keygen_native()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem_encapsulate_native(public_key: &[u8]) -> Result<mlkemEncapsulated, String> {
    mlkem768_encapsulate_native(public_key)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn mlkem_decapsulate_native(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    mlkem768_decapsulate_native(secret_key, ciphertext)
}

pub use traits::*;
