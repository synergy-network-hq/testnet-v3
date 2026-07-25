//! mlkem-specific trait implementations.

use crate::traits::{ Kem, KemError, Algorithm };
use crate::mlkem::mlkem_keygen;
#[cfg(target_arch = "wasm32")]
use crate::mlkem::{ mlkem_encapsulate, mlkem_decapsulate };
#[cfg(not(target_arch = "wasm32"))]
use crate::mlkem::{ mlkem768_encapsulate_native, mlkem768_decapsulate_native };
use zeroize::Zeroize;
use std::vec::Vec;

/// mlkem 768 implementation of the KEM trait.
pub struct mlkem768;

/// mlkem public key wrapper.
#[derive(Clone)]
pub struct mlkemPublicKey(pub Vec<u8>);

/// mlkem secret key wrapper.
#[derive(Clone)]
pub struct mlkemSecretKey(pub Vec<u8>);

/// mlkem ciphertext wrapper.
#[derive(Clone)]
pub struct mlkemCiphertext(pub Vec<u8>);

/// mlkem shared secret wrapper.
#[derive(Clone)]
pub struct mlkemSharedSecret(pub Vec<u8>);

impl AsRef<[u8]> for mlkemPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for mlkemSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for mlkemCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for mlkemSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl mlkemSharedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for mlkemSecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for mlkemSharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Algorithm for mlkem768 {
    fn name() -> &'static str {
        "mlkem768"
    }

    fn security_level() -> usize {
        192
    }
}

impl Kem for mlkem768 {
    type PublicKey = mlkemPublicKey;
    type SecretKey = mlkemSecretKey;
    type Ciphertext = mlkemCiphertext;
    type SharedSecret = mlkemSharedSecret;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey), KemError> {
        let keypair = mlkem_keygen();
        Ok((mlkemPublicKey(keypair.public_key()), mlkemSecretKey(keypair.secret_key())))
    }

    fn encapsulate(
        public_key: &Self::PublicKey
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError> {
        #[cfg(target_arch = "wasm32")]
        {
            match mlkem_encapsulate(&public_key.0) {
                Ok(encapsulated) =>
                    Ok((
                        mlkemCiphertext(encapsulated.ciphertext()),
                        mlkemSharedSecret(encapsulated.shared_secret()),
                    )),
                Err(_) => Err(KemError::EncapsulationFailed),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            match mlkem768_encapsulate_native(&public_key.0) {
                Ok(encapsulated) =>
                    Ok((
                        mlkemCiphertext(encapsulated.ciphertext()),
                        mlkemSharedSecret(encapsulated.shared_secret()),
                    )),
                Err(_) => Err(KemError::EncapsulationFailed),
            }
        }
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &[u8]
    ) -> Result<Self::SharedSecret, KemError> {
        #[cfg(target_arch = "wasm32")]
        {
            match mlkem_decapsulate(&secret_key.0, ciphertext) {
                Ok(shared_secret) => Ok(mlkemSharedSecret(shared_secret)),
                Err(_) => Err(KemError::DecapsulationFailed),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            match mlkem768_decapsulate_native(&secret_key.0, ciphertext) {
                Ok(shared_secret) => Ok(mlkemSharedSecret(shared_secret)),
                Err(_) => Err(KemError::DecapsulationFailed),
            }
        }
    }
}
