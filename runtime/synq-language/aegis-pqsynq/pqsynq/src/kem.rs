//! Key Encapsulation Mechanism adapters.

use crate::error::PqcError;
use crate::traits::KeyEncapsulation;
use crate::utils::check_buffer_size;
use alloc::{format, vec::Vec};

#[cfg(feature = "hqckem")]
use pqrust_hqckem::{hqckem128 as hqc128, hqckem192 as hqc192, hqckem256 as hqc256};
#[cfg(feature = "mlkem")]
use pqrust_mlkem::{mlkem1024, mlkem512, mlkem768};
#[cfg(any(feature = "mlkem", feature = "hqckem"))]
use pqrust_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
#[cfg(all(feature = "hqckem", feature = "std"))]
use std::panic::catch_unwind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    #[cfg(feature = "mlkem")]
    Mlkem512,
    #[cfg(feature = "mlkem")]
    Mlkem768,
    #[cfg(feature = "mlkem")]
    Mlkem1024,
    #[cfg(feature = "hqckem")]
    Hqckem128,
    #[cfg(feature = "hqckem")]
    Hqckem192,
    #[cfg(feature = "hqckem")]
    Hqckem256,
}

pub struct Kem {
    algorithm: KemAlgorithm,
}

impl Kem {
    pub fn new(algorithm: KemAlgorithm) -> Self {
        Self { algorithm }
    }

    #[cfg(feature = "mlkem")]
    pub fn mlkem512() -> Self {
        Self::new(KemAlgorithm::Mlkem512)
    }

    #[cfg(feature = "mlkem")]
    pub fn mlkem768() -> Self {
        Self::new(KemAlgorithm::Mlkem768)
    }

    #[cfg(feature = "mlkem")]
    pub fn mlkem1024() -> Self {
        Self::new(KemAlgorithm::Mlkem1024)
    }

    #[cfg(feature = "hqckem")]
    pub fn hqckem128() -> Self {
        Self::new(KemAlgorithm::Hqckem128)
    }

    #[cfg(feature = "hqckem")]
    pub fn hqckem192() -> Self {
        Self::new(KemAlgorithm::Hqckem192)
    }

    #[cfg(feature = "hqckem")]
    pub fn hqckem256() -> Self {
        Self::new(KemAlgorithm::Hqckem256)
    }
}

impl KeyEncapsulation for Kem {
    fn keygen(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        match self.algorithm {
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem512 => {
                let (pk, sk) = mlkem512::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("ML-KEM-512 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem768 => {
                let (pk, sk) = mlkem768::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("ML-KEM-768 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem1024 => {
                let (pk, sk) = mlkem1024::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("ML-KEM-1024 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem128 => {
                let (pk, sk) = hqc128::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("HQC-KEM-128 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem192 => {
                let (pk, sk) = hqc192::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("HQC-KEM-192 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem256 => {
                let (pk, sk) = hqc256::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("HQC-KEM-256 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
        }
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        check_buffer_size(public_key, self.public_key_size())?;

        match self.algorithm {
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem512 => {
                let pk = mlkem512::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-KEM-512 public key".into()))?;
                let (ss, ct) = mlkem512::encapsulate(&pk).map_err(|err| {
                    PqcError::CryptoError(format!("ML-KEM-512 encapsulation failed: {err:?}"))
                })?;
                Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
            }
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem768 => {
                let pk = mlkem768::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-KEM-768 public key".into()))?;
                let (ss, ct) = mlkem768::encapsulate(&pk).map_err(|err| {
                    PqcError::CryptoError(format!("ML-KEM-768 encapsulation failed: {err:?}"))
                })?;
                Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
            }
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem1024 => {
                let pk = mlkem1024::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-KEM-1024 public key".into()))?;
                let (ss, ct) = mlkem1024::encapsulate(&pk).map_err(|err| {
                    PqcError::CryptoError(format!("ML-KEM-1024 encapsulation failed: {err:?}"))
                })?;
                Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
            }
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem128 => {
                let pk = hqc128::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid HQC-KEM-128 public key".into()))?;
                let (ss, ct) = hqc128::encapsulate(&pk).map_err(|err| {
                    PqcError::CryptoError(format!("HQC-KEM-128 encapsulation failed: {err:?}"))
                })?;
                Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
            }
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem192 => {
                let pk = hqc192::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid HQC-KEM-192 public key".into()))?;
                let (ss, ct) = hqc192::encapsulate(&pk).map_err(|err| {
                    PqcError::CryptoError(format!("HQC-KEM-192 encapsulation failed: {err:?}"))
                })?;
                Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
            }
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem256 => {
                let pk = hqc256::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid HQC-KEM-256 public key".into()))?;
                let (ss, ct) = hqc256::encapsulate(&pk).map_err(|err| {
                    PqcError::CryptoError(format!("HQC-KEM-256 encapsulation failed: {err:?}"))
                })?;
                Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
            }
        }
    }

    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError> {
        check_buffer_size(ciphertext, self.ciphertext_size())?;
        check_buffer_size(secret_key, self.secret_key_size())?;

        match self.algorithm {
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem512 => {
                let ct = mlkem512::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-KEM-512 ciphertext".into()))?;
                let sk = mlkem512::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-KEM-512 secret key".into()))?;
                Ok(mlkem512::decapsulate(&ct, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("ML-KEM-512 decapsulation failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem768 => {
                let ct = mlkem768::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-KEM-768 ciphertext".into()))?;
                let sk = mlkem768::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-KEM-768 secret key".into()))?;
                Ok(mlkem768::decapsulate(&ct, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("ML-KEM-768 decapsulation failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem1024 => {
                let ct = mlkem1024::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-KEM-1024 ciphertext".into()))?;
                let sk = mlkem1024::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-KEM-1024 secret key".into()))?;
                Ok(mlkem1024::decapsulate(&ct, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("ML-KEM-1024 decapsulation failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem128 => {
                let ct = hqc128::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| PqcError::CryptoError("Invalid HQC-KEM-128 ciphertext".into()))?;
                let sk = hqc128::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid HQC-KEM-128 secret key".into()))?;
                let ss = catch_unwind(|| hqc128::decapsulate(&ct, &sk))
                    .map_err(|_| {
                        PqcError::CryptoError("HQC-KEM-128 decapsulation panicked".into())
                    })?
                    .map_err(|err| {
                        PqcError::CryptoError(format!("HQC-KEM-128 decapsulation failed: {err:?}"))
                    })?;
                Ok(ss.as_bytes().to_vec())
            }
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem192 => {
                let ct = hqc192::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| PqcError::CryptoError("Invalid HQC-KEM-192 ciphertext".into()))?;
                let sk = hqc192::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid HQC-KEM-192 secret key".into()))?;
                let ss = catch_unwind(|| hqc192::decapsulate(&ct, &sk))
                    .map_err(|_| {
                        PqcError::CryptoError("HQC-KEM-192 decapsulation panicked".into())
                    })?
                    .map_err(|err| {
                        PqcError::CryptoError(format!("HQC-KEM-192 decapsulation failed: {err:?}"))
                    })?;
                Ok(ss.as_bytes().to_vec())
            }
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem256 => {
                let ct = hqc256::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| PqcError::CryptoError("Invalid HQC-KEM-256 ciphertext".into()))?;
                let sk = hqc256::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid HQC-KEM-256 secret key".into()))?;
                let ss = catch_unwind(|| hqc256::decapsulate(&ct, &sk))
                    .map_err(|_| {
                        PqcError::CryptoError("HQC-KEM-256 decapsulation panicked".into())
                    })?
                    .map_err(|err| {
                        PqcError::CryptoError(format!("HQC-KEM-256 decapsulation failed: {err:?}"))
                    })?;
                Ok(ss.as_bytes().to_vec())
            }
        }
    }

    fn public_key_size(&self) -> usize {
        match self.algorithm {
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem512 => mlkem512::public_key_bytes(),
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem768 => mlkem768::public_key_bytes(),
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem1024 => mlkem1024::public_key_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem128 => hqc128::public_key_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem192 => hqc192::public_key_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem256 => hqc256::public_key_bytes(),
        }
    }

    fn secret_key_size(&self) -> usize {
        match self.algorithm {
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem512 => mlkem512::secret_key_bytes(),
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem768 => mlkem768::secret_key_bytes(),
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem1024 => mlkem1024::secret_key_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem128 => hqc128::secret_key_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem192 => hqc192::secret_key_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem256 => hqc256::secret_key_bytes(),
        }
    }

    fn ciphertext_size(&self) -> usize {
        match self.algorithm {
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem512 => mlkem512::ciphertext_bytes(),
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem768 => mlkem768::ciphertext_bytes(),
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem1024 => mlkem1024::ciphertext_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem128 => hqc128::ciphertext_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem192 => hqc192::ciphertext_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem256 => hqc256::ciphertext_bytes(),
        }
    }

    fn shared_secret_size(&self) -> usize {
        match self.algorithm {
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem512 => mlkem512::shared_secret_bytes(),
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem768 => mlkem768::shared_secret_bytes(),
            #[cfg(feature = "mlkem")]
            KemAlgorithm::Mlkem1024 => mlkem1024::shared_secret_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem128 => hqc128::shared_secret_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem192 => hqc192::shared_secret_bytes(),
            #[cfg(feature = "hqckem")]
            KemAlgorithm::Hqckem256 => hqc256::shared_secret_bytes(),
        }
    }
}

pub type Mlkem512 = Kem;
pub type Mlkem768 = Kem;
pub type Mlkem1024 = Kem;
#[cfg(feature = "hqckem")]
pub type Hqckem128 = Kem;
#[cfg(feature = "hqckem")]
pub type Hqckem192 = Kem;
#[cfg(feature = "hqckem")]
pub type Hqckem256 = Kem;
