//! Digital Signature adapters.

use crate::error::PqcError;
use crate::traits::{Contextual, DetachedSignature as DetachedSignatureExt, DigitalSignature};
use crate::utils::check_buffer_size;
use alloc::{format, vec::Vec};

#[cfg(feature = "fndsa")]
use pqrust_fndsa::{fndsa1024, fndsa512};
#[cfg(feature = "mldsa")]
use pqrust_mldsa::{mldsa44, mldsa65, mldsa87};
#[cfg(any(feature = "mldsa", feature = "fndsa"))]
use pqrust_traits::sign::{DetachedSignature as _, PublicKey, SecretKey};

#[cfg(feature = "fndsa")]
const FNDSA_CONTEXT_PREFIX: &[u8] = b"AEGIS-PQSYNQ-FNDSA-CONTEXT-V1";

#[cfg(feature = "fndsa")]
fn fndsa_context_payload(message: &[u8], context: &[u8]) -> Vec<u8> {
    let mut payload =
        Vec::with_capacity(FNDSA_CONTEXT_PREFIX.len() + 16 + context.len() + message.len());
    payload.extend_from_slice(FNDSA_CONTEXT_PREFIX);
    payload.extend_from_slice(&(context.len() as u64).to_be_bytes());
    payload.extend_from_slice(context);
    payload.extend_from_slice(&(message.len() as u64).to_be_bytes());
    payload.extend_from_slice(message);
    payload
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm {
    #[cfg(feature = "mldsa")]
    Mldsa44,
    #[cfg(feature = "mldsa")]
    Mldsa65,
    #[cfg(feature = "mldsa")]
    Mldsa87,
    #[cfg(feature = "fndsa")]
    Fndsa512,
    #[cfg(feature = "fndsa")]
    Fndsa1024,
}

pub struct Sign {
    algorithm: SignAlgorithm,
}

impl Sign {
    pub fn new(algorithm: SignAlgorithm) -> Self {
        Self { algorithm }
    }

    #[cfg(feature = "mldsa")]
    pub fn mldsa44() -> Self {
        Self::new(SignAlgorithm::Mldsa44)
    }

    #[cfg(feature = "mldsa")]
    pub fn mldsa65() -> Self {
        Self::new(SignAlgorithm::Mldsa65)
    }

    #[cfg(feature = "mldsa")]
    pub fn mldsa87() -> Self {
        Self::new(SignAlgorithm::Mldsa87)
    }

    #[cfg(feature = "fndsa")]
    pub fn fndsa512() -> Self {
        Self::new(SignAlgorithm::Fndsa512)
    }

    #[cfg(feature = "fndsa")]
    pub fn fndsa1024() -> Self {
        Self::new(SignAlgorithm::Fndsa1024)
    }

    pub fn detached_sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError> {
        self.sign(message, secret_key)
    }

    pub fn verify_detached(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, PqcError> {
        self.verify(message, signature, public_key)
    }

    pub fn sign_ctx(
        &self,
        message: &[u8],
        secret_key: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, PqcError> {
        check_buffer_size(secret_key, self.secret_key_size())?;

        match self.algorithm {
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa44 => {
                let sk = mldsa44::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-44 secret key".into()))?;
                Ok(mldsa44::detached_sign_ctx(message, context, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("ML-DSA-44 context signing failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa65 => {
                let sk = mldsa65::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-65 secret key".into()))?;
                Ok(mldsa65::detached_sign_ctx(message, context, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("ML-DSA-65 context signing failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa87 => {
                let sk = mldsa87::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-87 secret key".into()))?;
                Ok(mldsa87::detached_sign_ctx(message, context, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("ML-DSA-87 context signing failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa512 | SignAlgorithm::Fndsa1024 => {
                let payload = fndsa_context_payload(message, context);
                self.sign(&payload, secret_key)
            }
        }
    }

    pub fn verify_ctx(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        context: &[u8],
    ) -> Result<bool, PqcError> {
        check_buffer_size(public_key, self.public_key_size())?;

        match self.algorithm {
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa44 => {
                let pk = mldsa44::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-44 public key".into()))?;
                let sig = mldsa44::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-44 signature".into()))?;
                Ok(mldsa44::verify_detached_signature_ctx(&sig, message, context, &pk).is_ok())
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa65 => {
                let pk = mldsa65::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-65 public key".into()))?;
                let sig = mldsa65::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-65 signature".into()))?;
                Ok(mldsa65::verify_detached_signature_ctx(&sig, message, context, &pk).is_ok())
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa87 => {
                let pk = mldsa87::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-87 public key".into()))?;
                let sig = mldsa87::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-87 signature".into()))?;
                Ok(mldsa87::verify_detached_signature_ctx(&sig, message, context, &pk).is_ok())
            }
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa512 | SignAlgorithm::Fndsa1024 => {
                let payload = fndsa_context_payload(message, context);
                self.verify(&payload, signature, public_key)
            }
        }
    }
}

impl DigitalSignature for Sign {
    fn keygen(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        match self.algorithm {
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa44 => {
                let (pk, sk) = mldsa44::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("ML-DSA-44 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa65 => {
                let (pk, sk) = mldsa65::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("ML-DSA-65 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa87 => {
                let (pk, sk) = mldsa87::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("ML-DSA-87 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa512 => {
                let (pk, sk) = fndsa512::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("FN-DSA-512 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa1024 => {
                let (pk, sk) = fndsa1024::keypair().map_err(|err| {
                    PqcError::CryptoError(format!("FN-DSA-1024 key generation failed: {err:?}"))
                })?;
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            }
        }
    }

    fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError> {
        check_buffer_size(secret_key, self.secret_key_size())?;

        match self.algorithm {
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa44 => {
                let sk = mldsa44::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-44 secret key".into()))?;
                Ok(mldsa44::detached_sign(message, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("ML-DSA-44 signing failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa65 => {
                let sk = mldsa65::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-65 secret key".into()))?;
                Ok(mldsa65::detached_sign(message, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("ML-DSA-65 signing failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa87 => {
                let sk = mldsa87::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-87 secret key".into()))?;
                Ok(mldsa87::detached_sign(message, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("ML-DSA-87 signing failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa512 => {
                let sk = fndsa512::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid FN-DSA-512 secret key".into()))?;
                Ok(fndsa512::detached_sign(message, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("FN-DSA-512 signing failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa1024 => {
                let sk = fndsa1024::SecretKey::from_bytes(secret_key)
                    .map_err(|_| PqcError::CryptoError("Invalid FN-DSA-1024 secret key".into()))?;
                Ok(fndsa1024::detached_sign(message, &sk)
                    .map_err(|err| {
                        PqcError::CryptoError(format!("FN-DSA-1024 signing failed: {err:?}"))
                    })?
                    .as_bytes()
                    .to_vec())
            }
        }
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, PqcError> {
        check_buffer_size(public_key, self.public_key_size())?;

        match self.algorithm {
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa44 => {
                let pk = mldsa44::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-44 public key".into()))?;
                let sig = mldsa44::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-44 signature".into()))?;
                Ok(mldsa44::verify_detached_signature(&sig, message, &pk).is_ok())
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa65 => {
                let pk = mldsa65::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-65 public key".into()))?;
                let sig = mldsa65::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-65 signature".into()))?;
                Ok(mldsa65::verify_detached_signature(&sig, message, &pk).is_ok())
            }
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa87 => {
                let pk = mldsa87::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-87 public key".into()))?;
                let sig = mldsa87::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::CryptoError("Invalid ML-DSA-87 signature".into()))?;
                Ok(mldsa87::verify_detached_signature(&sig, message, &pk).is_ok())
            }
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa512 => {
                let pk = fndsa512::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid FN-DSA-512 public key".into()))?;
                let sig = fndsa512::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::CryptoError("Invalid FN-DSA-512 signature".into()))?;
                Ok(fndsa512::verify_detached_signature(&sig, message, &pk).is_ok())
            }
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa1024 => {
                let pk = fndsa1024::PublicKey::from_bytes(public_key)
                    .map_err(|_| PqcError::CryptoError("Invalid FN-DSA-1024 public key".into()))?;
                let sig = fndsa1024::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::CryptoError("Invalid FN-DSA-1024 signature".into()))?;
                Ok(fndsa1024::verify_detached_signature(&sig, message, &pk).is_ok())
            }
        }
    }

    fn public_key_size(&self) -> usize {
        match self.algorithm {
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa44 => mldsa44::public_key_bytes(),
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa65 => mldsa65::public_key_bytes(),
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa87 => mldsa87::public_key_bytes(),
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa512 => fndsa512::public_key_bytes(),
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa1024 => fndsa1024::public_key_bytes(),
        }
    }

    fn secret_key_size(&self) -> usize {
        match self.algorithm {
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa44 => mldsa44::secret_key_bytes(),
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa65 => mldsa65::secret_key_bytes(),
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa87 => mldsa87::secret_key_bytes(),
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa512 => fndsa512::secret_key_bytes(),
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa1024 => fndsa1024::secret_key_bytes(),
        }
    }

    fn signature_size(&self) -> usize {
        match self.algorithm {
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa44 => mldsa44::signature_bytes(),
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa65 => mldsa65::signature_bytes(),
            #[cfg(feature = "mldsa")]
            SignAlgorithm::Mldsa87 => mldsa87::signature_bytes(),
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa512 => fndsa512::signature_bytes(),
            #[cfg(feature = "fndsa")]
            SignAlgorithm::Fndsa1024 => fndsa1024::signature_bytes(),
        }
    }
}

impl DetachedSignatureExt for Sign {
    fn detached_sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError> {
        self.detached_sign(message, secret_key)
    }

    fn verify_detached(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, PqcError> {
        self.verify_detached(message, signature, public_key)
    }
}

impl Contextual for Sign {
    fn sign_ctx(
        &self,
        message: &[u8],
        secret_key: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, PqcError> {
        self.sign_ctx(message, secret_key, context)
    }

    fn verify_ctx(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        context: &[u8],
    ) -> Result<bool, PqcError> {
        self.verify_ctx(message, signature, public_key, context)
    }
}

pub type Mldsa44 = Sign;
pub type Mldsa65 = Sign;
pub type Mldsa87 = Sign;
pub type Fndsa512 = Sign;
pub type Fndsa1024 = Sign;
