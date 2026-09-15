//! PQVM-backed verification for canonical Aegis contexts.
use aegis_pqvm::pqc::signatures::mldsa::{mldsa65, mldsa87};
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

use crate::{
    AegisPolicy, AegisSigner, AegisVerifier, KeyId, Signature, SignatureAlgorithm, SigningContext,
    SigningError, VerificationError,
};

/// Local node-embedded Aegis PQVM verifier. It validates only the selected
/// canonical algorithm and never treats cryptographic identity as PoSy authority.
#[derive(Debug, Clone)]
pub struct PqvmVerifier {
    policy: AegisPolicy,
}

impl PqvmVerifier {
    pub fn new(policy: AegisPolicy) -> Result<Self, VerificationError> {
        policy.validate().map_err(VerificationError::Policy)?;
        Ok(Self { policy })
    }
}

impl AegisVerifier for PqvmVerifier {
    fn verify(
        &self,
        context: &SigningContext,
        message: &[u8],
        signature: &Signature,
        public_key: &[u8],
    ) -> Result<(), VerificationError> {
        context
            .validate()
            .map_err(|_| VerificationError::InvalidContext)?;
        self.policy
            .authorize(signature.algorithm, message.len(), signature.bytes.len())
            .map_err(VerificationError::Policy)?;
        match signature.algorithm {
            SignatureAlgorithm::MlDsa65 => {
                let public_key = mldsa65::PublicKey::from_bytes(public_key)
                    .map_err(|_| VerificationError::InvalidPublicKey)?;
                let signature = mldsa65::DetachedSignature::from_bytes(&signature.bytes)
                    .map_err(|_| VerificationError::InvalidSignature)?;
                mldsa65::verify_detached_signature(&signature, message, &public_key)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            SignatureAlgorithm::MlDsa87 => {
                let public_key = mldsa87::PublicKey::from_bytes(public_key)
                    .map_err(|_| VerificationError::InvalidPublicKey)?;
                let signature = mldsa87::DetachedSignature::from_bytes(&signature.bytes)
                    .map_err(|_| VerificationError::InvalidSignature)?;
                mldsa87::verify_detached_signature(&signature, message, &public_key)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            _ => Err(VerificationError::Provider(
                "PQVM verifier has no implementation for the requested approved algorithm".into(),
            )),
        }
    }
}

/// Node-embedded PQVM signer for provisioned ML-DSA-65 P2P identity keys.
/// This type never generates or exports a node identity key.
pub struct PqvmSigner {
    policy: AegisPolicy,
    key_id: KeyId,
    secret_key: Vec<u8>,
}

impl PqvmSigner {
    pub fn from_secret_key_bytes(
        policy: AegisPolicy,
        key_id: KeyId,
        secret_key: Vec<u8>,
    ) -> Result<Self, SigningError> {
        policy.validate().map_err(SigningError::Policy)?;
        if !policy
            .allowed_algorithms
            .contains(&SignatureAlgorithm::MlDsa65)
            || mldsa65::SecretKey::from_bytes(&secret_key).is_err()
        {
            return Err(SigningError::KeyUnavailable);
        }
        Ok(Self {
            policy,
            key_id,
            secret_key,
        })
    }
}

impl Drop for PqvmSigner {
    fn drop(&mut self) {
        for byte in &mut self.secret_key {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl AegisSigner for PqvmSigner {
    fn sign(
        &self,
        key_id: &KeyId,
        context: &SigningContext,
        message: &[u8],
    ) -> Result<Signature, SigningError> {
        context.validate()?;
        if key_id != &self.key_id {
            return Err(SigningError::KeyUnavailable);
        }
        self.policy
            .authorize(SignatureAlgorithm::MlDsa65, message.len(), 0)
            .map_err(SigningError::Policy)?;
        let secret_key = mldsa65::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| SigningError::KeyUnavailable)?;
        let signature = mldsa65::detached_sign(message, &secret_key);
        let bytes = signature.as_bytes().to_vec();
        self.policy
            .authorize(SignatureAlgorithm::MlDsa65, message.len(), bytes.len())
            .map_err(SigningError::Policy)?;
        Ok(Signature {
            algorithm: SignatureAlgorithm::MlDsa65,
            key_id: key_id.clone(),
            bytes,
        })
    }
}
