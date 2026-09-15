use synergy_etdag::{EtdagDigest, IngressKemKeyRecord, ShareCapsule};

use crate::{pad_plaintext, ActiveIngressKeys, PaddingError, VerifiedTargetContext};

#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub content_blind_order_key: EtdagDigest,
    pub share_capsules: Vec<ShareCapsule>,
}

pub trait ClientEncryptor {
    fn encrypt(
        &self,
        target: &VerifiedTargetContext,
        keys: &[IngressKemKeyRecord],
        padded_plaintext: &[u8],
    ) -> Result<EncryptedPayload, ClientEncryptionError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEncryptionError {
    Padding(PaddingError),
    ContextMismatch,
    Provider(String),
    InvalidPayload,
}

pub fn encrypt_for_target(
    encryptor: &impl ClientEncryptor,
    target: &VerifiedTargetContext,
    keys: &ActiveIngressKeys,
    plaintext: &[u8],
) -> Result<EncryptedPayload, ClientEncryptionError> {
    if keys.context_root()
        != &target
            .context_root()
            .map_err(|_| ClientEncryptionError::ContextMismatch)?
    {
        return Err(ClientEncryptionError::ContextMismatch);
    }
    let padded = pad_plaintext(plaintext).map_err(ClientEncryptionError::Padding)?;
    let payload = encryptor.encrypt(target, keys.records(), &padded)?;
    if payload.ciphertext.is_empty()
        || payload.share_capsules.is_empty()
        || payload.content_blind_order_key.validate().is_err()
    {
        return Err(ClientEncryptionError::InvalidPayload);
    }
    Ok(payload)
}
