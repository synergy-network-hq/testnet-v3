use synergy_etdag::{EncryptedTransactionEnvelope, EtdagDigest};

use crate::{
    encrypt_for_target, ActiveIngressKeys, ClientEncryptionError, ClientEncryptor,
    VerifiedTargetContext,
};

#[derive(Debug, Clone)]
pub struct ClientEnvelope {
    pub envelope: EncryptedTransactionEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeBuildError {
    Encryption(ClientEncryptionError),
    Invalid(String),
}

impl ClientEnvelope {
    pub fn encrypt(
        encryptor: &impl ClientEncryptor,
        target: &VerifiedTargetContext,
        keys: &ActiveIngressKeys,
        envelope_id: EtdagDigest,
        plaintext: &[u8],
    ) -> Result<Self, EnvelopeBuildError> {
        let payload = encrypt_for_target(encryptor, target, keys, plaintext)
            .map_err(EnvelopeBuildError::Encryption)?;
        let envelope = EncryptedTransactionEnvelope {
            envelope_id,
            target_context_root: target
                .context_root()
                .map_err(|error| EnvelopeBuildError::Invalid(format!("{error:?}")))?,
            target_height: target.target_height(),
            ciphertext: payload.ciphertext,
            content_blind_order_key: payload.content_blind_order_key,
            share_capsules: payload.share_capsules,
        };
        envelope
            .validate()
            .map_err(|error| EnvelopeBuildError::Invalid(format!("{error:?}")))?;
        Ok(Self { envelope })
    }
}
