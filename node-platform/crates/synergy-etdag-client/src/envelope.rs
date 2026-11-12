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
        plaintext: &[u8],
    ) -> Result<Self, EnvelopeBuildError> {
        let payload = encrypt_for_target(encryptor, target, keys, plaintext)
            .map_err(EnvelopeBuildError::Encryption)?;
        let mut envelope = EncryptedTransactionEnvelope {
            envelope_version: 2,
            envelope_id: EtdagDigest("0".repeat(128)),
            target_context_root: target
                .context_root()
                .map_err(|error| EnvelopeBuildError::Invalid(format!("{error:?}")))?,
            target_height: target.target_height(),
            aad: payload.aad,
            aead_nonce: payload.aead_nonce,
            key_commitment: payload.key_commitment,
            share_commitment_root: EtdagDigest("0".repeat(128)),
            share_capsule_root: EtdagDigest("0".repeat(128)),
            ciphertext: payload.ciphertext,
            content_blind_order_key: payload.content_blind_order_key,
            share_capsules: payload.share_capsules,
        };
        envelope
            .refresh_capsule_roots()
            .map_err(|e| EnvelopeBuildError::Invalid(format!("{e:?}")))?;
        envelope.envelope_id = synergy_etdag::envelope_commitment(&envelope)
            .map_err(|e| EnvelopeBuildError::Invalid(format!("{e:?}")))?;
        envelope
            .validate()
            .map_err(|error| EnvelopeBuildError::Invalid(format!("{error:?}")))?;
        Ok(Self { envelope })
    }
}
