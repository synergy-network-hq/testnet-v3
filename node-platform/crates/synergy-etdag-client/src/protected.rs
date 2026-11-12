//! Concrete ML-KEM-1024/AES-256-GCM client encryption. The caller supplies
//! governed quorum and the admission order key; neither is inferred from keys.
use crate::{ClientEncryptionError, ClientEncryptor, EncryptedPayload, VerifiedTargetContext};
use synergy_etdag::{
    crypto::{encrypt_protected_payload, governed_reveal_threshold},
    EnvelopeAad, EtdagDigest, IngressKemKeyRecord,
};

pub struct ProtectedClientEncryptor {
    aad: EnvelopeAad,
    count_quorum: usize,
    content_blind_order_key: EtdagDigest,
}
impl ProtectedClientEncryptor {
    pub fn new(
        aad: EnvelopeAad,
        count_quorum: usize,
        content_blind_order_key: EtdagDigest,
    ) -> Result<Self, ClientEncryptionError> {
        aad.canonical_bytes()
            .map_err(|_| ClientEncryptionError::InvalidPayload)?;
        content_blind_order_key
            .validate()
            .map_err(|_| ClientEncryptionError::InvalidPayload)?;
        if count_quorum == 0 {
            return Err(ClientEncryptionError::InvalidPayload);
        }
        Ok(Self {
            aad,
            count_quorum,
            content_blind_order_key,
        })
    }
}
impl ClientEncryptor for ProtectedClientEncryptor {
    fn encrypt(
        &self,
        target: &VerifiedTargetContext,
        keys: &[IngressKemKeyRecord],
        padded_plaintext: &[u8],
    ) -> Result<EncryptedPayload, ClientEncryptionError> {
        let context = target.inner();
        if self.aad.chain_id != context.chain_id
            || self.aad.network_id != context.network_id
            || self.aad.protocol_version != context.protocol_version
            || self.aad.epoch != context.epoch
            || self.aad.target_height != context.target_height
            || self.aad.assigned_cluster_id != context.assigned_cluster_id
            || self.aad.target_context_root
                != target
                    .context_root()
                    .map_err(|_| ClientEncryptionError::ContextMismatch)?
            || u64::try_from(keys.len()).ok() != Some(context.assigned_cluster_validator_count)
        {
            return Err(ClientEncryptionError::ContextMismatch);
        }
        governed_reveal_threshold(keys.len(), self.count_quorum)
            .map_err(|_| ClientEncryptionError::InvalidPayload)?;
        let payload =
            encrypt_protected_payload(&self.aad, keys, self.count_quorum, padded_plaintext)
                .map_err(|_| {
                    ClientEncryptionError::Provider("protected encryption failed".into())
                })?;
        Ok(EncryptedPayload {
            aad: self.aad.clone(),
            aead_nonce: payload.aead_nonce,
            key_commitment: payload.key_commitment,
            ciphertext: payload.ciphertext,
            content_blind_order_key: self.content_blind_order_key.clone(),
            share_capsules: payload.share_capsules,
        })
    }
}
