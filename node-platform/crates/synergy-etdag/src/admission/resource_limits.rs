use crate::{EtdagError, CIPHERTEXT_SIZE_CLASSES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionResourceLimits {
    pub maximum_envelopes: usize,
    pub maximum_capsules: usize,
    pub maximum_capsule_bytes: usize,
}

impl AdmissionResourceLimits {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.maximum_envelopes == 0
            || self.maximum_capsules == 0
            || self.maximum_capsule_bytes == 0
        {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(())
    }

    pub fn validate_envelope(
        &self,
        envelope: &crate::EncryptedTransactionEnvelope,
    ) -> Result<(), EtdagError> {
        self.validate()?;
        envelope.validate()?;
        if !CIPHERTEXT_SIZE_CLASSES.contains(&envelope.ciphertext.len()) {
            return Err(EtdagError::InvalidCiphertextClasses);
        }
        if envelope.share_capsules.len() > self.maximum_capsules
            || envelope.share_capsules.iter().any(|capsule| {
                capsule
                    .kem_ciphertext
                    .len()
                    .saturating_add(capsule.encrypted_share.len())
                    > self.maximum_capsule_bytes
            })
        {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(())
    }
}
