use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareCapsule {
    pub validator_id: String,
    pub key_id: String,
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_share: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedTransactionEnvelope {
    pub envelope_id: EtdagDigest,
    pub target_context_root: EtdagDigest,
    pub target_height: u64,
    pub ciphertext: Vec<u8>,
    pub content_blind_order_key: EtdagDigest,
    pub share_capsules: Vec<ShareCapsule>,
}

impl EncryptedTransactionEnvelope {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.envelope_id.validate()?;
        self.target_context_root.validate()?;
        self.content_blind_order_key.validate()?;
        if self.target_height == 0
            || self.ciphertext.is_empty()
            || self.share_capsules.is_empty()
            || self.share_capsules.iter().any(|capsule| {
                capsule.validator_id.trim().is_empty()
                    || capsule.key_id.trim().is_empty()
                    || capsule.kem_ciphertext.is_empty()
                    || capsule.encrypted_share.is_empty()
            })
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid encrypted transaction envelope".into(),
            ));
        }
        Ok(())
    }
}
