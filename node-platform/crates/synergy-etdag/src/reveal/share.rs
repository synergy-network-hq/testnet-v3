use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError, ProtectedRevealAuthorization};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptShareMessage {
    pub share_version: u32,
    pub authorization: ProtectedRevealAuthorization,
    pub envelope_id: EtdagDigest,
    pub validator_id: String,
    pub key_id: String,
    pub ingress_kem_key_id: String,
    pub share_index: u8,
    pub share_commitment: EtdagDigest,
    /// Released canonical Shamir share bytes; capsule ciphertext stays in the envelope.
    pub encrypted_share: Vec<u8>,
    pub signature: Vec<u8>,
}

impl DecryptShareMessage {
    /// Domain-bound consensus signature transcript, also usable before signing.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        crate::crypto::canonical_signing_bytes(
            super::verifier::DECRYPT_SHARE_DOMAIN,
            &(
                self.share_version,
                &self.authorization,
                &self.envelope_id,
                &self.validator_id,
                &self.key_id,
                &self.ingress_kem_key_id,
                self.share_index,
                &self.share_commitment,
                &self.encrypted_share,
            ),
        )
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        self.authorization.validate()?;
        self.envelope_id.validate()?;
        self.share_commitment.validate()?;
        if self.share_version != 2
            || self.validator_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.ingress_kem_key_id.trim().is_empty()
            || self.share_index == 0
            || self.encrypted_share.is_empty()
            || self.signature.is_empty()
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        let share = crate::crypto::ShamirShare::from_canonical_bytes(&self.encrypted_share)?;
        if share.index != self.share_index
            || share.commitment(
                &self.validator_id,
                &self.authorization.context_root,
                self.authorization.target_height,
            )? != self.share_commitment
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        Ok(())
    }
}
