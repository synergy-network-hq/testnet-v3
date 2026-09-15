use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError, ProtectedRevealAuthorization};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptShareMessage {
    pub share_version: u32,
    pub authorization: ProtectedRevealAuthorization,
    pub envelope_id: EtdagDigest,
    pub validator_id: String,
    pub key_id: String,
    pub encrypted_share: Vec<u8>,
    pub signature: Vec<u8>,
}

impl DecryptShareMessage {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.authorization.validate()?;
        self.envelope_id.validate()?;
        if self.share_version != 1
            || self.validator_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.encrypted_share.is_empty()
            || self.signature.is_empty()
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        Ok(())
    }
}
