use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityVote {
    pub context_root: EtdagDigest,
    pub vertex_id: EtdagDigest,
    pub validator_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

impl AvailabilityVote {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.vertex_id.validate()?;
        if self.validator_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.signature.is_empty()
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid availability vote".into(),
            ));
        }
        Ok(())
    }
}
