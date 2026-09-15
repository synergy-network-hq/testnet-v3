use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedRevealAuthorization {
    pub authorization_version: u32,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub protected_batch_root: EtdagDigest,
    pub finality_reference: EtdagDigest,
}

impl ProtectedRevealAuthorization {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.protected_batch_root.validate()?;
        self.finality_reference.validate()?;
        if self.authorization_version != 1 || self.target_height == 0 {
            return Err(EtdagError::UnauthorizedReveal);
        }
        Ok(())
    }
}
