use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionVote {
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub envelope_id: EtdagDigest,
    pub validator_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

impl AdmissionVote {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.envelope_id.validate()?;
        if self.target_height == 0
            || self.validator_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.signature.is_empty()
        {
            return Err(EtdagError::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionCertificate {
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub envelope_id: EtdagDigest,
    pub votes: Vec<AdmissionVote>,
}

impl AdmissionCertificate {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.envelope_id.validate()?;
        if self.target_height == 0 || self.votes.is_empty() {
            return Err(EtdagError::InsufficientAvailability {
                signed: self.votes.len(),
                required: 1,
            });
        }
        let mut validators = BTreeSet::new();
        for vote in &self.votes {
            vote.validate_shape()?;
            if vote.context_root != self.context_root
                || vote.target_height != self.target_height
                || vote.envelope_id != self.envelope_id
                || !validators.insert(vote.validator_id.as_str())
            {
                return Err(EtdagError::ConflictingArtifact(
                    "invalid admission vote set".into(),
                ));
            }
        }
        Ok(())
    }
}
