use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{DecryptShareMessage, EtdagDigest, EtdagError, ProtectedRevealAuthorization};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealTranscript {
    pub transcript_version: u32,
    pub authorization: ProtectedRevealAuthorization,
    pub shares: Vec<DecryptShareMessage>,
}

impl RevealTranscript {
    pub fn root(&self, threshold: usize) -> Result<EtdagDigest, EtdagError> {
        self.authorization.validate()?;
        let mut validators = BTreeSet::new();
        if self.transcript_version != 1 || threshold == 0 {
            return Err(EtdagError::UnauthorizedReveal);
        }
        for share in &self.shares {
            share.validate()?;
            if share.authorization != self.authorization || !validators.insert(&share.validator_id)
            {
                return Err(EtdagError::UnauthorizedReveal);
            }
        }
        if validators.len() < threshold {
            return Err(EtdagError::RevealThreshold {
                collected: validators.len(),
                required: threshold,
            });
        }
        let mut shares = self.shares.clone();
        shares.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_REVEAL_TRANSCRIPT_V1",
            &(self.transcript_version, &self.authorization, shares),
        )
    }
}
