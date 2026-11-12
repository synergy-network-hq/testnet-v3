use serde::{Deserialize, Serialize};

use crate::{crypto::canonical_signing_bytes, EtdagDigest, EtdagError};

/// Authenticated close evidence, not a batch vote or finality certificate.
/// The frontier may be empty; only a verified quorum can establish an empty cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedCutMarker {
    pub marker_version: u32,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub cutoff_context_root: EtdagDigest,
    pub frontier: Vec<EtdagDigest>,
    pub validator_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

impl ProtectedCutMarker {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.context_root.validate()?;
        self.cutoff_context_root.validate()?;
        if self.marker_version != 1
            || self.target_height < 3
            || self.context_root.is_zero()
            || self.cutoff_context_root.is_zero()
            || self.validator_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.frontier.len() > crate::dag::MAX_VERTEX_PARENTS
            || self.frontier.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        for id in &self.frontier {
            id.validate()?;
        }
        canonical_signing_bytes(
            "SYNERGY_ETDAG_CUTOFF_MARKER_V1",
            &(
                self.marker_version,
                &self.context_root,
                self.target_height,
                &self.cutoff_context_root,
                &self.frontier,
                &self.validator_id,
                &self.key_id,
            ),
        )
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        self.signing_bytes()?;
        if self.signature.is_empty() || self.signature.len() > 16 * 1024 {
            return Err(EtdagError::InvalidSignature);
        }
        Ok(())
    }
}
