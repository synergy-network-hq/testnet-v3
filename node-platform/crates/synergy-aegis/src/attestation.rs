//! Opaque, bounded evidence that identifies a concrete custody provider.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAttestation {
    pub provider_id: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence: Vec<u8>,
}

impl ProviderAttestation {
    pub const MAX_EVIDENCE_BYTES: usize = 64 * 1024;

    pub fn validate_shape(&self, now: u64) -> Result<(), ProviderAttestationError> {
        if self.provider_id.is_empty() || self.provider_id.len() > 128 {
            return Err(ProviderAttestationError::InvalidProviderId);
        }
        if self.evidence.is_empty() || self.evidence.len() > Self::MAX_EVIDENCE_BYTES {
            return Err(ProviderAttestationError::InvalidEvidenceLength);
        }
        if self.expires_at_unix_seconds <= self.issued_at_unix_seconds {
            return Err(ProviderAttestationError::InvalidValidityWindow);
        }
        if now < self.issued_at_unix_seconds || now >= self.expires_at_unix_seconds {
            return Err(ProviderAttestationError::OutsideValidityWindow);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAttestationError {
    InvalidProviderId,
    InvalidEvidenceLength,
    InvalidValidityWindow,
    OutsideValidityWindow,
}

impl std::fmt::Display for ProviderAttestationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid provider attestation: {self:?}")
    }
}

impl std::error::Error for ProviderAttestationError {}
