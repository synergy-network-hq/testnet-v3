use std::collections::BTreeMap;

use crate::{DecryptShareMessage, EtdagDigest, EtdagError};

use super::{
    authorization::ProtectedRevealAuthorization, decrypt_share::VerifiedDecryptShare,
    transcript::RevealTranscript,
};

/// Collects only previously verified shares for one authorization and envelope.
#[derive(Debug)]
pub struct VerifiedShareCollector {
    authorization: ProtectedRevealAuthorization,
    envelope_id: EtdagDigest,
    threshold: usize,
    member_count: usize,
    shares: BTreeMap<String, VerifiedDecryptShare>,
}

impl VerifiedShareCollector {
    /// Creates a collector for one governed reveal slot.
    pub fn new(
        authorization: ProtectedRevealAuthorization,
        envelope_id: EtdagDigest,
        threshold: usize,
        member_count: usize,
    ) -> Result<Self, EtdagError> {
        authorization.validate()?;
        envelope_id.validate()?;
        if threshold == 0 || member_count == 0 || threshold > member_count {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(Self {
            authorization,
            envelope_id,
            threshold,
            member_count,
            shares: BTreeMap::new(),
        })
    }

    /// Adds a verified share after checking the active slot, before mutation.
    pub fn insert(&mut self, share: VerifiedDecryptShare) -> Result<(), EtdagError> {
        if share.authorization() != &self.authorization || share.envelope_id() != &self.envelope_id
        {
            return Err(EtdagError::ContextMismatch);
        }
        if self.shares.contains_key(share.validator_id()) {
            return Err(EtdagError::DuplicateShare(share.validator_id().to_owned()));
        }
        if self.shares.len() >= self.member_count {
            return Err(EtdagError::InvalidCapacity);
        }
        self.shares.insert(share.validator_id().to_owned(), share);
        Ok(())
    }

    /// Seals the collector once the governed reveal threshold is present.
    pub fn into_threshold_shares(self) -> Result<ThresholdDecryptShares, EtdagError> {
        if self.shares.len() < self.threshold {
            return Err(EtdagError::RevealThreshold {
                collected: self.shares.len(),
                required: self.threshold,
            });
        }
        Ok(ThresholdDecryptShares {
            authorization: self.authorization,
            envelope_id: self.envelope_id,
            threshold: self.threshold,
            shares: self.shares.into_values().collect(),
        })
    }
}

/// Threshold-sufficient, authenticated shares for exactly one protected envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdDecryptShares {
    authorization: ProtectedRevealAuthorization,
    envelope_id: EtdagDigest,
    threshold: usize,
    shares: Vec<VerifiedDecryptShare>,
}

impl ThresholdDecryptShares {
    /// Returns the finality-bound reveal authorization.
    pub fn authorization(&self) -> &ProtectedRevealAuthorization {
        &self.authorization
    }

    /// Returns the protected envelope bound to every share.
    pub fn envelope_id(&self) -> &EtdagDigest {
        &self.envelope_id
    }

    /// Returns the verified shares in canonical validator-id order.
    pub fn shares(&self) -> &[VerifiedDecryptShare] {
        &self.shares
    }

    /// Computes the canonical transcript root over the signed share messages.
    pub fn transcript_root(&self) -> Result<EtdagDigest, EtdagError> {
        let shares = self
            .shares
            .iter()
            .map(VerifiedDecryptShare::message)
            .cloned()
            .collect::<Vec<DecryptShareMessage>>();
        RevealTranscript {
            transcript_version: 1,
            authorization: self.authorization.clone(),
            shares,
        }
        .root(self.threshold)
    }
}
