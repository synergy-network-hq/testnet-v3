use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

pub trait RevealAuthorizationVerifier {
    fn verify_parent_commitment(
        &self,
        authorization: &ProtectedRevealAuthorization,
        evidence: &crate::execution::ParentProposalRevealEvidence,
    ) -> Result<(), EtdagError>;
}

/// Cannot be deserialized or constructed from a caller's unverified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRevealAuthorization(ProtectedRevealAuthorization);

impl VerifiedRevealAuthorization {
    pub fn verify(
        authorization: ProtectedRevealAuthorization,
        evidence: &crate::execution::ParentProposalRevealEvidence,
        verifier: &impl RevealAuthorizationVerifier,
    ) -> Result<Self, EtdagError> {
        authorization.validate()?;
        evidence.material.validate()?;
        evidence.next_batch.validate()?;
        if evidence.validation_proof.is_empty()
            || evidence.validation_proof.len() > 1024 * 1024
            || evidence.next_batch.target_height != authorization.target_height
            || evidence.next_batch.context_root != authorization.context_root
            || evidence.next_batch.protected_batch_root != authorization.protected_batch_root
            || evidence.material.height.checked_add(1) != Some(authorization.target_height)
            || evidence.material.next_batch_root != authorization.protected_batch_root
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        verifier.verify_parent_commitment(&authorization, evidence)?;
        Ok(Self(authorization))
    }

    pub fn authorization(&self) -> &ProtectedRevealAuthorization {
        &self.0
    }
}

pub fn parent_reveal_reference(
    parent_block_id: &str,
    validation_id: &str,
    authorization: &ProtectedRevealAuthorization,
) -> Result<EtdagDigest, EtdagError> {
    if parent_block_id.is_empty() || validation_id.is_empty() {
        return Err(EtdagError::UnauthorizedReveal);
    }
    EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_PARENT_REVEAL_V1",
        &(
            parent_block_id,
            validation_id,
            &authorization.context_root,
            authorization.target_height,
            &authorization.protected_batch_root,
        ),
    )
}

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
