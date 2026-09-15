use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    validate_block_vote, verify_strict_dual_quorum, BlockVote, CertifiedCandidateSubject,
    ConsensusObjectContext, ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyError,
    PosyResult, SimplifiedEpochContext, SimplifiedFinalityParent,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantSignature {
    pub validator_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificateReference {
    pub height: u64,
    pub block_id: String,
    pub qc_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplifiedQuorumCertificate {
    pub context: ConsensusObjectContext,
    pub block_id: String,
    pub parent_block_id: String,
    pub parent: SimplifiedFinalityParent,
    pub takeover_tc_id: Option<String>,
    pub protected_execution_root: String,
    pub participants: Vec<ParticipantSignature>,
}

impl SimplifiedQuorumCertificate {
    pub fn from_votes(mut votes: Vec<BlockVote>) -> PosyResult<Self> {
        let first = votes
            .first()
            .cloned()
            .ok_or_else(|| PosyError::invalid("cannot assemble QC without votes"))?;
        if votes.iter().any(|vote| {
            vote.context != first.context
                || vote.block_id != first.block_id
                || vote.parent_block_id != first.parent_block_id
                || vote.parent != first.parent
                || vote.takeover_tc_id != first.takeover_tc_id
                || vote.protected_execution_root != first.protected_execution_root
        }) {
            return Err(PosyError::invalid("QC votes do not share a transcript"));
        }
        votes.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        Ok(Self {
            context: first.context,
            block_id: first.block_id,
            parent_block_id: first.parent_block_id,
            parent: first.parent,
            takeover_tc_id: first.takeover_tc_id,
            protected_execution_root: first.protected_execution_root,
            participants: votes
                .into_iter()
                .map(|vote| ParticipantSignature {
                    validator_id: vote.validator_id,
                    key_id: vote.key_id,
                    signature: vote.signature,
                })
                .collect(),
        })
    }

    pub fn reference(&self) -> PosyResult<QuorumCertificateReference> {
        Ok(QuorumCertificateReference {
            height: self.context.height,
            block_id: self.block_id.clone(),
            qc_id: self.id()?,
        })
    }

    /// Stable certified-candidate identity. The proof round, takeover
    /// certificate, participant subset, and signature bytes deliberately do
    /// not change the identity named by descendant proposals.
    pub fn subject(&self) -> PosyResult<CertifiedCandidateSubject> {
        CertifiedCandidateSubject::new(
            self.context.clone(),
            self.block_id.clone(),
            self.parent_block_id.clone(),
            self.parent.clone(),
            self.protected_execution_root.clone(),
        )
    }

    pub fn id(&self) -> PosyResult<String> {
        self.subject()?.id()
    }

    pub fn verify(
        &self,
        epoch_context: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<()> {
        self.context.validate_against(epoch_context)?;
        self.parent.validate_for_child_height(self.context.height)?;
        if self.block_id.trim().is_empty()
            || self.parent_block_id != self.parent.block_id()
            || self.participants.is_empty()
            || self
                .takeover_tc_id
                .as_deref()
                .is_some_and(|id| !crate::is_hash(id))
            || self
                .participants
                .windows(2)
                .any(|pair| pair[0].validator_id >= pair[1].validator_id)
        {
            return Err(PosyError::invalid(
                "invalid canonical QC participants or ancestry",
            ));
        }

        let mut signers = Vec::new();
        let mut seen_keys = BTreeSet::new();
        for participant in &self.participants {
            if !seen_keys.insert(&participant.key_id) {
                return Err(PosyError::invalid("QC has duplicate consensus key"));
            }
            let validator = validators.active_validator(&participant.validator_id)?;
            if validator.consensus_key_id != participant.key_id {
                return Err(PosyError::invalid("QC signer uses wrong frozen key"));
            }
            let vote = BlockVote {
                context: self.context.clone(),
                block_id: self.block_id.clone(),
                parent_block_id: self.parent_block_id.clone(),
                parent: self.parent.clone(),
                takeover_tc_id: self.takeover_tc_id.clone(),
                protected_execution_root: self.protected_execution_root.clone(),
                validator_id: participant.validator_id.clone(),
                key_id: participant.key_id.clone(),
                signature: participant.signature.clone(),
            };
            validate_block_vote(&vote, epoch_context, validators, verifier)?;
            signers.push(participant.validator_id.clone());
        }
        verify_strict_dual_quorum(&validators.quorum_validators(), &signers).map_err(|error| {
            PosyError::Quorum(match error {
                crate::QuorumError::StrictDistinctSigner { signed, total } => {
                    crate::errors::QuorumError::InsufficientDistinct { signed, total }
                }
                crate::QuorumError::StrictFrozenWeight { signed, total } => {
                    crate::errors::QuorumError::InsufficientWeight { signed, total }
                }
                crate::QuorumError::DuplicateValidator => {
                    crate::errors::QuorumError::DuplicateSigner("validator".into())
                }
                other => return PosyError::invalid(format!("invalid frozen quorum: {other:?}")),
            })
        })?;
        Ok(())
    }
}
