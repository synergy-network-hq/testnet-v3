use serde::{Deserialize, Serialize};

use crate::{
    canonical_hash, is_hash, require_nonempty, PosyError, PosyResult, SimplifiedEpochContext,
    POSY_OBJECT_SCHEMA_VERSION, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusObjectContext {
    pub schema_version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub protocol_version: String,
    pub epoch: u64,
    pub height: u64,
    pub round: u64,
    pub epoch_context_root: String,
    pub consensus_parameter_root: String,
    pub active_validator_set_root: String,
    pub validator_consensus_key_root: String,
    pub frozen_voting_weight_root: String,
}

impl ConsensusObjectContext {
    pub fn for_height(
        epoch_context: &SimplifiedEpochContext,
        height: u64,
        round: u64,
    ) -> PosyResult<Self> {
        if !epoch_context.contains_height(height) {
            return Err(PosyError::invalid(
                "consensus object height is outside epoch",
            ));
        }
        Ok(Self {
            schema_version: POSY_OBJECT_SCHEMA_VERSION,
            chain_id: epoch_context.chain_id,
            network_id: epoch_context.network_id.clone(),
            protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.into(),
            epoch: epoch_context.epoch,
            height,
            round,
            epoch_context_root: epoch_context.root()?,
            consensus_parameter_root: epoch_context.consensus_parameter_root.clone(),
            active_validator_set_root: epoch_context.active_validator_set_root.clone(),
            validator_consensus_key_root: epoch_context.validator_consensus_key_root.clone(),
            frozen_voting_weight_root: epoch_context.frozen_voting_weight_root.clone(),
        })
    }

    pub fn validate_against(&self, epoch_context: &SimplifiedEpochContext) -> PosyResult<()> {
        if self.schema_version != POSY_OBJECT_SCHEMA_VERSION
            || self.chain_id != epoch_context.chain_id
            || self.network_id != epoch_context.network_id
            || self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
            || self.epoch != epoch_context.epoch
            || !epoch_context.contains_height(self.height)
            || self.epoch_context_root != epoch_context.root()?
            || self.consensus_parameter_root != epoch_context.consensus_parameter_root
            || self.active_validator_set_root != epoch_context.active_validator_set_root
            || self.validator_consensus_key_root != epoch_context.validator_consensus_key_root
            || self.frozen_voting_weight_root != epoch_context.frozen_voting_weight_root
        {
            return Err(PosyError::invalid(
                "consensus object does not match frozen epoch context",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reference", rename_all = "snake_case")]
pub enum SimplifiedFinalityParent {
    Genesis {
        genesis_hash: String,
        block_id: String,
        reference_id: String,
    },
    QuorumCertificate {
        height: u64,
        block_id: String,
        qc_id: String,
    },
}

impl SimplifiedFinalityParent {
    pub fn validate_for_child_height(&self, child_height: u64) -> PosyResult<()> {
        match self {
            Self::Genesis {
                genesis_hash,
                block_id,
                reference_id,
            } if child_height == 1
                && is_hash(genesis_hash)
                && !block_id.trim().is_empty()
                && is_hash(reference_id) =>
            {
                Ok(())
            }
            Self::Genesis { .. } => Err(PosyError::invalid(
                "Genesis reference may only parent fresh chain block one",
            )),
            Self::QuorumCertificate {
                height,
                block_id,
                qc_id,
            } if height.checked_add(1) == Some(child_height)
                && !block_id.trim().is_empty()
                && is_hash(qc_id) =>
            {
                Ok(())
            }
            Self::QuorumCertificate { .. } => Err(PosyError::invalid(
                "quorum-certificate parent does not precede its child",
            )),
        }
    }

    pub fn height(&self) -> u64 {
        match self {
            Self::Genesis { .. } => 0,
            Self::QuorumCertificate { height, .. } => *height,
        }
    }

    pub fn quorum_certificate_reference(&self) -> Option<crate::QuorumCertificateReference> {
        match self {
            Self::Genesis { .. } => None,
            Self::QuorumCertificate {
                height,
                block_id,
                qc_id,
            } => Some(crate::QuorumCertificateReference {
                height: *height,
                block_id: block_id.clone(),
                qc_id: qc_id.clone(),
            }),
        }
    }

    pub fn block_id(&self) -> &str {
        match self {
            Self::Genesis { block_id, .. } | Self::QuorumCertificate { block_id, .. } => block_id,
        }
    }

    pub fn reference_id(&self) -> &str {
        match self {
            Self::Genesis { reference_id, .. } => reference_id,
            Self::QuorumCertificate { qc_id, .. } => qc_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplifiedProposal {
    pub context: ConsensusObjectContext,
    pub proposer_id: String,
    pub block_id: String,
    pub parent_block_id: String,
    pub parent: SimplifiedFinalityParent,
    pub takeover_tc_id: Option<String>,
    pub protected_execution_root: String,
    pub proposer_key_id: String,
    pub proposer_signature: Vec<u8>,
}

#[derive(Serialize)]
struct ProposalSigningPayload<'a> {
    context: &'a ConsensusObjectContext,
    proposer_id: &'a str,
    block_id: &'a str,
    parent_block_id: &'a str,
    parent: &'a SimplifiedFinalityParent,
    takeover_tc_id: &'a Option<String>,
    protected_execution_root: &'a str,
    proposer_key_id: &'a str,
}

impl SimplifiedProposal {
    pub fn signing_bytes(&self) -> PosyResult<Vec<u8>> {
        serde_json::to_vec(&ProposalSigningPayload {
            context: &self.context,
            proposer_id: &self.proposer_id,
            block_id: &self.block_id,
            parent_block_id: &self.parent_block_id,
            parent: &self.parent,
            takeover_tc_id: &self.takeover_tc_id,
            protected_execution_root: &self.protected_execution_root,
            proposer_key_id: &self.proposer_key_id,
        })
        .map_err(|error| PosyError::invalid(format!("serialize proposal transcript: {error}")))
    }

    pub fn validate_shape(&self) -> PosyResult<()> {
        self.parent.validate_for_child_height(self.context.height)?;
        require_nonempty(&self.proposer_id, "proposal proposer")?;
        require_nonempty(&self.block_id, "proposal block id")?;
        require_nonempty(&self.proposer_key_id, "proposal key")?;
        if self.parent_block_id != self.parent.block_id()
            || !is_hash(&self.protected_execution_root)
            || self
                .takeover_tc_id
                .as_deref()
                .is_some_and(|id| !is_hash(id))
        {
            return Err(PosyError::invalid(
                "invalid proposal ancestry or protected root",
            ));
        }
        Ok(())
    }

    pub fn candidate_subject(&self) -> PosyResult<CertifiedCandidateSubject> {
        CertifiedCandidateSubject::new(
            self.context.clone(),
            self.block_id.clone(),
            self.parent_block_id.clone(),
            self.parent.clone(),
            self.protected_execution_root.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedCandidateSubject {
    pub context: ConsensusObjectContext,
    pub block_id: String,
    pub parent_block_id: String,
    pub parent: SimplifiedFinalityParent,
    pub protected_execution_root: String,
}

impl CertifiedCandidateSubject {
    pub fn new(
        mut context: ConsensusObjectContext,
        block_id: String,
        parent_block_id: String,
        parent: SimplifiedFinalityParent,
        protected_execution_root: String,
    ) -> PosyResult<Self> {
        context.round = 0;
        let subject = Self {
            context,
            block_id,
            parent_block_id,
            parent,
            protected_execution_root,
        };
        subject.validate()?;
        Ok(subject)
    }

    pub fn validate(&self) -> PosyResult<()> {
        self.parent.validate_for_child_height(self.context.height)?;
        if self.context.round != 0
            || self.block_id.trim().is_empty()
            || self.parent_block_id != self.parent.block_id()
            || !is_hash(&self.protected_execution_root)
        {
            return Err(PosyError::invalid("invalid certified candidate subject"));
        }
        Ok(())
    }

    pub fn id(&self) -> PosyResult<String> {
        self.validate()?;
        canonical_hash("SYNERGY_POSY_SIMPLIFIED_CERTIFIED_CANDIDATE_V1", self)
    }
}
