use serde::{Deserialize, Serialize};
use synergy_crypto::{sha3_256_segments, AegisSha3_256};

use crate::{
    ActivationPoint, Constitution, GovernanceAuthorization, GovernanceProposal, GovernanceVote,
    GovernedActivation, ProposalState, VoteVerifier,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedStateMutation {
    pub action_kind: String,
    pub target: String,
    pub expected_value: Option<Vec<u8>>,
    pub value: Vec<u8>,
}

impl GovernedStateMutation {
    pub fn payload_root(&self) -> Result<String, String> {
        let root = sha3_256_segments(
            &AegisSha3_256,
            &[
                b"SYNERGY_GOVERNANCE_STATE_MUTATION_V1",
                self.action_kind.as_bytes(),
                self.target.as_bytes(),
                &self.value,
            ],
        )?;
        Ok(root.0.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub fn state_key(&self) -> Result<String, String> {
        if self.action_kind.trim().is_empty()
            || self.action_kind.len() > 128
            || self.target.trim().is_empty()
            || self.target.len() > 256
            || self.value.is_empty()
            || self.value.len() > 4 * 1024 * 1024
        {
            return Err("invalid governed state mutation".into());
        }
        Ok(format!("governance/{}/{}", self.action_kind, self.target))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceExecution {
    pub proposal: GovernanceProposal,
    pub constitution: Constitution,
    pub votes: Vec<GovernanceVote>,
    pub authorization_root: String,
    pub activation: GovernedActivation,
    pub mutation: GovernedStateMutation,
}

impl GovernanceExecution {
    pub fn verify(
        &self,
        verifier: &impl VoteVerifier,
        authorization_id: &str,
        block_height: u64,
    ) -> Result<String, String> {
        if self.proposal.state != ProposalState::Authorized
            || authorization_id != self.authorization_root
            || self.activation.authorization_root != self.authorization_root
            || self.activation.proposal_root != self.proposal.proposal_root
            || self.votes.is_empty()
        {
            return Err("governance execution authorization mismatch".into());
        }
        let authorization = GovernanceAuthorization::assemble(
            &self.proposal,
            &self.constitution,
            &self.votes,
            verifier,
            self.authorization_root.clone(),
        )?;
        let expected_activation = GovernedActivation::new(
            &self.proposal,
            &authorization,
            ActivationPoint::FinalizedHeight {
                height: block_height,
            },
        )?;
        if self.activation != expected_activation {
            return Err("governance action is not activated at this block height".into());
        }
        if block_height > self.proposal.expires_at_height {
            return Err("governance proposal expired before activation".into());
        }
        let action = self
            .proposal
            .actions
            .iter()
            .find(|action| {
                action.kind == self.mutation.action_kind && action.target == self.mutation.target
            })
            .ok_or("governance mutation is absent from the authorized proposal")?;
        let rule = self.constitution.rule(&action.kind)?;
        let earliest = self
            .proposal
            .created_at_height
            .checked_add(rule.minimum_delay_blocks)
            .ok_or("governance activation height overflow")?;
        if block_height < earliest {
            return Err("governance action has not satisfied its minimum delay".into());
        }
        if action.payload_root != self.mutation.payload_root()? {
            return Err("governance mutation differs from its authorized payload root".into());
        }
        self.mutation.state_key()
    }
}
