//! Canonical application-facing amendment encoding. Constructing a spec or
//! mutation grants no authority: the native owner independently authenticates
//! scope, frozen dual quorum, one-use state and finalized activation height.
use crate::GovernedStateMutation;
use serde::{Deserialize, Serialize};

pub const ETHEREUM_ACTIVATION_ACTION_V1: &str = "aivm-ethereum-activation-v1";
pub const ETHEREUM_ACTIVATION_TARGET_V1: &str = "canonical";
pub const ETHEREUM_ACTIVATION_RECORD_KEY_V1: &str =
    "governance/aivm-ethereum-activation-v1/canonical";
pub const ETHEREUM_ACTIVATION_HISTORY_WARMUP_BLOCKS: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthereumActivationSpec {
    pub schema_version: u32,
    pub profile_id: String,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub frozen_epoch: u64,
    pub frozen_epoch_context_root: String,
    pub install_height: u64,
    pub activation_height: u64,
    pub policy_sha256: String,
    pub policy_bytes: Vec<u8>,
}
impl EthereumActivationSpec {
    /// Exact field order/bytes used by the proposal's signed mutation root.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }
    /// Builds only the canonical, unused initial-installation CAS mutation.
    /// Apps must gather genuine frozen approvals and submit it through native
    /// account admission; this helper does not authorize or install the policy.
    pub fn mutation(&self) -> Result<GovernedStateMutation, String> {
        Ok(GovernedStateMutation {
            action_kind: ETHEREUM_ACTIVATION_ACTION_V1.into(),
            target: ETHEREUM_ACTIVATION_TARGET_V1.into(),
            expected_value: None,
            value: self.canonical_bytes()?,
        })
    }
}

/// Public, unsigned review input. The renderer cannot supply a signing
/// transcript: native validators reconstruct it from this exact draft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthereumActivationDraft {
    pub spec: EthereumActivationSpec,
    pub proposal: crate::GovernanceProposal,
    pub constitution: crate::Constitution,
}
impl EthereumActivationDraft {
    pub fn validate(&self) -> Result<(), String> {
        self.proposal.validate(&self.constitution)?;
        let mutation = self.spec.mutation()?;
        if self.proposal.state != crate::ProposalState::Authorized
            || self.proposal.actions.len() != 1
            || self.proposal.actions[0].kind != mutation.action_kind
            || self.proposal.actions[0].target != mutation.target
            || self.proposal.actions[0].payload_root != mutation.payload_root()?
            || self.spec.schema_version != 1
            || self.spec.install_height < self.proposal.created_at_height
            || self.spec.install_height > self.proposal.expires_at_height
            || self.spec.activation_height
                < self
                    .proposal
                    .expires_at_height
                    .checked_add(ETHEREUM_ACTIVATION_HISTORY_WARMUP_BLOCKS)
                    .ok_or("activation height overflow")?
            || self.spec.policy_bytes.is_empty()
            || self.spec.policy_bytes.len() > 16384
        {
            return Err("invalid exact Ethereum activation draft".into());
        }
        let rule = self.constitution.rule(ETHEREUM_ACTIVATION_ACTION_V1)?;
        if self.spec.install_height
            < self
                .proposal
                .created_at_height
                .checked_add(rule.minimum_delay_blocks)
                .ok_or("activation delay overflow")?
        {
            return Err("activation draft does not satisfy its signed delay".into());
        }
        Ok(())
    }
    pub fn review_root(&self) -> Result<String, String> {
        self.validate()?;
        crate::canonical_root(b"SYNERGY_ETHEREUM_ACTIVATION_REVIEW_V1", self)
    }
    /// Existing authorization encoding, with native verification of every vote.
    /// The caller must additionally enforce the actual frozen dual quorum.
    pub fn assemble(
        &self,
        votes: Vec<crate::GovernanceVote>,
        verifier: &impl crate::VoteVerifier,
    ) -> Result<crate::GovernanceExecution, String> {
        self.validate()?;
        let approving: std::collections::BTreeSet<_> =
            votes.iter().map(|vote| vote.authority_id.clone()).collect();
        let root = crate::canonical_root(
            b"SYNERGY_GOVERNANCE_AUTHORIZATION_V1",
            &(
                &self.proposal.proposal_root,
                &self.constitution.constitution_root,
                &approving,
            ),
        )?;
        let authorization = crate::GovernanceAuthorization::assemble(
            &self.proposal,
            &self.constitution,
            &votes,
            verifier,
            root.clone(),
        )?;
        let activation = crate::GovernedActivation::new(
            &self.proposal,
            &authorization,
            crate::ActivationPoint::FinalizedHeight {
                height: self.spec.install_height,
            },
        )?;
        Ok(crate::GovernanceExecution {
            proposal: self.proposal.clone(),
            constitution: self.constitution.clone(),
            votes,
            authorization_root: root,
            activation,
            mutation: self.spec.mutation()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exported_spec_preserves_signed_wire_contract() {
        let bytes=br#"{"schema_version":1,"profile_id":"aivm-ethereum-eip155-shanghai-v1","chain_id":99999,"network_id":"canary-fixture","genesis_hash":"genesis","frozen_epoch":1,"frozen_epoch_context_root":"epoch","install_height":10,"activation_height":286,"policy_sha256":"policy","policy_bytes":[123,125]}"#;
        // Placeholder hashes deliberately exercise encoding only, not native
        // policy authorization. Native validation rejects this incomplete spec.
        let spec: EthereumActivationSpec = serde_json::from_slice(bytes).unwrap();
        assert_eq!(spec.canonical_bytes().unwrap(), bytes);
        let mutation = spec.mutation().unwrap();
        assert_eq!(mutation.action_kind, "aivm-ethereum-activation-v1");
        assert_eq!(mutation.target, "canonical");
        assert!(mutation.expected_value.is_none());
        assert_eq!(mutation.value, bytes);
        assert_eq!(
            mutation.state_key().unwrap(),
            "governance/aivm-ethereum-activation-v1/canonical"
        );
        let mut unknown = serde_json::from_slice::<serde_json::Value>(bytes).unwrap();
        unknown["caller_threshold"] = serde_json::json!(1);
        assert!(serde_json::from_value::<EthereumActivationSpec>(unknown).is_err());
    }
}
