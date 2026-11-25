//! An explicit retirement authorization is distinct from permissionless
//! registration eligibility. Neither changes a currently frozen committee.
use crate::GovernedStateMutation;
use serde::{Deserialize, Serialize};

pub const MEMBERSHIP_RETIREMENT_ACTION_V1: &str = "posy-membership-retirement-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipRetirementSpec {
    pub schema_version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub frozen_epoch: u64,
    pub frozen_epoch_context_root: String,
    /// Earliest authorized finalized block height, never a wall-clock value.
    /// Encrypted processing assigns actual inclusion before certification.
    pub install_not_before_finalized_height: u64,
    pub effective_epoch: u64,
    pub retired_validator_id: String,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub automatic_admission_policy:Option<crate::AutomaticValidatorAdmissionPolicy>,
}
impl MembershipRetirementSpec {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }
    pub fn mutation(&self) -> Result<GovernedStateMutation, String> {
        Ok(GovernedStateMutation {
            action_kind: MEMBERSHIP_RETIREMENT_ACTION_V1.into(),
            target: format!("epoch-{:020}", self.effective_epoch),
            expected_value: None,
            value: self.canonical_bytes()?,
        })
    }
    pub fn record_key(&self) -> String {
        format!("governance/{MEMBERSHIP_RETIREMENT_ACTION_V1}/epoch-{:020}", self.effective_epoch)
    }
}

/// Closed public review object. Native owners reconstruct the vote transcript.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipRetirementDraft {
    pub spec:MembershipRetirementSpec,
    pub proposal:crate::GovernanceProposal,
    pub constitution:crate::Constitution,
}
impl MembershipRetirementDraft {
    pub fn validate(&self)->Result<(),String>{
        self.proposal.validate(&self.constitution)?;
        if let Some(policy)=&self.spec.automatic_admission_policy {policy.validate()?;}
        let mutation=self.spec.mutation()?;
        let s=&self.spec;
        if self.proposal.state!=crate::ProposalState::Authorized||self.proposal.actions.len()!=1
            ||self.proposal.actions[0].kind!=mutation.action_kind||self.proposal.actions[0].target!=mutation.target
            ||self.proposal.actions[0].payload_root!=mutation.payload_root()?
            ||s.schema_version!=1||s.chain_id==0||!crate::bounded(&s.network_id,256)
            ||s.genesis_hash.len()!=64||s.frozen_epoch_context_root.len()!=64
            ||!s.genesis_hash.bytes().chain(s.frozen_epoch_context_root.bytes()).all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
            ||!crate::bounded(&s.retired_validator_id,128)||s.frozen_epoch.checked_add(1)!=Some(s.effective_epoch)
            ||s.install_not_before_finalized_height>self.proposal.expires_at_height
            ||s.install_not_before_finalized_height<self.proposal.created_at_height.checked_add(self.constitution.rule(MEMBERSHIP_RETIREMENT_ACTION_V1)?.minimum_delay_blocks).ok_or("retirement height overflow")? {
            return Err("invalid closed membership retirement draft".into());
        }
        Ok(())
    }
    pub fn review_root(&self)->Result<String,String>{self.validate()?;crate::canonical_root(b"SYNERGY_MEMBERSHIP_RETIREMENT_REVIEW_V1",self)}
    pub fn assemble(&self,votes:Vec<crate::GovernanceVote>,verifier:&impl crate::VoteVerifier)->Result<crate::GovernanceExecution,String>{
        self.validate()?;
        let approving:std::collections::BTreeSet<_>=votes.iter().map(|v|v.authority_id.clone()).collect();
        let root=crate::canonical_root(b"SYNERGY_GOVERNANCE_AUTHORIZATION_V1",&(&self.proposal.proposal_root,&self.constitution.constitution_root,&approving))?;
        let auth=crate::GovernanceAuthorization::assemble(&self.proposal,&self.constitution,&votes,verifier,root.clone())?;
        let activation=crate::GovernedActivation::new(&self.proposal,&auth,crate::ActivationPoint::FinalizedHeight{height:self.spec.install_not_before_finalized_height})?;
        Ok(crate::GovernanceExecution{proposal:self.proposal.clone(),constitution:self.constitution.clone(),votes,authorization_root:root,activation,mutation:self.spec.mutation()?})
    }
}
