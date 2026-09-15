use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{bounded, Constitution};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceAction {
    pub kind: String,
    pub target: String,
    pub payload_root: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalState {
    Draft,
    Open,
    Authorized,
    Activated,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceProposal {
    pub proposal_id: String,
    pub proposal_root: String,
    pub proposer: String,
    pub constitution_version: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub actions: Vec<GovernanceAction>,
    pub state: ProposalState,
}

impl GovernanceProposal {
    pub fn canonical_root(&self) -> Result<String, String> {
        crate::canonical_root(
            b"SYNERGY_GOVERNANCE_PROPOSAL_V1",
            &(
                &self.proposal_id,
                &self.proposer,
                self.constitution_version,
                self.created_at_height,
                self.expires_at_height,
                &self.actions,
            ),
        )
    }

    pub fn validate(&self, constitution: &Constitution) -> Result<(), String> {
        constitution.validate()?;
        if !bounded(&self.proposal_id, 256)
            || !bounded(&self.proposal_root, 256)
            || !bounded(&self.proposer, 256)
            || self.constitution_version != constitution.version
            || self.created_at_height == 0
            || self.expires_at_height <= self.created_at_height
            || self.actions.is_empty()
            || self.actions.len() > 64
            || self.proposal_root != self.canonical_root()?
        {
            return Err("invalid governance proposal".into());
        }
        let mut targets = BTreeSet::new();
        for action in &self.actions {
            constitution.rule(&action.kind)?;
            if !bounded(&action.target, 512)
                || !bounded(&action.payload_root, 256)
                || !targets.insert((action.kind.as_str(), action.target.as_str()))
            {
                return Err("invalid or duplicate governance action".into());
            }
        }
        Ok(())
    }
}
