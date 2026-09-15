use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Constitution, GovernanceProposal, GovernanceVote, VoteChoice, VoteVerifier};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceAuthorization {
    pub proposal_root: String,
    pub constitution_root: String,
    pub approving_authorities: BTreeSet<String>,
    pub authorization_root: String,
}

impl GovernanceAuthorization {
    pub fn assemble(
        proposal: &GovernanceProposal,
        constitution: &Constitution,
        votes: &[GovernanceVote],
        verifier: &impl VoteVerifier,
        authorization_root: String,
    ) -> Result<Self, String> {
        proposal.validate(constitution)?;
        let mut approvals = BTreeSet::new();
        for vote in votes {
            vote.validate_shape()?;
            verifier.verify(vote)?;
            if vote.proposal_root != proposal.proposal_root
                || vote.choice != VoteChoice::Approve
                || !approvals.insert(vote.authority_id.clone())
            {
                return Err("invalid or duplicate governance approval".into());
            }
        }
        for action in &proposal.actions {
            let rule = constitution.rule(&action.kind)?;
            let eligible = approvals
                .iter()
                .filter(|authority| rule.eligible_authorities.contains(*authority))
                .count();
            if eligible < rule.approval_threshold {
                return Err("governance approval threshold not met".into());
            }
        }
        let expected_root = crate::canonical_root(
            b"SYNERGY_GOVERNANCE_AUTHORIZATION_V1",
            &(
                &proposal.proposal_root,
                &constitution.constitution_root,
                &approvals,
            ),
        )?;
        if authorization_root != expected_root {
            return Err("governance authorization root mismatch".into());
        }
        Ok(Self {
            proposal_root: proposal.proposal_root.clone(),
            constitution_root: constitution.constitution_root.clone(),
            approving_authorities: approvals,
            authorization_root,
        })
    }
}
