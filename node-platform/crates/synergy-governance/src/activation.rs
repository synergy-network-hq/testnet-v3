use serde::{Deserialize, Serialize};

use crate::{GovernanceAuthorization, GovernanceProposal};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActivationPoint {
    FinalizedHeight { height: u64 },
    Epoch { epoch: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedActivation {
    pub proposal_root: String,
    pub authorization_root: String,
    pub point: ActivationPoint,
}

impl GovernedActivation {
    pub fn new(
        proposal: &GovernanceProposal,
        authorization: &GovernanceAuthorization,
        point: ActivationPoint,
    ) -> Result<Self, String> {
        if proposal.proposal_root != authorization.proposal_root {
            return Err("activation authorization is for a different proposal".into());
        }
        let value = match point {
            ActivationPoint::FinalizedHeight { height } => height,
            ActivationPoint::Epoch { epoch } => epoch,
        };
        if value == 0 {
            return Err("governance activation point must be nonzero".into());
        }
        Ok(Self {
            proposal_root: proposal.proposal_root.clone(),
            authorization_root: authorization.authorization_root.clone(),
            point,
        })
    }
}
