use serde::{Deserialize, Serialize};
use synergy_governance::EthereumActivationDraft;

/// Typed operations for the live native owner, never arbitrary signing bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernanceOperation {
    PrepareMembershipRetirement {retired_validator_id:String},
    ReviewMembershipRetirement {draft:synergy_governance::MembershipRetirementDraft},
    MembershipRetirementApprovalStatus {draft:synergy_governance::MembershipRetirementDraft},
    ApproveMembershipRetirement {draft:synergy_governance::MembershipRetirementDraft,review_root:String},
    AssembleMembershipRetirement {draft:synergy_governance::MembershipRetirementDraft,review_root:String,votes:Vec<synergy_governance::GovernanceVote>},
    PrepareEthereum {
        policy_json: String,
    },
    ReviewEthereum {
        draft: EthereumActivationDraft,
    },
    EthereumApprovalStatus {
        draft: EthereumActivationDraft,
    },
    ApproveEthereum {
        draft: EthereumActivationDraft,
        review_root: String,
    },
    AssembleEthereum {
        draft: EthereumActivationDraft,
        review_root: String,
        votes: Vec<synergy_governance::GovernanceVote>,
    },
}
impl GovernanceOperation {
    pub const fn is_mutating(&self) -> bool {
        matches!(self, Self::ApproveEthereum { .. }|Self::ApproveMembershipRetirement{..})
    }
    pub fn validate(&self) -> Result<(), crate::AdminError> {
        use crate::AdminError;
        if let Self::PrepareMembershipRetirement{retired_validator_id}=self {
            if retired_validator_id.is_empty()||retired_validator_id.len()>128||retired_validator_id.contains(char::is_control){return Err(AdminError::invalid_request("exact bounded validator identity required"));}
            return Ok(());
        }
        let membership=match self {
            Self::ReviewMembershipRetirement{draft}|Self::MembershipRetirementApprovalStatus{draft}
            |Self::ApproveMembershipRetirement{draft,..}|Self::AssembleMembershipRetirement{draft,..}=>Some(draft),_=>None};
        if let Some(draft)=membership {
            if serde_json::to_vec(draft).map_err(|_|AdminError::invalid_request("invalid retirement draft"))?.len()>65536{return Err(AdminError::invalid_request("retirement draft exceeds bound"));}
            let root=draft.review_root().map_err(AdminError::invalid_request)?;
            if let Self::ApproveMembershipRetirement{review_root,..}|Self::AssembleMembershipRetirement{review_root,..}=self {
                if *review_root!=root{return Err(AdminError::invalid_request("retirement review root differs"));}
            }
            if let Self::AssembleMembershipRetirement{votes,..}=self {
                if votes.is_empty()||votes.len()>64{return Err(AdminError::invalid_request("retirement vote bound exceeded"));}
                for vote in votes{vote.validate_shape().map_err(AdminError::invalid_request)?;}
            }
            return Ok(());
        }
        let draft = match self {
            Self::PrepareEthereum { policy_json } => {
                if policy_json.is_empty() || policy_json.len() > 8192 {
                    return Err(crate::AdminError::invalid_request(
                        "bounded explicit Ethereum policy required",
                    ));
                }
                return Ok(());
            }
            Self::ReviewEthereum { draft }
            | Self::ApproveEthereum { draft, .. }
            | Self::EthereumApprovalStatus { draft, .. }
            | Self::AssembleEthereum { draft, .. } => draft,
            Self::PrepareMembershipRetirement{..}|Self::ReviewMembershipRetirement{..}|Self::MembershipRetirementApprovalStatus{..}|Self::ApproveMembershipRetirement{..}|Self::AssembleMembershipRetirement{..}=>unreachable!("handled above"),
        };
        if serde_json::to_vec(draft)
            .map_err(|_| crate::AdminError::invalid_request("invalid governance draft"))?
            .len()
            > 65536
        {
            return Err(crate::AdminError::invalid_request(
                "governance review exceeds bound",
            ));
        }
        let root = draft
            .review_root()
            .map_err(crate::AdminError::invalid_request)?;
        if let Self::ApproveEthereum { review_root, .. }
        | Self::AssembleEthereum { review_root, .. } = self
        {
            if *review_root != root {
                return Err(crate::AdminError::invalid_request(
                    "governance review root differs",
                ));
            }
        }
        if let Self::AssembleEthereum { votes, .. } = self {
            if votes.is_empty() || votes.len() > 64 {
                return Err(crate::AdminError::invalid_request(
                    "governance vote bound exceeded",
                ));
            }
            for vote in votes {
                vote.validate_shape()
                    .map_err(crate::AdminError::invalid_request)?;
            }
        }
        Ok(())
    }
}
