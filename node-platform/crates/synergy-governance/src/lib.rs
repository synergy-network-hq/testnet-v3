//! Governed change authorization contracts.
//!
//! Governance approval may authorize configuration or protocol activation, but
//! it never creates PoSy votes, QCs, validator membership, or finality.
pub mod activation;
pub mod audit;
pub mod authorization;
pub mod constitution;
pub mod emergency;
pub mod ethereum_activation;
pub mod execution;
pub mod membership;
pub mod validator_admission;
pub use validator_admission::*;
pub mod proposal;
pub mod vote;

pub use activation::{ActivationPoint, GovernedActivation};
pub use authorization::GovernanceAuthorization;
pub use constitution::{Constitution, GovernanceRule};
pub use emergency::EmergencyAuthorization;
pub use ethereum_activation::{
    EthereumActivationDraft, EthereumActivationSpec, ETHEREUM_ACTIVATION_ACTION_V1,
    ETHEREUM_ACTIVATION_HISTORY_WARMUP_BLOCKS, ETHEREUM_ACTIVATION_RECORD_KEY_V1,
    ETHEREUM_ACTIVATION_TARGET_V1,
};
pub use execution::{GovernanceExecution, GovernedStateMutation};
pub use membership::{MembershipRetirementSpec, MembershipRetirementDraft, MEMBERSHIP_RETIREMENT_ACTION_V1};
pub use proposal::{GovernanceAction, GovernanceProposal, ProposalState};
pub use vote::{GovernanceVote, VoteChoice, VoteVerifier};

pub(crate) fn bounded(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.contains(char::is_control)
}

pub(crate) fn canonical_root(
    domain: &[u8],
    value: &impl serde::Serialize,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("encode governance commitment: {error}"))?;
    let root =
        synergy_crypto::sha3_256_segments(&synergy_crypto::AegisSha3_256, &[domain, &bytes])?;
    Ok(root.0.iter().map(|byte| format!("{byte:02x}")).collect())
}
