use serde::{Deserialize, Serialize};
use synergy_protocol_types::NodeAddress;

use crate::RewardError;

/// Canonical reward account keyed only by NodeAddress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewardAccount {
    pub node_address: NodeAddress,
    pub total_earned_nwei: u128,
    pub pending_withdrawal_nwei: u128,
    pub withdrawn_nwei: u128,
    pub sequence: u64,
}

impl RewardAccount {
    pub fn available_nwei(&self) -> Result<u128, RewardError> {
        self.total_earned_nwei
            .checked_sub(self.pending_withdrawal_nwei)
            .and_then(|value| value.checked_sub(self.withdrawn_nwei))
            .ok_or(RewardError::CorruptState)
    }

    pub(crate) fn validate(&self) -> Result<(), RewardError> {
        if self.sequence == 0 {
            return Err(RewardError::CorruptState);
        }
        self.available_nwei().map(|_| ())
    }
}
