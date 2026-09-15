use serde::{Deserialize, Serialize};

use crate::{FrozenValidatorRegistry, PosyError, PosyResult, SimplifiedEpochContext};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTransitionAuthorization {
    pub previous_epoch: u64,
    pub previous_epoch_context_root: String,
    pub finalized_height: u64,
    pub next_epoch: u64,
    pub next_epoch_start_height: u64,
    pub next_epoch_end_height: u64,
    pub next_consensus_parameter_root: String,
    pub next_active_validator_set_root: String,
    pub next_validator_consensus_key_root: String,
    pub next_frozen_voting_weight_root: String,
}

impl EpochTransitionAuthorization {
    pub fn validate(
        &self,
        previous: &SimplifiedEpochContext,
        next: &SimplifiedEpochContext,
        next_registry: &FrozenValidatorRegistry,
    ) -> PosyResult<()> {
        if self.previous_epoch != previous.epoch
            || self.next_epoch != previous.epoch.saturating_add(1)
            || self.next_epoch != next.epoch
            || self.previous_epoch_context_root != previous.root()?
            || self.finalized_height.checked_add(2) != Some(previous.epoch_end_height)
            || self.next_epoch_start_height != previous.epoch_end_height.saturating_add(1)
            || self.next_epoch_start_height != next.epoch_start_height
            || self.next_epoch_end_height != next.epoch_end_height
            || self.next_consensus_parameter_root != next.consensus_parameter_root
            || self.next_active_validator_set_root != next.active_validator_set_root
            || self.next_validator_consensus_key_root != next.validator_consensus_key_root
            || self.next_frozen_voting_weight_root != next.frozen_voting_weight_root
            || next_registry.epoch() != next.epoch
            || self.finalized_height == 0
        {
            return Err(PosyError::invalid(
                "invalid finalized epoch transition authority",
            ));
        }
        Ok(())
    }
}
