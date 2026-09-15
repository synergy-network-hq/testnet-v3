use serde::{Deserialize, Serialize};
use synergy_posy::ValidatorId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorLifecycleState {
    Registered,
    Authorized,
    Synchronizing,
    Shadowing,
    Ready,
    ActivationScheduled,
    Active,
    Jailed,
    Removed,
    Expelled,
}

pub trait ActiveMembershipWitness {
    fn confirms_active(&self, validator_id: &str, epoch: u64) -> Result<bool, String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorLifecycle {
    pub validator_id: ValidatorId,
    pub state: ValidatorLifecycleState,
    pub target_epoch: u64,
    pub required_shadow_blocks: u64,
    pub shadow_progress_blocks: u64,
}

impl ValidatorLifecycle {
    pub fn new(
        validator_id: ValidatorId,
        target_epoch: u64,
        required_shadow_blocks: u64,
    ) -> Result<Self, String> {
        if validator_id.trim().is_empty() || target_epoch == 0 || required_shadow_blocks == 0 {
            return Err("invalid validator lifecycle registration".into());
        }
        Ok(Self {
            validator_id,
            state: ValidatorLifecycleState::Registered,
            target_epoch,
            required_shadow_blocks,
            shadow_progress_blocks: 0,
        })
    }

    pub fn record_shadow_progress(&mut self, verified_blocks: u64) -> Result<(), String> {
        if self.state != ValidatorLifecycleState::Shadowing {
            return Err("shadow progress is accepted only while shadowing".into());
        }
        self.shadow_progress_blocks = self
            .shadow_progress_blocks
            .checked_add(verified_blocks)
            .ok_or_else(|| "shadow progress overflow".to_string())?;
        Ok(())
    }

    pub fn transition(
        &mut self,
        next: ValidatorLifecycleState,
        active_witness: Option<&impl ActiveMembershipWitness>,
    ) -> Result<(), String> {
        let permitted = matches!(
            (self.state, next),
            (
                ValidatorLifecycleState::Registered,
                ValidatorLifecycleState::Authorized
            ) | (
                ValidatorLifecycleState::Authorized,
                ValidatorLifecycleState::Synchronizing
            ) | (
                ValidatorLifecycleState::Synchronizing,
                ValidatorLifecycleState::Shadowing
            ) | (
                ValidatorLifecycleState::Shadowing,
                ValidatorLifecycleState::Ready
            ) | (
                ValidatorLifecycleState::Ready,
                ValidatorLifecycleState::ActivationScheduled
            ) | (
                ValidatorLifecycleState::ActivationScheduled,
                ValidatorLifecycleState::Active
            ) | (
                ValidatorLifecycleState::Active,
                ValidatorLifecycleState::Jailed
            ) | (
                ValidatorLifecycleState::Active,
                ValidatorLifecycleState::Removed
            ) | (
                ValidatorLifecycleState::Active,
                ValidatorLifecycleState::Expelled
            ) | (
                ValidatorLifecycleState::Jailed,
                ValidatorLifecycleState::ActivationScheduled
            ) | (
                ValidatorLifecycleState::Jailed,
                ValidatorLifecycleState::Removed
            ) | (
                ValidatorLifecycleState::Jailed,
                ValidatorLifecycleState::Expelled
            ) | (_, ValidatorLifecycleState::Removed)
        );
        if !permitted {
            return Err("invalid validator lifecycle transition".into());
        }
        if next == ValidatorLifecycleState::Ready
            && self.shadow_progress_blocks < self.required_shadow_blocks
        {
            return Err("required governed shadow progress is incomplete".into());
        }
        if next == ValidatorLifecycleState::Active {
            let witness = active_witness.ok_or_else(|| {
                "active transition requires frozen PoSy membership proof".to_string()
            })?;
            if !witness.confirms_active(&self.validator_id, self.target_epoch)? {
                return Err("frozen PoSy membership does not confirm active authority".into());
            }
        }
        self.state = next;
        Ok(())
    }
}
