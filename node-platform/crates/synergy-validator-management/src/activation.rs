use serde::{Deserialize, Serialize};
use synergy_posy::{is_hash, MembershipAuthority, ValidatorId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationRequest {
    pub validator_id: ValidatorId,
    pub target_epoch: u64,
    pub membership_authority_id: String,
}

impl ActivationRequest {
    pub fn validate(&self, authority: &MembershipAuthority) -> Result<(), String> {
        if self.validator_id.trim().is_empty()
            || self.target_epoch != authority.target_epoch
            || !is_hash(&self.membership_authority_id)
            || self.membership_authority_id != authority.id().map_err(|error| error.to_string())?
        {
            return Err("activation request is not bound to next-epoch authority".into());
        }
        Ok(())
    }
}
