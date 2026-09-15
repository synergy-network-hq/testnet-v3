use synergy_posy::{MembershipAuthority, ValidatorRecord, ValidatorRegistration, ValidatorStatus};

use crate::ValidatorApplication;

pub fn stage_shadow_registration(
    application: ValidatorApplication,
    authority: &MembershipAuthority,
    frozen_voting_weight: u128,
) -> Result<ValidatorRegistration, String> {
    application.validate(authority.previous_epoch)?;
    if application.target_epoch != authority.target_epoch {
        return Err("validator application targets a different epoch".into());
    }
    let registration = ValidatorRegistration {
        target_epoch: application.target_epoch,
        validator: ValidatorRecord {
            validator_id: application.validator_id,
            consensus_key_id: application.consensus_key_id,
            frozen_voting_weight,
            status: ValidatorStatus::Shadow,
        },
        membership_authority_id: authority.id().map_err(|error| error.to_string())?,
    };
    registration
        .validate(authority)
        .map_err(|error| error.to_string())?;
    Ok(registration)
}
