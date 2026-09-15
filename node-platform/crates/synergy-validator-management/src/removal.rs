use synergy_posy::{ScheduledDeactivation, ValidatorId};

pub fn schedule_removal(
    validator_id: ValidatorId,
    current_epoch: u64,
    effective_epoch: u64,
    authorization_root: String,
) -> Result<ScheduledDeactivation, String> {
    let decision = ScheduledDeactivation {
        validator_id,
        effective_epoch,
        authorization_root,
    };
    decision
        .validate(current_epoch)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}
