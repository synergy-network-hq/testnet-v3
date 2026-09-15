use synergy_posy::{ScheduledExpulsion, ValidatorId};

pub fn schedule_expulsion(
    validator_id: ValidatorId,
    evidence_root: String,
    current_epoch: u64,
    effective_epoch: u64,
    authorization_root: String,
) -> Result<ScheduledExpulsion, String> {
    let decision = ScheduledExpulsion {
        validator_id,
        evidence_root,
        effective_epoch,
        authorization_root,
    };
    decision
        .validate(current_epoch)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}
