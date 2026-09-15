use synergy_posy::{ScheduledJailing, ValidatorId};

pub fn schedule_jailing(
    validator_id: ValidatorId,
    evidence_root: String,
    current_epoch: u64,
    effective_epoch: u64,
    release_epoch: Option<u64>,
    authorization_root: String,
) -> Result<ScheduledJailing, String> {
    let decision = ScheduledJailing {
        validator_id,
        evidence_root,
        effective_epoch,
        release_epoch,
        authorization_root,
    };
    decision
        .validate(current_epoch)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}
