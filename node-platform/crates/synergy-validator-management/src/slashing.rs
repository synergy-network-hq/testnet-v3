use synergy_posy::{SlashingDecision, ValidatorId};

pub fn schedule_slashing(
    validator_id: ValidatorId,
    evidence_root: String,
    penalty_units: u128,
    current_epoch: u64,
    effective_epoch: u64,
    authorization_root: String,
) -> Result<SlashingDecision, String> {
    let decision = SlashingDecision {
        validator_id,
        evidence_root,
        penalty_units,
        effective_epoch,
        authorization_root,
    };
    decision
        .validate(current_epoch)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}
