use synergy_posy::{FrozenValidatorRegistry, MembershipAuthority, ValidatorRecord};

pub fn prepare_next_epoch_records(
    current_epoch: u64,
    authority: &MembershipAuthority,
    records: Vec<ValidatorRecord>,
) -> Result<Vec<ValidatorRecord>, String> {
    if authority.previous_epoch != current_epoch
        || authority.target_epoch != current_epoch.saturating_add(1)
    {
        return Err("validator migration lacks next-epoch authority".into());
    }
    for record in &records {
        record.validate().map_err(|error| error.to_string())?;
    }
    // Constructing the next frozen registry preserves unique validator/key
    // bindings, nonzero frozen weights, and the independent active-validator
    // count floor. Quorum verification continues to enforce count and weight.
    FrozenValidatorRegistry::new(authority.target_epoch, records.clone())
        .map_err(|error| error.to_string())?;
    Ok(records)
}
