use std::collections::BTreeMap;

use crate::{EtdagError, IngressKemKeyRecord, IngressKemKeyRegistry};

pub fn validate_key_schedule(registry: &IngressKemKeyRegistry) -> Result<(), EtdagError> {
    registry.validate_shape()?;
    let mut previous_by_validator = BTreeMap::<&str, &IngressKemKeyRecord>::new();
    let mut records = registry.records.iter().collect::<Vec<_>>();
    records.sort_by_key(|record| (record.validator_id.as_str(), record.activation_height));
    for record in records {
        if let Some(previous) = previous_by_validator.insert(&record.validator_id, record) {
            let retirement = previous.retirement_height.ok_or_else(|| {
                EtdagError::Governance(format!(
                    "key {} has no retirement before successor activation",
                    previous.key_id
                ))
            })?;
            if retirement > record.activation_height {
                return Err(EtdagError::Governance(format!(
                    "validator {} has overlapping ingress keys",
                    record.validator_id
                )));
            }
        }
    }
    Ok(())
}

pub fn active_key_for_validator<'a>(
    registry: &'a IngressKemKeyRegistry,
    validator_id: &str,
    target_height: u64,
) -> Result<&'a IngressKemKeyRecord, EtdagError> {
    validate_key_schedule(registry)?;
    registry
        .records
        .iter()
        .find(|record| {
            record.validator_id == validator_id
                && record.activation_height <= target_height
                && record
                    .retirement_height
                    .is_none_or(|retirement| target_height < retirement)
        })
        .ok_or_else(|| {
            EtdagError::MissingArtifact(format!("active ingress key for {validator_id}"))
        })
}
