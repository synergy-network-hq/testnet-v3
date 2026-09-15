use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use synergy_aegis::SignatureAlgorithm;
use synergy_posy::{ValidatorRecord, POSY_MIN_VALIDATOR_COUNT};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisValidator {
    pub record: ValidatorRecord,
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
}

pub fn validate(validators: &[GenesisValidator]) -> Result<(), String> {
    if validators.len() < POSY_MIN_VALIDATOR_COUNT {
        return Err(format!(
            "genesis requires at least {POSY_MIN_VALIDATOR_COUNT} validators"
        ));
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for validator in validators {
        validator
            .record
            .validate()
            .map_err(|error| error.to_string())?;
        if !validator.record.may_sign_consensus()
            || validator.algorithm != SignatureAlgorithm::MlDsa65
            || validator.public_key.is_empty()
            || !ids.insert(&validator.record.validator_id)
            || !keys.insert(&validator.record.consensus_key_id)
        {
            return Err("invalid, duplicate, inactive, or unsupported genesis validator".into());
        }
    }
    Ok(())
}
