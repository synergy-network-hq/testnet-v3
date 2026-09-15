use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonical_hash, FrozenValidator, PosyError, PosyResult, ValidatorId, ValidatorRecord,
    ValidatorStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenValidatorRegistry {
    epoch: u64,
    validators: BTreeMap<ValidatorId, ValidatorRecord>,
}

impl FrozenValidatorRegistry {
    pub fn new(epoch: u64, validators: Vec<ValidatorRecord>) -> PosyResult<Self> {
        if validators.len() < crate::POSY_MIN_VALIDATOR_COUNT {
            return Err(PosyError::invalid(format!(
                "PoSy v3 requires at least {} validators",
                crate::POSY_MIN_VALIDATOR_COUNT
            )));
        }
        let mut indexed = BTreeMap::new();
        let mut keys = BTreeSet::new();
        for validator in validators {
            validator.validate()?;
            if indexed
                .insert(validator.validator_id.clone(), validator.clone())
                .is_some()
            {
                return Err(PosyError::invalid("duplicate validator id"));
            }
            if !keys.insert(validator.consensus_key_id.clone()) {
                return Err(PosyError::invalid("duplicate validator consensus key"));
            }
        }
        if indexed
            .values()
            .filter(|validator| validator.may_sign_consensus())
            .count()
            < crate::POSY_MIN_VALIDATOR_COUNT
        {
            return Err(PosyError::invalid(
                "active validator set is below PoSy minimum",
            ));
        }
        Ok(Self {
            epoch,
            validators: indexed,
        })
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn active(&self) -> impl Iterator<Item = &ValidatorRecord> {
        self.validators
            .values()
            .filter(|validator| validator.status == ValidatorStatus::Active)
    }

    pub fn validator(&self, id: &str) -> PosyResult<&ValidatorRecord> {
        self.validators
            .get(id)
            .ok_or_else(|| PosyError::UnknownValidator(id.into()))
    }

    pub fn active_validator(&self, id: &str) -> PosyResult<&ValidatorRecord> {
        let validator = self.validator(id)?;
        if validator.may_sign_consensus() {
            Ok(validator)
        } else {
            Err(PosyError::invalid(format!(
                "validator {id} is not active for this frozen epoch"
            )))
        }
    }

    pub fn active_count(&self) -> usize {
        self.active().count()
    }

    pub fn active_weight(&self) -> PosyResult<u128> {
        self.active().try_fold(0u128, |total, validator| {
            total
                .checked_add(validator.frozen_voting_weight)
                .ok_or_else(|| PosyError::invalid("active validator weight overflow"))
        })
    }

    pub fn quorum_validators(&self) -> Vec<FrozenValidator> {
        self.active()
            .map(|validator| FrozenValidator {
                validator_id: validator.validator_id.clone(),
                frozen_voting_weight: validator.frozen_voting_weight,
            })
            .collect()
    }

    pub fn active_set_root(&self) -> PosyResult<String> {
        canonical_hash(
            "SYNERGY_POSY_FROZEN_VALIDATOR_SET_V3",
            &self
                .active()
                .map(|validator| &validator.validator_id)
                .collect::<Vec<_>>(),
        )
    }

    pub fn consensus_key_root(&self) -> PosyResult<String> {
        canonical_hash(
            "SYNERGY_POSY_FROZEN_CONSENSUS_KEYS_V3",
            &self
                .active()
                .map(|validator| (&validator.validator_id, &validator.consensus_key_id))
                .collect::<Vec<_>>(),
        )
    }

    pub fn frozen_weight_root(&self) -> PosyResult<String> {
        canonical_hash(
            "SYNERGY_POSY_FROZEN_VOTING_WEIGHTS_V3",
            &self
                .active()
                .map(|validator| (&validator.validator_id, validator.frozen_voting_weight))
                .collect::<Vec<_>>(),
        )
    }
}
