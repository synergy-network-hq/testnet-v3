use serde::{Deserialize, Serialize};

use crate::{
    canonical_hash, is_hash, FinalizedBlockRecord, PosyError, PosyResult, SimplifiedEpochContext,
};

/// Finalized authority for preparing membership changes in the next epoch.
///
/// This type cannot alter the active frozen registry. It binds a change-set
/// commitment to the finality certificate that closes the preceding epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipAuthority {
    pub previous_epoch: u64,
    pub previous_epoch_context_root: String,
    pub finalized_height: u64,
    pub finality_certificate_id: String,
    pub target_epoch: u64,
    pub change_set_root: String,
}

impl MembershipAuthority {
    /// Validates this authority against an epoch context and finalized record.
    pub fn validate(
        &self,
        previous: &SimplifiedEpochContext,
        finalized: &FinalizedBlockRecord,
    ) -> PosyResult<()> {
        let target_epoch = previous
            .epoch
            .checked_add(1)
            .ok_or_else(|| PosyError::invalid("membership target epoch overflow"))?;
        if self.previous_epoch != previous.epoch
            || self.previous_epoch_context_root != previous.root()?
            // Under three-QC finality the terminal QC finalizes end - 2.
            // The boundary caller must verify the full three-QC witness.
            || self.finalized_height.checked_add(2) != Some(previous.epoch_end_height)
            || self.finalized_height != finalized.height
            || self.finality_certificate_id != finalized.finality_certificate_id
            || self.target_epoch != target_epoch
            || !is_hash(&self.finality_certificate_id)
            || !is_hash(&self.change_set_root)
            || !previous.contains_height(self.finalized_height)
        {
            return Err(PosyError::invalid(
                "membership authority is not bound to finalized epoch closure",
            ));
        }
        Ok(())
    }

    /// Returns the canonical identifier referenced by next-epoch changes.
    pub fn id(&self) -> PosyResult<String> {
        canonical_hash("Synergy/PoSy/v3/membership-authority", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrozenValidatorRegistry, ValidatorRecord, ValidatorStatus};

    #[test]
    fn membership_authority_uses_three_qc_epoch_closure() {
        let validators = FrozenValidatorRegistry::new(
            4,
            (0..5)
                .map(|i| ValidatorRecord {
                    validator_id: format!("validator-{i}"),
                    consensus_key_id: format!("key-{i}"),
                    frozen_voting_weight: 1,
                    status: ValidatorStatus::Active,
                })
                .collect(),
        )
        .unwrap();
        let previous = SimplifiedEpochContext::from_frozen_registry(
            7,
            "membership-qualification".into(),
            4,
            101,
            1100,
            "1".repeat(64),
            "2".repeat(64),
            &validators,
        )
        .unwrap();
        let finalized = FinalizedBlockRecord {
            height: 1098,
            block_id: "3".repeat(64),
            finality_certificate_id: "4".repeat(64),
            protected_execution_root: "5".repeat(64),
        };
        let mut authority = MembershipAuthority {
            previous_epoch: 4,
            previous_epoch_context_root: previous.root().unwrap(),
            finalized_height: 1098,
            finality_certificate_id: finalized.finality_certificate_id.clone(),
            target_epoch: 5,
            change_set_root: "6".repeat(64),
        };
        assert!(authority.validate(&previous, &finalized).is_ok());
        for height in [1097, 1099, 1100, u64::MAX] {
            authority.finalized_height = height;
            let wrong = FinalizedBlockRecord {
                height,
                ..finalized.clone()
            };
            assert!(authority.validate(&previous, &wrong).is_err());
        }
        authority.finalized_height = finalized.height;
        authority.target_epoch = 6;
        assert!(authority.validate(&previous, &finalized).is_err());
    }
}
