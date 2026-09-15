use std::collections::{BTreeMap, BTreeSet};

use super::{FrozenValidator, QuorumError};

/// Validates the existing strict PoSy dual quorum: 3*signed > 2*total for
/// independent validator count and frozen epoch voting weight.
pub fn verify_strict_dual_quorum(
    validators: &[FrozenValidator],
    signers: &[String],
) -> Result<(), QuorumError> {
    if validators.is_empty() {
        return Err(QuorumError::EmptyValidatorSet);
    }

    let mut weights = BTreeMap::new();
    for validator in validators {
        if validator.frozen_voting_weight == 0 {
            return Err(QuorumError::ZeroWeight);
        }
        if weights
            .insert(
                validator.validator_id.clone(),
                validator.frozen_voting_weight,
            )
            .is_some()
        {
            return Err(QuorumError::DuplicateValidator);
        }
    }

    let mut distinct = BTreeSet::new();
    let mut signed = 0u128;
    for signer in signers {
        if !distinct.insert(signer) {
            continue;
        }
        signed = signed
            .checked_add(
                *weights
                    .get(signer)
                    .ok_or_else(|| QuorumError::UnknownSigner(signer.clone()))?,
            )
            .ok_or(QuorumError::StrictFrozenWeight {
                signed: u128::MAX,
                total: 0,
            })?;
    }

    let total = weights.values().copied().sum::<u128>();
    let signer_count = distinct.len();
    if signer_count.saturating_mul(3) <= validators.len().saturating_mul(2) {
        return Err(QuorumError::StrictDistinctSigner {
            signed: signer_count,
            total: validators.len(),
        });
    }
    if signed
        .checked_mul(3)
        .zip(total.checked_mul(2))
        .is_none_or(|(a, b)| a <= b)
    {
        return Err(QuorumError::StrictFrozenWeight { signed, total });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validators(weights: &[u128]) -> Vec<FrozenValidator> {
        weights
            .iter()
            .enumerate()
            .map(|(index, weight)| FrozenValidator {
                validator_id: format!("v{index}"),
                frozen_voting_weight: *weight,
            })
            .collect()
    }

    fn signers(ids: &[usize]) -> Vec<String> {
        ids.iter().map(|index| format!("v{index}")).collect()
    }

    #[test]
    fn preserves_strict_non_uniform_dual_quorum() {
        let validators = validators(&[7, 3, 3, 3, 3]);
        assert!(verify_strict_dual_quorum(&validators, &signers(&[0, 1, 2, 3])).is_ok());
        assert_eq!(
            verify_strict_dual_quorum(&validators, &signers(&[0, 1, 2])),
            Err(QuorumError::StrictDistinctSigner {
                signed: 3,
                total: 5
            })
        );
        assert!(matches!(
            verify_strict_dual_quorum(&validators, &signers(&[1, 2, 3, 4])),
            Err(QuorumError::StrictFrozenWeight { .. })
        ));
    }
}
