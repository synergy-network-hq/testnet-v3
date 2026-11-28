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

    let total = weights.values().try_fold(0u128, |total, weight| {
        total
            .checked_add(*weight)
            .ok_or(QuorumError::StrictFrozenWeight {
                signed,
                total: u128::MAX,
            })
    })?;
    let signer_count = distinct.len();
    if signer_count.saturating_mul(3) <= validators.len().saturating_mul(2) {
        return Err(QuorumError::StrictDistinctSigner {
            signed: signer_count,
            total: validators.len(),
        });
    }
    // PoSy v0.5 p21: qW=floor(2W/3)+1. Decompose before multiplying so
    // representable frozen totals do not lose liveness through comparison
    // overflow. Actual signed/total accumulation above remains checked.
    let floor_two_thirds = (total / 3) * 2 + ((total % 3) * 2) / 3;
    if signed <= floor_two_thirds {
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
    #[test]
    fn representable_large_weights_use_exact_strict_comparison_without_overflow() {
        let unit = u128::MAX / 6;
        let equal = validators(&[unit; 6]);
        assert!(verify_strict_dual_quorum(&equal, &signers(&[0, 1, 2, 3, 4])).is_ok());
        assert!(verify_strict_dual_quorum(&equal, &signers(&[0, 1, 2, 3, 4, 5])).is_ok());
        assert!(verify_strict_dual_quorum(&equal, &signers(&[0, 1, 2, 3])).is_err());
        let skewed = validators(&[u128::MAX - 5, 1, 1, 1, 1, 1]);
        assert!(verify_strict_dual_quorum(&skewed, &signers(&[0, 1, 2, 3, 4])).is_ok());
        assert!(matches!(verify_strict_dual_quorum(&skewed, &signers(&[1, 2, 3, 4, 5])),
            Err(QuorumError::StrictFrozenWeight { .. })));
    }
    #[test]
    fn dynamic_frozen_denominators_and_weight_overflow_fail_closed() {
        for n in [3, 4, 5, 9, 10, 20, 21, 150, 151] {
            let vs = validators(&vec![1; n]);
            let q = 2 * n / 3 + 1;
            assert!(verify_strict_dual_quorum(&vs, &signers(&(0..q).collect::<Vec<_>>())).is_ok());
            assert!(
                verify_strict_dual_quorum(&vs, &signers(&(0..q - 1).collect::<Vec<_>>())).is_err()
            );
        }
        // No signer-weight overflow is needed to trigger total overflow.
        let vs = validators(&[u128::MAX, 1, 1]);
        assert!(verify_strict_dual_quorum(&vs, &signers(&[1, 2])).is_err());
        assert!(verify_strict_dual_quorum(&vs, &signers(&[0, 1, 2])).is_err());
        // Exact two-thirds (count and weight) never qualifies.
        assert!(verify_strict_dual_quorum(&validators(&[1, 1, 1]), &signers(&[0, 1])).is_err());
    }
}
