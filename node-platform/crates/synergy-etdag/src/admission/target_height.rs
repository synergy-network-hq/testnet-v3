use crate::{EtdagError, MAX_EXPERIMENTAL_TARGET_HEIGHT_OFFSET, MIN_TARGET_HEIGHT_OFFSET};

pub fn protected_target_height(finalized_height: u64) -> Result<u64, EtdagError> {
    protected_target_height_with_offset(finalized_height, MIN_TARGET_HEIGHT_OFFSET)
}

pub fn validate_protected_target_height(source: u64, target: u64) -> Result<(), EtdagError> {
    validate_protected_target_height_with_offset(source, target, MIN_TARGET_HEIGHT_OFFSET)
}

fn validate_offset(offset: u64) -> Result<(), EtdagError> {
    if !(MIN_TARGET_HEIGHT_OFFSET..=MAX_EXPERIMENTAL_TARGET_HEIGHT_OFFSET).contains(&offset) {
        return Err(EtdagError::InvalidTargetOffset);
    }
    Ok(())
}

pub fn protected_target_height_with_offset(source: u64, offset: u64) -> Result<u64, EtdagError> {
    validate_offset(offset)?;
    source
        .checked_add(offset)
        .ok_or(EtdagError::InvalidTargetOffset)
}

pub fn source_finalized_height_with_offset(target: u64, offset: u64) -> Result<u64, EtdagError> {
    validate_offset(offset)?;
    if target < 3 {
        return Err(EtdagError::ContextMismatch);
    }
    Ok(target.saturating_sub(offset))
}

/// Genesis opens H3 through HD; each subsequent finalized source opens F+D.
pub fn validate_protected_target_height_with_offset(
    source: u64,
    target: u64,
    offset: u64,
) -> Result<(), EtdagError> {
    validate_offset(offset)?;
    // Check addition before comparison, retaining the legacy overflow rejection.
    let expected = protected_target_height_with_offset(source, offset)?;
    if (source == 0 && (3..=offset).contains(&target)) || (source > 0 && target == expected) {
        Ok(())
    } else {
        Err(EtdagError::ContextMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_opens_h3_h4_h5_without_requiring_future_finality() {
        for target in 0..=7 {
            assert_eq!(
                validate_protected_target_height(0, target).is_ok(),
                (3..=5).contains(&target)
            );
        }
    }

    #[test]
    fn later_finality_opens_only_f_plus_five_and_rejects_overflow() {
        for source in 1..=20 {
            for target in 0..=26 {
                assert_eq!(
                    validate_protected_target_height(source, target).is_ok(),
                    target == source + 5
                );
            }
        }
        assert_eq!(
            validate_protected_target_height(u64::MAX, 4),
            Err(EtdagError::InvalidTargetOffset)
        );
    }
}
