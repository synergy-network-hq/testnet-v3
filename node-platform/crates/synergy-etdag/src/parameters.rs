use crate::{EtdagError, ETDAG_EXPERIMENTAL_PROFILE_ID, ETDAG_PROFILE_ID};

pub const MIN_TARGET_HEIGHT_OFFSET: u64 = 5;
pub const MAX_EXPERIMENTAL_TARGET_HEIGHT_OFFSET: u64 = 16;
pub const MAX_OUTSTANDING_NONCE_SLOTS: usize = 4;
pub const CIPHERTEXT_SIZE_CLASSES: &[usize] =
    &[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EtdagParameters {
    pub profile_id: String,
    pub target_height_offset: u64,
    pub max_outstanding_nonce_slots: usize,
    pub ciphertext_size_classes: Vec<usize>,
    pub max_protected_gas: u64,
    pub max_protected_bytes: u64,
}

impl Default for EtdagParameters {
    fn default() -> Self {
        Self {
            profile_id: ETDAG_PROFILE_ID.into(),
            target_height_offset: MIN_TARGET_HEIGHT_OFFSET,
            max_outstanding_nonce_slots: MAX_OUTSTANDING_NONCE_SLOTS,
            ciphertext_size_classes: CIPHERTEXT_SIZE_CLASSES.to_vec(),
            max_protected_gas: 30_000_000,
            max_protected_bytes: 8 * 1024 * 1024,
        }
    }
}

impl EtdagParameters {
    pub fn protected_target_height(&self, source: u64) -> Result<u64, EtdagError> {
        self.validate()?;
        crate::admission::protected_target_height_with_offset(source, self.target_height_offset)
    }

    pub fn source_finalized_height(&self, target: u64) -> Result<u64, EtdagError> {
        self.validate()?;
        crate::admission::source_finalized_height_with_offset(target, self.target_height_offset)
    }

    pub fn validate_target_height(&self, source: u64, target: u64) -> Result<(), EtdagError> {
        self.validate()?;
        crate::admission::validate_protected_target_height_with_offset(
            source,
            target,
            self.target_height_offset,
        )
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        match self.profile_id.as_str() {
            ETDAG_PROFILE_ID if self.target_height_offset == MIN_TARGET_HEIGHT_OFFSET => {}
            ETDAG_EXPERIMENTAL_PROFILE_ID
                if (6..=MAX_EXPERIMENTAL_TARGET_HEIGHT_OFFSET)
                    .contains(&self.target_height_offset) => {}
            ETDAG_PROFILE_ID | ETDAG_EXPERIMENTAL_PROFILE_ID => {
                return Err(EtdagError::InvalidTargetOffset)
            }
            _ => return Err(EtdagError::UnsupportedProfile),
        }
        if self.max_outstanding_nonce_slots == 0
            || self.max_protected_gas == 0
            || self.max_protected_bytes == 0
        {
            return Err(EtdagError::InvalidCapacity);
        }
        if self.ciphertext_size_classes != CIPHERTEXT_SIZE_CLASSES {
            return Err(EtdagError::InvalidCiphertextClasses);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn experiment(offset: u64) -> EtdagParameters {
        EtdagParameters {
            profile_id: ETDAG_EXPERIMENTAL_PROFILE_ID.into(),
            target_height_offset: offset,
            ..Default::default()
        }
    }

    #[test]
    fn profile_and_offset_must_be_governed_together() {
        assert!(EtdagParameters::default().validate().is_ok());
        for offset in 0..=20 {
            let legacy = EtdagParameters {
                target_height_offset: offset,
                ..Default::default()
            };
            assert_eq!(legacy.validate().is_ok(), offset == 5);
            assert_eq!(
                experiment(offset).validate().is_ok(),
                (6..=16).contains(&offset)
            );
        }
        let unknown = EtdagParameters {
            profile_id: "unknown".into(),
            ..Default::default()
        };
        assert_eq!(unknown.validate(), Err(EtdagError::UnsupportedProfile));
    }

    #[test]
    fn all_experimental_sources_and_genesis_targets_use_one_mapping() {
        for offset in 6..=16 {
            let parameters = experiment(offset);
            for target in 0..=offset + 3 {
                if target < 3 {
                    assert!(parameters.source_finalized_height(target).is_err());
                } else {
                    let source = parameters.source_finalized_height(target).unwrap();
                    assert_eq!(source, target.saturating_sub(offset));
                    assert!(parameters.validate_target_height(source, target).is_ok());
                }
                assert_eq!(
                    parameters.validate_target_height(0, target).is_ok(),
                    (3..=offset).contains(&target)
                );
            }
            for source in 1..=20 {
                let target = parameters.protected_target_height(source).unwrap();
                assert_eq!(target, source + offset);
                assert_eq!(parameters.source_finalized_height(target).unwrap(), source);
                assert!(parameters.validate_target_height(source, target).is_ok());
                assert!(parameters
                    .validate_target_height(source, target + 1)
                    .is_err());
            }
            assert_eq!(
                parameters.protected_target_height(u64::MAX),
                Err(EtdagError::InvalidTargetOffset)
            );
        }
    }
}
