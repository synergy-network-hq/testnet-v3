use crate::{EtdagError, ETDAG_PROFILE_ID};

pub const MIN_TARGET_HEIGHT_OFFSET: u64 = 5;
pub const MAX_OUTSTANDING_NONCE_SLOTS: usize = 4;
pub const CIPHERTEXT_SIZE_CLASSES: &[usize] =
    &[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EtdagParameters {
    pub profile_id: String,
    pub target_height_offset: u64,
    pub max_outstanding_nonce_slots: usize,
    pub ciphertext_size_classes: Vec<usize>,
}

impl Default for EtdagParameters {
    fn default() -> Self {
        Self {
            profile_id: ETDAG_PROFILE_ID.into(),
            target_height_offset: MIN_TARGET_HEIGHT_OFFSET,
            max_outstanding_nonce_slots: MAX_OUTSTANDING_NONCE_SLOTS,
            ciphertext_size_classes: CIPHERTEXT_SIZE_CLASSES.to_vec(),
        }
    }
}

impl EtdagParameters {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.profile_id != ETDAG_PROFILE_ID {
            return Err(EtdagError::UnsupportedProfile);
        }
        if self.target_height_offset != MIN_TARGET_HEIGHT_OFFSET {
            return Err(EtdagError::InvalidTargetOffset);
        }
        if self.max_outstanding_nonce_slots == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        if self.ciphertext_size_classes != CIPHERTEXT_SIZE_CLASSES {
            return Err(EtdagError::InvalidCiphertextClasses);
        }
        Ok(())
    }
}
