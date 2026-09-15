use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFinalityCertificate {
    pub certificate_version: u32,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub protected_batch_root: EtdagDigest,
    pub posy_finality_reference: EtdagDigest,
}

impl BatchFinalityCertificate {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.protected_batch_root.validate()?;
        self.posy_finality_reference.validate()?;
        if self.certificate_version != 1 || self.target_height == 0 {
            return Err(EtdagError::UnauthorizedReveal);
        }
        Ok(())
    }

    pub fn certificate_root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate_shape()?;
        EtdagDigest::from_canonical("SYNERGY_ETDAG_BATCH_FINALITY_REFERENCE_V1", self)
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

/// Implemented by the PoSy owner. ETDAG can consume, but never manufacture,
/// finality authority.
pub trait FinalityReferenceVerifier {
    fn verify_finality_reference(
        &self,
        certificate: &BatchFinalityCertificate,
    ) -> Result<(), EtdagError>;
}
