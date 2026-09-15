use serde::{Deserialize, Serialize};

use crate::{DeterministicProtectedExecutionInput, EtdagDigest, EtdagError};

use super::CertificateSignature;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchValidationCertificate {
    pub execution_input: DeterministicProtectedExecutionInput,
    pub execution_input_root: EtdagDigest,
    pub signatures: Vec<CertificateSignature>,
}

impl BatchValidationCertificate {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.execution_input.validate()?;
        self.execution_input_root.validate()?;
        super::ordering::validate_signatures(&self.signatures)?;
        if self.execution_input_root
            != EtdagDigest::from_canonical(
                "SYNERGY_ETDAG_EXECUTION_INPUT_V1",
                &self.execution_input,
            )?
        {
            return Err(EtdagError::ConflictingArtifact(
                "execution input root mismatch".into(),
            ));
        }
        Ok(())
    }

    pub fn certificate_root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate_shape()?;
        EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_BATCH_VALIDATION_CERTIFICATE_V1",
            &self.execution_input_root,
        )
    }
}
