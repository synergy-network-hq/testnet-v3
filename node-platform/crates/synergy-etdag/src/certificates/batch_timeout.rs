use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

use super::CertificateSignature;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchTimeoutCertificate {
    pub certificate_version: u32,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub protected_round: u64,
    pub reason_code: String,
    pub signatures: Vec<CertificateSignature>,
}

impl BatchTimeoutCertificate {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        if self.certificate_version != 1
            || self.target_height == 0
            || self.reason_code.trim().is_empty()
            || self.reason_code.len() > 128
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        super::ordering::validate_signatures(&self.signatures)
    }

    pub fn certificate_root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate_shape()?;
        EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_BATCH_TIMEOUT_CERTIFICATE_V1",
            &(
                self.certificate_version,
                &self.context_root,
                self.target_height,
                self.protected_round,
                self.reason_code.trim(),
            ),
        )
    }
}
