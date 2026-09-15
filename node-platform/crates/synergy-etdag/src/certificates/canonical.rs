use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

use super::{
    BatchFinalityCertificate, BatchTimeoutCertificate, BatchValidationCertificate,
    OrderingCertificate,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateSignature {
    pub validator_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

impl CertificateSignature {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        if self.validator_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.signature.is_empty()
        {
            return Err(EtdagError::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalCertificate {
    TargetAdmission(crate::admission::AdmissionCertificate),
    Availability(crate::AvailabilityCertificate),
    Ordering(OrderingCertificate),
    BatchValidation(BatchValidationCertificate),
    BatchFinality(BatchFinalityCertificate),
    BatchTimeout(BatchTimeoutCertificate),
}

pub fn canonical_certificate_root(
    certificate: &CanonicalCertificate,
) -> Result<EtdagDigest, EtdagError> {
    match certificate {
        CanonicalCertificate::TargetAdmission(cert) => {
            super::target_admission_certificate_root(cert)
        }
        CanonicalCertificate::Availability(cert) => super::availability_certificate_root(cert),
        CanonicalCertificate::Ordering(cert) => cert.certificate_root(),
        CanonicalCertificate::BatchValidation(cert) => cert.certificate_root(),
        CanonicalCertificate::BatchFinality(cert) => cert.certificate_root(),
        CanonicalCertificate::BatchTimeout(cert) => cert.certificate_root(),
    }
}
