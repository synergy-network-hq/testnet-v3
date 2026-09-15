use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError, ProtectedOrderingProof};

use super::CertificateSignature;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingCertificate {
    pub proof: ProtectedOrderingProof,
    pub signatures: Vec<CertificateSignature>,
}

impl OrderingCertificate {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        crate::ordering::verify_ordering_proof(&self.proof)?;
        validate_signatures(&self.signatures)
    }

    pub fn certificate_root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate_shape()?;
        EtdagDigest::from_canonical("SYNERGY_ETDAG_ORDERING_CERTIFICATE_V1", &self.proof)
    }
}

pub(crate) fn validate_signatures(signatures: &[CertificateSignature]) -> Result<(), EtdagError> {
    if signatures.is_empty() {
        return Err(EtdagError::InvalidSignature);
    }
    let mut validators = BTreeSet::new();
    for signature in signatures {
        signature.validate_shape()?;
        if !validators.insert(signature.validator_id.as_str()) {
            return Err(EtdagError::ConflictingArtifact(
                "duplicate certificate signer".into(),
            ));
        }
    }
    Ok(())
}
