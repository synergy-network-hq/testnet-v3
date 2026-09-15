use std::collections::BTreeSet;

use crate::{
    crypto::{canonical_signing_bytes, SignatureVerifier},
    EtdagDigest, EtdagError,
};

use super::CertificateSignature;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateQuorum {
    pub members: BTreeSet<String>,
    pub required_signers: usize,
}

impl CertificateQuorum {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.members.is_empty()
            || self.required_signers == 0
            || self.required_signers > self.members.len()
        {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(())
    }
}

pub fn verify_certificate_signatures(
    certificate_domain: &str,
    certificate_root: &EtdagDigest,
    signatures: &[CertificateSignature],
    quorum: &CertificateQuorum,
    verifier: &impl SignatureVerifier,
) -> Result<(), EtdagError> {
    certificate_root.validate()?;
    quorum.validate()?;
    let message = canonical_signing_bytes(certificate_domain, certificate_root)?;
    let mut verified = BTreeSet::new();
    for signature in signatures {
        signature.validate_shape()?;
        if !quorum.members.contains(&signature.validator_id) {
            return Err(EtdagError::UnauthorizedValidator(
                signature.validator_id.clone(),
            ));
        }
        if !verified.insert(signature.validator_id.as_str()) {
            return Err(EtdagError::ConflictingArtifact(
                "duplicate certificate signer".into(),
            ));
        }
        verifier.verify(
            &signature.validator_id,
            &signature.key_id,
            &message,
            &signature.signature,
        )?;
    }
    if verified.len() < quorum.required_signers {
        return Err(EtdagError::InsufficientAvailability {
            signed: verified.len(),
            required: quorum.required_signers,
        });
    }
    Ok(())
}
