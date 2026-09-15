use std::path::PathBuf;

use crate::{
    ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyError, PosyResult,
    SimplifiedEpochContext, SimplifiedTimeoutCertificate,
};

use super::CanonicalObjectStore;

/// Durable, independently reverified timeout certificates for exact
/// height/round recovery. A certificate never grants membership or finality.
#[derive(Debug)]
pub struct VerifiedTimeoutCertificateStore(CanonicalObjectStore<SimplifiedTimeoutCertificate>);

impl VerifiedTimeoutCertificateStore {
    pub fn new(root: impl Into<PathBuf>) -> PosyResult<Self> {
        CanonicalObjectStore::new(root, "verified-timeouts").map(Self)
    }

    pub fn put_verified(
        &self,
        certificate: &SimplifiedTimeoutCertificate,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<bool> {
        certificate.verify(epoch, validators, verifier)?;
        let key = key(certificate.context.height, certificate.context.round);
        if let Some(existing) = self.get_verified(
            certificate.context.height,
            certificate.context.round,
            epoch,
            validators,
            verifier,
        )? {
            return if existing.id()? == certificate.id()? {
                Ok(false)
            } else {
                Err(PosyError::Conflict(
                    "different timeout closure already stored at one height/round".into(),
                ))
            };
        }
        self.0.put_once(&key, certificate)
    }

    pub fn get_verified(
        &self,
        height: u64,
        round: u64,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Option<SimplifiedTimeoutCertificate>> {
        let Some(certificate) = self.0.get(&key(height, round))? else {
            return Ok(None);
        };
        if certificate.context.height != height || certificate.context.round != round {
            return Err(PosyError::Conflict(
                "stored timeout certificate differs from its recovery slot".into(),
            ));
        }
        certificate.verify(epoch, validators, verifier)?;
        Ok(Some(certificate))
    }
}

fn key(height: u64, round: u64) -> String {
    format!("h{height}r{round}")
}
