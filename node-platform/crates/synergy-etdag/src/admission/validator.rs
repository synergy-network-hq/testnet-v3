use super::{
    verify_admission_request, AdmissionRequest, AdmissionResourceLimits,
    AdmissionSignatureVerifier,
};
use crate::{EtdagDigest, EtdagError};

pub struct AdmissionValidator<V> {
    chain_id: u64,
    network_id: String,
    context_root: EtdagDigest,
    target_height: u64,
    limits: AdmissionResourceLimits,
    verifier: V,
}

impl<V: AdmissionSignatureVerifier> AdmissionValidator<V> {
    pub fn new(
        chain_id: u64,
        network_id: String,
        context_root: EtdagDigest,
        target_height: u64,
        limits: AdmissionResourceLimits,
        verifier: V,
    ) -> Result<Self, EtdagError> {
        context_root.validate()?;
        limits.validate()?;
        if chain_id == 0
            || network_id.trim().is_empty()
            || network_id.len() > 128
            || network_id.contains(char::is_control)
            || target_height == 0
        {
            return Err(EtdagError::ContextMismatch);
        }
        Ok(Self {
            chain_id,
            network_id,
            context_root,
            target_height,
            limits,
            verifier,
        })
    }

    pub fn verify(&self, request: &AdmissionRequest) -> Result<(), EtdagError> {
        self.limits.validate_envelope(&request.envelope)?;
        verify_admission_request(
            request,
            self.chain_id,
            &self.network_id,
            &self.context_root,
            self.target_height,
            &self.verifier,
        )
    }
}
