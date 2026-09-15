use crate::admission::{AdmissionRequest, AdmissionResourceLimits};
use crate::{EtdagDigest, EtdagError};

pub fn validate_ingress_envelope(
    request: &AdmissionRequest,
    context_root: &EtdagDigest,
    target_height: u64,
    limits: &AdmissionResourceLimits,
) -> Result<(), EtdagError> {
    request.validate_shape()?;
    if &request.context_root != context_root || request.target_height != target_height {
        return Err(EtdagError::ContextMismatch);
    }
    limits.validate_envelope(&request.envelope)
}
