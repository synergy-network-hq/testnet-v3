use crate::{
    ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyResult, SimplifiedEpochContext,
    SimplifiedQuorumCertificate,
};

pub fn verify_quorum_certificate(
    certificate: &SimplifiedQuorumCertificate,
    context: &SimplifiedEpochContext,
    validators: &FrozenValidatorRegistry,
    verifier: &impl ConsensusSignatureVerifier,
) -> PosyResult<()> {
    certificate.verify(context, validators, verifier)
}
