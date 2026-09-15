use crate::{AvailabilityCertificate, EtdagDigest, EtdagError};

pub fn availability_certificate_root(
    certificate: &AvailabilityCertificate,
) -> Result<EtdagDigest, EtdagError> {
    certificate.context_root.validate()?;
    certificate.vertex_id.validate()?;
    if certificate.votes.is_empty() {
        return Err(EtdagError::InsufficientAvailability {
            signed: 0,
            required: 1,
        });
    }
    let mut votes = certificate.votes.clone();
    votes.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_AVAILABILITY_CERTIFICATE_V1",
        &(&certificate.context_root, &certificate.vertex_id, votes),
    )
}
