use crate::{admission::AdmissionCertificate, EtdagDigest, EtdagError};

pub fn target_admission_certificate_root(
    certificate: &AdmissionCertificate,
) -> Result<EtdagDigest, EtdagError> {
    certificate.validate_shape()?;
    let mut votes = certificate.votes.clone();
    votes.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_TARGET_ADMISSION_CERTIFICATE_V1",
        &(
            &certificate.context_root,
            certificate.target_height,
            &certificate.envelope_id,
            votes,
        ),
    )
}
