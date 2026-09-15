//! Frozen domain separators for the canonical ETDAG protocol.

pub const ENVELOPE_ID: &str = "SYNERGY_ETDAG_ENVELOPE_V1";
pub const ADMISSION_REQUEST: &str = "SYNERGY_ETDAG_ADMISSION_REQUEST_V1";
pub const ADMISSION_CERTIFICATE: &str = "SYNERGY_ETDAG_ADMISSION_CERTIFICATE_V1";
pub const DAG_VERTEX: &str = "SYNERGY_ETDAG_VERTEX_V1";
pub const AVAILABILITY_VOTE: &str = "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1";
pub const PROTECTED_BATCH: &str = "SYNERGY_ETDAG_PROTECTED_BATCH_V1";
pub const EXECUTION_HANDOFF: &str = "SYNERGY_ETDAG_EXECUTION_HANDOFF_V1";

pub fn validate_domain(domain: &str) -> Result<(), crate::EtdagError> {
    if matches!(
        domain,
        ENVELOPE_ID
            | ADMISSION_REQUEST
            | ADMISSION_CERTIFICATE
            | DAG_VERTEX
            | AVAILABILITY_VOTE
            | PROTECTED_BATCH
            | EXECUTION_HANDOFF
    ) {
        Ok(())
    } else {
        Err(crate::EtdagError::Corrupt(
            "unrecognized ETDAG domain separator".into(),
        ))
    }
}
