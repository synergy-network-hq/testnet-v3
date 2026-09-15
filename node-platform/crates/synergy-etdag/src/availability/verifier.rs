use std::collections::BTreeSet;

use crate::{
    crypto::{canonical_signing_bytes, SignatureVerifier},
    AvailabilityCertificate, EtdagError,
};

pub fn verify_availability_certificate(
    cert: &AvailabilityCertificate,
    members: &BTreeSet<String>,
    verifier: &impl SignatureVerifier,
) -> Result<(), EtdagError> {
    let required = crate::certificate_quorum(members.len())?;
    if cert.votes.len() < required {
        return Err(EtdagError::InsufficientAvailability {
            signed: cert.votes.len(),
            required,
        });
    }
    let mut seen = BTreeSet::new();
    for vote in &cert.votes {
        vote.validate()?;
        if vote.context_root != cert.context_root || vote.vertex_id != cert.vertex_id {
            return Err(EtdagError::ContextMismatch);
        }
        if !members.contains(&vote.validator_id) || !seen.insert(&vote.validator_id) {
            return Err(EtdagError::UnauthorizedValidator(vote.validator_id.clone()));
        }
        let bytes = canonical_signing_bytes(
            "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
            &(
                &vote.context_root,
                &vote.vertex_id,
                &vote.validator_id,
                &vote.key_id,
            ),
        )?;
        verifier.verify(&vote.validator_id, &vote.key_id, &bytes, &vote.signature)?;
    }
    Ok(())
}
