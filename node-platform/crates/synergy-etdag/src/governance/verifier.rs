use std::collections::BTreeSet;

use crate::{
    crypto::{canonical_signing_bytes, SignatureVerifier},
    EtdagError,
};

use super::SignedEtdagManifest;

pub fn verify_signed_manifest(
    signed: &SignedEtdagManifest,
    governance_authorities: &BTreeSet<String>,
    verifier: &impl SignatureVerifier,
) -> Result<(), EtdagError> {
    signed.manifest.validate()?;
    if !governance_authorities.contains(&signed.authority_id) {
        return Err(EtdagError::UnauthorizedValidator(
            signed.authority_id.clone(),
        ));
    }
    if signed.key_id.trim().is_empty() || signed.signature.is_empty() {
        return Err(EtdagError::InvalidSignature);
    }
    let bytes = canonical_signing_bytes(
        "SYNERGY_ETDAG_GOVERNANCE_MANIFEST_SIGNATURE_V1",
        &signed.manifest,
    )?;
    verifier.verify(
        &signed.authority_id,
        &signed.key_id,
        &bytes,
        &signed.signature,
    )
}
