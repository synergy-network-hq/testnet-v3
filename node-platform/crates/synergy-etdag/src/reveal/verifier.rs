use std::collections::BTreeSet;

use crate::{
    crypto::{canonical_signing_bytes, SignatureVerifier},
    DecryptShareMessage, EtdagError,
};

use super::{authorization::ProtectedRevealAuthorization, decrypt_share::VerifiedDecryptShare};

const DECRYPT_SHARE_DOMAIN: &str = "SYNERGY_ETDAG_REVEAL_SHARE_V1";

/// Verifies one reveal share without exposing plaintext or mutating collection
/// state.
///
/// The supplied verifier must resolve `validator_id` and `key_id` against the
/// governed consensus-key registry bound by the authorization context.
pub fn verify_decrypt_share(
    message: &DecryptShareMessage,
    expected_authorization: &ProtectedRevealAuthorization,
    allowed_validators: &BTreeSet<String>,
    verifier: &impl SignatureVerifier,
) -> Result<VerifiedDecryptShare, EtdagError> {
    expected_authorization.validate()?;
    message.validate()?;

    if &message.authorization != expected_authorization {
        return Err(EtdagError::UnauthorizedReveal);
    }
    if !allowed_validators.contains(&message.validator_id) {
        return Err(EtdagError::UnauthorizedValidator(
            message.validator_id.clone(),
        ));
    }

    let signing_bytes = canonical_signing_bytes(
        DECRYPT_SHARE_DOMAIN,
        &(
            message.share_version,
            &message.authorization,
            &message.envelope_id,
            &message.validator_id,
            &message.key_id,
            &message.encrypted_share,
        ),
    )?;
    verifier.verify(
        &message.validator_id,
        &message.key_id,
        &signing_bytes,
        &message.signature,
    )?;

    Ok(VerifiedDecryptShare::new(message.clone()))
}
