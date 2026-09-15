use crate::{EncryptedTransactionEnvelope, EtdagDigest, EtdagError};

use super::{decrypt_share::VerifiedDecryptShare, share_collector::ThresholdDecryptShares};

/// Cryptographic threshold-decryption provider owned by the node crypto layer.
pub trait ThresholdDecryptor {
    /// Reconstructs plaintext from a threshold-sufficient verified share set.
    fn decrypt(
        &self,
        envelope: &EncryptedTransactionEnvelope,
        shares: &[VerifiedDecryptShare],
    ) -> Result<Vec<u8>, EtdagError>;
}

/// Plaintext produced only after finality authorization and threshold verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealedTransaction {
    envelope_id: EtdagDigest,
    transcript_root: EtdagDigest,
    authorization: crate::ProtectedRevealAuthorization,
    plaintext: Vec<u8>,
}

impl RevealedTransaction {
    /// Returns the protected envelope identifier.
    pub fn envelope_id(&self) -> &EtdagDigest {
        &self.envelope_id
    }

    /// Returns the authenticated reveal transcript root.
    pub fn transcript_root(&self) -> &EtdagDigest {
        &self.transcript_root
    }

    /// Returns the finality-bound authorization that opened the reveal gate.
    pub fn authorization(&self) -> &crate::ProtectedRevealAuthorization {
        &self.authorization
    }

    /// Returns plaintext after the caller has crossed the authorized reveal gate.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

/// Performs threshold decryption only for the envelope and finalized reveal
/// authorization bound into `shares`.
pub fn decrypt_authorized_envelope(
    envelope: &EncryptedTransactionEnvelope,
    shares: &ThresholdDecryptShares,
    decryptor: &impl ThresholdDecryptor,
) -> Result<RevealedTransaction, EtdagError> {
    envelope.validate()?;
    let authorization = shares.authorization();
    authorization.validate()?;
    if shares.envelope_id() != &envelope.envelope_id
        || authorization.context_root != envelope.target_context_root
        || authorization.target_height != envelope.target_height
    {
        return Err(EtdagError::UnauthorizedReveal);
    }

    for share in shares.shares() {
        let matching_capsule = envelope.share_capsules.iter().any(|capsule| {
            capsule.validator_id == share.validator_id() && capsule.key_id == share.key_id()
        });
        if !matching_capsule {
            return Err(EtdagError::UnauthorizedValidator(
                share.validator_id().to_owned(),
            ));
        }
    }

    let transcript_root = shares.transcript_root()?;
    let plaintext = decryptor.decrypt(envelope, shares.shares())?;
    if plaintext.is_empty() {
        return Err(EtdagError::InvalidExecutionInput);
    }
    Ok(RevealedTransaction {
        envelope_id: envelope.envelope_id.clone(),
        transcript_root,
        authorization: authorization.clone(),
        plaintext,
    })
}
