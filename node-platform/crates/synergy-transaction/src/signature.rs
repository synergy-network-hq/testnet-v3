use crate::{SignedTransaction, TransactionError};

/// Cryptographic verification is supplied by Aegis. Transaction ownership never
/// implies validator, VPN, PoSy quorum, or finality authority.
pub trait AegisTransactionVerifier {
    type Error: std::fmt::Display;

    fn verify_transaction(
        &self,
        signing_bytes: &[u8],
        signer_public_key: &[u8],
        signature: &[u8],
        signature_algorithm: &str,
    ) -> Result<bool, Self::Error>;
}

pub fn verify<V: AegisTransactionVerifier>(
    transaction: &SignedTransaction,
    verifier: &V,
) -> Result<(), TransactionError> {
    transaction.validate_structure()?;
    if !synergy_address::address_matches_public_key(
        &transaction.unsigned.sender,
        &transaction.signer_public_key,
    ) {
        return Err(TransactionError::InvalidSignature);
    }
    let verified = verifier
        .verify_transaction(
            &transaction.unsigned.signing_bytes()?,
            &transaction.signer_public_key,
            &transaction.signature,
            &transaction.signature_algorithm,
        )
        .map_err(|error| TransactionError::SignatureVerifier(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(TransactionError::InvalidSignature)
    }
}
