use serde::{Deserialize, Serialize};
use synergy_protocol_types::NodeAddress;

use crate::{validate_wallet, OwnershipError};

pub const MAX_OWNERSHIP_PROOF_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipAuthorization {
    pub wallet: String,
    pub nonce: u64,
    pub proof: Vec<u8>,
}

impl OwnershipAuthorization {
    /// Validates the public authorization envelope without verifying its proof.
    pub fn validate(&self) -> Result<(), OwnershipError> {
        validate_wallet(&self.wallet)?;
        if self.nonce == 0 {
            return Err(OwnershipError::InvalidNonce);
        }
        validate_proof(&self.proof)
    }
}

pub(crate) fn validate_proof(proof: &[u8]) -> Result<(), OwnershipError> {
    if proof.is_empty() {
        return Err(OwnershipError::MissingProof);
    }
    if proof.len() > MAX_OWNERSHIP_PROOF_BYTES {
        return Err(OwnershipError::ProofTooLarge);
    }
    Ok(())
}

/// Cryptographic boundary supplied by the canonical Aegis engine/provider.
pub trait OwnershipAuthorizationVerifier {
    fn verify_wallet_proof(&self, wallet: &str, payload: &[u8], proof: &[u8])
        -> Result<(), String>;

    fn verify_node_possession(
        &self,
        node_address: &NodeAddress,
        payload: &[u8],
        proof: &[u8],
    ) -> Result<(), String>;
}
