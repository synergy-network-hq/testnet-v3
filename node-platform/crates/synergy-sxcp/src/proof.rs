use serde::{Deserialize, Serialize};

use crate::{ExternalChain, SxcpTransfer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalFinalityProof {
    pub chain: ExternalChain,
    pub block_reference: String,
    pub transaction_reference: String,
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedExternalTransfer {
    pub transfer: SxcpTransfer,
    pub finality_reference: String,
}

pub trait ExternalProofAdapter {
    fn chain(&self) -> ExternalChain;
    fn verify(
        &self,
        transfer: &SxcpTransfer,
        proof: &ExternalFinalityProof,
    ) -> Result<VerifiedExternalTransfer, String>;
}
