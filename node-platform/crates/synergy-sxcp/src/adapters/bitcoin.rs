use crate::{ExternalFinalityProof, SxcpTransfer, VerifiedExternalTransfer};

pub trait BitcoinProofProvider {
    fn verify_bitcoin_inclusion(
        &self,
        transfer: &SxcpTransfer,
        proof: &ExternalFinalityProof,
    ) -> Result<VerifiedExternalTransfer, String>;
}
