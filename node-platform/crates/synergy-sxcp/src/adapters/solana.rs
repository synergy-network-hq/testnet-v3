use crate::{ExternalFinalityProof, SxcpTransfer, VerifiedExternalTransfer};

pub trait SolanaProofProvider {
    fn verify_solana_confirmation(
        &self,
        transfer: &SxcpTransfer,
        proof: &ExternalFinalityProof,
    ) -> Result<VerifiedExternalTransfer, String>;
}
