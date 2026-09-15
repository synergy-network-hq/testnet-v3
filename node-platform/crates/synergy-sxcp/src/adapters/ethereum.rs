use crate::{ExternalFinalityProof, SxcpTransfer, VerifiedExternalTransfer};

pub trait EthereumProofProvider {
    fn verify_ethereum_receipt(
        &self,
        transfer: &SxcpTransfer,
        proof: &ExternalFinalityProof,
    ) -> Result<VerifiedExternalTransfer, String>;
}
