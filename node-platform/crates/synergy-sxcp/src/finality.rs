use crate::{ExternalFinalityProof, ExternalProofAdapter, SxcpTransfer, VerifiedExternalTransfer};

pub fn verify_external_finality(
    adapter: &(impl ExternalProofAdapter + ?Sized),
    transfer: &SxcpTransfer,
    proof: &ExternalFinalityProof,
) -> Result<VerifiedExternalTransfer, String> {
    transfer.validate_shape()?;
    if adapter.chain() != transfer.source_chain || proof.chain != transfer.source_chain {
        return Err("SXCP proof adapter chain mismatch".into());
    }
    if proof.block_reference.trim().is_empty()
        || proof.transaction_reference != transfer.source_transaction
        || proof.proof_bytes.is_empty()
    {
        return Err("invalid SXCP external finality proof".into());
    }
    adapter.verify(transfer, proof)
}
