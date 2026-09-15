use std::collections::BTreeMap;

use crate::{
    ExternalChain, ExternalFinalityProof, ExternalProofAdapter, SxcpTransfer,
    VerifiedExternalTransfer,
};

#[derive(Default)]
pub struct SxcpVerifierRegistry {
    adapters: BTreeMap<ExternalChain, Box<dyn ExternalProofAdapter + Send + Sync>>,
}

impl SxcpVerifierRegistry {
    pub fn register(
        &mut self,
        adapter: Box<dyn ExternalProofAdapter + Send + Sync>,
    ) -> Result<(), String> {
        let chain = adapter.chain();
        if self.adapters.insert(chain, adapter).is_some() {
            return Err("duplicate SXCP proof adapter".into());
        }
        Ok(())
    }

    pub fn verify(
        &self,
        transfer: &SxcpTransfer,
        proof: &ExternalFinalityProof,
    ) -> Result<VerifiedExternalTransfer, String> {
        let adapter = self
            .adapters
            .get(&transfer.source_chain)
            .ok_or_else(|| "unsupported SXCP source chain".to_string())?;
        crate::verify_external_finality(adapter.as_ref(), transfer, proof)
    }
}
