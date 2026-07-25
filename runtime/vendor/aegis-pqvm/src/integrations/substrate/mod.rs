use crate::integrations::abi;
use crate::integrations::IntegrationError;

pub struct SubstrateIntegration;

impl SubstrateIntegration {
    pub fn register_pallet() -> Result<(), IntegrationError> {
        // This crate does not ship a full Substrate pallet (to avoid pulling Substrate
        // dependencies into the core crate). Instead, it provides a deterministic
        // dispatch layer that a pallet can call into.
        Ok(())
    }

    pub fn dispatch_call(_call_data: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        abi::dispatch_deterministic(_call_data)
    }
}
