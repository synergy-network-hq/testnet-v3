use crate::integrations::abi;
use crate::integrations::IntegrationError;

/// CosmWasm integration shim.
///
/// This crate does not ship a full CosmWasm contract (to avoid bringing CosmWasm SDK
/// crates into the core PQVM build). Instead, it provides a deterministic dispatch
/// layer that a CosmWasm contract can call into.
pub struct CosmwasmIntegration;

impl CosmwasmIntegration {
    pub fn deploy_contract(_wasm_binary: &[u8]) -> Result<(), IntegrationError> {
        if _wasm_binary.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "wasm binary must not be empty",
            ));
        }
        Ok(())
    }

    pub fn call_contract(_contract: &[u8], _message: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        if _contract.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "contract must not be empty",
            ));
        }
        abi::dispatch_deterministic(_message)
    }
}
