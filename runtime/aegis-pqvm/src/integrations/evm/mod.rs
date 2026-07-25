use crate::integrations::abi;
use crate::integrations::IntegrationError;

/// EVM-style precompile entrypoint (deterministic).
///
/// This function is designed to be usable in an EVM precompile context where
/// calls must be deterministic across all nodes.
///
/// Payload format: `integrations::abi` (AEG1).
pub fn evm_precompile_call(payload: &[u8]) -> Result<Vec<u8>, IntegrationError> {
    if payload.is_empty() {
        return Err(IntegrationError::InvalidPayload(
            "payload must not be empty",
        ));
    }
    abi::dispatch_deterministic(payload)
}

/// Conservative gas estimate for supported deterministic operations.
pub fn evm_gas_cost(payload: &[u8]) -> Result<u64, IntegrationError> {
    if payload.is_empty() {
        return Err(IntegrationError::InvalidPayload(
            "payload must not be empty",
        ));
    }
    abi::gas_cost_deterministic(payload)
}
