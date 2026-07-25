use crate::integrations::abi;
use crate::integrations::IntegrationError;

pub struct SubstrateIntegration;

impl SubstrateIntegration {
    pub fn dispatch_call(call_data: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        if call_data.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "call data must not be empty",
            ));
        }
        abi::dispatch_deterministic(call_data)
    }
}
