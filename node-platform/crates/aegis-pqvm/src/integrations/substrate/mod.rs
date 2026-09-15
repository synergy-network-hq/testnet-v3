use crate::integrations::abi;
use crate::integrations::IntegrationError;
use crate::licensing::{check_platform, VmPlatform};

pub struct SubstrateIntegration;

impl SubstrateIntegration {
    pub fn dispatch_call(call_data: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        if call_data.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "call data must not be empty",
            ));
        }
        check_platform(VmPlatform::Substrate)
            .map_err(|msg| IntegrationError::Unsupported(Box::leak(msg.into_boxed_str())))?;
        abi::dispatch_deterministic(call_data)
    }
}
