use crate::integrations::abi;
use crate::integrations::IntegrationError;
use crate::licensing::{check_platform, VmPlatform};

pub struct SolanaIntegration;

impl SolanaIntegration {
    pub fn invoke_instruction(ix: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        if ix.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "instruction payload must not be empty",
            ));
        }
        check_platform(VmPlatform::Solana)
            .map_err(|msg| IntegrationError::Unsupported(Box::leak(msg.into_boxed_str())))?;
        abi::dispatch_deterministic(ix)
    }
}
