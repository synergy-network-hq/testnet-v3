use crate::integrations::abi;
use crate::integrations::IntegrationError;

pub struct SolanaIntegration;

impl SolanaIntegration {
    pub fn deploy_program(_program: &[u8]) -> Result<(), IntegrationError> {
        if _program.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "program bytes must not be empty",
            ));
        }
        Ok(())
    }

    pub fn invoke_instruction(_ix: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        // Convention: the instruction data is the AEG1 payload.
        abi::dispatch_deterministic(_ix)
    }
}
