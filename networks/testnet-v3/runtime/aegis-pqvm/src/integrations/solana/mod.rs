use crate::integrations::abi;
use crate::integrations::IntegrationError;

pub struct SolanaIntegration;

impl SolanaIntegration {
    pub fn invoke_instruction(ix: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        if ix.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "instruction payload must not be empty",
            ));
        }
        // Convention: the instruction data is the AEG1 payload.
        abi::dispatch_deterministic(ix)
    }
}
