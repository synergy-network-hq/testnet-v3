use crate::integrations::abi;
use crate::integrations::IntegrationError;

pub struct MoveIntegration;

impl MoveIntegration {
    pub fn publish_package(_bytecode: &[u8]) -> Result<(), IntegrationError> {
        if _bytecode.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "bytecode must not be empty",
            ));
        }
        Ok(())
    }

    pub fn invoke_entry_function(
        _module: &str,
        _function: &str,
        _args: &[Vec<u8>],
    ) -> Result<Vec<u8>, IntegrationError> {
        // Convention: Move integration passes an AEG1-encoded payload as the first arg.
        // Additional args are ignored by this shim (chains can decide how to route them).
        let payload = _args
            .get(0)
            .ok_or(IntegrationError::InvalidPayload("missing AEG1 payload arg"))?;
        let _ = _module;
        let _ = _function;
        abi::dispatch_deterministic(payload)
    }
}
