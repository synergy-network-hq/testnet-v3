use crate::integrations::abi;
use crate::integrations::IntegrationError;

/// Bitcoin integration adapter.
///
/// This adapter is intentionally deterministic and payload-oriented. Host Bitcoin
/// runtimes are responsible for script/witness plumbing and lifecycle concerns.
pub struct BitcoinIntegration;

impl BitcoinIntegration {
    /// Execute a deterministic AEG1 payload in a Bitcoin-style verification flow.
    pub fn verify_script_payload(payload: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        if payload.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "script payload must not be empty",
            ));
        }
        abi::dispatch_deterministic(payload)
    }
}
