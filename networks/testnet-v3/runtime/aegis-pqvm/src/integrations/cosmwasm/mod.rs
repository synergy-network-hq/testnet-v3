use crate::integrations::abi;
use crate::integrations::IntegrationError;

const COSMWASM_BOUND_MAGIC: [u8; 4] = *b"CWB1";

/// CosmWasm integration adapter.
///
/// This crate does not ship a full CosmWasm contract (to avoid bringing CosmWasm SDK
/// crates into the core PQVM build). Instead, it provides a deterministic dispatch
/// layer that a CosmWasm contract can call into.
pub struct CosmwasmIntegration;

impl CosmwasmIntegration {
    /// Build a contract-bound envelope:
    /// `CWB1 || contract_len_be_u32 || contract || aeg1_payload`.
    pub fn encode_bound_message(
        contract: &[u8],
        aeg1_payload: &[u8],
    ) -> Result<Vec<u8>, IntegrationError> {
        if contract.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "contract must not be empty",
            ));
        }
        if aeg1_payload.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "message must not be empty",
            ));
        }
        if contract.len() > u32::MAX as usize {
            return Err(IntegrationError::InvalidPayload("contract too large"));
        }

        let mut out = Vec::with_capacity(8 + contract.len() + aeg1_payload.len());
        out.extend_from_slice(&COSMWASM_BOUND_MAGIC);
        out.extend_from_slice(&(contract.len() as u32).to_be_bytes());
        out.extend_from_slice(contract);
        out.extend_from_slice(aeg1_payload);
        Ok(out)
    }

    fn decode_bound_message<'a>(
        contract: &[u8],
        message: &'a [u8],
    ) -> Result<&'a [u8], IntegrationError> {
        if message.len() < 8 {
            return Err(IntegrationError::InvalidPayload(
                "message too short for CosmWasm envelope",
            ));
        }
        if message[0..4] != COSMWASM_BOUND_MAGIC {
            return Err(IntegrationError::InvalidPayload(
                "invalid CosmWasm envelope magic",
            ));
        }

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&message[4..8]);
        let contract_len = u32::from_be_bytes(len_bytes) as usize;
        if message.len() < 8 + contract_len {
            return Err(IntegrationError::InvalidPayload(
                "truncated contract binding in envelope",
            ));
        }

        let bound_contract = &message[8..8 + contract_len];
        if bound_contract != contract {
            return Err(IntegrationError::InvalidPayload(
                "CosmWasm envelope contract mismatch",
            ));
        }

        let payload = &message[8 + contract_len..];
        if payload.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "missing AEG1 payload in envelope",
            ));
        }

        Ok(payload)
    }

    pub fn call_contract(contract: &[u8], message: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        if contract.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "contract must not be empty",
            ));
        }
        if message.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "message must not be empty",
            ));
        }

        let payload = Self::decode_bound_message(contract, message)?;
        abi::dispatch_deterministic(payload)
    }
}
