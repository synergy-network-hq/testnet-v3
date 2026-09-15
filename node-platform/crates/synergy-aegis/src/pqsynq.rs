//! Aegis-owned PQSynQ authorization and execution binding.
//!
//! Consumers submit the signed PQSynQ envelope and invocation bytes together;
//! this provider verifies the account-domain signature and exact artifact/input
//! commitments without exposing raw PQ primitives above the Aegis engine.

use pqsynq::{
    AegisSynQVerifier, ChainId, NetworkId, SynQTransactionEnvelope, VerificationContext,
    VerifiedSynQTransaction,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_AUTHORIZATION_BYTES: usize = 1024 * 1024;
const MAX_INVOCATION_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqSynqExecutionAuthorization {
    pub envelope: SynQTransactionEnvelope,
    pub invocation_input: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedPqSynqOperation {
    Deploy {
        deployer_id: String,
    },
    Call {
        caller_id: String,
        contract_address_preimage: [u8; 41],
        method_selector: [u8; 4],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPqSynqExecution {
    pub operation: VerifiedPqSynqOperation,
    pub invocation_input: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PqSynqVerifier {
    verifier: AegisSynQVerifier,
}

impl PqSynqVerifier {
    pub fn testnet_1266() -> Self {
        Self {
            verifier: AegisSynQVerifier::testnet_1266(),
        }
    }

    pub fn verify_execution(
        &self,
        artifact: &[u8],
        encoded_authorization: &[u8],
        chain_id: u64,
        network_id: &str,
        transaction_time_unix: u64,
        expected_signer_public_key: &[u8],
    ) -> Result<VerifiedPqSynqExecution, PqSynqError> {
        if artifact.is_empty()
            || encoded_authorization.is_empty()
            || encoded_authorization.len() > MAX_AUTHORIZATION_BYTES
            || transaction_time_unix == 0
        {
            return Err(PqSynqError::InvalidExecutionInput);
        }
        let authorization: PqSynqExecutionAuthorization =
            serde_json::from_slice(encoded_authorization)
                .map_err(|_| PqSynqError::InvalidEncoding)?;
        if authorization.invocation_input.len() > MAX_INVOCATION_BYTES {
            return Err(PqSynqError::InvalidExecutionInput);
        }
        let envelope_public_key = match &authorization.envelope {
            SynQTransactionEnvelope::ContractDeploy(envelope) => &envelope.public_key.bytes,
            SynQTransactionEnvelope::ContractCall(envelope) => &envelope.public_key.bytes,
        };
        if envelope_public_key.as_slice() != expected_signer_public_key {
            return Err(PqSynqError::SignerKeyMismatch);
        }
        let network_id = match network_id {
            "synergy-testnet-v3" | "synergy-testnet" => NetworkId::testnet(),
            other => NetworkId(other.to_string()),
        };
        let context = VerificationContext {
            chain_id: ChainId(chain_id),
            network_id,
            now_unix: transaction_time_unix,
            policy: self.verifier.policy.clone(),
        };
        let verified = self
            .verifier
            .verify_synq_transaction(&authorization.envelope, &context)
            .map_err(|error| PqSynqError::Verification(error.to_string()))?;
        let operation = match (&authorization.envelope, verified) {
            (
                SynQTransactionEnvelope::ContractDeploy(envelope),
                VerifiedSynQTransaction::ContractDeploy(verified),
            ) => {
                if sha256(artifact) != envelope.bytecode_hash
                    || sha256(&authorization.invocation_input) != envelope.constructor_args_hash
                    || verified.bytecode_hash != envelope.bytecode_hash
                {
                    return Err(PqSynqError::CommitmentMismatch);
                }
                VerifiedPqSynqOperation::Deploy {
                    deployer_id: verified.deployer.to_execution_signer_id(),
                }
            }
            (
                SynQTransactionEnvelope::ContractCall(envelope),
                VerifiedSynQTransaction::ContractCall(verified),
            ) => {
                if sha256(&authorization.invocation_input) != envelope.encoded_args_hash {
                    return Err(PqSynqError::CommitmentMismatch);
                }
                VerifiedPqSynqOperation::Call {
                    caller_id: verified.caller.to_execution_signer_id(),
                    contract_address_preimage: *verified.contract_address.as_bytes(),
                    method_selector: verified.method_selector,
                }
            }
            _ => return Err(PqSynqError::OperationMismatch),
        };
        Ok(VerifiedPqSynqExecution {
            operation,
            invocation_input: authorization.invocation_input,
        })
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqSynqError {
    InvalidEncoding,
    InvalidExecutionInput,
    CommitmentMismatch,
    OperationMismatch,
    SignerKeyMismatch,
    Verification(String),
}

impl std::fmt::Display for PqSynqError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEncoding => formatter.write_str("invalid PQSynQ execution encoding"),
            Self::InvalidExecutionInput => formatter.write_str("invalid PQSynQ execution input"),
            Self::CommitmentMismatch => formatter.write_str("PQSynQ execution commitment mismatch"),
            Self::OperationMismatch => formatter.write_str("PQSynQ operation mismatch"),
            Self::SignerKeyMismatch => {
                formatter.write_str("PQSynQ signer key does not match the outer transaction")
            }
            Self::Verification(message) => {
                write!(formatter, "PQSynQ verification failed: {message}")
            }
        }
    }
}

impl std::error::Error for PqSynqError {}
