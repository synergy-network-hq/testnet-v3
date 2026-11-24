//! External EIP155 authorization is public. Ciphertext follows the same native
//! asynchronous ordering/reveal path, but standard raw Ethereum admission does
//! not claim transaction confidentiality or a forged native identity signature.
use super::ETHEREUM_PROCESSING_PROFILE_ID;
use crate::execution::ProcessingVertexAdmission;
use crate::{CertifiedEnvelopeRef, EtdagError, ProcessingContext, ProcessingEnvelope};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthereumProcessingAdmission {
    pub envelope: ProcessingEnvelope,
    /// Exact externally signed legacy wire bytes, not an admission signature.
    pub raw_transaction: Vec<u8>,
    pub gas_limit: u64,
}
impl EthereumProcessingAdmission {
    pub fn validate_context(&self, context: &ProcessingContext) -> Result<(), EtdagError> {
        if context.profile_id != ETHEREUM_PROCESSING_PROFILE_ID
            || self.raw_transaction.is_empty()
            || self.raw_transaction.len() > 1_048_576
            || self.gas_limit < 21_000
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        self.envelope.validate_context(context)
    }
}
impl ProcessingVertexAdmission for EthereumProcessingAdmission {
    fn envelope(&self) -> &ProcessingEnvelope {
        &self.envelope
    }
    fn validate_vertex_resources(
        &self,
        reference: &CertifiedEnvelopeRef,
    ) -> Result<(), EtdagError> {
        self.envelope.validate()?;
        if self.envelope.aad.profile_id != ETHEREUM_PROCESSING_PROFILE_ID
            || self.raw_transaction.is_empty()
            || self.raw_transaction.len() > 1_048_576
            || self.gas_limit < 21_000
            || reference.gas_class_units != self.gas_limit
            || reference.fee_class != 0
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}
