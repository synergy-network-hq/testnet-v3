//! Exact PW13 encrypted carrier used by the protected Wallet work owner.
//! Shape and resource binding alone do not qualify a profile or a proof.
use super::{Pw13SponsoredAdmission, Pw13TransferAdmission};
use crate::{
    execution::ProcessingVertexAdmission, CertifiedEnvelopeRef, EtdagError, ProcessingContext,
    ProcessingEnvelope,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "authorization",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProtectedWalletAuthorization {
    Transfer(Pw13TransferAdmission),
    SponsoredEnrollment(Pw13SponsoredAdmission),
    FeeFreeEnrollment(super::Pw13FeeFreeEnrollmentAdmission),
    FeeFreeSynId(super::Pw13FeeFreeSynIdAdmission),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedWalletAdmission {
    pub envelope: ProcessingEnvelope,
    pub authorization: ProtectedWalletAuthorization,
}

impl ProtectedWalletAdmission {
    pub fn gas_limit(&self) -> u64 {
        match &self.authorization {
            ProtectedWalletAuthorization::Transfer(proof) => proof.resources.gas_limit,
            ProtectedWalletAuthorization::SponsoredEnrollment(proof) => proof.resources.gas_limit,
            ProtectedWalletAuthorization::FeeFreeEnrollment(proof) => proof.resources.gas_limit,
            ProtectedWalletAuthorization::FeeFreeSynId(proof)=>proof.resources.gas_limit,
        }
    }

    pub fn validate_context(&self, context: &ProcessingContext) -> Result<(), EtdagError> {
        match &self.authorization {
            ProtectedWalletAuthorization::Transfer(proof) => {
                proof.validate_context(&self.envelope, context)
            }
            ProtectedWalletAuthorization::SponsoredEnrollment(proof) => {
                proof.validate_context(&self.envelope, context)
            }
            ProtectedWalletAuthorization::FeeFreeEnrollment(proof) => proof.validate_context(&self.envelope, context),
            ProtectedWalletAuthorization::FeeFreeSynId(proof)=>proof.validate_context(&self.envelope, context),
        }
    }
}

impl ProcessingVertexAdmission for ProtectedWalletAdmission {
    fn envelope(&self) -> &ProcessingEnvelope {
        &self.envelope
    }

    fn validate_vertex_resources(
        &self,
        reference: &CertifiedEnvelopeRef,
    ) -> Result<(), EtdagError> {
        self.envelope.validate()?;
        if self.gas_limit() != reference.gas_class_units {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}
