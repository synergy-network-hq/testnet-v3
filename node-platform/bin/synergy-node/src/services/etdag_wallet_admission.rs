use super::processing_pipeline::is_pw13_context;
use crate::services::processing_store::{PendingProcessingIdentity, ProcessingAdmissionRecord};
use synergy_etdag::{
    admission::ProtectedWalletAdmission,
    execution::{ProcessingVertex, ProcessingVertexAdmission},
    CertifiedEnvelopeRef, EtdagError, EtdagNetworkMessage, ProcessingContext, ProcessingEnvelope,
    WalletProcessingAdmission,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub(super) enum RuntimeProcessingAdmission {
    Ordinary(WalletProcessingAdmission),
    Protected(ProtectedWalletAdmission),
}

impl RuntimeProcessingAdmission {
    pub(super) fn outbound_envelope(&self) -> &ProcessingEnvelope {
        self.envelope()
    }

    pub(super) fn profile(&self) -> &'static str {
        use synergy_etdag::admission::*;
        match self {
            Self::Ordinary(_) => PROCESSING_PROFILE_ID,
            Self::Protected(value) => match &value.authorization {
                ProtectedWalletAuthorization::Transfer(_) => PW13_TRANSFER_CANDIDATE_PROFILE_ID,
                ProtectedWalletAuthorization::SponsoredEnrollment(_) => {
                    PW13_SPONSOR_CANDIDATE_PROFILE_ID
                }
            },
        }
    }
}

impl ProcessingAdmissionRecord for RuntimeProcessingAdmission {
    fn decode_original(
        value: &str,
        context: &ProcessingContext,
    ) -> Result<Self, serde_json::Error> {
        if context.profile_id == synergy_etdag::PROCESSING_PROFILE_ID {
            serde_json::from_str(value).map(Self::Ordinary)
        } else if is_pw13_context(context) {
            serde_json::from_str(value).map(Self::Protected)
        } else {
            Err(serde::de::Error::custom(
                "unknown encrypted Wallet processing profile",
            ))
        }
    }

    fn allows_legacy_kem_recovery(&self) -> bool {
        matches!(self, Self::Ordinary(_))
    }

    fn validate_context(&self, context: &ProcessingContext) -> Result<(), EtdagError> {
        if context.profile_id != self.profile() {
            return Err(EtdagError::ContextMismatch);
        }
        match self {
            Self::Ordinary(value) => value.validate_context(context),
            Self::Protected(value) => value.validate_context(context),
        }
    }

    fn identity(&self) -> PendingProcessingIdentity {
        match self {
            Self::Ordinary(value) => value.identity(),
            Self::Protected(value) => value.identity(),
        }
    }
}

impl ProcessingVertexAdmission for RuntimeProcessingAdmission {
    fn envelope(&self) -> &ProcessingEnvelope {
        match self {
            Self::Ordinary(value) => value.envelope(),
            Self::Protected(value) => value.envelope(),
        }
    }

    fn validate_vertex_resources(
        &self,
        reference: &CertifiedEnvelopeRef,
    ) -> Result<(), EtdagError> {
        match self {
            Self::Ordinary(value) => value.validate_vertex_resources(reference),
            Self::Protected(value) => value.validate_vertex_resources(reference),
        }
    }
}

pub(super) fn vertex_message(
    vertex: ProcessingVertex<RuntimeProcessingAdmission>,
) -> EtdagNetworkMessage {
    if matches!(&vertex.admission, RuntimeProcessingAdmission::Ordinary(_)) {
        EtdagNetworkMessage::ProcessingVertexV1(vertex.map_admission(|admission| {
            let RuntimeProcessingAdmission::Ordinary(value) = admission else {
                unreachable!()
            };
            value
        }))
    } else {
        EtdagNetworkMessage::ProcessingProtectedWalletVertexV1(vertex.map_admission(|admission| {
            let RuntimeProcessingAdmission::Protected(value) = admission else {
                unreachable!()
            };
            value
        }))
    }
}
