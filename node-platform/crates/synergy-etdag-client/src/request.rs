use synergy_etdag::{AdmissionRequest, EtdagError, ADMISSION_REQUEST_VERSION};

use crate::ClientEnvelope;

/// Client signing boundary for the outer protected-ingress request.
///
/// Implementations delegate to the canonical Aegis engine or a wallet signing
/// provider. This crate never owns or exports private key material.
pub trait AdmissionRequestSigner {
    fn sign_admission_request(
        &self,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, AdmissionRequestBuildError>;
}

#[derive(Debug, Clone)]
pub struct ClientAdmissionRequest {
    pub request: AdmissionRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRequestBuildError {
    Signing(String),
    Invalid(EtdagError),
}

impl std::fmt::Display for AdmissionRequestBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signing(message) => {
                write!(formatter, "admission request signing failed: {message}")
            }
            Self::Invalid(error) => write!(formatter, "invalid admission request: {error:?}"),
        }
    }
}

impl std::error::Error for AdmissionRequestBuildError {}

impl ClientAdmissionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        signer: &impl AdmissionRequestSigner,
        chain_id: u64,
        network_id: impl Into<String>,
        sender_wallet: impl Into<String>,
        sender_nonce: u64,
        gas_class_units: u64,
        fee_class: u32,
        signature_algorithm: impl Into<String>,
        signer_public_key: Vec<u8>,
        envelope: ClientEnvelope,
    ) -> Result<Self, AdmissionRequestBuildError> {
        let mut request = AdmissionRequest {
            request_version: ADMISSION_REQUEST_VERSION,
            chain_id,
            network_id: network_id.into(),
            context_root: envelope.envelope.target_context_root.clone(),
            target_height: envelope.envelope.target_height,
            sender_wallet: sender_wallet.into(),
            sender_nonce,
            gas_class_units,
            fee_class,
            signature_algorithm: signature_algorithm.into(),
            signer_public_key,
            envelope: envelope.envelope,
            signature: Vec::new(),
        };
        if request
            .envelope_commitment()
            .map_err(AdmissionRequestBuildError::Invalid)?
            != request.envelope.envelope_id
        {
            return Err(AdmissionRequestBuildError::Invalid(
                EtdagError::InvalidEnvelope(
                    "client envelope identifier differs from canonical body".into(),
                ),
            ));
        }
        let signing_bytes = request
            .signing_bytes()
            .map_err(AdmissionRequestBuildError::Invalid)?;
        request.signature = signer.sign_admission_request(&signing_bytes)?;
        request
            .validate_shape()
            .map_err(AdmissionRequestBuildError::Invalid)?;
        Ok(Self { request })
    }

    pub fn into_request(self) -> AdmissionRequest {
        self.request
    }
}
