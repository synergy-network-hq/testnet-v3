use synergy_etdag::{AdmissionRequest, ProtectedIngressReceipt};

use crate::{ClientAdmissionRequest, ClientSubmissionReceipt};

/// Transport boundary for the complete wallet-signed protected-ingress request.
/// Implementations must send the request unchanged to the canonical node RPC
/// method; an encrypted envelope alone is never sufficient for admission.
pub trait ProtectedIngressSubmitter {
    fn submit_protected(
        &self,
        request: AdmissionRequest,
    ) -> Result<ProtectedIngressReceipt, SubmissionError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionError {
    Transport(String),
    Rejected(String),
}

pub fn submit(
    submitter: &impl ProtectedIngressSubmitter,
    request: ClientAdmissionRequest,
) -> Result<ClientSubmissionReceipt, SubmissionError> {
    let receipt = submitter.submit_protected(request.into_request())?;
    Ok(ClientSubmissionReceipt { receipt })
}
