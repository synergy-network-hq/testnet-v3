use synergy_etdag::{EncryptedTransactionEnvelope, ProtectedIngressReceipt};

use crate::{ClientEnvelope, ClientSubmissionReceipt};

pub trait ProtectedIngressSubmitter {
    fn submit_protected(
        &self,
        envelope: EncryptedTransactionEnvelope,
    ) -> Result<ProtectedIngressReceipt, SubmissionError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionError {
    Transport(String),
    Rejected(String),
}

pub fn submit(
    submitter: &impl ProtectedIngressSubmitter,
    envelope: ClientEnvelope,
) -> Result<ClientSubmissionReceipt, SubmissionError> {
    let receipt = submitter.submit_protected(envelope.envelope)?;
    Ok(ClientSubmissionReceipt { receipt })
}
