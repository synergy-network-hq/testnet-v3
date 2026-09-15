use synergy_etdag::EncryptedTransactionEnvelope;

use crate::{IngressError, ProtectedIngress};

/// Bridges a verified encrypted client envelope into ETDAG-owned admission.
/// It does not decrypt, order, certify, execute, vote, or finalize.
pub trait ProtectedIngressRouter {
    fn submit(
        &mut self,
        queue: &mut ProtectedIngress,
        envelope: EncryptedTransactionEnvelope,
    ) -> Result<(), IngressError>;
}

#[derive(Debug, Default)]
pub struct DirectProtectedIngressRouter;

impl ProtectedIngressRouter for DirectProtectedIngressRouter {
    fn submit(
        &mut self,
        queue: &mut ProtectedIngress,
        envelope: EncryptedTransactionEnvelope,
    ) -> Result<(), IngressError> {
        queue.admit(envelope)
    }
}
