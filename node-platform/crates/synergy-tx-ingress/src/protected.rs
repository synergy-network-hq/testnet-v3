use std::collections::BTreeMap;

use synergy_etdag::{EncryptedTransactionEnvelope, EtdagDigest, TargetAdmissionContextV3};

use crate::IngressError;

/// ETDAG-bound encrypted ingress. No plaintext can be admitted through this
/// boundary and a target context is immutable once the queue is created.
#[derive(Debug)]
pub struct ProtectedIngress {
    context: TargetAdmissionContextV3,
    context_root: EtdagDigest,
    capacity: usize,
    envelopes: BTreeMap<EtdagDigest, EncryptedTransactionEnvelope>,
}

impl ProtectedIngress {
    pub fn new(context: TargetAdmissionContextV3, capacity: usize) -> Result<Self, IngressError> {
        context.validate().map_err(IngressError::Etdag)?;
        if capacity == 0 {
            return Err(IngressError::InvalidLimits);
        }
        let context_root = context.root().map_err(IngressError::Etdag)?;
        Ok(Self {
            context,
            context_root,
            capacity,
            envelopes: BTreeMap::new(),
        })
    }

    pub fn admit(&mut self, envelope: EncryptedTransactionEnvelope) -> Result<(), IngressError> {
        envelope.validate().map_err(IngressError::Etdag)?;
        if envelope.target_height != self.context.target_height
            || envelope.target_context_root != self.context_root
        {
            return Err(IngressError::TargetContextMismatch);
        }
        if self.envelopes.len() >= self.capacity {
            return Err(IngressError::Capacity);
        }
        if self
            .envelopes
            .insert(envelope.envelope_id.clone(), envelope)
            .is_some()
        {
            return Err(IngressError::DuplicateEnvelope);
        }
        Ok(())
    }

    pub fn context(&self) -> &TargetAdmissionContextV3 {
        &self.context
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
