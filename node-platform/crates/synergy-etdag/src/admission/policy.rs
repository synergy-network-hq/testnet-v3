use std::collections::{BTreeMap, BTreeSet};

use crate::{EtdagError, EtdagParameters, ProtectedEnvelope, TargetAdmissionContext};

/// Bounded, context-bound encrypted ingress. No plaintext or execution input is
/// accepted by this owner.
#[derive(Debug, Clone)]
pub struct EtdagAdmission {
    pub(crate) context: TargetAdmissionContext,
    pub(crate) capacity: usize,
    pub(crate) envelopes: BTreeMap<String, ProtectedEnvelope>,
    pub(crate) closed: bool,
}

impl EtdagAdmission {
    pub fn new(
        context: TargetAdmissionContext,
        parameters: &EtdagParameters,
    ) -> Result<Self, EtdagError> {
        context.validate()?;
        parameters.validate()?;
        Ok(Self {
            context,
            capacity: parameters.max_outstanding_nonce_slots,
            envelopes: BTreeMap::new(),
            closed: false,
        })
    }

    pub fn admit(&mut self, envelope: ProtectedEnvelope) -> Result<(), EtdagError> {
        if self.closed {
            return Err(EtdagError::AdmissionClosed);
        }
        if envelope.target_height != self.context.target_height {
            return Err(EtdagError::ContextMismatch);
        }
        if envelope.ciphertext.is_empty() {
            return Err(EtdagError::EmptyCiphertext);
        }
        if self.envelopes.contains_key(&envelope.envelope_id) {
            return Err(EtdagError::DuplicateEnvelope);
        }
        if self.envelopes.len() >= self.capacity {
            return Err(EtdagError::AdmissionCapacity);
        }
        self.envelopes
            .insert(envelope.envelope_id.clone(), envelope);
        Ok(())
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn deterministic_order(&self) -> Result<Vec<&ProtectedEnvelope>, EtdagError> {
        let mut keys = BTreeSet::new();
        let mut ordered = self.envelopes.values().collect::<Vec<_>>();
        for item in &ordered {
            if !keys.insert(item.content_blind_order_key.as_str()) {
                return Err(EtdagError::DuplicateOrderKey);
            }
        }
        ordered.sort_by(|left, right| {
            left.content_blind_order_key
                .cmp(&right.content_blind_order_key)
                .then_with(|| left.envelope_id.cmp(&right.envelope_id))
        });
        Ok(ordered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> TargetAdmissionContext {
        TargetAdmissionContext {
            source_finalized_height: 10,
            target_height: 15,
            active_validator_set_root: "set".into(),
            validator_consensus_key_root: "keys".into(),
            frozen_voting_weight_root: "weight".into(),
            assigned_cluster_validator_count: 5,
            assigned_cluster_total_voting_weight: 10,
        }
    }

    fn envelope(id: &str, key: &str) -> ProtectedEnvelope {
        ProtectedEnvelope {
            envelope_id: id.into(),
            target_height: 15,
            ciphertext: vec![7],
            content_blind_order_key: key.into(),
        }
    }

    #[test]
    fn admission_requires_finalized_h_plus_five_context_and_ciphertext() {
        let mut admission = EtdagAdmission::new(context(), &EtdagParameters::default()).unwrap();
        assert!(admission.admit(envelope("a", "b")).is_ok());
        assert_eq!(
            admission.admit(ProtectedEnvelope {
                target_height: 14,
                ..envelope("b", "c")
            }),
            Err(EtdagError::ContextMismatch)
        );
        assert_eq!(
            admission.admit(ProtectedEnvelope {
                ciphertext: vec![],
                ..envelope("c", "d")
            }),
            Err(EtdagError::EmptyCiphertext)
        );
    }

    #[test]
    fn content_blind_order_is_independent_of_arrival_order() {
        let mut admission = EtdagAdmission::new(context(), &EtdagParameters::default()).unwrap();
        admission.admit(envelope("later", "z")).unwrap();
        admission.admit(envelope("earlier", "a")).unwrap();
        assert_eq!(
            admission
                .deterministic_order()
                .unwrap()
                .iter()
                .map(|envelope| envelope.envelope_id.as_str())
                .collect::<Vec<_>>(),
            vec!["earlier", "later"]
        );
    }

    #[test]
    fn closed_or_duplicate_admission_fails_without_execution_side_effects() {
        let mut admission = EtdagAdmission::new(context(), &EtdagParameters::default()).unwrap();
        admission.admit(envelope("a", "a")).unwrap();
        assert_eq!(
            admission.admit(envelope("a", "b")),
            Err(EtdagError::DuplicateEnvelope)
        );
        admission.close();
        assert_eq!(
            admission.admit(envelope("b", "b")),
            Err(EtdagError::AdmissionClosed)
        );
    }
}
