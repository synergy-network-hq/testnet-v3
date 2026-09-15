use serde::{Deserialize, Serialize};

use crate::{
    EtdagAdmission, EtdagError, EtdagParameters, ProtectedEnvelope, TargetAdmissionContext,
};

/// Durable ETDAG admission state. The encrypted envelopes remain opaque; this
/// wrapper only restores the already-validated admission owner after restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableAdmission {
    format: String,
    context: TargetAdmissionContext,
    capacity: usize,
    envelopes: Vec<ProtectedEnvelope>,
    closed: bool,
}

#[derive(Debug)]
pub struct PersistentEtdagAdmission {
    store: synergy_storage::AtomicStore,
    admission: EtdagAdmission,
}

impl PersistentEtdagAdmission {
    pub fn open(
        root: impl AsRef<std::path::Path>,
        context: TargetAdmissionContext,
        parameters: &EtdagParameters,
    ) -> Result<Self, EtdagError> {
        context.validate()?;
        parameters.validate()?;
        let store = synergy_storage::AtomicStore::new(root.as_ref(), 16 * 1024 * 1024)
            .map_err(storage_error)?;
        let admission = if store.exists("admission.json").map_err(storage_error)? {
            let bytes = store
                .read_bounded("admission.json")
                .map_err(storage_error)?;
            let durable: DurableAdmission = serde_json::from_slice(&bytes)
                .map_err(|error| EtdagError::Corrupt(error.to_string()))?;
            if durable.format != "synergy-etdag-admission-v1"
                || durable.context != context
                || durable.capacity != parameters.max_outstanding_nonce_slots
            {
                return Err(EtdagError::ContextMismatch);
            }

            let mut rebuilt = EtdagAdmission::new(durable.context, parameters)?;
            for envelope in durable.envelopes {
                rebuilt.admit(envelope)?;
            }
            if durable.closed {
                rebuilt.close();
            }
            rebuilt
        } else {
            EtdagAdmission::new(context, parameters)?
        };
        Ok(Self { store, admission })
    }

    pub fn admission(&self) -> &EtdagAdmission {
        &self.admission
    }

    pub fn admit(&mut self, envelope: ProtectedEnvelope) -> Result<(), EtdagError> {
        let mut next = self.admission.clone();
        next.admit(envelope)?;
        self.persist(&next)?;
        self.admission = next;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), EtdagError> {
        let mut next = self.admission.clone();
        next.close();
        self.persist(&next)?;
        self.admission = next;
        Ok(())
    }

    fn persist(&self, admission: &EtdagAdmission) -> Result<(), EtdagError> {
        let bytes = serde_json::to_vec(&DurableAdmission {
            format: "synergy-etdag-admission-v1".into(),
            context: admission.context.clone(),
            capacity: admission.capacity,
            envelopes: admission.envelopes.values().cloned().collect(),
            closed: admission.closed,
        })
        .map_err(|error| EtdagError::Corrupt(error.to_string()))?;
        self.store
            .write_atomic("admission.json", &bytes)
            .map_err(storage_error)
    }
}

fn storage_error(error: synergy_storage::StorageError) -> EtdagError {
    EtdagError::Storage(error.to_string())
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
    fn persistent_admission_recovers_context_bound_envelopes_and_closed_state() {
        let root =
            std::env::temp_dir().join(format!("synergy-etdag-recovery-{}", std::process::id()));
        let parameters = EtdagParameters::default();
        let mut persistent = PersistentEtdagAdmission::open(&root, context(), &parameters).unwrap();
        persistent.admit(envelope("later", "z")).unwrap();
        persistent.admit(envelope("earlier", "a")).unwrap();
        persistent.close().unwrap();
        drop(persistent);

        let persistent = PersistentEtdagAdmission::open(&root, context(), &parameters).unwrap();
        assert_eq!(
            persistent
                .admission()
                .deterministic_order()
                .unwrap()
                .iter()
                .map(|entry| entry.envelope_id.as_str())
                .collect::<Vec<_>>(),
            vec!["earlier", "later"]
        );

        let mut persistent = persistent;
        assert_eq!(
            persistent.admit(envelope("new", "x")),
            Err(EtdagError::AdmissionClosed)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn persistent_admission_rejects_context_mismatch_on_recovery() {
        let root = std::env::temp_dir().join(format!(
            "synergy-etdag-context-mismatch-{}",
            std::process::id()
        ));
        let parameters = EtdagParameters::default();
        PersistentEtdagAdmission::open(&root, context(), &parameters)
            .unwrap()
            .close()
            .unwrap();
        let mut mismatched = context();
        mismatched.validator_consensus_key_root = "different".into();
        assert!(matches!(
            PersistentEtdagAdmission::open(&root, mismatched, &parameters),
            Err(EtdagError::ContextMismatch)
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
