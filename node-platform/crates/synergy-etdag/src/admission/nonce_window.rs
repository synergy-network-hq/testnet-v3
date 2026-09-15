use std::collections::{BTreeMap, BTreeSet};

use crate::EtdagError;

#[derive(Debug, Clone)]
pub struct AdmissionNonceWindow {
    maximum_per_sender: usize,
    accepted: BTreeMap<String, BTreeSet<u64>>,
}

impl AdmissionNonceWindow {
    pub fn new(maximum_per_sender: usize) -> Result<Self, EtdagError> {
        if maximum_per_sender == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(Self {
            maximum_per_sender,
            accepted: BTreeMap::new(),
        })
    }

    pub fn accept(&mut self, sender: &str, nonce: u64) -> Result<(), EtdagError> {
        if sender.trim().is_empty() {
            return Err(EtdagError::InvalidEnvelope("empty sender identity".into()));
        }
        let existing = self.accepted.get(sender);
        if existing.is_some_and(|nonces| nonces.contains(&nonce)) {
            return Err(EtdagError::Replay(format!("{sender}:{nonce}")));
        }
        if existing.is_some_and(|nonces| nonces.len() >= self.maximum_per_sender) {
            return Err(EtdagError::AdmissionCapacity);
        }
        self.accepted
            .entry(sender.into())
            .or_default()
            .insert(nonce);
        Ok(())
    }

    pub fn release_through(&mut self, sender: &str, nonce: u64) {
        if let Some(nonces) = self.accepted.get_mut(sender) {
            nonces.retain(|candidate| *candidate > nonce);
            if nonces.is_empty() {
                self.accepted.remove(sender);
            }
        }
    }
}
