use std::collections::BTreeSet;

use crate::admission::AdmissionRequest;
use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone)]
pub struct IngressReplayProtection {
    maximum_entries: usize,
    nonces: BTreeSet<(String, u64)>,
    envelopes: BTreeSet<EtdagDigest>,
}

impl IngressReplayProtection {
    pub fn new(maximum_entries: usize) -> Result<Self, EtdagError> {
        if maximum_entries == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(Self {
            maximum_entries,
            nonces: BTreeSet::new(),
            envelopes: BTreeSet::new(),
        })
    }

    pub fn check(&self, request: &AdmissionRequest) -> Result<(), EtdagError> {
        if self
            .nonces
            .contains(&(request.sender_wallet.clone(), request.sender_nonce))
        {
            return Err(EtdagError::Replay(format!(
                "{}:{}",
                request.sender_wallet, request.sender_nonce
            )));
        }
        if self.envelopes.contains(&request.envelope.envelope_id) {
            return Err(EtdagError::DuplicateEnvelope);
        }
        if self.nonces.len() >= self.maximum_entries || self.envelopes.len() >= self.maximum_entries
        {
            return Err(EtdagError::AdmissionCapacity);
        }
        Ok(())
    }

    pub fn record(&mut self, request: &AdmissionRequest) {
        self.nonces
            .insert((request.sender_wallet.clone(), request.sender_nonce));
        self.envelopes.insert(request.envelope.envelope_id.clone());
    }

    pub fn release(&mut self, sender: &str, nonce: u64, envelope: &EtdagDigest) {
        self.nonces.remove(&(sender.into(), nonce));
        self.envelopes.remove(envelope);
    }
}
