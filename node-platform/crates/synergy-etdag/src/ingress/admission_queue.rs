use std::collections::{BTreeSet, VecDeque};

use crate::admission::AdmissionRequest;
use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone)]
pub struct AdmissionQueue {
    capacity: usize,
    queued_ids: BTreeSet<EtdagDigest>,
    queue: VecDeque<AdmissionRequest>,
}

impl AdmissionQueue {
    pub fn new(capacity: usize) -> Result<Self, EtdagError> {
        if capacity == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            queued_ids: BTreeSet::new(),
            queue: VecDeque::new(),
        })
    }

    pub fn check(&self, request: &AdmissionRequest) -> Result<(), EtdagError> {
        if self.queue.len() >= self.capacity {
            return Err(EtdagError::AdmissionCapacity);
        }
        if self.queued_ids.contains(&request.envelope.envelope_id) {
            return Err(EtdagError::DuplicateEnvelope);
        }
        Ok(())
    }

    pub fn push(&mut self, request: AdmissionRequest) {
        self.queued_ids.insert(request.envelope.envelope_id.clone());
        self.queue.push_back(request);
    }

    pub fn pop(&mut self) -> Option<AdmissionRequest> {
        let request = self.queue.pop_front()?;
        self.queued_ids.remove(&request.envelope.envelope_id);
        Some(request)
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}
