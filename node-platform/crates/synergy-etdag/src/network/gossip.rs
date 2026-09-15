use std::collections::{BTreeSet, VecDeque};

use crate::{AuthenticatedEtdagMessage, EtdagDigest, EtdagError};

#[derive(Debug)]
pub struct GossipQueue {
    capacity: usize,
    queued: VecDeque<AuthenticatedEtdagMessage>,
    known: BTreeSet<EtdagDigest>,
}

impl GossipQueue {
    pub fn new(capacity: usize) -> Result<Self, EtdagError> {
        if capacity == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            queued: VecDeque::new(),
            known: BTreeSet::new(),
        })
    }

    pub fn enqueue(&mut self, message: AuthenticatedEtdagMessage) -> Result<bool, EtdagError> {
        message.validate_shape()?;
        if self.known.contains(&message.message_id) {
            return Ok(false);
        }
        if self.queued.len() >= self.capacity {
            return Err(EtdagError::InvalidCapacity);
        }
        self.known.insert(message.message_id.clone());
        self.queued.push_back(message);
        Ok(true)
    }

    pub fn pop(&mut self) -> Option<AuthenticatedEtdagMessage> {
        self.queued.pop_front()
    }

    pub fn acknowledge(&mut self, message_id: &EtdagDigest) {
        self.known.remove(message_id);
    }
}
