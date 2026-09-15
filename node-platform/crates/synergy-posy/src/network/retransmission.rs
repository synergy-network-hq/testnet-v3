use std::collections::VecDeque;

use crate::{ConsensusEvent, PosyError, PosyResult};

#[derive(Debug)]
pub struct BoundedPosyRetransmission {
    capacity: usize,
    pending: VecDeque<(String, ConsensusEvent)>,
}

impl BoundedPosyRetransmission {
    pub fn new(capacity: usize) -> PosyResult<Self> {
        if capacity == 0 {
            return Err(PosyError::invalid("PoSy retransmission capacity is zero"));
        }
        Ok(Self {
            capacity,
            pending: VecDeque::new(),
        })
    }

    pub fn enqueue(&mut self, peer_id: String, event: ConsensusEvent) -> PosyResult<()> {
        if self.pending.len() >= self.capacity {
            return Err(PosyError::NotReady(
                "PoSy retransmission queue is full".into(),
            ));
        }
        self.pending.push_back((peer_id, event));
        Ok(())
    }

    pub fn pop(&mut self) -> Option<(String, ConsensusEvent)> {
        self.pending.pop_front()
    }
}
