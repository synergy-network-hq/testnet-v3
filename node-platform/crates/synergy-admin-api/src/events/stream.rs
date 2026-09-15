use std::collections::VecDeque;

use super::AdminEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStreamError {
    InvalidCapacity,
    Full,
    InvalidEvent,
}

#[derive(Debug)]
pub struct AdminEventStream {
    capacity: usize,
    max_payload_bytes: usize,
    events: VecDeque<AdminEvent>,
    last_sequence: u64,
}

impl AdminEventStream {
    pub fn new(capacity: usize, max_payload_bytes: usize) -> Result<Self, EventStreamError> {
        if capacity == 0 || max_payload_bytes == 0 {
            return Err(EventStreamError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            max_payload_bytes,
            events: VecDeque::new(),
            last_sequence: 0,
        })
    }

    pub fn publish(&mut self, event: AdminEvent) -> Result<(), EventStreamError> {
        event
            .validate(self.max_payload_bytes)
            .map_err(|_| EventStreamError::InvalidEvent)?;
        if event.sequence <= self.last_sequence {
            return Err(EventStreamError::InvalidEvent);
        }
        if self.events.len() >= self.capacity {
            return Err(EventStreamError::Full);
        }
        self.last_sequence = event.sequence;
        self.events.push_back(event);
        Ok(())
    }

    pub fn next(&mut self) -> Option<AdminEvent> {
        self.events.pop_front()
    }

    pub fn depth(&self) -> usize {
        self.events.len()
    }
}
