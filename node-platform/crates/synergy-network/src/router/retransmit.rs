use std::collections::BTreeMap;

use synergy_protocol_types::ProtocolKind;

use super::QueueError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRetransmission {
    pub message_id: String,
    pub peer_id: String,
    pub protocol: ProtocolKind,
    pub payload: Vec<u8>,
    pub attempts: u32,
    pub next_attempt_at: u64,
}

#[derive(Debug)]
pub struct RetransmissionBuffer {
    capacity: usize,
    max_attempts: u32,
    entries: BTreeMap<String, OutboundRetransmission>,
}

impl RetransmissionBuffer {
    pub fn new(capacity: usize, max_attempts: u32) -> Result<Self, QueueError> {
        if capacity == 0 || max_attempts == 0 {
            return Err(QueueError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            max_attempts,
            entries: BTreeMap::new(),
        })
    }

    pub fn insert(&mut self, entry: OutboundRetransmission) -> Result<(), QueueError> {
        if entry.message_id.trim().is_empty()
            || entry.peer_id.trim().is_empty()
            || entry.payload.is_empty()
        {
            return Err(QueueError::InvalidCapacity);
        }
        if !self.entries.contains_key(&entry.message_id) && self.entries.len() >= self.capacity {
            return Err(QueueError::Capacity);
        }
        self.entries
            .entry(entry.message_id.clone())
            .or_insert(entry);
        Ok(())
    }

    pub fn due(&self, now: u64) -> Vec<OutboundRetransmission> {
        self.entries
            .values()
            .filter(|entry| entry.next_attempt_at <= now)
            .cloned()
            .collect()
    }

    pub fn record_attempt(&mut self, message_id: &str, retry_at: u64) -> bool {
        let Some(entry) = self.entries.get_mut(message_id) else {
            return false;
        };
        entry.attempts = entry.attempts.saturating_add(1);
        if entry.attempts >= self.max_attempts {
            self.entries.remove(message_id);
            return false;
        }
        entry.next_attempt_at = retry_at;
        true
    }

    pub fn acknowledge(&mut self, message_id: &str) -> bool {
        self.entries.remove(message_id).is_some()
    }
}
