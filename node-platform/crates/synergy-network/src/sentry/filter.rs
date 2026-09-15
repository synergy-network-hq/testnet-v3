use std::collections::BTreeSet;

use crate::protocol::InboundFrame;
use synergy_protocol_types::ProtocolKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentryFilterError {
    Denied,
    Oversize { received: usize, maximum: usize },
}

#[derive(Debug, Clone)]
pub struct SentryFilter {
    allowed: BTreeSet<ProtocolKind>,
    max_payload_bytes: usize,
}

impl SentryFilter {
    pub fn new(
        allowed: BTreeSet<ProtocolKind>,
        max_payload_bytes: usize,
    ) -> Result<Self, SentryFilterError> {
        if allowed.is_empty() || max_payload_bytes == 0 {
            return Err(SentryFilterError::Denied);
        }
        Ok(Self {
            allowed,
            max_payload_bytes,
        })
    }

    pub fn permit(&self, frame: &InboundFrame) -> Result<(), SentryFilterError> {
        if !self.allowed.contains(&frame.protocol) {
            return Err(SentryFilterError::Denied);
        }
        if frame.payload.len() > self.max_payload_bytes {
            return Err(SentryFilterError::Oversize {
                received: frame.payload.len(),
                maximum: self.max_payload_bytes,
            });
        }
        Ok(())
    }
}
