use std::collections::BTreeMap;

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetransmissionRequest {
    pub artifact_id: EtdagDigest,
    pub attempts: u32,
    pub next_attempt_at_ms: u64,
}

#[derive(Debug)]
pub struct RetransmissionQueue {
    max_attempts: u32,
    base_delay_ms: u64,
    pending: BTreeMap<EtdagDigest, RetransmissionRequest>,
}

impl RetransmissionQueue {
    pub fn new(max_attempts: u32, base_delay_ms: u64) -> Result<Self, EtdagError> {
        if max_attempts == 0 || base_delay_ms == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(Self {
            max_attempts,
            base_delay_ms,
            pending: BTreeMap::new(),
        })
    }

    pub fn schedule(&mut self, artifact_id: EtdagDigest, now_ms: u64) -> Result<(), EtdagError> {
        artifact_id.validate()?;
        self.pending
            .entry(artifact_id.clone())
            .or_insert(RetransmissionRequest {
                artifact_id,
                attempts: 0,
                next_attempt_at_ms: now_ms,
            });
        Ok(())
    }

    pub fn due(&self, now_ms: u64) -> Vec<RetransmissionRequest> {
        self.pending
            .values()
            .filter(|request| request.next_attempt_at_ms <= now_ms)
            .cloned()
            .collect()
    }

    pub fn record_attempt(
        &mut self,
        artifact_id: &EtdagDigest,
        now_ms: u64,
    ) -> Result<bool, EtdagError> {
        let request = self
            .pending
            .get_mut(artifact_id)
            .ok_or_else(|| EtdagError::MissingArtifact(artifact_id.0.clone()))?;
        request.attempts = request
            .attempts
            .checked_add(1)
            .ok_or(EtdagError::InvalidCapacity)?;
        if request.attempts >= self.max_attempts {
            self.pending.remove(artifact_id);
            return Ok(false);
        }
        let shift = request.attempts.saturating_sub(1).min(31);
        let delay = self
            .base_delay_ms
            .checked_mul(1u64 << shift)
            .ok_or(EtdagError::InvalidCapacity)?;
        request.next_attempt_at_ms = now_ms
            .checked_add(delay)
            .ok_or(EtdagError::InvalidCapacity)?;
        Ok(true)
    }

    pub fn complete(&mut self, artifact_id: &EtdagDigest) {
        self.pending.remove(artifact_id);
    }
}
