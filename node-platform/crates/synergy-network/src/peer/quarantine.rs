use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineRecord {
    pub reason: String,
    pub retry_at: u64,
}

#[derive(Debug, Default)]
pub struct QuarantineTable {
    records: BTreeMap<String, QuarantineRecord>,
}

impl QuarantineTable {
    pub fn quarantine(
        &mut self,
        peer_id: impl Into<String>,
        record: QuarantineRecord,
        now: u64,
    ) -> Result<(), super::ConnectionLimitError> {
        let peer_id = peer_id.into();
        if peer_id.trim().is_empty() || record.reason.trim().is_empty() || record.retry_at <= now {
            return Err(super::ConnectionLimitError::InvalidConfiguration);
        }
        self.records.insert(peer_id, record);
        Ok(())
    }

    pub fn retry_at(&self, peer_id: &str, now: u64) -> Option<u64> {
        self.records
            .get(peer_id)
            .filter(|record| record.retry_at > now)
            .map(|record| record.retry_at)
    }

    pub fn remove_expired(&mut self, now: u64) {
        self.records.retain(|_, record| record.retry_at > now);
    }
}
