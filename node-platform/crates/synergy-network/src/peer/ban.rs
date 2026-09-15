use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRecord {
    pub reason: String,
    pub until: Option<u64>,
}

#[derive(Debug, Default)]
pub struct BanTable {
    records: BTreeMap<String, BanRecord>,
}

impl BanTable {
    pub fn ban(
        &mut self,
        peer_id: impl Into<String>,
        record: BanRecord,
    ) -> Result<(), super::ConnectionLimitError> {
        let peer_id = peer_id.into();
        if peer_id.trim().is_empty() || record.reason.trim().is_empty() {
            return Err(super::ConnectionLimitError::InvalidConfiguration);
        }
        self.records.insert(peer_id, record);
        Ok(())
    }

    pub fn is_banned(&self, peer_id: &str, now: u64) -> bool {
        self.records
            .get(peer_id)
            .is_some_and(|record| record.until.is_none_or(|until| now < until))
    }

    pub fn remove_expired(&mut self, now: u64) {
        self.records
            .retain(|_, record| record.until.is_none_or(|until| now < until));
    }
}
