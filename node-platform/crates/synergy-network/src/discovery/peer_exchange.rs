use std::collections::BTreeSet;

use super::DiscoveryRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerExchange {
    pub sender_peer_id: String,
    pub generated_at: u64,
    pub records: Vec<DiscoveryRecord>,
}

impl PeerExchange {
    pub fn validate(&self, now: u64, max_records: usize) -> Result<(), String> {
        if self.sender_peer_id.trim().is_empty()
            || self.generated_at > now
            || self.records.len() > max_records
        {
            return Err("invalid peer exchange envelope".into());
        }
        let mut peers = BTreeSet::new();
        for record in &self.records {
            if !peers.insert(record.peer_id.as_str()) {
                return Err("duplicate peer exchange identity".into());
            }
            super::verify_discovery_record(record, now)
                .map_err(|error| format!("invalid peer exchange record: {error:?}"))?;
        }
        Ok(())
    }
}
