use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRecord {
    pub peer_id: String,
    pub dial_addresses: Vec<String>,
    pub observed_at: u64,
    pub expires_at: u64,
}

#[derive(Debug)]
pub struct DiscoveryCache {
    capacity: usize,
    records: BTreeMap<String, DiscoveryRecord>,
}

impl DiscoveryCache {
    pub fn new(capacity: usize) -> Result<Self, String> {
        if capacity == 0 {
            return Err("discovery cache capacity must be nonzero".into());
        }
        Ok(Self {
            capacity,
            records: BTreeMap::new(),
        })
    }

    pub fn insert(&mut self, record: DiscoveryRecord, now: u64) -> Result<(), String> {
        super::verify_discovery_record(&record, now).map_err(|error| format!("{error:?}"))?;
        if !self.records.contains_key(&record.peer_id) && self.records.len() >= self.capacity {
            return Err("discovery cache capacity reached".into());
        }
        self.records.insert(record.peer_id.clone(), record);
        Ok(())
    }

    pub fn get(&self, peer_id: &str, now: u64) -> Option<&DiscoveryRecord> {
        self.records
            .get(peer_id)
            .filter(|record| record.expires_at > now)
    }

    pub fn remove_expired(&mut self, now: u64) {
        self.records.retain(|_, record| record.expires_at > now);
    }
}
